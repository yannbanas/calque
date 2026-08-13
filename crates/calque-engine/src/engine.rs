//! Le moteur d'accessibilité concret (§5.1).
//!
//! Séquence par équipement (§3.1) :
//! entrée → filtre d'entrée → DNAT → routage → filtre de sortie → SNAT → sortie.
//!
//! Arrêts : refus (règle responsable), pas de route, boucle (équipement déjà
//! visité), destination atteinte (adresse portée par un équipement, ou sortie
//! vers un réseau directement connecté qui la contient), SORTIE DE PÉRIMÈTRE
//! (voir ci-dessous), ou `Unknown` quand un élément du chemin manque ou est
//! ambigu (§6.3 : ne jamais deviner).
//!
//! Sortie de périmètre (critère précis, documenté) : quand la décision de
//! routage donne une interface de sortie et que
//! 1. la destination n'appartient à AUCUN équipement du modèle (aucune
//!    interface active ne porte un réseau la contenant), ET
//! 2. l'interface de sortie n'a AUCUN lien,
//!
//! alors le paquet SORT du périmètre modélisé (Internet via une interface
//! WAN, site distant via un tunnel sans adresse ni lien…). L'équipement a
//! tranché : le verdict est celui des filtres (`Allowed` s'ils ont accepté),
//! avec une décision `Outcome::ExitsModel` explicite. Si la destination
//! appartient au périmètre (équipement ou réseau modélisé) mais est
//! injoignable, c'est un vrai trou de topologie INTERNE : le comportement
//! historique est conservé (« topologie incomplète » → `Unknown`).
//!
//! ECMP (plusieurs routes optimales divergentes) : chaque route candidate
//! est évaluée comme une BRANCHE complète (filtres de sortie, SNAT, lien ou
//! sortie de périmètre, équipements suivants). Si toutes les branches mènent
//! au même verdict, ce verdict est ferme (« ne jamais deviner » ≠ « ne
//! jamais répondre ») ; sinon `Unknown` avec le verdict de chaque branche en
//! diagnostic. Bornes : [`crate::route::MAX_ECMP_ROUTES`] par recherche,
//! [`MAX_ECMP_TOTAL_BRANCHES`] en cumulé sur la trace.

use std::collections::BTreeSet;
use std::net::IpAddr;

use calque_model::{
    AdminState, ConcretePacket, Device, DeviceId, Diagnostic, Endpoint, IfaceId, Network, Severity,
    ZoneId,
};
use ipnet::IpNet;

use crate::error::EvalError;
use crate::policy::{evaluate_policy, FilterPoint, FilterResult, NatGrant};
use crate::route::{lookup_route, EcmpRoute, RouteDecision};
use crate::trace::{Decision, Hop, Outcome, Stage, Trace, Verdict};

/// Borne CUMULÉE de branches ECMP évaluées sur une même trace : une branche
/// peut elle-même rencontrer un ECMP (bifurcation récursive), et chaque
/// embranchement consomme autant de budget que de routes candidates.
/// Budget épuisé → verdict `Unknown` diagnostiqué, jamais une évaluation
/// partielle silencieuse. Voir aussi [`crate::route::MAX_ECMP_ROUTES`]
/// (borne PAR recherche de route).
pub const MAX_ECMP_TOTAL_BRANCHES: usize = 16;

/// Résultat de la traversée d'un équipement JUSQU'À la décision de routage
/// (filtres d'entrée, DNAT, livraison locale, recherche de route). Les
/// filtres de sortie restent à évaluer PAR interface candidate — c'est ce
/// qui permet l'évaluation par branches de l'ECMP.
enum DeviceStep {
    Denied,
    /// L'équipement porte l'adresse destination : livraison locale.
    LocalDelivery,
    /// Aucune route (ou route de rejet, documentée dans les décisions).
    NoRoute,
    /// Routage décidé : une candidate en temps normal, plusieurs en ECMP.
    Routed {
        candidates: Vec<EcmpRoute>,
        /// SNAT accordé à l'entrée mais différé (appliqué après le filtre
        /// de sortie de la branche).
        pending_snat: Option<NatGrant>,
        in_zone: Option<ZoneId>,
    },
}

/// Point d'entrée localisé pour la source.
struct EntryPoint {
    device: DeviceId,
    iface: IfaceId,
    /// Le réseau connecté qui a permis la localisation.
    net: IpNet,
}

fn info(message: String) -> Diagnostic {
    Diagnostic {
        severity: Severity::Info,
        message,
        span: None,
    }
}

/// La zone d'une interface : champ de l'interface, sinon la table des zones
/// de l'équipement.
fn zone_of(device: &Device, iface_id: &IfaceId) -> Option<ZoneId> {
    if let Some(iface) = device.interfaces.get(iface_id) {
        if iface.zone.is_some() {
            return iface.zone.clone();
        }
    }
    device
        .zones
        .iter()
        .find(|(_, members)| members.contains(iface_id))
        .map(|(zone, _)| zone.clone())
}

/// L'équipement (et l'interface) qui porte EXACTEMENT cette adresse, s'il
/// est modélisé. Plusieurs porteurs → ambiguïté (adresse dupliquée).
fn owner_of_address(
    network: &Network,
    addr: &IpAddr,
) -> Result<Option<(DeviceId, IfaceId)>, Diagnostic> {
    let mut owners: Vec<(DeviceId, IfaceId)> = Vec::new();
    for device in network.devices.values() {
        for iface in device.interfaces.values() {
            if iface.state == AdminState::Up && iface.addrs.iter().any(|a| a.addr() == *addr) {
                owners.push((device.id.clone(), iface.id.clone()));
            }
        }
    }
    match owners.len() {
        0 => Ok(None),
        1 => Ok(owners.pop()),
        _ => Err(Diagnostic::error(
            format!("adresse {addr} portée par plusieurs équipements : modèle ambigu"),
            None,
        )),
    }
}

/// Localise la source : l'équipement/interface dont un réseau connecté
/// contient l'adresse source (plus long préfixe). Ambiguïté ou absence →
/// diagnostic, jamais une supposition.
fn locate_source(network: &Network, src: &IpAddr) -> Result<EntryPoint, Diagnostic> {
    // (équipement, interface, réseau, l'interface porte-t-elle src exactement ?)
    let mut candidates: Vec<(DeviceId, IfaceId, IpNet, bool)> = Vec::new();
    for device in network.devices.values() {
        for iface in device.interfaces.values() {
            if iface.state != AdminState::Up {
                continue;
            }
            for addr in &iface.addrs {
                if addr.contains(src) {
                    candidates.push((
                        device.id.clone(),
                        iface.id.clone(),
                        addr.trunc(),
                        addr.addr() == *src,
                    ));
                }
            }
        }
    }
    let Some(best_len) = candidates.iter().map(|c| c.2.prefix_len()).max() else {
        return Err(Diagnostic::error(
            format!("source {src} introuvable : aucune interface active ne porte un réseau la contenant"),
            None,
        ));
    };
    candidates.retain(|c| c.2.prefix_len() == best_len);
    // Si la source est l'adresse propre d'une interface, ce porteur gagne.
    if let Some((d, i, n, _)) = candidates.iter().find(|c| c.3).cloned() {
        return Ok(EntryPoint {
            device: d,
            iface: i,
            net: n,
        });
    }
    if candidates.len() > 1 {
        let list: Vec<String> = candidates
            .iter()
            .map(|(d, i, _, _)| format!("{d}/{i}"))
            .collect();
        return Err(Diagnostic::error(
            format!(
                "source {src} ambiguë : plusieurs interfaces portent un réseau la contenant \
                 ({})",
                list.join(", ")
            ),
            None,
        ));
    }
    match candidates.pop() {
        Some((d, i, n, _)) => Ok(EntryPoint {
            device: d,
            iface: i,
            net: n,
        }),
        None => Err(Diagnostic::error(format!("source {src} introuvable"), None)),
    }
}

/// Les extrémités distantes des liens partant de (équipement, interface).
fn links_from<'a>(network: &'a Network, device: &DeviceId, iface: &IfaceId) -> Vec<&'a Endpoint> {
    let mut peers: Vec<&Endpoint> = Vec::new();
    for link in &network.links {
        if link.a.device == *device && link.a.iface == *iface {
            peers.push(&link.b);
        } else if link.b.device == *device && link.b.iface == *iface {
            peers.push(&link.a);
        }
    }
    peers
}

/// La destination appartient-elle au périmètre modélisé ? Vraie si une
/// interface ACTIVE d'un équipement du modèle porte un réseau qui la
/// contient (donc en particulier si un équipement porte l'adresse exacte).
/// C'est la moitié « destination » du critère de sortie de périmètre (voir
/// l'en-tête du module) — l'autre moitié étant l'absence de lien depuis
/// l'interface de sortie. Volontairement PRUDENT : une destination couverte
/// par un réseau modélisé mais injoignable reste un trou de topologie
/// interne (`Unknown`), jamais une sortie de périmètre.
fn destination_in_model(network: &Network, dst: &IpAddr) -> bool {
    network.devices.values().any(|d| {
        d.interfaces
            .values()
            .any(|i| i.state == AdminState::Up && i.addrs.iter().any(|a| a.contains(dst)))
    })
}

/// Traverse UN équipement, en remplissant `hop` et en réécrivant `pkt`
/// (NAT). La séquence est celle de §3.1.
fn process_device(
    device: &Device,
    in_iface_id: &IfaceId,
    pkt: &mut ConcretePacket,
    hop: &mut Hop,
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<DeviceStep, EvalError> {
    let in_iface = device
        .interfaces
        .get(in_iface_id)
        .ok_or_else(|| EvalError::Inconsistent {
            message: format!(
                "interface d'entrée « {in_iface_id} » absente de l'équipement « {} »",
                device.id
            ),
            span: None,
        })?;
    if in_iface.state != AdminState::Up {
        return Err(EvalError::Inconsistent {
            message: format!(
                "le paquet entre par « {}/{in_iface_id} » qui est désactivée",
                device.id
            ),
            span: None,
        });
    }
    let in_zone = zone_of(device, in_iface_id);

    // SNAT accordé mais différé : appliqué après le filtre de sortie.
    let mut pending_snat: Option<NatGrant> = None;

    // --- Filtres d'entrée -------------------------------------------------
    let ingress_point = FilterPoint::Ingress {
        in_zone: in_zone.clone(),
    };
    for pid in &device.pipeline.ingress {
        let policy = device
            .policies
            .get(pid)
            .ok_or_else(|| EvalError::PolicyMissing {
                policy: pid.clone(),
            })?;
        let ev = evaluate_policy(device, policy, pkt, &ingress_point, Stage::IngressFilter)?;
        hop.decisions.extend(ev.decisions);
        diagnostics.extend(ev.diagnostics);
        match ev.result {
            FilterResult::Deny => return Ok(DeviceStep::Denied),
            FilterResult::Accept { nat: Some(grant) } => {
                // DNAT : réécriture de la destination AVANT le routage.
                if let Some(dnat) = &grant.action.dnat {
                    pkt.dst = dnat.addr;
                    if let Some(port) = dnat.port {
                        pkt.dport = port;
                    }
                    hop.decisions.push(Decision {
                        stage: Stage::Nat,
                        rule: grant.rule.clone(),
                        source: grant.source.clone(),
                        outcome: Outcome::Rewritten,
                        shadowed_by: Vec::new(),
                    });
                }
                if grant.action.snat.is_some() {
                    pending_snat = Some(grant);
                }
            }
            FilterResult::Accept { nat: None } => {}
        }
    }

    // --- Livraison locale : l'équipement porte l'adresse destination ------
    if device
        .interfaces
        .values()
        .any(|i| i.state == AdminState::Up && i.addrs.iter().any(|a| a.addr() == pkt.dst))
    {
        return Ok(DeviceStep::LocalDelivery);
    }

    // --- Routage ----------------------------------------------------------
    // Les filtres de sortie ne sont PAS évalués ici : ils dépendent de
    // l'interface candidate, et l'ECMP en rend plusieurs (une par branche).
    match lookup_route(device, &in_iface.vrf, &pkt.dst)? {
        RouteDecision::NoRoute => {
            hop.decisions.push(Decision {
                stage: Stage::Route,
                rule: None,
                source: None,
                outcome: Outcome::NoRoute,
                shadowed_by: Vec::new(),
            });
            Ok(DeviceStep::NoRoute)
        }
        RouteDecision::Blackhole { source, .. } => {
            // Verdict global `NoRoute` ; la décision `RouteDrop` pointe la
            // route de rejet responsable (choix documenté sur `Outcome`).
            hop.decisions.push(Decision {
                stage: Stage::Route,
                rule: None,
                source,
                outcome: Outcome::RouteDrop,
                shadowed_by: Vec::new(),
            });
            Ok(DeviceStep::NoRoute)
        }
        RouteDecision::Forward {
            out_iface,
            gateway,
            source,
            ..
        } => Ok(DeviceStep::Routed {
            candidates: vec![EcmpRoute {
                out_iface,
                gateway,
                source,
            }],
            pending_snat,
            in_zone,
        }),
        RouteDecision::Ecmp { routes, .. } => Ok(DeviceStep::Routed {
            candidates: routes,
            pending_snat,
            in_zone,
        }),
    }
}

/// Filtres de sortie puis SNAT pour UNE interface de sortie candidate
/// (zones d'entrée ET de sortie connues). Rend `true` si un filtre refuse ;
/// mute `pkt` (SNAT) et remplit `hop`.
fn process_egress(
    device: &Device,
    in_zone: &Option<ZoneId>,
    out_iface: &IfaceId,
    mut pending_snat: Option<NatGrant>,
    pkt: &mut ConcretePacket,
    hop: &mut Hop,
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<bool, EvalError> {
    let egress_point = FilterPoint::Egress {
        in_zone: in_zone.clone(),
        out_zone: zone_of(device, out_iface),
    };
    for pid in &device.pipeline.egress {
        let policy = device
            .policies
            .get(pid)
            .ok_or_else(|| EvalError::PolicyMissing {
                policy: pid.clone(),
            })?;
        let ev = evaluate_policy(device, policy, pkt, &egress_point, Stage::EgressFilter)?;
        hop.decisions.extend(ev.decisions);
        diagnostics.extend(ev.diagnostics);
        match ev.result {
            FilterResult::Deny => return Ok(true),
            FilterResult::Accept { nat: Some(grant) } => {
                if grant.action.dnat.is_some() {
                    // Trop tard pour réécrire la destination.
                    return Err(EvalError::DnatAfterRouting {
                        rule: grant.rule,
                        source: grant.source,
                    });
                }
                if grant.action.snat.is_some() {
                    if pending_snat.is_some() {
                        diagnostics.push(info(format!(
                            "SNAT d'entrée remplacé par le SNAT de sortie sur « {} »",
                            device.id
                        )));
                    }
                    pending_snat = Some(grant);
                }
            }
            FilterResult::Accept { nat: None } => {}
        }
    }

    // --- SNAT : réécriture de la source APRÈS le filtre de sortie ---------
    if let Some(grant) = pending_snat {
        if let Some(pool) = grant.action.snat {
            if pool.prefix_len() < pool.max_prefix_len() {
                diagnostics.push(info(format!(
                    "SNAT vers le pool {pool} : adresse représentative {} retenue",
                    pool.addr()
                )));
            }
            pkt.src = pool.addr();
            hop.decisions.push(Decision {
                stage: Stage::Nat,
                rule: grant.rule,
                source: grant.source,
                outcome: Outcome::Rewritten,
                shadowed_by: Vec::new(),
            });
        }
    }
    Ok(false)
}

/// L'état d'une branche prête à poursuivre sur l'équipement suivant.
struct NextHopState {
    device: DeviceId,
    iface: IfaceId,
    pkt: ConcretePacket,
    visited: BTreeSet<DeviceId>,
    hops: Vec<Hop>,
    diagnostics: Vec<Diagnostic>,
}

/// Le sort d'une branche après filtres de sortie et franchissement.
enum BranchStep {
    /// La branche est terminée : voici sa trace complète.
    Done(Trace),
    /// La branche continue sur l'équipement suivant.
    Next(Box<NextHopState>),
}

/// Le marcheur de la propagation concrète (§5.1). Il porte le budget cumulé
/// de branches ECMP ([`MAX_ECMP_TOTAL_BRANCHES`]) : la récursion n'a lieu
/// QUE sur un embranchement ECMP, le chemin linéaire reste une boucle — la
/// profondeur de pile est donc bornée par ce budget.
struct Walker<'a> {
    network: &'a Network,
    ecmp_budget: usize,
}

impl Walker<'_> {
    /// La boucle de propagation (§5.1), à partir d'un point d'entrée connu.
    fn walk(
        &mut self,
        mut cur_device: DeviceId,
        mut cur_iface: IfaceId,
        mut pkt: ConcretePacket,
        mut visited: BTreeSet<DeviceId>,
        mut hops: Vec<Hop>,
        mut diagnostics: Vec<Diagnostic>,
    ) -> Trace {
        loop {
            // Détection de boucle : équipement déjà traversé.
            if !visited.insert(cur_device.clone()) {
                diagnostics.push(Diagnostic::error(
                    format!("boucle de routage : « {cur_device} » déjà traversé"),
                    None,
                ));
                return Trace {
                    verdict: Verdict::Loop,
                    hops,
                    diagnostics,
                };
            }
            let network = self.network;
            let Some(device) = network.devices.get(&cur_device) else {
                diagnostics.push(Diagnostic::error(
                    format!("équipement « {cur_device} » absent du modèle"),
                    None,
                ));
                return Trace {
                    verdict: Verdict::Unknown,
                    hops,
                    diagnostics,
                };
            };

            let mut hop = Hop {
                device: cur_device.clone(),
                in_iface: cur_iface.clone(),
                out_iface: None,
                header_in: pkt,
                header_out: pkt,
                decisions: Vec::new(),
            };
            let step = process_device(device, &cur_iface, &mut pkt, &mut hop, &mut diagnostics);
            hop.header_out = pkt;

            match step {
                Err(e) => {
                    diagnostics.push(e.to_diagnostic());
                    hops.push(hop);
                    return Trace {
                        verdict: Verdict::Unknown,
                        hops,
                        diagnostics,
                    };
                }
                Ok(DeviceStep::Denied) => {
                    hops.push(hop);
                    return Trace {
                        verdict: Verdict::Denied,
                        hops,
                        diagnostics,
                    };
                }
                Ok(DeviceStep::LocalDelivery) => {
                    hops.push(hop);
                    return Trace {
                        verdict: Verdict::Allowed,
                        hops,
                        diagnostics,
                    };
                }
                Ok(DeviceStep::NoRoute) => {
                    hops.push(hop);
                    return Trace {
                        verdict: Verdict::NoRoute,
                        hops,
                        diagnostics,
                    };
                }
                Ok(DeviceStep::Routed {
                    mut candidates,
                    pending_snat,
                    in_zone,
                }) => {
                    if candidates.len() == 1 {
                        let cand = candidates.remove(0);
                        match self.finish_branch(
                            device,
                            in_zone,
                            cand,
                            pending_snat,
                            pkt,
                            hop,
                            visited,
                            hops,
                            diagnostics,
                        ) {
                            BranchStep::Done(trace) => return trace,
                            BranchStep::Next(next) => {
                                let n = *next;
                                cur_device = n.device;
                                cur_iface = n.iface;
                                pkt = n.pkt;
                                visited = n.visited;
                                hops = n.hops;
                                diagnostics = n.diagnostics;
                            }
                        }
                    } else {
                        return self.walk_ecmp(
                            device,
                            in_zone,
                            candidates,
                            pending_snat,
                            pkt,
                            hop,
                            visited,
                            hops,
                            diagnostics,
                        );
                    }
                }
            }
        }
    }

    /// Termine la traversée d'un équipement pour UNE route candidate :
    /// filtres de sortie, SNAT, puis livraison connectée, lien physique ou
    /// SORTIE DE PÉRIMÈTRE (critère documenté en tête de module).
    #[allow(clippy::too_many_arguments)]
    fn finish_branch(
        &mut self,
        device: &Device,
        in_zone: Option<ZoneId>,
        cand: EcmpRoute,
        pending_snat: Option<NatGrant>,
        mut pkt: ConcretePacket,
        mut hop: Hop,
        visited: BTreeSet<DeviceId>,
        mut hops: Vec<Hop>,
        mut diagnostics: Vec<Diagnostic>,
    ) -> BranchStep {
        let network = self.network;
        // La décision de routage de la branche (l'origine de la route).
        hop.decisions.push(Decision {
            stage: Stage::Route,
            rule: None,
            source: cand.source.clone(),
            outcome: Outcome::RouteFound,
            shadowed_by: Vec::new(),
        });
        hop.out_iface = Some(cand.out_iface.clone());

        let denied = match process_egress(
            device,
            &in_zone,
            &cand.out_iface,
            pending_snat,
            &mut pkt,
            &mut hop,
            &mut diagnostics,
        ) {
            Ok(denied) => denied,
            Err(e) => {
                diagnostics.push(e.to_diagnostic());
                hop.header_out = pkt;
                hops.push(hop);
                return BranchStep::Done(Trace {
                    verdict: Verdict::Unknown,
                    hops,
                    diagnostics,
                });
            }
        };
        hop.header_out = pkt;
        hops.push(hop);
        if denied {
            return BranchStep::Done(Trace {
                verdict: Verdict::Denied,
                hops,
                diagnostics,
            });
        }

        // Destination sur un réseau directement connecté à la sortie ?
        let delivered = device
            .interfaces
            .get(&cand.out_iface)
            .map(|o| o.addrs.iter().any(|a| a.contains(&pkt.dst)))
            .unwrap_or(false);
        if delivered {
            return match owner_of_address(network, &pkt.dst) {
                // L'adresse est portée par un équipement modélisé :
                // on y entre (ses filtres s'appliquent).
                Ok(Some((d, i))) => BranchStep::Next(Box::new(NextHopState {
                    device: d,
                    iface: i,
                    pkt,
                    visited,
                    hops,
                    diagnostics,
                })),
                // Hôte non modélisé du réseau connecté : atteint.
                Ok(None) => BranchStep::Done(Trace {
                    verdict: Verdict::Allowed,
                    hops,
                    diagnostics,
                }),
                Err(d) => {
                    diagnostics.push(d);
                    BranchStep::Done(Trace {
                        verdict: Verdict::Unknown,
                        hops,
                        diagnostics,
                    })
                }
            };
        }

        // Lien(s) physique(s) depuis l'interface de sortie.
        let peers = links_from(network, &device.id, &cand.out_iface);
        match peers.len() {
            0 => {
                if destination_in_model(network, &pkt.dst) {
                    // Vrai trou de topologie INTERNE : la destination
                    // appartient au périmètre mais est injoignable — jamais
                    // transformé en « autorisé » (§6.3).
                    diagnostics.push(Diagnostic::error(
                        format!(
                            "topologie incomplète : aucun lien depuis {}/{} et la \
                             destination {} appartient au périmètre modélisé",
                            device.id, cand.out_iface, pkt.dst
                        ),
                        None,
                    ));
                    BranchStep::Done(Trace {
                        verdict: Verdict::Unknown,
                        hops,
                        diagnostics,
                    })
                } else {
                    // SORTIE DE PÉRIMÈTRE : la destination n'appartient à
                    // aucun équipement ni réseau du modèle ET l'interface de
                    // sortie n'a aucun lien. L'équipement a tranché (filtres
                    // passés, route choisie) : verdict ferme `Allowed`, avec
                    // la décision explicite `ExitsModel`.
                    if let Some(last) = hops.last_mut() {
                        last.decisions.push(Decision {
                            stage: Stage::Route,
                            rule: None,
                            source: cand.source,
                            outcome: Outcome::ExitsModel {
                                iface: cand.out_iface,
                                gateway: cand.gateway,
                            },
                            shadowed_by: Vec::new(),
                        });
                    }
                    BranchStep::Done(Trace {
                        verdict: Verdict::Allowed,
                        hops,
                        diagnostics,
                    })
                }
            }
            1 => {
                let peer = peers[0];
                let peer_ok = network
                    .devices
                    .get(&peer.device)
                    .and_then(|d| d.interfaces.get(&peer.iface))
                    .map(|i| i.state == AdminState::Up);
                match peer_ok {
                    Some(true) => BranchStep::Next(Box::new(NextHopState {
                        device: peer.device.clone(),
                        iface: peer.iface.clone(),
                        pkt,
                        visited,
                        hops,
                        diagnostics,
                    })),
                    Some(false) => {
                        diagnostics.push(Diagnostic::error(
                            format!(
                                "l'extrémité distante {}/{} est désactivée",
                                peer.device, peer.iface
                            ),
                            None,
                        ));
                        BranchStep::Done(Trace {
                            verdict: Verdict::Unknown,
                            hops,
                            diagnostics,
                        })
                    }
                    None => {
                        diagnostics.push(Diagnostic::error(
                            format!(
                                "l'extrémité distante {}/{} est absente du modèle",
                                peer.device, peer.iface
                            ),
                            None,
                        ));
                        BranchStep::Done(Trace {
                            verdict: Verdict::Unknown,
                            hops,
                            diagnostics,
                        })
                    }
                }
            }
            _ => {
                diagnostics.push(Diagnostic::error(
                    format!(
                        "topologie ambiguë : plusieurs liens depuis {}/{}",
                        device.id, cand.out_iface
                    ),
                    None,
                ));
                BranchStep::Done(Trace {
                    verdict: Verdict::Unknown,
                    hops,
                    diagnostics,
                })
            }
        }
    }

    /// Évalue CHAQUE route candidate d'un ECMP comme une branche complète.
    /// Toutes les branches mènent au même verdict → ce verdict est ferme
    /// (la trace détaillée suit la PREMIÈRE branche, choix documenté) ;
    /// verdicts divergents → `Unknown` avec le verdict de chaque branche en
    /// diagnostic. Budget cumulé : [`MAX_ECMP_TOTAL_BRANCHES`].
    #[allow(clippy::too_many_arguments)]
    fn walk_ecmp(
        &mut self,
        device: &Device,
        in_zone: Option<ZoneId>,
        candidates: Vec<EcmpRoute>,
        pending_snat: Option<NatGrant>,
        pkt: ConcretePacket,
        mut hop: Hop,
        visited: BTreeSet<DeviceId>,
        mut hops: Vec<Hop>,
        mut diagnostics: Vec<Diagnostic>,
    ) -> Trace {
        let ifaces: Vec<IfaceId> = candidates.iter().map(|c| c.out_iface.clone()).collect();
        let list = ifaces
            .iter()
            .map(|i| i.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        // Position d'insertion de la décision ECMP dans le saut décideur :
        // juste avant la décision de routage de la branche retenue.
        let ingress_len = hop.decisions.len();
        let base_hops_len = hops.len();
        let base_diags_len = diagnostics.len();

        if candidates.len() > self.ecmp_budget {
            hop.decisions.push(Decision {
                stage: Stage::Route,
                rule: None,
                source: None,
                outcome: Outcome::EcmpDiverged { ifaces },
                shadowed_by: Vec::new(),
            });
            hops.push(hop);
            diagnostics.push(Diagnostic::error(
                format!(
                    "borne de bifurcation ECMP atteinte \
                     ({MAX_ECMP_TOTAL_BRANCHES} branches cumulées) : verdict indéterminé"
                ),
                None,
            ));
            return Trace {
                verdict: Verdict::Unknown,
                hops,
                diagnostics,
            };
        }
        self.ecmp_budget -= candidates.len();

        let n = candidates.len();
        let mut branches: Vec<(IfaceId, Trace)> = Vec::with_capacity(n);
        for cand in candidates {
            let iface = cand.out_iface.clone();
            let step = self.finish_branch(
                device,
                in_zone.clone(),
                cand,
                pending_snat.clone(),
                pkt,
                hop.clone(),
                visited.clone(),
                hops.clone(),
                diagnostics.clone(),
            );
            let trace = match step {
                BranchStep::Done(t) => t,
                BranchStep::Next(next) => {
                    let s = *next;
                    self.walk(s.device, s.iface, s.pkt, s.visited, s.hops, s.diagnostics)
                }
            };
            branches.push((iface, trace));
        }

        let agreed = branches
            .iter()
            .all(|(_, t)| t.verdict == branches[0].1.verdict);
        if agreed {
            // Toutes les branches mènent au même verdict : il est FERME.
            let (first_iface, mut trace) = branches.remove(0);
            if let Some(h) = trace.hops.get_mut(base_hops_len) {
                let pos = ingress_len.min(h.decisions.len());
                h.decisions.insert(
                    pos,
                    Decision {
                        stage: Stage::Route,
                        rule: None,
                        source: None,
                        outcome: Outcome::EcmpAgreed {
                            ifaces: ifaces.clone(),
                        },
                        shadowed_by: Vec::new(),
                    },
                );
            }
            trace.diagnostics.push(info(format!(
                "ECMP : {n} routes candidates ({list}), verdict identique sur toutes \
                 les branches ; la trace détaillée suit la première branche \
                 ({first_iface})"
            )));
            trace
        } else {
            // Verdicts divergents : indéterminé, avec le diagnostic
            // actionnable par branche (« wan1 : autorisé ; wan2 : refusé
            // par la règle X »).
            let details = branches
                .iter()
                .map(|(i, t)| format!("{i} : {}", branch_summary(t)))
                .collect::<Vec<_>>()
                .join(" ; ");
            hop.decisions.push(Decision {
                stage: Stage::Route,
                rule: None,
                source: None,
                outcome: Outcome::EcmpDiverged { ifaces },
                shadowed_by: Vec::new(),
            });
            hops.push(hop);
            diagnostics.push(Diagnostic::error(
                format!(
                    "routes multiples et divergentes (ECMP) vers {} : {details} — \
                     verdict indéterminé (§6.3, ne jamais deviner)",
                    pkt.dst
                ),
                None,
            ));
            // Les diagnostics propres à chaque branche restent visibles.
            for (_, t) in &branches {
                diagnostics.extend(t.diagnostics.iter().skip(base_diags_len).cloned());
            }
            Trace {
                verdict: Verdict::Unknown,
                hops,
                diagnostics,
            }
        }
    }
}

/// Libellé français du verdict d'une branche ECMP, avec la règle décisive
/// quand elle existe (« refusé par la règle 20 (fw-01.conf ligne 200) »).
fn branch_summary(trace: &Trace) -> String {
    match trace.verdict {
        Verdict::Allowed => {
            let exits = trace
                .hops
                .iter()
                .flat_map(|h| &h.decisions)
                .any(|d| matches!(d.outcome, Outcome::ExitsModel { .. }));
            if exits {
                "autorisé (sort du périmètre modélisé)".to_owned()
            } else {
                "autorisé".to_owned()
            }
        }
        Verdict::Denied => {
            let denial = trace
                .hops
                .iter()
                .rev()
                .flat_map(|h| h.decisions.iter().rev())
                .find(|d| matches!(d.outcome, Outcome::Denied | Outcome::DefaultAction));
            match denial {
                Some(d) => match (&d.rule, &d.source) {
                    (Some(r), Some(s)) => format!("refusé par la règle {r} ({s})"),
                    (Some(r), None) => format!("refusé par la règle {r}"),
                    _ => "refusé (action par défaut de la politique)".to_owned(),
                },
                None => "refusé".to_owned(),
            }
        }
        Verdict::NoRoute => "pas de route".to_owned(),
        Verdict::Loop => "boucle de routage".to_owned(),
        Verdict::Unknown => "indéterminé (voir les diagnostics)".to_owned(),
    }
}

/// Point d'entrée interne : construit le marcheur avec son budget ECMP.
fn run(
    network: &Network,
    cur_device: DeviceId,
    cur_iface: IfaceId,
    packet: &ConcretePacket,
    diagnostics: Vec<Diagnostic>,
) -> Trace {
    let mut walker = Walker {
        network,
        ecmp_budget: MAX_ECMP_TOTAL_BRANCHES,
    };
    walker.walk(
        cur_device,
        cur_iface,
        *packet,
        BTreeSet::new(),
        Vec::new(),
        diagnostics,
    )
}

/// Trace un paquet concret à travers le réseau, en localisant d'abord la
/// source (§5.1). C'est le point d'entrée principal du moteur.
pub fn trace_packet(network: &Network, packet: &ConcretePacket) -> Trace {
    let mut diagnostics = Vec::new();

    let entry = match locate_source(network, &packet.src) {
        Ok(e) => e,
        Err(d) => {
            diagnostics.push(d);
            return Trace {
                verdict: Verdict::Unknown,
                hops: Vec::new(),
                diagnostics,
            };
        }
    };

    // Source et destination sur le même réseau connecté : livraison directe
    // en couche 2, sans traverser l'équipement — sauf si la destination est
    // l'adresse d'un équipement modélisé (ses filtres s'appliquent alors).
    if entry.net.contains(&packet.dst) {
        match owner_of_address(network, &packet.dst) {
            Ok(Some((d, i))) => return run(network, d, i, packet, diagnostics),
            Ok(None) => {
                diagnostics.push(info(format!(
                    "source et destination sur le même réseau connecté {} : \
                     livraison directe sans filtrage",
                    entry.net
                )));
                return Trace {
                    verdict: Verdict::Allowed,
                    hops: Vec::new(),
                    diagnostics,
                };
            }
            Err(d) => {
                diagnostics.push(d);
                return Trace {
                    verdict: Verdict::Unknown,
                    hops: Vec::new(),
                    diagnostics,
                };
            }
        }
    }

    run(network, entry.device, entry.iface, packet, diagnostics)
}

/// Variante avec point d'entrée explicite (utile quand la localisation
/// automatique de la source est ambiguë).
pub fn trace_packet_from(network: &Network, entry: &Endpoint, packet: &ConcretePacket) -> Trace {
    let valid = network
        .devices
        .get(&entry.device)
        .and_then(|d| d.interfaces.get(&entry.iface))
        .map(|i| i.state == AdminState::Up)
        .unwrap_or(false);
    if !valid {
        return Trace {
            verdict: Verdict::Unknown,
            hops: Vec::new(),
            diagnostics: vec![Diagnostic::error(
                format!(
                    "point d'entrée {}/{} absent du modèle ou désactivé",
                    entry.device, entry.iface
                ),
                None,
            )],
        };
    }
    run(
        network,
        entry.device.clone(),
        entry.iface.clone(),
        packet,
        Vec::new(),
    )
}

// ---------------------------------------------------------------------------
// Tests d'intégration sur un petit réseau construit à la main :
//
//   [hôtes 10.0.10.0/24] — lan[fw1]wan —— wan2[fw2]dmz — [hôtes 10.0.20.0/24]
//                            192.168.0.0/30
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use calque_model::{
        Action, AddrExpr, AddrObject, DnatTarget, Interface, Link, LinkOrigin, NatAction, ObjectId,
        Policy, PolicyId, PortRange, Route, RouteOrigin, Rule, RuleId, RuleMatch, Service,
        ServiceExpr, SourceSpan, Vendor, Vrf, VrfId,
    };

    fn ip(s: &str) -> IpAddr {
        s.parse().expect("adresse IP de test")
    }

    fn net(s: &str) -> IpNet {
        s.parse().expect("préfixe de test")
    }

    fn span(line: u32) -> SourceSpan {
        SourceSpan::new("fw-01.conf", line)
    }

    fn tcp(src: &str, dst: &str, dport: u16) -> ConcretePacket {
        ConcretePacket {
            src: ip(src),
            dst: ip(dst),
            proto: 6,
            sport: 40000,
            dport,
        }
    }

    fn iface(id: &str, addr: &str, zone: Option<&str>) -> Interface {
        let mut i = Interface::new(IfaceId::new(id));
        i.addrs = vec![net(addr)];
        i.zone = zone.map(ZoneId::new);
        i
    }

    #[allow(clippy::too_many_arguments)]
    fn rule(
        id: &str,
        src: Vec<AddrExpr>,
        dst: Vec<AddrExpr>,
        services: Vec<ServiceExpr>,
        from: Option<&str>,
        to: Option<&str>,
        action: Action,
        line: u32,
    ) -> Rule {
        Rule {
            id: RuleId::new(id),
            matches: RuleMatch { src, dst, services },
            from: from.map(ZoneId::new),
            to: to.map(ZoneId::new),
            action,
            source: span(line),
        }
    }

    fn tcp_svc(dport: u16) -> ServiceExpr {
        ServiceExpr::Service(Service::tcp_dport(PortRange::single(dport)))
    }

    /// Le réseau de base à deux équipements, sans aucune politique accrochée.
    fn base_network() -> Network {
        let mut fw1 = Device::new(DeviceId::new("fw1"), Vendor::Fortigate);
        for i in [
            iface("lan", "10.0.10.1/24", Some("lan")),
            iface("wan", "192.168.0.1/30", Some("wan")),
        ] {
            fw1.interfaces.insert(i.id.clone(), i);
        }
        fw1.vrfs.insert(
            VrfId::default_vrf(),
            Vrf {
                routes: vec![
                    Route {
                        prefix: net("10.0.20.0/24"),
                        next_hop: calque_model::NextHop::Ip(ip("192.168.0.2")),
                        metric: 10,
                        origin: RouteOrigin::Static,
                        source: Some(span(812)),
                    },
                    Route {
                        prefix: net("10.0.66.0/24"),
                        next_hop: calque_model::NextHop::Drop,
                        metric: 10,
                        origin: RouteOrigin::Static,
                        source: Some(span(820)),
                    },
                ],
            },
        );

        let mut fw2 = Device::new(DeviceId::new("fw2"), Vendor::Fortigate);
        for i in [
            iface("wan2", "192.168.0.2/30", None),
            iface("dmz", "10.0.20.1/24", Some("dmz")),
        ] {
            fw2.interfaces.insert(i.id.clone(), i);
        }
        fw2.vrfs.insert(VrfId::default_vrf(), Vrf::default());

        let mut network = Network::default();
        network.devices.insert(fw1.id.clone(), fw1);
        network.devices.insert(fw2.id.clone(), fw2);
        network.links.push(Link {
            a: Endpoint {
                device: DeviceId::new("fw1"),
                iface: IfaceId::new("wan"),
            },
            b: Endpoint {
                device: DeviceId::new("fw2"),
                iface: IfaceId::new("wan2"),
            },
            origin: LinkOrigin::Declared,
        });
        network
    }

    /// Accroche une politique de SORTIE sur fw1.
    fn with_fw1_egress(rules: Vec<Rule>, default_action: Action) -> Network {
        let mut network = base_network();
        let fw1 = network.devices.get_mut(&DeviceId::new("fw1")).expect("fw1");
        let pid = PolicyId::new("fw1-out");
        fw1.policies.insert(
            pid.clone(),
            Policy {
                id: pid.clone(),
                rules,
                default_action,
            },
        );
        fw1.pipeline.egress.push(pid);
        network
    }

    fn find_decision(trace: &Trace, pred: impl Fn(&Decision) -> bool) -> Option<&Decision> {
        trace
            .hops
            .iter()
            .flat_map(|h| &h.decisions)
            .find(|d| pred(d))
    }

    /// La politique « standard » des tests : autorise le flux SMB vers le
    /// serveur de fichiers, refuse telnet explicitement, refuse le reste.
    fn standard_rules() -> Vec<Rule> {
        vec![
            rule(
                "10",
                vec![AddrExpr::Net(net("10.0.10.0/24"))],
                vec![AddrExpr::Net(net("10.0.20.5/32"))],
                vec![tcp_svc(445)],
                Some("lan"),
                Some("wan"),
                Action::Accept,
                100,
            ),
            rule(
                "20",
                vec![],
                vec![],
                vec![tcp_svc(23)],
                None,
                None,
                Action::Deny,
                200,
            ),
        ]
    }

    #[test]
    fn flux_autorise_par_la_bonne_regle() {
        let network = with_fw1_egress(standard_rules(), Action::Deny);
        let trace = trace_packet(&network, &tcp("10.0.10.5", "10.0.20.5", 445));
        assert_eq!(trace.verdict, Verdict::Allowed);
        // Deux sauts : fw1 puis fw2.
        assert_eq!(trace.hops.len(), 2);
        assert_eq!(trace.hops[0].device, DeviceId::new("fw1"));
        assert_eq!(trace.hops[1].device, DeviceId::new("fw2"));
        assert_eq!(trace.hops[1].out_iface, Some(IfaceId::new("dmz")));
        // La règle décisive est la 10, au filtre de sortie de fw1.
        let d = find_decision(&trace, |d| d.rule == Some(RuleId::new("10")))
            .expect("décision de la règle 10");
        assert_eq!(d.stage, Stage::EgressFilter);
        assert_eq!(d.outcome, Outcome::Accepted);
        assert!(d.shadowed_by.is_empty());
    }

    #[test]
    fn flux_refuse_avec_regle_et_span() {
        let network = with_fw1_egress(standard_rules(), Action::Deny);
        let trace = trace_packet(&network, &tcp("10.0.10.5", "10.0.20.5", 23));
        assert_eq!(trace.verdict, Verdict::Denied);
        assert_eq!(trace.hops.len(), 1); // arrêt sur fw1
        let d = find_decision(&trace, |d| d.outcome == Outcome::Denied).expect("décision de refus");
        assert_eq!(d.rule, Some(RuleId::new("20")));
        // Le SourceSpan pointe la ligne de configuration responsable.
        assert_eq!(d.source, Some(span(200)));
        // Refusé APRÈS routage : l'interface de sortie est connue.
        assert_eq!(trace.hops[0].out_iface, Some(IfaceId::new("wan")));
    }

    #[test]
    fn regle_masquee_apparait_dans_shadowed_by() {
        // La règle 5 (refus large) masque la règle 10 (autorisation) :
        // le cas qui fait perdre le plus de temps aux administrateurs.
        let mut rules = vec![rule(
            "5",
            vec![AddrExpr::Net(net("10.0.10.0/24"))],
            vec![],
            vec![],
            None,
            None,
            Action::Deny,
            50,
        )];
        rules.extend(standard_rules());
        let network = with_fw1_egress(rules, Action::Deny);
        let trace = trace_packet(&network, &tcp("10.0.10.5", "10.0.20.5", 445));
        assert_eq!(trace.verdict, Verdict::Denied);
        // Décisive : la règle 5.
        let decisive =
            find_decision(&trace, |d| d.outcome == Outcome::Denied).expect("décision de refus");
        assert_eq!(decisive.rule, Some(RuleId::new("5")));
        assert_eq!(decisive.source, Some(span(50)));
        // La règle 10 correspond aussi mais est masquée par la 5.
        let shadowed = find_decision(&trace, |d| d.rule == Some(RuleId::new("10")))
            .expect("décision informationnelle de la règle 10");
        assert_eq!(shadowed.outcome, Outcome::Matched);
        assert_eq!(shadowed.shadowed_by, vec![RuleId::new("5")]);
    }

    #[test]
    fn pas_de_route() {
        let network = base_network();
        let trace = trace_packet(&network, &tcp("10.0.10.5", "10.0.99.5", 445));
        assert_eq!(trace.verdict, Verdict::NoRoute);
        assert_eq!(trace.hops.len(), 1);
        let d = find_decision(&trace, |d| d.stage == Stage::Route).expect("décision de routage");
        assert_eq!(d.outcome, Outcome::NoRoute);
    }

    #[test]
    fn route_de_rejet_explicite() {
        let network = base_network();
        let trace = trace_packet(&network, &tcp("10.0.10.5", "10.0.66.9", 445));
        // Choix documenté : blackhole → verdict NoRoute + décision RouteDrop.
        assert_eq!(trace.verdict, Verdict::NoRoute);
        let d =
            find_decision(&trace, |d| d.outcome == Outcome::RouteDrop).expect("décision RouteDrop");
        assert_eq!(d.source, Some(span(820)));
    }

    #[test]
    fn boucle_de_routage_detectee() {
        let mut network = base_network();
        // fw1 et fw2 se renvoient 10.0.30.0/24 l'un à l'autre.
        network
            .devices
            .get_mut(&DeviceId::new("fw1"))
            .and_then(|d| d.vrfs.get_mut(&VrfId::default_vrf()))
            .expect("vrf fw1")
            .routes
            .push(Route {
                prefix: net("10.0.30.0/24"),
                next_hop: calque_model::NextHop::Ip(ip("192.168.0.2")),
                metric: 10,
                origin: RouteOrigin::Static,
                source: None,
            });
        network
            .devices
            .get_mut(&DeviceId::new("fw2"))
            .and_then(|d| d.vrfs.get_mut(&VrfId::default_vrf()))
            .expect("vrf fw2")
            .routes
            .push(Route {
                prefix: net("10.0.30.0/24"),
                next_hop: calque_model::NextHop::Ip(ip("192.168.0.1")),
                metric: 10,
                origin: RouteOrigin::Static,
                source: None,
            });
        let trace = trace_packet(&network, &tcp("10.0.10.5", "10.0.30.7", 445));
        assert_eq!(trace.verdict, Verdict::Loop);
        assert_eq!(trace.hops.len(), 2); // fw1 puis fw2, puis retour détecté
        assert!(!trace.diagnostics.is_empty());
    }

    #[test]
    fn nat_destination_reecrit_l_en_tete() {
        let mut network = base_network();
        let fw1 = network.devices.get_mut(&DeviceId::new("fw1")).expect("fw1");
        let pid = PolicyId::new("fw1-vip");
        fw1.policies.insert(
            pid.clone(),
            Policy {
                id: pid.clone(),
                rules: vec![rule(
                    "1",
                    vec![],
                    vec![AddrExpr::Net(net("203.0.113.10/32"))],
                    vec![tcp_svc(80)],
                    None,
                    None,
                    Action::Nat(NatAction {
                        snat: None,
                        dnat: Some(DnatTarget {
                            addr: ip("10.0.20.5"),
                            port: Some(8080),
                        }),
                    }),
                    300,
                )],
                default_action: Action::Accept,
            },
        );
        fw1.pipeline.ingress.push(pid);

        let trace = trace_packet(&network, &tcp("10.0.10.5", "203.0.113.10", 80));
        assert_eq!(trace.verdict, Verdict::Allowed);
        // header_in / header_out du saut fw1 reflètent la réécriture.
        assert_eq!(trace.hops[0].header_in.dst, ip("203.0.113.10"));
        assert_eq!(trace.hops[0].header_in.dport, 80);
        assert_eq!(trace.hops[0].header_out.dst, ip("10.0.20.5"));
        assert_eq!(trace.hops[0].header_out.dport, 8080);
        // Le saut suivant voit l'en-tête traduit.
        assert_eq!(trace.hops[1].header_in.dst, ip("10.0.20.5"));
        // Une décision NAT tracée avec la règle responsable.
        let d = find_decision(&trace, |d| d.stage == Stage::Nat).expect("décision NAT");
        assert_eq!(d.rule, Some(RuleId::new("1")));
        assert_eq!(d.outcome, Outcome::Rewritten);
    }

    #[test]
    fn nat_source_apres_filtre_de_sortie() {
        let rules = vec![rule(
            "30",
            vec![],
            vec![],
            vec![],
            None,
            None,
            Action::Nat(NatAction {
                snat: Some(net("198.51.100.1/32")),
                dnat: None,
            }),
            400,
        )];
        let network = with_fw1_egress(rules, Action::Deny);
        let trace = trace_packet(&network, &tcp("10.0.10.5", "10.0.20.5", 445));
        assert_eq!(trace.verdict, Verdict::Allowed);
        assert_eq!(trace.hops[0].header_in.src, ip("10.0.10.5"));
        assert_eq!(trace.hops[0].header_out.src, ip("198.51.100.1"));
        assert_eq!(trace.hops[1].header_in.src, ip("198.51.100.1"));
    }

    #[test]
    fn groupe_d_objets_imbrique_resolu_tardivement() {
        let mut rules = standard_rules();
        // La règle 10 référence un groupe qui contient un objet réseau.
        rules[0].matches.src = vec![AddrExpr::Object(ObjectId::new("GRP-INTERNES"))];
        let mut network = with_fw1_egress(rules, Action::Deny);
        let fw1 = network.devices.get_mut(&DeviceId::new("fw1")).expect("fw1");
        fw1.objects.addresses.insert(
            ObjectId::new("NET-INTERNES"),
            AddrObject::Nets(vec![net("10.0.10.0/24")]),
        );
        fw1.objects.addresses.insert(
            ObjectId::new("GRP-INTERNES"),
            AddrObject::Group(vec![ObjectId::new("NET-INTERNES")]),
        );
        let trace = trace_packet(&network, &tcp("10.0.10.5", "10.0.20.5", 445));
        assert_eq!(trace.verdict, Verdict::Allowed);
        let d = find_decision(&trace, |d| d.rule == Some(RuleId::new("10")))
            .expect("décision de la règle 10");
        assert_eq!(d.outcome, Outcome::Accepted);
    }

    #[test]
    fn cycle_de_groupes_rend_unknown() {
        let mut rules = standard_rules();
        rules[0].matches.src = vec![AddrExpr::Object(ObjectId::new("A"))];
        let mut network = with_fw1_egress(rules, Action::Deny);
        let fw1 = network.devices.get_mut(&DeviceId::new("fw1")).expect("fw1");
        fw1.objects.addresses.insert(
            ObjectId::new("A"),
            AddrObject::Group(vec![ObjectId::new("B")]),
        );
        fw1.objects.addresses.insert(
            ObjectId::new("B"),
            AddrObject::Group(vec![ObjectId::new("A")]),
        );
        let trace = trace_packet(&network, &tcp("10.0.10.5", "10.0.20.5", 445));
        // Ne jamais deviner : cycle → verdict Unknown + diagnostic.
        assert_eq!(trace.verdict, Verdict::Unknown);
        assert!(trace
            .diagnostics
            .iter()
            .any(|d| d.message.contains("cycle")));
    }

    #[test]
    fn zone_non_correspondante_tombe_sur_l_action_par_defaut() {
        // La règle n'accepte que depuis la zone « guest » : le flux depuis
        // « lan » tombe sur l'action par défaut (refus).
        let rules = vec![rule(
            "40",
            vec![],
            vec![],
            vec![],
            Some("guest"),
            None,
            Action::Accept,
            500,
        )];
        let network = with_fw1_egress(rules, Action::Deny);
        let trace = trace_packet(&network, &tcp("10.0.10.5", "10.0.20.5", 445));
        assert_eq!(trace.verdict, Verdict::Denied);
        let d = find_decision(&trace, |d| d.outcome == Outcome::DefaultAction)
            .expect("décision par défaut");
        assert_eq!(d.rule, None);
    }

    #[test]
    fn meme_sous_reseau_livraison_directe() {
        let network = base_network();
        let trace = trace_packet(&network, &tcp("10.0.10.5", "10.0.10.9", 445));
        assert_eq!(trace.verdict, Verdict::Allowed);
        assert!(trace.hops.is_empty());
    }

    #[test]
    fn source_introuvable_rend_unknown() {
        let network = base_network();
        let trace = trace_packet(&network, &tcp("172.16.0.5", "10.0.20.5", 445));
        assert_eq!(trace.verdict, Verdict::Unknown);
        assert!(!trace.diagnostics.is_empty());
    }

    #[test]
    fn destination_portee_par_un_equipement() {
        // 10.0.20.1 est l'adresse de fw2/dmz : livraison locale sur fw2.
        let network = base_network();
        let trace = trace_packet(&network, &tcp("10.0.10.5", "10.0.20.1", 22));
        assert_eq!(trace.verdict, Verdict::Allowed);
        assert_eq!(trace.hops.len(), 2);
        assert_eq!(trace.hops[1].device, DeviceId::new("fw2"));
        assert_eq!(trace.hops[1].out_iface, None); // livraison locale
    }

    // -----------------------------------------------------------------------
    // Sortie de périmètre modélisé et ECMP par branches.
    //
    // Le réseau à UN équipement (cas réel : un FortiGate de collectivité) :
    //
    //   [hôtes 10.0.10.0/24] — lan[fw]wan1 → passerelle 198.51.100.1 (hors
    //   modèle, aucun lien)
    // -----------------------------------------------------------------------

    /// Le pare-feu seul : lan + wan1, route par défaut vers une passerelle
    /// hors modèle, aucun lien.
    fn single_device_network() -> Network {
        let mut fw = Device::new(DeviceId::new("fw"), Vendor::Fortigate);
        for i in [
            iface("lan", "10.0.10.1/24", Some("lan")),
            iface("wan1", "198.51.100.2/30", Some("wan")),
        ] {
            fw.interfaces.insert(i.id.clone(), i);
        }
        fw.vrfs.insert(
            VrfId::default_vrf(),
            Vrf {
                routes: vec![Route {
                    prefix: net("0.0.0.0/0"),
                    next_hop: calque_model::NextHop::Ip(ip("198.51.100.1")),
                    metric: 10,
                    origin: RouteOrigin::Static,
                    source: Some(span(900)),
                }],
            },
        );
        let mut network = Network::default();
        network.devices.insert(fw.id.clone(), fw);
        network
    }

    /// Accroche une politique de SORTIE sur l'équipement « fw ».
    fn with_fw_egress(mut network: Network, rules: Vec<Rule>, default_action: Action) -> Network {
        let fw = network.devices.get_mut(&DeviceId::new("fw")).expect("fw");
        let pid = PolicyId::new("fw-out");
        fw.policies.insert(
            pid.clone(),
            Policy {
                id: pid.clone(),
                rules,
                default_action,
            },
        );
        fw.pipeline.egress.push(pid);
        network
    }

    /// La décision ExitsModel d'une trace, si elle existe.
    fn exits_decision(trace: &Trace) -> Option<&Decision> {
        find_decision(trace, |d| matches!(d.outcome, Outcome::ExitsModel { .. }))
    }

    /// (a) Un flux routé vers l'extérieur du modèle : l'équipement A tranché
    /// (filtre passé, route choisie), le verdict est FERME — `Allowed` avec
    /// la décision explicite « sort du périmètre modélisé via wan1 ».
    #[test]
    fn sortie_de_perimetre_autorisee_via_wan() {
        let network = with_fw_egress(
            single_device_network(),
            vec![rule(
                "10",
                vec![AddrExpr::Net(net("10.0.10.0/24"))],
                vec![],
                vec![tcp_svc(443)],
                Some("lan"),
                Some("wan"),
                Action::Accept,
                100,
            )],
            Action::Deny,
        );
        let trace = trace_packet(&network, &tcp("10.0.10.5", "203.0.113.50", 443));
        assert_eq!(trace.verdict, Verdict::Allowed);
        assert_eq!(trace.hops.len(), 1);
        assert_eq!(trace.hops[0].out_iface, Some(IfaceId::new("wan1")));
        let d = exits_decision(&trace).expect("décision ExitsModel");
        assert_eq!(
            d.outcome,
            Outcome::ExitsModel {
                iface: IfaceId::new("wan1"),
                gateway: Some(ip("198.51.100.1")),
            }
        );
        // Le libellé rendu dit clairement la sortie de périmètre.
        assert_eq!(
            d.outcome.to_string(),
            "sort du périmètre modélisé via wan1 (passerelle 198.51.100.1)"
        );
        // La règle décisive reste tracée.
        let accept = find_decision(&trace, |d| d.outcome == Outcome::Accepted)
            .expect("décision d'acceptation");
        assert_eq!(accept.rule, Some(RuleId::new("10")));
    }

    /// (a) Le même flux refusé par le filtre de sortie : `Denied` normal,
    /// sans décision de sortie de périmètre.
    #[test]
    fn sortie_de_perimetre_refusee_par_le_filtre() {
        let network = with_fw_egress(single_device_network(), vec![], Action::Deny);
        let trace = trace_packet(&network, &tcp("10.0.10.5", "203.0.113.50", 443));
        assert_eq!(trace.verdict, Verdict::Denied);
        assert!(exits_decision(&trace).is_none());
    }

    /// (b) Interface tunnel sans adresse ni lien (le cas IPsec) + route par
    /// objet vers le réseau distant : `Allowed` avec ExitsModel via le
    /// tunnel, sans passerelle.
    #[test]
    fn sortie_de_perimetre_via_tunnel_sans_adresse() {
        let mut network = single_device_network();
        let fw = network.devices.get_mut(&DeviceId::new("fw")).expect("fw");
        // Tunnel : aucune adresse, aucune zone, aucun lien.
        let tunnel = Interface::new(IfaceId::new("vpn-siteb"));
        fw.interfaces.insert(tunnel.id.clone(), tunnel);
        fw.vrfs
            .get_mut(&VrfId::default_vrf())
            .expect("vrf")
            .routes
            .push(Route {
                prefix: net("192.168.100.0/24"),
                next_hop: calque_model::NextHop::Interface(IfaceId::new("vpn-siteb")),
                metric: 10,
                origin: RouteOrigin::Static,
                source: Some(span(910)),
            });
        let network = with_fw_egress(network, vec![], Action::Accept);

        let trace = trace_packet(&network, &tcp("10.0.10.5", "192.168.100.20", 445));
        assert_eq!(trace.verdict, Verdict::Allowed);
        let d = exits_decision(&trace).expect("décision ExitsModel");
        assert_eq!(
            d.outcome,
            Outcome::ExitsModel {
                iface: IfaceId::new("vpn-siteb"),
                gateway: None,
            }
        );
        assert_eq!(d.source, Some(span(910))); // la route responsable
    }

    /// (c) Non-régression : un vrai trou de topologie INTERNE (destination
    /// portée par un équipement du modèle, mais aucun lien pour l'atteindre)
    /// reste `Unknown` — jamais transformé en « autorisé ».
    #[test]
    fn trou_de_topologie_interne_reste_unknown() {
        let mut network = with_fw1_egress(vec![], Action::Accept);
        network.links.clear(); // fw1 et fw2 ne sont plus reliés

        // 10.0.20.1 est PORTÉE par fw2/dmz : trou interne.
        let trace = trace_packet(&network, &tcp("10.0.10.5", "10.0.20.1", 445));
        assert_eq!(trace.verdict, Verdict::Unknown);
        assert!(trace
            .diagnostics
            .iter()
            .any(|d| d.message.contains("topologie incomplète")));
        assert!(exits_decision(&trace).is_none());

        // 10.0.20.7 n'est portée par personne mais appartient au réseau
        // modélisé 10.0.20.0/24 (fw2/dmz) : toujours un trou interne.
        let trace = trace_packet(&network, &tcp("10.0.10.5", "10.0.20.7", 445));
        assert_eq!(trace.verdict, Verdict::Unknown);
        assert!(exits_decision(&trace).is_none());
    }

    /// Le pare-feu seul en ECMP : deux routes par défaut divergentes
    /// (wan1 et wan2 — le cas réel : route par défaut SD-WAN à 2 membres).
    fn ecmp_network() -> Network {
        let mut network = single_device_network();
        let fw = network.devices.get_mut(&DeviceId::new("fw")).expect("fw");
        let wan2 = iface("wan2", "203.0.113.2/30", Some("wan2z"));
        fw.interfaces.insert(wan2.id.clone(), wan2);
        fw.vrfs
            .get_mut(&VrfId::default_vrf())
            .expect("vrf")
            .routes
            .push(Route {
                prefix: net("0.0.0.0/0"),
                next_hop: calque_model::NextHop::Ip(ip("203.0.113.1")),
                metric: 10, // même préfixe, même métrique : ECMP
                origin: RouteOrigin::Static,
                source: Some(span(901)),
            });
        network
    }

    /// (d) ECMP dont TOUTES les branches mènent au même verdict : le verdict
    /// est ferme, la décision `EcmpAgreed` liste les interfaces, et la trace
    /// détaillée suit la première branche (documenté).
    #[test]
    fn ecmp_verdict_identique_est_ferme() {
        let network = with_fw_egress(ecmp_network(), vec![], Action::Accept);
        let trace = trace_packet(&network, &tcp("10.0.10.5", "8.8.8.8", 443));
        assert_eq!(trace.verdict, Verdict::Allowed);
        // La décision ECMP liste les deux interfaces candidates.
        let d = find_decision(&trace, |d| matches!(d.outcome, Outcome::EcmpAgreed { .. }))
            .expect("décision EcmpAgreed");
        assert_eq!(
            d.outcome,
            Outcome::EcmpAgreed {
                ifaces: vec![IfaceId::new("wan1"), IfaceId::new("wan2")],
            }
        );
        // Le saut retenu est la première branche (wan1), documenté par un
        // diagnostic informatif.
        assert_eq!(trace.hops[0].out_iface, Some(IfaceId::new("wan1")));
        assert!(trace
            .diagnostics
            .iter()
            .any(|d| d.severity == Severity::Info && d.message.contains("première branche")));
        // Les deux branches sortent du périmètre : la première est tracée.
        assert!(exits_decision(&trace).is_some());
    }

    /// (d) ECMP aux verdicts DIVERGENTS (une branche filtrée en sortie,
    /// l'autre non) : `Unknown`, avec chaque branche et son verdict dans les
    /// diagnostics — l'information actionnable.
    #[test]
    fn ecmp_verdicts_divergents_rend_unknown_diagnostique() {
        // Refus explicite vers la zone de wan2 ; le reste passe.
        let network = with_fw_egress(
            ecmp_network(),
            vec![rule(
                "50",
                vec![],
                vec![],
                vec![],
                None,
                Some("wan2z"),
                Action::Deny,
                500,
            )],
            Action::Accept,
        );
        let trace = trace_packet(&network, &tcp("10.0.10.5", "8.8.8.8", 443));
        assert_eq!(trace.verdict, Verdict::Unknown);
        let d = find_decision(&trace, |d| {
            matches!(d.outcome, Outcome::EcmpDiverged { .. })
        })
        .expect("décision EcmpDiverged");
        assert_eq!(
            d.outcome,
            Outcome::EcmpDiverged {
                ifaces: vec![IfaceId::new("wan1"), IfaceId::new("wan2")],
            }
        );
        // Le diagnostic liste chaque branche et son verdict, règle comprise.
        let diag = trace
            .diagnostics
            .iter()
            .find(|d| d.message.contains("divergentes"))
            .expect("diagnostic ECMP divergent");
        assert!(
            diag.message.contains("wan1 : autorisé"),
            "branche wan1 : {}",
            diag.message
        );
        assert!(
            diag.message
                .contains("wan2 : refusé par la règle 50 (fw-01.conf ligne 500)"),
            "branche wan2 : {}",
            diag.message
        );
    }
}
