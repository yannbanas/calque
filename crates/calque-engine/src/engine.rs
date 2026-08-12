//! Le moteur d'accessibilité concret (§5.1).
//!
//! Séquence par équipement (§3.1) :
//! entrée → filtre d'entrée → DNAT → routage → filtre de sortie → SNAT → sortie.
//!
//! Arrêts : refus (règle responsable), pas de route, boucle (équipement déjà
//! visité), destination atteinte (adresse portée par un équipement, ou sortie
//! vers un réseau directement connecté qui la contient), ou `Unknown` quand
//! un élément du chemin manque ou est ambigu (§6.3 : ne jamais deviner).

use std::collections::BTreeSet;
use std::net::IpAddr;

use calque_model::{
    AdminState, ConcretePacket, Device, DeviceId, Diagnostic, Endpoint, IfaceId, Network, Severity,
    ZoneId,
};
use ipnet::IpNet;

use crate::error::EvalError;
use crate::policy::{evaluate_policy, FilterPoint, FilterResult, NatGrant};
use crate::route::{lookup_route, RouteDecision};
use crate::trace::{Decision, Hop, Outcome, Stage, Trace, Verdict};

/// Résultat de la traversée d'un seul équipement.
enum DeviceOutcome {
    Denied,
    /// L'équipement porte l'adresse destination : livraison locale.
    LocalDelivery,
    /// Le paquet ressort par cette interface.
    Forwarded {
        out_iface: IfaceId,
    },
    /// Aucune route (ou route de rejet, documentée dans les décisions).
    NoRoute,
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

/// Le lien physique partant de (équipement, interface). Aucun lien ou liens
/// multiples → diagnostic (topologie incomplète ou ambiguë).
fn find_link<'a>(
    network: &'a Network,
    device: &DeviceId,
    iface: &IfaceId,
) -> Result<&'a Endpoint, Diagnostic> {
    let mut peers: Vec<&Endpoint> = Vec::new();
    for link in &network.links {
        if link.a.device == *device && link.a.iface == *iface {
            peers.push(&link.b);
        } else if link.b.device == *device && link.b.iface == *iface {
            peers.push(&link.a);
        }
    }
    match peers.len() {
        0 => Err(Diagnostic::error(
            format!("topologie incomplète : aucun lien depuis {device}/{iface}"),
            None,
        )),
        1 => Ok(peers[0]),
        _ => Err(Diagnostic::error(
            format!("topologie ambiguë : plusieurs liens depuis {device}/{iface}"),
            None,
        )),
    }
}

/// Traverse UN équipement, en remplissant `hop` et en réécrivant `pkt`
/// (NAT). La séquence est celle de §3.1.
fn process_device(
    device: &Device,
    in_iface_id: &IfaceId,
    pkt: &mut ConcretePacket,
    hop: &mut Hop,
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<DeviceOutcome, EvalError> {
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
            FilterResult::Deny => return Ok(DeviceOutcome::Denied),
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
        return Ok(DeviceOutcome::LocalDelivery);
    }

    // --- Routage ----------------------------------------------------------
    match lookup_route(device, &in_iface.vrf, &pkt.dst)? {
        RouteDecision::NoRoute => {
            hop.decisions.push(Decision {
                stage: Stage::Route,
                rule: None,
                source: None,
                outcome: Outcome::NoRoute,
                shadowed_by: Vec::new(),
            });
            Ok(DeviceOutcome::NoRoute)
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
            Ok(DeviceOutcome::NoRoute)
        }
        RouteDecision::Forward {
            out_iface, source, ..
        } => {
            hop.decisions.push(Decision {
                stage: Stage::Route,
                rule: None,
                source,
                outcome: Outcome::RouteFound,
                shadowed_by: Vec::new(),
            });
            hop.out_iface = Some(out_iface.clone());

            // --- Filtres de sortie (zones d'entrée ET de sortie connues) --
            let egress_point = FilterPoint::Egress {
                in_zone,
                out_zone: zone_of(device, &out_iface),
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
                    FilterResult::Deny => return Ok(DeviceOutcome::Denied),
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

            // --- SNAT : réécriture de la source APRÈS le filtre de sortie -
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

            Ok(DeviceOutcome::Forwarded { out_iface })
        }
    }
}

/// La boucle de propagation (§5.1), à partir d'un point d'entrée connu.
fn run(
    network: &Network,
    mut cur_device: DeviceId,
    mut cur_iface: IfaceId,
    packet: &ConcretePacket,
    mut diagnostics: Vec<Diagnostic>,
) -> Trace {
    let mut pkt = *packet;
    let mut hops: Vec<Hop> = Vec::new();
    let mut visited: BTreeSet<DeviceId> = BTreeSet::new();

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
        let outcome = process_device(device, &cur_iface, &mut pkt, &mut hop, &mut diagnostics);
        hop.header_out = pkt;

        match outcome {
            Err(e) => {
                diagnostics.push(e.to_diagnostic());
                hops.push(hop);
                return Trace {
                    verdict: Verdict::Unknown,
                    hops,
                    diagnostics,
                };
            }
            Ok(DeviceOutcome::Denied) => {
                hops.push(hop);
                return Trace {
                    verdict: Verdict::Denied,
                    hops,
                    diagnostics,
                };
            }
            Ok(DeviceOutcome::LocalDelivery) => {
                hops.push(hop);
                return Trace {
                    verdict: Verdict::Allowed,
                    hops,
                    diagnostics,
                };
            }
            Ok(DeviceOutcome::NoRoute) => {
                hops.push(hop);
                return Trace {
                    verdict: Verdict::NoRoute,
                    hops,
                    diagnostics,
                };
            }
            Ok(DeviceOutcome::Forwarded { out_iface }) => {
                hops.push(hop);

                // Destination sur un réseau directement connecté à la sortie ?
                let delivered = device
                    .interfaces
                    .get(&out_iface)
                    .map(|o| o.addrs.iter().any(|a| a.contains(&pkt.dst)))
                    .unwrap_or(false);
                if delivered {
                    match owner_of_address(network, &pkt.dst) {
                        // L'adresse est portée par un équipement modélisé :
                        // on y entre (ses filtres s'appliquent).
                        Ok(Some((d, i))) => {
                            cur_device = d;
                            cur_iface = i;
                            continue;
                        }
                        // Hôte non modélisé du réseau connecté : atteint.
                        Ok(None) => {
                            return Trace {
                                verdict: Verdict::Allowed,
                                hops,
                                diagnostics,
                            }
                        }
                        Err(d) => {
                            diagnostics.push(d);
                            return Trace {
                                verdict: Verdict::Unknown,
                                hops,
                                diagnostics,
                            };
                        }
                    }
                }

                // Sinon : traverser le lien physique vers l'équipement suivant.
                match find_link(network, &cur_device, &out_iface) {
                    Ok(peer) => {
                        let peer_ok = network
                            .devices
                            .get(&peer.device)
                            .and_then(|d| d.interfaces.get(&peer.iface))
                            .map(|i| i.state == AdminState::Up);
                        match peer_ok {
                            Some(true) => {
                                cur_device = peer.device.clone();
                                cur_iface = peer.iface.clone();
                            }
                            Some(false) => {
                                diagnostics.push(Diagnostic::error(
                                    format!(
                                        "l'extrémité distante {}/{} est désactivée",
                                        peer.device, peer.iface
                                    ),
                                    None,
                                ));
                                return Trace {
                                    verdict: Verdict::Unknown,
                                    hops,
                                    diagnostics,
                                };
                            }
                            None => {
                                diagnostics.push(Diagnostic::error(
                                    format!(
                                        "l'extrémité distante {}/{} est absente du modèle",
                                        peer.device, peer.iface
                                    ),
                                    None,
                                ));
                                return Trace {
                                    verdict: Verdict::Unknown,
                                    hops,
                                    diagnostics,
                                };
                            }
                        }
                    }
                    Err(d) => {
                        diagnostics.push(d);
                        return Trace {
                            verdict: Verdict::Unknown,
                            hops,
                            diagnostics,
                        };
                    }
                }
            }
        }
    }
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
}
