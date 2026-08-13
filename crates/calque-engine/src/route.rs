//! Recherche de route : plus long préfixe correspondant dans le VRF,
//! départage par métrique.
//!
//! En plus des routes déclarées, le moteur dérive les routes CONNECTÉES des
//! adresses d'interfaces actives du VRF (métrique 0) : c'est la sémantique
//! standard d'un routeur, pas une supposition.

use std::net::IpAddr;

use calque_model::{AdminState, Device, IfaceId, NextHop, SourceSpan, VrfId};
use ipnet::IpNet;

use crate::error::EvalError;

/// Nombre maximal de routes optimales divergentes (ECMP) évaluées PAR
/// BRANCHES lors d'une même recherche de route. Au-delà : erreur
/// [`EvalError::EcmpTooWide`] → verdict `Unknown` diagnostiqué, jamais une
/// évaluation partielle silencieuse.
pub const MAX_ECMP_ROUTES: usize = 8;

/// Une route candidate résolue (interface de sortie + passerelle
/// éventuelle). Une recherche en rend UNE en temps normal, plusieurs en cas
/// d'ECMP — chacune est alors évaluée comme une branche.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EcmpRoute {
    pub out_iface: IfaceId,
    /// Prochain saut IP, absent pour une route d'interface ou connectée.
    pub gateway: Option<IpAddr>,
    pub source: Option<SourceSpan>,
}

/// Le résultat d'une recherche de route.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteDecision {
    Forward {
        out_iface: IfaceId,
        /// Prochain saut IP, absent pour une route d'interface ou connectée.
        gateway: Option<IpAddr>,
        prefix: IpNet,
        source: Option<SourceSpan>,
    },
    /// Plusieurs routes optimales divergentes (ECMP — cas réel : route par
    /// défaut SD-WAN à plusieurs membres). Chaque candidate est rendue pour
    /// que le moteur évalue CHAQUE branche : « ne jamais deviner » n'oblige
    /// pas à ne jamais répondre — si toutes les branches mènent au même
    /// verdict, ce verdict est ferme. Bornée par [`MAX_ECMP_ROUTES`].
    Ecmp {
        routes: Vec<EcmpRoute>,
        prefix: IpNet,
    },
    /// Route de rejet explicite (`NextHop::Drop`).
    Blackhole {
        prefix: IpNet,
        source: Option<SourceSpan>,
    },
    NoRoute,
}

/// Candidat interne : route déclarée ou connectée dérivée.
#[derive(Debug, Clone)]
struct Candidate {
    prefix: IpNet,
    metric: u32,
    next_hop: NextHop,
    source: Option<SourceSpan>,
}

/// Plus long préfixe correspondant dans le VRF, départagé par métrique.
/// Plusieurs meilleures routes divergentes (ECMP) → erreur : indéterminable
/// en mode concret sans deviner.
pub fn lookup_route(
    device: &Device,
    vrf_id: &VrfId,
    dst: &IpAddr,
) -> Result<RouteDecision, EvalError> {
    let mut candidates: Vec<Candidate> = Vec::new();

    // Routes déclarées du VRF.
    if let Some(vrf) = device.vrfs.get(vrf_id) {
        for route in &vrf.routes {
            if route.prefix.contains(dst) {
                candidates.push(Candidate {
                    prefix: route.prefix,
                    metric: route.metric,
                    next_hop: route.next_hop.clone(),
                    source: route.source.clone(),
                });
            }
        }
    }

    // Routes connectées dérivées des interfaces actives du VRF.
    for iface in device.interfaces.values() {
        if iface.state != AdminState::Up || iface.vrf != *vrf_id {
            continue;
        }
        for addr in &iface.addrs {
            let prefix = addr.trunc();
            if prefix.contains(dst) {
                candidates.push(Candidate {
                    prefix,
                    metric: 0,
                    next_hop: NextHop::Interface(iface.id.clone()),
                    source: None,
                });
            }
        }
    }

    // Plus long préfixe, puis métrique la plus basse.
    let Some(best_len) = candidates.iter().map(|c| c.prefix.prefix_len()).max() else {
        return Ok(RouteDecision::NoRoute);
    };
    candidates.retain(|c| c.prefix.prefix_len() == best_len);
    let Some(best_metric) = candidates.iter().map(|c| c.metric).min() else {
        return Ok(RouteDecision::NoRoute); // inatteignable, par prudence
    };
    candidates.retain(|c| c.metric == best_metric);

    let Some(best) = candidates.first().cloned() else {
        return Ok(RouteDecision::NoRoute); // inatteignable, par prudence
    };
    // Routes optimales à prochains sauts DISTINCTS (l'ordre de la table est
    // conservé ; les doublons de même saut comptent pour un).
    let mut distinct: Vec<Candidate> = Vec::new();
    for c in candidates {
        if !distinct.iter().any(|d| d.next_hop == c.next_hop) {
            distinct.push(c);
        }
    }

    if distinct.len() > 1 {
        // ECMP : chaque candidate est rendue pour évaluation PAR BRANCHE —
        // jamais un choix deviné, jamais un refus de répondre a priori.
        if distinct.len() > MAX_ECMP_ROUTES {
            return Err(EvalError::EcmpTooWide {
                dst: *dst,
                prefix: best.prefix,
                count: distinct.len(),
            });
        }
        // Une route de rejet mêlée à des routes de transfert au même rang :
        // modèle incohérent, indéterminable sans deviner.
        if distinct.iter().any(|c| c.next_hop == NextHop::Drop) {
            return Err(EvalError::Inconsistent {
                message: format!(
                    "routes optimales mêlant transfert et rejet vers {dst} \
                     (préfixe {}) : modèle incohérent",
                    best.prefix
                ),
                span: best.source,
            });
        }
        let mut routes = Vec::with_capacity(distinct.len());
        for c in distinct {
            routes.push(resolve_next_hop(device, vrf_id, &c)?);
        }
        return Ok(RouteDecision::Ecmp {
            routes,
            prefix: best.prefix,
        });
    }

    match best.next_hop {
        NextHop::Drop => Ok(RouteDecision::Blackhole {
            prefix: best.prefix,
            source: best.source,
        }),
        _ => {
            let prefix = best.prefix;
            let route = resolve_next_hop(device, vrf_id, &best)?;
            Ok(RouteDecision::Forward {
                out_iface: route.out_iface,
                gateway: route.gateway,
                prefix,
                source: route.source,
            })
        }
    }
}

/// Résout le prochain saut d'une candidate de TRANSFERT (jamais `Drop`) en
/// interface de sortie + passerelle éventuelle. Interface absente ou
/// désactivée, passerelle injoignable → erreur (verdict `Unknown`).
fn resolve_next_hop(
    device: &Device,
    vrf_id: &VrfId,
    candidate: &Candidate,
) -> Result<EcmpRoute, EvalError> {
    match &candidate.next_hop {
        NextHop::Drop => Err(EvalError::Inconsistent {
            message: format!(
                "route de rejet inattendue au transfert (préfixe {})",
                candidate.prefix
            ),
            span: candidate.source.clone(),
        }),
        NextHop::Interface(iface_id) => {
            let up = device
                .interfaces
                .get(iface_id)
                .map(|i| i.state == AdminState::Up)
                .unwrap_or(false);
            if !up {
                return Err(EvalError::Inconsistent {
                    message: format!(
                        "la route {} pointe vers l'interface « {iface_id} » absente ou désactivée",
                        candidate.prefix
                    ),
                    span: candidate.source.clone(),
                });
            }
            Ok(EcmpRoute {
                out_iface: iface_id.clone(),
                gateway: None,
                source: candidate.source.clone(),
            })
        }
        NextHop::Ip(gw) => {
            let out_iface =
                resolve_gateway(device, vrf_id, gw).ok_or_else(|| EvalError::Inconsistent {
                    message: format!(
                        "prochain saut {gw} injoignable : aucune interface active du VRF \
                         « {vrf_id} » ne porte un réseau le contenant"
                    ),
                    span: candidate.source.clone(),
                })?;
            Ok(EcmpRoute {
                out_iface,
                gateway: Some(*gw),
                source: candidate.source.clone(),
            })
        }
    }
}

/// L'interface de sortie vers un prochain saut IP : l'interface active du
/// VRF dont un réseau connecté contient le saut (plus long préfixe si
/// plusieurs). Pas de résolution récursive de route : hors périmètre v1.
fn resolve_gateway(device: &Device, vrf_id: &VrfId, gw: &IpAddr) -> Option<IfaceId> {
    let mut best: Option<(u8, IfaceId)> = None;
    for iface in device.interfaces.values() {
        if iface.state != AdminState::Up || iface.vrf != *vrf_id {
            continue;
        }
        for addr in &iface.addrs {
            if addr.contains(gw) {
                let len = addr.prefix_len();
                let better = match &best {
                    Some((blen, _)) => len > *blen,
                    None => true,
                };
                if better {
                    best = Some((len, iface.id.clone()));
                }
            }
        }
    }
    best.map(|(_, i)| i)
}

#[cfg(test)]
mod tests {
    use super::*;
    use calque_model::{DeviceId, Interface, Route, RouteOrigin, Vendor, Vrf};

    fn device() -> Device {
        let mut d = Device::new(DeviceId::new("r1"), Vendor::Unknown);
        let mut lan = Interface::new(IfaceId::new("lan"));
        lan.addrs = vec!["10.0.10.1/24".parse().expect("net")];
        let mut wan = Interface::new(IfaceId::new("wan"));
        wan.addrs = vec!["192.168.0.1/30".parse().expect("net")];
        d.interfaces.insert(lan.id.clone(), lan);
        d.interfaces.insert(wan.id.clone(), wan);
        d.vrfs.insert(
            VrfId::default_vrf(),
            Vrf {
                routes: vec![
                    Route {
                        prefix: "10.0.0.0/8".parse().expect("net"),
                        next_hop: NextHop::Ip("192.168.0.2".parse().expect("ip")),
                        metric: 10,
                        origin: RouteOrigin::Static,
                        source: None,
                    },
                    Route {
                        prefix: "10.0.20.0/24".parse().expect("net"),
                        next_hop: NextHop::Ip("192.168.0.2".parse().expect("ip")),
                        metric: 10,
                        origin: RouteOrigin::Static,
                        source: None,
                    },
                    Route {
                        prefix: "10.0.66.0/24".parse().expect("net"),
                        next_hop: NextHop::Drop,
                        metric: 10,
                        origin: RouteOrigin::Static,
                        source: Some(SourceSpan::new("r1.conf", 820)),
                    },
                ],
            },
        );
        d
    }

    #[test]
    fn plus_long_prefixe_gagne() {
        let d = device();
        let dst: IpAddr = "10.0.20.5".parse().expect("ip");
        match lookup_route(&d, &VrfId::default_vrf(), &dst) {
            Ok(RouteDecision::Forward {
                prefix,
                out_iface,
                gateway,
                ..
            }) => {
                assert_eq!(prefix, "10.0.20.0/24".parse::<IpNet>().expect("net"));
                assert_eq!(out_iface, IfaceId::new("wan"));
                assert_eq!(gateway, Some("192.168.0.2".parse().expect("ip")));
            }
            other => panic!("Forward attendu, obtenu {other:?}"),
        }
    }

    #[test]
    fn la_route_connectee_prime_sur_la_generale() {
        let d = device();
        let dst: IpAddr = "10.0.10.5".parse().expect("ip");
        match lookup_route(&d, &VrfId::default_vrf(), &dst) {
            Ok(RouteDecision::Forward {
                out_iface, gateway, ..
            }) => {
                assert_eq!(out_iface, IfaceId::new("lan"));
                assert_eq!(gateway, None);
            }
            other => panic!("Forward attendu, obtenu {other:?}"),
        }
    }

    #[test]
    fn aucune_route() {
        let d = device();
        let dst: IpAddr = "172.16.0.1".parse().expect("ip");
        assert_eq!(
            lookup_route(&d, &VrfId::default_vrf(), &dst),
            Ok(RouteDecision::NoRoute)
        );
    }

    #[test]
    fn route_de_rejet() {
        let d = device();
        let dst: IpAddr = "10.0.66.9".parse().expect("ip");
        match lookup_route(&d, &VrfId::default_vrf(), &dst) {
            Ok(RouteDecision::Blackhole { source, .. }) => {
                assert_eq!(source, Some(SourceSpan::new("r1.conf", 820)));
            }
            other => panic!("Blackhole attendu, obtenu {other:?}"),
        }
    }

    #[test]
    fn metrique_departage() {
        let mut d = device();
        if let Some(vrf) = d.vrfs.get_mut(&VrfId::default_vrf()) {
            vrf.routes.push(Route {
                prefix: "10.0.20.0/24".parse().expect("net"),
                next_hop: NextHop::Interface(IfaceId::new("lan")),
                metric: 5, // meilleure métrique que la route via 192.168.0.2
                origin: RouteOrigin::Static,
                source: None,
            });
        }
        let dst: IpAddr = "10.0.20.5".parse().expect("ip");
        match lookup_route(&d, &VrfId::default_vrf(), &dst) {
            Ok(RouteDecision::Forward { out_iface, .. }) => {
                assert_eq!(out_iface, IfaceId::new("lan"));
            }
            other => panic!("Forward attendu, obtenu {other:?}"),
        }
    }

    /// Depuis l'évaluation par branches, l'ECMP n'est plus une erreur
    /// (`AmbiguousRoutes` a disparu) : la recherche rend les candidates,
    /// c'est le moteur qui évalue chaque branche et tranche.
    #[test]
    fn ecmp_divergent_rend_les_candidates() {
        let mut d = device();
        if let Some(vrf) = d.vrfs.get_mut(&VrfId::default_vrf()) {
            vrf.routes.push(Route {
                prefix: "10.0.20.0/24".parse().expect("net"),
                next_hop: NextHop::Interface(IfaceId::new("lan")),
                metric: 10, // même préfixe, même métrique, saut différent
                origin: RouteOrigin::Static,
                source: None,
            });
        }
        let dst: IpAddr = "10.0.20.5".parse().expect("ip");
        match lookup_route(&d, &VrfId::default_vrf(), &dst) {
            Ok(RouteDecision::Ecmp { routes, prefix }) => {
                assert_eq!(prefix, "10.0.20.0/24".parse::<IpNet>().expect("net"));
                assert_eq!(routes.len(), 2);
                // L'ordre de la table est conservé : la route via la
                // passerelle d'abord, puis la route d'interface.
                assert_eq!(routes[0].out_iface, IfaceId::new("wan"));
                assert_eq!(routes[0].gateway, Some("192.168.0.2".parse().expect("ip")));
                assert_eq!(routes[1].out_iface, IfaceId::new("lan"));
                assert_eq!(routes[1].gateway, None);
            }
            other => panic!("Ecmp attendu, obtenu {other:?}"),
        }
    }

    /// Au-delà de MAX_ECMP_ROUTES candidates divergentes : erreur bornée
    /// (le moteur rendra `Unknown` diagnostiqué), jamais de troncature.
    #[test]
    fn ecmp_au_dela_de_la_borne_est_refuse() {
        let mut d = device();
        // MAX_ECMP_ROUTES + 1 passerelles distinctes sur le réseau wan… il
        // n'a que 4 adresses (/30) : on élargit d'abord l'interface.
        if let Some(wan) = d.interfaces.get_mut(&IfaceId::new("wan")) {
            wan.addrs = vec!["192.168.0.1/24".parse().expect("net")];
        }
        if let Some(vrf) = d.vrfs.get_mut(&VrfId::default_vrf()) {
            for i in 0..=(MAX_ECMP_ROUTES as u8) {
                vrf.routes.push(Route {
                    prefix: "10.0.20.0/24".parse().expect("net"),
                    next_hop: NextHop::Ip(format!("192.168.0.{}", 10 + i).parse().expect("ip")),
                    metric: 10,
                    origin: RouteOrigin::Static,
                    source: None,
                });
            }
        }
        let dst: IpAddr = "10.0.20.5".parse().expect("ip");
        assert!(matches!(
            lookup_route(&d, &VrfId::default_vrf(), &dst),
            Err(EvalError::EcmpTooWide { .. })
        ));
    }
}
