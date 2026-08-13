//! `reach` (§5.3, S6) : « voici tout ce qui peut atteindre cette
//! destination » — et le symétrique « voici tout ce que cette source peut
//! atteindre ».
//!
//! Pour chaque point d'entrée du réseau (interface active ET adressée),
//! l'univers restreint par la contrainte demandée est propagé
//! symboliquement ([`symbolic_trace_from`]) ; les sous-ensembles au verdict
//! `Allowed` sont collectés avec, pour chacun, un paquet concret exemple
//! (`sample()`, §4.1) et la chaîne des règles décisives.
//!
//! Limites documentées :
//! - l'entrée n'est PAS restreinte aux sources topologiquement présentes
//!   derrière l'interface : le rapport couvre donc aussi les sources
//!   usurpées (aucun anti-spoofing n'est modélisé) — c'est le point de vue
//!   le plus prudent pour une question d'exposition ;
//! - les ensembles rapportés sont exprimés APRÈS traductions d'adresse
//!   (voir les limites NAT de `symtrace.rs`) ;
//! - les parts non décidables restent hors de `flows` et sont signalées
//!   dans `diagnostics` (§6.3 : ne jamais deviner).

use calque_model::{AdminState, ConcretePacket, Diagnostic, Endpoint, Network, Severity};
use calque_space::{HeaderSet, HeaderSpace};
use serde::{Deserialize, Serialize};

use crate::symtrace::{symbolic_trace_from, SymbolicDecision};
use crate::trace::Verdict;

/// Le rapport d'accessibilité symbolique.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReachReport {
    /// Les flux au verdict `Allowed`, par point d'entrée.
    pub flows: Vec<ReachFlow>,
    /// Parts non décidables et incidents rencontrés pendant la propagation
    /// (fidélité §6.3) : le rapport est incomplet si cette liste contient
    /// des erreurs.
    pub diagnostics: Vec<Diagnostic>,
}

/// Un sous-ensemble autorisé, depuis un point d'entrée donné.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReachFlow {
    /// L'interface par laquelle ce trafic entre dans le réseau modélisé.
    pub entry: Endpoint,
    /// Le sous-ensemble autorisé (exprimé après traductions d'adresse).
    pub set: HeaderSet,
    /// Un paquet concret exemple du sous-ensemble (§4.1).
    pub sample: ConcretePacket,
    /// La chaîne des décisions décisives (règles, routes, NAT), étiquetées
    /// par équipement.
    pub decisions: Vec<SymbolicDecision>,
}

/// Tout ce qui peut atteindre `target`.
///
/// `target` est un [`HeaderSet`] qui contraint typiquement la dimension
/// destination (et éventuellement protocole/ports) ; l'univers est
/// intersecté avec lui puis propagé depuis chaque point d'entrée.
pub fn reach_to(network: &Network, target: &HeaderSet) -> ReachReport {
    reach_with(network, &HeaderSet::full().intersect(target))
}

/// Tout ce que `source` peut atteindre (symétrique de [`reach_to`]) :
/// `source` contraint typiquement la dimension source.
pub fn reach_from(network: &Network, source: &HeaderSet) -> ReachReport {
    reach_with(network, &HeaderSet::full().intersect(source))
}

fn reach_with(network: &Network, start: &HeaderSet) -> ReachReport {
    let mut flows = Vec::new();
    let mut diagnostics = Vec::new();
    if start.is_empty() {
        diagnostics.push(Diagnostic {
            severity: Severity::Info,
            message: "contrainte vide : aucun paquet à propager".to_owned(),
            span: None,
        });
        return ReachReport { flows, diagnostics };
    }
    // Points d'entrée : les interfaces actives et adressées (l'ordre des
    // BTreeMap rend le rapport déterministe).
    for device in network.devices.values() {
        for iface in device.interfaces.values() {
            if iface.state != AdminState::Up || iface.addrs.is_empty() {
                continue;
            }
            let entry = Endpoint {
                device: device.id.clone(),
                iface: iface.id.clone(),
            };
            let trace = symbolic_trace_from(network, &entry, start);
            diagnostics.extend(trace.diagnostics.iter().cloned());
            for vs in trace.verdict_sets() {
                match vs.verdict {
                    Verdict::Allowed => {
                        if let Some(sample) = vs.sample {
                            flows.push(ReachFlow {
                                entry: entry.clone(),
                                set: vs.set.clone(),
                                sample,
                                decisions: vs.decisions.clone(),
                            });
                        }
                    }
                    // Fidélité : les parts indécidables sont signalées.
                    Verdict::Unknown => diagnostics.extend(vs.diagnostics.iter().cloned()),
                    _ => {}
                }
            }
        }
    }
    ReachReport { flows, diagnostics }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::trace_packet;
    use crate::testutil::{net, rule, tcp_svc, with_fw1_egress};
    use calque_model::{Action, AddrExpr, DeviceId, IfaceId, PortRange, RuleId};
    use calque_space::{Cube, PortRanges, PrefixSet, ProtoSet};

    fn two_sources_network() -> Network {
        with_fw1_egress(
            vec![
                rule(
                    "10",
                    vec![AddrExpr::Net(net("10.0.10.5/32"))],
                    vec![AddrExpr::Net(net("10.0.20.5/32"))],
                    vec![tcp_svc(445)],
                    None,
                    None,
                    Action::Accept,
                    100,
                ),
                rule(
                    "20",
                    vec![AddrExpr::Net(net("10.0.10.7/32"))],
                    vec![AddrExpr::Net(net("10.0.20.5/32"))],
                    vec![tcp_svc(445)],
                    None,
                    None,
                    Action::Accept,
                    200,
                ),
            ],
            Action::Deny,
        )
    }

    /// reach_to trouve EXACTEMENT les deux sources autorisées.
    #[test]
    fn reach_to_trouve_exactement_les_deux_sources() {
        let network = two_sources_network();
        let target = HeaderSet::from_cube(Cube::new(
            PrefixSet::full(),
            PrefixSet::from_net(net("10.0.20.5/32")),
            ProtoSet::single(6),
            PortRanges::full(),
            PortRanges::single(445),
        ));
        let report = reach_to(&network, &target);
        let lan = Endpoint {
            device: DeviceId::new("fw1"),
            iface: IfaceId::new("lan"),
        };
        let from_lan: Vec<&ReachFlow> = report.flows.iter().filter(|f| f.entry == lan).collect();
        assert!(!from_lan.is_empty());
        let mut union = HeaderSet::empty();
        for f in &from_lan {
            union = union.union(&f.set);
            // Le paquet exemple est réellement autorisé par le moteur
            // concret, et la chaîne cite une des deux règles décisives.
            assert_eq!(trace_packet(&network, &f.sample).verdict, Verdict::Allowed);
            assert!(f.decisions.iter().any(|d| {
                d.decision.rule == Some(RuleId::new("10"))
                    || d.decision.rule == Some(RuleId::new("20"))
            }));
        }
        let expected = HeaderSet::flow(
            net("10.0.10.5/32"),
            net("10.0.20.5/32"),
            6,
            PortRange::single(445),
        )
        .union(&HeaderSet::flow(
            net("10.0.10.7/32"),
            net("10.0.20.5/32"),
            6,
            PortRange::single(445),
        ));
        assert!(
            union.contains_set(&expected) && expected.contains_set(&union),
            "les sources trouvées ne sont pas exactement les deux autorisées"
        );
    }

    /// reach_from (symétrique) : ce que 10.0.10.5 peut atteindre depuis le
    /// LAN contient exactement le flux SMB autorisé, et chaque exemple est
    /// confirmé par le moteur concret.
    #[test]
    fn reach_from_liste_les_destinations() {
        let network = two_sources_network();
        let source = HeaderSet::from_cube(Cube::new(
            PrefixSet::from_net(net("10.0.10.5/32")),
            PrefixSet::full(),
            ProtoSet::full(),
            PortRanges::full(),
            PortRanges::full(),
        ));
        let report = reach_from(&network, &source);
        let lan = Endpoint {
            device: DeviceId::new("fw1"),
            iface: IfaceId::new("lan"),
        };
        let mut union = HeaderSet::empty();
        for f in report.flows.iter().filter(|f| f.entry == lan) {
            union = union.union(&f.set);
            assert_eq!(
                trace_packet(&network, &f.sample).verdict,
                Verdict::Allowed,
                "exemple non confirmé : {:?}",
                f.sample
            );
        }
        let smb = HeaderSet::flow(
            net("10.0.10.5/32"),
            net("10.0.20.5/32"),
            6,
            PortRange::single(445),
        );
        assert!(union.contains_set(&smb), "le flux SMB autorisé manque");
        // La règle 20 (source 10.0.10.7) ne doit PAS apparaître : la source
        // est restreinte à 10.0.10.5.
        let other = HeaderSet::flow(
            net("10.0.10.7/32"),
            net("10.0.20.5/32"),
            6,
            PortRange::single(445),
        );
        assert!(union.intersect(&other).is_empty());
    }

    #[test]
    fn contrainte_vide_rend_un_rapport_vide() {
        let network = two_sources_network();
        let report = reach_to(&network, &HeaderSet::empty());
        assert!(report.flows.is_empty());
        assert!(!report.diagnostics.is_empty());
    }

    /// Une cible EXTERNE au modèle est atteignable « en sortie de
    /// périmètre » : `reach_to` la trouve fermement (décision `ExitsModel`
    /// dans la chaîne), et chaque exemple est confirmé par le moteur
    /// concret.
    #[test]
    fn reach_to_cible_externe_en_sortie_de_perimetre() {
        use crate::testutil::{single_device_network, with_fw_egress};
        use crate::trace::Outcome;

        let network = with_fw_egress(
            single_device_network(),
            vec![rule(
                "10",
                vec![AddrExpr::Net(net("10.0.10.0/24"))],
                vec![],
                vec![tcp_svc(443)],
                None,
                None,
                Action::Accept,
                100,
            )],
            Action::Deny,
        );
        let target = HeaderSet::from_cube(Cube::new(
            PrefixSet::full(),
            PrefixSet::from_net(net("203.0.113.50/32")),
            ProtoSet::single(6),
            PortRanges::full(),
            PortRanges::single(443),
        ));
        let report = reach_to(&network, &target);
        let lan = Endpoint {
            device: DeviceId::new("fw"),
            iface: IfaceId::new("lan"),
        };
        let from_lan: Vec<&ReachFlow> = report.flows.iter().filter(|f| f.entry == lan).collect();
        assert!(!from_lan.is_empty(), "la cible externe doit être atteinte");
        for f in &from_lan {
            assert_eq!(trace_packet(&network, &f.sample).verdict, Verdict::Allowed);
            // La chaîne dit explicitement la sortie de périmètre.
            assert!(f
                .decisions
                .iter()
                .any(|d| matches!(d.decision.outcome, Outcome::ExitsModel { .. })));
        }
        // Le rapport est ferme : aucune part indécidable en erreur.
        assert!(!report
            .diagnostics
            .iter()
            .any(|d| d.severity == calque_model::Severity::Error));
    }
}
