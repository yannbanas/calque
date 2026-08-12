//! Topologie — inférence par sous-réseau et vérification (§7).
//!
//! Version 1 : deux interfaces ACTIVES de deux équipements différents qui
//! portent des adresses dans le même sous-réseau sont probablement reliées.
//! C'est rapide mais faux dès qu'un commutateur s'intercale ; d'où les deux
//! fonctions qui vont ensemble :
//!
//! - [`infer_links_from_subnets`] n'infère un lien QUE pour les segments
//!   « francs » : exactement deux interfaces dans le sous-réseau, sur deux
//!   équipements différents.
//! - [`check_topology`] signale tout le reste : segments ambigus, liens
//!   déclarés cassés ou incohérents, interfaces isolées, chevauchements.
//!
//! CHOIX DOCUMENTÉ pour les segments partagés (trois interfaces ou plus
//! dans le même sous-réseau) : AUCUN lien n'est inféré. Générer une étoile
//! reviendrait à deviner un câblage que rien n'atteste (§6.3 : ne jamais
//! deviner) — un commutateur intermédiaire est probable et l'étoile serait
//! fausse dans presque tous les cas. À la place, [`check_topology`] émet
//! une issue « segment ambigu » (Warning) invitant à déclarer les liens
//! dans le fichier de topologie.
//!
//! Module PUR : aucune entrée-sortie, aucun panic sur entrée quelconque.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use calque_model::{AdminState, Endpoint, Interface, Link, LinkOrigin, Network, Severity};
use ipnet::IpNet;

// ---------------------------------------------------------------------------
// Issues
// ---------------------------------------------------------------------------

/// Nature d'une anomalie topologique.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum TopologyIssueKind {
    /// (a) Sous-réseau porté par trois interfaces ou plus : commutateur
    /// probable, aucun lien inférable sans deviner.
    AmbiguousSegment,
    /// (b) Lien déclaré dont une extrémité (équipement ou interface)
    /// n'existe pas dans le modèle.
    UnknownEndpoint,
    /// (c) Lien déclaré entre deux interfaces adressées sans aucun
    /// sous-réseau commun.
    AddressingMismatch,
    /// (d) Interface active et adressée qui n'apparaît dans aucun lien ni
    /// aucun segment partagé — souvent normal pour le WAN.
    IsolatedInterface,
    /// (e) Chevauchement de sous-réseaux entre interfaces d'un même
    /// équipement.
    OverlappingSubnets,
    /// (f) Lien déclaré vers une interface administrativement désactivée.
    LinkToDownInterface,
}

/// Une anomalie relevée par [`check_topology`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TopologyIssue {
    pub severity: Severity,
    /// Message lisible, en français.
    pub message: String,
    pub kind: TopologyIssueKind,
}

impl TopologyIssue {
    fn new(severity: Severity, kind: TopologyIssueKind, message: String) -> Self {
        Self {
            severity,
            message,
            kind,
        }
    }
}

impl fmt::Display for TopologyIssue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self.severity {
            Severity::Info => "info",
            Severity::Warning => "avertissement",
            Severity::Error => "erreur",
        };
        write!(f, "{label} : {}", self.message)
    }
}

// ---------------------------------------------------------------------------
// Segments — le calcul partagé
// ---------------------------------------------------------------------------

/// Une interface « porte » un segment si elle est active et que l'adresse,
/// tronquée à son préfixe, n'est pas un préfixe hôte (/32 ou /128 : une
/// adresse seule n'est pas un segment).
fn segment_of(addr: &IpNet) -> Option<IpNet> {
    if addr.prefix_len() >= addr.max_prefix_len() {
        return None;
    }
    Some(addr.trunc())
}

/// Regroupe les extrémités actives par sous-réseau porté. Les `BTreeMap`
/// et `BTreeSet` garantissent un ordre stable, donc un résultat
/// déterministe.
fn segments(network: &Network) -> BTreeMap<IpNet, Vec<Endpoint>> {
    let mut map: BTreeMap<IpNet, BTreeSet<Endpoint>> = BTreeMap::new();
    for (device_id, device) in &network.devices {
        for (iface_id, iface) in &device.interfaces {
            if iface.state != AdminState::Up {
                continue;
            }
            for addr in &iface.addrs {
                if let Some(net) = segment_of(addr) {
                    map.entry(net).or_default().insert(Endpoint {
                        device: device_id.clone(),
                        iface: iface_id.clone(),
                    });
                }
            }
        }
    }
    map.into_iter()
        .map(|(net, eps)| (net, eps.into_iter().collect()))
        .collect()
}

/// Paire d'extrémités normalisée (indépendante de l'ordre a/b).
fn pair_key(a: &Endpoint, b: &Endpoint) -> (Endpoint, Endpoint) {
    if a <= b {
        (a.clone(), b.clone())
    } else {
        (b.clone(), a.clone())
    }
}

// ---------------------------------------------------------------------------
// Inférence
// ---------------------------------------------------------------------------

/// Infère les liens probables à partir des sous-réseaux (§7, source n° 3).
///
/// Un lien est inféré quand un sous-réseau est porté par EXACTEMENT deux
/// interfaces actives, sur DEUX équipements différents. Trois interfaces
/// ou plus : segment partagé, aucun lien inféré (voir le choix documenté
/// en tête de module) — [`check_topology`] le signalera. Les préfixes
/// hôtes (/32, /128) sont ignorés. Les liens déjà présents dans
/// `network.links` (même paire d'extrémités, peu importe l'ordre et
/// l'origine) ne sont pas dupliqués. Résultat déterministe : les liens
/// sortent dans l'ordre des sous-réseaux, extrémités normalisées.
pub fn infer_links_from_subnets(network: &Network) -> Vec<Link> {
    // Paires déjà connues : liens déclarés + liens déjà inférés ici.
    let mut seen: BTreeSet<(Endpoint, Endpoint)> =
        network.links.iter().map(|l| pair_key(&l.a, &l.b)).collect();

    let mut out = Vec::new();
    for endpoints in segments(network).values() {
        let [a, b] = endpoints.as_slice() else {
            continue; // segment vide, solitaire ou partagé : rien à inférer
        };
        if a.device == b.device {
            continue; // deux interfaces du même équipement : pas un câble
        }
        let key = pair_key(a, b);
        if seen.insert(key.clone()) {
            out.push(Link {
                a: key.0,
                b: key.1,
                origin: LinkOrigin::InferredFromSubnet,
            });
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Vérification
// ---------------------------------------------------------------------------

/// L'interface visée par une extrémité, si elle existe dans le modèle.
fn lookup<'a>(network: &'a Network, ep: &Endpoint) -> Option<&'a Interface> {
    network.devices.get(&ep.device)?.interfaces.get(&ep.iface)
}

/// Deux ensembles d'adresses partagent-ils un sous-réseau ? Critère :
/// même réseau tronqué (préfixes hôtes exclus).
fn share_a_subnet(a: &Interface, b: &Interface) -> bool {
    a.addrs.iter().filter_map(segment_of).any(|net_a| {
        b.addrs
            .iter()
            .filter_map(segment_of)
            .any(|net_b| net_a == net_b)
    })
}

/// Deux réseaux se chevauchent-ils ? (Même famille d'adresses seulement :
/// `contains` renvoie faux entre IPv4 et IPv6.)
fn nets_overlap(a: &IpNet, b: &IpNet) -> bool {
    a.contains(&b.network()) || b.contains(&a.network())
}

/// Vérifie la cohérence topologique du modèle. Détecte, dans cet ordre :
///
/// - (a) segment partagé par 3+ interfaces (ambigu, Warning) ;
/// - (b) lien déclaré vers un équipement ou une interface inconnus (Error) ;
/// - (c) lien déclaré entre interfaces adressées sans sous-réseau commun
///   (Warning) — ignoré si une extrémité n'a aucune adresse (lien de
///   niveau 2, normal) ;
/// - (d) interface active adressée absente de tout lien (déclaré OU
///   inféré) et de tout segment à 2+ interfaces (Info : souvent normal
///   pour le WAN) ;
/// - (e) chevauchement de sous-réseaux entre interfaces actives d'un même
///   équipement (Warning) ;
/// - (f) lien déclaré vers une interface administrativement désactivée
///   (Warning).
///
/// Cohérent avec [`infer_links_from_subnets`] : les segments à 3+
/// interfaces ne produisent aucun lien, ils produisent l'issue (a).
/// Résultat déterministe.
pub fn check_topology(network: &Network) -> Vec<TopologyIssue> {
    let mut issues = Vec::new();
    let segs = segments(network);

    // (a) Segments ambigus : 3+ interfaces dans le même sous-réseau.
    for (net, endpoints) in &segs {
        if endpoints.len() >= 3 {
            let list = endpoints
                .iter()
                .map(|e| format!("{}/{}", e.device, e.iface))
                .collect::<Vec<_>>()
                .join(", ");
            issues.push(TopologyIssue::new(
                Severity::Warning,
                TopologyIssueKind::AmbiguousSegment,
                format!(
                    "segment ambigu : le sous-réseau {net} est porté par {} interfaces \
                     ({list}) — commutateur probable, aucun lien inféré ; déclarez les \
                     liens dans le fichier de topologie",
                    endpoints.len()
                ),
            ));
        }
    }

    // (b), (c), (f) : examen des liens présents dans le modèle.
    for link in &network.links {
        let mut broken = false;
        for ep in [&link.a, &link.b] {
            match network.devices.get(&ep.device) {
                None => {
                    broken = true;
                    issues.push(TopologyIssue::new(
                        Severity::Error,
                        TopologyIssueKind::UnknownEndpoint,
                        format!(
                            "lien déclaré invalide : l'équipement « {} » (extrémité \
                             {}/{}) n'existe pas dans le modèle",
                            ep.device, ep.device, ep.iface
                        ),
                    ));
                }
                Some(device) => {
                    if !device.interfaces.contains_key(&ep.iface) {
                        broken = true;
                        issues.push(TopologyIssue::new(
                            Severity::Error,
                            TopologyIssueKind::UnknownEndpoint,
                            format!(
                                "lien déclaré invalide : l'interface « {} » n'existe \
                                 pas sur l'équipement « {} »",
                                ep.iface, ep.device
                            ),
                        ));
                    }
                }
            }
        }
        if broken {
            continue; // (c) et (f) n'ont pas de sens sur un lien cassé
        }
        // Les deux extrémités existent forcément ici.
        let (Some(ia), Some(ib)) = (lookup(network, &link.a), lookup(network, &link.b)) else {
            continue;
        };

        // (f) Lien vers une interface désactivée.
        for (ep, iface) in [(&link.a, ia), (&link.b, ib)] {
            if iface.state == AdminState::Down {
                issues.push(TopologyIssue::new(
                    Severity::Warning,
                    TopologyIssueKind::LinkToDownInterface,
                    format!(
                        "lien déclaré vers l'interface « {} » de « {} », \
                         administrativement désactivée",
                        ep.iface, ep.device
                    ),
                ));
            }
        }

        // (c) Incohérence d'adressage : les deux extrémités sont adressées
        // mais ne partagent aucun sous-réseau. Une extrémité sans adresse
        // (lien de niveau 2) n'est pas signalée.
        if !ia.addrs.is_empty() && !ib.addrs.is_empty() && !share_a_subnet(ia, ib) {
            issues.push(TopologyIssue::new(
                Severity::Warning,
                TopologyIssueKind::AddressingMismatch,
                format!(
                    "lien incohérent entre {}/{} et {}/{} : aucun sous-réseau commun \
                     entre les deux extrémités",
                    link.a.device, link.a.iface, link.b.device, link.b.iface
                ),
            ));
        }
    }

    // (d) Interfaces isolées : actives, adressées (hors préfixes hôtes),
    // absentes de tout lien — déclaré ou inféré — et seules dans leurs
    // sous-réseaux.
    let inferred = infer_links_from_subnets(network);
    let mut covered: BTreeSet<Endpoint> = BTreeSet::new();
    for link in network.links.iter().chain(inferred.iter()) {
        covered.insert(link.a.clone());
        covered.insert(link.b.clone());
    }
    for endpoints in segs.values() {
        if endpoints.len() >= 2 {
            covered.extend(endpoints.iter().cloned());
        }
    }
    for (device_id, device) in &network.devices {
        for (iface_id, iface) in &device.interfaces {
            if iface.state != AdminState::Up {
                continue;
            }
            if !iface.addrs.iter().any(|a| segment_of(a).is_some()) {
                continue; // pas adressée (ou seulement /32 et /128)
            }
            let ep = Endpoint {
                device: device_id.clone(),
                iface: iface_id.clone(),
            };
            if !covered.contains(&ep) {
                issues.push(TopologyIssue::new(
                    Severity::Info,
                    TopologyIssueKind::IsolatedInterface,
                    format!(
                        "interface « {iface_id} » de « {device_id} » active et adressée \
                         mais présente dans aucun lien ni segment partagé — souvent \
                         normal pour une interface WAN"
                    ),
                ));
            }
        }
    }

    // (e) Chevauchement de sous-réseaux entre interfaces actives d'un même
    // équipement (préfixes hôtes exclus).
    for (device_id, device) in &network.devices {
        let ifaces: Vec<_> = device
            .interfaces
            .iter()
            .filter(|(_, i)| i.state == AdminState::Up)
            .collect();
        for (idx, (id_a, iface_a)) in ifaces.iter().enumerate() {
            for (id_b, iface_b) in ifaces.iter().skip(idx + 1) {
                let overlap = iface_a.addrs.iter().filter_map(segment_of).find_map(|na| {
                    iface_b
                        .addrs
                        .iter()
                        .filter_map(segment_of)
                        .find(|nb| nets_overlap(&na, nb))
                        .map(|nb| (na, nb))
                });
                if let Some((na, nb)) = overlap {
                    issues.push(TopologyIssue::new(
                        Severity::Warning,
                        TopologyIssueKind::OverlappingSubnets,
                        format!(
                            "chevauchement de sous-réseaux sur « {device_id} » : \
                             « {id_a} » ({na}) et « {id_b} » ({nb})"
                        ),
                    ));
                }
            }
        }
    }

    issues
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use calque_model::{Device, DeviceId, IfaceId, Vendor};

    /// Un équipement avec des interfaces (nom, adresses, état).
    fn device(id: &str, ifaces: &[(&str, &[&str], AdminState)]) -> Device {
        let mut d = Device::new(DeviceId::new(id), Vendor::Unknown);
        for (name, addrs, state) in ifaces {
            let mut iface = Interface::new(IfaceId::new(*name));
            iface.addrs = addrs.iter().map(|a| a.parse().expect("réseau")).collect();
            iface.state = *state;
            d.interfaces.insert(iface.id.clone(), iface);
        }
        d
    }

    fn network(devices: Vec<Device>) -> Network {
        let mut n = Network::default();
        for d in devices {
            n.devices.insert(d.id.clone(), d);
        }
        n
    }

    fn ep(device: &str, iface: &str) -> Endpoint {
        Endpoint {
            device: DeviceId::new(device),
            iface: IfaceId::new(iface),
        }
    }

    #[test]
    fn inference_franche_a_deux_interfaces() {
        let n = network(vec![
            device(
                "r1",
                &[
                    ("eth0", &["10.0.0.1/30"], AdminState::Up),
                    // /32 : pas un segment, ne doit rien produire.
                    ("lo", &["192.0.2.1/32"], AdminState::Up),
                ],
            ),
            device("r2", &[("eth3", &["10.0.0.2/30"], AdminState::Up)]),
        ]);
        let links = infer_links_from_subnets(&n);
        assert_eq!(links.len(), 1);
        assert_eq!(links[0].origin, LinkOrigin::InferredFromSubnet);
        assert_eq!(
            pair_key(&links[0].a, &links[0].b),
            (ep("r1", "eth0"), ep("r2", "eth3"))
        );
    }

    #[test]
    fn interface_desactivee_ignoree_par_l_inference() {
        let n = network(vec![
            device("r1", &[("eth0", &["10.0.0.1/24"], AdminState::Up)]),
            device("r2", &[("eth0", &["10.0.0.2/24"], AdminState::Down)]),
        ]);
        assert!(infer_links_from_subnets(&n).is_empty());
    }

    #[test]
    fn segment_a_trois_interfaces_aucun_lien_mais_issue_ambigue() {
        // Choix documenté : 3+ interfaces dans le sous-réseau → aucun lien
        // inféré, une issue « segment ambigu » (Warning) dans check_topology.
        let n = network(vec![
            device("r1", &[("eth0", &["10.1.0.1/24"], AdminState::Up)]),
            device("r2", &[("eth0", &["10.1.0.2/24"], AdminState::Up)]),
            device("r3", &[("eth0", &["10.1.0.3/24"], AdminState::Up)]),
        ]);
        assert!(infer_links_from_subnets(&n).is_empty());
        let issues = check_topology(&n);
        let ambiguous: Vec<_> = issues
            .iter()
            .filter(|i| i.kind == TopologyIssueKind::AmbiguousSegment)
            .collect();
        assert_eq!(ambiguous.len(), 1);
        assert_eq!(ambiguous[0].severity, Severity::Warning);
        assert!(ambiguous[0].message.contains("10.1.0.0/24"));
        // Cohérence : personne n'est « isolé » sur un segment partagé.
        assert!(!issues
            .iter()
            .any(|i| i.kind == TopologyIssueKind::IsolatedInterface));
    }

    #[test]
    fn pas_de_doublon_avec_un_lien_declare() {
        let mut n = network(vec![
            device("r1", &[("eth0", &["10.0.0.1/30"], AdminState::Up)]),
            device("r2", &[("eth3", &["10.0.0.2/30"], AdminState::Up)]),
        ]);
        // Lien déclaré dans l'ordre INVERSE (b/a) : doit quand même bloquer
        // l'inférence, peu importe l'ordre et l'origine.
        n.links.push(Link {
            a: ep("r2", "eth3"),
            b: ep("r1", "eth0"),
            origin: LinkOrigin::Declared,
        });
        assert!(infer_links_from_subnets(&n).is_empty());
    }

    #[test]
    fn lien_declare_vers_extremite_inconnue() {
        let mut n = network(vec![device(
            "r1",
            &[("eth0", &["10.0.0.1/30"], AdminState::Up)],
        )]);
        n.links.push(Link {
            a: ep("r1", "eth0"),
            b: ep("fantome", "eth9"), // équipement inconnu
            origin: LinkOrigin::Declared,
        });
        n.links.push(Link {
            a: ep("r1", "eth7"), // interface inconnue sur r1
            b: ep("r1", "eth0"),
            origin: LinkOrigin::Declared,
        });
        let issues = check_topology(&n);
        let broken: Vec<_> = issues
            .iter()
            .filter(|i| i.kind == TopologyIssueKind::UnknownEndpoint)
            .collect();
        assert_eq!(broken.len(), 2);
        assert!(broken.iter().all(|i| i.severity == Severity::Error));
        assert!(broken.iter().any(|i| i.message.contains("fantome")));
        assert!(broken.iter().any(|i| i.message.contains("eth7")));
    }

    #[test]
    fn lien_declare_sans_sous_reseau_commun() {
        let mut n = network(vec![
            device("r1", &[("eth0", &["10.0.0.1/24"], AdminState::Up)]),
            device("r2", &[("eth0", &["172.16.0.1/24"], AdminState::Up)]),
        ]);
        n.links.push(Link {
            a: ep("r1", "eth0"),
            b: ep("r2", "eth0"),
            origin: LinkOrigin::Declared,
        });
        let issues = check_topology(&n);
        assert!(issues.iter().any(|i| {
            i.kind == TopologyIssueKind::AddressingMismatch && i.severity == Severity::Warning
        }));
    }

    #[test]
    fn interface_isolee_en_info() {
        // r1/wan est seule dans 203.0.113.0/29 : isolée (Info). r1/lan et
        // r2/lan forment un lien franc : pas isolées.
        let n = network(vec![
            device(
                "r1",
                &[
                    ("lan", &["10.0.0.1/30"], AdminState::Up),
                    ("wan", &["203.0.113.2/29"], AdminState::Up),
                ],
            ),
            device("r2", &[("lan", &["10.0.0.2/30"], AdminState::Up)]),
        ]);
        let issues = check_topology(&n);
        let isolated: Vec<_> = issues
            .iter()
            .filter(|i| i.kind == TopologyIssueKind::IsolatedInterface)
            .collect();
        assert_eq!(isolated.len(), 1);
        assert_eq!(isolated[0].severity, Severity::Info);
        assert!(isolated[0].message.contains("wan"));
    }

    #[test]
    fn chevauchement_sur_le_meme_equipement() {
        let n = network(vec![device(
            "r1",
            &[
                ("eth0", &["10.0.0.1/16"], AdminState::Up),
                ("eth1", &["10.0.5.1/24"], AdminState::Up),
            ],
        )]);
        let issues = check_topology(&n);
        assert!(issues.iter().any(|i| {
            i.kind == TopologyIssueKind::OverlappingSubnets && i.severity == Severity::Warning
        }));
    }

    #[test]
    fn lien_declare_vers_interface_desactivee() {
        let mut n = network(vec![
            device("r1", &[("eth0", &["10.0.0.1/30"], AdminState::Up)]),
            device("r2", &[("eth0", &["10.0.0.2/30"], AdminState::Down)]),
        ]);
        n.links.push(Link {
            a: ep("r1", "eth0"),
            b: ep("r2", "eth0"),
            origin: LinkOrigin::Declared,
        });
        let issues = check_topology(&n);
        let down: Vec<_> = issues
            .iter()
            .filter(|i| i.kind == TopologyIssueKind::LinkToDownInterface)
            .collect();
        assert_eq!(down.len(), 1);
        assert_eq!(down[0].severity, Severity::Warning);
        assert!(down[0].message.contains("r2"));
    }

    #[test]
    fn inference_ipv6_et_prefixe_hote_ignore() {
        let n = network(vec![
            device(
                "r1",
                &[
                    ("eth0", &["2001:db8:0:1::1/64"], AdminState::Up),
                    // /128 : pas un segment.
                    ("lo6", &["2001:db8::1/128"], AdminState::Up),
                ],
            ),
            device(
                "r2",
                &[
                    ("eth0", &["2001:db8:0:1::2/64"], AdminState::Up),
                    ("lo6", &["2001:db8::1/128"], AdminState::Up),
                ],
            ),
        ]);
        let links = infer_links_from_subnets(&n);
        assert_eq!(links.len(), 1);
        assert_eq!(
            pair_key(&links[0].a, &links[0].b),
            (ep("r1", "eth0"), ep("r2", "eth0"))
        );
        assert_eq!(links[0].origin, LinkOrigin::InferredFromSubnet);
    }

    #[test]
    fn deux_interfaces_du_meme_equipement_ne_font_pas_un_lien() {
        let n = network(vec![device(
            "r1",
            &[
                ("eth0", &["10.0.0.1/24"], AdminState::Up),
                ("eth1", &["10.0.0.2/24"], AdminState::Up),
            ],
        )]);
        assert!(infer_links_from_subnets(&n).is_empty());
        // Mais le chevauchement (même sous-réseau) est bien signalé.
        assert!(check_topology(&n)
            .iter()
            .any(|i| i.kind == TopologyIssueKind::OverlappingSubnets));
    }

    #[test]
    fn determinisme_deux_appels_meme_resultat() {
        // Un réseau mélangé : lien franc IPv4, segment ambigu, isolée IPv6.
        let n = network(vec![
            device(
                "r1",
                &[
                    ("p2p", &["10.0.0.1/30"], AdminState::Up),
                    ("lan", &["192.168.1.1/24"], AdminState::Up),
                    ("wan6", &["2001:db8:ffff::1/64"], AdminState::Up),
                ],
            ),
            device(
                "r2",
                &[
                    ("p2p", &["10.0.0.2/30"], AdminState::Up),
                    ("lan", &["192.168.1.2/24"], AdminState::Up),
                ],
            ),
            device("r3", &[("lan", &["192.168.1.3/24"], AdminState::Up)]),
        ]);
        assert_eq!(infer_links_from_subnets(&n), infer_links_from_subnets(&n));
        assert_eq!(check_topology(&n), check_topology(&n));
    }

    #[test]
    fn affichage_en_francais() {
        let issue = TopologyIssue::new(
            Severity::Warning,
            TopologyIssueKind::AmbiguousSegment,
            "segment ambigu".to_owned(),
        );
        assert_eq!(issue.to_string(), "avertissement : segment ambigu");
    }
}
