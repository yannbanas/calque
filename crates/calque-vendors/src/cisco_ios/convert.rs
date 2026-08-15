//! Conversion arbre générique → représentation intermédiaire pour
//! Cisco IOS / IOS-XE. Voir l'en-tête de `mod.rs` pour les choix de
//! modélisation.
//!
//! Discipline §6.3, appliquée partout dans ce module :
//! - un mot-clé COMPRIS et porteur de sens → mappé vers le modèle ;
//! - un mot-clé COMPRIS et sans effet sur le filtrage/routage du trafic
//!   transitant → accepté explicitement, liste par liste (voir les
//!   constantes `*_IGNORABLE` ci-dessous) ;
//! - tout le reste → `Diagnostic` avec span, accumulé dans
//!   `Fidelity::Partial`. Jamais d'ignorance silencieuse.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr};

use calque_model::{
    Action, AddrExpr, AddrObject, AdminState, Device, DeviceId, Diagnostic, Fidelity, IfaceId,
    Interface, NextHop, ObjectId, Policy, PolicyId, PortRange, ProtoMatch, Route, RouteOrigin,
    Rule, RuleId, RuleMatch, Service, ServiceExpr, ServiceObject, Severity, SourceSpan, Vendor,
    VrfId, ZoneId,
};
use ipnet::IpNet;

use super::values::{self, AclProto};
use crate::{directive_excerpt, AdapterOutput, ConfigNode, ConfigTree};

/// Distance administrative par défaut d'une route statique IOS.
const DEFAULT_STATIC_DISTANCE: u32 = 1;

/// Directives de PREMIER NIVEAU reconnues comme sans effet sur le
/// filtrage et le routage du trafic TRANSITANT (plan de gestion,
/// cosmétique, couche 2 locale). Les accepter n'est pas deviner :
/// chacune est listée explicitement (§6.3). Le sous-arbre entier est
/// couvert (ex. les enfants d'un bloc `line vty`).
const ROOT_IGNORABLE: &[&str] = &[
    "alias",
    "archive",
    "banner",
    "boot",
    "boot-end-marker",
    "boot-start-marker",
    "call-home",
    "cdp",
    "clock",
    "control-plane",
    "diagnostic",
    "dot1x",
    "end",
    "errdisable",
    "exit",
    "license",
    "line",
    "lldp",
    "logging",
    "login",
    "memory-size",
    "monitor",
    "multilink",
    "ntp",
    "parser",
    "platform",
    "privilege",
    "redundancy",
    "scheduler",
    "service",
    "snmp-server",
    "spanning-tree",
    "udld",
    "version",
    "vtp",
];

/// `aaa ...` est aussi de premier niveau ; listé à part car la
/// directive `aaa` recouvre authentification/comptabilité, jamais le
/// filtrage du trafic transitant.
const ROOT_IGNORABLE_AAA: &str = "aaa";

/// Formes `no ...` de premier niveau reconnues sans effet (préfixes).
const NO_ROOT_IGNORABLE: &[&str] = &[
    "aaa",
    "banner",
    "cdp",
    "errdisable",
    "ip bootp",
    "ip domain lookup",
    "ip domain-lookup",
    "ip finger",
    "ip forward-protocol",
    "ip gratuitous-arps",
    "ip http",
    "ip source-route",
    "logging",
    "login",
    "ntp",
    "platform",
    "service",
    "snmp-server",
    "spanning-tree",
    "vtp",
];

/// Sous-directives `ip ...` de premier niveau reconnues sans effet
/// (résolution de noms, gestion, services locaux à l'équipement).
const IP_ROOT_IGNORABLE: &[&str] = &[
    "bootp",
    "cef",
    "classless",
    "dhcp",
    "domain",
    "domain-list",
    "domain-lookup",
    "domain-name",
    "finger",
    "forward-protocol",
    "gratuitous-arps",
    "host",
    "http",
    "name-server",
    "radius",
    "scp",
    "ssh",
    "subnet-zero",
    "tacacs",
    "tftp",
];

/// Directives d'INTERFACE reconnues sans effet sur l'accessibilité
/// (négociation physique, cosmétique, supervision).
const IFACE_IGNORABLE: &[&str] = &[
    "bandwidth",
    "cdp",
    "delay",
    "description",
    "duplex",
    "hold-queue",
    "keepalive",
    "load-interval",
    "logging",
    "media-type",
    "negotiation",
    "spanning-tree",
    "speed",
];

/// Formes `no ...` d'interface reconnues sans effet (préfixes),
/// `no shutdown` étant traité à part (état administratif).
const IFACE_NO_IGNORABLE: &[&str] = &[
    "cdp enable",
    "ip proxy-arp",
    "ip redirects",
    "ip unreachables",
    "keepalive",
    "logging event",
    "mop enabled",
    "mop sysid",
    "negotiation",
    "snmp trap",
];

pub(super) fn convert(tree: &ConfigTree) -> Result<AdapterOutput, Vec<Diagnostic>> {
    if tree.roots.is_empty() {
        return Err(vec![Diagnostic::error(
            "configuration vide ou inexploitable : aucune directive reconnue",
            Some(SourceSpan::new(tree.file.as_str(), 1)),
        )]);
    }
    let mut conv = Converter::new(tree);
    for root in &tree.roots {
        conv.dispatch(root);
    }
    Ok(conv.finish())
}

/// Sens d'accrochage d'une ACL sur une interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Direction {
    In,
    Out,
}

impl std::fmt::Display for Direction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Direction::In => "in",
            Direction::Out => "out",
        })
    }
}

/// Sorte d'ACL : standard (source seule) ou étendue (5-uplet).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AclKind {
    Standard,
    Extended,
}

/// Une entrée d'ACL déjà comprise, en attente d'accrochage.
struct AclEntry {
    id: RuleId,
    action: Action,
    matches: RuleMatch,
    span: SourceSpan,
}

/// Une ACL nommée ou numérotée : ses entrées ORDONNÉES et le span de sa
/// première apparition (pour les notes).
struct AclDef {
    entries: Vec<AclEntry>,
    span: SourceSpan,
}

/// Un `ip access-group NOM in|out` rencontré sur une interface.
struct Binding {
    iface: IfaceId,
    acl: String,
    dir: Direction,
    span: SourceSpan,
}

struct Converter {
    device: Device,
    /// Ce qui n'a PAS été compris → `Fidelity::Partial` (§6.3).
    unsupported: Vec<Diagnostic>,
    /// Constats informatifs qui ne dégradent pas la fidélité.
    notes: Vec<Diagnostic>,
    /// ACL comprises, matérialisées en politiques à la fin (les ACL
    /// sont souvent définies APRÈS les interfaces qui les référencent).
    acls: BTreeMap<String, AclDef>,
    /// Ordre de PREMIÈRE définition des ACL (les BTreeMap trient par
    /// nom ; les notes et politiques non branchées suivent le fichier).
    acl_order: Vec<String>,
    bindings: Vec<Binding>,
}

impl Converter {
    fn new(tree: &ConfigTree) -> Self {
        // Identifiant provisoire tiré du nom de fichier ; remplacé par
        // `hostname` s'il est présent.
        let id = DeviceId::new(file_stem(&tree.file));
        Self {
            device: Device::new(id, Vendor::CiscoIos),
            unsupported: Vec::new(),
            notes: Vec::new(),
            acls: BTreeMap::new(),
            acl_order: Vec::new(),
            bindings: Vec::new(),
        }
    }

    fn finish(mut self) -> AdapterOutput {
        self.materialize_bindings();
        let fidelity = if self.unsupported.is_empty() {
            Fidelity::Complete
        } else {
            Fidelity::Partial {
                unsupported: self.unsupported,
            }
        };
        AdapterOutput {
            device: self.device,
            fidelity,
            notes: self.notes,
        }
    }

    // -- accumulation de diagnostics ------------------------------------

    fn unsupported(&mut self, message: String, span: &SourceSpan) {
        self.unsupported
            .push(Diagnostic::warning(message, Some(span.clone())));
    }

    fn note_info(&mut self, message: String, span: &SourceSpan) {
        self.notes.push(Diagnostic {
            severity: Severity::Info,
            message,
            span: Some(span.clone()),
        });
    }

    fn note_warning(&mut self, message: String, span: &SourceSpan) {
        self.notes
            .push(Diagnostic::warning(message, Some(span.clone())));
    }

    // -- répartition de premier niveau ----------------------------------

    fn dispatch(&mut self, node: &ConfigNode) {
        let kw = node.keyword.as_str();
        match kw {
            "hostname" => match node.arg(0) {
                Some(name) => self.device.id = DeviceId::new(name),
                None => self.unsupported("`hostname` sans nom".to_owned(), &node.span),
            },
            "interface" => self.interface_block(node),
            "ip" => self.ip_root(node),
            "access-list" => self.numbered_acl_line(node),
            "object-group" => self.object_group(node),
            "vrf" => self.vrf_root(node),
            "no" => self.no_root(node),
            // Les secrets sont constatés, jamais modélisés ni ignorés
            // en silence — et leur VALEUR ne va jamais dans un diagnostic.
            // `secret`/`password` peuvent être précédés d'options
            // (`enable algorithm-type sha256 secret …`).
            "enable" => {
                if node.args.iter().any(|a| a == "secret" || a == "password") {
                    self.note_info(
                        "secret d'activation présent, non modélisé".to_owned(),
                        &node.span,
                    );
                } else {
                    self.unsupported(
                        format!("`{}` non géré", directive_excerpt("enable", &node.args, 1)),
                        &node.span,
                    );
                }
            }
            "username" => self.note_info(
                format!(
                    "compte local `{}` : secret présent, non modélisé",
                    node.arg(0).unwrap_or("?")
                ),
                &node.span,
            ),
            // `crypto pki` (certificats) est sans effet sur le trafic
            // transitant ; le reste de `crypto` (map, isakmp, ipsec)
            // détourne du trafic vers des tunnels : non modélisé.
            // Message tronqué à dessein : `crypto isakmp key S3CRET …`
            // porte un secret, qui ne doit pas fuiter dans un diagnostic.
            "crypto" => match node.arg(0) {
                Some("pki") => {}
                _ => self.unsupported(
                    format!(
                        "`{}` non modélisé (VPN : le trafic peut être détourné)",
                        directive_excerpt("crypto", &node.args, 1)
                    ),
                    &node.span,
                ),
            },
            // Les routes d'un protocole dynamique ne sont pas dans le
            // fichier : impossible de les modéliser hors ligne.
            "router" => self.unsupported(
                format!(
                    "`router {}` : routage dynamique non modélisable hors ligne",
                    node.args_joined()
                ),
                &node.span,
            ),
            _ if kw == ROOT_IGNORABLE_AAA || ROOT_IGNORABLE.contains(&kw) => {}
            _ => self.unsupported(
                format!("directive de premier niveau `{kw}` non gérée"),
                &node.span,
            ),
        }
    }

    fn no_root(&mut self, node: &ConfigNode) {
        let rest = node.args.join(" ");
        if NO_ROOT_IGNORABLE
            .iter()
            .any(|p| rest == *p || rest.starts_with(&format!("{p} ")))
        {
            return;
        }
        self.unsupported(
            format!("`{}` non géré", directive_excerpt("no", &node.args, 2)),
            &node.span,
        );
    }

    fn ip_root(&mut self, node: &ConfigNode) {
        match node.arg(0) {
            Some("route") => self.route_line(node),
            Some("access-list") => self.named_acl(node),
            Some("vrf") => self.ip_vrf_block(node),
            Some("nat") => self.unsupported(
                format!(
                    "NAT IOS non modélisé (`ip {}`) : les adresses traduites fausseraient les verdicts",
                    node.args_joined()
                ),
                &node.span,
            ),
            Some("default-gateway") => self.unsupported(
                "`ip default-gateway` non géré (routage sans `ip routing`)".to_owned(),
                &node.span,
            ),
            Some(sub) if IP_ROOT_IGNORABLE.contains(&sub) => {}
            // Message tronqué : `ip ftp password …` porterait un secret.
            _ => self.unsupported(
                format!("`{}` non géré", directive_excerpt("ip", &node.args, 2)),
                &node.span,
            ),
        }
    }

    // -- interfaces ------------------------------------------------------

    fn interface_block(&mut self, node: &ConfigNode) {
        let name = node.args_joined();
        if name.is_empty() {
            self.unsupported("`interface` sans nom".to_owned(), &node.span);
            return;
        }
        let mut iface = Interface::new(IfaceId::new(name.as_str()));
        for d in &node.children {
            let kw = d.keyword.as_str();
            match kw {
                "shutdown" => iface.state = AdminState::Down,
                "no" => self.iface_no(d, &mut iface, &name),
                "ip" => self.iface_ip(d, &mut iface, &name),
                "vrf" if d.arg(0) == Some("forwarding") => {
                    self.set_iface_vrf(d.arg(1), &mut iface, &name, &d.span)
                }
                "encapsulation" => self.iface_encapsulation(d, &mut iface, &name),
                "switchport" => self.iface_switchport(d, &mut iface, &name),
                // Redondance de passerelle : l'adresse VIRTUELLE portée
                // par le groupe n'est pas sur l'interface ; l'ignorer
                // fausserait l'accessibilité.
                "standby" | "vrrp" | "glbp" => self.unsupported(
                    format!(
                        "redondance de passerelle `{kw}` non modélisée sur `{name}` (adresse virtuelle)"
                    ),
                    &d.span,
                ),
                "crypto" => self.unsupported(
                    format!(
                        "`{}` non modélisé sur `{name}` (VPN)",
                        directive_excerpt("crypto", &d.args, 1)
                    ),
                    &d.span,
                ),
                _ if IFACE_IGNORABLE.contains(&kw) => {}
                // Message tronqué : une directive inconnue peut porter un
                // secret (`ppp chap password 0 …`).
                _ => self.unsupported(
                    format!(
                        "directive `{}` non gérée sur l'interface `{name}`",
                        directive_excerpt(kw, &d.args, 1)
                    ),
                    &d.span,
                ),
            }
        }
        // Sur l'équipement réel, rouvrir `interface X` FUSIONNE les
        // directives ; ici la seconde définition REMPLACE la première.
        // Fusionner serait deviner (§6.3) : on remplace ET on dégrade la
        // fidélité pour que le verdict ne soit pas ferme.
        if self.device.interfaces.contains_key(&iface.id) {
            self.unsupported(
                format!(
                    "interface `{name}` redéfinie : la nouvelle définition remplace la \
                     première (l'équipement réel les fusionnerait)"
                ),
                &node.span,
            );
        }
        self.device.interfaces.insert(iface.id.clone(), iface);
    }

    fn iface_no(&mut self, d: &ConfigNode, iface: &mut Interface, name: &str) {
        let rest = d.args.join(" ");
        if rest == "shutdown" {
            iface.state = AdminState::Up;
            return;
        }
        if IFACE_NO_IGNORABLE
            .iter()
            .any(|p| rest == *p || rest.starts_with(&format!("{p} ")))
        {
            return;
        }
        self.unsupported(
            format!(
                "`{}` non géré sur l'interface `{name}`",
                directive_excerpt("no", &d.args, 2)
            ),
            &d.span,
        );
    }

    fn iface_ip(&mut self, d: &ConfigNode, iface: &mut Interface, name: &str) {
        match d.arg(0) {
            Some("address") => match d.arg(1) {
                // L'adresse n'est pas dans le fichier : pas modélisable
                // hors ligne.
                Some("dhcp") => self.unsupported(
                    format!("adresse DHCP non modélisable hors ligne (`{name}`)"),
                    &d.span,
                ),
                Some(addr) => {
                    match values::ip_mask_to_net(addr, d.arg(2).unwrap_or("")) {
                        Some(net) => match d.arg(3) {
                            // `secondary` : adresse additionnelle, même
                            // vecteur — l'ordre du fichier est conservé.
                            None | Some("secondary") => iface.addrs.push(net),
                            Some(extra) => self.unsupported(
                                format!(
                                    "`ip address ... {extra}` non géré sur l'interface `{name}`"
                                ),
                                &d.span,
                            ),
                        },
                        None => self.unsupported(
                            format!(
                                "adresse invalide ou masque non contigu `ip {}` sur `{name}`",
                                d.args_joined()
                            ),
                            &d.span,
                        ),
                    }
                }
                None => {
                    self.unsupported(format!("`ip address` sans adresse sur `{name}`"), &d.span)
                }
            },
            Some("access-group") => match (d.arg(1), d.arg(2)) {
                (Some(acl), Some(dir @ ("in" | "out"))) => self.bindings.push(Binding {
                    iface: IfaceId::new(name),
                    acl: acl.to_owned(),
                    dir: if dir == "in" {
                        Direction::In
                    } else {
                        Direction::Out
                    },
                    span: d.span.clone(),
                }),
                _ => self.unsupported(
                    format!(
                        "`ip {}` invalide sur `{name}` (attendu : `ip access-group NOM in|out`)",
                        d.args_joined()
                    ),
                    &d.span,
                ),
            },
            Some("vrf") if d.arg(1) == Some("forwarding") => {
                self.set_iface_vrf(d.arg(2), iface, name, &d.span)
            }
            // NAT : jamais ignoré en silence — les adresses traduites
            // fausseraient tous les verdicts en aval.
            Some("nat") => self.unsupported(
                format!(
                    "NAT IOS non modélisé (`ip {}` sur `{name}`)",
                    d.args_joined()
                ),
                &d.span,
            ),
            // Relais DHCP : ne filtre ni ne route le trafic transitant.
            Some("helper-address") => {}
            _ => self.unsupported(
                format!(
                    "`{}` non géré sur l'interface `{name}`",
                    directive_excerpt("ip", &d.args, 2)
                ),
                &d.span,
            ),
        }
    }

    fn set_iface_vrf(
        &mut self,
        vrf: Option<&str>,
        iface: &mut Interface,
        name: &str,
        span: &SourceSpan,
    ) {
        match vrf {
            Some(v) => {
                let vid = VrfId::new(v);
                self.device.vrfs.entry(vid.clone()).or_default();
                iface.vrf = vid;
            }
            None => self.unsupported(
                format!("`vrf forwarding` sans nom de VRF sur `{name}`"),
                span,
            ),
        }
    }

    fn iface_encapsulation(&mut self, d: &ConfigNode, iface: &mut Interface, name: &str) {
        if !d.arg(0).is_some_and(|a| a.eq_ignore_ascii_case("dot1q")) {
            self.unsupported(
                format!("encapsulation `{}` non gérée sur `{name}`", d.args_joined()),
                &d.span,
            );
            return;
        }
        match d.arg(1).and_then(|v| v.parse::<u16>().ok()) {
            Some(vlan) => {
                iface.vlan = Some(vlan);
                if let Some(extra) = d.arg(2) {
                    // `native` : VLAN natif du trunk, sans effet sur le
                    // pavé d'en-têtes modélisé.
                    if extra != "native" {
                        self.unsupported(
                            format!("`encapsulation dot1Q ... {extra}` non géré sur `{name}`"),
                            &d.span,
                        );
                    }
                }
            }
            None => self.unsupported(
                format!("`encapsulation dot1Q` sans numéro de VLAN valide sur `{name}`"),
                &d.span,
            ),
        }
    }

    fn iface_switchport(&mut self, d: &ConfigNode, iface: &mut Interface, name: &str) {
        let args: Vec<&str> = d.args.iter().map(String::as_str).collect();
        match args.as_slice() {
            // `switchport` seul bascule le port en couche 2.
            [] | ["mode", "access"] => {}
            ["access", "vlan", v] => match v.parse::<u16>() {
                Ok(vlan) => iface.vlan = Some(vlan),
                Err(_) => self.unsupported(
                    format!("`switchport access vlan {v}` invalide sur `{name}`"),
                    &d.span,
                ),
            },
            _ => self.unsupported(
                format!("`switchport {}` non géré sur `{name}`", d.args_joined()),
                &d.span,
            ),
        }
    }

    // -- routes statiques ------------------------------------------------

    /// `ip route [vrf NOM] PRÉFIXE MASQUE (IP|INTERFACE|Null0) [DISTANCE]`.
    fn route_line(&mut self, node: &ConfigNode) {
        let toks: Vec<&str> = node.args.iter().skip(1).map(String::as_str).collect();
        let mut i = 0usize;
        let mut vrf = VrfId::default_vrf();
        if toks.first() == Some(&"vrf") {
            match toks.get(1) {
                Some(v) => {
                    vrf = VrfId::new(*v);
                    i = 2;
                }
                None => {
                    self.unsupported("`ip route vrf` sans nom de VRF".to_owned(), &node.span);
                    return;
                }
            }
        }
        let (Some(dst), Some(mask)) = (toks.get(i), toks.get(i + 1)) else {
            self.unsupported(
                format!("route incomplète `ip {}`", node.args_joined()),
                &node.span,
            );
            return;
        };
        let Some(net) = values::ip_mask_to_net(dst, mask) else {
            self.unsupported(
                format!(
                    "destination invalide ou masque non contigu sur la route `ip {}`",
                    node.args_joined()
                ),
                &node.span,
            );
            return;
        };
        // Une destination de route est un réseau : bits d'hôte normalisés.
        let prefix = net.trunc();
        let Some(nh) = toks.get(i + 2) else {
            self.unsupported(
                format!("route sans prochain saut `ip {}`", node.args_joined()),
                &node.span,
            );
            return;
        };
        let next_hop = if nh.eq_ignore_ascii_case("null0") {
            // `Null0` est la route de rejet idiomatique d'IOS.
            NextHop::Drop
        } else if let Ok(ip) = nh.parse::<IpAddr>() {
            NextHop::Ip(ip)
        } else {
            // Forme `INTERFACE PASSERELLE` : le modèle ne porte qu'UN
            // prochain saut ; retenir l'un des deux serait deviner.
            if toks.get(i + 3).is_some_and(|t| t.parse::<IpAddr>().is_ok()) {
                self.unsupported(
                    format!(
                        "forme `interface + passerelle` non représentable : route `ip {}` non modélisée",
                        node.args_joined()
                    ),
                    &node.span,
                );
                return;
            }
            NextHop::Interface(IfaceId::new(*nh))
        };
        i += 3;
        let mut metric = DEFAULT_STATIC_DISTANCE;
        if let Some(d) = toks.get(i).and_then(|t| t.parse::<u32>().ok()) {
            metric = d;
            i += 1;
        }
        while i < toks.len() {
            match toks[i] {
                // `name` est une étiquette purement descriptive.
                "name" if toks.get(i + 1).is_some() => i += 2,
                extra => {
                    self.unsupported(
                        format!(
                            "option `{extra}` non gérée : route `ip {}` non modélisée",
                            node.args_joined()
                        ),
                        &node.span,
                    );
                    return;
                }
            }
        }
        self.device.vrfs.entry(vrf).or_default().routes.push(Route {
            prefix,
            next_hop,
            // Distance administrative IOS → métrique du modèle.
            metric,
            origin: RouteOrigin::Static,
            source: Some(node.span.clone()),
        });
    }

    // -- VRF -------------------------------------------------------------

    /// `ip vrf NOM` (ancienne forme). `rd`/`description` sont sans effet
    /// sur le filtrage local ; `route-target` (fuite de routes MPLS)
    /// ne l'est pas.
    fn ip_vrf_block(&mut self, node: &ConfigNode) {
        let Some(name) = node.arg(1) else {
            self.unsupported("`ip vrf` sans nom".to_owned(), &node.span);
            return;
        };
        self.device.vrfs.entry(VrfId::new(name)).or_default();
        for d in &node.children {
            match d.keyword.as_str() {
                "rd" | "description" => {}
                "route-target" => self.unsupported(
                    format!("fuite de routes `route-target` non modélisée (VRF `{name}`)"),
                    &d.span,
                ),
                kw => self.unsupported(
                    format!("directive `{kw}` non gérée dans le VRF `{name}`"),
                    &d.span,
                ),
            }
        }
    }

    /// `vrf definition NOM` (forme IOS-XE).
    fn vrf_root(&mut self, node: &ConfigNode) {
        if node.arg(0) != Some("definition") {
            self.unsupported(format!("`vrf {}` non géré", node.args_joined()), &node.span);
            return;
        }
        let Some(name) = node.arg(1) else {
            self.unsupported("`vrf definition` sans nom".to_owned(), &node.span);
            return;
        };
        self.device.vrfs.entry(VrfId::new(name)).or_default();
        for d in &node.children {
            match d.keyword.as_str() {
                "rd" | "description" | "address-family" | "exit-address-family" => {}
                "route-target" => self.unsupported(
                    format!("fuite de routes `route-target` non modélisée (VRF `{name}`)"),
                    &d.span,
                ),
                kw => self.unsupported(
                    format!("directive `{kw}` non gérée dans le VRF `{name}`"),
                    &d.span,
                ),
            }
        }
    }

    // -- object-groups ---------------------------------------------------

    fn object_group(&mut self, node: &ConfigNode) {
        match node.arg(0) {
            Some("network") => self.og_network(node),
            Some("service") => self.og_service(node),
            other => self.unsupported(
                format!("type d'object-group `{}` non géré", other.unwrap_or("?")),
                &node.span,
            ),
        }
    }

    fn og_network(&mut self, node: &ConfigNode) {
        let Some(name) = node.arg(1) else {
            self.unsupported("`object-group network` sans nom".to_owned(), &node.span);
            return;
        };
        let name = name.to_owned();
        let mut nets: Vec<IpNet> = Vec::new();
        let mut groups: Vec<ObjectId> = Vec::new();
        for d in &node.children {
            let kw = d.keyword.as_str();
            match kw {
                "description" => {}
                "host" => match d.arg(0).and_then(values::host_net) {
                    Some(net) => nets.push(net),
                    None => self.unsupported(
                        format!(
                            "`host {}` invalide dans l'object-group `{name}`",
                            d.args_joined()
                        ),
                        &d.span,
                    ),
                },
                "group-object" => match d.arg(0) {
                    Some(g) => {
                        let oid = ObjectId::new(g);
                        // Résolution tardive (§3.3), mais une référence
                        // brisée est signalée dès l'import.
                        if !self.device.objects.addresses.contains_key(&oid) {
                            self.note_warning(
                                format!(
                                    "l'object-group `{name}` référence un groupe inconnu `{g}`"
                                ),
                                &d.span,
                            );
                        }
                        groups.push(oid);
                    }
                    None => self.unsupported(
                        format!("`group-object` sans nom dans l'object-group `{name}`"),
                        &d.span,
                    ),
                },
                "range" => {
                    let bounds = d
                        .arg(0)
                        .and_then(|a| a.parse::<Ipv4Addr>().ok())
                        .zip(d.arg(1).and_then(|b| b.parse::<Ipv4Addr>().ok()));
                    match bounds {
                        Some((a, b)) => {
                            let r = values::range_to_nets(a, b);
                            if r.is_empty() {
                                self.unsupported(
                                    format!("plage vide ou inversée dans l'object-group `{name}`"),
                                    &d.span,
                                );
                            } else {
                                nets.extend(r);
                            }
                        }
                        None => self.unsupported(
                            format!(
                                "`range {}` invalide dans l'object-group `{name}`",
                                d.args_joined()
                            ),
                            &d.span,
                        ),
                    }
                }
                // Membre `RÉSEAU MASQUE` : le premier jeton est l'adresse.
                _ => {
                    let parsed = kw
                        .parse::<Ipv4Addr>()
                        .ok()
                        .and_then(|_| values::ip_mask_to_net(kw, d.arg(0).unwrap_or("")));
                    match parsed {
                        Some(net) => nets.push(net.trunc()),
                        None => self.unsupported(
                            format!(
                                "membre `{kw} {}` non géré dans l'object-group `{name}` \
                                 (adresse invalide ou masque non contigu ?)",
                                d.args_joined()
                            ),
                            &d.span,
                        ),
                    }
                }
            }
        }
        self.store_addr_group(name, nets, groups, &node.span);
    }

    /// Range un object-group network dans l'`ObjectStore`. Un groupe
    /// MIXTE (membres directs + `group-object`) ne tient pas dans
    /// `AddrObject` (Nets OU Group) : les membres directs sont regroupés
    /// sous un objet auxiliaire `NOM::membres-directs` référencé par le
    /// groupe — la sémantique (union) est préservée EXACTEMENT, ce n'est
    /// pas une supposition. Une note documente la transformation.
    fn store_addr_group(
        &mut self,
        name: String,
        nets: Vec<IpNet>,
        groups: Vec<ObjectId>,
        span: &SourceSpan,
    ) {
        let obj = match (nets.is_empty(), groups.is_empty()) {
            (false, true) => AddrObject::Nets(nets),
            (true, false) => AddrObject::Group(groups),
            (false, false) => {
                let direct = ObjectId::new(format!("{name}::membres-directs"));
                self.note_info(
                    format!(
                        "object-group `{name}` mixte : membres directs regroupés sous \
                         `{direct}` (sémantique préservée)"
                    ),
                    span,
                );
                self.device
                    .objects
                    .addresses
                    .insert(direct.clone(), AddrObject::Nets(nets));
                let mut all = groups;
                all.push(direct);
                AddrObject::Group(all)
            }
            (true, true) => {
                self.unsupported(format!("object-group `{name}` vide"), span);
                return;
            }
        };
        // IOS fusionne un object-group rouvert ; remplacer sans le dire
        // fausserait les règles qui le référencent (§6.3).
        let oid = ObjectId::new(name.as_str());
        if self.device.objects.addresses.contains_key(&oid) {
            self.unsupported(
                format!(
                    "object-group `{name}` redéfini : la nouvelle définition remplace la \
                     première (l'équipement réel les fusionnerait)"
                ),
                span,
            );
        }
        self.device.objects.addresses.insert(oid, obj);
    }

    fn og_service(&mut self, node: &ConfigNode) {
        let Some(name) = node.arg(1) else {
            self.unsupported("`object-group service` sans nom".to_owned(), &node.span);
            return;
        };
        let name = name.to_owned();
        let mut svcs: Vec<Service> = Vec::new();
        let mut groups: Vec<ObjectId> = Vec::new();
        for d in &node.children {
            let kw = d.keyword.as_str();
            match kw {
                "description" => {}
                "group-object" => match d.arg(0) {
                    Some(g) => {
                        let oid = ObjectId::new(g);
                        if !self.device.objects.services.contains_key(&oid) {
                            self.note_warning(
                                format!(
                                    "l'object-group service `{name}` référence un groupe \
                                     inconnu `{g}`"
                                ),
                                &d.span,
                            );
                        }
                        groups.push(oid);
                    }
                    None => self.unsupported(
                        format!("`group-object` sans nom dans l'object-group service `{name}`"),
                        &d.span,
                    ),
                },
                "tcp" | "udp" | "tcp-udp" => {
                    let protos: &[u8] = match kw {
                        "tcp" => &[6],
                        "udp" => &[17],
                        _ => &[6, 17],
                    };
                    match service_ports(&d.args) {
                        Ok((sports, dports)) => {
                            for p in protos {
                                for sp in &sports {
                                    for dp in &dports {
                                        svcs.push(Service {
                                            proto: ProtoMatch::Number(*p),
                                            sport: *sp,
                                            dport: *dp,
                                        });
                                    }
                                }
                            }
                        }
                        Err(e) => self.unsupported(
                            format!(
                                "membre `{kw} {}` de l'object-group service `{name}` : {e}",
                                d.args_joined()
                            ),
                            &d.span,
                        ),
                    }
                }
                // Un protocole nu (`esp`, `gre`, `47`…) est un membre valide.
                _ => match values::acl_proto(kw) {
                    Some(AclProto::Number(p)) if d.args.is_empty() => svcs.push(Service {
                        proto: ProtoMatch::Number(p),
                        sport: PortRange::ANY,
                        dport: PortRange::ANY,
                    }),
                    _ => self.unsupported(
                        format!(
                            "membre `{kw} {}` non géré dans l'object-group service `{name}`",
                            d.args_joined()
                        ),
                        &d.span,
                    ),
                },
            }
        }
        self.store_service_group(name, svcs, groups, &node.span);
    }

    /// Même transformation que [`Self::store_addr_group`], côté services.
    fn store_service_group(
        &mut self,
        name: String,
        svcs: Vec<Service>,
        groups: Vec<ObjectId>,
        span: &SourceSpan,
    ) {
        let obj = match (svcs.is_empty(), groups.is_empty()) {
            (false, true) => ServiceObject::Services(svcs),
            (true, false) => ServiceObject::Group(groups),
            (false, false) => {
                let direct = ObjectId::new(format!("{name}::membres-directs"));
                self.note_info(
                    format!(
                        "object-group service `{name}` mixte : membres directs regroupés \
                         sous `{direct}` (sémantique préservée)"
                    ),
                    span,
                );
                self.device
                    .objects
                    .services
                    .insert(direct.clone(), ServiceObject::Services(svcs));
                let mut all = groups;
                all.push(direct);
                ServiceObject::Group(all)
            }
            (true, true) => {
                self.unsupported(format!("object-group service `{name}` vide"), span);
                return;
            }
        };
        let oid = ObjectId::new(name.as_str());
        if self.device.objects.services.contains_key(&oid) {
            self.unsupported(
                format!(
                    "object-group service `{name}` redéfini : la nouvelle définition \
                     remplace la première (l'équipement réel les fusionnerait)"
                ),
                span,
            );
        }
        self.device.objects.services.insert(oid, obj);
    }

    // -- ACL nommées -----------------------------------------------------

    fn named_acl(&mut self, node: &ConfigNode) {
        let kind = match node.arg(1) {
            Some("extended") => AclKind::Extended,
            Some("standard") => AclKind::Standard,
            _ => {
                self.unsupported(format!("`ip {}` non géré", node.args_joined()), &node.span);
                return;
            }
        };
        let Some(name) = node.arg(2) else {
            self.unsupported(
                format!("`ip access-list` sans nom (`ip {}`)", node.args_joined()),
                &node.span,
            );
            return;
        };
        let name = name.to_owned();
        // IOS autorise la ré-ouverture d'une ACL : les entrées s'ajoutent.
        let mut def = self.take_acl(&name, &node.span);
        for child in &node.children {
            // Une entrée peut porter un numéro de SÉQUENCE explicite :
            // `10 permit tcp ...` — le mot-clé est alors le numéro.
            let (seq, action_kw, toks): (Option<&str>, &str, &[String]) =
                if child.keyword.parse::<u32>().is_ok() {
                    match child.arg(0) {
                        Some(a @ ("permit" | "deny")) => {
                            (Some(child.keyword.as_str()), a, &child.args[1..])
                        }
                        _ => {
                            self.unsupported(
                                format!(
                                    "entrée `{} {}` non gérée dans l'ACL `{name}`",
                                    child.keyword,
                                    child.args_joined()
                                ),
                                &child.span,
                            );
                            continue;
                        }
                    }
                } else {
                    (None, child.keyword.as_str(), &child.args[..])
                };
            match action_kw {
                // Un commentaire d'ACL, sans effet.
                "remark" => {}
                "permit" | "deny" => {
                    let action = if action_kw == "permit" {
                        Action::Accept
                    } else {
                        Action::Deny
                    };
                    let parsed = match kind {
                        AclKind::Extended => self.extended_match(toks, &child.span),
                        AclKind::Standard => self.standard_match(toks, &child.span),
                    };
                    match parsed {
                        Ok(matches) => {
                            let id = seq
                                .map(str::to_owned)
                                .unwrap_or_else(|| (def.entries.len() + 1).to_string());
                            def.entries.push(AclEntry {
                                id: RuleId::new(id),
                                action,
                                matches,
                                span: child.span.clone(),
                            });
                        }
                        Err(e) => self.unsupported(
                            format!("ACL `{name}` : {e} — entrée non modélisée"),
                            &child.span,
                        ),
                    }
                }
                other => self.unsupported(
                    format!("`{other}` non géré dans l'ACL `{name}`"),
                    &child.span,
                ),
            }
        }
        self.acls.insert(name, def);
    }

    // -- ACL numérotées (une directive par ligne) ------------------------

    fn numbered_acl_line(&mut self, node: &ConfigNode) {
        let Some(num) = node.arg(0) else {
            self.unsupported("`access-list` sans numéro".to_owned(), &node.span);
            return;
        };
        let Ok(n) = num.parse::<u32>() else {
            self.unsupported(
                format!("`access-list {}` non géré", node.args_joined()),
                &node.span,
            );
            return;
        };
        let kind = if (1..=99).contains(&n) || (1300..=1999).contains(&n) {
            AclKind::Standard
        } else if (100..=199).contains(&n) || (2000..=2699).contains(&n) {
            AclKind::Extended
        } else {
            self.unsupported(
                format!("numéro d'ACL `{n}` hors des plages standard/étendue gérées"),
                &node.span,
            );
            return;
        };
        let name = num.to_owned();
        match node.arg(1) {
            // Le commentaire réserve l'ACL sans lui ajouter d'entrée.
            Some("remark") => {
                let def = self.take_acl(&name, &node.span);
                self.acls.insert(name, def);
            }
            Some(a @ ("permit" | "deny")) => {
                let action = if a == "permit" {
                    Action::Accept
                } else {
                    Action::Deny
                };
                let toks = &node.args[2..];
                let parsed = match kind {
                    AclKind::Extended => self.extended_match(toks, &node.span),
                    AclKind::Standard => self.standard_match(toks, &node.span),
                };
                let mut def = self.take_acl(&name, &node.span);
                match parsed {
                    Ok(matches) => def.entries.push(AclEntry {
                        id: RuleId::new((def.entries.len() + 1).to_string()),
                        action,
                        matches,
                        span: node.span.clone(),
                    }),
                    Err(e) => self.unsupported(
                        format!("ACL {name} : {e} — entrée non modélisée"),
                        &node.span,
                    ),
                }
                self.acls.insert(name, def);
            }
            _ => self.unsupported(
                format!("`access-list {}` non géré", node.args_joined()),
                &node.span,
            ),
        }
    }

    /// Récupère (ou crée) une ACL en préservant l'ordre de première
    /// définition.
    fn take_acl(&mut self, name: &str, span: &SourceSpan) -> AclDef {
        match self.acls.remove(name) {
            Some(def) => def,
            None => {
                self.acl_order.push(name.to_owned());
                AclDef {
                    entries: Vec::new(),
                    span: span.clone(),
                }
            }
        }
    }

    // -- grammaire des entrées d'ACL -------------------------------------

    /// Entrée d'ACL étendue :
    /// `PROTO SRC [PORTS] DST [PORTS] [log]`, où PROTO peut aussi être
    /// `object-group GROUPE-DE-SERVICES`.
    fn extended_match(&mut self, toks: &[String], span: &SourceSpan) -> Result<RuleMatch, String> {
        let first = toks.first().ok_or("protocole manquant")?;
        let mut svc_group: Option<ObjectId> = None;
        let mut proto = AclProto::Any;
        let mut i = if first == "object-group" {
            let g = toks.get(1).ok_or("`object-group` (services) sans nom")?;
            let oid = ObjectId::new(g.as_str());
            if !self.device.objects.services.contains_key(&oid) {
                self.unsupported(
                    format!("groupe de services `{g}` introuvable : irrésoluble à l'évaluation"),
                    span,
                );
            }
            svc_group = Some(oid);
            2
        } else {
            proto =
                values::acl_proto(first).ok_or_else(|| format!("protocole `{first}` inconnu"))?;
            1
        };
        // Seuls TCP, UDP et SCTP portent des ports.
        let l4 = matches!(
            proto,
            AclProto::Number(6) | AclProto::Number(17) | AclProto::Number(132)
        );

        let (src, n) = self.addr_spec(&toks[i..], false, span)?;
        i += n;
        let (sports, n) = if l4 {
            port_spec(&toks[i..])?
        } else {
            (vec![PortRange::ANY], 0)
        };
        i += n;
        let (dst, n) = self.addr_spec(&toks[i..], false, span)?;
        i += n;
        let (dports, n) = if l4 {
            port_spec(&toks[i..])?
        } else {
            (vec![PortRange::ANY], 0)
        };
        i += n;
        while i < toks.len() {
            match toks[i].as_str() {
                // La journalisation ne change pas le verdict.
                "log" | "log-input" => i += 1,
                t => return Err(format!("jeton `{t}` non géré")),
            }
        }

        let services = match (svc_group, proto) {
            (Some(oid), _) => vec![ServiceExpr::Object(oid)],
            // `ip` sans contrainte de port : tout protocole.
            (None, AclProto::Any) => vec![ServiceExpr::Any],
            (None, AclProto::Number(p)) => {
                let mut out = Vec::new();
                for sp in &sports {
                    for dp in &dports {
                        out.push(ServiceExpr::Service(Service {
                            proto: ProtoMatch::Number(p),
                            sport: *sp,
                            dport: *dp,
                        }));
                    }
                }
                out
            }
        };
        Ok(RuleMatch {
            src: vec![src],
            dst: vec![dst],
            services,
        })
    }

    /// Entrée d'ACL standard : SOURCE seule (`A [WILDCARD]`, `host A`,
    /// `any`), destination et services sans contrainte.
    fn standard_match(&mut self, toks: &[String], span: &SourceSpan) -> Result<RuleMatch, String> {
        let (src, n) = self.addr_spec(toks, true, span)?;
        let mut i = n;
        while i < toks.len() {
            match toks[i].as_str() {
                "log" => i += 1,
                t => return Err(format!("jeton `{t}` non géré")),
            }
        }
        Ok(RuleMatch {
            src: vec![src],
            dst: Vec::new(),
            services: Vec::new(),
        })
    }

    /// Une spécification d'adresse d'ACL : `any`, `host A`,
    /// `object-group NOM`, `A WILDCARD` — et, en ACL standard, `A` seule
    /// (équivalent d'un hôte). Rend l'expression et le nombre de jetons
    /// consommés.
    fn addr_spec(
        &mut self,
        toks: &[String],
        standard: bool,
        span: &SourceSpan,
    ) -> Result<(AddrExpr, usize), String> {
        match toks.first().map(String::as_str) {
            None => Err("spécification d'adresse manquante".to_owned()),
            Some("any") => Ok((AddrExpr::Any, 1)),
            Some("host") => {
                let a = toks.get(1).ok_or("`host` sans adresse")?;
                let net = values::host_net(a).ok_or_else(|| format!("adresse `{a}` invalide"))?;
                Ok((AddrExpr::Net(net), 2))
            }
            Some("object-group") => {
                let g = toks.get(1).ok_or("`object-group` sans nom")?;
                let oid = ObjectId::new(g.as_str());
                if !self.device.objects.addresses.contains_key(&oid) {
                    self.unsupported(
                        format!(
                            "object-group réseau `{g}` introuvable : irrésoluble à l'évaluation"
                        ),
                        span,
                    );
                }
                Ok((AddrExpr::Object(oid), 2))
            }
            Some(a) => {
                let ip: Ipv4Addr = a.parse().map_err(|_| format!("adresse `{a}` invalide"))?;
                match toks.get(1).and_then(|w| w.parse::<Ipv4Addr>().ok()) {
                    Some(w) => {
                        let net = values::ip_wildcard_to_net(ip, w).ok_or_else(|| {
                            format!(
                                "masque générique non contigu `{w}` (wildcard, PAS un masque \
                                 de sous-réseau) : non représentable en préfixe"
                            )
                        })?;
                        Ok((AddrExpr::Net(net), 2))
                    }
                    // ACL standard : une adresse seule désigne un hôte.
                    None if standard => Ok((
                        AddrExpr::Net(
                            values::host_net(a).ok_or_else(|| format!("adresse `{a}` invalide"))?,
                        ),
                        1,
                    )),
                    None => Err(format!("masque générique manquant après `{a}`")),
                }
            }
        }
    }

    // -- matérialisation des liaisons ACL → politiques -------------------

    /// Transforme chaque `ip access-group` en une [`Policy`] accrochée
    /// au [`Pipeline`], avec la zone implicite de l'interface (voir
    /// mod.rs). Les ACL jamais accrochées deviennent des politiques non
    /// branchées, avec une note.
    fn materialize_bindings(&mut self) {
        let bindings = std::mem::take(&mut self.bindings);
        let acls = std::mem::take(&mut self.acls);
        let acl_order = std::mem::take(&mut self.acl_order);
        let mut bound: BTreeSet<String> = BTreeSet::new();

        for b in &bindings {
            let Some(def) = acls.get(&b.acl) else {
                self.unsupported(
                    format!(
                        "`ip access-group {} {}` référence une ACL inconnue",
                        b.acl, b.dir
                    ),
                    &b.span,
                );
                continue;
            };
            bound.insert(b.acl.clone());
            let zone = self.implicit_zone(&b.iface, &b.span);
            let pid = if self
                .device
                .policies
                .contains_key(&PolicyId::new(b.acl.as_str()))
            {
                let alt = PolicyId::new(format!("{}@{}:{}", b.acl, b.iface, b.dir));
                self.note_info(
                    format!(
                        "ACL `{}` accrochée plusieurs fois : liaison supplémentaire \
                         matérialisée sous la politique `{alt}`",
                        b.acl
                    ),
                    &b.span,
                );
                alt
            } else {
                PolicyId::new(b.acl.as_str())
            };
            let (from, to) = match b.dir {
                Direction::In => (Some(zone), None),
                Direction::Out => (None, Some(zone)),
            };
            let rules = def
                .entries
                .iter()
                .map(|e| Rule {
                    id: e.id.clone(),
                    matches: e.matches.clone(),
                    from: from.clone(),
                    to: to.clone(),
                    action: e.action.clone(),
                    source: e.span.clone(),
                    // Cisco IOS : une ACL avec `object-group` irrésoluble est
                    // déjà gérée (règle exclue) ; rien d'évident ici ne
                    // sur-approxime la correspondance → fidèle.
                    approximation: None,
                })
                .collect();
            self.device.policies.insert(
                pid.clone(),
                Policy {
                    id: pid.clone(),
                    rules,
                    // Le `deny` implicite de toute ACL Cisco.
                    default_action: Action::Deny,
                },
            );
            match b.dir {
                Direction::In => self.device.pipeline.ingress.push(pid),
                Direction::Out => self.device.pipeline.egress.push(pid),
            }
        }

        // ACL comprises mais jamais accrochées : politiques non branchées
        // (utilisables par `access-class`, SNMP, etc., hors périmètre).
        for name in &acl_order {
            if bound.contains(name) {
                continue;
            }
            let Some(def) = acls.get(name) else { continue };
            self.note_info(
                format!(
                    "ACL `{name}` définie mais accrochée à aucune interface : politique \
                     non branchée au pipeline"
                ),
                &def.span,
            );
            let pid = PolicyId::new(name.as_str());
            if self.device.policies.contains_key(&pid) {
                continue;
            }
            let rules = def
                .entries
                .iter()
                .map(|e| Rule {
                    id: e.id.clone(),
                    matches: e.matches.clone(),
                    from: None,
                    to: None,
                    action: e.action.clone(),
                    source: e.span.clone(),
                    approximation: None,
                })
                .collect();
            self.device.policies.insert(
                pid.clone(),
                Policy {
                    id: pid,
                    rules,
                    default_action: Action::Deny,
                },
            );
        }
    }

    /// La zone IMPLICITE d'une interface : une zone du même nom,
    /// contenant cette seule interface (convention partagée avec
    /// l'adaptateur FortiGate, voir mod.rs).
    fn implicit_zone(&mut self, iface_id: &IfaceId, span: &SourceSpan) -> ZoneId {
        let zid = ZoneId::new(iface_id.as_str());
        match self.device.interfaces.get_mut(iface_id) {
            Some(iface) => iface.zone = Some(zid.clone()),
            None => self.note_warning(
                format!("zone implicite pour une interface inconnue `{iface_id}`"),
                span,
            ),
        }
        self.device
            .zones
            .entry(zid.clone())
            .or_insert_with(|| vec![iface_id.clone()]);
        zid
    }
}

/// Un opérateur de port d'ACL (`eq`, `gt`, `lt`, `neq`, `range`) →
/// intervalles EXACTS (un `neq` en produit deux). Rend aussi le nombre
/// de jetons consommés ; `(ANY, 0)` en l'absence d'opérateur.
fn port_spec(toks: &[String]) -> Result<(Vec<PortRange>, usize), String> {
    let Some(op) = toks.first().map(String::as_str) else {
        return Ok((vec![PortRange::ANY], 0));
    };
    match op {
        "eq" => {
            let p = one_port(toks.get(1))?;
            Ok((vec![PortRange::single(p)], 2))
        }
        "gt" => {
            let p = one_port(toks.get(1))?;
            if p == u16::MAX {
                return Err("`gt 65535` ne correspond à aucun port".to_owned());
            }
            Ok((
                vec![PortRange {
                    start: p + 1,
                    end: u16::MAX,
                }],
                2,
            ))
        }
        "lt" => {
            let p = one_port(toks.get(1))?;
            if p == 0 {
                return Err("`lt 0` ne correspond à aucun port".to_owned());
            }
            Ok((
                vec![PortRange {
                    start: 0,
                    end: p - 1,
                }],
                2,
            ))
        }
        "neq" => {
            let p = one_port(toks.get(1))?;
            let mut ranges = Vec::new();
            if p > 0 {
                ranges.push(PortRange {
                    start: 0,
                    end: p - 1,
                });
            }
            if p < u16::MAX {
                ranges.push(PortRange {
                    start: p + 1,
                    end: u16::MAX,
                });
            }
            Ok((ranges, 2))
        }
        "range" => {
            let a = one_port(toks.get(1))?;
            let b = one_port(toks.get(2))?;
            if a > b {
                return Err(format!("`range {a} {b}` : bornes inversées"));
            }
            Ok((vec![PortRange { start: a, end: b }], 3))
        }
        _ => Ok((vec![PortRange::ANY], 0)),
    }
}

fn one_port(tok: Option<&String>) -> Result<u16, String> {
    let t = tok.ok_or("numéro de port manquant")?;
    values::port_number(t).ok_or_else(|| format!("port `{t}` inconnu"))
}

/// Les ports d'un membre `tcp|udp|tcp-udp` d'object-group service :
/// `[source OP ...] [OP ...]` → (ports source, ports destination).
fn service_ports(toks: &[String]) -> Result<(Vec<PortRange>, Vec<PortRange>), String> {
    let mut i = 0usize;
    let mut sports = vec![PortRange::ANY];
    if toks.first().map(String::as_str) == Some("source") {
        let (r, n) = port_spec(&toks[1..])?;
        if n == 0 {
            return Err("`source` sans opérateur de port".to_owned());
        }
        sports = r;
        i = 1 + n;
    }
    let (dports, n) = port_spec(&toks[i..])?;
    i += n;
    if i < toks.len() {
        return Err(format!("jeton `{}` non géré", toks[i]));
    }
    Ok((sports, dports))
}

/// `configs/rtr-01.conf` → `rtr-01`. Repli pour nommer l'équipement
/// quand la configuration ne porte pas de `hostname`.
fn file_stem(path: &str) -> String {
    let name = path
        .rsplit(['/', '\\'])
        .next()
        .filter(|s| !s.is_empty())
        .unwrap_or(path);
    let stem = match name.rsplit_once('.') {
        Some((s, _)) if !s.is_empty() => s,
        _ => name,
    };
    if stem.is_empty() {
        "equipement".to_owned()
    } else {
        stem.to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cisco_ios::CiscoIosAdapter;

    #[test]
    fn nom_de_fichier_vers_identifiant() {
        assert_eq!(file_stem("configs/rtr-01.conf"), "rtr-01");
        assert_eq!(file_stem("C:\\configs\\rtr-01.conf"), "rtr-01");
        assert_eq!(file_stem(""), "equipement");
    }

    fn import(raw: &str) -> AdapterOutput {
        CiscoIosAdapter
            .import_str(raw, "t.conf")
            .expect("un modèle doit sortir")
    }

    fn all_messages(out: &AdapterOutput) -> Vec<&str> {
        let mut msgs: Vec<&str> = out.notes.iter().map(|d| d.message.as_str()).collect();
        if let Fidelity::Partial { unsupported } = &out.fidelity {
            msgs.extend(unsupported.iter().map(|d| d.message.as_str()));
        }
        msgs
    }

    /// §11.4 — les VALEURS des directives non comprises (qui peuvent
    /// porter des secrets : clés IKE, mots de passe FTP/PPP, secrets
    /// d'activation) ne fuient JAMAIS dans les diagnostics.
    #[test]
    fn secrets_absents_des_diagnostics() {
        let out = import(
            "hostname r1\n\
             crypto isakmp key S3CRET-IKE address 192.0.2.1\n\
             enable algorithm-type scrypt secret S3CRET-EN\n\
             ip ftp password S3CRET-FTP\n\
             no directive-inconnue avec S3CRET-NO en-position-profonde\n\
             interface Dialer1\n \
               ppp chap password 0 S3CRET-PPP\n",
        );
        let msgs = all_messages(&out);
        // Les directives SONT diagnostiquées (jamais d'ignorance
        // silencieuse)…
        assert!(msgs.iter().any(|m| m.contains("crypto isakmp")), "{msgs:?}");
        assert!(msgs.iter().any(|m| m.contains("secret")), "{msgs:?}");
        assert!(msgs.iter().any(|m| m.contains("ip ftp")), "{msgs:?}");
        assert!(msgs.iter().any(|m| m.contains("ppp chap")), "{msgs:?}");
        // …mais aucune valeur potentielle de secret ne fuit.
        assert!(
            msgs.iter().all(|m| !m.contains("S3CRET")),
            "une valeur fuit dans un diagnostic : {msgs:?}"
        );
    }

    /// Une interface redéfinie est remplacée ET diagnostiquée : IOS
    /// fusionnerait, remplacer en silence fausserait le modèle.
    #[test]
    fn interface_redefinie_degrade_la_fidelite() {
        let out = import(
            "interface GigabitEthernet0/1\n \
               ip address 10.0.0.1 255.255.255.0\n\
             interface GigabitEthernet0/1\n \
               description seconde definition\n",
        );
        let Fidelity::Partial { unsupported } = &out.fidelity else {
            panic!("la redéfinition doit dégrader la fidélité");
        };
        assert!(unsupported
            .iter()
            .any(|d| d.message.contains("GigabitEthernet0/1") && d.message.contains("redéfinie")));
    }

    /// Un object-group rouvert est remplacé ET diagnostiqué (IOS
    /// fusionnerait les membres).
    #[test]
    fn object_group_redefini_diagnostique() {
        let out = import(
            "object-group network og-a\n host 10.0.0.1\n\
             object-group network og-a\n host 10.0.0.2\n",
        );
        let Fidelity::Partial { unsupported } = &out.fidelity else {
            panic!("la redéfinition doit dégrader la fidélité");
        };
        assert!(unsupported
            .iter()
            .any(|d| d.message.contains("og-a") && d.message.contains("redéfini")));
    }

    #[test]
    fn operateurs_de_ports() {
        let (r, n) = port_spec(&["eq".into(), "445".into()]).unwrap();
        assert_eq!((r, n), (vec![PortRange::single(445)], 2));

        let (r, _) = port_spec(&["gt".into(), "1024".into()]).unwrap();
        assert_eq!(
            r,
            vec![PortRange {
                start: 1025,
                end: 65535
            }]
        );

        let (r, _) = port_spec(&["lt".into(), "1024".into()]).unwrap();
        assert_eq!(
            r,
            vec![PortRange {
                start: 0,
                end: 1023
            }]
        );

        // `neq` : deux intervalles EXACTS, pas d'approximation.
        let (r, _) = port_spec(&["neq".into(), "80".into()]).unwrap();
        assert_eq!(
            r,
            vec![
                PortRange { start: 0, end: 79 },
                PortRange {
                    start: 81,
                    end: 65535
                }
            ]
        );

        let (r, n) = port_spec(&["range".into(), "8000".into(), "8010".into()]).unwrap();
        assert_eq!(
            (r, n),
            (
                vec![PortRange {
                    start: 8000,
                    end: 8010
                }],
                3
            )
        );

        assert!(port_spec(&["range".into(), "10".into(), "5".into()]).is_err());
        assert!(port_spec(&["eq".into(), "teleport".into()]).is_err());
        assert!(port_spec(&["gt".into(), "65535".into()]).is_err());
        // Pas d'opérateur : aucune contrainte, rien de consommé.
        assert_eq!(
            port_spec(&["host".into()]).unwrap(),
            (vec![PortRange::ANY], 0)
        );
    }
}
