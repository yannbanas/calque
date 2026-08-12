//! Conversion arbre générique → représentation intermédiaire pour
//! FortiGate. Voir l'en-tête de `mod.rs` pour les choix de modélisation.
//!
//! Discipline §6.3, appliquée partout dans ce module :
//! - un mot-clé COMPRIS et porteur de sens → mappé vers le modèle ;
//! - un mot-clé COMPRIS et sans effet sur l'accessibilité (description,
//!   couleur…) → accepté explicitement, liste par liste ;
//! - tout le reste → `Diagnostic` avec span, accumulé dans
//!   `Fidelity::Partial`. Jamais d'ignorance silencieuse.

use std::net::Ipv4Addr;

use calque_model::{
    Action, AddrExpr, AddrObject, AdminState, Device, DeviceId, Diagnostic, Fidelity, IfaceId,
    Interface, NatAction, NextHop, ObjectId, Policy, PolicyId, Route, RouteOrigin, Rule, RuleId,
    RuleMatch, Service, ServiceExpr, ServiceObject, Severity, SourceSpan, Vendor, VrfId, ZoneId,
};

use super::values;
use crate::{directive_excerpt, AdapterOutput, ConfigNode, ConfigTree};

/// Distance administrative par défaut d'une route statique FortiGate.
const DEFAULT_STATIC_DISTANCE: u32 = 10;

/// Identifiant de l'unique politique de filtrage forward d'un FortiGate.
const FORWARD_POLICY: &str = "forward";

pub(super) fn convert(tree: &ConfigTree) -> Result<AdapterOutput, Vec<Diagnostic>> {
    if tree.roots.is_empty() {
        return Err(vec![Diagnostic::error(
            "configuration vide ou inexploitable : aucun bloc reconnu",
            Some(SourceSpan::new(tree.file.as_str(), 1)),
        )]);
    }
    let mut conv = Converter::new(tree);
    conv.run(tree);
    Ok(conv.finish())
}

struct Converter {
    device: Device,
    /// Ce qui n'a PAS été compris → `Fidelity::Partial` (§6.3).
    unsupported: Vec<Diagnostic>,
    /// Constats informatifs qui ne dégradent pas la fidélité.
    notes: Vec<Diagnostic>,
}

impl Converter {
    fn new(tree: &ConfigTree) -> Self {
        // Identifiant provisoire tiré du nom de fichier ; remplacé par
        // `set hostname` (config system global) s'il est présent.
        let id = DeviceId::new(file_stem(&tree.file));
        Self {
            device: Device::new(id, Vendor::Fortigate),
            unsupported: Vec::new(),
            notes: Vec::new(),
        }
    }

    fn finish(self) -> AdapterOutput {
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

    // -- parcours -------------------------------------------------------

    /// Deux passes : tout sauf les politiques d'abord (les politiques ont
    /// besoin de connaître interfaces, zones et objets), puis les
    /// politiques — quel que soit l'ordre des blocs dans le fichier.
    fn run(&mut self, tree: &ConfigTree) {
        for child in &tree.roots {
            if !is_policy_block(child) {
                self.dispatch(child);
            }
        }
        for child in &tree.roots {
            if is_policy_block(child) {
                self.policy_block(child);
            }
        }
    }

    fn dispatch(&mut self, node: &ConfigNode) {
        if node.keyword != "config" {
            self.unsupported(
                format!("directive de premier niveau `{}` non gérée", node.keyword),
                &node.span,
            );
            return;
        }
        let path: Vec<&str> = node.args.iter().map(String::as_str).collect();
        match path.as_slice() {
            ["system", "global"] => self.global_block(node),
            ["system", "interface"] => self.interfaces_block(node),
            ["system", "zone"] => self.zones_block(node),
            ["router", "static"] => self.routes_block(node),
            ["firewall", "address"] => self.addresses_block(node),
            ["firewall", "addrgrp"] => self.addrgrp_block(node),
            ["firewall", "service", "custom"] => self.services_block(node),
            ["firewall", "service", "group"] => self.service_group_block(node),
            _ => self.unsupported(
                format!("bloc `config {}` non géré", node.args.join(" ")),
                &node.span,
            ),
        }
    }

    /// Le nom d'un `edit` (premier argument), ou un diagnostic si le
    /// nœud n'a pas la forme attendue.
    fn edit_name(&mut self, node: &ConfigNode, context: &str) -> Option<String> {
        if node.keyword != "edit" {
            self.unsupported(
                format!("directive `{}` non gérée dans `{context}`", node.keyword),
                &node.span,
            );
            return None;
        }
        match node.arg(0) {
            Some(name) => Some(name.to_owned()),
            None => {
                self.unsupported(format!("`edit` sans nom dans `{context}`"), &node.span);
                None
            }
        }
    }

    // -- config system global -------------------------------------------

    fn global_block(&mut self, block: &ConfigNode) {
        for d in &block.children {
            match (d.keyword.as_str(), d.arg(0)) {
                ("set", Some("hostname")) => {
                    if let Some(name) = d.arg(1) {
                        self.device.id = DeviceId::new(name);
                    }
                }
                // Message tronqué à dessein : une directive non comprise
                // peut porter un secret — sa VALEUR ne va jamais dans un
                // diagnostic (§11.4), le span suffit à retrouver la ligne.
                _ => self.unsupported(
                    format!(
                        "`{}` non géré dans `config system global`",
                        directive_excerpt(&d.keyword, &d.args, 1)
                    ),
                    &d.span,
                ),
            }
        }
    }

    // -- config system interface ----------------------------------------

    fn interfaces_block(&mut self, block: &ConfigNode) {
        for edit in &block.children {
            let Some(name) = self.edit_name(edit, "config system interface") else {
                continue;
            };
            let mut iface = Interface::new(IfaceId::new(name.as_str()));
            for d in &edit.children {
                if d.keyword != "set" {
                    self.unsupported(
                        format!(
                            "directive `{}` non gérée dans l'interface `{name}`",
                            d.keyword
                        ),
                        &d.span,
                    );
                    continue;
                }
                match d.arg(0) {
                    Some("ip") => match values::ip_mask_to_net(d.arg(1).unwrap_or(""), d.arg(2)) {
                        Some(net) => iface.addrs.push(net),
                        None => self.unsupported(
                            format!(
                                "adresse invalide `set ip {}` sur l'interface `{name}`",
                                d.args[1..].join(" ")
                            ),
                            &d.span,
                        ),
                    },
                    Some("vlanid") => match d.arg(1).and_then(|v| v.parse::<u16>().ok()) {
                        Some(v) => iface.vlan = Some(v),
                        None => self.unsupported(
                            format!("`set vlanid` invalide sur l'interface `{name}`"),
                            &d.span,
                        ),
                    },
                    Some("status") => match d.arg(1) {
                        Some("up") => iface.state = AdminState::Up,
                        Some("down") => iface.state = AdminState::Down,
                        _ => self.unsupported(
                            format!("`set status` invalide sur l'interface `{name}`"),
                            &d.span,
                        ),
                    },
                    // Membres d'un agrégat (type aggregate/redundant).
                    Some("member") => {
                        iface.members = d.args[1..].iter().map(IfaceId::new).collect();
                    }
                    Some("type") => match d.arg(1) {
                        // Types dont la sémantique est couverte par le
                        // modèle (adresses, membres, vlan).
                        Some(
                            "physical" | "aggregate" | "redundant" | "vlan" | "loopback" | "tunnel",
                        ) => {}
                        other => self.unsupported(
                            format!(
                                "type d'interface `{}` non géré (`{name}`)",
                                other.unwrap_or("?")
                            ),
                            &d.span,
                        ),
                    },
                    Some("mode") => match d.arg(1) {
                        Some("static") => {}
                        // DHCP/PPPoE : l'adresse n'est pas dans le
                        // fichier, donc pas modélisable hors ligne.
                        other => self.unsupported(
                            format!(
                                "mode d'adressage `{}` non modélisable hors ligne (`{name}`)",
                                other.unwrap_or("?")
                            ),
                            &d.span,
                        ),
                    },
                    // Reconnus, sans effet sur l'accessibilité.
                    Some(
                        "vdom"
                        | "allowaccess"
                        | "alias"
                        | "description"
                        | "role"
                        | "snmp-index"
                        | "device-identification",
                    ) => {}
                    other => self.unsupported(
                        format!(
                            "`set {}` non géré sur l'interface `{name}`",
                            other.unwrap_or("")
                        ),
                        &d.span,
                    ),
                }
            }
            // FortiOS fusionne un `edit` rouvert sur le même nom ; ici la
            // seconde définition REMPLACE la première. Fusionner serait
            // deviner (§6.3) : on remplace ET on dégrade la fidélité.
            if self.device.interfaces.contains_key(&iface.id) {
                self.unsupported(
                    format!(
                        "interface `{name}` redéfinie : la nouvelle définition remplace \
                         la première (l'équipement réel les fusionnerait)"
                    ),
                    &edit.span,
                );
            }
            self.device.interfaces.insert(iface.id.clone(), iface);
        }
    }

    // -- config system zone ---------------------------------------------

    fn zones_block(&mut self, block: &ConfigNode) {
        for edit in &block.children {
            let Some(name) = self.edit_name(edit, "config system zone") else {
                continue;
            };
            let zone_id = ZoneId::new(name.as_str());
            let mut members: Vec<IfaceId> = Vec::new();
            for d in &edit.children {
                match (d.keyword.as_str(), d.arg(0)) {
                    // FortiOS utilise `set interface` ; on accepte aussi
                    // `set member` (formes rencontrées selon versions).
                    ("set", Some("interface" | "member")) => {
                        members = d.args[1..].iter().map(IfaceId::new).collect();
                    }
                    ("set", Some("description" | "comment")) => {}
                    _ => self.unsupported(
                        format!(
                            "`{}` non géré dans la zone `{name}`",
                            directive_excerpt(&d.keyword, &d.args, 1)
                        ),
                        &d.span,
                    ),
                }
            }
            // Renseigne l'appartenance côté interface.
            for m in &members {
                match self.device.interfaces.get_mut(m) {
                    Some(iface) => iface.zone = Some(zone_id.clone()),
                    None => self.note_warning(
                        format!("la zone `{name}` référence une interface inconnue `{m}`"),
                        &edit.span,
                    ),
                }
            }
            if self.device.zones.contains_key(&zone_id) {
                self.unsupported(
                    format!(
                        "zone `{name}` redéfinie : la nouvelle liste de membres remplace \
                         la première"
                    ),
                    &edit.span,
                );
            }
            self.device.zones.insert(zone_id, members);
        }
    }

    // -- config router static -------------------------------------------

    fn routes_block(&mut self, block: &ConfigNode) {
        for edit in &block.children {
            let Some(seq) = self.edit_name(edit, "config router static") else {
                continue;
            };
            // Sans `set dst`, une route statique FortiGate est la route
            // par défaut 0.0.0.0/0 (comportement documenté du produit).
            let mut prefix: ipnet::IpNet = ipnet::IpNet::V4(
                ipnet::Ipv4Net::new(Ipv4Addr::UNSPECIFIED, 0).expect("préfixe /0 constant"),
            );
            let mut gateway: Option<std::net::IpAddr> = None;
            let mut out_iface: Option<IfaceId> = None;
            let mut distance: Option<u32> = None;
            let mut blackhole = false;
            let mut disabled = false;
            let mut broken = false;

            for d in &edit.children {
                if d.keyword != "set" {
                    self.unsupported(
                        format!("directive `{}` non gérée dans la route {seq}", d.keyword),
                        &d.span,
                    );
                    continue;
                }
                match d.arg(0) {
                    Some("dst") => {
                        match values::ip_mask_to_net(d.arg(1).unwrap_or(""), d.arg(2)) {
                            // `.trunc()` : une destination de route est un
                            // réseau, les bits d'hôte sont normalisés.
                            Some(net) => prefix = net.trunc(),
                            None => {
                                self.unsupported(
                                    format!("destination invalide sur la route {seq}"),
                                    &d.span,
                                );
                                broken = true;
                            }
                        }
                    }
                    Some("gateway") => match d.arg(1).and_then(|v| v.parse().ok()) {
                        Some(ip) => gateway = Some(ip),
                        None => {
                            self.unsupported(
                                format!("passerelle invalide sur la route {seq}"),
                                &d.span,
                            );
                            broken = true;
                        }
                    },
                    Some("device") => out_iface = d.arg(1).map(IfaceId::new),
                    Some("distance") => match d.arg(1).and_then(|v| v.parse::<u32>().ok()) {
                        Some(v) => distance = Some(v),
                        None => self
                            .unsupported(format!("distance invalide sur la route {seq}"), &d.span),
                    },
                    Some("blackhole") => blackhole = d.arg(1) == Some("enable"),
                    Some("status") => disabled = d.arg(1) == Some("disable"),
                    Some("comment") => {}
                    other => self.unsupported(
                        format!("`set {}` non géré sur la route {seq}", other.unwrap_or("")),
                        &d.span,
                    ),
                }
            }

            if disabled {
                self.note_info(
                    format!("route statique {seq} désactivée (`set status disable`) : ignorée"),
                    &edit.span,
                );
                continue;
            }
            if broken {
                continue; // déjà diagnostiqué, on ne devine pas une route.
            }
            // FortiGate : la passerelle prime ; `device` seul route sur
            // l'interface ; `blackhole` rejette.
            let next_hop = if blackhole {
                NextHop::Drop
            } else if let Some(ip) = gateway {
                NextHop::Ip(ip)
            } else if let Some(iface) = out_iface {
                NextHop::Interface(iface)
            } else {
                self.unsupported(
                    format!("route {seq} sans passerelle, ni interface, ni blackhole"),
                    &edit.span,
                );
                continue;
            };

            let route = Route {
                prefix,
                next_hop,
                // `distance` FortiGate → métrique du modèle (le champ
                // `set priority` départagerait des distances égales ; il
                // serait diagnostiqué comme non géré s'il apparaissait).
                metric: distance.unwrap_or(DEFAULT_STATIC_DISTANCE),
                origin: RouteOrigin::Static,
                source: Some(edit.span.clone()),
            };
            // FortiGate sans VDOM ni VRF explicite : tout va dans le VRF
            // par défaut.
            self.device
                .vrfs
                .entry(VrfId::default_vrf())
                .or_default()
                .routes
                .push(route);
        }
    }

    // -- config firewall address ----------------------------------------

    fn addresses_block(&mut self, block: &ConfigNode) {
        for edit in &block.children {
            let Some(name) = self.edit_name(edit, "config firewall address") else {
                continue;
            };
            let mut is_range = false;
            let mut is_iface_subnet = false;
            let mut iface_ref: Option<String> = None;
            let mut subnet: Option<ipnet::IpNet> = None;
            let mut start_ip: Option<Ipv4Addr> = None;
            let mut end_ip: Option<Ipv4Addr> = None;
            let mut broken = false;

            for d in &edit.children {
                if d.keyword != "set" {
                    self.unsupported(
                        format!(
                            "directive `{}` non gérée dans l'objet adresse `{name}`",
                            d.keyword
                        ),
                        &d.span,
                    );
                    continue;
                }
                match d.arg(0) {
                    Some("subnet") => {
                        match values::ip_mask_to_net(d.arg(1).unwrap_or(""), d.arg(2)) {
                            // Un objet adresse désigne un réseau : on
                            // normalise les bits d'hôte.
                            Some(net) => subnet = Some(net.trunc()),
                            None => {
                                self.unsupported(
                                    format!("`set subnet` invalide dans l'objet `{name}`"),
                                    &d.span,
                                );
                                broken = true;
                            }
                        }
                    }
                    Some("type") => match d.arg(1) {
                        Some("subnet" | "ipmask") => {}
                        Some("iprange") => is_range = true,
                        // « Le sous-réseau de l'interface » : FortiOS crée
                        // ces objets automatiquement (`lan address`…). Le
                        // sous-réseau est en général exporté (`set subnet`),
                        // sinon il se déduit des adresses de l'interface —
                        // déjà dans le modèle, rien n'est deviné.
                        Some("interface-subnet") => is_iface_subnet = true,
                        // fqdn, geography, wildcard… : irrésolubles hors
                        // ligne, on ne devine pas.
                        other => {
                            self.unsupported(
                                format!(
                                    "type d'objet adresse `{}` non géré (`{name}`)",
                                    other.unwrap_or("?")
                                ),
                                &d.span,
                            );
                            broken = true;
                        }
                    },
                    Some("start-ip") => match d.arg(1).and_then(|v| v.parse().ok()) {
                        Some(ip) => start_ip = Some(ip),
                        None => {
                            self.unsupported(
                                format!("`set start-ip` invalide dans l'objet `{name}`"),
                                &d.span,
                            );
                            broken = true;
                        }
                    },
                    Some("end-ip") => match d.arg(1).and_then(|v| v.parse().ok()) {
                        Some(ip) => end_ip = Some(ip),
                        None => {
                            self.unsupported(
                                format!("`set end-ip` invalide dans l'objet `{name}`"),
                                &d.span,
                            );
                            broken = true;
                        }
                    },
                    // L'interface de référence d'un objet interface-subnet.
                    Some("interface") => iface_ref = d.arg(1).map(str::to_owned),
                    // Reconnus, sans effet sur l'accessibilité.
                    Some(
                        "comment" | "color" | "uuid" | "associated-interface" | "allow-routing",
                    ) => {}
                    other => self.unsupported(
                        format!(
                            "`set {}` non géré dans l'objet adresse `{name}`",
                            other.unwrap_or("")
                        ),
                        &d.span,
                    ),
                }
            }

            if broken {
                continue; // diagnostiqué ; un objet à moitié compris ne rentre pas.
            }
            let object = if is_range {
                match (start_ip, end_ip) {
                    (Some(s), Some(e)) => {
                        // Une plage devient une liste EXACTE de préfixes
                        // CIDR (aucune approximation, voir `values.rs`).
                        let nets = values::range_to_nets(s, e);
                        if nets.is_empty() {
                            self.unsupported(
                                format!("plage vide ou inversée dans l'objet `{name}`"),
                                &edit.span,
                            );
                            continue;
                        }
                        AddrObject::Nets(nets)
                    }
                    _ => {
                        self.unsupported(
                            format!("objet `{name}` de type iprange sans start-ip/end-ip"),
                            &edit.span,
                        );
                        continue;
                    }
                }
            } else {
                match subnet {
                    Some(net) => AddrObject::Nets(vec![net]),
                    // interface-subnet sans `set subnet` exporté : les
                    // adresses de l'interface (déjà converties, première
                    // passe) donnent le réseau exact.
                    None if is_iface_subnet => {
                        let nets: Vec<ipnet::IpNet> = iface_ref
                            .as_deref()
                            .and_then(|ifn| self.device.interfaces.get(&IfaceId::new(ifn)))
                            .map(|itf| itf.addrs.iter().map(|a| a.trunc()).collect())
                            .unwrap_or_default();
                        if nets.is_empty() {
                            self.unsupported(
                                format!(
                                    "objet `{name}` de type interface-subnet sans sous-réseau \
                                     déductible (interface absente ou sans adresse)"
                                ),
                                &edit.span,
                            );
                            continue;
                        }
                        AddrObject::Nets(nets)
                    }
                    None => {
                        self.unsupported(
                            format!("objet adresse `{name}` sans `set subnet`"),
                            &edit.span,
                        );
                        continue;
                    }
                }
            };
            let oid = ObjectId::new(name.as_str());
            if self.device.objects.addresses.contains_key(&oid) {
                self.unsupported(
                    format!(
                        "objet adresse `{name}` redéfini : la nouvelle définition \
                         remplace la première"
                    ),
                    &edit.span,
                );
            }
            self.device.objects.addresses.insert(oid, object);
        }
    }

    // -- config firewall addrgrp ----------------------------------------

    fn addrgrp_block(&mut self, block: &ConfigNode) {
        for edit in &block.children {
            let Some(name) = self.edit_name(edit, "config firewall addrgrp") else {
                continue;
            };
            let mut members: Vec<ObjectId> = Vec::new();
            for d in &edit.children {
                match (d.keyword.as_str(), d.arg(0)) {
                    ("set", Some("member")) => {
                        members = d.args[1..].iter().map(ObjectId::new).collect();
                    }
                    ("set", Some("comment" | "color" | "uuid")) => {}
                    _ => self.unsupported(
                        format!(
                            "`{}` non géré dans le groupe d'adresses `{name}`",
                            directive_excerpt(&d.keyword, &d.args, 1)
                        ),
                        &d.span,
                    ),
                }
            }
            // Les objets sont résolus tard (§3.3), mais une référence
            // brisée mérite d'être signalée dès l'import.
            for m in &members {
                if !self.device.objects.addresses.contains_key(m) {
                    self.note_warning(
                        format!("le groupe d'adresses `{name}` référence un objet inconnu `{m}`"),
                        &edit.span,
                    );
                }
            }
            let oid = ObjectId::new(name.as_str());
            if self.device.objects.addresses.contains_key(&oid) {
                self.unsupported(
                    format!(
                        "groupe d'adresses `{name}` redéfini (ou en collision avec un \
                         objet adresse) : la nouvelle définition remplace la première"
                    ),
                    &edit.span,
                );
            }
            self.device
                .objects
                .addresses
                .insert(oid, AddrObject::Group(members));
        }
    }

    // -- config firewall service custom ---------------------------------

    fn services_block(&mut self, block: &ConfigNode) {
        for edit in &block.children {
            let Some(name) = self.edit_name(edit, "config firewall service custom") else {
                continue;
            };
            let mut services: Vec<Service> = Vec::new();
            let mut protocol: Option<String> = None;
            let mut proto_number: Option<u8> = None;
            let mut broken = false;

            for d in &edit.children {
                if d.keyword != "set" {
                    self.unsupported(
                        format!(
                            "directive `{}` non gérée dans le service `{name}`",
                            d.keyword
                        ),
                        &d.span,
                    );
                    continue;
                }
                match d.arg(0) {
                    // `set tcp-portrange 443 8080-8090:1024-65535` :
                    // chaque jeton est `dstrange[:srcrange]`.
                    Some(key @ ("tcp-portrange" | "udp-portrange" | "sctp-portrange")) => {
                        let proto = match key {
                            "tcp-portrange" => 6,
                            "udp-portrange" => 17,
                            _ => 132, // sctp
                        };
                        for token in &d.args[1..] {
                            match values::parse_port_token(token) {
                                Some((dport, sport)) => services.push(Service {
                                    proto: calque_model::ProtoMatch::Number(proto),
                                    sport,
                                    dport,
                                }),
                                None => {
                                    self.unsupported(
                                        format!(
                                            "plage de ports invalide `{token}` dans le service `{name}`"
                                        ),
                                        &d.span,
                                    );
                                    broken = true;
                                }
                            }
                        }
                    }
                    Some("protocol") => protocol = d.arg(1).map(str::to_owned),
                    Some("protocol-number") => match d.arg(1).and_then(|v| v.parse::<u8>().ok()) {
                        Some(n) => proto_number = Some(n),
                        None => {
                            self.unsupported(
                                format!("`set protocol-number` invalide dans le service `{name}`"),
                                &d.span,
                            );
                            broken = true;
                        }
                    },
                    // Un type/code ICMP restreint le service ; le modèle
                    // ne porte pas cette dimension : on ne devine pas.
                    Some("icmptype" | "icmpcode") => {
                        self.unsupported(
                            format!("type/code ICMP non modélisé dans le service `{name}`"),
                            &d.span,
                        );
                        broken = true;
                    }
                    Some("comment" | "color" | "category" | "visibility") => {}
                    other => self.unsupported(
                        format!(
                            "`set {}` non géré dans le service `{name}`",
                            other.unwrap_or("")
                        ),
                        &d.span,
                    ),
                }
            }

            match protocol.as_deref() {
                // Valeur par défaut de FortiOS : les portranges portent
                // tout le sens.
                None | Some("TCP/UDP/SCTP") | Some("TCP/UDP/UDP-Lite/SCTP") => {}
                Some("ICMP") => services.push(Service {
                    proto: calque_model::ProtoMatch::Number(1),
                    sport: calque_model::PortRange::ANY,
                    dport: calque_model::PortRange::ANY,
                }),
                Some("ICMP6") => services.push(Service {
                    proto: calque_model::ProtoMatch::Number(58),
                    sport: calque_model::PortRange::ANY,
                    dport: calque_model::PortRange::ANY,
                }),
                Some("IP") => match proto_number {
                    Some(n) => services.push(Service {
                        proto: calque_model::ProtoMatch::Number(n),
                        sport: calque_model::PortRange::ANY,
                        dport: calque_model::PortRange::ANY,
                    }),
                    None => {
                        self.unsupported(
                            format!("service `{name}` de protocole IP sans `protocol-number`"),
                            &edit.span,
                        );
                        broken = true;
                    }
                },
                Some(other) => {
                    self.unsupported(
                        format!("protocole `{other}` non géré dans le service `{name}`"),
                        &edit.span,
                    );
                    broken = true;
                }
            }

            if broken {
                continue;
            }
            if services.is_empty() {
                self.unsupported(
                    format!("service `{name}` sans aucune définition de ports/protocole"),
                    &edit.span,
                );
                continue;
            }
            let oid = ObjectId::new(name.as_str());
            if self.device.objects.services.contains_key(&oid) {
                self.unsupported(
                    format!(
                        "service `{name}` redéfini : la nouvelle définition remplace \
                         la première"
                    ),
                    &edit.span,
                );
            }
            self.device
                .objects
                .services
                .insert(oid, ServiceObject::Services(services));
        }
    }

    // -- config firewall service group ----------------------------------

    fn service_group_block(&mut self, block: &ConfigNode) {
        for edit in &block.children {
            let Some(name) = self.edit_name(edit, "config firewall service group") else {
                continue;
            };
            let mut members: Vec<ObjectId> = Vec::new();
            for d in &edit.children {
                match (d.keyword.as_str(), d.arg(0)) {
                    ("set", Some("member")) => {
                        members = d.args[1..].iter().map(ObjectId::new).collect();
                    }
                    ("set", Some("comment" | "color")) => {}
                    _ => self.unsupported(
                        format!(
                            "`{}` non géré dans le groupe de services `{name}`",
                            directive_excerpt(&d.keyword, &d.args, 1)
                        ),
                        &d.span,
                    ),
                }
            }
            for m in &members {
                if !self.device.objects.services.contains_key(m) {
                    self.note_warning(
                        format!(
                            "le groupe de services `{name}` référence un service inconnu `{m}`"
                        ),
                        &edit.span,
                    );
                }
            }
            let oid = ObjectId::new(name.as_str());
            if self.device.objects.services.contains_key(&oid) {
                self.unsupported(
                    format!(
                        "groupe de services `{name}` redéfini (ou en collision avec un \
                         service) : la nouvelle définition remplace la première"
                    ),
                    &edit.span,
                );
            }
            self.device
                .objects
                .services
                .insert(oid, ServiceObject::Group(members));
        }
    }

    // -- config firewall policy -----------------------------------------

    fn policy_block(&mut self, block: &ConfigNode) {
        let mut rules: Vec<Rule> = Vec::new();

        for edit in &block.children {
            let Some(num) = self.edit_name(edit, "config firewall policy") else {
                continue;
            };
            let span = edit.span.clone();
            let mut srcintf: Vec<String> = Vec::new();
            let mut dstintf: Vec<String> = Vec::new();
            let mut srcaddr: Vec<String> = Vec::new();
            let mut dstaddr: Vec<String> = Vec::new();
            let mut service: Vec<String> = Vec::new();
            let mut action_kw: Option<String> = None;
            let mut nat = false;
            let mut disabled = false;

            for d in &edit.children {
                if d.keyword != "set" {
                    self.unsupported(
                        format!(
                            "directive `{}` non gérée dans la politique {num}",
                            d.keyword
                        ),
                        &d.span,
                    );
                    continue;
                }
                match d.arg(0) {
                    Some("srcintf") => srcintf = d.args[1..].to_vec(),
                    Some("dstintf") => dstintf = d.args[1..].to_vec(),
                    Some("srcaddr") => srcaddr = d.args[1..].to_vec(),
                    Some("dstaddr") => dstaddr = d.args[1..].to_vec(),
                    Some("service") => service = d.args[1..].to_vec(),
                    Some("action") => action_kw = d.arg(1).map(str::to_owned),
                    Some("nat") => nat = d.arg(1) == Some("enable"),
                    Some("status") => disabled = d.arg(1) == Some("disable"),
                    Some("schedule") => {
                        // `always` est l'absence de contrainte ; toute
                        // autre planification est temporelle, non
                        // modélisée : on ne devine pas.
                        if d.arg(1) != Some("always") {
                            self.unsupported(
                                format!(
                                    "planification `{}` non modélisée (politique {num})",
                                    d.arg(1).unwrap_or("?")
                                ),
                                &d.span,
                            );
                        }
                    }
                    // Reconnus, sans effet sur l'accessibilité.
                    Some("name" | "uuid" | "comments" | "logtraffic" | "logtraffic-start") => {}
                    other => self.unsupported(
                        format!(
                            "`set {}` non géré dans la politique {num}",
                            other.unwrap_or("")
                        ),
                        &d.span,
                    ),
                }
            }

            if disabled {
                // Comprise mais volontairement écartée : Info, la
                // fidélité n'est pas dégradée.
                self.note_info(
                    format!("politique {num} désactivée (`set status disable`) : ignorée"),
                    &span,
                );
                continue;
            }

            let from = self.zone_ref(&srcintf, &span, "srcintf");
            let to = self.zone_ref(&dstintf, &span, "dstintf");

            let action = match action_kw.as_deref() {
                Some("accept") => {
                    if nat {
                        // SNAT vers l'adresse de l'interface de sortie ;
                        // cible résolue à l'évaluation (voir mod.rs).
                        Action::Nat(NatAction::default())
                    } else {
                        Action::Accept
                    }
                }
                // Sans `set action`, FortiGate refuse : comportement
                // documenté du produit, pas une supposition.
                None | Some("deny") => {
                    if nat {
                        self.note_warning(
                            format!("politique {num} : `set nat enable` sans `accept`, sans effet"),
                            &span,
                        );
                    }
                    Action::Deny
                }
                Some(other) => {
                    self.unsupported(
                        format!("action `{other}` non gérée (politique {num})"),
                        &span,
                    );
                    continue; // on ne devine pas une action.
                }
            };

            let matches = RuleMatch {
                src: self.addr_exprs(&srcaddr, &span),
                dst: self.addr_exprs(&dstaddr, &span),
                services: self.service_exprs(&service, &span),
            };

            rules.push(Rule {
                id: RuleId::new(num),
                matches,
                from,
                to,
                action,
                // Le span du `edit N` : fichier + ligne (+ ligne du `next`).
                source: span,
            });
        }

        let pid = PolicyId::new(FORWARD_POLICY);
        // Plusieurs blocs `config firewall policy` (fichier concaténé,
        // entrée hostile) : les règles s'AJOUTENT dans l'ordre du fichier.
        // Remplacer la table ferait disparaître en silence les règles du
        // premier bloc — un refus effacé rendrait un verdict optimiste.
        let policy = self
            .device
            .policies
            .entry(pid.clone())
            .or_insert_with(|| Policy {
                id: pid.clone(),
                rules: Vec::new(),
                // Tout ce qu'aucune politique n'accepte est refusé.
                default_action: Action::Deny,
            });
        policy.rules.extend(rules);
        // Filtrage forward, décidé à l'entrée (voir l'en-tête de mod.rs).
        if !self.device.pipeline.ingress.contains(&pid) {
            self.device.pipeline.ingress.push(pid);
        }
    }

    /// Résout un `srcintf`/`dstintf` vers une zone du modèle.
    ///
    /// - nom d'une zone déclarée → cette zone ;
    /// - nom d'une interface hors zone → zone IMPLICITE du même nom,
    ///   créée à la volée (choix documenté dans mod.rs) ;
    /// - nom d'une interface déjà en zone → la zone de l'interface,
    ///   avec une note (FortiOS n'autorise normalement pas cette forme) ;
    /// - `any` ou absence → `None` (pas de contrainte) ;
    /// - nom inconnu → diagnostic, la référence est conservée telle quelle.
    fn zone_ref(&mut self, names: &[String], span: &SourceSpan, field: &str) -> Option<ZoneId> {
        if names.is_empty() {
            return None;
        }
        if names.len() > 1 {
            // `Rule.from`/`Rule.to` ne portent qu'une zone : retenir la
            // première serait silencieusement faux pour les autres.
            self.unsupported(
                format!(
                    "plusieurs valeurs pour `{field}` ({}) non gérées ; seule `{}` est retenue",
                    names.join(", "),
                    names[0]
                ),
                span,
            );
        }
        let name = names[0].as_str();
        if name == "any" {
            return None;
        }
        let zone_id = ZoneId::new(name);
        if self.device.zones.contains_key(&zone_id) {
            return Some(zone_id);
        }
        let iface_id = IfaceId::new(name);
        if let Some(iface) = self.device.interfaces.get_mut(&iface_id) {
            match iface.zone.clone() {
                Some(existing) if existing != zone_id => {
                    self.note_warning(
                        format!(
                            "`{field}` référence l'interface `{name}` qui appartient déjà à la zone `{existing}`"
                        ),
                        span,
                    );
                    return Some(existing);
                }
                _ => iface.zone = Some(zone_id.clone()),
            }
            self.device
                .zones
                .entry(zone_id.clone())
                .or_insert_with(|| vec![iface_id]);
            Some(zone_id)
        } else {
            self.unsupported(
                format!("`{field}` référence `{name}`, qui n'est ni une zone ni une interface"),
                span,
            );
            Some(zone_id)
        }
    }

    /// `srcaddr`/`dstaddr` → expressions d'adresse. `all` est l'objet
    /// prédéfini FortiGate « tout » → `Any`. Les autres noms restent des
    /// références (résolution tardive, §3.3), mais une référence brisée
    /// est diagnostiquée dès maintenant.
    fn addr_exprs(&mut self, names: &[String], span: &SourceSpan) -> Vec<AddrExpr> {
        let mut out = Vec::new();
        for name in names {
            if name == "all" {
                out.push(AddrExpr::Any);
                continue;
            }
            let oid = ObjectId::new(name.as_str());
            if !self.device.objects.addresses.contains_key(&oid) {
                self.unsupported(
                    format!("objet adresse `{name}` introuvable : irrésoluble à l'évaluation"),
                    span,
                );
            }
            out.push(AddrExpr::Object(oid));
        }
        out
    }

    /// `service` → expressions de service. `ALL` est le service prédéfini
    /// « tout » → `Any`. Un nom inconnu du magasin est diagnostiqué : les
    /// services PRÉDÉFINIS de FortiOS (HTTP, HTTPS…) ne sont pas encore
    /// embarqués, et on ne devine pas leurs ports.
    fn service_exprs(&mut self, names: &[String], span: &SourceSpan) -> Vec<ServiceExpr> {
        let mut out = Vec::new();
        for name in names {
            if name == "ALL" {
                out.push(ServiceExpr::Any);
                continue;
            }
            let oid = ObjectId::new(name.as_str());
            if !self.device.objects.services.contains_key(&oid) {
                self.unsupported(
                    format!(
                        "service `{name}` introuvable (service prédéfini FortiOS non embarqué ?)"
                    ),
                    span,
                );
            }
            out.push(ServiceExpr::Object(oid));
        }
        out
    }
}

fn is_policy_block(node: &ConfigNode) -> bool {
    node.keyword == "config"
        && node.args.len() == 2
        && node.args[0] == "firewall"
        && node.args[1] == "policy"
}

/// `configs/fw-01.conf` → `fw-01`. Repli pour nommer l'équipement quand
/// la configuration ne porte pas de `set hostname`.
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
    use crate::fortigate::FortigateAdapter;

    #[test]
    fn nom_de_fichier_vers_identifiant() {
        assert_eq!(file_stem("configs/fw-01.conf"), "fw-01");
        assert_eq!(file_stem("C:\\configs\\fw-01.conf"), "fw-01");
        assert_eq!(file_stem("fw-01"), "fw-01");
        assert_eq!(file_stem(".conf"), ".conf");
        assert_eq!(file_stem(""), "equipement");
    }

    fn import(raw: &str) -> AdapterOutput {
        FortigateAdapter
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

    /// §11.4 — la VALEUR d'une directive non comprise ne fuit jamais dans
    /// un diagnostic : elle peut porter un secret.
    #[test]
    fn secrets_absents_des_diagnostics() {
        let out = import(
            "config system global\n    set hostname fw-t\n    \
             set directive-inconnue S3CRET-VALEUR\nend\n",
        );
        let msgs = all_messages(&out);
        assert!(
            msgs.iter().any(|m| m.contains("directive-inconnue")),
            "la directive est diagnostiquée par son NOM : {msgs:?}"
        );
        assert!(
            msgs.iter().all(|m| !m.contains("S3CRET")),
            "la valeur ne doit jamais apparaître : {msgs:?}"
        );
    }

    /// Deux blocs `config firewall policy` : les règles s'AJOUTENT dans
    /// l'ordre du fichier. Écraser le premier bloc effacerait ses refus
    /// et rendrait des verdicts optimistes.
    #[test]
    fn blocs_de_politiques_multiples_concatenes() {
        let out = import(
            "config firewall policy\n    edit 1\n        set action deny\n    next\nend\n\
             config firewall policy\n    edit 2\n        set action accept\n    next\nend\n",
        );
        let policy = out
            .device
            .policies
            .get(&PolicyId::new(FORWARD_POLICY))
            .expect("politique forward");
        let ids: Vec<&str> = policy.rules.iter().map(|r| r.id.as_str()).collect();
        assert_eq!(ids, ["1", "2"], "ordre du fichier préservé");
        assert_eq!(policy.rules[0].action, Action::Deny);
        assert_eq!(policy.rules[1].action, Action::Accept);
        // Le pipeline ne référence la politique qu'une seule fois.
        assert_eq!(out.device.pipeline.ingress.len(), 1);
    }

    /// Une interface redéfinie est REMPLACÉE (jamais fusionnée en
    /// silence) et la fidélité est dégradée : pas de verdict ferme sur un
    /// modèle qui diverge de l'équipement réel.
    #[test]
    fn interface_redefinie_degrade_la_fidelite() {
        let out = import(
            "config system interface\n    edit \"port1\"\n        \
             set ip 10.0.0.1 255.255.255.0\n    next\n    edit \"port1\"\n        \
             set vlanid 10\n    next\nend\n",
        );
        let Fidelity::Partial { unsupported } = &out.fidelity else {
            panic!("la redéfinition doit dégrader la fidélité");
        };
        assert!(
            unsupported
                .iter()
                .any(|d| d.message.contains("port1") && d.message.contains("redéfinie")),
            "{unsupported:?}"
        );
    }

    /// Un objet adresse redéfini est diagnostiqué (même classe de risque :
    /// un refus qui visait l'ancienne définition change de portée).
    #[test]
    fn objet_adresse_redefini_diagnostique() {
        let out = import(
            "config firewall address\n    edit \"SRV\"\n        \
             set subnet 10.0.20.5 255.255.255.255\n    next\n    edit \"SRV\"\n        \
             set subnet 10.0.99.0 255.255.255.0\n    next\nend\n",
        );
        let Fidelity::Partial { unsupported } = &out.fidelity else {
            panic!("la redéfinition doit dégrader la fidélité");
        };
        assert!(unsupported
            .iter()
            .any(|d| d.message.contains("SRV") && d.message.contains("redéfini")));
    }

    /// Les objets auto-créés `type interface-subnet` (omniprésents dans
    /// les configurations réelles : `lan address`…) sont modélisés :
    /// sous-réseau exporté explicitement, ou déduit des adresses de
    /// l'interface — jamais deviné.
    #[test]
    fn objet_interface_subnet_modelise() {
        let out = import(
            "config system interface\n    edit \"lan\"\n        \
             set ip 10.10.1.1 255.255.248.0\n    next\nend\n\
             config firewall address\n    edit \"lan address\"\n        \
             set type interface-subnet\n        \
             set subnet 10.10.1.1 255.255.248.0\n        \
             set interface \"lan\"\n    next\n    edit \"lan implicite\"\n        \
             set type interface-subnet\n        \
             set interface \"lan\"\n    next\n    edit \"orphelin\"\n        \
             set type interface-subnet\n        \
             set interface \"absente\"\n    next\nend\n",
        );
        let attendu = AddrObject::Nets(vec!["10.10.0.0/21".parse().expect("net")]);
        assert_eq!(
            out.device
                .objects
                .addresses
                .get(&ObjectId::new("lan address")),
            Some(&attendu),
            "sous-réseau exporté explicitement"
        );
        assert_eq!(
            out.device
                .objects
                .addresses
                .get(&ObjectId::new("lan implicite")),
            Some(&attendu),
            "sous-réseau déduit des adresses de l'interface"
        );
        // Interface introuvable : diagnostic, jamais une supposition.
        assert!(!out
            .device
            .objects
            .addresses
            .contains_key(&ObjectId::new("orphelin")));
        let Fidelity::Partial { unsupported } = &out.fidelity else {
            panic!("l'objet irrésoluble doit dégrader la fidélité");
        };
        assert!(unsupported
            .iter()
            .any(|d| d.message.contains("orphelin") && d.message.contains("interface-subnet")));
    }
}
