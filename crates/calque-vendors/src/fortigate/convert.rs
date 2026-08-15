//! Conversion arbre générique → représentation intermédiaire pour
//! FortiGate. Voir l'en-tête de `mod.rs` pour les choix de modélisation.
//!
//! Discipline §6.3, appliquée partout dans ce module :
//! - un mot-clé COMPRIS et porteur de sens → mappé vers le modèle ;
//! - un mot-clé COMPRIS et sans effet sur l'accessibilité (description,
//!   couleur…) → accepté explicitement, liste par liste ;
//! - tout le reste → `Diagnostic` avec span, accumulé dans
//!   `Fidelity::Partial`. Jamais d'ignorance silencieuse.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr};

use calque_model::{
    Action, AddrExpr, AddrObject, AdminState, Device, DeviceId, Diagnostic, DnatTarget,
    ExternalKind, Fidelity, IfaceId, Interface, NatAction, NextHop, ObjectId, Policy, PolicyId,
    PortRange, ProtoMatch, Route, RouteOrigin, Rule, RuleId, RuleMatch, Service, ServiceExpr,
    ServiceObject, Severity, SourceSpan, Vendor, VrfId, ZoneId,
};

use super::values;
use crate::{directive_excerpt, AdapterOutput, ConfigNode, ConfigTree};

/// Distance administrative par défaut d'une route statique FortiGate.
const DEFAULT_STATIC_DISTANCE: u32 = 10;

/// Identifiant de l'unique politique de filtrage forward d'un FortiGate.
const FORWARD_POLICY: &str = "forward";

/// Zone SD-WAN implicite de FortiOS : elle existe dès que le SD-WAN est
/// activé, même sans `config zone`, et c'est la zone par défaut des
/// membres sans `set zone` (comportement documenté du produit).
const SDWAN_DEFAULT_ZONE: &str = "virtual-wan-link";

/// La redirection portée par un VIP (`config firewall vip`), une fois
/// comprise EXACTEMENT. Un VIP dont la redirection n'est pas représentable
/// (plage d'adresses externes, plage de ports décalée) n'est PAS stocké :
/// il est diagnostiqué, et les règles qui le référencent deviennent
/// irrésolubles — jamais approximées (§6.3).
#[derive(Debug, Clone)]
struct Vip {
    /// La cible de réécriture de destination. `port: None` = port
    /// préservé (VIP 1:1, ou plage de ports identitaire).
    dnat: DnatTarget,
    /// La contrainte de service induite par `set protocol` + `set extport`
    /// (redirection de ports uniquement). `None` pour un VIP 1:1.
    service: Option<Service>,
}

/// Un membre SD-WAN (`config members` de `config system sdwan`).
#[derive(Debug, Clone)]
struct SdwanMember {
    iface: IfaceId,
    /// Passerelle du membre ; absente = routage sur l'interface seule.
    gateway: Option<IpAddr>,
    zone: String,
}

/// Destination d'une route statique : littérale (`set dst`) ou par objet
/// adresse (`set dstaddr`), résolue APRÈS la première passe (l'ordre des
/// blocs dans le fichier ne garantit pas que les objets précèdent les
/// routes).
#[derive(Debug, Clone)]
enum RouteDest {
    Literal(ipnet::IpNet),
    Object(String),
}

/// Prochain saut d'une route statique : direct, ou une zone SD-WAN à
/// développer en une route PAR MEMBRE (candidates ECMP).
#[derive(Debug, Clone)]
enum RouteVia {
    Single(NextHop),
    SdwanZone(String),
}

/// Une route statique en attente de résolution (fin de première passe).
#[derive(Debug, Clone)]
struct PendingRoute {
    seq: String,
    dest: RouteDest,
    via: RouteVia,
    metric: u32,
    span: SourceSpan,
}

/// Un sélecteur de phase2 : par objet adresse (`src-name`/`dst-name`) ou
/// par préfixe (`src-subnet`/`dst-subnet`).
#[derive(Debug, Clone)]
enum Phase2Sel {
    Name(String),
    Subnet(ipnet::IpNet),
}

/// Un sélecteur IPsec phase2 en attente (résolu après la première passe :
/// les objets adresse peuvent être déclarés après le bloc VPN).
#[derive(Debug, Clone)]
struct PendingPhase2 {
    name: String,
    phase1name: String,
    src: Option<Phase2Sel>,
    dst: Option<Phase2Sel>,
    span: SourceSpan,
}

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
    /// VIP compris exactement, par nom — pour porter le DNAT sur les
    /// règles qui les référencent en `dstaddr`.
    vips: BTreeMap<String, Vip>,
    /// Groupes de VIP (`config firewall vipgrp`), par nom.
    vipgrps: BTreeMap<String, Vec<String>>,
    /// `config system sdwan` : `set status enable`.
    sdwan_enabled: bool,
    /// Zones SD-WAN déclarées (+ la zone implicite de FortiOS).
    sdwan_zones: BTreeSet<String>,
    /// Membres SD-WAN actifs, dans l'ordre du fichier.
    sdwan_members: Vec<SdwanMember>,
    /// Routes statiques en attente (résolues après la première passe).
    pending_routes: Vec<PendingRoute>,
    /// Tunnels phase1 vus (`config vpn ipsec phase1-interface`).
    phase1_names: BTreeSet<String>,
    /// Sélecteurs phase2 en attente (résolus après la première passe).
    pending_phase2: Vec<PendingPhase2>,
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
            vips: BTreeMap::new(),
            vipgrps: BTreeMap::new(),
            sdwan_enabled: false,
            sdwan_zones: BTreeSet::new(),
            sdwan_members: Vec::new(),
            pending_routes: Vec::new(),
            phase1_names: BTreeSet::new(),
            pending_phase2: Vec::new(),
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
    ///
    /// Entre les deux : les routes statiques (dont celles par objet
    /// adresse ou par zone SD-WAN) et les sélecteurs IPsec phase2 sont
    /// RÉSOLUS — ils référencent des objets, membres et interfaces que
    /// l'ordre des blocs dans le fichier ne garantit pas.
    fn run(&mut self, tree: &ConfigTree) {
        for child in &tree.roots {
            if !is_policy_block(child) {
                self.dispatch(child);
            }
        }
        self.resolve_pending_routes();
        self.build_ipsec_policies();
        self.register_sdwan_zones();
        for child in &tree.roots {
            if is_policy_block(child) {
                self.policy_block(child);
            }
        }
    }

    /// Les zones SD-WAN deviennent de vraies zones du modèle, membres =
    /// les interfaces des membres SD-WAN : les politiques `dstintf
    /// "SD-WAN"` doivent s'appliquer quand le paquet sort par wan1 ou
    /// wan2 — sans cette inscription, elles ne matchent jamais et tout
    /// flux vers Internet tombe à tort sur le refus par défaut.
    fn register_sdwan_zones(&mut self) {
        if self.sdwan_members.is_empty() {
            return;
        }
        for zone in self.sdwan_zones.clone() {
            let members: Vec<IfaceId> = self
                .sdwan_members
                .iter()
                .filter(|m| m.zone == zone)
                .map(|m| m.iface.clone())
                .collect();
            if members.is_empty() {
                continue;
            }
            self.device
                .zones
                .entry(ZoneId::new(zone.as_str()))
                .or_insert(members);
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
            ["firewall", "vip"] => self.vip_block(node),
            ["firewall", "vipgrp"] => self.vipgrp_block(node),
            ["system", "sdwan"] => self.sdwan_block(node),
            ["vpn", "ipsec", "phase1-interface"] => self.phase1_block(node),
            ["vpn", "ipsec", "phase2-interface"] => self.phase2_block(node),
            // Blocs sans AUCUN effet sur l'accessibilité (« qui joint quoi ») :
            // messages de remplacement HTML, réglages d'administration/GUI,
            // journalisation, supervision… Ce n'est pas « deviner » (§6.3) :
            // ces blocs sont RECONNUS et classés hors périmètre du modèle de
            // filtrage/routage. Note Info, la fidélité n'est pas dégradée.
            _ if is_cosmetic_block(&path) => self.note_info(
                format!(
                    "bloc `config {}` reconnu, sans effet sur l'accessibilité (hors modèle)",
                    node.args.join(" ")
                ),
                &node.span,
            ),
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
                // Réglages GLOBAUX sans effet sur l'accessibilité :
                // administration, GUI, ports d'admin, fuseau, contrôleur de
                // switch, hôte de gestion… Préfixes `admin-`/`gui-` et liste
                // explicite. Une clé VRAIMENT inconnue reste signalée (on ne
                // devine pas qu'un futur réglage global est sans effet).
                ("set", Some(k))
                    if k.starts_with("admin-")
                        || k.starts_with("gui-")
                        || matches!(
                            k,
                            "alias"
                                | "timezone"
                                | "switch-controller"
                                | "virtual-switch-vlan"
                                | "hostname"
                                | "language"
                                | "gui-theme"
                                | "management-vdom"
                                | "pre-login-banner"
                                | "post-login-banner"
                                | "revision-backup-on-logout"
                                | "daylight-saving-time"
                                | "gui-certificates"
                                | "cfg-save"
                                | "timezone-offset"
                        ) => {}
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
                    // Le VRF de l'interface (cloisonnement de routage) EST
                    // modélisé : le moteur route par VRF.
                    Some("vrf") => {
                        if let Some(v) = d.arg(1) {
                            iface.vrf = VrfId::new(v);
                        }
                    }
                    // L'interface parente d'un VLAN (`set interface "lan"`) :
                    // le VLAN a sa propre adresse et sa propre zone, la
                    // parenté ne change pas « qui joint quoi » — reconnue,
                    // sans effet sur l'accessibilité.
                    Some("interface") => {}
                    // Reconnus, sans effet sur l'accessibilité : administration,
                    // supervision, débit, découverte de voisinage, métadonnées.
                    Some(
                        "vdom"
                        | "allowaccess"
                        | "alias"
                        | "description"
                        | "role"
                        | "snmp-index"
                        | "device-identification"
                        | "estimated-upstream-bandwidth"
                        | "estimated-downstream-bandwidth"
                        | "measured-upstream-bandwidth"
                        | "measured-downstream-bandwidth"
                        | "monitor-bandwidth"
                        | "bandwidth-measure-time"
                        | "speed"
                        | "mtu"
                        | "mtu-override"
                        | "lldp-transmission"
                        | "lldp-reception"
                        | "ip-managed-by-fortiipam"
                        | "src-check"
                        | "stp"
                        | "fortilink"
                        | "arpforward"
                        | "broadcast-forward"
                        | "l2forward"
                        | "netbios-forward"
                        | "detectserver"
                        | "detectprotocol"
                        | "fail-detect"
                        | "external"
                        | "dedicated-to"
                        | "trust-ip-1"
                        | "trust-ip-2"
                        | "trust-ip-3"
                        | "color"
                        | "status-report-mode"
                        | "sflow-sampler"
                        | "netflow-sampler"
                        | "secondary-IP"
                        | "preserve-session-route"
                        | "weight",
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
            let mut dst_net: Option<ipnet::IpNet> = None;
            let mut dst_obj: Option<String> = None;
            let mut sdwan_zone: Option<String> = None;
            let mut gateway: Option<IpAddr> = None;
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
                            Some(net) => dst_net = Some(net.trunc()),
                            None => {
                                self.unsupported(
                                    format!("destination invalide sur la route {seq}"),
                                    &d.span,
                                );
                                broken = true;
                            }
                        }
                    }
                    // Route par objet adresse : résolue APRÈS la première
                    // passe (les objets peuvent être déclarés plus loin).
                    Some("dstaddr") => match d.arg(1) {
                        Some(name) => dst_obj = Some(name.to_owned()),
                        None => {
                            self.unsupported(
                                format!("`set dstaddr` sans objet sur la route {seq}"),
                                &d.span,
                            );
                            broken = true;
                        }
                    },
                    // Route par zone SD-WAN : développée en une route PAR
                    // MEMBRE lors de la résolution.
                    Some("sdwan-zone") => match d.arg(1) {
                        Some(name) => sdwan_zone = Some(name.to_owned()),
                        None => {
                            self.unsupported(
                                format!("`set sdwan-zone` sans zone sur la route {seq}"),
                                &d.span,
                            );
                            broken = true;
                        }
                    },
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
                    // VRF de la route : `0` est le VRF racine (défaut), où
                    // vont déjà toutes les routes du modèle — sans effet.
                    // Un VRF non nul est un cloisonnement de routage que le
                    // modèle ne porte pas encore PAR ROUTE : on le signale.
                    Some("vrf") => {
                        if !matches!(d.arg(1), Some("0") | None) {
                            self.unsupported(
                                format!(
                                    "route {seq} : `set vrf {}` — routage par VRF non-défaut \
                                     non encore modélisé par route",
                                    d.arg(1).unwrap_or("")
                                ),
                                &d.span,
                            );
                        }
                    }
                    Some(k) if is_cosmetic_key(k) => {}
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
            // `dst` et `dstaddr` sont exclusifs chez FortiOS : les deux à
            // la fois, c'est une entrée incohérente — on ne devine pas
            // laquelle prime.
            if dst_net.is_some() && dst_obj.is_some() {
                self.unsupported(
                    format!("route {seq} : `set dst` et `set dstaddr` simultanés, incohérent"),
                    &edit.span,
                );
                continue;
            }
            let dest = match dst_obj {
                Some(name) => RouteDest::Object(name),
                // Sans `set dst`, une route statique FortiGate est la
                // route par défaut 0.0.0.0/0 (comportement documenté).
                None => RouteDest::Literal(dst_net.unwrap_or(ipnet::IpNet::V4(
                    ipnet::Ipv4Net::new(Ipv4Addr::UNSPECIFIED, 0).expect("préfixe /0 constant"),
                ))),
            };
            // FortiGate : `blackhole` rejette (et exclut tout saut) ; une
            // zone SD-WAN est exclusive d'une passerelle ou d'une
            // interface ; sinon la passerelle prime et `device` seul
            // route sur l'interface.
            let via = if blackhole {
                RouteVia::Single(NextHop::Drop)
            } else if let Some(zone) = sdwan_zone {
                if gateway.is_some() || out_iface.is_some() {
                    self.unsupported(
                        format!(
                            "route {seq} : `set sdwan-zone` combiné à une passerelle ou une \
                             interface, incohérent"
                        ),
                        &edit.span,
                    );
                    continue;
                }
                RouteVia::SdwanZone(zone)
            } else if let Some(ip) = gateway {
                RouteVia::Single(NextHop::Ip(ip))
            } else if let Some(iface) = out_iface {
                RouteVia::Single(NextHop::Interface(iface))
            } else {
                self.unsupported(
                    format!(
                        "route {seq} sans passerelle, ni interface, ni blackhole, ni zone SD-WAN"
                    ),
                    &edit.span,
                );
                continue;
            };

            self.pending_routes.push(PendingRoute {
                seq,
                dest,
                via,
                // `distance` FortiGate → métrique du modèle (le champ
                // `set priority` départagerait des distances égales ; il
                // serait diagnostiqué comme non géré s'il apparaissait).
                metric: distance.unwrap_or(DEFAULT_STATIC_DISTANCE),
                span: edit.span.clone(),
            });
        }
    }

    /// Résout les routes statiques en attente, une fois la première passe
    /// terminée (objets adresse et membres SD-WAN connus).
    ///
    /// - `dstaddr` → UNE route par préfixe de l'objet (mêmes saut,
    ///   métrique et span) ; un objet irrésoluble (absent — fqdn ou
    ///   géographie non modélisés — ou groupe brisé) est diagnostiqué,
    ///   jamais approximé ;
    /// - `sdwan-zone` → UNE route par membre actif de la zone (même
    ///   préfixe, même métrique) : le moteur les voit comme candidates
    ///   ECMP et les évalue par branches — c'est le comportement voulu,
    ///   « l'un des WAN ».
    fn resolve_pending_routes(&mut self) {
        let pending = std::mem::take(&mut self.pending_routes);
        for p in pending {
            let prefixes: Vec<ipnet::IpNet> = match &p.dest {
                RouteDest::Literal(net) => vec![*net],
                RouteDest::Object(name) => {
                    let (nets, unresolved) = self.resolve_addr_prefixes(name);
                    for missing in &unresolved {
                        self.unsupported(
                            format!(
                                "route {} : objet adresse `{missing}` irrésoluble (absent, \
                                 fqdn/géographie non modélisés, ou groupe brisé)",
                                p.seq
                            ),
                            &p.span,
                        );
                    }
                    if nets.is_empty() {
                        continue; // rien de résolu : pas de route devinée.
                    }
                    nets
                }
            };
            let hops: Vec<NextHop> = match &p.via {
                RouteVia::Single(hop) => vec![hop.clone()],
                RouteVia::SdwanZone(zone) => {
                    if !self.sdwan_enabled {
                        self.unsupported(
                            format!(
                                "route {} via la zone SD-WAN `{zone}` : `config system sdwan` \
                                 absent ou désactivé",
                                p.seq
                            ),
                            &p.span,
                        );
                        continue;
                    }
                    if !self.sdwan_zones.contains(zone) {
                        self.unsupported(
                            format!("route {} : zone SD-WAN `{zone}` inconnue", p.seq),
                            &p.span,
                        );
                        continue;
                    }
                    let hops: Vec<NextHop> = self
                        .sdwan_members
                        .iter()
                        .filter(|m| &m.zone == zone)
                        .map(|m| match m.gateway {
                            Some(ip) => NextHop::Ip(ip),
                            None => NextHop::Interface(m.iface.clone()),
                        })
                        .collect();
                    if hops.is_empty() {
                        self.unsupported(
                            format!(
                                "route {} : la zone SD-WAN `{zone}` n'a aucun membre actif",
                                p.seq
                            ),
                            &p.span,
                        );
                        continue;
                    }
                    hops
                }
            };
            let routes = self.device.vrfs.entry(VrfId::default_vrf()).or_default();
            for prefix in &prefixes {
                for hop in &hops {
                    routes.routes.push(Route {
                        prefix: *prefix,
                        next_hop: hop.clone(),
                        metric: p.metric,
                        origin: RouteOrigin::Static,
                        source: Some(p.span.clone()),
                    });
                }
            }
        }
    }

    /// Les préfixes EXACTS d'un objet adresse (résolution récursive des
    /// groupes, bornée par un ensemble de visite). Rend `(préfixes,
    /// noms irrésolus)` : les membres résolus restent exacts, les
    /// manquants sont rapportés à l'appelant — qui diagnostique.
    fn resolve_addr_prefixes(&self, name: &str) -> (Vec<ipnet::IpNet>, Vec<String>) {
        fn go(
            store: &BTreeMap<ObjectId, AddrObject>,
            name: &str,
            visited: &mut BTreeSet<String>,
            nets: &mut Vec<ipnet::IpNet>,
            unresolved: &mut Vec<String>,
        ) {
            if !visited.insert(name.to_owned()) {
                return; // déjà vu (cycle ou doublon) : compté une fois.
            }
            match store.get(&ObjectId::new(name)) {
                Some(AddrObject::Nets(list)) => {
                    // Une destination de route est un réseau : les bits
                    // d'hôte sont normalisés.
                    nets.extend(list.iter().map(|n| n.trunc()));
                }
                Some(AddrObject::Group(members)) => {
                    for m in members {
                        go(store, m.as_str(), visited, nets, unresolved);
                    }
                }
                // Objet externe (fqdn/géographie) : son étendue en préfixes
                // n'est pas connue à l'import (la résolution `--resolve`
                // s'applique plus tard, sur le modèle). Une route qui le
                // référence reste donc irrésoluble ici — diagnostiquée par
                // l'appelant, jamais devinée.
                Some(AddrObject::External { .. }) => unresolved.push(name.to_owned()),
                None => unresolved.push(name.to_owned()),
            }
        }
        let mut nets = Vec::new();
        let mut unresolved = Vec::new();
        let mut visited = BTreeSet::new();
        go(
            &self.device.objects.addresses,
            name,
            &mut visited,
            &mut nets,
            &mut unresolved,
        );
        (nets, unresolved)
    }

    // -- config firewall vip --------------------------------------------

    /// `config firewall vip` : chaque VIP compris devient un objet
    /// adresse `Nets([extip/32])` sous son nom (les `dstaddr` qui le
    /// référencent se résolvent), et sa redirection est mémorisée pour
    /// être portée en DNAT par les règles qui le référencent.
    ///
    /// Représentable EXACTEMENT (§6.3) :
    /// - VIP 1:1 (`set portforward` absent/disable) : toutes destinations
    ///   `extip` → `mappedip`, tous ports préservés ;
    /// - redirection d'un port unique : `extport` → `mappedport` ;
    /// - plage de ports IDENTITAIRE (`extport` == `mappedport`) : DNAT
    ///   d'adresse seule, ports préservés.
    ///
    /// Non représentable → diagnostic, le VIP n'est PAS stocké (les
    /// règles qui le référencent deviennent irrésolubles — jamais
    /// approximées) : plage d'adresses externes (une cible DNAT par
    /// adresse), plage de ports réellement décalée.
    ///
    /// `set extintf` est COMPRIS et sans effet propre : la contrainte
    /// d'interface d'entrée est déjà portée par le `srcintf` des
    /// politiques qui référencent le VIP.
    fn vip_block(&mut self, block: &ConfigNode) {
        for edit in &block.children {
            let Some(name) = self.edit_name(edit, "config firewall vip") else {
                continue;
            };
            let mut extip_raw: Option<String> = None;
            let mut mappedip_raw: Option<String> = None;
            let mut portforward = false;
            let mut protocol: Option<String> = None;
            let mut extport_raw: Option<String> = None;
            let mut mappedport_raw: Option<String> = None;
            let mut broken = false;

            for d in &edit.children {
                if d.keyword != "set" {
                    self.unsupported(
                        format!("directive `{}` non gérée dans le VIP `{name}`", d.keyword),
                        &d.span,
                    );
                    continue;
                }
                match d.arg(0) {
                    // Plusieurs valeurs (`set mappedip "a" "b"` :
                    // répartition sur plusieurs plages) : une cible DNAT
                    // unique ne peut pas les représenter — jamais tronqué
                    // en silence.
                    Some(key @ ("extip" | "mappedip")) if d.args.len() > 2 => {
                        self.unsupported(
                            format!(
                                "`set {key}` à valeurs multiples non représentable dans le \
                                 VIP `{name}`"
                            ),
                            &d.span,
                        );
                        broken = true;
                    }
                    Some("extip") => extip_raw = d.arg(1).map(str::to_owned),
                    Some("mappedip") => mappedip_raw = d.arg(1).map(str::to_owned),
                    Some("portforward") => portforward = d.arg(1) == Some("enable"),
                    Some("protocol") => protocol = d.arg(1).map(str::to_owned),
                    Some("extport") => extport_raw = d.arg(1).map(str::to_owned),
                    Some("mappedport") => mappedport_raw = d.arg(1).map(str::to_owned),
                    Some("type") => match d.arg(1) {
                        // Le seul type modélisé : la traduction statique.
                        Some("static-nat") => {}
                        other => {
                            self.unsupported(
                                format!(
                                    "type de VIP `{}` non géré (`{name}`)",
                                    other.unwrap_or("?")
                                ),
                                &d.span,
                            );
                            broken = true;
                        }
                    },
                    // Compris, sans effet propre sur l'accessibilité
                    // (extintf : voir l'en-tête de la méthode).
                    Some("extintf" | "comment" | "color" | "uuid" | "arp-reply") => {}
                    other => self.unsupported(
                        format!(
                            "`set {}` non géré dans le VIP `{name}`",
                            other.unwrap_or("")
                        ),
                        &d.span,
                    ),
                }
            }
            if broken {
                continue;
            }

            let Some(extip_raw) = extip_raw else {
                self.unsupported(format!("VIP `{name}` sans `set extip`"), &edit.span);
                continue;
            };
            let Some((ext_start, ext_end)) = values::parse_ip_span(&extip_raw) else {
                self.unsupported(
                    format!("`set extip` invalide dans le VIP `{name}`"),
                    &edit.span,
                );
                continue;
            };
            if ext_start != ext_end {
                self.unsupported(
                    format!(
                        "VIP `{name}` : plage d'adresses externes non représentable (une cible \
                         DNAT par adresse externe) — jamais approximée"
                    ),
                    &edit.span,
                );
                continue;
            }
            let Some(mappedip_raw) = mappedip_raw else {
                self.unsupported(format!("VIP `{name}` sans `set mappedip`"), &edit.span);
                continue;
            };
            let Some((mapped_start, mapped_end)) = values::parse_ip_span(&mappedip_raw) else {
                self.unsupported(
                    format!("`set mappedip` invalide dans le VIP `{name}`"),
                    &edit.span,
                );
                continue;
            };
            if mapped_start != mapped_end {
                self.unsupported(
                    format!(
                        "VIP `{name}` : plage d'adresses traduites non représentable (une cible \
                         DNAT par adresse) — jamais approximée"
                    ),
                    &edit.span,
                );
                continue;
            }

            let (dnat_port, service): (Option<u16>, Option<Service>) = if !portforward {
                // VIP 1:1 : toutes destinations extip → mappedip, tous
                // ports et protocoles. Des ports déclarés sans
                // `portforward enable` seraient incohérents.
                if extport_raw.is_some() || mappedport_raw.is_some() {
                    self.unsupported(
                        format!("VIP `{name}` : `extport`/`mappedport` sans `portforward enable`"),
                        &edit.span,
                    );
                    continue;
                }
                (None, None)
            } else {
                // FortiOS : `tcp` est le protocole par défaut de la
                // redirection de ports (comportement documenté).
                let proto: u8 = match protocol.as_deref() {
                    None | Some("tcp") => 6,
                    Some("udp") => 17,
                    Some("sctp") => 132,
                    Some(other) => {
                        self.unsupported(
                            format!(
                                "protocole `{other}` non géré pour la redirection de ports du \
                                 VIP `{name}`"
                            ),
                            &edit.span,
                        );
                        continue;
                    }
                };
                let Some(extport_raw) = extport_raw else {
                    self.unsupported(
                        format!("VIP `{name}` : `portforward enable` sans `set extport`"),
                        &edit.span,
                    );
                    continue;
                };
                let Some(ext) = values::parse_port_span(&extport_raw) else {
                    self.unsupported(
                        format!("`set extport` invalide dans le VIP `{name}`"),
                        &edit.span,
                    );
                    continue;
                };
                // Sans `set mappedport`, FortiOS reprend `extport`
                // (comportement documenté du produit).
                let mapped = match &mappedport_raw {
                    Some(raw) => match values::parse_port_span(raw) {
                        Some(span) => span,
                        None => {
                            self.unsupported(
                                format!("`set mappedport` invalide dans le VIP `{name}`"),
                                &edit.span,
                            );
                            continue;
                        }
                    },
                    None => ext,
                };
                let dport = PortRange {
                    start: ext.0,
                    end: ext.1,
                };
                let svc = Service {
                    proto: ProtoMatch::Number(proto),
                    sport: PortRange::ANY,
                    dport,
                };
                if ext.0 == ext.1 {
                    // Port unique : mappé exactement.
                    if mapped.0 != mapped.1 {
                        self.unsupported(
                            format!(
                                "VIP `{name}` : plage de ports traduite pour un port externe \
                                 unique, non représentable"
                            ),
                            &edit.span,
                        );
                        continue;
                    }
                    (Some(mapped.0), Some(svc))
                } else if mapped == ext {
                    // Plage m-vers-n IDENTITAIRE : DNAT d'adresse seule,
                    // le port est préservé — exact.
                    (None, Some(svc))
                } else {
                    // Plage réellement décalée : `DnatTarget` ne porte
                    // qu'un port unique — jamais approximée.
                    self.unsupported(
                        format!(
                            "VIP `{name}` : plage de ports décalée non représentable (un seul \
                             port cible par règle) — jamais approximée"
                        ),
                        &edit.span,
                    );
                    continue;
                }
            };

            let oid = ObjectId::new(name.as_str());
            if self.device.objects.addresses.contains_key(&oid) {
                self.unsupported(
                    format!(
                        "VIP `{name}` redéfini (ou en collision avec un objet adresse) : la \
                         nouvelle définition remplace la première"
                    ),
                    &edit.span,
                );
            }
            // L'objet adresse du VIP : son adresse EXTERNE (c'est elle
            // que les `dstaddr` des politiques désignent).
            if let Ok(net) = ipnet::Ipv4Net::new(ext_start, 32) {
                self.device
                    .objects
                    .addresses
                    .insert(oid, AddrObject::Nets(vec![ipnet::IpNet::V4(net)]));
            }
            self.vips.insert(
                name,
                Vip {
                    dnat: DnatTarget {
                        addr: IpAddr::V4(mapped_start),
                        port: dnat_port,
                    },
                    service,
                },
            );
        }
    }

    // -- config firewall vipgrp -----------------------------------------

    /// `config firewall vipgrp` : un groupe de VIP. Enregistré comme
    /// groupe d'objets adresse (les références se résolvent) ET mémorisé
    /// pour être développé en ses membres à l'évaluation des politiques
    /// (chaque membre porte sa propre redirection).
    fn vipgrp_block(&mut self, block: &ConfigNode) {
        for edit in &block.children {
            let Some(name) = self.edit_name(edit, "config firewall vipgrp") else {
                continue;
            };
            let mut members: Vec<String> = Vec::new();
            for d in &edit.children {
                match (d.keyword.as_str(), d.arg(0)) {
                    ("set", Some("member")) => {
                        members = d.args[1..].to_vec();
                    }
                    ("set", Some("comment" | "color" | "uuid")) => {}
                    _ => self.unsupported(
                        format!(
                            "`{}` non géré dans le groupe de VIP `{name}`",
                            directive_excerpt(&d.keyword, &d.args, 1)
                        ),
                        &d.span,
                    ),
                }
            }
            for m in &members {
                if !self.vips.contains_key(m) {
                    self.note_warning(
                        format!("le groupe de VIP `{name}` référence un VIP inconnu `{m}`"),
                        &edit.span,
                    );
                }
            }
            let oid = ObjectId::new(name.as_str());
            if self.device.objects.addresses.contains_key(&oid) {
                self.unsupported(
                    format!(
                        "groupe de VIP `{name}` redéfini (ou en collision avec un objet \
                         adresse) : la nouvelle définition remplace la première"
                    ),
                    &edit.span,
                );
            }
            self.device.objects.addresses.insert(
                oid,
                AddrObject::Group(members.iter().map(ObjectId::new).collect()),
            );
            self.vipgrps.insert(name, members);
        }
    }

    // -- config system sdwan --------------------------------------------

    /// `config system sdwan` : zones et membres, pour développer les
    /// routes `set sdwan-zone` en une route PAR MEMBRE (candidates ECMP,
    /// évaluées par branches par le moteur — « l'un des WAN »).
    ///
    /// - `config health-check` : supervision de liens, sans effet sur le
    ///   modèle statique → note Info ;
    /// - `config service` (règles de routage par flux avec
    ///   priority-members) : reconnu → note Info. La sélection du membre
    ///   par flux choisit QUEL WAN, pas SI le trafic passe ; tous les
    ///   membres sortent vers le même périmètre externe avec le même
    ///   filtre de sortie, donc le VERDICT d'accessibilité est identique
    ///   (le moteur évalue les WAN en ECMP et tranche fermement s'ils
    ///   s'accordent). La fidélité n'est PAS dégradée.
    fn sdwan_block(&mut self, block: &ConfigNode) {
        // La zone implicite de FortiOS existe dès que le SD-WAN est
        // configuré (comportement documenté du produit).
        self.sdwan_zones.insert(SDWAN_DEFAULT_ZONE.to_owned());
        for d in &block.children {
            match (d.keyword.as_str(), d.arg(0)) {
                ("set", Some("status")) => match d.arg(1) {
                    Some("enable") => self.sdwan_enabled = true,
                    Some("disable") => {
                        self.sdwan_enabled = false;
                        self.note_info(
                            "SD-WAN désactivé (`set status disable`) : zones et membres sans \
                             effet"
                                .to_owned(),
                            &d.span,
                        );
                    }
                    _ => self.unsupported(
                        "`set status` invalide dans `config system sdwan`".to_owned(),
                        &d.span,
                    ),
                },
                ("config", Some("zone")) => self.sdwan_zone_block(d),
                ("config", Some("members")) => self.sdwan_members_block(d),
                ("config", Some("health-check")) => {
                    for check in &d.children {
                        match (check.keyword.as_str(), check.arg(0)) {
                            ("edit", Some(name)) => self.note_info(
                                format!(
                                    "health-check SD-WAN `{name}` non modélisé : la \
                                     supervision des liens n'affecte pas le modèle statique"
                                ),
                                &check.span,
                            ),
                            _ => self.unsupported(
                                format!(
                                    "directive `{}` non gérée dans `config health-check` \
                                     (system sdwan)",
                                    check.keyword
                                ),
                                &check.span,
                            ),
                        }
                    }
                }
                ("config", Some("service")) => {
                    for svc in &d.children {
                        match (svc.keyword.as_str(), svc.arg(0)) {
                            // Une règle SD-WAN par flux choisit QUEL membre
                            // (WAN) emprunter, pas SI le trafic passe : tous
                            // les membres sont des liens de sortie vers le
                            // même périmètre externe, avec le même filtre de
                            // sortie (zone SD-WAN). Le choix relève de la
                            // qualité de service et de la disponibilité, pas
                            // de l'accessibilité — le verdict d'un flux ne
                            // change pas (le moteur évalue déjà les WAN en
                            // ECMP et rend un verdict ferme s'ils s'accordent).
                            // Reconnue, sans effet sur le verdict : note Info.
                            ("edit", Some(name)) => self.note_info(
                                format!(
                                    "règle SD-WAN {name} reconnue : la sélection du membre \
                                     (WAN) par flux relève de la QoS/disponibilité, sans effet \
                                     sur le verdict d'accessibilité (les WAN sont évalués en ECMP)"
                                ),
                                &svc.span,
                            ),
                            _ => self.unsupported(
                                format!(
                                    "directive `{}` non gérée dans `config service` \
                                     (system sdwan)",
                                    svc.keyword
                                ),
                                &svc.span,
                            ),
                        }
                    }
                }
                _ => self.unsupported(
                    format!(
                        "`{}` non géré dans `config system sdwan`",
                        directive_excerpt(&d.keyword, &d.args, 1)
                    ),
                    &d.span,
                ),
            }
        }
    }

    /// `config zone` (system sdwan) : les noms de zones SD-WAN.
    fn sdwan_zone_block(&mut self, block: &ConfigNode) {
        for edit in &block.children {
            let Some(name) = self.edit_name(edit, "config zone (system sdwan)") else {
                continue;
            };
            for d in &edit.children {
                self.unsupported(
                    format!(
                        "`{}` non géré dans la zone SD-WAN `{name}`",
                        directive_excerpt(&d.keyword, &d.args, 1)
                    ),
                    &d.span,
                );
            }
            self.sdwan_zones.insert(name);
        }
    }

    /// `config members` (system sdwan) : interface + passerelle de chaque
    /// membre, et sa zone d'appartenance.
    fn sdwan_members_block(&mut self, block: &ConfigNode) {
        for edit in &block.children {
            let Some(label) = self.edit_name(edit, "config members (system sdwan)") else {
                continue;
            };
            let mut iface: Option<IfaceId> = None;
            let mut gateway: Option<IpAddr> = None;
            let mut zone = SDWAN_DEFAULT_ZONE.to_owned();
            let mut disabled = false;
            let mut broken = false;
            for d in &edit.children {
                if d.keyword != "set" {
                    self.unsupported(
                        format!(
                            "directive `{}` non gérée dans le membre SD-WAN {label}",
                            d.keyword
                        ),
                        &d.span,
                    );
                    continue;
                }
                match d.arg(0) {
                    Some("interface") => iface = d.arg(1).map(IfaceId::new),
                    Some("gateway") => match d.arg(1).and_then(|v| v.parse().ok()) {
                        Some(ip) => gateway = Some(ip),
                        None => {
                            self.unsupported(
                                format!("passerelle invalide sur le membre SD-WAN {label}"),
                                &d.span,
                            );
                            broken = true;
                        }
                    },
                    Some("zone") => {
                        if let Some(z) = d.arg(1) {
                            zone = z.to_owned();
                        }
                    }
                    Some("status") => disabled = d.arg(1) == Some("disable"),
                    Some("comment") => {}
                    // weight, cost, priority… : ils pilotent la sélection
                    // de membre, non modélisée → chemin normal (§6.3).
                    other => self.unsupported(
                        format!(
                            "`set {}` non géré sur le membre SD-WAN {label}",
                            other.unwrap_or("")
                        ),
                        &d.span,
                    ),
                }
            }
            if disabled {
                self.note_info(
                    format!("membre SD-WAN {label} désactivé (`set status disable`) : ignoré"),
                    &edit.span,
                );
                continue;
            }
            if broken {
                continue;
            }
            let Some(iface) = iface else {
                self.unsupported(
                    format!("membre SD-WAN {label} sans `set interface`"),
                    &edit.span,
                );
                continue;
            };
            if !self.device.interfaces.contains_key(&iface) {
                self.note_warning(
                    format!("le membre SD-WAN {label} référence une interface inconnue `{iface}`"),
                    &edit.span,
                );
            }
            self.sdwan_members.push(SdwanMember {
                iface,
                gateway,
                zone,
            });
        }
    }

    // -- config vpn ipsec phase1-interface ------------------------------

    /// `config vpn ipsec phase1-interface` : la passerelle distante et
    /// l'interface parente sont des faits de TOPOLOGIE (le site distant
    /// n'est pas dans le modèle) → note Info. L'interface tunnel du même
    /// nom vient de `config system interface` (type tunnel).
    ///
    /// Chiffrement et négociation (`proposal`, `dhgrp`, `psksecret`…) :
    /// compris et sans effet sur le filtrage — la valeur de `psksecret`
    /// ne va JAMAIS dans un diagnostic (§11.4).
    fn phase1_block(&mut self, block: &ConfigNode) {
        for edit in &block.children {
            let Some(name) = self.edit_name(edit, "config vpn ipsec phase1-interface") else {
                continue;
            };
            let mut parent: Option<String> = None;
            let mut remote_gw: Option<IpAddr> = None;
            for d in &edit.children {
                if d.keyword != "set" {
                    self.unsupported(
                        format!(
                            "directive `{}` non gérée dans le tunnel IPsec `{name}`",
                            d.keyword
                        ),
                        &d.span,
                    );
                    continue;
                }
                match d.arg(0) {
                    Some("interface") => parent = d.arg(1).map(str::to_owned),
                    Some("remote-gw") => match d.arg(1).and_then(|v| v.parse().ok()) {
                        Some(ip) => remote_gw = Some(ip),
                        None => self.unsupported(
                            format!("`set remote-gw` invalide dans le tunnel IPsec `{name}`"),
                            &d.span,
                        ),
                    },
                    // Chiffrement/négociation : sans effet sur le
                    // filtrage. La VALEUR de psksecret est un secret :
                    // elle ne sort jamais dans un diagnostic.
                    Some(
                        "psksecret"
                        | "proposal"
                        | "dhgrp"
                        | "ike-version"
                        | "keylife"
                        | "nattraversal"
                        | "dpd"
                        | "dpd-retrycount"
                        | "dpd-retryinterval"
                        | "peertype"
                        | "comments"
                        | "net-device"
                        | "mode-cfg"
                        | "mode"
                        | "add-route"
                        | "exchange-interface-ip"
                        | "wizard-type"
                        | "role"
                        | "xauthtype"
                        | "authusrgrp"
                        | "save-password"
                        | "idle-timeout"
                        | "idle-timeoutinterval"
                        | "ipv4-dns-server1"
                        | "ipv4-dns-server2"
                        | "ipv4-dns-server3"
                        | "ipv4-split-include"
                        | "ipv4-start-ip"
                        | "ipv4-end-ip"
                        | "ipv4-netmask"
                        | "dns-mode"
                        | "localid"
                        | "localid-type",
                    ) => {}
                    Some(k) if is_cosmetic_key(k) => {}
                    other => self.unsupported(
                        format!(
                            "`set {}` non géré dans le tunnel IPsec `{name}`",
                            other.unwrap_or("")
                        ),
                        &d.span,
                    ),
                }
            }
            if !self
                .device
                .interfaces
                .contains_key(&IfaceId::new(name.as_str()))
            {
                self.note_warning(
                    format!(
                        "tunnel IPsec `{name}` sans interface tunnel du même nom \
                         (`config system interface`)"
                    ),
                    &edit.span,
                );
            }
            match (remote_gw, parent) {
                (Some(gw), Some(itf)) => self.note_info(
                    format!(
                        "tunnel IPsec `{name}` : passerelle distante {gw} via `{itf}` \
                         (topologie inter-sites non modélisée pour l'instant)"
                    ),
                    &edit.span,
                ),
                _ => self.note_info(
                    format!(
                        "tunnel IPsec `{name}` (topologie inter-sites non modélisée pour \
                         l'instant)"
                    ),
                    &edit.span,
                ),
            }
            self.phase1_names.insert(name);
        }
    }

    // -- config vpn ipsec phase2-interface ------------------------------

    /// `config vpn ipsec phase2-interface` : les SÉLECTEURS. Chaque
    /// phase2 devient une règle d'une politique de SORTIE `ipsec:<T>`
    /// (construite après la première passe, voir
    /// [`Self::build_ipsec_policies`]).
    fn phase2_block(&mut self, block: &ConfigNode) {
        for edit in &block.children {
            let Some(name) = self.edit_name(edit, "config vpn ipsec phase2-interface") else {
                continue;
            };
            let mut phase1name: Option<String> = None;
            let mut src: Option<Phase2Sel> = None;
            let mut dst: Option<Phase2Sel> = None;
            let mut broken = false;
            for d in &edit.children {
                if d.keyword != "set" {
                    self.unsupported(
                        format!(
                            "directive `{}` non gérée dans le sélecteur phase2 `{name}`",
                            d.keyword
                        ),
                        &d.span,
                    );
                    continue;
                }
                match d.arg(0) {
                    Some("phase1name") => phase1name = d.arg(1).map(str::to_owned),
                    Some(key @ ("src-name" | "dst-name")) => match d.arg(1) {
                        Some(obj) => {
                            let sel = Some(Phase2Sel::Name(obj.to_owned()));
                            if key == "src-name" {
                                src = sel;
                            } else {
                                dst = sel;
                            }
                        }
                        None => {
                            self.unsupported(
                                format!("`set {key}` sans objet dans le sélecteur phase2 `{name}`"),
                                &d.span,
                            );
                            broken = true;
                        }
                    },
                    Some(key @ ("src-subnet" | "dst-subnet")) => {
                        match values::ip_mask_to_net(d.arg(1).unwrap_or(""), d.arg(2)) {
                            Some(net) => {
                                let sel = Some(Phase2Sel::Subnet(net.trunc()));
                                if key == "src-subnet" {
                                    src = sel;
                                } else {
                                    dst = sel;
                                }
                            }
                            None => {
                                self.unsupported(
                                    format!(
                                        "`set {key}` invalide dans le sélecteur phase2 `{name}`"
                                    ),
                                    &d.span,
                                );
                                broken = true;
                            }
                        }
                    }
                    // Chiffrement/négociation : sans effet sur les
                    // sélecteurs.
                    Some(
                        "proposal" | "pfs" | "dhgrp" | "keylifeseconds" | "keylife-type"
                        | "auto-negotiate" | "keepalive" | "replay" | "comments"
                        // `src-addr-type`/`dst-addr-type` disent SEULEMENT
                        // sous quelle forme le sélecteur est donné (nom ou
                        // sous-réseau) — la VALEUR est déjà captée par
                        // src-name/dst-name/src-subnet/dst-subnet.
                        | "src-addr-type" | "dst-addr-type" | "encapsulation",
                    ) => {}
                    Some(k) if is_cosmetic_key(k) => {}
                    other => self.unsupported(
                        format!(
                            "`set {}` non géré dans le sélecteur phase2 `{name}`",
                            other.unwrap_or("")
                        ),
                        &d.span,
                    ),
                }
            }
            if broken {
                continue;
            }
            let Some(phase1name) = phase1name else {
                self.unsupported(
                    format!("sélecteur phase2 `{name}` sans `set phase1name`"),
                    &edit.span,
                );
                continue;
            };
            self.pending_phase2.push(PendingPhase2 {
                name,
                phase1name,
                src,
                dst,
                span: edit.span.clone(),
            });
        }
    }

    /// Construit les politiques `ipsec:<tunnel>` à partir des sélecteurs
    /// phase2, une fois la première passe terminée.
    ///
    /// Sémantique modélisée (celle du produit) : sur l'interface tunnel,
    /// le FortiGate ne chiffre QUE le trafic qui correspond à un
    /// sélecteur phase2 et JETTE le reste. C'est donc un vrai filtre de
    /// SORTIE : une politique `ipsec:<T>` accrochée en `egress`, une
    /// règle Accept par sélecteur (zone `to` = l'interface tunnel `T`),
    /// `default_action = Deny`.
    ///
    /// Un sélecteur absent (`src-name`/`src-subnet` non posés) est
    /// `0.0.0.0/0` chez FortiOS : dimension laissée vide (= Any).
    fn build_ipsec_policies(&mut self) {
        let pending = std::mem::take(&mut self.pending_phase2);
        // Zone du tunnel de chaque politique ipsec:<T>, pour la règle
        // finale de rejet (une par politique, APRÈS tous les sélecteurs).
        let mut deny_scopes: Vec<(PolicyId, Option<ZoneId>, SourceSpan)> = Vec::new();
        for p2 in pending {
            if !self.phase1_names.contains(&p2.phase1name) {
                self.note_warning(
                    format!(
                        "sélecteur phase2 `{}` : tunnel phase1 `{}` inconnu",
                        p2.name, p2.phase1name
                    ),
                    &p2.span,
                );
            }
            let to = self.zone_ref(std::slice::from_ref(&p2.phase1name), &p2.span, "phase1name");
            let src = self.phase2_sel_exprs(p2.src, &p2.span);
            let dst = self.phase2_sel_exprs(p2.dst, &p2.span);
            let pid = PolicyId::new(format!("ipsec:{}", p2.phase1name));
            let policy = self
                .device
                .policies
                .entry(pid.clone())
                .or_insert_with(|| Policy {
                    id: pid.clone(),
                    rules: Vec::new(),
                    // ACCEPT par défaut : dans le pipeline de sortie
                    // CHAÎNÉ du moteur, cette politique voit AUSSI le
                    // trafic qui ne sort pas par le tunnel — un défaut
                    // Deny refuserait tout le reste. Le comportement
                    // FortiGate (« ce qui ne matche aucun sélecteur est
                    // jeté ») est porté par la règle finale
                    // `ipsec-implicit-deny`, SCOPÉE à la zone du tunnel.
                    default_action: Action::Accept,
                });
            if !deny_scopes.iter().any(|(id, _, _)| *id == pid) {
                deny_scopes.push((pid.clone(), to.clone(), p2.span.clone()));
            }
            policy.rules.push(Rule {
                id: RuleId::new(p2.name),
                matches: RuleMatch {
                    src,
                    dst,
                    services: Vec::new(),
                },
                from: None,
                to,
                action: Action::Accept,
                source: p2.span,
            });
            if !self.device.pipeline.egress.contains(&pid) {
                self.device.pipeline.egress.push(pid);
            }
        }
        // Le rejet implicite du tunnel : tout ce qui SORT PAR LE TUNNEL
        // sans matcher un sélecteur est jeté (sémantique FortiGate),
        // le reste du trafic n'est pas concerné. Si un sélecteur couvre
        // déjà tout (Any/Any — tunnels nomades en mode-cfg), le rejet
        // serait inatteignable par construction : on ne l'ajoute pas,
        // sinon `dead-rules` le signalerait à tort comme une anomalie de
        // la configuration analysée.
        for (pid, to, span) in deny_scopes {
            if let Some(policy) = self.device.policies.get_mut(&pid) {
                let un_selecteur_couvre_tout = policy.rules.iter().any(|r| {
                    r.matches.src.is_empty()
                        && r.matches.dst.is_empty()
                        && r.matches.services.is_empty()
                });
                if un_selecteur_couvre_tout {
                    continue;
                }
                policy.rules.push(Rule {
                    id: RuleId::new("ipsec-implicit-deny"),
                    matches: RuleMatch::default(),
                    from: None,
                    to,
                    action: Action::Deny,
                    source: span,
                });
            }
        }
    }

    /// Un sélecteur phase2 → expressions d'adresse (vide = Any).
    fn phase2_sel_exprs(&mut self, sel: Option<Phase2Sel>, span: &SourceSpan) -> Vec<AddrExpr> {
        match sel {
            None => Vec::new(),
            Some(Phase2Sel::Subnet(net)) => vec![AddrExpr::Net(net)],
            Some(Phase2Sel::Name(name)) => self.addr_exprs(&[name], span),
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
            // Objet dont l'étendue est EXTERNE (fqdn/wildcard/géographie) :
            // le type et sa valeur-repère (« hint ») sont compris, seule
            // l'étendue en préfixes est inconnue hors ligne (§6.3).
            let mut external_kind: Option<ExternalKind> = None;
            let mut fqdn_value: Option<String> = None;
            let mut wildcard_value: Option<String> = None;
            let mut country_value: Option<String> = None;
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
                        // fqdn, wildcard-fqdn, geography : étendue INCONNUE
                        // hors ligne. On ne devine pas, mais on ne jette
                        // plus l'objet : il est COMPRIS et stocké en
                        // `External` (résoluble via `--resolve`).
                        Some("fqdn") => external_kind = Some(ExternalKind::Fqdn),
                        Some("wildcard-fqdn") => external_kind = Some(ExternalKind::WildcardFqdn),
                        Some("geography") => external_kind = Some(ExternalKind::Geography),
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
                    // Valeurs-repère des objets externes : le nom de domaine
                    // (fqdn/wildcard) ou le code pays (geography). Ce sont
                    // les clés à fournir dans le fichier `--resolve`.
                    Some("fqdn") => fqdn_value = d.arg(1).map(str::to_owned),
                    Some("wildcard-fqdn") => wildcard_value = d.arg(1).map(str::to_owned),
                    Some("country") => country_value = d.arg(1).map(str::to_owned),
                    // Reconnus, sans effet sur l'accessibilité.
                    Some("associated-interface" | "allow-routing") => {}
                    Some(k) if is_cosmetic_key(k) => {}
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
            let object = if let Some(kind) = external_kind {
                // Objet externe : la valeur-repère selon le type.
                let raw_hint = match kind {
                    ExternalKind::Fqdn | ExternalKind::WildcardFqdn => {
                        fqdn_value.clone().or_else(|| wildcard_value.clone())
                    }
                    ExternalKind::Geography => country_value.clone(),
                };
                let Some(hint) = raw_hint else {
                    self.unsupported(
                        format!(
                            "objet adresse `{name}` de type {kind} sans valeur-repère \
                             (`set fqdn`/`set wildcard-fqdn`/`set country`)"
                        ),
                        &edit.span,
                    );
                    continue;
                };
                // Un `type fqdn` dont la valeur porte un `*` est en fait un
                // motif : on le classe en wildcard (correspondance de clé
                // EXACTE à la résolution, jamais de glob).
                let kind = match kind {
                    ExternalKind::Fqdn if hint.starts_with('*') => ExternalKind::WildcardFqdn,
                    k => k,
                };
                // Note Info (pas Warning) : l'objet EST compris, ce n'est
                // pas une lacune de fidélité — juste une étendue à fournir.
                self.note_info(
                    format!(
                        "objet adresse `{name}` de type {kind} : étendue externe (« {hint} ») \
                         non résolue hors ligne — fournissez ses préfixes via `--resolve` pour \
                         l'inclure dans l'analyse"
                    ),
                    &edit.span,
                );
                AddrObject::External { kind, hint }
            } else if is_range {
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
                    ("set", Some(k)) if is_cosmetic_key(k) => {}
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
            // ICMP : le type et le code sont modélisés dans les dimensions
            // de ports (convention de `ConcretePacket` : dport = type,
            // sport = code). `None` = tout type / tout code.
            let mut icmp_type: Option<u16> = None;
            let mut icmp_code: Option<u16> = None;
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
                    // Type/code ICMP : modélisés dans les dimensions de
                    // ports (dport = type, sport = code). `~`/absent = tout.
                    Some("icmptype") => match d.arg(1) {
                        None | Some("~") => {}
                        Some(v) => match v.parse::<u16>() {
                            Ok(t) if t <= 255 => icmp_type = Some(t),
                            _ => {
                                self.unsupported(
                                    format!("`set icmptype` invalide dans le service `{name}`"),
                                    &d.span,
                                );
                                broken = true;
                            }
                        },
                    },
                    Some("icmpcode") => match d.arg(1) {
                        None | Some("~") => {}
                        Some(v) => match v.parse::<u16>() {
                            Ok(c) if c <= 255 => icmp_code = Some(c),
                            _ => {
                                self.unsupported(
                                    format!("`set icmpcode` invalide dans le service `{name}`"),
                                    &d.span,
                                );
                                broken = true;
                            }
                        },
                    },
                    Some(k) if is_cosmetic_key(k) => {}
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
                Some("ICMP") => services.push(icmp_service(1, icmp_type, icmp_code)),
                Some("ICMP6") => services.push(icmp_service(58, icmp_type, icmp_code)),
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
                    ("set", Some(k)) if is_cosmetic_key(k) => {}
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
                    // Reconnus, sans effet sur la DÉCISION autoriser/refuser.
                    // Les profils UTM (antivirus, filtrage web, IPS, SSL…)
                    // inspectent le trafic DÉJÀ AUTORISÉ ; ils ne changent
                    // pas « qui peut joindre quoi ». `port-preserve` est un
                    // détail de traduction de port source. Reconnus, sans
                    // effet sur l'accessibilité de premier niveau.
                    Some(
                        "name"
                        | "logtraffic"
                        | "logtraffic-start"
                        | "utm-status"
                        | "inspection-mode"
                        | "ssl-ssh-profile"
                        | "av-profile"
                        | "webfilter-profile"
                        | "dnsfilter-profile"
                        | "emailfilter-profile"
                        | "dlp-profile"
                        | "dlp-sensor"
                        | "file-filter-profile"
                        | "ips-sensor"
                        | "application-list"
                        | "voip-profile"
                        | "icap-profile"
                        | "waf-profile"
                        | "ssh-filter-profile"
                        | "profile-protocol-options"
                        | "profile-type"
                        | "profile-group"
                        | "av-quarantine"
                        | "scan-botnet-connections"
                        | "port-preserve"
                        | "auto-asic-offload"
                        | "np-acceleration"
                        | "fixedport"
                        | "block-notification"
                        | "replacemsg-override-group"
                        | "traffic-shaper"
                        | "traffic-shaper-reverse"
                        | "per-ip-shaper"
                        | "capture-packet"
                        | "wanopt"
                        | "webcache"
                        | "session-ttl"
                        | "schedule-timeout"
                        | "anti-replay"
                        | "tcp-mss-sender"
                        | "tcp-mss-receiver"
                        | "label"
                        | "global-label",
                    ) => {}
                    // ATTENTION — ces clés CHANGENT le périmètre de la règle
                    // et NE doivent PAS être avalées en silence (ce serait
                    // sur-approximer → risque de faux « autorisé », §6.3) :
                    // `groups`/`users`/`fsso-groups` restreignent aux
                    // identités authentifiées ; `internet-service*` remplace
                    // les adresses par des jeux d'IP prédéfinis ; `*-negate`
                    // INVERSE la correspondance ; `nat46/64` change
                    // l'adressage. Elles restent diagnostiquées (Partial).
                    Some(k) if is_cosmetic_key(k) => {}
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

            let src = self.addr_exprs(&srcaddr, &span);
            let services = self.service_exprs(&service, &span);

            // Destinations VIP : quand la règle ACCEPTE vers un VIP (ou
            // un groupe de VIP), elle porte la redirection (DNAT). Un
            // refus vers un VIP ne traduit rien : chemin normal.
            let mut vip_parts: Vec<String> = Vec::new();
            let mut autres: Vec<String> = Vec::new();
            if matches!(action, Action::Deny) {
                autres = dstaddr.clone();
            } else {
                for dname in &dstaddr {
                    if let Some(members) = self.vipgrps.get(dname).cloned() {
                        for m in members {
                            if self.vips.contains_key(&m) {
                                vip_parts.push(m);
                            } else {
                                self.unsupported(
                                    format!(
                                        "politique {num} : le groupe de VIP `{dname}` référence \
                                         un VIP inconnu `{m}` — redirection irrésoluble"
                                    ),
                                    &span,
                                );
                            }
                        }
                    } else if self.vips.contains_key(dname) {
                        vip_parts.push(dname.clone());
                    } else {
                        autres.push(dname.clone());
                    }
                }
            }

            if vip_parts.is_empty() {
                rules.push(Rule {
                    id: RuleId::new(num),
                    matches: RuleMatch {
                        src,
                        dst: self.addr_exprs(&autres, &span),
                        services,
                    },
                    from,
                    to,
                    action,
                    // Le span du `edit N` : fichier + ligne (+ ligne du `next`).
                    source: span,
                });
                continue;
            }

            // Plusieurs destinations externes aux cibles DIFFÉRENTES ne
            // tiennent pas dans un seul `DnatTarget` : la règle est
            // ÉCLATÉE en une règle par VIP (identifiants suffixés
            // `<n>:<vip>`, même span — exact et traçable), les
            // destinations non-VIP gardant l'identifiant d'origine.
            let multi = vip_parts.len() + usize::from(!autres.is_empty()) > 1;
            if multi {
                self.note_info(
                    format!(
                        "politique {num} éclatée en {} règles : une par VIP référencé \
                         (identifiants suffixés `{num}:<vip>`), chaque destination externe \
                         ayant sa propre cible de redirection",
                        vip_parts.len() + usize::from(!autres.is_empty())
                    ),
                    &span,
                );
            }
            // `set nat enable` éventuel : la part de SNAT existante est
            // conservée et le DNAT du VIP s'y ajoute.
            let base_nat = match &action {
                Action::Nat(nat) => nat.clone(),
                _ => NatAction::default(),
            };
            for vip_name in &vip_parts {
                let Some(vip) = self.vips.get(vip_name).cloned() else {
                    continue; // filtré ci-dessus, jamais atteint.
                };
                // `set protocol`/`set extport` du VIP contraignent le
                // service de la règle : le trafic ne matche que s'il vise
                // le port externe du VIP. La contrainte réelle est donc
                // `service ∩ port_du_VIP`. On la calcule quand c'est
                // représentable (service Any, ou objets service résolus en
                // services concrets), sinon on diagnostique.
                let rule_services = match &vip.service {
                    Some(svc) if is_any_services(&services) => vec![ServiceExpr::Service(*svc)],
                    Some(svc) => match self.intersect_services_with_vip(&services, *svc) {
                        Some(inter) => inter,
                        None => {
                            self.unsupported(
                                format!(
                                    "politique {num} : service explicite combiné à la redirection \
                                     de ports du VIP `{vip_name}` — intersection non \
                                     représentable, la restriction de port du VIP n'est pas \
                                     appliquée"
                                ),
                                &span,
                            );
                            services.clone()
                        }
                    },
                    None => services.clone(),
                };
                rules.push(Rule {
                    id: if multi {
                        RuleId::new(format!("{num}:{vip_name}"))
                    } else {
                        RuleId::new(num.as_str())
                    },
                    matches: RuleMatch {
                        src: src.clone(),
                        dst: vec![AddrExpr::Object(ObjectId::new(vip_name.as_str()))],
                        services: rule_services,
                    },
                    from: from.clone(),
                    to: to.clone(),
                    action: Action::Nat(NatAction {
                        snat: base_nat.snat,
                        dnat: Some(vip.dnat),
                    }),
                    source: span.clone(),
                });
            }
            if !autres.is_empty() {
                // Les destinations non-VIP de la même règle : pas de
                // redirection pour elles (comportement du produit).
                let dst = self.addr_exprs(&autres, &span);
                rules.push(Rule {
                    id: RuleId::new(num),
                    matches: RuleMatch { src, dst, services },
                    from,
                    to,
                    action,
                    source: span,
                });
            }
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

/// `set service "ALL"` (ou aucune contrainte) : le service de la règle
/// est « tout » — la contrainte de port d'un VIP peut alors le remplacer
/// EXACTEMENT (l'intersection de « tout » avec la contrainte, c'est la
/// contrainte).
fn is_any_services(services: &[ServiceExpr]) -> bool {
    matches!(services, [] | [ServiceExpr::Any])
}

/// Un service ICMP, type/code portés par les dimensions de ports
/// (convention de `ConcretePacket` : dport = type, sport = code). `None`
/// = tout type / tout code (`PortRange::ANY`).
fn icmp_service(proto: u8, icmp_type: Option<u16>, icmp_code: Option<u16>) -> Service {
    let dim = |v: Option<u16>| match v {
        Some(n) => PortRange::single(n),
        None => PortRange::ANY,
    };
    Service {
        proto: ProtoMatch::Number(proto),
        sport: dim(icmp_code),
        dport: dim(icmp_type),
    }
}

/// Une clé `set …` qui est de la MÉTADONNÉE pure dans n'importe quel
/// contexte d'objet : identifiants internes, commentaires, couleur,
/// état FortiManager, redondances de type déjà captées ailleurs. Aucune
/// ne peut changer un verdict d'accessibilité. Reconnue, sans effet —
/// note Info, jamais une lacune de fidélité (§6.3 : classer n'est pas
/// deviner ; seule une clé qui POURRAIT peser sur le filtrage reste en
/// `unsupported`).
fn is_cosmetic_key(key: &str) -> bool {
    matches!(
        key,
        "uuid"
            | "comment"
            | "comments"
            | "color"
            | "dirty"
            | "sub-type"
            | "obj-type"
            | "visibility"
            | "global-object"
            | "category"
    )
}

/// Un bloc de premier niveau `config …` sans AUCUN effet possible sur
/// l'accessibilité (filtrage, NAT, routage, interfaces, objets). Reconnu
/// et classé hors modèle : note Info, pas une lacune de fidélité.
///
/// Ce n'est pas « deviner » (§6.3) : rien de ces blocs ne peut changer un
/// verdict « qui peut joindre quoi » — ce sont des messages de
/// remplacement, de l'administration, du GUI, de la journalisation, de la
/// supervision, du contrôleur WiFi/switch, etc. La liste est explicite et
/// prudente : au moindre doute sur un bloc touchant le trafic, il RESTE en
/// `unsupported` (Warning + Partial).
fn is_cosmetic_block(path: &[&str]) -> bool {
    match path {
        // Messages de remplacement (HTML/texte affichés à l'utilisateur).
        ["system", "replacemsg", ..] | ["system", "replacemsg-image", ..] => true,
        // Administration, GUI, supervision, journalisation — aucun filtrage.
        ["system", "admin"]
        | ["system", "accprofile"]
        | ["system", "sso-admin"]
        | ["system", "api-user"]
        | ["system", "snmp", ..]
        | ["system", "npu"]
        | ["system", "console"]
        | ["system", "ntp"]
        | ["system", "dns"]
        | ["system", "dns-database"]
        | ["system", "ddns"]
        | ["system", "fortiguard"]
        | ["system", "fortimanager", ..]
        | ["system", "central-management"]
        | ["system", "auto-install"]
        | ["system", "automation-trigger" | "automation-action" | "automation-stitch"]
        | ["system", "settings"]
        | ["system", "session-helper" | "session-ttl"]
        | ["system", "standalone-cluster"]
        | ["system", "ha"]
        | ["system", "email-server"]
        | ["system", "custom-language"]
        | ["system", "object-tagging"]
        | ["system", "sdn-connector"]
        | ["system", "saml"]
        | ["system", "vdom", ..]
        | ["system", "gre-tunnel"]
        | ["system", "physical-switch"]
        | ["system", "virtual-switch"]
        | ["system", "sso-fortigate-cloud-admin"]
        | ["system", "sso-forticloud-admin"]
        | ["system", "autoupdate", ..]
        | ["system", "ftm-push"]
        | ["system", "federated-upgrade"]
        | ["system", "ike"]
        | ["system", "dhcp", ..]
        | ["system", "fortiguard-log"]
        | ["system", "fortisandbox"]
        | ["system", "geoip-override"]
        | ["system", "speed-test-schedule"]
        | ["system", "vne-tunnel"]
        | ["log", ..]
        | ["user", ..]
        | ["switch-controller", ..]
        | ["wireless-controller", ..]
        | ["endpoint-control", ..]
        | ["vpn", "certificate", ..]
        | ["vpn", "ssl", ..]
        | ["certificate", ..] => true,
        // Profils de sécurité (inspection de contenu) : ils modulent le
        // trafic AUTORISÉ (antivirus, filtrage web…) mais ne changent pas
        // la décision d'accessibilité de premier niveau. Hors modèle.
        ["antivirus", ..]
        | ["webfilter", ..]
        | ["dnsfilter", ..]
        | ["application", ..]
        | ["ips", ..]
        | ["emailfilter", ..]
        | ["dlp", ..]
        | ["file-filter", ..]
        | ["ssh-filter", ..]
        | ["icap", ..]
        | ["waf", ..]
        | ["casb", ..]
        | ["virtual-patch", ..]
        | ["videofilter", ..]
        | ["firewall", "profile-protocol-options" | "ssl-ssh-profile"]
        | ["firewall", "shaper", ..]
        | ["firewall", "schedule", ..]
        | ["firewall", "internet-service-name" | "internet-service-definition"]
        // Définitions de libellés de catégories de services : métadonnée.
        | ["firewall", "service", "category"]
        | ["firewall", "on-demand-sniffer"]
        | ["firewall", "proxy-address" | "proxy-addrgrp"]
        | ["web-proxy", ..]
        | ["router", "rip" | "ripng" | "ospf" | "ospf6" | "bgp" | "isis" | "multicast"]
        | ["firewall", "ssh", ..] => true,
        _ => false,
    }
}

impl Converter {
    /// `service ∩ port_du_VIP` : le trafic d'une règle référençant un VIP
    /// ne matche que s'il vise le port externe du VIP. On résout chaque
    /// expression de service en services concrets (via l'`ObjectStore`,
    /// déjà peuplé — les blocs service sont traités avant les politiques),
    /// on intersecte chacun avec la contrainte du VIP, et on garde les
    /// intersections non vides.
    ///
    /// Rend `None` (→ diagnostic, jamais d'approximation) dès qu'une
    /// expression n'est pas résoluble en services concrets : `Any`
    /// résiduel, objet service manquant ou groupe cyclique. Cela ÉVITE le
    /// faux positif de `dead-rules` où deux règles éclatées d'un même VIP
    /// (ports différents) se masqueraient faute de contrainte de port.
    fn intersect_services_with_vip(
        &self,
        services: &[ServiceExpr],
        vip: Service,
    ) -> Option<Vec<ServiceExpr>> {
        let mut out = Vec::new();
        for expr in services {
            let concretes = match expr {
                ServiceExpr::Service(s) => vec![*s],
                ServiceExpr::Object(id) => {
                    let mut acc = Vec::new();
                    self.flatten_service_object(id, &mut Vec::new(), &mut acc)?;
                    acc
                }
                ServiceExpr::Any => return None,
            };
            for c in concretes {
                if let Some(inter) = c.intersect(vip) {
                    out.push(ServiceExpr::Service(inter));
                }
            }
        }
        // Intersection VIDE (service explicite et port du VIP disjoints) :
        // la règle ne matche RIEN. On ne peut PAS le représenter par un
        // vecteur vide — la convention de `RuleMatch` fait qu'un vecteur
        // vide vaut `Any` (tout), l'exact contraire. Faute de « service
        // impossible » dans le modèle, on rend `None` : l'appelant garde le
        // service d'origine (sur-approximation) ET diagnostique — honnête,
        // jamais un faux « autorisé » silencieux.
        if out.is_empty() {
            return None;
        }
        Some(out)
    }

    /// Aplatit un objet service en services concrets, groupes imbriqués
    /// compris. `None` si l'objet est absent ou si un cycle est détecté
    /// (l'intersection n'est alors pas représentable).
    fn flatten_service_object(
        &self,
        id: &ObjectId,
        stack: &mut Vec<ObjectId>,
        out: &mut Vec<Service>,
    ) -> Option<()> {
        if stack.contains(id) {
            return None; // cycle : non représentable.
        }
        match self.device.objects.services.get(id)? {
            ServiceObject::Services(list) => {
                out.extend(list.iter().copied());
                Some(())
            }
            ServiceObject::Group(members) => {
                stack.push(id.clone());
                for m in members {
                    self.flatten_service_object(m, stack, out)?;
                }
                stack.pop();
                Some(())
            }
        }
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

    /// Un service ICMP avec `set icmptype` est modélisé : le type va dans
    /// la dimension `dport`, le code (absent) reste « tout » (convention de
    /// `ConcretePacket`). Un `path … :8/icmp` (echo request) matche alors.
    #[test]
    fn service_icmp_type_modelise() {
        let out = import(
            "config firewall service custom\n    edit \"PING\"\n        \
             set protocol ICMP\n        set icmptype 8\n    next\n    \
             edit \"ICMP-ALL\"\n        set protocol ICMP\n    next\nend\n",
        );
        assert_eq!(out.fidelity, Fidelity::Complete, "{:?}", out.fidelity);
        let ping = svc_obj_local(&out.device, "PING");
        assert_eq!(
            ping,
            &ServiceObject::Services(vec![Service {
                proto: ProtoMatch::Number(1),
                sport: PortRange::ANY,       // tout code
                dport: PortRange::single(8), // type 8 = echo request
            }])
        );
        // Sans icmptype : tout type, tout code.
        let all = svc_obj_local(&out.device, "ICMP-ALL");
        assert_eq!(
            all,
            &ServiceObject::Services(vec![Service {
                proto: ProtoMatch::Number(1),
                sport: PortRange::ANY,
                dport: PortRange::ANY,
            }])
        );
    }

    fn svc_obj_local<'a>(dev: &'a Device, name: &str) -> &'a ServiceObject {
        dev.objects
            .services
            .get(&ObjectId::new(name))
            .unwrap_or_else(|| panic!("service `{name}` absent"))
    }

    /// Un bloc sans effet sur l'accessibilité (messages de remplacement,
    /// profil de sécurité, administration…) ne dégrade PAS la fidélité :
    /// il est reconnu (note Info), pas compté comme lacune. Sinon toute
    /// configuration réelle serait `Partial` et aucun verdict ne serait
    /// ferme.
    #[test]
    fn les_blocs_cosmetiques_ne_degradent_pas_la_fidelite() {
        // Deux interfaces pour un modèle minimal viable, plus des blocs
        // purement cosmétiques.
        let out = super::super::FortigateAdapter
            .import_str(
                "config system global\n    set hostname fw-t\n    \
                 set admin-sport 4443\n    set gui-theme blue\nend\n\
                 config system replacemsg http url-block\n    set buffer \"<html>…</html>\"\nend\n\
                 config log memory setting\n    set status enable\nend\n\
                 config antivirus profile\n    edit \"default\"\n    next\nend\n",
                "t.conf",
            )
            .expect("modèle");
        assert_eq!(out.fidelity, Fidelity::Complete, "{:?}", out.fidelity);
        // Les blocs cosmétiques sont bien reconnus (notes Info).
        assert!(out.notes.iter().any(|n| n.message.contains("replacemsg")
            || n.message.contains("antivirus")
            || n.message.contains("log memory")));
    }

    /// À l'inverse, une clé qui CHANGE le périmètre d'une règle
    /// (restriction par identité, négation, internet-service) reste
    /// diagnostiquée : l'avaler en silence sur-approximerait la règle et
    /// pourrait produire un faux « autorisé » (§6.3).
    #[test]
    fn les_cles_qui_changent_le_perimetre_restent_signalees() {
        let out = import(
            "config firewall policy\n    edit 1\n        set srcintf \"lan\"\n        \
             set dstintf \"wan\"\n        set srcaddr \"all\"\n        \
             set dstaddr \"all\"\n        set action accept\n        \
             set groups \"employes\"\n        set dstaddr-negate enable\n    next\nend\n",
        );
        let Fidelity::Partial { unsupported } = &out.fidelity else {
            panic!("une restriction par identité/négation doit dégrader la fidélité");
        };
        assert!(unsupported.iter().any(|d| d.message.contains("groups")));
        assert!(unsupported
            .iter()
            .any(|d| d.message.contains("dstaddr-negate")));
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

    /// Une route par objet GROUPE se développe en une route par préfixe
    /// résolu ; la combinaison `dstaddr` + `blackhole` rejette chaque
    /// préfixe.
    #[test]
    fn route_par_objet_groupe_et_blackhole() {
        let out = import(
            "config firewall address\n    edit \"A\"\n        \
             set subnet 10.1.0.0 255.255.0.0\n    next\n    edit \"B\"\n        \
             set subnet 10.2.0.0 255.255.0.0\n    next\nend\n\
             config firewall addrgrp\n    edit \"G\"\n        \
             set member \"A\" \"B\"\n    next\nend\n\
             config router static\n    edit 1\n        \
             set dstaddr \"G\"\n        set blackhole enable\n    next\nend\n",
        );
        assert_eq!(out.fidelity, Fidelity::Complete);
        let routes = &out.device.vrfs[&VrfId::default_vrf()].routes;
        assert_eq!(routes.len(), 2);
        assert_eq!(routes[0].prefix, "10.1.0.0/16".parse().unwrap());
        assert_eq!(routes[0].next_hop, NextHop::Drop);
        assert_eq!(routes[1].prefix, "10.2.0.0/16".parse().unwrap());
        assert_eq!(routes[1].next_hop, NextHop::Drop);
    }

    /// Une route par objet irrésoluble (objet absent : fqdn, géographie…)
    /// ne produit AUCUNE route et dégrade la fidélité — jamais devinée.
    #[test]
    fn route_par_objet_irresoluble_diagnostiquee() {
        let out = import(
            "config router static\n    edit 1\n        \
             set dstaddr \"OBJET-FANTOME\"\n        set gateway 10.0.0.1\n    next\nend\n",
        );
        assert!(out
            .device
            .vrfs
            .get(&VrfId::default_vrf())
            .is_none_or(|v| v.routes.is_empty()));
        let Fidelity::Partial { unsupported } = &out.fidelity else {
            panic!("objet irrésoluble → fidélité dégradée");
        };
        assert!(unsupported
            .iter()
            .any(|d| d.message.contains("OBJET-FANTOME") && d.message.contains("irrésoluble")));
    }

    /// Une route `sdwan-zone` vers une zone inconnue (ou sans bloc
    /// `config system sdwan`) est diagnostiquée, jamais devinée.
    #[test]
    fn route_sdwan_zone_inconnue_diagnostiquee() {
        let out = import(
            "config system sdwan\n    set status enable\nend\n\
             config router static\n    edit 1\n        \
             set sdwan-zone \"ZONE-X\"\n    next\nend\n",
        );
        let Fidelity::Partial { unsupported } = &out.fidelity else {
            panic!("zone inconnue → fidélité dégradée");
        };
        assert!(unsupported
            .iter()
            .any(|d| d.message.contains("ZONE-X") && d.message.contains("inconnue")));
    }

    /// Une règle `config service` SD-WAN choisit QUEL WAN, pas SI le
    /// trafic passe : elle est RECONNUE (note Info) et ne dégrade PAS la
    /// fidélité — le verdict d'accessibilité est identique quel que soit le
    /// membre (les WAN sont évalués en ECMP).
    #[test]
    fn regle_sdwan_service_est_une_note_sans_degrader_la_fidelite() {
        let out = import(
            "config system sdwan\n    set status enable\n    config service\n        \
             edit 1\n            set priority-members 2 1\n        next\n    end\nend\n",
        );
        assert!(
            out.fidelity.is_complete(),
            "la sélection de membre est sans effet sur le verdict : {:?}",
            out.fidelity
        );
        assert!(
            out.notes
                .iter()
                .any(|d| d.severity == Severity::Info
                    && d.message.contains("règle SD-WAN 1 reconnue"))
        );
    }

    /// Un membre SD-WAN sans passerelle route sur son interface (comme
    /// une route statique `device` seule).
    #[test]
    fn membre_sdwan_sans_passerelle_route_sur_l_interface() {
        let out = import(
            "config system interface\n    edit \"wan1\"\n        \
             set ip 192.0.2.1 255.255.255.252\n    next\nend\n\
             config system sdwan\n    set status enable\n    config members\n        \
             edit 1\n            set interface \"wan1\"\n        next\n    end\nend\n\
             config router static\n    edit 1\n        \
             set sdwan-zone \"virtual-wan-link\"\n    next\nend\n",
        );
        assert_eq!(out.fidelity, Fidelity::Complete);
        let routes = &out.device.vrfs[&VrfId::default_vrf()].routes;
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].next_hop, NextHop::Interface(IfaceId::new("wan1")));
    }

    /// Un VIP à plage de ports IDENTITAIRE (extport == mappedport) est un
    /// DNAT d'adresse seule : le port est préservé — exact.
    #[test]
    fn vip_plage_de_ports_identitaire_dnat_adresse_seule() {
        let out = import(
            "config firewall vip\n    edit \"V\"\n        set extip 192.0.2.10\n        \
             set portforward enable\n        set mappedip \"10.0.0.10\"\n        \
             set extport 8000-8010\n        set mappedport 8000-8010\n    next\nend\n\
             config firewall policy\n    edit 1\n        set dstaddr \"V\"\n        \
             set action accept\n        set service \"ALL\"\n    next\nend\n",
        );
        assert_eq!(out.fidelity, Fidelity::Complete);
        let policy = &out.device.policies[&PolicyId::new(FORWARD_POLICY)];
        let r = &policy.rules[0];
        assert_eq!(r.id.as_str(), "1");
        assert_eq!(
            r.matches.services,
            vec![calque_model::ServiceExpr::Service(Service::tcp_dport(
                calque_model::PortRange {
                    start: 8000,
                    end: 8010
                }
            ))]
        );
        assert_eq!(
            r.action,
            Action::Nat(NatAction {
                snat: None,
                dnat: Some(DnatTarget {
                    addr: "10.0.0.10".parse().unwrap(),
                    port: None,
                }),
            })
        );
    }

    /// Un VIP à plage de ports réellement DÉCALÉE n'est pas représentable
    /// (`DnatTarget` porte un port unique) : diagnostic, le VIP n'existe
    /// pas et la règle qui le référence devient irrésoluble — jamais
    /// approximée.
    #[test]
    fn vip_plage_de_ports_decalee_jamais_approximee() {
        let out = import(
            "config firewall vip\n    edit \"V\"\n        set extip 192.0.2.10\n        \
             set portforward enable\n        set mappedip \"10.0.0.10\"\n        \
             set extport 8000-8010\n        set mappedport 9000-9010\n    next\nend\n\
             config firewall policy\n    edit 1\n        set dstaddr \"V\"\n        \
             set action accept\n    next\nend\n",
        );
        assert!(!out
            .device
            .objects
            .addresses
            .contains_key(&ObjectId::new("V")));
        let Fidelity::Partial { unsupported } = &out.fidelity else {
            panic!("plage décalée → fidélité dégradée");
        };
        assert!(unsupported
            .iter()
            .any(|d| d.message.contains("plage de ports décalée")));
        assert!(
            unsupported
                .iter()
                .any(|d| d.message.contains("`V` introuvable")),
            "la règle qui référence le VIP écarté est irrésoluble : {unsupported:?}"
        );
    }

    /// Une plage d'adresses externes (`set extip a-b`) exigerait une
    /// cible DNAT par adresse : non représentable, diagnostiquée.
    #[test]
    fn vip_plage_d_adresses_externes_jamais_approximee() {
        let out = import(
            "config firewall vip\n    edit \"V\"\n        \
             set extip 192.0.2.10-192.0.2.12\n        \
             set mappedip \"10.0.0.10-10.0.0.12\"\n    next\nend\n",
        );
        let Fidelity::Partial { unsupported } = &out.fidelity else {
            panic!("plage d'adresses externes → fidélité dégradée");
        };
        assert!(unsupported
            .iter()
            .any(|d| d.message.contains("plage d'adresses externes")));
    }

    /// Un service EXPLICITE combiné à la restriction de port d'un VIP ne
    /// s'intersecte pas dans le modèle : le service de la règle est
    /// conservé et la restriction du VIP est diagnostiquée — jamais une
    /// approximation silencieuse.
    #[test]
    fn vip_et_service_explicite_diagnostiques() {
        let out = import(
            "config firewall service custom\n    edit \"TCP-9\"\n        \
             set tcp-portrange 9\n    next\nend\n\
             config firewall vip\n    edit \"V\"\n        set extip 192.0.2.10\n        \
             set portforward enable\n        set mappedip \"10.0.0.10\"\n        \
             set extport 443\n        set mappedport 443\n    next\nend\n\
             config firewall policy\n    edit 1\n        set dstaddr \"V\"\n        \
             set action accept\n        set service \"TCP-9\"\n    next\nend\n",
        );
        let policy = &out.device.policies[&PolicyId::new(FORWARD_POLICY)];
        let r = &policy.rules[0];
        // Le service de la règle est conservé tel quel…
        assert_eq!(
            r.matches.services,
            vec![calque_model::ServiceExpr::Object(ObjectId::new("TCP-9"))]
        );
        // …et l'impossibilité d'intersecter est diagnostiquée.
        let Fidelity::Partial { unsupported } = &out.fidelity else {
            panic!("intersection non représentable → fidélité dégradée");
        };
        assert!(unsupported
            .iter()
            .any(|d| d.message.contains("intersection non représentable")));
    }

    /// Deux VIP sur la MÊME adresse externe, ports différents (80 et 443),
    /// dans une règle au service explicite [HTTP, HTTPS] : le découpage
    /// applique `service ∩ port_du_VIP` à chaque moitié, si bien qu'elles
    /// ne se masquent PAS (sinon `dead-rules` déclarerait la seconde morte
    /// à tort). Reproduit le cas réel HDVAIRS.
    #[test]
    fn vip_multiple_meme_extip_ports_disjoints_intersecte_le_service() {
        let out = import(
            "config firewall service custom\n    edit \"HTTP\"\n        \
             set tcp-portrange 80\n    next\n    edit \"HTTPS\"\n        \
             set tcp-portrange 443\n    next\nend\n\
             config firewall vip\n    edit \"V80\"\n        set extip 192.0.2.10\n        \
             set portforward enable\n        set mappedip \"10.0.0.10\"\n        \
             set extport 80\n        set mappedport 80\n    next\n    edit \"V443\"\n        \
             set extip 192.0.2.10\n        set portforward enable\n        \
             set mappedip \"10.0.0.10\"\n        set extport 443\n        \
             set mappedport 443\n    next\nend\n\
             config firewall policy\n    edit 1\n        set dstaddr \"V80\" \"V443\"\n        \
             set action accept\n        set service \"HTTP\" \"HTTPS\"\n    next\nend\n",
        );
        assert_eq!(out.fidelity, Fidelity::Complete, "{:?}", out.fidelity);
        let policy = &out.device.policies[&PolicyId::new(FORWARD_POLICY)];
        // Deux règles éclatées, chacune contrainte à SON port.
        let r80 = policy
            .rules
            .iter()
            .find(|r| r.id.as_str() == "1:V80")
            .expect("règle V80");
        assert_eq!(
            r80.matches.services,
            vec![ServiceExpr::Service(Service::tcp_dport(PortRange::single(
                80
            )))]
        );
        let r443 = policy
            .rules
            .iter()
            .find(|r| r.id.as_str() == "1:V443")
            .expect("règle V443");
        assert_eq!(
            r443.matches.services,
            vec![ServiceExpr::Service(Service::tcp_dport(PortRange::single(
                443
            )))]
        );
    }

    /// Un REFUS vers un VIP ne traduit rien (le DNAT n'est porté que par
    /// les règles qui acceptent) : la destination se résout sur l'adresse
    /// externe, l'action reste Deny.
    #[test]
    fn refus_vers_un_vip_sans_dnat() {
        let out = import(
            "config firewall vip\n    edit \"V\"\n        set extip 192.0.2.10\n        \
             set mappedip \"10.0.0.10\"\n    next\nend\n\
             config firewall policy\n    edit 1\n        set dstaddr \"V\"\n        \
             set action deny\n    next\nend\n",
        );
        assert_eq!(out.fidelity, Fidelity::Complete);
        let policy = &out.device.policies[&PolicyId::new(FORWARD_POLICY)];
        let r = &policy.rules[0];
        assert_eq!(r.action, Action::Deny);
        assert_eq!(r.matches.dst, vec![AddrExpr::Object(ObjectId::new("V"))]);
    }

    /// `set nat enable` + VIP : la règle porte le DNAT du VIP fusionné
    /// avec la part de SNAT (cible résolue tardivement, convention de
    /// l'adaptateur).
    #[test]
    fn nat_enable_et_vip_fusionnes() {
        let out = import(
            "config firewall vip\n    edit \"V\"\n        set extip 192.0.2.10\n        \
             set mappedip \"10.0.0.10\"\n    next\nend\n\
             config firewall policy\n    edit 1\n        set dstaddr \"V\"\n        \
             set action accept\n        set nat enable\n    next\nend\n",
        );
        assert_eq!(out.fidelity, Fidelity::Complete);
        let policy = &out.device.policies[&PolicyId::new(FORWARD_POLICY)];
        assert_eq!(
            policy.rules[0].action,
            Action::Nat(NatAction {
                snat: None,
                dnat: Some(DnatTarget {
                    addr: "10.0.0.10".parse().unwrap(),
                    port: None,
                }),
            })
        );
    }

    /// La valeur d'un `psksecret` ne sort JAMAIS dans un diagnostic, même
    /// quand le tunnel porte par ailleurs une directive inconnue.
    #[test]
    fn psksecret_jamais_dans_les_diagnostics() {
        let out = import(
            "config vpn ipsec phase1-interface\n    edit \"t1\"\n        \
             set interface \"wan\"\n        set remote-gw 192.0.2.99\n        \
             set psksecret ENC ULTRASECRET==\n        \
             set gadget-exotique enable\n    next\nend\n",
        );
        let msgs = all_messages(&out);
        assert!(
            msgs.iter().any(|m| m.contains("gadget-exotique")),
            "{msgs:?}"
        );
        assert!(msgs.iter().all(|m| !m.contains("ULTRASECRET")), "{msgs:?}");
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
