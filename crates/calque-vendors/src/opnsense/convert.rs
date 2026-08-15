//! Conversion arbre générique (config.xml) → représentation intermédiaire
//! pour OPNsense/pfSense. Voir l'en-tête de `mod.rs` pour les choix de
//! modélisation.
//!
//! Discipline §6.3, appliquée partout dans ce module :
//! - un élément COMPRIS et porteur de sens → mappé vers le modèle ;
//! - un élément COMPRIS et sans effet sur le filtrage/routage du trafic
//!   transitant → accepté explicitement, liste par liste ;
//! - un élément qui TOUCHE le trafic mais n'est pas modélisé (ipsec,
//!   openvpn, shaper, carp…) → `Diagnostic` Warning, fidélité dégradée ;
//! - tout le reste → `Diagnostic` avec span. Jamais d'ignorance
//!   silencieuse.
//!
//! Règle de sûreté (§11.4) : un config.xml porte des secrets (mots de
//! passe hachés, communautés SNMP, clés privées des certificats). La
//! VALEUR d'un élément non compris ne va JAMAIS dans un diagnostic —
//! seul son NOM y figure, le `SourceSpan` suffit à retrouver la ligne.

use std::net::IpAddr;

use calque_model::{
    Action, AddrExpr, AddrObject, AdminState, Device, DeviceId, Diagnostic, DnatTarget, Fidelity,
    IfaceId, Interface, NatAction, NextHop, ObjectId, Policy, PolicyId, PortRange, ProtoMatch,
    Route, RouteOrigin, Rule, RuleId, RuleMatch, Service, ServiceExpr, ServiceObject, Severity,
    SourceSpan, Vendor, VrfId, ZoneId,
};
use std::collections::BTreeMap;

use super::values;
use crate::{AdapterOutput, ConfigNode, ConfigTree};

/// Identifiant de la politique de filtrage (règles `<filter>`).
const FILTER_POLICY: &str = "filter";
/// Identifiant de la politique de redirections de ports (`<nat>`).
const DNAT_POLICY: &str = "dnat";

/// Sections de premier niveau SANS effet sur le filtrage ou le routage du
/// trafic transitant : services locaux (DHCP, DNS, NTP, SNMP…), matériel
/// de confiance et cosmétique. Les accepter n'est pas deviner.
const ROOT_IGNORABLE: &[&str] = &[
    "version",
    "trigger_initial_wizard",
    "theme",
    "revision",
    "lastchange",
    "dhcpd",
    "dhcpdv6",
    "dhcrelay",
    "dhcrelay6",
    "unbound",
    "dnsmasq",
    "snmpd",
    "ntpd",
    "syslog",
    "rrd",
    "widgets",
    "notifications",
    "cert",
    "ca",
    "crl",
    "hasync",
    "ssh",
    "wizardtemp",
];

/// Sections de premier niveau qui TOUCHENT le trafic mais ne sont pas
/// modélisées : tunnels, encapsulations, façonnage, haute disponibilité,
/// interfaces virtuelles. Une occurrence NON VIDE dégrade la fidélité —
/// un verdict qui ignorerait un tunnel IPsec serait faux.
const ROOT_TRAFFIC_UNSUPPORTED: &[&str] = &[
    "ipsec",
    "openvpn",
    "wireguard",
    "sysctl",
    "captiveportal",
    "load_balancer",
    "shaper",
    "dnshaper",
    "installedpackages",
    "bridges",
    "vlans",
    "laggs",
    "gifs",
    "gres",
    "ppps",
    "ifgroups",
    "wireless",
    "proxyarp",
];

pub(super) fn convert(tree: &ConfigTree) -> Result<AdapterOutput, Vec<Diagnostic>> {
    let root = tree
        .roots
        .iter()
        .find(|n| n.keyword == "opnsense" || n.keyword == "pfsense")
        .ok_or_else(|| {
            vec![Diagnostic::error(
                "configuration inexploitable : aucune racine <opnsense> ni <pfsense>",
                Some(SourceSpan::new(tree.file.as_str(), 1)),
            )]
        })?;
    let mut conv = Converter::new(tree);
    for extra in tree.roots.iter().filter(|n| !std::ptr::eq(*n, root)) {
        conv.unsupported(
            format!(
                "élément racine supplémentaire `<{}>` non géré",
                extra.keyword
            ),
            &extra.span,
        );
    }
    conv.run(root);
    Ok(conv.finish())
}

/// Une passerelle nommée (`<gateway_item>`), résolue par les routes.
struct Gateway {
    ip: IpAddr,
    span: SourceSpan,
}

struct Converter {
    device: Device,
    /// Ce qui n'a PAS été compris → `Fidelity::Partial` (§6.3).
    unsupported: Vec<Diagnostic>,
    /// Constats informatifs qui ne dégradent pas la fidélité.
    notes: Vec<Diagnostic>,
    /// Clé d'interface (`lan`, `opt1`…) → zone du modèle (la `<descr>`
    /// fait office d'alias au nom logique).
    zone_of_iface: BTreeMap<String, ZoneId>,
    /// Passerelles nommées, pour `<staticroutes>` et `defaultgw`.
    gateways: BTreeMap<String, Gateway>,
}

impl Converter {
    fn new(tree: &ConfigTree) -> Self {
        // Identifiant provisoire tiré du nom de fichier ; remplacé par
        // `<system><hostname>` s'il est présent.
        let id = DeviceId::new(file_stem(&tree.file));
        Self {
            device: Device::new(id, Vendor::Opnsense),
            unsupported: Vec::new(),
            notes: Vec::new(),
            zone_of_iface: BTreeMap::new(),
            gateways: BTreeMap::new(),
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

    // -- parcours -------------------------------------------------------

    /// Passes ordonnées, quel que soit l'ordre des sections du fichier :
    /// interfaces → aliases → passerelles → routes → VIP → NAT → filtre.
    /// Le filtre et le NAT ont besoin des interfaces (zones, réseaux) et
    /// des aliases ; les routes ont besoin des passerelles nommées.
    fn run(&mut self, root: &ConfigNode) {
        if root.keyword == "pfsense" {
            self.note_info(
                "racine <pfsense> : format cousin d'OPNsense, converti par le même \
                 adaptateur ; les divergences sont diagnostiquées au cas par cas"
                    .to_owned(),
                &root.span,
            );
        }

        let mut filters: Vec<&ConfigNode> = Vec::new();
        let mut nats: Vec<&ConfigNode> = Vec::new();
        let mut gateways: Vec<&ConfigNode> = Vec::new();
        let mut staticroutes: Vec<&ConfigNode> = Vec::new();
        let mut virtualips: Vec<&ConfigNode> = Vec::new();
        let mut legacy_aliases: Vec<&ConfigNode> = Vec::new();
        let mut opnsense_ns: Vec<&ConfigNode> = Vec::new();

        for child in &root.children {
            match child.keyword.as_str() {
                "system" => self.system_block(child),
                "interfaces" => self.interfaces_block(child),
                "filter" => filters.push(child),
                "nat" => nats.push(child),
                "gateways" => gateways.push(child),
                "staticroutes" => staticroutes.push(child),
                "virtualip" => virtualips.push(child),
                "aliases" => legacy_aliases.push(child),
                "OPNsense" => opnsense_ns.push(child),
                k if ROOT_IGNORABLE.contains(&k) => {}
                k if ROOT_TRAFFIC_UNSUPPORTED.contains(&k) => {
                    // Vide (`<vlans/>`) : rien à modéliser. Non vide : du
                    // trafic passe par là sans être modélisé.
                    if !is_empty_node(child) {
                        self.unsupported(
                            format!(
                                "section `<{k}>` non modélisée : elle touche le trafic \
                                 (tunnel, encapsulation, façonnage ou haute disponibilité)"
                            ),
                            &child.span,
                        );
                    }
                }
                k => {
                    if !is_empty_node(child) {
                        // Nom seul, jamais la valeur (§11.4).
                        self.unsupported(format!("section `<{k}>` non gérée"), &child.span);
                    }
                }
            }
        }

        for node in opnsense_ns {
            self.opnsense_ns_block(node);
        }
        for node in legacy_aliases {
            self.legacy_aliases_block(node);
        }
        for node in gateways {
            self.gateways_block(node);
        }
        for node in staticroutes {
            self.staticroutes_block(node);
        }
        for node in virtualips {
            self.virtualip_block(node);
        }
        // NAT avant filtre : les redirections de ports sont évaluées
        // AVANT les règles de filtrage (rdr de pf), et le filtre voit la
        // destination déjà traduite — l'ordre du pipeline le matérialise.
        for node in nats {
            self.nat_block(node);
        }
        for node in &filters {
            self.filter_block(node);
        }
        // pf refuse par défaut tout ce qu'aucune règle n'autorise : la
        // politique de filtrage existe même si `<filter>` est vide ou
        // absent (default deny documenté du produit).
        self.ensure_filter_policy();
    }

    // -- <system> --------------------------------------------------------

    /// `<system>` : uniquement de l'administration LOCALE (comptes,
    /// interface web, DNS du boîtier, fuseau…) — reconnu comme sans effet
    /// sur le trafic transitant, à l'exception du `hostname` qui nomme
    /// l'équipement. Rien de son contenu (mots de passe hachés, clés SSH)
    /// n'est recopié dans un diagnostic.
    fn system_block(&mut self, block: &ConfigNode) {
        if let Some(h) = block.child("hostname") {
            let name = h.args_joined();
            if !name.is_empty() {
                self.device.id = DeviceId::new(name);
            }
        }
    }

    // -- <interfaces> ----------------------------------------------------

    fn interfaces_block(&mut self, block: &ConfigNode) {
        for entry in &block.children {
            let key = entry.keyword.clone();
            let mut iface = Interface::new(IfaceId::new(key.as_str()));
            let mut descr: Option<String> = None;
            let mut enabled = false;
            let mut ipaddr: Option<(String, SourceSpan)> = None;
            let mut subnet: Option<String> = None;
            let mut ipaddrv6: Option<(String, SourceSpan)> = None;
            let mut subnetv6: Option<String> = None;

            for d in &entry.children {
                match d.keyword.as_str() {
                    "descr" => {
                        let v = d.args_joined();
                        if !v.is_empty() {
                            descr = Some(v);
                        }
                    }
                    "enable" => enabled = d.arg(0) != Some("0"),
                    "ipaddr" => ipaddr = Some((d.args_joined(), d.span.clone())),
                    "subnet" => subnet = Some(d.args_joined()),
                    "ipaddrv6" => ipaddrv6 = Some((d.args_joined(), d.span.clone())),
                    "subnetv6" => subnetv6 = Some(d.args_joined()),
                    // Le périphérique de l'OS (`vtnet0`…) : l'identité du
                    // modèle est la clé logique, référencée par les règles.
                    "if" => {}
                    // La route par défaut vient de `<gateways>` ; ici ce
                    // n'est qu'un rattachement nominal.
                    "gateway" | "gatewayv6" => {}
                    // Cosmétique reconnu, sans effet sur l'accessibilité.
                    "spoofmac" | "mtu" | "media" | "mediaopt" => {}
                    "blockpriv" | "blockbogons" => {
                        // Ces cases ajoutent des règles de blocage
                        // IMPLICITES (RFC1918, bogons) non modélisées.
                        if d.arg(0) != Some("0") {
                            self.unsupported(
                                format!(
                                    "`<{}>` sur l'interface `{key}` : règles de blocage \
                                     implicites non modélisées",
                                    d.keyword
                                ),
                                &d.span,
                            );
                        }
                    }
                    k => self.unsupported(
                        format!("élément `<{k}>` non géré dans l'interface `{key}`"),
                        &d.span,
                    ),
                }
            }

            match ipaddr {
                Some((v, span)) if v == "dhcp" || v == "pppoe" || v == "pptp" || v == "l2tp" => {
                    self.unsupported(
                        format!(
                            "interface `{key}` en mode `{v}` : adresse non modélisable \
                             hors ligne"
                        ),
                        &span,
                    );
                }
                Some((v, span)) => match values::iface_addr(&v, subnet.as_deref()) {
                    Some(net) => iface.addrs.push(net),
                    None => self.unsupported(
                        format!("adresse invalide `{v}` sur l'interface `{key}`"),
                        &span,
                    ),
                },
                None => {}
            }
            match ipaddrv6 {
                Some((v, span)) if v == "dhcp6" || v == "track6" || v == "slaac" || v == "6rd" => {
                    self.unsupported(
                        format!(
                            "interface `{key}` en mode IPv6 `{v}` : adresse non \
                             modélisable hors ligne"
                        ),
                        &span,
                    );
                }
                Some((v, span)) => match values::iface_addr(&v, subnetv6.as_deref()) {
                    Some(net) => iface.addrs.push(net),
                    None => self.unsupported(
                        format!("adresse IPv6 invalide `{v}` sur l'interface `{key}`"),
                        &span,
                    ),
                },
                None => {}
            }

            if !enabled {
                // Ne pas modéliser ce qui est éteint (§3.2) : l'interface
                // reste visible mais inactive — un constat, pas une
                // incompréhension.
                iface.state = AdminState::Down;
                self.note_info(
                    format!("interface `{key}` désactivée (pas de `<enable>`)"),
                    &entry.span,
                );
            }

            // La zone : la `<descr>` fait office d'alias au nom logique,
            // sinon la clé elle-même (`lan`, `opt1`…).
            let zone_name = descr.unwrap_or_else(|| key.clone());
            let zone_id = ZoneId::new(zone_name.as_str());
            let zone_id = if self.device.zones.contains_key(&zone_id) {
                self.unsupported(
                    format!(
                        "descr `{zone_name}` de l'interface `{key}` en collision avec \
                         une zone existante : repli sur la clé `{key}`"
                    ),
                    &entry.span,
                );
                ZoneId::new(key.as_str())
            } else {
                zone_id
            };
            iface.zone = Some(zone_id.clone());
            self.device
                .zones
                .insert(zone_id.clone(), vec![iface.id.clone()]);
            self.zone_of_iface.insert(key.clone(), zone_id);

            if self.device.interfaces.contains_key(&iface.id) {
                self.unsupported(
                    format!(
                        "interface `{key}` redéfinie : la nouvelle définition remplace \
                         la première"
                    ),
                    &entry.span,
                );
            }
            self.device.interfaces.insert(iface.id.clone(), iface);
        }
    }

    // -- aliases (emplacement moderne : <OPNsense><Firewall><Alias>) -----

    fn opnsense_ns_block(&mut self, block: &ConfigNode) {
        for child in &block.children {
            match child.keyword.as_str() {
                "Firewall" => {
                    for sub in &child.children {
                        match sub.keyword.as_str() {
                            "Alias" => {
                                for aliases in sub.children_named("aliases") {
                                    self.alias_entries(aliases, AliasFormat::Modern);
                                }
                            }
                            // Étiquettes de catégories : purement cosmétique.
                            "Category" => {}
                            "Filter" if !is_empty_node(sub) => self.unsupported(
                                "règles d'automatisation `<Firewall><Filter>` non \
                                 modélisées : elles filtrent le trafic"
                                    .to_owned(),
                                &sub.span,
                            ),
                            "Filter" => {}
                            k => {
                                if !is_empty_node(sub) {
                                    self.unsupported(
                                        format!("section `<Firewall><{k}>` non gérée"),
                                        &sub.span,
                                    );
                                }
                            }
                        }
                    }
                }
                k => {
                    if !is_empty_node(child) {
                        self.unsupported(
                            format!("section `<OPNsense><{k}>` non gérée"),
                            &child.span,
                        );
                    }
                }
            }
        }
    }

    // -- aliases (ancien emplacement : <aliases> à la racine) ------------

    fn legacy_aliases_block(&mut self, block: &ConfigNode) {
        self.alias_entries(block, AliasFormat::Legacy);
    }

    /// Les entrées `<alias>` des deux emplacements. Le format moderne
    /// écrit le contenu dans `<content>` (séparé par des sauts de ligne),
    /// l'ancien dans `<address>` (séparé par des espaces) — la couche 1
    /// a déjà découpé les deux en jetons.
    fn alias_entries(&mut self, block: &ConfigNode, format: AliasFormat) {
        for alias in &block.children {
            if alias.keyword != "alias" {
                self.unsupported(
                    format!("élément `<{}>` non géré parmi les aliases", alias.keyword),
                    &alias.span,
                );
                continue;
            }
            self.alias_entry(alias, format);
        }
    }

    fn alias_entry(&mut self, alias: &ConfigNode, format: AliasFormat) {
        let span = alias.span.clone();
        let mut name: Option<String> = None;
        let mut kind: Option<String> = None;
        let mut entries: Vec<String> = Vec::new();
        let mut disabled = false;
        let mut broken = false;

        for d in &alias.children {
            match d.keyword.as_str() {
                "name" => name = Some(d.args_joined()),
                "type" => kind = Some(d.args_joined()),
                "enabled" => disabled = d.arg(0) == Some("0"),
                "content" | "address" => entries.extend(d.args.iter().cloned()),
                // Champ `proto` du type geoip : vide = sans objet.
                "proto" if is_empty_node(d) => {}
                // Cosmétique et méta reconnus.
                "descr" | "detail" | "categories" | "counters" | "updatefreq" | "interface"
                | "current_items" | "last_updated" => {}
                k => {
                    self.unsupported(format!("élément `<{k}>` non géré dans un alias"), &d.span);
                    broken = true;
                }
            }
        }

        let Some(name) = name.filter(|n| !n.is_empty()) else {
            self.unsupported("alias sans `<name>`".to_owned(), &span);
            return;
        };
        if disabled {
            self.note_info(format!("alias `{name}` désactivé : ignoré"), &span);
            return;
        }

        match kind.as_deref() {
            Some("host") | Some("network") => {
                let strict_host = kind.as_deref() == Some("host");
                let mut nets = Vec::new();
                for e in &entries {
                    let parsed = if strict_host {
                        values::parse_host(e)
                    } else {
                        values::parse_net(e)
                    };
                    match parsed {
                        Some(net) => nets.push(net),
                        None => {
                            // Nom d'hôte à résoudre, alias imbriqué… :
                            // irrésoluble hors ligne, on ne devine pas.
                            self.unsupported(
                                format!(
                                    "entrée `{e}` de l'alias `{name}` irrésoluble \
                                     (ni adresse ni réseau)"
                                ),
                                &span,
                            );
                            broken = true;
                        }
                    }
                }
                if broken {
                    return; // diagnostiqué ; un alias à moitié compris ne rentre pas.
                }
                if nets.is_empty() {
                    self.unsupported(format!("alias `{name}` sans aucune entrée"), &span);
                    return;
                }
                let oid = ObjectId::new(name.as_str());
                if self.device.objects.addresses.contains_key(&oid) {
                    self.unsupported(
                        format!(
                            "alias `{name}` redéfini : la nouvelle définition remplace \
                             la première"
                        ),
                        &span,
                    );
                }
                self.device
                    .objects
                    .addresses
                    .insert(oid, AddrObject::Nets(nets));
            }
            Some("port") => {
                let mut services = Vec::new();
                for e in &entries {
                    match values::parse_port_spec(e) {
                        // Un alias de ports ne fixe PAS le protocole :
                        // il vaut pour celui que la règle précisera.
                        Some(range) => services.push(Service {
                            proto: ProtoMatch::Any,
                            sport: PortRange::ANY,
                            dport: range,
                        }),
                        None => {
                            self.unsupported(
                                format!("port `{e}` invalide dans l'alias `{name}`"),
                                &span,
                            );
                            broken = true;
                        }
                    }
                }
                if broken {
                    return;
                }
                if services.is_empty() {
                    self.unsupported(format!("alias `{name}` sans aucune entrée"), &span);
                    return;
                }
                let oid = ObjectId::new(name.as_str());
                if self.device.objects.services.contains_key(&oid) {
                    self.unsupported(
                        format!(
                            "alias de ports `{name}` redéfini : la nouvelle définition \
                             remplace la première"
                        ),
                        &span,
                    );
                }
                self.device
                    .objects
                    .services
                    .insert(oid, ServiceObject::Services(services));
            }
            Some(other) => {
                // urltable, geoip, mac… : irrésolubles hors ligne.
                self.unsupported(format!("type d'alias `{other}` non géré (`{name}`)"), &span);
            }
            None => {
                let what = match format {
                    AliasFormat::Modern => "moderne",
                    AliasFormat::Legacy => "ancien",
                };
                self.unsupported(
                    format!("alias `{name}` (format {what}) sans `<type>`"),
                    &span,
                );
            }
        }
    }

    // -- <gateways> ------------------------------------------------------

    fn gateways_block(&mut self, block: &ConfigNode) {
        let mut default_v4: Option<(String, SourceSpan)> = None;
        for item in &block.children {
            match item.keyword.as_str() {
                "gateway_item" => self.gateway_item(item, &mut default_v4),
                // Sélection moderne de la passerelle par défaut.
                "defaultgw4" => {
                    let v = item.args_joined();
                    if !v.is_empty() {
                        default_v4 = Some((v, item.span.clone()));
                    }
                }
                "defaultgw6" => {
                    if !is_empty_node(item) {
                        self.unsupported(
                            "passerelle par défaut IPv6 (`<defaultgw6>`) non gérée".to_owned(),
                            &item.span,
                        );
                    }
                }
                "gateway_group" => self.unsupported(
                    "groupe de passerelles (multi-WAN) non modélisé : la bascule \
                     change le routage"
                        .to_owned(),
                    &item.span,
                ),
                k => {
                    if !is_empty_node(item) {
                        self.unsupported(
                            format!("élément `<{k}>` non géré dans `<gateways>`"),
                            &item.span,
                        );
                    }
                }
            }
        }
        if let Some((name, span)) = default_v4 {
            match self.gateways.get(&name) {
                Some(gw) => {
                    let (ip, gw_span) = (gw.ip, gw.span.clone());
                    self.push_route(default_net(), NextHop::Ip(ip), &gw_span);
                }
                None => self.unsupported(
                    format!("`<defaultgw4>` référence la passerelle inconnue `{name}`"),
                    &span,
                ),
            }
        }
    }

    fn gateway_item(&mut self, item: &ConfigNode, default_v4: &mut Option<(String, SourceSpan)>) {
        let span = item.span.clone();
        let mut name: Option<String> = None;
        let mut ip: Option<IpAddr> = None;
        let mut is_default = false;
        let mut disabled = false;
        let mut broken = false;

        for d in &item.children {
            match d.keyword.as_str() {
                "name" => name = Some(d.args_joined()),
                "gateway" => match d.args_joined().as_str() {
                    "dynamic" => {
                        self.unsupported(
                            "passerelle `dynamic` : adresse apprise en ligne, non \
                             modélisable hors ligne"
                                .to_owned(),
                            &d.span,
                        );
                        broken = true;
                    }
                    v => match v.parse() {
                        Ok(addr) => ip = Some(addr),
                        Err(_) => {
                            self.unsupported(
                                format!("adresse de passerelle invalide `{v}`"),
                                &d.span,
                            );
                            broken = true;
                        }
                    },
                },
                "defaultgw" => is_default = d.arg(0) != Some("0"),
                "disabled" => disabled = d.arg(0) != Some("0"),
                "ipprotocol" => match d.arg(0) {
                    None | Some("inet") => {}
                    Some(other) => {
                        self.unsupported(
                            format!("passerelle `{other}` : seul `inet` est géré"),
                            &d.span,
                        );
                        broken = true;
                    }
                },
                // Rattachement nominal et supervision : sans effet sur la
                // table de routage déclarée.
                "interface" | "descr" | "weight" | "priority" | "monitor" | "monitor_disable"
                | "interval" | "fargw" => {}
                k => self.unsupported(
                    format!("élément `<{k}>` non géré dans une passerelle"),
                    &d.span,
                ),
            }
        }

        let Some(name) = name.filter(|n| !n.is_empty()) else {
            self.unsupported("passerelle sans `<name>`".to_owned(), &span);
            return;
        };
        if disabled {
            self.note_info(format!("passerelle `{name}` désactivée : ignorée"), &span);
            return;
        }
        if broken {
            return;
        }
        let Some(ip) = ip else {
            self.unsupported(format!("passerelle `{name}` sans adresse"), &span);
            return;
        };
        if self.gateways.contains_key(&name) {
            self.unsupported(
                format!("passerelle `{name}` redéfinie : la nouvelle remplace la première"),
                &span,
            );
        }
        self.gateways.insert(
            name.clone(),
            Gateway {
                ip,
                span: span.clone(),
            },
        );
        if is_default {
            // L'ancienne forme (`<defaultgw>1</defaultgw>` sur l'item).
            *default_v4 = Some((name, span));
        }
    }

    // -- <staticroutes> --------------------------------------------------

    fn staticroutes_block(&mut self, block: &ConfigNode) {
        for route in &block.children {
            if route.keyword != "route" {
                self.unsupported(
                    format!(
                        "élément `<{}>` non géré dans `<staticroutes>`",
                        route.keyword
                    ),
                    &route.span,
                );
                continue;
            }
            let span = route.span.clone();
            let mut network: Option<ipnet::IpNet> = None;
            let mut gateway: Option<String> = None;
            let mut disabled = false;
            let mut broken = false;

            for d in &route.children {
                match d.keyword.as_str() {
                    "network" => {
                        let v = d.args_joined();
                        match values::parse_net(&v) {
                            Some(net) => network = Some(net),
                            None => {
                                self.unsupported(
                                    format!("destination de route invalide `{v}`"),
                                    &d.span,
                                );
                                broken = true;
                            }
                        }
                    }
                    "gateway" => gateway = Some(d.args_joined()),
                    "disabled" => disabled = d.arg(0) != Some("0"),
                    "descr" => {}
                    k => self.unsupported(
                        format!("élément `<{k}>` non géré dans une route statique"),
                        &d.span,
                    ),
                }
            }

            if disabled {
                self.note_info("route statique désactivée : ignorée".to_owned(), &span);
                continue;
            }
            if broken {
                continue; // déjà diagnostiqué, on ne devine pas une route.
            }
            let Some(prefix) = network else {
                self.unsupported("route statique sans `<network>`".to_owned(), &span);
                continue;
            };
            let Some(gw_name) = gateway.filter(|g| !g.is_empty()) else {
                self.unsupported("route statique sans `<gateway>`".to_owned(), &span);
                continue;
            };
            // Le champ référence une passerelle NOMMÉE ; une adresse IP
            // littérale est aussi acceptée (formes rencontrées).
            let next_hop = match self.gateways.get(&gw_name) {
                Some(gw) => NextHop::Ip(gw.ip),
                None => match gw_name.parse::<IpAddr>() {
                    Ok(ip) => NextHop::Ip(ip),
                    Err(_) => {
                        self.unsupported(
                            format!("route statique vers la passerelle inconnue `{gw_name}`"),
                            &span,
                        );
                        continue;
                    }
                },
            };
            self.push_route(prefix, next_hop, &span);
        }
    }

    fn push_route(&mut self, prefix: ipnet::IpNet, next_hop: NextHop, span: &SourceSpan) {
        self.device
            .vrfs
            .entry(VrfId::default_vrf())
            .or_default()
            .routes
            .push(Route {
                prefix,
                next_hop,
                // OPNsense n'expose pas de distance sur ses routes
                // statiques : métrique uniforme.
                metric: 1,
                origin: RouteOrigin::Static,
                source: Some(span.clone()),
            });
    }

    // -- <virtualip> -----------------------------------------------------

    fn virtualip_block(&mut self, block: &ConfigNode) {
        for vip in &block.children {
            if vip.keyword != "vip" {
                self.unsupported(
                    format!("élément `<{}>` non géré dans `<virtualip>`", vip.keyword),
                    &vip.span,
                );
                continue;
            }
            // CARP, alias d'IP, proxy ARP : autant d'adresses portées par
            // l'équipement que le modèle ne connaît pas — un verdict qui
            // les ignorerait serait faux.
            let mode = vip
                .child("mode")
                .map(|m| m.args_joined())
                .filter(|m| matches!(m.as_str(), "carp" | "ipalias" | "proxyarp" | "other"))
                .unwrap_or_else(|| "?".to_owned());
            self.unsupported(
                format!("adresse IP virtuelle (mode `{mode}`) non modélisée"),
                &vip.span,
            );
        }
    }

    // -- <nat> -----------------------------------------------------------

    fn nat_block(&mut self, block: &ConfigNode) {
        let mut rules: Vec<Rule> = Vec::new();
        let mut index: u32 = 0;
        for child in &block.children {
            match child.keyword.as_str() {
                "rule" => {
                    index += 1;
                    if let Some(rule) = self.nat_rule(child, index) {
                        rules.push(rule);
                    }
                }
                "outbound" => self.nat_outbound(child),
                // Séparateurs visuels de l'interface web (pfSense).
                "separator" => {}
                k => {
                    if !is_empty_node(child) {
                        self.unsupported(
                            format!("élément `<{k}>` non géré dans `<nat>`"),
                            &child.span,
                        );
                    }
                }
            }
        }
        if rules.is_empty() {
            return;
        }
        let pid = PolicyId::new(DNAT_POLICY);
        let policy = self
            .device
            .policies
            .entry(pid.clone())
            .or_insert_with(|| Policy {
                id: pid.clone(),
                rules: Vec::new(),
                // Une redirection ne FILTRE pas : un paquet qui ne
                // correspond à aucune règle continue, non traduit, vers
                // la politique de filtrage.
                default_action: Action::Accept,
            });
        policy.rules.extend(rules);
        if !self.device.pipeline.ingress.contains(&pid) {
            self.device.pipeline.ingress.push(pid);
        }
    }

    fn nat_outbound(&mut self, node: &ConfigNode) {
        for d in &node.children {
            match (d.keyword.as_str(), d.args_joined().as_str()) {
                ("mode", "automatic") => self.note_info(
                    "NAT sortant `automatic` : traduction de source implicite vers \
                     l'adresse WAN, cible résolue à l'évaluation — les verdicts \
                     autorisé/refusé de CET équipement ne changent pas"
                        .to_owned(),
                    &d.span,
                ),
                ("mode", "disabled") => self.note_info(
                    "NAT sortant désactivé : aucune traduction de source".to_owned(),
                    &d.span,
                ),
                ("mode", mode @ ("hybrid" | "advanced")) => self.unsupported(
                    format!(
                        "NAT sortant `{mode}` : règles de traduction de source \
                         manuelles non modélisées"
                    ),
                    &d.span,
                ),
                ("rule", _) => self.unsupported(
                    "règle de NAT sortant manuelle non modélisée".to_owned(),
                    &d.span,
                ),
                (k, _) => self.unsupported(
                    format!("élément `<{k}>` non géré dans `<nat><outbound>`"),
                    &d.span,
                ),
            }
        }
    }

    /// Une redirection de port (`<nat><rule>`) → règle `Action::Nat` avec
    /// cible DNAT. La règle ne filtre pas (voir `default_action` de la
    /// politique) : elle traduit, et le filtre tranche ensuite sur la
    /// destination TRADUITE.
    fn nat_rule(&mut self, rule: &ConfigNode, index: u32) -> Option<Rule> {
        let span = rule.span.clone();
        let mut interface: Option<String> = None;
        let mut protocols: Option<Vec<u8>> = None;
        let mut src: Vec<AddrExpr> = Vec::new();
        let mut sport: Option<PortRange> = None;
        let mut dst: Vec<AddrExpr> = Vec::new();
        let mut dport: Option<PortRange> = None;
        let mut target: Option<IpAddr> = None;
        let mut local_port: Option<u16> = None;
        let mut descr: Option<String> = None;
        let mut disabled = false;
        let mut broken = false;

        for d in &rule.children {
            match d.keyword.as_str() {
                "interface" => interface = Some(d.args_joined()),
                "protocol" => {
                    let v = d.args_joined();
                    match values::proto_numbers(&v) {
                        Some(p) => protocols = Some(p),
                        None => {
                            self.unsupported(
                                format!("protocole `{v}` non géré (redirection {index})"),
                                &d.span,
                            );
                            broken = true;
                        }
                    }
                }
                "source" => {
                    let (exprs, port, ok) = self.endpoint_block(d, &format!("redirection {index}"));
                    src = exprs;
                    sport = port;
                    broken |= !ok;
                }
                "destination" => {
                    let (exprs, port, ok) = self.endpoint_block(d, &format!("redirection {index}"));
                    dst = exprs;
                    dport = port;
                    broken |= !ok;
                }
                "target" => {
                    let v = d.args_joined();
                    match v.parse() {
                        Ok(ip) => target = Some(ip),
                        Err(_) => {
                            // Un alias en cible dépendrait d'une résolution
                            // tardive que `DnatTarget` ne porte pas.
                            self.unsupported(
                                format!(
                                    "cible de redirection `{v}` non gérée (redirection {index})"
                                ),
                                &d.span,
                            );
                            broken = true;
                        }
                    }
                }
                "local-port" => {
                    let v = d.args_joined();
                    match v.parse::<u16>() {
                        Ok(p) => local_port = Some(p),
                        Err(_) => {
                            self.unsupported(
                                format!("`<local-port>` invalide (redirection {index})"),
                                &d.span,
                            );
                            broken = true;
                        }
                    }
                }
                "descr" => {
                    let v = d.args_joined();
                    if !v.is_empty() {
                        descr = Some(v);
                    }
                }
                "disabled" => disabled = d.arg(0) != Some("0"),
                "ipprotocol" => match d.arg(0) {
                    None | Some("inet") => {}
                    Some(other) => {
                        self.unsupported(
                            format!("`<ipprotocol>` `{other}` non géré (redirection {index})"),
                            &d.span,
                        );
                        broken = true;
                    }
                },
                "associated-rule-id" => {
                    // La règle de filtrage associée vit dans `<filter>` et
                    // est convertie là-bas — SAUF la forme `pass`, qui
                    // court-circuite le filtre.
                    if d.args_joined() == "pass" {
                        self.unsupported(
                            format!(
                                "redirection {index} en `associated-rule-id pass` : le \
                                 contournement du filtre n'est pas modélisé"
                            ),
                            &d.span,
                        );
                        broken = true;
                    }
                }
                // Cosmétique et méta reconnus.
                "created" | "updated" | "category" | "log" | "tag" | "tagged" => {}
                k => self.unsupported(
                    format!("élément `<{k}>` non géré dans la redirection {index}"),
                    &d.span,
                ),
            }
        }

        if disabled {
            self.note_info(
                format!("redirection de port {index} désactivée : ignorée"),
                &span,
            );
            return None;
        }
        if broken {
            return None;
        }
        let Some(target) = target else {
            self.unsupported(format!("redirection {index} sans `<target>`"), &span);
            return None;
        };
        // Une plage redirigée vers un port unique décale les ports chez
        // pf ; `DnatTarget` porte un port unique : on ne devine pas.
        if let (Some(range), Some(_)) = (dport, local_port) {
            if range.start != range.end {
                self.unsupported(
                    format!(
                        "redirection {index} d'une plage de ports : le décalage de \
                         plage n'est pas modélisé"
                    ),
                    &span,
                );
                return None;
            }
        }

        let from = interface.and_then(|i| self.zone_ref(&i, &span, "redirection"));
        let services = self.build_services(protocols, sport, dport, &span, index)?;

        Some(Rule {
            id: rule_id(index, descr.as_deref(), rule),
            matches: RuleMatch { src, dst, services },
            from,
            to: None,
            action: Action::Nat(NatAction {
                snat: None,
                dnat: Some(DnatTarget {
                    addr: target,
                    port: local_port,
                }),
            }),
            source: span,
            // OPNsense : aucune sur-approximation de correspondance connue
            // ici (pas d'équivalent identité/internet-service géré) → fidèle.
            approximation: None,
        })
    }

    // -- <filter> --------------------------------------------------------

    fn filter_block(&mut self, block: &ConfigNode) {
        let mut rules: Vec<Rule> = Vec::new();
        let mut index: u32 = 0;
        for child in &block.children {
            match child.keyword.as_str() {
                "rule" => {
                    index += 1;
                    if let Some(rule) = self.filter_rule(child, index) {
                        rules.push(rule);
                    }
                }
                // Séparateurs visuels de l'interface web (pfSense).
                "separator" => {}
                k => {
                    if !is_empty_node(child) {
                        self.unsupported(
                            format!("élément `<{k}>` non géré dans `<filter>`"),
                            &child.span,
                        );
                    }
                }
            }
        }
        let pid = PolicyId::new(FILTER_POLICY);
        // Plusieurs blocs `<filter>` (fichier concaténé, entrée hostile) :
        // les règles s'AJOUTENT dans l'ordre du fichier — écraser le
        // premier bloc effacerait ses refus.
        let policy = self
            .device
            .policies
            .entry(pid.clone())
            .or_insert_with(|| Policy {
                id: pid.clone(),
                rules: Vec::new(),
                // Le pf généré par OPNsense refuse tout ce qu'aucune
                // règle n'autorise (default deny documenté du produit).
                default_action: Action::Deny,
            });
        policy.rules.extend(rules);
        if !self.device.pipeline.ingress.contains(&pid) {
            self.device.pipeline.ingress.push(pid);
        }
    }

    fn ensure_filter_policy(&mut self) {
        let pid = PolicyId::new(FILTER_POLICY);
        if !self.device.policies.contains_key(&pid) {
            self.device.policies.insert(
                pid.clone(),
                Policy {
                    id: pid.clone(),
                    rules: Vec::new(),
                    default_action: Action::Deny,
                },
            );
        }
        if !self.device.pipeline.ingress.contains(&pid) {
            self.device.pipeline.ingress.push(pid);
        }
    }

    /// Une règle `<filter><rule>` → règle du modèle. L'ORDRE DU FICHIER
    /// est l'ordre d'évaluation : OPNsense génère des règles pf `quick`,
    /// donc la PREMIÈRE correspondance gagne (voir mod.rs).
    fn filter_rule(&mut self, rule: &ConfigNode, index: u32) -> Option<Rule> {
        let span = rule.span.clone();
        let mut kind: Option<String> = None;
        let mut interface: Option<String> = None;
        let mut protocols: Option<Vec<u8>> = None;
        let mut src: Vec<AddrExpr> = Vec::new();
        let mut sport: Option<PortRange> = None;
        let mut dst: Vec<AddrExpr> = Vec::new();
        let mut dport: Option<PortRange> = None;
        let mut descr: Option<String> = None;
        let mut disabled = false;
        let mut broken = false;

        for d in &rule.children {
            match d.keyword.as_str() {
                "type" => kind = Some(d.args_joined()),
                "interface" => interface = Some(d.args_joined()),
                "protocol" => {
                    let v = d.args_joined();
                    match values::proto_numbers(&v) {
                        Some(p) => protocols = Some(p),
                        None => {
                            self.unsupported(
                                format!("protocole `{v}` non géré (règle {index})"),
                                &d.span,
                            );
                            broken = true;
                        }
                    }
                }
                "source" => {
                    let (exprs, port, ok) = self.endpoint_block(d, &format!("règle {index}"));
                    src = exprs;
                    sport = port;
                    broken |= !ok;
                }
                "destination" => {
                    let (exprs, port, ok) = self.endpoint_block(d, &format!("règle {index}"));
                    dst = exprs;
                    dport = port;
                    broken |= !ok;
                }
                "descr" => {
                    let v = d.args_joined();
                    if !v.is_empty() {
                        descr = Some(v);
                    }
                }
                "disabled" => disabled = d.arg(0) != Some("0"),
                "ipprotocol" => match d.arg(0) {
                    None | Some("inet") => {}
                    Some(other) => {
                        self.unsupported(
                            format!("`<ipprotocol>` `{other}` non géré (règle {index})"),
                            &d.span,
                        );
                        broken = true;
                    }
                },
                "quick" => {
                    // OPNsense génère `quick` par défaut : premier match
                    // gagnant. Sans quick, la DERNIÈRE règle qui
                    // correspond l'emporte — sémantique non modélisée.
                    if d.arg(0) == Some("0") {
                        self.unsupported(
                            format!(
                                "règle {index} sans `quick` : la sémantique \
                                 dernier-match de pf n'est pas modélisée"
                            ),
                            &d.span,
                        );
                        broken = true;
                    }
                }
                "direction" => match d.arg(0) {
                    None | Some("in") => {}
                    Some(other) => {
                        self.unsupported(
                            format!("direction `{other}` non gérée (règle {index})"),
                            &d.span,
                        );
                        broken = true;
                    }
                },
                "floating" => {
                    if d.arg(0) != Some("0") && d.arg(0) != Some("no") {
                        self.unsupported(
                            format!(
                                "règle {index} flottante : évaluée sur toutes les \
                                 interfaces avant les règles d'interface, non modélisée"
                            ),
                            &d.span,
                        );
                        broken = true;
                    }
                }
                "statetype" => match d.args_joined().as_str() {
                    "keep state" | "sloppy state" | "" => {}
                    other => {
                        self.unsupported(
                            format!("suivi d'état `{other}` non géré (règle {index})"),
                            &d.span,
                        );
                        broken = true;
                    }
                },
                "gateway" => {
                    if !is_empty_node(d) {
                        self.unsupported(
                            format!(
                                "règle {index} avec passerelle dédiée : le routage par \
                                 politique n'est pas modélisé"
                            ),
                            &d.span,
                        );
                        broken = true;
                    }
                }
                // Cosmétique et méta reconnus (journalisation comprise).
                "log" | "category" | "tracker" | "created" | "updated" => {}
                k => {
                    // Nom seul, jamais la valeur (§11.4).
                    self.unsupported(
                        format!("élément `<{k}>` non géré dans la règle {index}"),
                        &d.span,
                    );
                    broken = true;
                }
            }
        }

        if disabled {
            let what = descr
                .as_deref()
                .map(|d| format!(" (« {d} »)"))
                .unwrap_or_default();
            self.note_info(format!("règle {index}{what} désactivée : ignorée"), &span);
            return None;
        }

        let action = match kind.as_deref() {
            Some("pass") => Action::Accept,
            // `reject` répond (RST/ICMP) là où `block` jette : même
            // verdict d'accessibilité — refusé (choix documenté, mod.rs).
            Some("block") | Some("reject") => Action::Deny,
            Some(other) => {
                self.unsupported(
                    format!("type de règle `{other}` non géré (règle {index})"),
                    &span,
                );
                return None; // on ne devine pas une action.
            }
            None => {
                self.unsupported(format!("règle {index} sans `<type>`"), &span);
                return None;
            }
        };
        if broken {
            return None;
        }

        let from = interface.and_then(|i| self.zone_ref(&i, &span, "règle"));
        let services = self.build_services(protocols, sport, dport, &span, index)?;

        Some(Rule {
            id: rule_id(index, descr.as_deref(), rule),
            matches: RuleMatch { src, dst, services },
            from,
            // Le filtrage pf est accroché PAR interface d'ENTRÉE : la
            // zone de sortie n'existe pas dans une règle OPNsense.
            to: None,
            action,
            source: span,
            approximation: None,
        })
    }

    // -- briques communes filtre/NAT ------------------------------------

    /// Un bloc `<source>`/`<destination>` : expressions d'adresses + port.
    /// Le booléen rendu vaut `false` si quelque chose n'a pas été compris
    /// (déjà diagnostiqué ici).
    fn endpoint_block(
        &mut self,
        node: &ConfigNode,
        context: &str,
    ) -> (Vec<AddrExpr>, Option<PortRange>, bool) {
        let mut exprs: Vec<AddrExpr> = Vec::new();
        let mut port: Option<PortRange> = None;
        let mut ok = true;

        for d in &node.children {
            match d.keyword.as_str() {
                "any" => exprs.push(AddrExpr::Any),
                "network" => {
                    let v = d.args_joined();
                    match self.network_ref(&v) {
                        Some(mut nets) => exprs.append(&mut nets),
                        None => {
                            self.unsupported(
                                format!(
                                    "`<network>` `{v}` irrésoluble ({context}) : ni une \
                                     interface connue ni sa forme `…ip`"
                                ),
                                &d.span,
                            );
                            ok = false;
                        }
                    }
                }
                "address" => {
                    let v = d.args_joined();
                    match values::parse_net(&v) {
                        Some(net) => exprs.push(AddrExpr::Net(net)),
                        None => {
                            // Pas une adresse : une référence d'alias,
                            // résolue tard (§3.3) — mais une référence
                            // brisée est diagnostiquée dès maintenant.
                            let oid = ObjectId::new(v.as_str());
                            if !self.device.objects.addresses.contains_key(&oid) {
                                self.unsupported(
                                    format!("alias d'adresses `{v}` introuvable ({context})"),
                                    &d.span,
                                );
                                ok = false;
                            }
                            exprs.push(AddrExpr::Object(oid));
                        }
                    }
                }
                "port" => {
                    let v = d.args_joined();
                    if v == "any" || v.is_empty() {
                        continue;
                    }
                    match values::parse_port_spec(&v) {
                        Some(range) => port = Some(range),
                        None => {
                            // Un alias de ports : traité par
                            // `build_services` via le magasin d'objets.
                            match self.port_alias_range(&v) {
                                Some(range) => port = Some(range),
                                None => {
                                    self.unsupported(
                                        format!("port `{v}` irrésoluble ({context})"),
                                        &d.span,
                                    );
                                    ok = false;
                                }
                            }
                        }
                    }
                }
                "not" => {
                    if d.arg(0) != Some("0") {
                        self.unsupported(
                            format!("négation d'adresse (`<not>`) non modélisée ({context})"),
                            &d.span,
                        );
                        ok = false;
                    }
                }
                k => {
                    self.unsupported(
                        format!("élément `<{k}>` non géré dans source/destination ({context})"),
                        &d.span,
                    );
                    ok = false;
                }
            }
        }
        (exprs, port, ok)
    }

    /// `<network>NOM</network>` : le RÉSEAU d'une interface (`lan` → son
    /// sous-réseau), ou son ADRESSE pour la forme `NOMip` (`wanip` → le
    /// /32 de l'interface WAN). Résolution déterministe depuis les
    /// interfaces déjà converties — pas une supposition.
    fn network_ref(&self, name: &str) -> Option<Vec<AddrExpr>> {
        if let Some(iface) = self.device.interfaces.get(&IfaceId::new(name)) {
            let nets: Vec<AddrExpr> = iface
                .addrs
                .iter()
                .map(|a| AddrExpr::Net(a.trunc()))
                .collect();
            return (!nets.is_empty()).then_some(nets);
        }
        if let Some(key) = name.strip_suffix("ip") {
            if let Some(iface) = self.device.interfaces.get(&IfaceId::new(key)) {
                let hosts: Vec<AddrExpr> = iface
                    .addrs
                    .iter()
                    .filter_map(|a| {
                        let max = if a.addr().is_ipv4() { 32 } else { 128 };
                        ipnet::IpNet::new(a.addr(), max).ok().map(AddrExpr::Net)
                    })
                    .collect();
                return (!hosts.is_empty()).then_some(hosts);
            }
        }
        None
    }

    /// La plage UNIQUE d'un alias de ports, quand la règle y fait
    /// référence par son nom. Un alias multi-plages combiné à un
    /// protocole n'est pas réductible à un seul `Service` : `None`, et
    /// l'appelant diagnostique.
    fn port_alias_range(&self, name: &str) -> Option<PortRange> {
        match self.device.objects.services.get(&ObjectId::new(name))? {
            ServiceObject::Services(svcs) if svcs.len() == 1 => Some(svcs[0].dport),
            _ => None,
        }
    }

    /// Compose les expressions de service d'une règle : protocole(s) ×
    /// ports. pf exige un protocole pour contraindre un port : un port
    /// sans protocole est diagnostiqué, jamais élargi en silence.
    fn build_services(
        &mut self,
        protocols: Option<Vec<u8>>,
        sport: Option<PortRange>,
        dport: Option<PortRange>,
        span: &SourceSpan,
        index: u32,
    ) -> Option<Vec<ServiceExpr>> {
        match protocols {
            None => {
                if sport.is_some() || dport.is_some() {
                    self.unsupported(
                        format!(
                            "règle {index} : un port sans `<protocol>` n'est pas une \
                             règle pf valide"
                        ),
                        span,
                    );
                    return None;
                }
                Some(Vec::new()) // aucun service = tout protocole.
            }
            Some(protos) => Some(
                protos
                    .into_iter()
                    .map(|p| {
                        ServiceExpr::Service(Service {
                            proto: ProtoMatch::Number(p),
                            sport: sport.unwrap_or(PortRange::ANY),
                            dport: dport.unwrap_or(PortRange::ANY),
                        })
                    })
                    .collect(),
            ),
        }
    }

    /// Résout un nom d'interface de règle vers une zone du modèle.
    /// `lan` → la zone de l'interface (sa `<descr>` si elle en a une).
    fn zone_ref(&mut self, name: &str, span: &SourceSpan, what: &str) -> Option<ZoneId> {
        if name.is_empty() {
            return None;
        }
        // Plusieurs interfaces (`lan,opt1`) : `Rule.from` ne porte
        // qu'une zone — retenir la première en silence serait faux.
        if let Some((first, _rest)) = name.split_once(',') {
            self.unsupported(
                format!(
                    "{what} sur plusieurs interfaces (`{name}`) non gérée ; seule \
                     `{first}` est retenue"
                ),
                span,
            );
            let first = first.to_owned();
            return self.zone_ref(&first, span, what);
        }
        match self.zone_of_iface.get(name) {
            Some(zone) => Some(zone.clone()),
            None => {
                // `enc0` (IPsec), `openvpn`, groupe d'interfaces… :
                // aucune interface convertie ne porte ce nom.
                self.unsupported(format!("{what} sur l'interface inconnue `{name}`"), span);
                Some(ZoneId::new(name))
            }
        }
    }
}

/// Le format d'origine d'un alias (pour les messages seulement).
#[derive(Clone, Copy)]
enum AliasFormat {
    Modern,
    Legacy,
}

/// Identifiant de règle : l'index dans l'ordre du fichier (base 1, les
/// règles désactivées comptent), complété de l'uuid ou de la description
/// — c'est sous ce nom que l'administrateur reconnaît sa règle.
fn rule_id(index: u32, descr: Option<&str>, node: &ConfigNode) -> RuleId {
    if let Some(d) = descr {
        return RuleId::new(format!("{index} ({d})"));
    }
    // L'attribut `@uuid=…` posé par la couche 1, s'il existe.
    if let Some(uuid) = node
        .args
        .iter()
        .find_map(|a| a.strip_prefix("@uuid="))
        .filter(|u| !u.is_empty())
    {
        return RuleId::new(format!("{index} ({uuid})"));
    }
    RuleId::new(index.to_string())
}

/// Un nœud « vide » : ni texte, ni attribut, ni enfant (`<vlans/>`).
fn is_empty_node(node: &ConfigNode) -> bool {
    node.args.is_empty() && node.children.is_empty()
}

/// La route par défaut IPv4.
fn default_net() -> ipnet::IpNet {
    ipnet::IpNet::V4(
        ipnet::Ipv4Net::new(std::net::Ipv4Addr::UNSPECIFIED, 0).expect("préfixe /0 constant"),
    )
}

/// `configs/config-fw.xml` → `config-fw`. Repli pour nommer l'équipement
/// quand la configuration ne porte pas de `<hostname>`.
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
    use crate::opnsense::OpnsenseAdapter;

    fn import(raw: &str) -> AdapterOutput {
        OpnsenseAdapter
            .import_str(raw, "t.xml")
            .expect("un modèle doit sortir")
    }

    fn all_messages(out: &AdapterOutput) -> Vec<&str> {
        let mut msgs: Vec<&str> = out.notes.iter().map(|d| d.message.as_str()).collect();
        if let Fidelity::Partial { unsupported } = &out.fidelity {
            msgs.extend(unsupported.iter().map(|d| d.message.as_str()));
        }
        msgs
    }

    #[test]
    fn nom_de_fichier_vers_identifiant() {
        assert_eq!(file_stem("configs/config-fw.xml"), "config-fw");
        assert_eq!(file_stem("C:\\configs\\config.xml"), "config");
        assert_eq!(file_stem("config"), "config");
        assert_eq!(file_stem(""), "equipement");
    }

    /// §11.4 — la VALEUR d'un élément non compris ne fuit jamais dans un
    /// diagnostic : un config.xml porte des mots de passe hachés, des
    /// communautés SNMP, des clés privées.
    #[test]
    fn secrets_absents_des_diagnostics() {
        let out = import(
            "<opnsense><system><hostname>fw-t</hostname></system>\
             <gadget><cle>S3CRET-VALEUR</cle></gadget></opnsense>",
        );
        let msgs = all_messages(&out);
        assert!(
            msgs.iter().any(|m| m.contains("gadget")),
            "la section est diagnostiquée par son NOM : {msgs:?}"
        );
        assert!(
            msgs.iter().all(|m| !m.contains("S3CRET")),
            "la valeur ne doit jamais apparaître : {msgs:?}"
        );
    }

    /// Une section qui touche le trafic (ipsec) dégrade la fidélité même
    /// si tout le reste est compris.
    #[test]
    fn section_trafic_non_vide_degrade_la_fidelite() {
        let out = import("<opnsense><ipsec><enable>1</enable></ipsec></opnsense>");
        let Fidelity::Partial { unsupported } = &out.fidelity else {
            panic!("ipsec non vide doit dégrader la fidélité");
        };
        assert!(unsupported.iter().any(|d| d.message.contains("ipsec")));

        // Vide : rien à modéliser, fidélité intacte.
        let out = import("<opnsense><ipsec/></opnsense>");
        assert_eq!(out.fidelity, Fidelity::Complete);
    }

    /// Deux blocs `<filter>` : les règles s'AJOUTENT dans l'ordre du
    /// fichier — écraser le premier bloc effacerait ses refus.
    #[test]
    fn blocs_filter_multiples_concatenes() {
        let out = import(
            "<opnsense>\
             <filter><rule><type>block</type></rule></filter>\
             <filter><rule><type>pass</type></rule></filter>\
             </opnsense>",
        );
        let policy = out
            .device
            .policies
            .get(&PolicyId::new(FILTER_POLICY))
            .expect("politique filter");
        assert_eq!(policy.rules.len(), 2);
        assert_eq!(policy.rules[0].action, Action::Deny);
        assert_eq!(policy.rules[1].action, Action::Accept);
        assert_eq!(out.device.pipeline.ingress.len(), 1);
    }

    /// Sans `<filter>`, la politique default-deny existe quand même :
    /// c'est le comportement du pf généré.
    #[test]
    fn default_deny_sans_section_filter() {
        let out =
            import("<opnsense><interfaces><lan><enable>1</enable></lan></interfaces></opnsense>");
        let policy = out
            .device
            .policies
            .get(&PolicyId::new(FILTER_POLICY))
            .expect("politique filter implicite");
        assert!(policy.rules.is_empty());
        assert_eq!(policy.default_action, Action::Deny);
        assert_eq!(out.device.pipeline.ingress, vec![policy.id.clone()]);
    }

    /// Un alias de ports référencé par son nom est réduit à sa plage,
    /// combinée au protocole de la règle (résolution documentée).
    #[test]
    fn alias_de_ports_reference_par_une_regle() {
        let out = import(
            "<opnsense>\
             <interfaces><lan><enable>1</enable><ipaddr>10.0.0.1</ipaddr><subnet>24</subnet></lan></interfaces>\
             <aliases><alias><name>p_web</name><type>port</type><address>8443</address></alias></aliases>\
             <filter><rule><type>pass</type><interface>lan</interface><protocol>tcp</protocol>\
             <source><any/></source><destination><any/><port>p_web</port></destination></rule></filter>\
             </opnsense>",
        );
        assert_eq!(out.fidelity, Fidelity::Complete, "{:?}", out.fidelity);
        let policy = &out.device.policies[&PolicyId::new(FILTER_POLICY)];
        assert_eq!(
            policy.rules[0].matches.services,
            vec![ServiceExpr::Service(Service {
                proto: ProtoMatch::Number(6),
                sport: PortRange::ANY,
                dport: PortRange::single(8443),
            })]
        );
    }

    /// Un port sans protocole n'est pas une règle pf valide : diagnostic,
    /// jamais un élargissement silencieux à tous les protocoles.
    #[test]
    fn port_sans_protocole_diagnostique() {
        let out = import(
            "<opnsense><filter><rule><type>pass</type>\
             <destination><any/><port>443</port></destination></rule></filter></opnsense>",
        );
        let Fidelity::Partial { unsupported } = &out.fidelity else {
            panic!("port sans protocole doit dégrader la fidélité");
        };
        assert!(unsupported
            .iter()
            .any(|d| d.message.contains("sans `<protocol>`")));
        let policy = &out.device.policies[&PolicyId::new(FILTER_POLICY)];
        assert!(policy.rules.is_empty(), "la règle n'entre pas à moitié");
    }
}
