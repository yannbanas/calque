//! La comparaison de COMPORTEMENT — le cœur de `calque plan` (§10.2, S4).
//!
//! [`plan`] rejoue chaque flux déclaré sur le modèle courant (`before`) et
//! sur le modèle candidat (`after`) via `calque_engine::trace_packet`, puis
//! classe les écarts :
//!
//! - verdict identique des deux côtés → `unchanged` ;
//! - le flux passait et ne passe plus (ou l'inverse) → ROMPU ou CORRIGÉ
//!   selon l'attente déclarée (`expect_allow`) ; sans attente déclarée
//!   (`None`, flux sonde), l'écart est rangé dans `changed` ;
//! - un verdict `Unknown` d'un côté ou de l'autre → `undecided` : le modèle
//!   ne permet pas de conclure, on ne devine JAMAIS (§6.3) ;
//! - les ouvertures NON DEMANDÉES → `new_flows`, détectées par SONDES
//!   (voir plus bas) : la ligne « NOUVEAU » de §10.2.
//!
//! Chaque [`FlowDelta`] porte la JUSTIFICATION avant/après : le verdict ET
//! la règle décisive (identifiant + fichier/ligne), extraite de la trace —
//! « avant : autorisé par la règle 12 ; après : refusé par la règle 8 ».
//! La trace est le produit (§5.2) : un verdict sans sa règle ne vaut rien.
//!
//! # Détection des ouvertures par sondes — une HEURISTIQUE assumée
//!
//! Sans mode symbolique (S6), l'exhaustivité est hors de portée : la
//! détection des ouvertures non déclarées procède par ÉCHANTILLONNAGE.
//! Pour chaque règle de chaque politique DES DEUX modèles, on dérive des
//! paquets représentatifs (premier hôte libre de chaque préfixe, premier
//! port de chaque plage, protocole de la règle ; `Any` → les sous-réseaux
//! d'interfaces des deux réseaux servent d'univers). Chaque sonde est
//! rejouée sur les deux modèles : bloquée avant ET autorisée après ET non
//! couverte par un flux déclaré → [`NewOpening`], avec le paquet précis
//! (§4.1) et la règle qui l'autorise désormais.
//!
//! Bornes documentées (constantes ci-dessous) : au plus
//! [`PROBE_BUDGET`] sondes au total, [`MAX_UNIVERSE`] sous-réseaux
//! d'univers pour `Any`, [`MAX_ADDRS_PER_SIDE`] adresses et
//! [`MAX_SERVICES_PER_RULE`] services par règle, [`MAX_PROBES_PER_RULE`]
//! sondes par règle. Une absence d'ouverture dans le rapport ne PROUVE
//! donc rien : seule la version symbolique (S6) le pourra. Aucun nom ni
//! type ici ne prétend à l'exhaustivité.

use std::collections::{BTreeSet, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use calque_engine::{trace_packet, Outcome, Trace, Verdict};
use calque_model::{
    AddrExpr, AddrObject, ConcretePacket, Network, ObjectId, ObjectStore, PortRange, ProtoMatch,
    RuleId, Service, ServiceExpr, ServiceObject, SourceSpan,
};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Bornes de l'échantillonnage (documentées dans le rustdoc du module)
// ---------------------------------------------------------------------------

/// Nombre TOTAL maximal de sondes générées (les deux modèles confondus).
pub const PROBE_BUDGET: usize = 512;
/// Nombre maximal de sous-réseaux d'interfaces retenus comme univers
/// quand une règle dit `Any` sur une adresse.
pub const MAX_UNIVERSE: usize = 8;
/// Nombre maximal d'adresses représentatives par côté (src ou dst) de règle.
pub const MAX_ADDRS_PER_SIDE: usize = 4;
/// Nombre maximal de services représentatifs par règle.
pub const MAX_SERVICES_PER_RULE: usize = 4;
/// Nombre maximal de sondes dérivées d'une même règle.
pub const MAX_PROBES_PER_RULE: usize = 8;
/// Nombre d'hôtes candidats parcourus dans un sous-réseau pour éviter les
/// adresses portées par un équipement.
const MAX_HOST_SCAN: u32 = 8;
/// Profondeur maximale de résolution des groupes imbriqués pendant la
/// génération de sondes. La détection de cycle ne suffit pas : une CHAÎNE
/// de groupes distincts (hostile) serait parcourue récursivement jusqu'au
/// débordement de pile. Les groupes réels s'imbriquent sur 2 ou 3 niveaux.
const MAX_GROUP_DEPTH: usize = 32;

/// Port source représentatif quand la plage source est `Any`.
const REPR_SPORT: u16 = 40000;
/// Port destination représentatif quand le service est `Any`.
const REPR_DPORT: u16 = 80;
/// Protocole représentatif quand le service est `Any` (6 = TCP).
const REPR_PROTO: u8 = 6;

// ---------------------------------------------------------------------------
// L'API imposée : ResolvedFlow → plan()
// ---------------------------------------------------------------------------

/// Un flux déclaré (une ligne de `flows.yaml`) déjà résolu en paquet
/// concret par l'appelant (le CLI).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedFlow {
    pub name: String,
    pub packet: ConcretePacket,
    /// `Some(true)` = le flux doit passer, `Some(false)` = il doit être
    /// bloqué, `None` = flux non déclaré (sonde) : un écart est rapporté
    /// comme « changé », ni ROMPU ni CORRIGÉ.
    pub expect_allow: Option<bool>,
}

// ---------------------------------------------------------------------------
// Types du rapport
// ---------------------------------------------------------------------------

/// Statut d'un flux tel que rapporté par `calque plan` — aligné sur le
/// `Verdict` de `calque-engine`. `Unknown` couvre les modèles à fidélité
/// partielle sur le chemin analysé (§6.3 : ne jamais deviner).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FlowStatus {
    Allowed,
    Denied,
    NoRoute,
    Loop,
    Unknown,
}

impl From<Verdict> for FlowStatus {
    fn from(v: Verdict) -> Self {
        match v {
            Verdict::Allowed => FlowStatus::Allowed,
            Verdict::Denied => FlowStatus::Denied,
            Verdict::NoRoute => FlowStatus::NoRoute,
            Verdict::Loop => FlowStatus::Loop,
            Verdict::Unknown => FlowStatus::Unknown,
        }
    }
}

impl FlowStatus {
    /// Le flux atteint-il sa destination ?
    pub fn passes(self) -> bool {
        matches!(self, FlowStatus::Allowed)
    }
}

/// La justification d'un verdict : le statut ET la règle décisive (la
/// DERNIÈRE décision décisive de la trace), avec son fichier/ligne.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Justification {
    pub status: FlowStatus,
    /// `None` quand aucune règle n'a décidé (action par défaut d'une
    /// politique, absence de route, livraison directe).
    pub rule: Option<RuleId>,
    /// Fichier + ligne de la règle ou de la route responsable.
    pub source: Option<SourceSpan>,
}

impl Justification {
    /// Phrase de justification, dans l'esprit de la maquette §10.2 :
    /// « autorisé par la règle 12 (fw-01.conf ligne 120) ».
    pub fn describe(&self) -> String {
        let origine = self
            .source
            .as_ref()
            .map(|s| format!(" ({s})"))
            .unwrap_or_default();
        match (self.status, &self.rule) {
            (FlowStatus::Allowed, Some(r)) => format!("autorisé par la règle {r}{origine}"),
            (FlowStatus::Allowed, None) => {
                "autorisé (action par défaut ou livraison directe)".to_owned()
            }
            (FlowStatus::Denied, Some(r)) => format!("refusé par la règle {r}{origine}"),
            (FlowStatus::Denied, None) => "refusé par l'action par défaut".to_owned(),
            (FlowStatus::NoRoute, _) => format!("sans route vers la destination{origine}"),
            (FlowStatus::Loop, _) => "boucle de routage".to_owned(),
            (FlowStatus::Unknown, _) => "indéterminé (modèle partiel)".to_owned(),
        }
    }
}

/// Un flux déclaré dont le comportement change entre les deux modèles,
/// avec la justification avant/après (verdict + règle décisive).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlowDelta {
    /// Nom du flux dans `flows.yaml`.
    pub flow: String,
    /// Le paquet concret rejoué sur les deux modèles.
    pub packet: ConcretePacket,
    pub before: Justification,
    pub after: Justification,
    /// Explication textuelle prête à afficher (« avant : autorisé par la
    /// règle 12 ; après : refusé par la règle 8 »).
    pub explanation: String,
}

/// Un flux déclaré sur lequel le modèle ne permet PAS de conclure
/// (verdict `Unknown` sur au moins un des deux modèles) : ni ROMPU, ni
/// CORRIGÉ, ni inchangé. Ne jamais deviner (§6.3) — le CLI l'affiche tel
/// quel, avec les diagnostics du moteur.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UndecidedFlow {
    pub flow: String,
    pub packet: ConcretePacket,
    pub before: FlowStatus,
    pub after: FlowStatus,
    /// Messages des diagnostics du moteur expliquant l'indécision.
    pub diagnostics: Vec<String>,
}

/// Une ouverture d'accès qui n'était couverte par AUCUN flux déclaré —
/// la ligne « NOUVEAU » de §10.2. C'est le signal le plus précieux du
/// rapport : un accès que personne n'avait demandé.
///
/// Détectée par SONDE (voir le rustdoc du module) : le paquet est un
/// ÉCHANTILLON précis (§4.1), pas la description complète de l'ouverture.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NewOpening {
    /// Source, telle qu'affichable.
    pub from: String,
    /// Destination.
    pub to: String,
    /// Service (« 445/tcp », « 80/tcp », ...).
    pub port: String,
    /// Le paquet de sonde précis qui était bloqué et passe désormais.
    pub packet: ConcretePacket,
    /// La règle qui l'autorise désormais, si une règle a décidé
    /// (`None` = action par défaut ou livraison directe).
    pub allowed_by: Option<RuleId>,
    /// Fichier + ligne de la règle responsable.
    pub source: Option<SourceSpan>,
}

/// Le rapport de `calque plan` : ce qui change de comportement entre le
/// modèle courant et le modèle candidat. Produit par [`plan`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanReport {
    /// Flux déclarés qui dévient désormais de leur attente (ROMPU) :
    /// attendu passant et ne passe plus, ou attendu bloqué et passe.
    pub broken: Vec<FlowDelta>,
    /// Flux déclarés qui déviaient et sont maintenant conformes (CORRIGÉ).
    pub fixed: Vec<FlowDelta>,
    /// Flux déclarés SANS attente (`expect_allow = None`) dont le verdict
    /// change, et flux dont le verdict change sans que l'effet passe/bloqué
    /// ne s'inverse (ex. refusé → sans route) : « changé », sans jugement.
    pub changed: Vec<FlowDelta>,
    /// Flux sur lesquels le modèle ne permet pas de conclure (§6.3).
    pub undecided: Vec<UndecidedFlow>,
    /// Ouvertures nouvelles non couvertes par un flux déclaré (NOUVEAU),
    /// détectées par échantillonnage — voir le rustdoc du module : une
    /// liste vide ne prouve PAS l'absence d'ouverture.
    pub new_flows: Vec<NewOpening>,
    /// Noms des flux déclarés dont le verdict ne change pas.
    pub unchanged: Vec<String>,
}

impl PlanReport {
    /// Vrai si aucun flux ne change de comportement, qu'aucune ouverture
    /// nouvelle n'est détectée et que tous les verdicts sont fermes.
    pub fn is_quiet(&self) -> bool {
        self.broken.is_empty()
            && self.fixed.is_empty()
            && self.changed.is_empty()
            && self.undecided.is_empty()
            && self.new_flows.is_empty()
    }

    /// Nombre de flux déclarés dont le comportement change.
    pub fn changed_count(&self) -> usize {
        self.broken.len() + self.fixed.len() + self.changed.len()
    }
}

// ---------------------------------------------------------------------------
// plan() — l'entrée principale
// ---------------------------------------------------------------------------

/// Compare le COMPORTEMENT de deux modèles : rejoue chaque flux déclaré
/// sur `before` et `after`, classe les écarts, puis cherche par sondes
/// les ouvertures non déclarées (heuristique bornée, voir le rustdoc du
/// module). Pur : aucune entrée-sortie.
pub fn plan(before: &Network, after: &Network, flows: &[ResolvedFlow]) -> PlanReport {
    let mut report = PlanReport::default();

    for flow in flows {
        let trace_before = trace_packet(before, &flow.packet);
        let trace_after = trace_packet(after, &flow.packet);

        // Verdict non ferme d'un côté ou de l'autre : classé à part,
        // jamais interprété (§6.3).
        if trace_before.verdict == Verdict::Unknown || trace_after.verdict == Verdict::Unknown {
            report.undecided.push(UndecidedFlow {
                flow: flow.name.clone(),
                packet: flow.packet,
                before: trace_before.verdict.into(),
                after: trace_after.verdict.into(),
                diagnostics: collect_messages(&trace_before, &trace_after),
            });
            continue;
        }

        if trace_before.verdict == trace_after.verdict {
            report.unchanged.push(flow.name.clone());
            continue;
        }

        let before_j = justification(&trace_before);
        let after_j = justification(&trace_after);
        let explanation = format!(
            "avant : {} ; après : {}",
            before_j.describe(),
            after_j.describe()
        );
        let passes_before = before_j.status.passes();
        let passes_after = after_j.status.passes();
        let delta = FlowDelta {
            flow: flow.name.clone(),
            packet: flow.packet,
            before: before_j,
            after: after_j,
            explanation,
        };

        // Classement selon l'attente déclarée. L'effet doit s'INVERSER
        // (passait/ne passe plus ou l'inverse) pour juger ROMPU/CORRIGÉ ;
        // un changement de mécanisme à effet égal (refusé → sans route)
        // est rapporté comme « changé ».
        match (passes_before, passes_after, flow.expect_allow) {
            // Passait et ne passe plus.
            (true, false, Some(true)) => report.broken.push(delta),
            (true, false, Some(false)) => report.fixed.push(delta),
            // Était bloqué et passe désormais.
            (false, true, Some(false)) => report.broken.push(delta),
            (false, true, Some(true)) => report.fixed.push(delta),
            // Pas d'attente déclarée, ou effet inchangé : « changé ».
            _ => report.changed.push(delta),
        }
    }

    report.new_flows = detect_new_openings(before, after, flows);
    report
}

/// Rassemble les messages de diagnostic des deux traces, sans doublon.
fn collect_messages(before: &Trace, after: &Trace) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for d in before.diagnostics.iter().chain(after.diagnostics.iter()) {
        if !out.contains(&d.message) {
            out.push(d.message.clone());
        }
    }
    out
}

/// Une décision porte-t-elle le verdict (par opposition aux décisions
/// informationnelles `Matched`/`NoMatch`/`RouteFound`/`Rewritten`) ?
fn is_decisive(outcome: Outcome) -> bool {
    matches!(
        outcome,
        Outcome::Accepted
            | Outcome::Denied
            | Outcome::DefaultAction
            | Outcome::NoRoute
            | Outcome::RouteDrop
    )
}

/// Extrait la justification d'une trace : la DERNIÈRE décision décisive
/// (celle du dernier équipement traversé porte le verdict final).
fn justification(trace: &Trace) -> Justification {
    let decisive = trace
        .hops
        .iter()
        .flat_map(|h| &h.decisions)
        .rfind(|d| is_decisive(d.outcome));
    Justification {
        status: trace.verdict.into(),
        rule: decisive.and_then(|d| d.rule.clone()),
        source: decisive.and_then(|d| d.source.clone()),
    }
}

// ---------------------------------------------------------------------------
// Détection des ouvertures non déclarées, par sondes (heuristique bornée)
// ---------------------------------------------------------------------------

/// Cherche les ouvertures non déclarées : chaque sonde (voir
/// [`build_probes`]) bloquée sur `before` ET autorisée sur `after` ET non
/// couverte par un flux déclaré devient une [`NewOpening`]. Une sonde au
/// verdict `Unknown` d'un côté est écartée : on ne rapporte jamais une
/// ouverture qu'on ne peut pas prouver sur le modèle.
fn detect_new_openings(
    before: &Network,
    after: &Network,
    flows: &[ResolvedFlow],
) -> Vec<NewOpening> {
    let mut openings: Vec<NewOpening> = Vec::new();
    // Dédoublonnage des ouvertures équivalentes (le port source, choisi
    // arbitrairement par la sonde, est ignoré).
    let mut seen: BTreeSet<(IpAddr, IpAddr, u8, u16)> = BTreeSet::new();

    for probe in build_probes(before, after) {
        if flows.iter().any(|f| covers(&f.packet, &probe)) {
            continue; // déjà couvert par un flux déclaré
        }
        let key = (probe.src, probe.dst, probe.proto, probe.dport);
        if seen.contains(&key) {
            continue;
        }
        let verdict_before = trace_packet(before, &probe).verdict;
        // « Bloqué avant » : un verdict ferme de non-passage, jamais Unknown.
        if !matches!(
            verdict_before,
            Verdict::Denied | Verdict::NoRoute | Verdict::Loop
        ) {
            continue;
        }
        let trace_after = trace_packet(after, &probe);
        if trace_after.verdict != Verdict::Allowed {
            continue;
        }
        seen.insert(key);
        let j = justification(&trace_after);
        openings.push(NewOpening {
            from: probe.src.to_string(),
            to: probe.dst.to_string(),
            port: format_service(probe.proto, probe.dport),
            packet: probe,
            allowed_by: j.rule,
            source: j.source,
        });
    }

    // Ordre déterministe pour le rapport.
    openings.sort_by_key(|o| (o.packet.src, o.packet.dst, o.packet.proto, o.packet.dport));
    openings
}

/// Un flux déclaré couvre-t-il la sonde ? Comparaison CONCRÈTE (même
/// source, destination, protocole et port destination ; le port source,
/// arbitraire, est ignoré). La couverture ensembliste viendra avec S6.
fn covers(declared: &ConcretePacket, probe: &ConcretePacket) -> bool {
    declared.src == probe.src
        && declared.dst == probe.dst
        && declared.proto == probe.proto
        && declared.dport == probe.dport
}

/// « 445/tcp », « 53/udp », « 8/icmp », « 0/proto-47 »...
fn format_service(proto: u8, dport: u16) -> String {
    match proto {
        6 => format!("{dport}/tcp"),
        17 => format!("{dport}/udp"),
        1 => format!("{dport}/icmp"),
        n => format!("{dport}/proto-{n}"),
    }
}

/// Construit les paquets de sonde à partir des règles DES DEUX modèles
/// (une règle retirée peut ouvrir un accès tout comme une règle ajoutée).
/// Déterministe (parcours des `BTreeMap` triées) et borné par
/// [`PROBE_BUDGET`], [`MAX_PROBES_PER_RULE`] et les bornes par côté.
fn build_probes(before: &Network, after: &Network) -> Vec<ConcretePacket> {
    let networks = [before, after];
    let avoid = owned_addresses(&networks);
    let universe = universe_hosts(&networks, &avoid);

    let mut seen: HashSet<ConcretePacket> = HashSet::new();
    let mut probes: Vec<ConcretePacket> = Vec::new();

    'networks: for network in networks {
        for device in network.devices.values() {
            for policy in device.policies.values() {
                for rule in &policy.rules {
                    let srcs =
                        addr_candidates(&device.objects, &rule.matches.src, &universe, &avoid);
                    let dsts =
                        addr_candidates(&device.objects, &rule.matches.dst, &universe, &avoid);
                    let services = service_candidates(&device.objects, &rule.matches.services);

                    let mut per_rule = 0usize;
                    'rule: for src in &srcs {
                        for dst in &dsts {
                            for (proto, sport, dport) in &services {
                                // Sondes dégénérées : même adresse, ou
                                // familles IP différentes.
                                if src == dst || src.is_ipv4() != dst.is_ipv4() {
                                    continue;
                                }
                                if per_rule >= MAX_PROBES_PER_RULE {
                                    break 'rule;
                                }
                                let packet = ConcretePacket {
                                    src: *src,
                                    dst: *dst,
                                    proto: *proto,
                                    sport: *sport,
                                    dport: *dport,
                                };
                                if seen.insert(packet) {
                                    probes.push(packet);
                                    per_rule += 1;
                                }
                                if probes.len() >= PROBE_BUDGET {
                                    break 'networks;
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    probes
}

/// Toutes les adresses portées par une interface d'un des deux modèles :
/// les sondes les évitent (viser l'équipement lui-même fausserait la
/// question « le sous-réseau est-il joignable ? »).
fn owned_addresses(networks: &[&Network]) -> BTreeSet<IpAddr> {
    let mut owned = BTreeSet::new();
    for network in networks {
        for device in network.devices.values() {
            for iface in device.interfaces.values() {
                for addr in &iface.addrs {
                    owned.insert(addr.addr());
                }
            }
        }
    }
    owned
}

/// L'univers de sondes pour `Any` : un hôte représentatif par sous-réseau
/// d'interface des deux modèles, borné à [`MAX_UNIVERSE`] sous-réseaux
/// (parcours trié et déterministe, premiers sous-réseaux retenus).
fn universe_hosts(networks: &[&Network], avoid: &BTreeSet<IpAddr>) -> Vec<IpAddr> {
    // Arrêt dès que la borne est atteinte : continuer à dédupliquer sur un
    // modèle hostile aux dizaines de milliers d'interfaces serait
    // quadratique pour un résultat identique (seuls les MAX_UNIVERSE
    // premiers sous-réseaux distincts sont retenus, parcours trié).
    let mut nets: Vec<IpNet> = Vec::new();
    'collect: for network in networks {
        for device in network.devices.values() {
            for iface in device.interfaces.values() {
                for addr in &iface.addrs {
                    let net = addr.trunc();
                    if !nets.contains(&net) {
                        nets.push(net);
                        if nets.len() >= MAX_UNIVERSE {
                            break 'collect;
                        }
                    }
                }
            }
        }
    }
    let mut hosts: Vec<IpAddr> = Vec::new();
    for net in &nets {
        let host = probe_host(net, avoid);
        if !hosts.contains(&host) {
            hosts.push(host);
        }
    }
    hosts
}

/// Le premier hôte « libre » d'un préfixe : la première adresse après
/// l'adresse de réseau qui n'est portée par aucun équipement (parcours
/// borné à [`MAX_HOST_SCAN`] candidats ; à défaut, la première adresse).
fn probe_host(net: &IpNet, avoid: &BTreeSet<IpAddr>) -> IpAddr {
    match net {
        IpNet::V4(n) => {
            if n.prefix_len() >= 31 {
                return IpAddr::V4(n.addr());
            }
            let base = u32::from(n.network());
            let broadcast = u32::from(n.broadcast());
            let mut candidate = base.saturating_add(1);
            for _ in 0..MAX_HOST_SCAN {
                if candidate >= broadcast {
                    break;
                }
                let ip = IpAddr::V4(Ipv4Addr::from(candidate));
                if !avoid.contains(&ip) {
                    return ip;
                }
                candidate = candidate.saturating_add(1);
            }
            IpAddr::V4(Ipv4Addr::from(base.saturating_add(1)))
        }
        IpNet::V6(n) => {
            if n.prefix_len() >= 127 {
                return IpAddr::V6(n.addr());
            }
            let base = u128::from(n.network());
            let mut candidate = base.saturating_add(1);
            for _ in 0..MAX_HOST_SCAN {
                let ip = IpAddr::V6(Ipv6Addr::from(candidate));
                if !avoid.contains(&ip) {
                    return ip;
                }
                candidate = candidate.saturating_add(1);
            }
            IpAddr::V6(Ipv6Addr::from(base.saturating_add(1)))
        }
    }
}

/// Adresses représentatives d'un côté de règle (src ou dst) : un hôte par
/// préfixe résolu (objets et groupes compris), borné à
/// [`MAX_ADDRS_PER_SIDE`]. `Any` (ou vecteur vide, la convention du
/// modèle) → l'univers des sous-réseaux d'interfaces.
fn addr_candidates(
    store: &ObjectStore,
    exprs: &[AddrExpr],
    universe: &[IpAddr],
    avoid: &BTreeSet<IpAddr>,
) -> Vec<IpAddr> {
    let mut nets: Vec<IpNet> = Vec::new();
    let mut any = exprs.is_empty();
    for expr in exprs {
        if addr_expr_nets(store, expr, &mut nets) {
            any = true;
        }
    }
    if any {
        return universe.iter().copied().take(MAX_ADDRS_PER_SIDE).collect();
    }
    let mut hosts: Vec<IpAddr> = Vec::new();
    for net in &nets {
        let host = probe_host(net, avoid);
        if !hosts.contains(&host) {
            hosts.push(host);
        }
        if hosts.len() >= MAX_ADDRS_PER_SIDE {
            break;
        }
    }
    hosts
}

/// Aplati une expression d'adresse en préfixes concrets. Rend `true` si
/// l'expression vaut `Any`. Un objet manquant ou cyclique est simplement
/// ignoré ICI (génération de sondes, meilleure-effort) : le moteur, lui,
/// le diagnostiquera en `Unknown` à l'évaluation.
fn addr_expr_nets(store: &ObjectStore, expr: &AddrExpr, out: &mut Vec<IpNet>) -> bool {
    match expr {
        AddrExpr::Any => true,
        AddrExpr::Net(net) => {
            if out.len() < MAX_ADDRS_PER_SIDE && !out.contains(net) {
                out.push(*net);
            }
            false
        }
        AddrExpr::Object(id) => {
            addr_object_nets(store, id, out, &mut Vec::new());
            false
        }
    }
}

/// Résolution récursive d'un objet adresse en préfixes, bornée et
/// protégée contre les cycles.
fn addr_object_nets(
    store: &ObjectStore,
    id: &ObjectId,
    out: &mut Vec<IpNet>,
    stack: &mut Vec<ObjectId>,
) {
    // `stack.len()` borne la PROFONDEUR (une chaîne hostile de groupes
    // distincts ferait déborder la pile), `stack.contains` casse les cycles.
    if out.len() >= MAX_ADDRS_PER_SIDE || stack.len() >= MAX_GROUP_DEPTH || stack.contains(id) {
        return;
    }
    match store.addresses.get(id) {
        None => {} // objet manquant : pas de sonde, le moteur diagnostiquera
        Some(AddrObject::Nets(nets)) => {
            for net in nets {
                if out.len() >= MAX_ADDRS_PER_SIDE {
                    break;
                }
                if !out.contains(net) {
                    out.push(*net);
                }
            }
        }
        Some(AddrObject::Group(members)) => {
            stack.push(id.clone());
            for member in members {
                addr_object_nets(store, member, out, stack);
            }
            stack.pop();
        }
    }
}

/// Services représentatifs d'une règle : `(protocole, port source, port
/// destination)`, borné à [`MAX_SERVICES_PER_RULE`]. `Any` (ou vecteur
/// vide) → UN représentant documenté ([`REPR_PROTO`]/[`REPR_DPORT`]) :
/// c'est un échantillon, pas une couverture.
fn service_candidates(store: &ObjectStore, exprs: &[ServiceExpr]) -> Vec<(u8, u16, u16)> {
    let mut services: Vec<Service> = Vec::new();
    let mut any = exprs.is_empty();
    for expr in exprs {
        match expr {
            ServiceExpr::Any => any = true,
            ServiceExpr::Service(svc) => {
                if services.len() < MAX_SERVICES_PER_RULE {
                    services.push(*svc);
                }
            }
            ServiceExpr::Object(id) => {
                service_object_services(store, id, &mut services, &mut Vec::new());
            }
        }
    }
    if any {
        return vec![(REPR_PROTO, REPR_SPORT, REPR_DPORT)];
    }
    let mut out: Vec<(u8, u16, u16)> = Vec::new();
    for svc in &services {
        let repr = service_repr(svc);
        if !out.contains(&repr) {
            out.push(repr);
        }
        if out.len() >= MAX_SERVICES_PER_RULE {
            break;
        }
    }
    out
}

/// Résolution récursive d'un objet service, bornée et protégée contre
/// les cycles (meilleure-effort, comme pour les adresses).
fn service_object_services(
    store: &ObjectStore,
    id: &ObjectId,
    out: &mut Vec<Service>,
    stack: &mut Vec<ObjectId>,
) {
    // Même garde de profondeur que `addr_object_nets`.
    if out.len() >= MAX_SERVICES_PER_RULE || stack.len() >= MAX_GROUP_DEPTH || stack.contains(id) {
        return;
    }
    match store.services.get(id) {
        None => {}
        Some(ServiceObject::Services(services)) => {
            for svc in services {
                if out.len() >= MAX_SERVICES_PER_RULE {
                    break;
                }
                out.push(*svc);
            }
        }
        Some(ServiceObject::Group(members)) => {
            stack.push(id.clone());
            for member in members {
                service_object_services(store, member, out, stack);
            }
            stack.pop();
        }
    }
}

/// Le représentant concret d'un service : protocole de la règle (TCP si
/// `Any`), premier port de chaque plage (représentants documentés pour
/// les plages `Any`).
fn service_repr(svc: &Service) -> (u8, u16, u16) {
    let proto = match svc.proto {
        ProtoMatch::Any => REPR_PROTO,
        ProtoMatch::Number(n) => n,
    };
    let sport = if svc.sport == PortRange::ANY {
        REPR_SPORT
    } else {
        svc.sport.start
    };
    let dport = if svc.dport == PortRange::ANY {
        REPR_DPORT
    } else {
        svc.dport.start
    };
    (proto, sport, dport)
}

// ---------------------------------------------------------------------------
// Tests — la maquette §10.2 reconstruite en code
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use calque_model::{
        Action, Device, DeviceId, IfaceId, Interface, Policy, PolicyId, Rule, RuleId, RuleMatch,
        Vendor, ZoneId,
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

    fn iface(id: &str, addr: &str, zone: &str) -> Interface {
        let mut i = Interface::new(IfaceId::new(id));
        i.addrs = vec![net(addr)];
        i.zone = Some(ZoneId::new(zone));
        i
    }

    fn rule(
        id: &str,
        src: Vec<AddrExpr>,
        dst: Vec<AddrExpr>,
        services: Vec<ServiceExpr>,
        action: Action,
        line: u32,
    ) -> Rule {
        Rule {
            id: RuleId::new(id),
            matches: RuleMatch { src, dst, services },
            from: None,
            to: None,
            action,
            source: span(line),
        }
    }

    fn tcp_svc(dport: u16) -> ServiceExpr {
        ServiceExpr::Service(Service::tcp_dport(PortRange::single(dport)))
    }

    /// Un pare-feu à trois pattes : lan (10.0.10.0/24), dmz (10.0.20.0/24)
    /// et invités (10.0.30.0/24). Politique de SORTIE, refus par défaut.
    fn reseau(rules: Vec<Rule>) -> Network {
        let mut fw = Device::new(DeviceId::new("fw-01"), Vendor::Fortigate);
        for i in [
            iface("lan", "10.0.10.1/24", "lan"),
            iface("dmz", "10.0.20.1/24", "dmz"),
            iface("invite", "10.0.30.1/24", "invite"),
        ] {
            fw.interfaces.insert(i.id.clone(), i);
        }
        let pid = PolicyId::new("filtrage");
        fw.policies.insert(
            pid.clone(),
            Policy {
                id: pid.clone(),
                rules,
                default_action: Action::Deny,
            },
        );
        fw.pipeline.egress.push(pid);

        let mut network = Network::default();
        network.devices.insert(fw.id.clone(), fw);
        network
    }

    /// La règle 12 de la maquette : la comptabilité vers le serveur de
    /// fichiers, 445/tcp.
    fn regle_12() -> Rule {
        rule(
            "12",
            vec![AddrExpr::Net(net("10.0.10.0/24"))],
            vec![AddrExpr::Net(net("10.0.20.5/32"))],
            vec![tcp_svc(445)],
            Action::Accept,
            120,
        )
    }

    // (a) — la maquette §10.2 : une règle de refus plus large insérée
    // AVANT casse un flux attendu passant → ROMPU, avec les deux
    // justifications exactes (règle 12 avant, règle 8 après).
    #[test]
    fn flux_attendu_passant_casse_par_une_regle_inseree_avant() {
        let before = reseau(vec![regle_12()]);
        let after = reseau(vec![
            rule(
                "8",
                vec![AddrExpr::Net(net("10.0.0.0/16"))],
                vec![],
                vec![],
                Action::Deny,
                80,
            ),
            regle_12(),
        ]);
        let flows = vec![ResolvedFlow {
            name: "la comptabilité accède au serveur de fichiers".to_owned(),
            packet: tcp("10.0.10.5", "10.0.20.5", 445),
            expect_allow: Some(true),
        }];

        let report = plan(&before, &after, &flows);
        assert_eq!(report.broken.len(), 1, "rapport : {report:?}");
        assert!(report.fixed.is_empty());
        assert!(report.unchanged.is_empty());
        assert!(report.undecided.is_empty());

        let delta = &report.broken[0];
        // Avant : autorisé par la règle 12 (fw-01.conf ligne 120).
        assert_eq!(delta.before.status, FlowStatus::Allowed);
        assert_eq!(delta.before.rule, Some(RuleId::new("12")));
        assert_eq!(delta.before.source, Some(span(120)));
        // Après : refusé par la règle 8 (fw-01.conf ligne 80).
        assert_eq!(delta.after.status, FlowStatus::Denied);
        assert_eq!(delta.after.rule, Some(RuleId::new("8")));
        assert_eq!(delta.after.source, Some(span(80)));
        // L'explication textuelle cite les deux règles.
        assert!(
            delta.explanation.contains("règle 12"),
            "{}",
            delta.explanation
        );
        assert!(
            delta.explanation.contains("règle 8"),
            "{}",
            delta.explanation
        );
    }

    // (b) — un flux attendu bloqué qui devient effectivement bloqué →
    // CORRIGÉ, avec la règle fautive d'avant et l'action par défaut après.
    #[test]
    fn flux_attendu_bloque_devient_bloque_donc_corrige() {
        // Avant : une règle trop permissive laisse sortir le wifi invité.
        let before = reseau(vec![rule(
            "wifi",
            vec![AddrExpr::Net(net("10.0.30.0/24"))],
            vec![],
            vec![],
            Action::Accept,
            200,
        )]);
        // Après : la règle est retirée, le refus par défaut s'applique.
        let after = reseau(vec![]);
        let flows = vec![ResolvedFlow {
            name: "le wifi invité est isolé de l'administration".to_owned(),
            packet: tcp("10.0.30.5", "10.0.20.5", 22),
            expect_allow: Some(false),
        }];

        let report = plan(&before, &after, &flows);
        assert_eq!(report.fixed.len(), 1, "rapport : {report:?}");
        assert!(report.broken.is_empty());
        assert!(report.new_flows.is_empty());

        let delta = &report.fixed[0];
        assert_eq!(delta.before.status, FlowStatus::Allowed);
        assert_eq!(delta.before.rule, Some(RuleId::new("wifi")));
        assert_eq!(delta.after.status, FlowStatus::Denied);
        assert_eq!(delta.after.rule, None); // action par défaut
        assert!(delta.explanation.contains("action par défaut"));
    }

    // (c) — un flux au verdict identique des deux côtés reste inchangé.
    #[test]
    fn flux_au_verdict_identique_est_inchange() {
        let before = reseau(vec![regle_12()]);
        let after = reseau(vec![
            // Refus ciblé sur les invités : ne touche pas la comptabilité.
            rule(
                "9",
                vec![AddrExpr::Net(net("10.0.30.0/24"))],
                vec![],
                vec![],
                Action::Deny,
                90,
            ),
            regle_12(),
        ]);
        let flows = vec![
            ResolvedFlow {
                name: "la comptabilité accède au serveur de fichiers".to_owned(),
                packet: tcp("10.0.10.5", "10.0.20.5", 445),
                expect_allow: Some(true),
            },
            ResolvedFlow {
                name: "le wifi invité est isolé de l'administration".to_owned(),
                packet: tcp("10.0.30.5", "10.0.20.5", 22),
                expect_allow: Some(false),
            },
        ];

        let report = plan(&before, &after, &flows);
        assert_eq!(
            report.unchanged,
            vec![
                "la comptabilité accède au serveur de fichiers".to_owned(),
                "le wifi invité est isolé de l'administration".to_owned(),
            ],
            "rapport : {report:?}"
        );
        assert_eq!(report.changed_count(), 0);
    }

    // (d) — une nouvelle règle d'acceptation large, couverte par aucun
    // flux déclaré, est détectée par sonde → NOUVEAU, avec le paquet
    // précis et la règle qui l'autorise désormais.
    #[test]
    fn ouverture_non_declaree_detectee_par_sonde() {
        let before = reseau(vec![]);
        let after = reseau(vec![rule(
            "99",
            vec![AddrExpr::Net(net("10.0.30.0/24"))],
            vec![AddrExpr::Net(net("10.0.20.0/24"))],
            vec![],
            Action::Accept,
            300,
        )]);

        let report = plan(&before, &after, &[]);
        assert_eq!(report.new_flows.len(), 1, "rapport : {report:?}");
        let opening = &report.new_flows[0];
        // Le paquet de sonde précis : premiers hôtes libres des préfixes
        // (10.0.30.1 et 10.0.20.1 sont portés par le pare-feu, évités),
        // service représentatif 80/tcp pour `Any`.
        assert_eq!(opening.packet.src, ip("10.0.30.2"));
        assert_eq!(opening.packet.dst, ip("10.0.20.2"));
        assert_eq!(opening.packet.proto, 6);
        assert_eq!(opening.packet.dport, 80);
        assert_eq!(opening.port, "80/tcp");
        // La règle qui l'autorise désormais, avec sa ligne.
        assert_eq!(opening.allowed_by, Some(RuleId::new("99")));
        assert_eq!(opening.source, Some(span(300)));
    }

    // (d bis) — la même ouverture couverte par un flux déclaré n'est PAS
    // rapportée en NOUVEAU : elle est déjà jugée comme flux déclaré.
    #[test]
    fn ouverture_couverte_par_un_flux_declare_non_rapportee() {
        let before = reseau(vec![]);
        let after = reseau(vec![rule(
            "99",
            vec![AddrExpr::Net(net("10.0.30.0/24"))],
            vec![AddrExpr::Net(net("10.0.20.0/24"))],
            vec![],
            Action::Accept,
            300,
        )]);
        let flows = vec![ResolvedFlow {
            name: "ouverture voulue des invités vers la dmz".to_owned(),
            packet: tcp("10.0.30.2", "10.0.20.2", 80),
            expect_allow: Some(true),
        }];

        let report = plan(&before, &after, &flows);
        assert!(report.new_flows.is_empty(), "rapport : {report:?}");
        // Le flux déclaré, lui, est bien jugé : bloqué → passant, attendu
        // passant → CORRIGÉ.
        assert_eq!(report.fixed.len(), 1);
    }

    // (e) — un verdict Unknown (source hors de tout sous-réseau modélisé)
    // classe le flux à part : ni ROMPU, ni CORRIGÉ, ni inchangé.
    #[test]
    fn verdict_non_ferme_classe_a_part() {
        let before = reseau(vec![regle_12()]);
        let after = reseau(vec![regle_12()]);
        let flows = vec![ResolvedFlow {
            name: "flux depuis un réseau non modélisé".to_owned(),
            packet: tcp("172.16.0.5", "10.0.20.5", 445),
            expect_allow: Some(true),
        }];

        let report = plan(&before, &after, &flows);
        assert_eq!(report.undecided.len(), 1, "rapport : {report:?}");
        assert!(report.broken.is_empty());
        assert!(report.unchanged.is_empty());
        let u = &report.undecided[0];
        assert_eq!(u.before, FlowStatus::Unknown);
        assert_eq!(u.after, FlowStatus::Unknown);
        assert!(!u.diagnostics.is_empty(), "les diagnostics expliquent");
        assert!(
            !report.is_quiet(),
            "un rapport avec indécision n'est pas calme"
        );
    }

    // Un flux SANS attente déclarée dont le verdict change est rangé dans
    // `changed`, sans jugement ROMPU/CORRIGÉ.
    #[test]
    fn flux_sans_attente_change_sans_jugement() {
        let before = reseau(vec![regle_12()]);
        let after = reseau(vec![]);
        let flows = vec![ResolvedFlow {
            name: "sonde sans attente".to_owned(),
            packet: tcp("10.0.10.5", "10.0.20.5", 445),
            expect_allow: None,
        }];

        let report = plan(&before, &after, &flows);
        assert_eq!(report.changed.len(), 1, "rapport : {report:?}");
        assert!(report.broken.is_empty());
        assert!(report.fixed.is_empty());
        assert_eq!(report.changed[0].before.status, FlowStatus::Allowed);
        assert_eq!(report.changed[0].after.status, FlowStatus::Denied);
    }

    // Deux modèles identiques : rapport calme, aucune sonde ne trouve rien.
    #[test]
    fn modeles_identiques_rapport_calme() {
        let n = reseau(vec![regle_12()]);
        let flows = vec![ResolvedFlow {
            name: "la comptabilité accède au serveur de fichiers".to_owned(),
            packet: tcp("10.0.10.5", "10.0.20.5", 445),
            expect_allow: Some(true),
        }];
        let report = plan(&n, &n.clone(), &flows);
        assert!(report.is_quiet(), "rapport : {report:?}");
        assert_eq!(report.unchanged.len(), 1);
    }

    // La génération de sondes respecte la borne globale et déduplique.
    #[test]
    fn les_sondes_sont_bornees_et_dedupliquees() {
        let mut rules = Vec::new();
        // Beaucoup de règles Any/Any : l'univers borné et la borne par
        // règle contiennent l'explosion combinatoire.
        for i in 0..200 {
            rules.push(rule(
                &format!("r{i}"),
                vec![],
                vec![],
                vec![],
                Action::Accept,
                i,
            ));
        }
        let n = reseau(rules);
        let probes = build_probes(&n, &n.clone());
        assert!(probes.len() <= PROBE_BUDGET, "{} sondes", probes.len());
        let unique: HashSet<_> = probes.iter().copied().collect();
        assert_eq!(unique.len(), probes.len(), "sondes dupliquées");
    }

    // Une chaîne HOSTILE de groupes imbriqués (10 000 niveaux, sans cycle)
    // ne fait pas déborder la pile pendant la génération de sondes : la
    // profondeur de résolution est bornée.
    #[test]
    fn chaine_de_groupes_hostile_bornee() {
        use calque_model::AddrObject;

        let mut network = reseau(vec![rule(
            "1",
            vec![AddrExpr::Object(ObjectId::new("g0"))],
            vec![AddrExpr::Net(net("10.0.20.0/24"))],
            vec![],
            Action::Accept,
            10,
        )]);
        let fw = network
            .devices
            .get_mut(&DeviceId::new("fw-01"))
            .expect("fw-01");
        let depth = 10_000;
        for i in 0..depth {
            fw.objects.addresses.insert(
                ObjectId::new(format!("g{i}")),
                AddrObject::Group(vec![ObjectId::new(format!("g{}", i + 1))]),
            );
        }
        fw.objects.addresses.insert(
            ObjectId::new(format!("g{depth}")),
            AddrObject::Nets(vec![net("10.0.30.0/24")]),
        );

        // Ni panique ni débordement : le rapport sort (meilleure-effort,
        // le moteur diagnostiquera l'objet à l'évaluation si besoin).
        let report = plan(&network, &network.clone(), &[]);
        assert!(report.new_flows.is_empty(), "modèles identiques");
    }

    // Le représentant d'un service : protocole de la règle, premier port
    // de chaque plage, représentants documentés pour Any.
    #[test]
    fn representant_de_service() {
        assert_eq!(
            service_repr(&Service::tcp_dport(PortRange::single(445))),
            (6, REPR_SPORT, 445)
        );
        assert_eq!(
            service_repr(&Service {
                proto: ProtoMatch::Number(17),
                sport: PortRange {
                    start: 500,
                    end: 600
                },
                dport: PortRange { start: 53, end: 53 },
            }),
            (17, 500, 53)
        );
        assert_eq!(
            service_repr(&Service {
                proto: ProtoMatch::Any,
                sport: PortRange::ANY,
                dport: PortRange::ANY,
            }),
            (REPR_PROTO, REPR_SPORT, REPR_DPORT)
        );
    }

    // Le premier hôte libre évite les adresses portées par un équipement.
    #[test]
    fn premier_hote_libre_evite_les_equipements() {
        let mut avoid = BTreeSet::new();
        avoid.insert(ip("10.0.20.1"));
        avoid.insert(ip("10.0.20.2"));
        assert_eq!(probe_host(&net("10.0.20.0/24"), &avoid), ip("10.0.20.3"));
        // /32 : l'adresse elle-même, il n'y a rien d'autre.
        assert_eq!(probe_host(&net("10.0.20.5/32"), &avoid), ip("10.0.20.5"));
    }
}
