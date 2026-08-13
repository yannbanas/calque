//! calque-report — les sorties : texte, JSON, JUnit.
//!
//! « La trace est le produit » (§5.2) : ce crate transforme une trace ou
//! un résultat de test de flux en quelque chose qu'un humain (texte), un
//! programme (JSON) ou une chaîne d'intégration continue (JUnit XML) peut
//! consommer.
//!
//! Les types d'entrée sont des « vues » construites uniquement sur
//! `calque-model` : `calque-cli` adapte les types réels du moteur
//! (`calque_engine::Trace`, etc.) vers ces vues. Exception : les
//! résultats de flux (`FlowResult`/`FlowStatus`) sont produits tels quels
//! par `calque_policy::evaluate_flow` — ils vivent là-bas et sont
//! ré-exportés ici pour compatibilité. Le vocabulaire des résultats de
//! flux (ROMPU / CORRIGÉ / NOUVEAU) est celui du §10.2.
//!
//! La sortie JUnit XML (testsuite / testcase / failure) est écrite à la
//! main, sans dépendance supplémentaire.

use std::fmt;
use std::fmt::Write as _;

use calque_model::{ConcretePacket, Diagnostic, Severity, SourceSpan};
use calque_space::{Cube, HeaderSet, PortRanges, PrefixSet, ProtoSet};
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Vues d'une trace (§5.2)
// ---------------------------------------------------------------------------

/// Verdict d'accessibilité, côté rendu.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VerdictView {
    Allowed,
    Denied,
    NoRoute,
    Loop,
    Unknown,
}

impl VerdictView {
    /// Libellé français du verdict.
    pub fn label(self) -> &'static str {
        match self {
            VerdictView::Allowed => "autorisé",
            VerdictView::Denied => "refusé",
            VerdictView::NoRoute => "pas de route",
            VerdictView::Loop => "boucle de routage",
            VerdictView::Unknown => "indéterminé (modèle partiel sur le chemin)",
        }
    }
}

impl fmt::Display for VerdictView {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// Étape de la séquence de traitement (§3.1) où une décision est prise.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StageView {
    IngressFilter,
    Nat,
    Route,
    EgressFilter,
}

impl StageView {
    pub fn label(self) -> &'static str {
        match self {
            StageView::IngressFilter => "filtre d'entrée",
            StageView::Nat => "traduction d'adresse",
            StageView::Route => "routage",
            StageView::EgressFilter => "filtre de sortie",
        }
    }
}

impl fmt::Display for StageView {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// Une décision d'un équipement, avec sa justification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionView {
    pub stage: StageView,
    /// Identifiant de la règle responsable, chez le constructeur.
    pub rule: Option<String>,
    /// Fichier + ligne d'origine de la règle.
    pub source: Option<SourceSpan>,
    /// Ce qui a été décidé, en clair (« accepté », « refusé », « via 10.0.20.0/24 »…).
    pub outcome: String,
    /// Règles antérieures qui masquent (« pourquoi ma règle ne matche pas »).
    pub shadowed_by: Vec<String>,
}

/// Un saut de la trace : un équipement traversé.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HopView {
    pub device: String,
    pub in_iface: String,
    pub out_iface: Option<String>,
    /// En-tête à l'entrée / à la sortie (après traduction d'adresse).
    pub header_in: Option<ConcretePacket>,
    pub header_out: Option<ConcretePacket>,
    pub decisions: Vec<DecisionView>,
}

/// Une trace complète, prête à rendre.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceView {
    pub verdict: VerdictView,
    /// Précision OBLIGATOIRE à afficher à côté du verdict quand il en porte
    /// une — le cas d'usage : « sort du périmètre modélisé via wan1,
    /// passerelle 79.141.8.65 ». Un « autorisé » en sortie de périmètre ne
    /// doit jamais laisser croire que la destination est modélisée.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verdict_note: Option<String>,
    pub hops: Vec<HopView>,
}

impl TraceView {
    /// La ligne de verdict, note comprise : « autorisé (sort du périmètre
    /// modélisé via wan1) » — jamais un « autorisé » nu quand une note
    /// existe.
    pub fn verdict_line(&self) -> String {
        match &self.verdict_note {
            Some(note) => format!("{} ({note})", self.verdict),
            None => self.verdict.to_string(),
        }
    }
}

/// Rendu texte d'une trace, règle par règle (`calque path --explain`).
pub fn render_trace_text(trace: &TraceView) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "Verdict : {}", trace.verdict_line());
    for (i, hop) in trace.hops.iter().enumerate() {
        let _ = write!(
            out,
            "\n  {}. {}  entrée {}",
            i + 1,
            hop.device,
            hop.in_iface
        );
        if let Some(out_iface) = &hop.out_iface {
            let _ = write!(out, " → sortie {out_iface}");
        }
        let _ = writeln!(out);
        if let (Some(hin), Some(hout)) = (&hop.header_in, &hop.header_out) {
            if hin != hout {
                let _ = writeln!(
                    out,
                    "     en-tête réécrit : {} → {}",
                    packet_label(hin),
                    packet_label(hout)
                );
            }
        }
        for d in &hop.decisions {
            let _ = write!(out, "     {} : {}", d.stage, d.outcome);
            if let Some(rule) = &d.rule {
                let _ = write!(out, " (règle {rule}");
                if let Some(span) = &d.source {
                    let _ = write!(out, ", {span}");
                }
                let _ = write!(out, ")");
            } else if let Some(span) = &d.source {
                let _ = write!(out, " ({span})");
            }
            let _ = writeln!(out);
            if !d.shadowed_by.is_empty() {
                let _ = writeln!(
                    out,
                    "       masquée par les règles antérieures : {}",
                    d.shadowed_by.join(", ")
                );
            }
        }
    }
    out
}

/// Rendu JSON d'une trace.
pub fn render_trace_json(trace: &TraceView) -> String {
    serde_json::to_string_pretty(trace).unwrap_or_else(|e| {
        // Sérialiser ces types ne peut pas échouer en pratique ; on reste
        // néanmoins sans panique.
        format!("{{\"erreur\":\"échec de sérialisation : {e}\"}}")
    })
}

/// Libellé français d'un numéro de protocole IP.
fn proto_label(proto: u8) -> String {
    match proto {
        1 => "icmp".to_owned(),
        6 => "tcp".to_owned(),
        17 => "udp".to_owned(),
        58 => "icmpv6".to_owned(),
        n => format!("proto {n}"),
    }
}

/// Libellé d'un paquet concret : `10.0.10.5 → 10.0.20.5:445/tcp`.
pub fn format_packet(p: &ConcretePacket) -> String {
    format!("{} → {}:{}/{}", p.src, p.dst, p.dport, proto_label(p.proto))
}

fn packet_label(p: &ConcretePacket) -> String {
    format_packet(p)
}

// ---------------------------------------------------------------------------
// Résumé lisible d'un HeaderSet (mode symbolique, §5.3)
// ---------------------------------------------------------------------------

/// Nombre maximal de pavés affichés par ensemble ; au-delà,
/// « … et N autres pavé(s) ».
pub const MAX_CUBES_SHOWN: usize = 10;

/// Nombre maximal de préfixes affichés par dimension d'un pavé ; au-delà,
/// « … (+N) ».
const MAX_PREFIXES_SHOWN: usize = 6;

/// Résumé d'une dimension adresse : `*` pour l'espace entier, sinon les
/// préfixes (borné), les /32 et /128 rendus en adresse nue.
fn prefixes_label(set: &PrefixSet) -> String {
    if *set == PrefixSet::full() {
        return "*".to_owned();
    }
    let mut parts: Vec<String> = set
        .prefixes()
        .iter()
        .take(MAX_PREFIXES_SHOWN)
        .map(|p| {
            if p.prefix_len() == p.max_prefix_len() {
                p.addr().to_string()
            } else {
                p.to_string()
            }
        })
        .collect();
    let hidden = set.prefixes().len().saturating_sub(MAX_PREFIXES_SHOWN);
    if hidden > 0 {
        parts.push(format!("… (+{hidden})"));
    }
    parts.join(", ")
}

/// Résumé d'un ensemble de ports : `*` pour tous, sinon `445` ou `7000-7010`.
fn ports_label(set: &PortRanges) -> String {
    if *set == PortRanges::full() {
        return "*".to_owned();
    }
    set.ranges()
        .iter()
        .map(|r| {
            if r.start == r.end {
                r.start.to_string()
            } else {
                format!("{}-{}", r.start, r.end)
            }
        })
        .collect::<Vec<_>>()
        .join(",")
}

/// Résumé d'un ensemble de protocoles : `any` pour tous, sinon les noms.
fn protos_label(set: &ProtoSet) -> String {
    if *set == ProtoSet::full() {
        return "any".to_owned();
    }
    let mut names: Vec<String> = Vec::new();
    for proto in 0..=255u8 {
        if set.contains_proto(proto) {
            names.push(proto_label(proto));
            if names.len() > 4 {
                // Résumé volontairement court : au-delà de quatre
                // protocoles, seul le décompte est utile.
                return format!("{} protocoles", set.len());
            }
        }
    }
    names.join(",")
}

/// Résumé d'un pavé : `10.0.0.0/24 → 10.0.20.5:445/tcp`.
///
/// Le port source n'est mentionné que s'il est contraint (cas rare).
pub fn format_cube(cube: &Cube) -> String {
    let service = if cube.proto == ProtoSet::full() && cube.dport == PortRanges::full() {
        ":any".to_owned()
    } else {
        format!(
            ":{}/{}",
            ports_label(&cube.dport),
            protos_label(&cube.proto)
        )
    };
    let mut out = format!(
        "{} → {}{}",
        prefixes_label(&cube.src),
        prefixes_label(&cube.dst),
        service
    );
    if cube.sport != PortRanges::full() {
        let _ = write!(out, " (port source {})", ports_label(&cube.sport));
    }
    out
}

/// Résumé lisible d'un [`HeaderSet`] : une ligne par pavé
/// (« 10.0.0.0/24 → 10.0.20.5:445/tcp »), borné à [`MAX_CUBES_SHOWN`]
/// pavés puis « … et N autres pavé(s) ». Vide → « (ensemble vide) ».
pub fn format_headerset(set: &HeaderSet) -> Vec<String> {
    if set.cubes().is_empty() {
        return vec!["(ensemble vide)".to_owned()];
    }
    let mut lines: Vec<String> = set
        .cubes()
        .iter()
        .take(MAX_CUBES_SHOWN)
        .map(format_cube)
        .collect();
    let hidden = set.cubes().len().saturating_sub(MAX_CUBES_SHOWN);
    if hidden > 0 {
        lines.push(format!("… et {hidden} autre(s) pavé(s)"));
    }
    lines
}

// ---------------------------------------------------------------------------
// Résultats de tests de flux (§10.1, vocabulaire §10.2)
// ---------------------------------------------------------------------------

// Les types `FlowResult` et `FlowStatus` vivent désormais dans
// `calque-policy` (crate PUR), au plus près de l'évaluation qui les
// produit (`evaluate_flow`) : les rendus ci-dessous restent ici, et les
// ré-exports préservent la compatibilité des consommateurs existants.
pub use calque_policy::{FlowResult, FlowStatus};

/// Rendu texte des résultats de flux.
pub fn render_flow_results_text(results: &[FlowResult]) -> String {
    let mut out = String::new();
    for r in results {
        let _ = writeln!(out, "  {:<8}{}", r.status.prefix(), r.name);
        let _ = writeln!(out, "          {}", r.flow);
        if let Some(actual) = &r.actual {
            let _ = writeln!(
                out,
                "          attendu : {} — obtenu : {}",
                r.expected, actual
            );
        }
        if let Some(detail) = &r.detail {
            let _ = writeln!(out, "          {detail}");
        }
    }
    let failures = results.iter().filter(|r| r.status.is_failure()).count();
    let _ = write!(out, "\n{} flux testé(s), ", results.len());
    if failures == 0 {
        let _ = writeln!(out, "aucun échec.");
    } else {
        let _ = writeln!(out, "{failures} échec(s).");
    }
    out
}

/// Rendu JSON des résultats de flux.
pub fn render_flow_results_json(results: &[FlowResult]) -> String {
    #[derive(Serialize)]
    struct Summary<'a> {
        tests: usize,
        failures: usize,
        results: &'a [FlowResult],
    }
    let s = Summary {
        tests: results.len(),
        failures: results.iter().filter(|r| r.status.is_failure()).count(),
        results,
    };
    serde_json::to_string_pretty(&s)
        .unwrap_or_else(|e| format!("{{\"erreur\":\"échec de sérialisation : {e}\"}}"))
}

// ---------------------------------------------------------------------------
// Vue d'un rapport de `calque plan` (§10.2)
// ---------------------------------------------------------------------------

/// Une ligne du rapport de `calque plan` : un flux dont le comportement
/// change, un flux non ferme, ou une ouverture non déclarée.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanEntry {
    /// Nom du flux (ou libellé de l'ouverture détectée).
    pub name: String,
    /// Libellé du paquet ou du flux : `10.0.10.5 → 10.0.20.5:445/tcp`.
    pub flow: String,
    /// Justification, éventuellement multi-ligne (avant/après, règles
    /// décisives avec fichier + ligne).
    pub detail: Option<String>,
}

/// La vue du rapport de `calque plan`, prête à rendre (§10.2). Comme pour
/// les traces, `calque-cli` adapte les types réels de `calque-diff` vers
/// cette vue.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanView {
    /// ROMPU — le flux déclaré dévie désormais de son attente.
    pub broken: Vec<PlanEntry>,
    /// CORRIGÉ — le flux déclaré redevient conforme.
    pub fixed: Vec<PlanEntry>,
    /// CHANGÉ — le verdict change sans jugement (flux sans attente, ou
    /// changement qui n'inverse pas passe/bloqué).
    pub changed: Vec<PlanEntry>,
    /// NON FERME — le modèle ne permet pas de conclure (§6.3).
    pub undecided: Vec<PlanEntry>,
    /// NOUVEAU — ouverture qu'aucun flux déclaré ne couvrait.
    pub new_flows: Vec<PlanEntry>,
    /// Noms des flux déclarés dont le comportement ne change pas.
    pub unchanged: Vec<String>,
}

impl PlanView {
    /// Nombre de flux déclarés dont le comportement change.
    pub fn changed_count(&self) -> usize {
        self.broken.len() + self.fixed.len() + self.changed.len()
    }
}

fn render_plan_entry(out: &mut String, prefix: &str, e: &PlanEntry) {
    let _ = writeln!(out, "  {prefix:<9}{}", e.name);
    let _ = writeln!(out, "           {}", e.flow);
    if let Some(detail) = &e.detail {
        for line in detail.lines() {
            let _ = writeln!(out, "           {line}");
        }
    }
    let _ = writeln!(out);
}

/// Rendu texte d'un rapport de `calque plan`, dans l'esprit de la
/// maquette §10.2 (ROMPU / CORRIGÉ / CHANGÉ / NON FERME / NOUVEAU,
/// puis le décompte des flux inchangés).
pub fn render_plan_text(view: &PlanView) -> String {
    let mut out = String::new();
    let changed = view.changed_count();
    if changed > 0 {
        let _ = writeln!(out, "{changed} flux change(nt) de comportement :\n");
    }
    for (prefix, entries) in [
        ("ROMPU", &view.broken),
        ("CORRIGÉ", &view.fixed),
        ("CHANGÉ", &view.changed),
        ("NON FERME", &view.undecided),
        ("NOUVEAU", &view.new_flows),
    ] {
        for e in entries {
            render_plan_entry(&mut out, prefix, e);
        }
    }
    if changed == 0 && view.new_flows.is_empty() && view.undecided.is_empty() {
        let _ = writeln!(out, "Aucun changement de comportement détecté.");
    }
    let _ = writeln!(out, "{} flux inchangé(s).", view.unchanged.len());
    out
}

/// Rendu JUnit XML minimal (testsuite / testcase / failure), écrit à la
/// main. Suffisant pour GitLab CI, Jenkins et consorts.
pub fn render_flow_results_junit(suite_name: &str, results: &[FlowResult]) -> String {
    let failures = results.iter().filter(|r| r.status.is_failure()).count();
    let mut out = String::new();
    let _ = writeln!(out, r#"<?xml version="1.0" encoding="UTF-8"?>"#);
    let _ = writeln!(
        out,
        r#"<testsuite name="{}" tests="{}" failures="{}">"#,
        xml_escape(suite_name),
        results.len(),
        failures
    );
    for r in results {
        let name = xml_escape(&r.name);
        if r.status.is_failure() {
            let message = match &r.actual {
                Some(actual) => format!(
                    "{} : attendu {}, obtenu {}",
                    r.status.prefix(),
                    r.expected,
                    actual
                ),
                None => format!("{} : attendu {}", r.status.prefix(), r.expected),
            };
            let mut body = r.flow.clone();
            if let Some(detail) = &r.detail {
                body.push('\n');
                body.push_str(detail);
            }
            let _ = writeln!(out, r#"  <testcase name="{name}">"#);
            let _ = writeln!(
                out,
                r#"    <failure message="{}">{}</failure>"#,
                xml_escape(&message),
                xml_escape(&body)
            );
            let _ = writeln!(out, "  </testcase>");
        } else {
            let _ = writeln!(out, r#"  <testcase name="{name}"/>"#);
        }
    }
    let _ = writeln!(out, "</testsuite>");
    out
}

/// Échappement XML des cinq caractères réservés.
fn xml_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            _ => out.push(c),
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Vue d'un rapport `calque reach` (mode symbolique, §5.3)
// ---------------------------------------------------------------------------

/// Une décision de la chaîne d'un flux symbolique, étiquetée par
/// l'équipement qui l'a prise.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReachDecisionView {
    pub device: String,
    pub decision: DecisionView,
}

/// Un flux autorisé trouvé par le mode symbolique : point d'entrée,
/// ensemble, exemple concret et chaîne des règles décisives.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReachFlowView {
    /// Le point d'entrée : `fw-01/lan`.
    pub entry: String,
    /// Le sous-ensemble autorisé (exprimé après traductions d'adresse).
    pub set: HeaderSet,
    /// Un paquet concret exemple du sous-ensemble (§4.1).
    pub sample: ConcretePacket,
    pub decisions: Vec<ReachDecisionView>,
}

/// Le rapport de `calque reach`, prêt à rendre.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReachView {
    /// La question posée, déjà libellée :
    /// « tout ce qui peut atteindre 10.0.20.5:445/tcp ».
    pub question: String,
    pub flows: Vec<ReachFlowView>,
    /// Parts non décidables et incidents (§6.3) : affichés honnêtement,
    /// le rapport est incomplet s'il y a des erreurs.
    pub diagnostics: Vec<Diagnostic>,
}

/// La justification finale d'un flux : la dernière décision portée par une
/// règle — « autorisé par la règle 2 (fw-01.conf ligne 82) ».
fn reach_flow_justification(flow: &ReachFlowView) -> Option<String> {
    flow.decisions
        .iter()
        .rev()
        .find(|d| d.decision.rule.is_some())
        .map(|d| {
            let rule = d.decision.rule.as_deref().unwrap_or("?");
            match &d.decision.source {
                Some(span) => format!("autorisé par la règle {rule} ({span})"),
                None => format!("autorisé par la règle {rule}"),
            }
        })
}

fn severity_label(s: Severity) -> &'static str {
    match s {
        Severity::Info => "info",
        Severity::Warning => "avertissement",
        Severity::Error => "erreur",
    }
}

fn render_diagnostics(out: &mut String, diagnostics: &[Diagnostic]) {
    for d in diagnostics {
        let label = severity_label(d.severity);
        match &d.span {
            Some(span) => {
                let _ = writeln!(out, "  [{label}] {span} : {}", d.message);
            }
            None => {
                let _ = writeln!(out, "  [{label}] {}", d.message);
            }
        }
    }
}

fn render_decision_line(out: &mut String, indent: &str, device: &str, d: &DecisionView) {
    let _ = write!(out, "{indent}{device} : {} : {}", d.stage, d.outcome);
    if let Some(rule) = &d.rule {
        let _ = write!(out, " (règle {rule}");
        if let Some(span) = &d.source {
            let _ = write!(out, ", {span}");
        }
        let _ = write!(out, ")");
    } else if let Some(span) = &d.source {
        let _ = write!(out, " ({span})");
    }
    let _ = writeln!(out);
    if !d.shadowed_by.is_empty() {
        let _ = writeln!(
            out,
            "{indent}  masquée par les règles antérieures : {}",
            d.shadowed_by.join(", ")
        );
    }
}

/// Rendu texte d'un rapport de `calque reach` : pour chaque flux trouvé,
/// le point d'entrée, l'ensemble résumé, un paquet exemple et la chaîne
/// des règles décisives (fichier + ligne).
pub fn render_reach_text(view: &ReachView) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "{} :", view.question);
    for (i, flow) in view.flows.iter().enumerate() {
        let _ = writeln!(out, "\n  {}. entrée {}", i + 1, flow.entry);
        let set_lines = format_headerset(&flow.set);
        let _ = writeln!(out, "     ensemble : {}", set_lines[0]);
        for line in &set_lines[1..] {
            let _ = writeln!(out, "                {line}");
        }
        let _ = writeln!(out, "     exemple  : {}", format_packet(&flow.sample));
        if let Some(justification) = reach_flow_justification(flow) {
            let _ = writeln!(out, "     {justification}");
        }
        if !flow.decisions.is_empty() {
            let _ = writeln!(out, "     chaîne des décisions :");
            for d in &flow.decisions {
                render_decision_line(&mut out, "       ", &d.device, &d.decision);
            }
        }
    }
    if view.flows.is_empty() {
        let _ = writeln!(out, "\nAucun flux autorisé trouvé.");
    } else {
        let _ = writeln!(out, "\n{} flux autorisé(s).", view.flows.len());
    }
    if !view.diagnostics.is_empty() {
        let _ = writeln!(
            out,
            "\n{} part(s) non décidable(s) ou incident(s) — le rapport est \
             incomplet sur ces parts (§6.3, jamais devinées) :",
            view.diagnostics.len()
        );
        render_diagnostics(&mut out, &view.diagnostics);
    }
    out
}

/// Rendu JSON d'un rapport de `calque reach`.
pub fn render_reach_json(view: &ReachView) -> String {
    serde_json::to_string_pretty(view)
        .unwrap_or_else(|e| format!("{{\"erreur\":\"échec de sérialisation : {e}\"}}"))
}

// ---------------------------------------------------------------------------
// Vue d'un rapport de règles mortes (S6)
// ---------------------------------------------------------------------------

/// Pourquoi la règle est morte, côté rendu.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeadRuleKindView {
    /// Entièrement couverte par l'union des règles antérieures.
    Shadowed,
    /// Le pavé de la règle est vide (objets ou groupes vides).
    EmptySet,
}

impl DeadRuleKindView {
    /// Préfixe affiché dans la sortie texte.
    pub fn prefix(self) -> &'static str {
        match self {
            DeadRuleKindView::Shadowed => "MASQUÉE",
            DeadRuleKindView::EmptySet => "ENSEMBLE VIDE",
        }
    }
}

impl fmt::Display for DeadRuleKindView {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.prefix())
    }
}

/// Une règle masquante : identifiant et origine de configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MaskerView {
    pub rule: String,
    pub source: SourceSpan,
}

/// Une règle morte, avec sa justification complète.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeadRuleView {
    pub device: String,
    pub policy: String,
    pub rule: String,
    /// Fichier + ligne de la règle morte.
    pub source: SourceSpan,
    pub kind: DeadRuleKindView,
    /// Les règles antérieures qui la masquent (vide pour `EmptySet`).
    pub masked_by: Vec<MaskerView>,
    /// Un paquet concret que la règle aurait traité mais qu'un masque
    /// capte avant elle (`None` pour `EmptySet`).
    pub sample: Option<ConcretePacket>,
}

/// Le rapport des règles mortes, prêt à rendre.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeadRulesView {
    /// Nombre d'équipements analysés.
    pub devices: usize,
    pub rules: Vec<DeadRuleView>,
    /// Règles exclues de l'analyse (objet irrésoluble hors ligne — fqdn,
    /// geography… — ou cycle), jamais déclarées mortes ni comptées comme
    /// masques (§6.3). Messages prêts à afficher.
    #[serde(default)]
    pub excluded: Vec<String>,
}

/// Rendu texte du rapport des règles mortes.
pub fn render_dead_rules_text(view: &DeadRulesView) -> String {
    let mut out = String::new();
    for r in &view.rules {
        let _ = writeln!(
            out,
            "  {:<14}règle {} (politique {}, équipement « {} ») — {}",
            r.kind.prefix(),
            r.rule,
            r.policy,
            r.device,
            r.source
        );
        match r.kind {
            DeadRuleKindView::EmptySet => {
                let _ = writeln!(
                    out,
                    "                ne peut correspondre à aucun paquet \
                     (objets ou groupes vides)"
                );
            }
            DeadRuleKindView::Shadowed => {
                let maskers = r
                    .masked_by
                    .iter()
                    .map(|m| format!("la règle {} ({})", m.rule, m.source))
                    .collect::<Vec<_>>()
                    .join(", ");
                let _ = writeln!(out, "                masquée par : {maskers}");
                if let Some(sample) = &r.sample {
                    let _ = writeln!(
                        out,
                        "                paquet témoin : {} (capté par un masque \
                         avant elle)",
                        format_packet(sample)
                    );
                }
            }
        }
        let _ = writeln!(out);
    }
    if view.rules.is_empty() {
        let _ = writeln!(
            out,
            "Aucune règle morte : chaque règle peut encore décider d'au moins \
             un paquet."
        );
    }
    if !view.excluded.is_empty() {
        let _ = writeln!(
            out,
            "\n{} règle(s) EXCLUE(S) de l'analyse (objets irrésolubles hors \
             ligne — jamais déclarées mortes, jamais comptées comme masques, \
             §6.3) :",
            view.excluded.len()
        );
        for e in &view.excluded {
            let _ = writeln!(out, "  - {e}");
        }
    }
    let _ = writeln!(
        out,
        "{} équipement(s) analysé(s), {} règle(s) morte(s), {} exclue(s).",
        view.devices,
        view.rules.len(),
        view.excluded.len()
    );
    out
}

/// Rendu JSON du rapport des règles mortes.
pub fn render_dead_rules_json(view: &DeadRulesView) -> String {
    serde_json::to_string_pretty(view)
        .unwrap_or_else(|e| format!("{{\"erreur\":\"échec de sérialisation : {e}\"}}"))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn exemples() -> Vec<FlowResult> {
        vec![
            FlowResult {
                name: "la comptabilité accède au serveur de fichiers".into(),
                flow: "10.0.10.0/24 → 10.0.20.5:445/tcp".into(),
                expected: "allow".into(),
                actual: Some("deny".into()),
                status: FlowStatus::Broken,
                detail: Some("refusé par la politique 8, fw-01.conf ligne 812".into()),
            },
            FlowResult {
                name: "le wifi invité est isolé de l'administration".into(),
                flow: "vlan-invite → vlan-admin:any".into(),
                expected: "deny".into(),
                actual: Some("deny".into()),
                status: FlowStatus::Ok,
                detail: None,
            },
        ]
    }

    #[test]
    fn rendu_texte_des_flux() {
        let txt = render_flow_results_text(&exemples());
        assert!(txt.contains("ROMPU"), "préfixe ROMPU absent : {txt}");
        assert!(txt.contains("OK"));
        assert!(txt.contains("la comptabilité accède au serveur de fichiers"));
        assert!(txt.contains("attendu : allow — obtenu : deny"));
        assert!(txt.contains("refusé par la politique 8, fw-01.conf ligne 812"));
        assert!(txt.contains("2 flux testé(s), 1 échec(s)."));
    }

    #[test]
    fn rendu_junit_des_flux() {
        let mut results = exemples();
        // Un nom avec des caractères réservés XML, pour vérifier l'échappement.
        results[0].name = "flux <cassé> & \"critique\"".into();
        let xml = render_flow_results_junit("calque", &results);

        assert!(xml.starts_with(r#"<?xml version="1.0" encoding="UTF-8"?>"#));
        assert!(xml.contains(r#"<testsuite name="calque" tests="2" failures="1">"#));
        assert!(xml.contains(r#"<testcase name="flux &lt;cassé&gt; &amp; &quot;critique&quot;">"#));
        assert!(xml.contains(r#"<failure message="ROMPU : attendu allow, obtenu deny">"#));
        assert!(xml.contains("</testsuite>"));
        // Le cas qui passe est auto-fermant, sans <failure> ; l'apostrophe
        // est échappée.
        assert!(
            xml.contains(r#"<testcase name="le wifi invité est isolé de l&apos;administration"/>"#)
        );
    }

    #[test]
    fn rendu_texte_dune_trace() {
        let trace = TraceView {
            verdict: VerdictView::Denied,
            verdict_note: None,
            hops: vec![HopView {
                device: "fw-01".into(),
                in_iface: "port1".into(),
                out_iface: None,
                header_in: None,
                header_out: None,
                decisions: vec![DecisionView {
                    stage: StageView::IngressFilter,
                    rule: Some("34".into()),
                    source: Some(SourceSpan::new("fw-01.conf", 812)),
                    outcome: "refusé".into(),
                    shadowed_by: vec!["12".into()],
                }],
            }],
        };
        let txt = render_trace_text(&trace);
        assert!(txt.contains("Verdict : refusé"));
        assert!(txt.contains("1. fw-01  entrée port1"));
        assert!(txt.contains("filtre d'entrée : refusé (règle 34, fw-01.conf ligne 812)"));
        assert!(txt.contains("masquée par les règles antérieures : 12"));
    }

    #[test]
    fn rendu_texte_dun_plan() {
        let view = PlanView {
            broken: vec![PlanEntry {
                name: "la comptabilité accède au serveur de fichiers".into(),
                flow: "10.0.10.5 → 10.0.20.5:445/tcp".into(),
                detail: Some(
                    "avant : autorisé par la règle 12 (fw-01.conf ligne 120)\n\
                     après : refusé par la règle 8 (fw-01-nouveau.conf ligne 80)"
                        .into(),
                ),
            }],
            fixed: vec![],
            changed: vec![],
            undecided: vec![],
            new_flows: vec![PlanEntry {
                name: "10.0.30.0/24 → 10.0.20.0/24:80/tcp devient joignable".into(),
                flow: "10.0.30.1 → 10.0.20.1:80/tcp".into(),
                detail: Some("n'était couvert par aucun flux déclaré".into()),
            }],
            unchanged: vec!["le wifi invité est isolé de l'administration".into()],
        };
        let txt = render_plan_text(&view);
        assert!(txt.contains("1 flux change(nt) de comportement :"), "{txt}");
        assert!(txt.contains("ROMPU"), "{txt}");
        assert!(txt.contains("avant : autorisé par la règle 12"), "{txt}");
        assert!(txt.contains("après : refusé par la règle 8"), "{txt}");
        assert!(txt.contains("NOUVEAU"), "{txt}");
        assert!(txt.contains("devient joignable"), "{txt}");
        assert!(txt.contains("1 flux inchangé(s)."), "{txt}");
    }

    #[test]
    fn rendu_dun_plan_calme() {
        let view = PlanView::default();
        let txt = render_plan_text(&view);
        assert!(
            txt.contains("Aucun changement de comportement détecté."),
            "{txt}"
        );
        assert!(txt.contains("0 flux inchangé(s)."), "{txt}");
    }

    #[test]
    fn rendu_json_dune_trace() {
        let trace = TraceView {
            verdict: VerdictView::Allowed,
            verdict_note: None,
            hops: vec![],
        };
        let json = render_trace_json(&trace);
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["verdict"], "Allowed");
        // Sans note, le champ est absent du JSON (compatibilité).
        assert!(v.get("verdict_note").is_none());
    }

    /// La sortie de périmètre modélisé : la ligne de verdict porte la note
    /// (« autorisé (sort du périmètre modélisé via wan1…) »), jamais un
    /// « autorisé » nu qui laisserait croire que la destination est
    /// modélisée.
    #[test]
    fn rendu_dune_trace_en_sortie_de_perimetre() {
        let trace = TraceView {
            verdict: VerdictView::Allowed,
            verdict_note: Some(
                "sort du périmètre modélisé via wan1, passerelle 79.141.8.65".into(),
            ),
            hops: vec![HopView {
                device: "fw-01".into(),
                in_iface: "lan".into(),
                out_iface: Some("wan1".into()),
                header_in: None,
                header_out: None,
                decisions: vec![DecisionView {
                    stage: StageView::Route,
                    rule: None,
                    source: None,
                    outcome: "sort du périmètre modélisé via wan1 (passerelle 79.141.8.65)".into(),
                    shadowed_by: vec![],
                }],
            }],
        };
        let txt = render_trace_text(&trace);
        assert!(
            txt.contains(
                "Verdict : autorisé (sort du périmètre modélisé via wan1, \
                 passerelle 79.141.8.65)"
            ),
            "{txt}"
        );
        assert!(
            txt.contains("routage : sort du périmètre modélisé via wan1 (passerelle 79.141.8.65)"),
            "{txt}"
        );
        // JSON : la note est sérialisée quand elle existe.
        let v: serde_json::Value = serde_json::from_str(&render_trace_json(&trace)).unwrap();
        assert!(v["verdict_note"]
            .as_str()
            .unwrap()
            .contains("sort du périmètre"));
    }

    // -- Résumé d'un HeaderSet ------------------------------------------

    fn net(s: &str) -> ipnet::IpNet {
        s.parse().expect("préfixe de test valide")
    }

    #[test]
    fn resume_dun_flux_simple() {
        // L'exemple de l'énoncé : « 10.0.0.0/24 → 10.0.20.5:445/tcp ».
        let set = HeaderSet::flow(
            net("10.0.0.0/24"),
            net("10.0.20.5/32"),
            6,
            calque_model::PortRange::single(445),
        );
        assert_eq!(
            format_headerset(&set),
            vec!["10.0.0.0/24 → 10.0.20.5:445/tcp".to_owned()]
        );
    }

    #[test]
    fn resume_borne_les_paves_et_les_cas_limites() {
        use calque_space::HeaderSpace;
        // Vide.
        assert_eq!(
            format_headerset(&HeaderSet::empty()),
            vec!["(ensemble vide)"]
        );
        // Plein : tout est « * », le service est « any ».
        assert_eq!(format_headerset(&HeaderSet::full()), vec!["* → *:any"]);
        // Plus de MAX_CUBES_SHOWN pavés non fusionnables : l'affichage est
        // borné avec le décompte du reste.
        let cubes = (0..(MAX_CUBES_SHOWN as u16 + 3)).map(|i| {
            Cube::from_flow(
                net(&format!("10.{i}.0.0/24")),
                net(&format!("10.20.{i}.5/32")),
                6,
                calque_model::PortRange::single(400 + i),
            )
        });
        let set = HeaderSet::from_cubes(cubes);
        let lines = format_headerset(&set);
        assert_eq!(lines.len(), MAX_CUBES_SHOWN + 1);
        assert_eq!(lines.last().unwrap(), "… et 3 autre(s) pavé(s)");
    }

    #[test]
    fn resume_dun_pave_avec_port_source_et_plage() {
        let cube = Cube::new(
            calque_space::PrefixSet::from_net(net("10.0.0.0/24")),
            calque_space::PrefixSet::from_net(net("10.0.20.5/32")),
            ProtoSet::single(17),
            PortRanges::from_range(calque_model::PortRange {
                start: 1024,
                end: 65535,
            }),
            PortRanges::from_range(calque_model::PortRange {
                start: 7000,
                end: 7010,
            }),
        );
        assert_eq!(
            format_cube(&cube),
            "10.0.0.0/24 → 10.0.20.5:7000-7010/udp (port source 1024-65535)"
        );
    }

    // -- Rendu d'un rapport reach ---------------------------------------

    fn reach_exemple() -> ReachView {
        ReachView {
            question: "Tout ce qui peut atteindre 10.0.20.5:445/tcp".into(),
            flows: vec![ReachFlowView {
                entry: "fw-01/lan".into(),
                set: HeaderSet::flow(
                    net("10.0.10.0/24"),
                    net("10.0.20.5/32"),
                    6,
                    calque_model::PortRange::single(445),
                ),
                sample: ConcretePacket {
                    src: "10.0.10.0".parse().unwrap(),
                    dst: "10.0.20.5".parse().unwrap(),
                    proto: 6,
                    sport: 0,
                    dport: 445,
                },
                decisions: vec![ReachDecisionView {
                    device: "fw-01".into(),
                    decision: DecisionView {
                        stage: StageView::EgressFilter,
                        rule: Some("12".into()),
                        source: Some(SourceSpan::new("fw-01.conf", 120)),
                        outcome: "accepté".into(),
                        shadowed_by: vec![],
                    },
                }],
            }],
            diagnostics: vec![Diagnostic::error(
                "topologie incomplète : aucun lien depuis fw-01/wan",
                None,
            )],
        }
    }

    #[test]
    fn rendu_texte_dun_reach() {
        let txt = render_reach_text(&reach_exemple());
        assert!(
            txt.contains("Tout ce qui peut atteindre 10.0.20.5:445/tcp :"),
            "{txt}"
        );
        assert!(txt.contains("1. entrée fw-01/lan"), "{txt}");
        assert!(
            txt.contains("ensemble : 10.0.10.0/24 → 10.0.20.5:445/tcp"),
            "{txt}"
        );
        assert!(
            txt.contains("exemple  : 10.0.10.0 → 10.0.20.5:445/tcp"),
            "{txt}"
        );
        assert!(
            txt.contains("autorisé par la règle 12 (fw-01.conf ligne 120)"),
            "{txt}"
        );
        assert!(
            txt.contains("fw-01 : filtre de sortie : accepté (règle 12, fw-01.conf ligne 120)"),
            "{txt}"
        );
        assert!(txt.contains("1 flux autorisé(s)."), "{txt}");
        // Les parts non décidables sont affichées honnêtement.
        assert!(txt.contains("1 part(s) non décidable(s)"), "{txt}");
        assert!(txt.contains("[erreur] topologie incomplète"), "{txt}");
    }

    #[test]
    fn rendu_texte_dun_reach_vide() {
        let view = ReachView {
            question: "Tout ce qui peut atteindre 192.0.2.1:22/tcp".into(),
            flows: vec![],
            diagnostics: vec![],
        };
        let txt = render_reach_text(&view);
        assert!(txt.contains("Aucun flux autorisé trouvé."), "{txt}");
        assert!(!txt.contains("part(s) non décidable(s)"), "{txt}");
    }

    #[test]
    fn rendu_json_dun_reach() {
        let json = render_reach_json(&reach_exemple());
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["flows"][0]["entry"], "fw-01/lan");
        assert_eq!(v["flows"][0]["decisions"][0]["decision"]["rule"], "12");
        assert_eq!(v["diagnostics"].as_array().unwrap().len(), 1);
    }

    // -- Rendu des règles mortes ----------------------------------------

    fn dead_exemple() -> DeadRulesView {
        DeadRulesView {
            excluded: Vec::new(),
            devices: 1,
            rules: vec![
                DeadRuleView {
                    device: "fw-01".into(),
                    policy: "forward".into(),
                    rule: "20".into(),
                    source: SourceSpan::new("fw-01.conf", 200),
                    kind: DeadRuleKindView::Shadowed,
                    masked_by: vec![MaskerView {
                        rule: "10".into(),
                        source: SourceSpan::new("fw-01.conf", 100),
                    }],
                    sample: Some(ConcretePacket {
                        src: "10.0.10.128".parse().unwrap(),
                        dst: "10.0.20.5".parse().unwrap(),
                        proto: 6,
                        sport: 0,
                        dport: 445,
                    }),
                },
                DeadRuleView {
                    device: "fw-01".into(),
                    policy: "forward".into(),
                    rule: "40".into(),
                    source: SourceSpan::new("fw-01.conf", 400),
                    kind: DeadRuleKindView::EmptySet,
                    masked_by: vec![],
                    sample: None,
                },
            ],
        }
    }

    #[test]
    fn rendu_texte_des_regles_mortes() {
        let txt = render_dead_rules_text(&dead_exemple());
        assert!(txt.contains("MASQUÉE"), "{txt}");
        assert!(
            txt.contains(
                "règle 20 (politique forward, équipement « fw-01 ») — fw-01.conf ligne 200"
            ),
            "{txt}"
        );
        assert!(
            txt.contains("masquée par : la règle 10 (fw-01.conf ligne 100)"),
            "{txt}"
        );
        assert!(
            txt.contains("paquet témoin : 10.0.10.128 → 10.0.20.5:445/tcp"),
            "{txt}"
        );
        assert!(txt.contains("ENSEMBLE VIDE"), "{txt}");
        assert!(txt.contains("ne peut correspondre à aucun paquet"), "{txt}");
        assert!(
            txt.contains("1 équipement(s) analysé(s), 2 règle(s) morte(s), 0 exclue(s)."),
            "{txt}"
        );
    }

    #[test]
    fn rendu_texte_sans_regle_morte() {
        let view = DeadRulesView {
            devices: 2,
            rules: vec![],
            excluded: vec!["équipement « fw-01 » : règle « 9 » exclue".into()],
        };
        let txt = render_dead_rules_text(&view);
        assert!(txt.contains("Aucune règle morte"), "{txt}");
        assert!(txt.contains("EXCLUE"), "{txt}");
        assert!(txt.contains("règle « 9 » exclue"), "{txt}");
        assert!(
            txt.contains("2 équipement(s) analysé(s), 0 règle(s) morte(s), 1 exclue(s)."),
            "{txt}"
        );
    }

    #[test]
    fn rendu_json_des_regles_mortes() {
        let json = render_dead_rules_json(&dead_exemple());
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["devices"], 1);
        assert_eq!(v["rules"][0]["kind"], "Shadowed");
        assert_eq!(v["rules"][1]["kind"], "EmptySet");
    }
}
