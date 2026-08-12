//! calque-report — les sorties : texte, JSON, JUnit.
//!
//! « La trace est le produit » (§5.2) : ce crate transforme une trace ou
//! un résultat de test de flux en quelque chose qu'un humain (texte), un
//! programme (JSON) ou une chaîne d'intégration continue (JUnit XML) peut
//! consommer.
//!
//! Les types d'entrée sont des « vues » construites uniquement sur
//! `calque-model` : `calque-cli` adapte les types réels du moteur
//! (`calque_engine::Trace`, etc.) vers ces vues. Le vocabulaire des
//! résultats de flux (ROMPU / CORRIGÉ / NOUVEAU) est celui du §10.2.
//!
//! La sortie JUnit XML (testsuite / testcase / failure) est écrite à la
//! main, sans dépendance supplémentaire.

use std::fmt;
use std::fmt::Write as _;

use calque_model::{ConcretePacket, SourceSpan};
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
    pub hops: Vec<HopView>,
}

/// Rendu texte d'une trace, règle par règle (`calque path --explain`).
pub fn render_trace_text(trace: &TraceView) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "Verdict : {}", trace.verdict);
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

fn packet_label(p: &ConcretePacket) -> String {
    format!("{} → {}:{}/proto {}", p.src, p.dst, p.dport, p.proto)
}

// ---------------------------------------------------------------------------
// Résultats de tests de flux (§10.1, vocabulaire §10.2)
// ---------------------------------------------------------------------------

/// Statut d'un flux, avec le vocabulaire du §10.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FlowStatus {
    /// Le flux se comporte comme déclaré.
    Ok,
    /// ROMPU — le flux ne se comporte plus comme déclaré.
    Broken,
    /// CORRIGÉ — le flux se comporte de nouveau comme déclaré.
    Fixed,
    /// NOUVEAU — une accessibilité qu'aucun flux déclaré ne couvrait.
    New,
}

impl FlowStatus {
    /// Préfixe affiché dans la sortie texte.
    pub fn prefix(self) -> &'static str {
        match self {
            FlowStatus::Ok => "OK",
            FlowStatus::Broken => "ROMPU",
            FlowStatus::Fixed => "CORRIGÉ",
            FlowStatus::New => "NOUVEAU",
        }
    }

    /// Ce statut compte-t-il comme un échec (code de sortie non nul,
    /// `<failure>` JUnit) ? ROMPU évidemment ; NOUVEAU aussi, car une
    /// ouverture non déclarée est exactement le type d'erreur qui crée
    /// une brèche de segmentation (§10.2).
    pub fn is_failure(self) -> bool {
        matches!(self, FlowStatus::Broken | FlowStatus::New)
    }
}

impl fmt::Display for FlowStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.prefix())
    }
}

/// Le résultat d'un flux testé.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlowResult {
    /// Le nom déclaré dans `flows.yaml`.
    pub name: String,
    /// Libellé du flux : `10.0.10.0/24 → 10.0.20.5:445/tcp`.
    pub flow: String,
    /// Comportement attendu (`allow` / `deny`).
    pub expected: String,
    /// Comportement observé sur le modèle, si le test a pu tourner.
    pub actual: Option<String>,
    pub status: FlowStatus,
    /// Justification : la règle qui décide, ou la raison d'un échec.
    pub detail: Option<String>,
}

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
    fn rendu_json_dune_trace() {
        let trace = TraceView {
            verdict: VerdictView::Allowed,
            hops: vec![],
        };
        let json = render_trace_json(&trace);
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["verdict"], "Allowed");
    }
}
