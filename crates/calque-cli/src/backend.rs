//! La couche d'adaptation entre le binaire et les crates du cœur :
//! `calque-vendors` (détection + conversion en IR) et `calque-engine`
//! (trace d'accessibilité), plus l'adaptation `Trace` → `TraceView` de
//! `calque-report`.

use std::path::Path;

use calque_engine::{DeadRule, DeadRuleKind, ReachReport, Stage, Trace, Verdict};
use calque_model::{ConcretePacket, Device, DeviceId, Diagnostic, Fidelity, Network, Vendor};
use calque_report::{
    DeadRuleKindView, DeadRuleView, DeadRulesView, DecisionView, HopView, MaskerView,
    ReachDecisionView, ReachFlowView, ReachView, StageView, TraceView, VerdictView,
};
use calque_vendors::{detect_and_import, DetectImportError};
use miette::{miette, IntoDiagnostic, WrapErr};

// Le port source éphémère représentatif vit désormais dans
// `calque-policy` (à côté de `flow_packet`, qui le pose) ; ré-exporté ici
// pour les consommateurs du binaire.
pub use calque_policy::EPHEMERAL_SPORT;

// La préparation du modèle pour le moteur vit désormais dans
// `calque-engine` (API publique de la jonction bibliothèque) ; ré-exportée
// ici pour que la CLI garde son point d'accès historique.
pub use calque_engine::prepare_for_engine;

// ---------------------------------------------------------------------------
// Bornes de lecture (audit 2026-08-12, finding R1)
// ---------------------------------------------------------------------------

/// Taille maximale d'un fichier YAML lu par le CLI (`flows.yaml`,
/// `topology.yaml`) : 4 Mo — plusieurs milliers de fois un fichier de flux
/// légitime (quelques Ko).
///
/// Pourquoi cette borne suffit contre une « bombe YAML » (R1) :
/// `serde_yaml` 0.9.34 embarque déjà deux gardes internes, non
/// configurables mais vérifiées dans sa source : une limite de répétition
/// d'aliases (au plus 100 sauts d'alias par événement du document,
/// `RepetitionLimitExceeded`) et une limite de profondeur de récursion
/// (128, `RecursionLimitExceeded`). L'expansion exponentielle « billion
/// laughs » est donc coupée par le parseur lui-même ; le coût résiduel au
/// pire est proportionnel à `100 × nombre d'événements`, et le nombre
/// d'événements est proportionnel à la taille du fichier. Borner la taille
/// borne donc le travail total. La désérialisation est par ailleurs TYPÉE
/// (`deny_unknown_fields`, aucune `serde_yaml::Value` générique) : rien ne
/// matérialise un arbre arbitraire en mémoire.
pub const MAX_YAML_BYTES: u64 = 4 * 1024 * 1024;

/// Taille maximale d'une configuration importée (`import`, la candidate de
/// `plan`, `scrub`) : 64 Mo — très au-delà des plus grosses configurations
/// réelles (quelques Mo pour un pare-feu chargé). Les parseurs sont
/// linéaires et bornés en profondeur (`MAX_DEPTH`, audit F4), mais lire le
/// fichier en mémoire reste proportionnel à sa taille : cette borne
/// plafonne ce coût-là face à un fichier hostile démesuré.
pub const MAX_CONFIG_BYTES: u64 = 64 * 1024 * 1024;

/// Lit un fichier texte en refusant proprement les fichiers trop gros
/// (borne documentée ci-dessus) et les contenus non UTF-8 — jamais de
/// panique, des erreurs miette claires (§11.3 : entrées hostiles).
///
/// `kind` complète le message : « un fichier de flux », « une
/// configuration »…
pub fn read_bounded(path: &Path, limit: u64, kind: &str) -> miette::Result<String> {
    let meta = std::fs::metadata(path)
        .into_diagnostic()
        .wrap_err_with(|| format!("lecture de {} impossible", path.display()))?;
    if meta.len() > limit {
        return Err(miette!(
            help = "cette borne protège contre les fichiers hostiles ou corrompus (déni de \
                    service — audit R1) ; un fichier légitime de ce type reste très en deçà",
            "{} fait {} octets : au-delà de la limite de {} Mo pour {kind}",
            path.display(),
            meta.len(),
            limit / (1024 * 1024)
        ));
    }
    let bytes = std::fs::read(path)
        .into_diagnostic()
        .wrap_err_with(|| format!("lecture de {} impossible", path.display()))?;
    String::from_utf8(bytes).map_err(|_| {
        miette!(
            help = "Calque ne lit que des fichiers texte encodés en UTF-8 ; vérifiez \
                    l'encodage de l'export (ou qu'il ne s'agit pas d'un binaire)",
            "{} n'est pas un fichier texte UTF-8 valide",
            path.display()
        )
    })
}

/// Ce qu'un import réussi produit : un équipement, sa fidélité (§6.3) et
/// les notes informatives de l'adaptateur (constats, pas des lacunes).
#[derive(Debug)]
pub struct ImportOutcome {
    pub device: Device,
    pub fidelity: Fidelity,
    pub notes: Vec<Diagnostic>,
    pub vendor: Vendor,
}

/// Libellé humain d'un constructeur.
pub fn vendor_label(v: Vendor) -> &'static str {
    match v {
        Vendor::Fortigate => "FortiGate",
        Vendor::CiscoIos => "Cisco IOS",
        Vendor::Opnsense => "OPNsense",
        Vendor::Nftables => "nftables",
        Vendor::Unknown => "inconnu",
    }
}

/// Détecte le constructeur d'un fichier de configuration et le convertit
/// en représentation intermédiaire. La détection et la conversion vivent
/// dans `calque-vendors` ([`calque_vendors::detect_and_import`], sans
/// I/O) : ici on lit le fichier (borné), puis on habille les erreurs
/// structurées en messages miette portant le chemin.
///
/// Sous le seuil de confiance, ou à égalité entre plusieurs adaptateurs :
/// erreur claire listant les scores — jamais de supposition (§6.3).
pub fn import_config(path: &Path, name: Option<&str>) -> miette::Result<ImportOutcome> {
    let raw = read_bounded(path, MAX_CONFIG_BYTES, "une configuration")?;
    // Le libellé de fichier porté par tous les SourceSpan du modèle : le
    // chemin tel que donné, pour que `model check` puisse relire la source.
    let label = path.display().to_string();

    let detected = detect_and_import(&raw, &label).map_err(|e| match &e {
        DetectImportError::Unrecognized { scores } => miette!(
            help = "aucun adaptateur ne reconnaît ce format avec assez de confiance (seuil : 60/100) ; vérifiez que le fichier est bien une configuration exportée d'un constructeur géré",
            "constructeur non reconnu pour « {} » (scores de détection : {})",
            path.display(),
            calque_vendors::score_summary(scores)
        ),
        DetectImportError::Ambiguous { scores } => miette!(
            help = "plusieurs adaptateurs obtiennent le même score : impossible de choisir sans deviner (§6.3)",
            "détection ambiguë pour « {} » (scores de détection : {})",
            path.display(),
            calque_vendors::score_summary(scores)
        ),
        DetectImportError::Import {
            vendor,
            diagnostics,
            ..
        } => {
            let details = diagnostics
                .iter()
                .map(|d| match &d.span {
                    Some(span) => format!("  - {span} : {}", d.message),
                    None => format!("  - {}", d.message),
                })
                .collect::<Vec<_>>()
                .join("\n");
            miette!(
                "import de « {} » impossible ({} détecté) :\n{details}",
                path.display(),
                vendor_label(*vendor)
            )
        }
    })?;

    let mut output = detected.output;
    if let Some(name) = name {
        output.device.id = DeviceId::new(name);
    }
    Ok(ImportOutcome {
        device: output.device,
        fidelity: output.fidelity,
        notes: output.notes,
        vendor: detected.vendor,
    })
}

/// Calcule la trace d'un paquet concret à travers le modèle.
///
/// Le moteur ne rend jamais d'erreur : tout ce qu'il ne peut pas conclure
/// sans deviner sort en verdict `Unknown` accompagné de diagnostics.
pub fn trace_concrete(network: &Network, packet: &ConcretePacket) -> Trace {
    let prepared = prepare_for_engine(network);
    calque_engine::trace_packet(&prepared, packet)
}

// ---------------------------------------------------------------------------
// Adaptation Trace (moteur) → TraceView (rendu)
// ---------------------------------------------------------------------------

/// Adapte une trace du moteur vers la vue rendue par `calque-report`.
pub fn trace_to_view(trace: &Trace) -> TraceView {
    TraceView {
        verdict: verdict_view(trace.verdict),
        hops: trace
            .hops
            .iter()
            .map(|h| HopView {
                device: h.device.to_string(),
                in_iface: h.in_iface.to_string(),
                out_iface: h.out_iface.as_ref().map(|i| i.to_string()),
                header_in: Some(h.header_in),
                header_out: Some(h.header_out),
                decisions: h.decisions.iter().map(decision_view).collect(),
            })
            .collect(),
    }
}

/// Adapte une décision du moteur vers la vue rendue par `calque-report`
/// (partagée entre la trace concrète et les rapports symboliques).
pub fn decision_view(d: &calque_engine::Decision) -> DecisionView {
    DecisionView {
        stage: stage_view(d.stage),
        rule: d.rule.as_ref().map(|r| r.to_string()),
        source: d.source.clone(),
        outcome: d.outcome.label().to_owned(),
        shadowed_by: d.shadowed_by.iter().map(|r| r.to_string()).collect(),
    }
}

/// Adapte un rapport symbolique `reach` vers la vue rendue par
/// `calque-report`. La `question` est le libellé déjà construit
/// (« Tout ce qui peut atteindre 10.0.20.5:445/tcp »).
pub fn reach_to_view(report: &ReachReport, question: String) -> ReachView {
    ReachView {
        question,
        flows: report
            .flows
            .iter()
            .map(|f| ReachFlowView {
                entry: format!("{}/{}", f.entry.device, f.entry.iface),
                set: f.set.clone(),
                sample: f.sample,
                decisions: f
                    .decisions
                    .iter()
                    .map(|d| ReachDecisionView {
                        device: d.device.to_string(),
                        decision: decision_view(&d.decision),
                    })
                    .collect(),
            })
            .collect(),
        diagnostics: report.diagnostics.clone(),
    }
}

/// Adapte les règles mortes d'un équipement vers les vues rendues par
/// `calque-report`.
pub fn dead_rules_to_views(device: &DeviceId, dead: &[DeadRule]) -> Vec<DeadRuleView> {
    dead.iter()
        .map(|d| DeadRuleView {
            device: device.to_string(),
            policy: d.policy.to_string(),
            rule: d.rule.to_string(),
            source: d.source.clone(),
            kind: match d.kind {
                DeadRuleKind::Shadowed => DeadRuleKindView::Shadowed,
                DeadRuleKind::EmptySet => DeadRuleKindView::EmptySet,
            },
            masked_by: d
                .masked_by
                .iter()
                .map(|m| MaskerView {
                    rule: m.rule.to_string(),
                    source: m.source.clone(),
                })
                .collect(),
            sample: d.sample,
        })
        .collect()
}

/// Construit la vue complète des règles mortes du modèle (chaque
/// équipement est analysé indépendamment). Une règle irrésoluble (objet
/// fqdn/geography, cycle…) est EXCLUE avec mention explicite, jamais
/// devinée (§6.3) — l'analyse continue sur le reste.
pub fn dead_rules_view(network: &Network) -> miette::Result<DeadRulesView> {
    let mut rules = Vec::new();
    let mut excluded = Vec::new();
    for device in network.devices.values() {
        let report = calque_engine::dead_rules_report(device);
        rules.extend(dead_rules_to_views(&device.id, &report.dead));
        excluded.extend(report.diagnostics.into_iter().map(|d| match d.span {
            Some(span) => format!("équipement « {} » : {} ({span})", device.id, d.message),
            None => format!("équipement « {} » : {}", device.id, d.message),
        }));
    }
    Ok(DeadRulesView {
        devices: network.devices.len(),
        rules,
        excluded,
    })
}

pub fn verdict_view(v: Verdict) -> VerdictView {
    match v {
        Verdict::Allowed => VerdictView::Allowed,
        Verdict::Denied => VerdictView::Denied,
        Verdict::NoRoute => VerdictView::NoRoute,
        Verdict::Loop => VerdictView::Loop,
        Verdict::Unknown => VerdictView::Unknown,
    }
}

fn stage_view(s: Stage) -> StageView {
    match s {
        Stage::IngressFilter => StageView::IngressFilter,
        Stage::Nat => StageView::Nat,
        Stage::Route => StageView::Route,
        Stage::EgressFilter => StageView::EgressFilter,
    }
}
