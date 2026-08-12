//! La couche d'adaptation entre le binaire et les crates du cœur :
//! `calque-vendors` (détection + conversion en IR) et `calque-engine`
//! (trace d'accessibilité), plus l'adaptation `Trace` → `TraceView` de
//! `calque-report`.

use std::path::Path;

use calque_engine::{DeadRule, DeadRuleKind, Outcome, ReachReport, Stage, Trace, Verdict};
use calque_model::{ConcretePacket, Device, DeviceId, Diagnostic, Fidelity, Network, Vendor};
use calque_report::{
    DeadRuleKindView, DeadRuleView, DeadRulesView, DecisionView, HopView, MaskerView,
    ReachDecisionView, ReachFlowView, ReachView, StageView, TraceView, VerdictView,
};
use calque_vendors::fortigate::FortigateAdapter;
use calque_vendors::{all_adapters, Confidence};
use miette::{miette, IntoDiagnostic, WrapErr};

/// Le port source utilisé pour construire un paquet concret quand
/// l'utilisateur n'en précise pas : un port éphémère représentatif
/// (40000, dans l'intervalle éphémère de fait de la plupart des piles).
/// Le mode symbolique couvrira tout l'intervalle ; en mode concret, un
/// paquet précis suffit et ce choix est affiché tel quel dans la trace.
pub const EPHEMERAL_SPORT: u16 = 40000;

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

/// Détecte le constructeur d'un fichier de configuration (meilleur score
/// `detect` parmi `all_adapters()`, au-dessus du seuil de confiance) et le
/// convertit en représentation intermédiaire.
///
/// Sous le seuil, ou à égalité entre plusieurs constructeurs : erreur
/// claire listant les scores — jamais de supposition (§6.3).
pub fn import_config(path: &Path, name: Option<&str>) -> miette::Result<ImportOutcome> {
    let raw = read_bounded(path, MAX_CONFIG_BYTES, "une configuration")?;
    // Le libellé de fichier porté par tous les SourceSpan du modèle : le
    // chemin tel que donné, pour que `model check` puisse relire la source.
    let label = path.display().to_string();

    let scores: Vec<(Vendor, Confidence)> = all_adapters()
        .iter()
        .map(|a| (a.vendor(), a.detect(&raw)))
        .collect();
    let score_list = scores
        .iter()
        .map(|(v, c)| format!("{} : {}/100", vendor_label(*v), c.score()))
        .collect::<Vec<_>>()
        .join(", ");
    let best = scores
        .iter()
        .map(|(_, c)| *c)
        .max()
        .unwrap_or(Confidence::NONE);
    if !best.is_confident() {
        return Err(miette!(
            help = "aucun adaptateur ne reconnaît ce format avec assez de confiance (seuil : 60/100) ; vérifiez que le fichier est bien une configuration exportée d'un constructeur géré",
            "constructeur non reconnu pour « {} » (scores de détection : {score_list})",
            path.display()
        ));
    }
    let winners: Vec<Vendor> = scores
        .iter()
        .filter(|(_, c)| *c == best)
        .map(|(v, _)| *v)
        .collect();
    if winners.len() > 1 {
        return Err(miette!(
            help = "plusieurs constructeurs obtiennent le même score : impossible de choisir sans deviner (§6.3)",
            "détection ambiguë pour « {} » (scores de détection : {score_list})",
            path.display()
        ));
    }
    let vendor = winners[0];

    let output = match vendor {
        Vendor::Fortigate => FortigateAdapter.import_str(&raw, &label),
        v => {
            return Err(miette!(
                "constructeur {} détecté pour « {} », mais son adaptateur n'est pas encore branché",
                vendor_label(v),
                path.display()
            ))
        }
    };
    let mut output = output.map_err(|diags| {
        let details = diags
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
            vendor_label(vendor)
        )
    })?;

    if let Some(name) = name {
        output.device.id = DeviceId::new(name);
    }
    Ok(ImportOutcome {
        device: output.device,
        fidelity: output.fidelity,
        notes: output.notes,
        vendor,
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

/// Choix documenté — accrochage des politiques à couple de zones.
///
/// L'adaptateur FortiGate accroche la politique `forward` en entrée
/// (`Pipeline::ingress`), mais ses règles contraignent un couple de zones
/// (`from`, `to`). Or la zone de SORTIE n'est connue qu'après la décision
/// de routage : le moteur, qui ne devine jamais, refuse d'évaluer une
/// contrainte `to` au point d'entrée (`EgressZoneUnknownAtIngress`).
///
/// Sur l'équipement réel, la politique forward est bel et bien consultée
/// APRÈS la recherche de route (la décision dépend de l'interface de
/// sortie). Évaluer ces politiques au point de sortie — où le moteur
/// conserve la zone d'entrée ET connaît la zone de sortie — reproduit donc
/// exactement la sémantique constructeur, sans rien supposer. On déplace
/// ici, sur une COPIE du modèle et uniquement pour l'évaluation, toute
/// politique d'entrée dont au moins une règle contraint la zone de sortie.
///
/// Publique parce que `calque plan` doit passer par la même préparation
/// avant de confier les deux modèles à `calque_diff::plan`.
pub fn prepare_for_engine(network: &Network) -> Network {
    let mut network = network.clone();
    for device in network.devices.values_mut() {
        let (to_egress, keep_ingress): (Vec<_>, Vec<_>) =
            device.pipeline.ingress.drain(..).partition(|pid| {
                device
                    .policies
                    .get(pid)
                    .is_some_and(|p| p.rules.iter().any(|r| r.to.is_some()))
            });
        device.pipeline.ingress = keep_ingress;
        if !to_egress.is_empty() {
            // Elles passaient avant les politiques de sortie existantes :
            // elles restent devant.
            let mut egress = to_egress;
            egress.append(&mut device.pipeline.egress);
            device.pipeline.egress = egress;
        }
    }
    network
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
        outcome: outcome_label(d.outcome).to_owned(),
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
/// équipement est analysé indépendamment). Une règle irrésoluble rend une
/// erreur : jamais un rapport deviné (§6.3).
pub fn dead_rules_view(network: &Network) -> miette::Result<DeadRulesView> {
    let mut rules = Vec::new();
    for device in network.devices.values() {
        let dead = calque_engine::dead_rules(device).map_err(|e| {
            miette!(
                "analyse des règles mortes impossible sur l'équipement « {} » : {e}",
                device.id
            )
        })?;
        rules.extend(dead_rules_to_views(&device.id, &dead));
    }
    Ok(DeadRulesView {
        devices: network.devices.len(),
        rules,
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

fn outcome_label(o: Outcome) -> &'static str {
    match o {
        Outcome::Accepted => "accepté",
        Outcome::Denied => "refusé",
        Outcome::Matched => "correspond aussi",
        Outcome::NoMatch => "aucune correspondance",
        Outcome::DefaultAction => "action par défaut de la politique",
        Outcome::RouteFound => "route retenue",
        Outcome::NoRoute => "aucune route vers la destination",
        Outcome::RouteDrop => "route de rejet explicite",
        Outcome::Rewritten => "en-tête réécrit",
    }
}
