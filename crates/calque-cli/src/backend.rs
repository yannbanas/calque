//! La couche d'adaptation entre le binaire et les crates du cœur :
//! `calque-vendors` (détection + conversion en IR) et `calque-engine`
//! (trace d'accessibilité), plus l'adaptation `Trace` → `TraceView` de
//! `calque-report`.

use std::path::Path;

use calque_engine::{Outcome, Stage, Trace, Verdict};
use calque_model::{ConcretePacket, Device, DeviceId, Diagnostic, Fidelity, Network, Vendor};
use calque_report::{DecisionView, HopView, StageView, TraceView, VerdictView};
use calque_vendors::fortigate::FortigateAdapter;
use calque_vendors::{all_adapters, Confidence};
use miette::{miette, IntoDiagnostic, WrapErr};

/// Le port source utilisé pour construire un paquet concret quand
/// l'utilisateur n'en précise pas : un port éphémère représentatif
/// (40000, dans l'intervalle éphémère de fait de la plupart des piles).
/// Le mode symbolique couvrira tout l'intervalle ; en mode concret, un
/// paquet précis suffit et ce choix est affiché tel quel dans la trace.
pub const EPHEMERAL_SPORT: u16 = 40000;

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
    let raw = std::fs::read_to_string(path)
        .into_diagnostic()
        .wrap_err_with(|| format!("lecture de {} impossible", path.display()))?;
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
                decisions: h
                    .decisions
                    .iter()
                    .map(|d| DecisionView {
                        stage: stage_view(d.stage),
                        rule: d.rule.as_ref().map(|r| r.to_string()),
                        source: d.source.clone(),
                        outcome: outcome_label(d.outcome).to_owned(),
                        shadowed_by: d.shadowed_by.iter().map(|r| r.to_string()).collect(),
                    })
                    .collect(),
            })
            .collect(),
    }
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
