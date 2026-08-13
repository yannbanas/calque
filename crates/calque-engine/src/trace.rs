//! Les types de trace (§5.2). La trace EST le produit : un verdict sans la
//! règle qui l'a produit ne vaut rien.

use std::net::IpAddr;

use calque_model::{ConcretePacket, DeviceId, Diagnostic, IfaceId, RuleId, SourceSpan};
use serde::{Deserialize, Serialize};

/// Résultat complet d'une question d'accessibilité, saut par saut.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Trace {
    pub verdict: Verdict,
    pub hops: Vec<Hop>,
    /// Diagnostics accumulés pendant l'évaluation. Jamais vide quand le
    /// verdict est `Unknown` (§6.3 : ne jamais deviner sans le dire).
    pub diagnostics: Vec<Diagnostic>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Verdict {
    Allowed,
    Denied,
    /// Aucune route, ou route de rejet explicite (voir `Outcome::RouteDrop`).
    NoRoute,
    Loop,
    /// Le modèle ne permet pas de conclure sans deviner ; voir les diagnostics.
    Unknown,
}

/// La traversée d'un équipement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hop {
    pub device: DeviceId,
    pub in_iface: IfaceId,
    /// Absente si le paquet s'arrête avant la décision de routage
    /// (refus d'entrée, pas de route, livraison locale).
    pub out_iface: Option<IfaceId>,
    pub header_in: ConcretePacket,
    /// L'en-tête en sortie d'équipement, après traductions d'adresse.
    pub header_out: ConcretePacket,
    pub decisions: Vec<Decision>,
}

/// Une décision prise à une étape de la séquence de traitement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Decision {
    pub stage: Stage,
    pub rule: Option<RuleId>,
    /// Fichier + ligne de la règle ou de la route responsable.
    pub source: Option<SourceSpan>,
    pub outcome: Outcome,
    /// Règles ANTÉRIEURES de la même politique qui correspondent aussi au
    /// paquet et masquent donc celle-ci. Rempli pour les décisions
    /// informationnelles `Outcome::Matched` (la fonctionnalité vedette :
    /// « pourquoi ma règle d'autorisation ne s'applique-t-elle pas ? »).
    pub shadowed_by: Vec<RuleId>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Stage {
    IngressFilter,
    Route,
    EgressFilter,
    Nat,
}

impl Stage {
    /// Libellé français de l'étape — le vocabulaire des traces rendues
    /// (identique à celui de `calque-report`).
    pub fn label(self) -> &'static str {
        match self {
            Stage::IngressFilter => "filtre d'entrée",
            Stage::Nat => "traduction d'adresse",
            Stage::Route => "routage",
            Stage::EgressFilter => "filtre de sortie",
        }
    }
}

impl std::fmt::Display for Stage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Outcome {
    /// La règle correspond et accepte le paquet (décisive).
    Accepted,
    /// La règle correspond et refuse le paquet (décisive).
    Denied,
    /// La règle correspond mais une règle antérieure a déjà décidé :
    /// informationnel, voir `shadowed_by`.
    Matched,
    /// Rien n'a correspondu (ex. cible d'un saut sans verdict).
    NoMatch,
    /// Aucune règle ne correspond : l'action par défaut de la politique
    /// s'applique (le verdict du saut dit dans quel sens).
    DefaultAction,
    /// Une route a été retenue (étape `Route`).
    RouteFound,
    /// Aucune route vers la destination (étape `Route`).
    NoRoute,
    /// Route de rejet explicite (`NextHop::Drop`) : le verdict global est
    /// `NoRoute`, cette décision pointe la route responsable.
    RouteDrop,
    /// En-tête réécrit par une traduction d'adresse (étape `Nat`).
    Rewritten,
    /// La route retenue fait SORTIR le paquet du périmètre modélisé (étape
    /// `Route`) : la destination n'appartient à aucun équipement ni réseau
    /// du modèle ET l'interface de sortie n'a aucun lien. Le verdict global
    /// reste celui des filtres (typiquement `Allowed`), mais le rendu DOIT
    /// mentionner la sortie de périmètre — jamais un « autorisé » silencieux
    /// qui laisserait croire que la destination est modélisée.
    ExitsModel {
        /// L'interface par laquelle le paquet quitte le périmètre.
        iface: IfaceId,
        /// La passerelle hors modèle, absente pour une route d'interface
        /// (ex. tunnel IPsec sans adresse).
        gateway: Option<IpAddr>,
    },
    /// Plusieurs routes optimales divergentes (ECMP, étape `Route`) : chaque
    /// branche a été évaluée et TOUTES mènent au même verdict — ce verdict
    /// est donc ferme. La trace détaillée suit la PREMIÈRE branche (choix
    /// documenté ; un diagnostic informatif le rappelle).
    EcmpAgreed { ifaces: Vec<IfaceId> },
    /// Plusieurs routes optimales divergentes (ECMP) aux verdicts
    /// DIVERGENTS selon la branche : verdict `Unknown`, chaque branche et
    /// son verdict sont détaillés dans les diagnostics (§6.3 : ne jamais
    /// deviner — mais dire exactement ce qui diverge).
    EcmpDiverged { ifaces: Vec<IfaceId> },
}

impl Outcome {
    /// Libellé français STATIQUE de l'issue (sans les parties dynamiques —
    /// interface, passerelle… — que `Display` ajoute).
    pub fn label(&self) -> &'static str {
        match self {
            Outcome::Accepted => "accepté",
            Outcome::Denied => "refusé",
            Outcome::Matched => "correspond aussi",
            Outcome::NoMatch => "aucune correspondance",
            Outcome::DefaultAction => "action par défaut de la politique",
            Outcome::RouteFound => "route retenue",
            Outcome::NoRoute => "aucune route vers la destination",
            Outcome::RouteDrop => "route de rejet explicite",
            Outcome::Rewritten => "en-tête réécrit",
            Outcome::ExitsModel { .. } => "sort du périmètre modélisé",
            Outcome::EcmpAgreed { .. } => {
                "routes multiples (ECMP), verdict identique sur toutes les branches"
            }
            Outcome::EcmpDiverged { .. } => {
                "routes multiples (ECMP), verdicts divergents selon la branche"
            }
        }
    }
}

/// Liste d'interfaces séparées par des virgules (« wan1, wan2 »).
fn ifaces_label(ifaces: &[IfaceId]) -> String {
    ifaces
        .iter()
        .map(|i| i.to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

impl std::fmt::Display for Outcome {
    /// Le libellé complet, parties dynamiques comprises — c'est ce texte
    /// que les rendus (`calque-report` via la CLI) affichent.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Outcome::ExitsModel { iface, gateway } => match gateway {
                Some(gw) => write!(
                    f,
                    "sort du périmètre modélisé via {iface} (passerelle {gw})"
                ),
                None => write!(f, "sort du périmètre modélisé via {iface}"),
            },
            Outcome::EcmpAgreed { ifaces } => write!(
                f,
                "{} routes candidates ({}) : verdict identique sur toutes les branches",
                ifaces.len(),
                ifaces_label(ifaces)
            ),
            Outcome::EcmpDiverged { ifaces } => write!(
                f,
                "{} routes candidates ({}) : verdicts divergents selon la branche",
                ifaces.len(),
                ifaces_label(ifaces)
            ),
            other => f.write_str(other.label()),
        }
    }
}
