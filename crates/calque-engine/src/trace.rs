//! Les types de trace (§5.2). La trace EST le produit : un verdict sans la
//! règle qui l'a produit ne vaut rien.

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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
}
