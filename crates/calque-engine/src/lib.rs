//! calque-engine — le moteur d'accessibilité de Calque (§5).
//!
//! Crate PUR (§1) : aucune entrée-sortie, pas d'horloge, pas de réseau.
//! Il prend un `Network` et un `ConcretePacket` de `calque-model` et rend
//! une `Trace` : le verdict ET la justification, saut par saut, règle par
//! règle — car la trace est le produit (§5.2).
//!
//! Deux modes, même sémantique :
//! - CONCRET : propagation d'un `ConcretePacket` (`engine.rs`) ;
//! - SYMBOLIQUE (§5.3) : propagation d'un `HeaderSet` de `calque-space`
//!   (`symbolic.rs`, `sympolicy.rs`, `symtrace.rs`), la sortie devenant un
//!   ARBRE de sous-ensembles verdicts. C'est la brique de `reach.rs`
//!   (« qui peut atteindre quoi ») et de `dead.rs` (règles mortes et
//!   masquées). La cohérence des deux modes est testée : tout paquet
//!   échantillonné d'un sous-ensemble symbolique reçoit le même verdict du
//!   moteur concret (§4.3).
//!
//! Principes respectés :
//! - résolution TARDIVE des objets (§3.3), groupes imbriqués compris, avec
//!   détection des cycles ;
//! - ordre des règles sémantique : première correspondance gagne, et les
//!   règles masquées sont signalées via `Decision::shadowed_by` (§5.2) ;
//! - ne jamais deviner (§6.3) : tout élément manquant ou ambigu sur le
//!   chemin produit un verdict `Unknown` accompagné d'un diagnostic ;
//! - mais répondre FERMEMENT quand le périmètre modélisé le permet : un flux
//!   routé hors du modèle est une sortie de périmètre explicite
//!   (`Outcome::ExitsModel`, verdict des filtres), et un ECMP est évalué
//!   PAR BRANCHES (verdict ferme si toutes les branches s'accordent, sinon
//!   `Unknown` avec le verdict de chaque branche) — « ne jamais deviner »
//!   n'oblige pas à ne jamais répondre.

pub mod dead;
pub mod engine;
pub mod error;
pub mod policy;
pub mod prepare;
pub mod reach;
pub mod resolve;
pub mod route;
pub mod symbolic;
pub mod sympolicy;
pub mod symtrace;
pub mod topology;
pub mod trace;

#[cfg(test)]
mod testutil;

pub use dead::{
    dead_rules, dead_rules_report, DeadRule, DeadRuleKind, DeadRulesReport, Masker, MAX_UNION_CUBES,
};
pub use engine::{trace_packet, trace_packet_from, trace_packet_opts, MAX_ECMP_TOTAL_BRANCHES};
pub use error::EvalError;
pub use policy::{
    evaluate_policy, evaluate_policy_opts, FilterPoint, FilterResult, NatGrant, PolicyEvaluation,
};
pub use prepare::prepare_for_engine;
pub use reach::{reach_from, reach_to, ReachFlow, ReachReport};
pub use resolve::{packet_matches_rule, packet_matches_rule_opts};
pub use route::{lookup_route, EcmpRoute, RouteDecision, MAX_ECMP_ROUTES};
pub use symbolic::rule_headerset;
pub use sympolicy::{evaluate_policy_symbolic, SymFilterResult, SymbolicPart, MAX_CUBES};
pub use symtrace::{
    symbolic_trace_from, SymbolicBranch, SymbolicDecision, SymbolicNode, SymbolicTrace,
    SymbolicVerdictSet, MAX_DEPTH, MAX_NODES,
};
pub use topology::{check_topology, infer_links_from_subnets, TopologyIssue, TopologyIssueKind};
pub use trace::{Decision, Hop, Outcome, Stage, Trace, Verdict};
