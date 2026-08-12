//! calque-engine — le moteur d'accessibilité de Calque (§5).
//!
//! Crate PUR (§1) : aucune entrée-sortie, pas d'horloge, pas de réseau.
//! Il prend un `Network` et un `ConcretePacket` de `calque-model` et rend
//! une `Trace` : le verdict ET la justification, saut par saut, règle par
//! règle — car la trace est le produit (§5.2).
//!
//! Version actuelle : mode CONCRET uniquement (propagation d'un
//! `ConcretePacket`). Le mode symbolique (§5.3), qui propagera un
//! `HeaderSpace` de `calque-space`, viendra plus tard derrière le même
//! découpage — c'est pour cela que la résolution des objets, l'évaluation
//! des politiques et la recherche de route sont des modules séparés.
//!
//! Principes respectés :
//! - résolution TARDIVE des objets (§3.3), groupes imbriqués compris, avec
//!   détection des cycles ;
//! - ordre des règles sémantique : première correspondance gagne, et les
//!   règles masquées sont signalées via `Decision::shadowed_by` (§5.2) ;
//! - ne jamais deviner (§6.3) : tout élément manquant ou ambigu sur le
//!   chemin produit un verdict `Unknown` accompagné d'un diagnostic.

pub mod engine;
pub mod error;
pub mod policy;
pub mod resolve;
pub mod route;
pub mod topology;
pub mod trace;

pub use engine::{trace_packet, trace_packet_from};
pub use error::EvalError;
pub use policy::{evaluate_policy, FilterPoint, FilterResult, NatGrant, PolicyEvaluation};
pub use resolve::packet_matches_rule;
pub use route::{lookup_route, RouteDecision};
pub use topology::{check_topology, infer_links_from_subnets, TopologyIssue, TopologyIssueKind};
pub use trace::{Decision, Hop, Outcome, Stage, Trace, Verdict};
