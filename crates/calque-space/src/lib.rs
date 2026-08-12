//! calque-space — l'algèbre d'espace d'en-têtes (§4 de CALQUE-ARCHITECTURE.md).
//!
//! Crate PUR (règle §1) : aucune entrée-sortie, aucune horloge, aucun réseau.
//! Seules dépendances : `ipnet`, `serde` et `calque-model`.
//!
//! Représentation : un [`HeaderSet`] est une union normalisée de pavés
//! disjoints ([`Cube`]) dans l'espace à cinq dimensions
//! (src, dst, proto, sport, dport). Chaque dimension est elle-même un
//! ensemble fermé par union/intersection/soustraction, ce qui rend
//! l'intersection de pavés composante par composante (§4.2).

#![forbid(unsafe_code)]

mod cube;
mod headerset;
mod ports;
mod prefix;
mod proto;

#[cfg(test)]
mod proptests;

pub use cube::Cube;
pub use headerset::HeaderSet;
pub use ports::PortRanges;
pub use prefix::PrefixSet;
pub use proto::ProtoSet;

pub use calque_model::ConcretePacket;

/// Le trait d'espace d'en-têtes (§4.1).
///
/// Il abstrait la représentation (pavés aujourd'hui, diagrammes de décision
/// binaires demain si nécessaire) derrière les opérations ensemblistes.
///
/// Note sur `Eq` : l'égalité est structurelle sur la forme normalisée.
/// La normalisation n'étant pas canonique pour une union de pavés, deux
/// ensembles sémantiquement égaux peuvent différer structurellement ;
/// pour l'égalité ensembliste, comparer par inclusion mutuelle
/// (cf. [`HeaderSet::contains_set`]).
pub trait HeaderSpace: Clone + Eq {
    /// L'espace entier (tout paquet possible).
    fn full() -> Self;
    /// L'ensemble vide.
    fn empty() -> Self;
    /// Vrai si aucun paquet n'appartient à l'ensemble.
    fn is_empty(&self) -> bool;
    /// Intersection ensembliste.
    fn intersect(&self, other: &Self) -> Self;
    /// Union ensembliste.
    fn union(&self, other: &Self) -> Self;
    /// Différence ensembliste `self \ other`.
    fn subtract(&self, other: &Self) -> Self;
    /// Appartenance d'un paquet concret.
    fn contains(&self, pkt: &ConcretePacket) -> bool;
    /// Un paquet concret représentatif, `None` si l'ensemble est vide.
    ///
    /// Quand une invariante est violée, l'outil doit sortir UN paquet
    /// précis qui viole, pas une abstraction (§4.1).
    fn sample(&self) -> Option<ConcretePacket>;
}
