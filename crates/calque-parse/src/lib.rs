//! calque-parse — couche 1 des analyseurs (§6 de CALQUE-ARCHITECTURE.md).
//!
//! Du texte brut vers l'arbre de configuration générique, PAR FORMAT :
//! aucune sémantique constructeur ici (elle vit dans `calque-vendors`).
//!
//! Crate pur : le texte arrive en `&str`, aucune lecture de fichier.
//! Les configurations sont des entrées non fiables (§11.3) : jamais de
//! `panic!` ni d'`unwrap()` sur l'entrée — toute anomalie devient une
//! [`ParseError`] structurée portant fichier et ligne.

pub mod cisco_ios;
pub mod error;
pub mod fortigate;
mod tokenize;
pub mod tree;

pub use calque_model::SourceSpan;
pub use error::ParseError;
pub use tree::{ConfigNode, ConfigTree};
