//! La couche d'adaptation vers les crates implémentés en parallèle.
//!
//! `calque-vendors` (détection + `to_ir`) et `calque-engine` (trace) sont
//! développés en même temps que ce binaire. Tant que leurs API ne sont pas
//! posées, les fonctions ci-dessous rendent une erreur honnête à
//! l'exécution — le binaire, lui, compile et se teste quoi qu'il arrive.
//!
//! Brancher le vrai flux consiste à remplacer le corps de ces fonctions
//! (et à réactiver les dépendances dans `Cargo.toml`) :
//! - `import_config` → `calque_vendors::detect(...)` puis `to_ir(...)` ;
//! - `trace_concrete` → `calque_engine::trace(...)`, adapté en `TraceView`.

use std::path::Path;

use calque_model::{ConcretePacket, Device, Fidelity, Network};
use calque_report::TraceView;
use miette::miette;

/// Ce qu'un import réussi produit : un équipement et sa fidélité.
#[derive(Debug)]
pub struct ImportOutcome {
    pub device: Device,
    pub fidelity: Fidelity,
}

/// Détecte le constructeur d'un fichier de configuration et le convertit
/// en représentation intermédiaire.
///
/// PAS ENCORE BRANCHÉ : `calque-vendors` est en cours d'implémentation.
pub fn import_config(path: &Path, _name: Option<&str>) -> miette::Result<ImportOutcome> {
    Err(miette!(
        help = "les crates calque-parse et calque-vendors sont en cours d'implémentation (étape S1 de la feuille de route) ; cette commande fonctionnera dès qu'ils seront branchés dans calque-cli/src/backend.rs",
        "l'analyseur de configurations n'est pas encore branché : impossible d'importer « {} »",
        path.display()
    ))
}

/// Calcule la trace d'un paquet concret à travers le modèle.
///
/// PAS ENCORE BRANCHÉ : `calque-engine` est en cours d'implémentation.
pub fn trace_concrete(_network: &Network, packet: &ConcretePacket) -> miette::Result<TraceView> {
    Err(miette!(
        help = "le crate calque-engine est en cours d'implémentation (étape S2 de la feuille de route) ; cette commande fonctionnera dès qu'il sera branché dans calque-cli/src/backend.rs",
        "le moteur d'accessibilité n'est pas encore branché : impossible de tracer {} → {}:{}",
        packet.src,
        packet.dst,
        packet.dport
    ))
}
