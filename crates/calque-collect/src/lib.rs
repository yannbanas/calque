//! calque-collect — la collecte en ligne (S7) et la confrontation au réel
//! (§11.2 de CALQUE-ARCHITECTURE.md).
//!
//! Crate officiellement IMPUR (§8) : c'est le seul endroit du projet qui
//! a le droit de toucher le réseau. Il reste optionnel — la feature
//! `collect` de `calque-cli` est DÉSACTIVÉE par défaut, et quelqu'un qui
//! analyse des fichiers hors ligne ne compile jamais la pile SSH.
//!
//! ## Principe n° 1 : lecture seule, toujours (§13)
//!
//! La collecte n'envoie QUE les commandes des profils embarqués
//! ([`profile`]), toutes de lecture stricte, contrôlées par une liste
//! blanche testée (aucun `configure`, `edit`, `set`, `write`, `copy`,
//! `reload`…) et revérifiées à l'envoi.
//!
//! ## Architecture interne (§1 s'applique même ici)
//!
//! | Module      | Pureté | Rôle |
//! |-------------|--------|------|
//! | [`profile`] | pur    | commandes par constructeur, liste blanche    |
//! | [`ifname`]  | pur    | normalisation des noms de ports (`Gi0/1` ↔ `GigabitEthernet0/1`) et d'équipements |
//! | [`clean`]   | pur    | neutralisation bannières / pagination / artefacts de terminal |
//! | [`parse`]   | pur    | sorties LLDP/CDP → voisins → `Vec<Link>`     |
//! | [`detect`]  | pur    | classification des sondes (`get system status`, `show version`) |
//! | [`reality`] | mixte  | confrontation au réel : logique PURE ([`reality::cross`]) + sonde TCP minuscule |
//! | [`ssh`]     | impur  | transport russh/tokio, derrière la feature `ssh` |
//!
//! Les parseurs sont testés sur les transcripts enregistrés de
//! `corpus/collect/` : c'est là qu'est l'essentiel de la valeur de test,
//! sans aucun réseau. Seul le transport (`ssh`) exige un équipement réel.

pub mod clean;
pub mod detect;
pub mod error;
pub mod ifname;
pub mod parse;
pub mod profile;
pub mod reality;

#[cfg(feature = "ssh")]
pub mod ssh;

pub use error::CollectError;
pub use parse::{neighbors_to_links, Neighbor, ParsedNeighbors};
