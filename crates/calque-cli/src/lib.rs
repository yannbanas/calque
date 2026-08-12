//! calque-cli — le binaire `calque`.
//!
//! Ce crate est exposé aussi comme bibliothèque pour que le parsing de la
//! ligne de commande soit testable (`Cli::try_parse_from`).
//!
//! ## Le « projet » `.calque/`
//!
//! Choix documenté : les commandes d'import sérialisent le modèle
//! (`Network` + `Fidelity`) en JSON dans un répertoire `.calque/` du
//! répertoire courant (`.calque/model.json`), que les autres commandes
//! relisent. C'est volontairement simple : un seul fichier, lisible à
//! l'œil, versionnable, et suffisant tant que les modèles se comptent en
//! quelques dizaines d'équipements. Voir `project.rs`.

pub mod backend;
pub mod cli;
pub mod commands;
pub mod project;
