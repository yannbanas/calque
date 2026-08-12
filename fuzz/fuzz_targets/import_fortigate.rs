//! Cible de fuzzing : chaîne complète FortiGate, couche 1 + couche 2
//! (`FortigateAdapter::import_str` — tokenizer puis conversion en IR).
//!
//! C'est la cible la plus profonde : elle exerce l'interprétation
//! sémantique (adresses, plages de ports, zones, politiques), là où
//! vivent les vrais bugs d'analyse de valeurs.
//!
//! §11.3 — aucun résultat inspecté : `Ok` comme `Err` sont acceptables.
//! Seul un panic, un débordement ou un blocage est un bug.

#![no_main]

use calque_vendors::fortigate::FortigateAdapter;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let adaptateur = FortigateAdapter;
    match std::str::from_utf8(data) {
        Ok(texte) => {
            let _ = adaptateur.import_str(texte, "fuzz.conf");
        }
        Err(_) => {
            let texte = String::from_utf8_lossy(data);
            let _ = adaptateur.import_str(&texte, "fuzz.conf");
        }
    }
});
