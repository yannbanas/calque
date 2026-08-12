//! Cible de fuzzing : couche 1 FortiGate (`calque_parse::fortigate::parse`).
//!
//! §11.3 — les configurations sont des entrées non fiables, potentiellement
//! issues d'un équipement compromis. On ne vérifie AUCUN résultat : `Ok` et
//! `Err` sont tous deux acceptables. Seul un panic, un débordement ou un
//! blocage est un bug.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // L'API prend un &str : on fuzze quand même les octets non-UTF8 via
    // une conversion avec pertes, pour couvrir les séquences invalides.
    match std::str::from_utf8(data) {
        Ok(texte) => {
            let _ = calque_parse::fortigate::parse(texte, "fuzz.conf");
        }
        Err(_) => {
            let texte = String::from_utf8_lossy(data);
            let _ = calque_parse::fortigate::parse(&texte, "fuzz.conf");
        }
    }
});
