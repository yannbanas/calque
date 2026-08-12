//! Cible de fuzzing : couche 1 Cisco IOS (`calque_parse::cisco_ios::parse`).
//!
//! §11.3 — aucun résultat inspecté : `Ok` comme `Err` sont acceptables.
//! Seul un panic, un débordement ou un blocage est un bug.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    match std::str::from_utf8(data) {
        Ok(texte) => {
            let _ = calque_parse::cisco_ios::parse(texte, "fuzz.conf");
        }
        Err(_) => {
            let texte = String::from_utf8_lossy(data);
            let _ = calque_parse::cisco_ios::parse(&texte, "fuzz.conf");
        }
    }
});
