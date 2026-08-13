//! Tests du point d'entrée de bibliothèque `detect_and_import` (sans
//! I/O) : sélection par score parmi tous les adaptateurs, erreurs
//! structurées — jamais de supposition (§6.3).

use calque_model::Vendor;
use calque_vendors::{detect_and_import, score_summary, DetectImportError};

/// Les fixtures du corpus, embarquées à la compilation (crate pur).
const FORTIGATE: &str = include_str!("../../../corpus/fortigate/basic.conf");
const FORTIGATE_YAML: &str = include_str!("../../../corpus/fortigate/basic-export.yaml");
const CISCO: &str = include_str!("../../../corpus/cisco_ios/basic.conf");
const OPNSENSE: &str = include_str!("../../../corpus/opnsense/basic.xml");
const NFTABLES: &str = include_str!("../../../corpus/nftables/basic.nft");

#[test]
fn detecte_chaque_format_du_corpus() {
    let cas: &[(&str, Vendor)] = &[
        (FORTIGATE, Vendor::Fortigate),
        (FORTIGATE_YAML, Vendor::Fortigate),
        (CISCO, Vendor::CiscoIos),
        (OPNSENSE, Vendor::Opnsense),
        (NFTABLES, Vendor::Nftables),
    ];
    for (raw, vendor) in cas {
        let detected = detect_and_import(raw, "fixture").expect("import de la fixture");
        assert_eq!(detected.vendor, *vendor);
        assert!(
            !detected.output.device.interfaces.is_empty(),
            "un import vide trahirait un mauvais adaptateur ({})",
            detected.adapter
        );
    }
}

#[test]
fn le_label_alimente_les_source_span() {
    let detected = detect_and_import(FORTIGATE, "archives/fw-2026-08.conf").expect("import");
    let policy = detected
        .output
        .device
        .policies
        .values()
        .next()
        .expect("au moins une politique");
    let rule = policy.rules.first().expect("au moins une règle");
    assert_eq!(
        rule.source.file, "archives/fw-2026-08.conf",
        "chaque règle porte le libellé fourni par l'appelant"
    );
}

#[test]
fn texte_non_reconnu_rend_les_scores() {
    let err = detect_and_import("bonjour, ceci n'est pas une configuration\n", "notes.txt")
        .expect_err("rien à reconnaître");
    let DetectImportError::Unrecognized { scores } = &err else {
        panic!("erreur inattendue : {err:?}");
    };
    // Un score par adaptateur connu, tous sous le seuil.
    assert_eq!(scores.len(), 5);
    assert!(scores.iter().all(|s| !s.confidence.is_confident()));
    // Le résumé humain liste chaque adaptateur avec son score.
    let summary = score_summary(scores);
    assert!(summary.contains("/100"), "résumé : {summary}");
    // Le Display français reste utilisable tel quel par un consommateur.
    assert!(
        err.to_string().contains("constructeur non reconnu"),
        "message : {err}"
    );
}
