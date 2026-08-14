//! Tests de profondeur sur la fixture `corpus/fortigate/basic-export.yaml`
//! (export YAML FortiOS fictif et anonyme — l'équivalent exact de
//! `basic.conf`, adressage RFC1918 inventé).
//!
//! Le test clé : le `Device` importé via l'export YAML est ÉGAL à celui
//! importé via `basic.conf`, à l'exception des `SourceSpan` (les lignes
//! diffèrent évidemment entre les deux fichiers).

use calque_model::{Device, Fidelity, Severity, SourceSpan};
use calque_vendors::fortigate::FortigateAdapter;
use calque_vendors::fortigate_yaml::FortigateYamlAdapter;
use calque_vendors::{AdapterOutput, VendorAdapter};

/// Les deux fixtures, embarquées à la compilation (crate pur : aucune E/S).
const BASIC_CONF: &str = include_str!("../../../corpus/fortigate/basic.conf");
const BASIC_YAML: &str = include_str!("../../../corpus/fortigate/basic-export.yaml");
const FILE_YAML: &str = "basic-export.yaml";

fn import_yaml() -> AdapterOutput {
    FortigateYamlAdapter
        .import_str(BASIC_YAML, FILE_YAML)
        .expect("la fixture YAML doit produire un modèle")
}

/// Copie d'un `Device` avec tous les `SourceSpan` neutralisés : seuls
/// les routes et les règles en portent.
fn sans_spans(mut device: Device) -> Device {
    for vrf in device.vrfs.values_mut() {
        for route in &mut vrf.routes {
            route.source = None;
        }
    }
    for policy in device.policies.values_mut() {
        for rule in &mut policy.rules {
            rule.source = SourceSpan::new("", 0);
        }
    }
    device
}

// ---------------------------------------------------------------------------
// Détection croisée : chaque format matche SON adaptateur, pas l'autre
// ---------------------------------------------------------------------------

#[test]
fn detection_croisee_yaml_et_cli() {
    let yaml = FortigateYamlAdapter;
    let cli = FortigateAdapter;

    // L'export YAML matche fortement l'adaptateur YAML : en-tête
    // `#config-version=` (40) + sections (25) + entrées (15) + clés
    // indentées (10).
    let c = yaml.detect(BASIC_YAML);
    assert!(c.is_confident(), "score YAML sur YAML : {}", c.score());
    assert_eq!(c.score(), 90);

    // ... mais PAS l'adaptateur CLI : seul `#config-version=` matche, et
    // sans structure edit/next/end le score est plafonné à 30 (le cas
    // réel qui a motivé cet adaptateur).
    let c = cli.detect(BASIC_YAML);
    assert!(!c.is_confident(), "score CLI sur YAML : {}", c.score());
    assert_eq!(c.score(), 30);

    // Et réciproquement : l'export CLI ne matche pas l'adaptateur YAML
    // (ses lignes `config`/`edit`/`set`/`end` plafonnent le score à 20)...
    let c = yaml.detect(BASIC_CONF);
    assert!(!c.is_confident(), "score YAML sur CLI : {}", c.score());
    assert_eq!(c.score(), 20);

    // ... alors qu'il matche pleinement l'adaptateur CLI.
    assert_eq!(cli.detect(BASIC_CONF).score(), 100);

    // Vide et Cisco : aucun des deux.
    assert_eq!(yaml.detect("").score(), 0);
    let ios = "hostname r1\ninterface GigabitEthernet0/0\n ip address 10.0.0.1 255.255.255.0\n!\n";
    assert!(!yaml.detect(ios).is_confident());
}

// ---------------------------------------------------------------------------
// Import complet : fidélité et égalité avec l'import CLI
// ---------------------------------------------------------------------------

#[test]
fn fidelite_complete_sur_la_fixture_yaml() {
    let out = import_yaml();
    assert_eq!(
        out.fidelity,
        Fidelity::Complete,
        "la fixture YAML ne contient que des directives gérées"
    );
    // Les mêmes six notes Info que via le CLI : health-check SD-WAN,
    // topologie du tunnel IPsec, les deux objets externes (fqdn + géo),
    // politique 4 désactivée, politique 7 éclatée.
    let infos: Vec<_> = out
        .notes
        .iter()
        .filter(|n| n.severity == Severity::Info)
        .collect();
    assert_eq!(infos.len(), 6, "{infos:?}");
    let dit = |motif: &str| infos.iter().any(|n| n.message.contains(motif));
    assert!(dit("health-check SD-WAN"));
    assert!(dit("tunnel IPsec `vpn-site-a`"));
    assert!(dit("politique 4"));
    assert!(dit("politique 7 éclatée"));
    assert!(dit("fqdn-insights") && dit("insights.nutanix.com"));
    assert!(dit("geo-fr") && dit("FR"));
}

/// LE test clé : même équipement, quel que soit le format d'entrée.
#[test]
fn device_yaml_egal_au_device_cli_spans_mis_a_part() {
    let via_cli = FortigateAdapter
        .import_str(BASIC_CONF, "basic.conf")
        .expect("basic.conf doit produire un modèle");
    let via_yaml = import_yaml();

    assert_eq!(
        sans_spans(via_yaml.device),
        sans_spans(via_cli.device),
        "le Device importé via YAML doit être identique à celui importé via CLI"
    );
    // Même fidélité des deux côtés.
    assert_eq!(via_yaml.fidelity, via_cli.fidelity);
}

// ---------------------------------------------------------------------------
// Spans exacts : les lignes du fichier YAML, pas celles du CLI
// ---------------------------------------------------------------------------

#[test]
fn spans_exacts_de_deux_regles_dans_le_yaml() {
    let dev = import_yaml().device;
    let policy = dev
        .policies
        .values()
        .next()
        .expect("la politique forward existe");

    // Règle 1 : `- 1:` ligne 53, dernier attribut (`nat: enable`) ligne 62.
    let r1 = policy
        .rules
        .iter()
        .find(|r| r.id.as_str() == "1")
        .expect("règle 1");
    assert_eq!(r1.source.file, FILE_YAML);
    assert_eq!(r1.source.line, 53);
    assert_eq!(r1.source.end_line, Some(62));

    // Règle 3 : `- 3:` ligne 72, dernier attribut ligne 80.
    let r3 = policy
        .rules
        .iter()
        .find(|r| r.id.as_str() == "3")
        .expect("règle 3");
    assert_eq!(r3.source.file, FILE_YAML);
    assert_eq!(r3.source.line, 72);
    assert_eq!(r3.source.end_line, Some(80));
}

// ---------------------------------------------------------------------------
// Robustesse : jamais de panique sur une entrée externe
// ---------------------------------------------------------------------------

#[test]
fn entrees_hostiles_sans_panique() {
    let adapter = FortigateYamlAdapter;
    for raw in [
        "",
        "juste du texte\n",
        "- orphelin:\n",
        "a: [jamais ferme\n",
        "system_interface:\n    - wan1:\n        ip: [999.999.999.999]\n",
        "firewall_policy:\n    - oops:\n        action: self-destruct\n",
        "a:\n\tb: \"non ferme\n",
        "\u{0}\u{1}: binaire\n",
    ] {
        // Ok(modèle partiel) ou Err(diagnostics) : tout sauf une panique.
        let _ = adapter.import_str(raw, "hostile.yaml");
        let _ = adapter.detect(raw);
    }
}
