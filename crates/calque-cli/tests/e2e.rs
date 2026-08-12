//! Tests de bout en bout du binaire `calque` sur la fixture
//! `corpus/fortigate/basic.conf` : import → model check → path → test.
//!
//! Chaque scénario tourne dans un répertoire temporaire : le projet
//! `.calque/` y est créé et détruit avec lui.

use std::path::Path;
use std::process::Output;

use assert_cmd::Command;
use tempfile::TempDir;

/// La fixture, embarquée à la compilation.
const BASIC: &str = include_str!("../../../corpus/fortigate/basic.conf");

fn calque(dir: &Path, args: &[&str]) -> Output {
    Command::cargo_bin("calque")
        .expect("binaire calque compilé")
        .current_dir(dir)
        .args(args)
        .output()
        .expect("exécution du binaire")
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn assert_code(output: &Output, expected: i32) {
    assert_eq!(
        output.status.code(),
        Some(expected),
        "code de sortie inattendu\n--- stdout ---\n{}\n--- stderr ---\n{}",
        stdout(output),
        stderr(output)
    );
}

/// Prépare un projet importé depuis la fixture dans un répertoire
/// temporaire.
fn projet_importe() -> TempDir {
    let tmp = TempDir::new().expect("répertoire temporaire");
    std::fs::write(tmp.path().join("basic.conf"), BASIC).expect("écriture de la fixture");
    let out = calque(tmp.path(), &["import", "basic.conf"]);
    assert_code(&out, 0);
    tmp
}

// ---------------------------------------------------------------------------
// import → model check
// ---------------------------------------------------------------------------

#[test]
fn import_puis_model_check_complet() {
    let tmp = projet_importe();

    // L'import annonce l'équipement détecté (hostname de la fixture).
    let out = calque(tmp.path(), &["import", "basic.conf"]);
    let txt = stdout(&out);
    assert!(txt.contains("fw-lab-01"), "sortie import : {txt}");
    assert!(txt.contains("FortiGate"), "sortie import : {txt}");
    // La politique 4 désactivée est signalée comme note, pas comme lacune.
    assert!(txt.contains("note"), "sortie import : {txt}");

    // La fixture est entièrement comprise : fidélité COMPLÈTE, code 0.
    let out = calque(tmp.path(), &["model", "check"]);
    assert_code(&out, 0);
    let txt = stdout(&out);
    assert!(txt.contains("COMPLÈTE"), "sortie model check : {txt}");
    assert!(
        txt.contains("1 équipement(s)"),
        "sortie model check : {txt}"
    );
}

#[test]
fn import_fichier_inconnu_liste_les_scores() {
    let tmp = TempDir::new().expect("répertoire temporaire");
    std::fs::write(
        tmp.path().join("notes.txt"),
        "bonjour, ceci n'est pas une configuration\n",
    )
    .expect("écriture");
    let out = calque(tmp.path(), &["import", "notes.txt"]);
    assert_code(&out, 1);
    let txt = stderr(&out);
    assert!(txt.contains("non reconnu"), "stderr : {txt}");
    assert!(txt.contains("FortiGate"), "les scores sont listés : {txt}");
}

// ---------------------------------------------------------------------------
// path
// ---------------------------------------------------------------------------

#[test]
fn path_autorise_avec_regle_et_ligne() {
    let tmp = projet_importe();
    // Politique 2 de la fixture : r-postes (10.10.1.50-69) → h-srv-web
    // (10.10.2.10) sur TCP-8443.
    let out = calque(
        tmp.path(),
        &["path", "10.10.1.55", "->", "10.10.2.10:8443/tcp"],
    );
    assert_code(&out, 0);
    let txt = stdout(&out);
    assert!(txt.contains("autorisé"), "sortie path : {txt}");
    assert!(txt.contains("règle 2"), "la règle décisive : {txt}");
    assert!(txt.contains("ligne 82"), "la ligne d'origine : {txt}");
}

#[test]
fn path_refuse_sort_en_erreur() {
    let tmp = projet_importe();
    // Politique 3 : z-dmz → lan refusé explicitement.
    let out = calque(
        tmp.path(),
        &["path", "10.10.2.10", "->", "10.10.1.55:445/tcp"],
    );
    assert_code(&out, 1);
    let txt = stdout(&out);
    assert!(txt.contains("refusé"), "sortie path : {txt}");
    assert!(txt.contains("règle 3"), "la règle décisive : {txt}");
    assert!(txt.contains("ligne 92"), "la ligne d'origine : {txt}");
}

#[test]
fn path_explain_montre_la_trace() {
    let tmp = projet_importe();
    let out = calque(
        tmp.path(),
        &[
            "path",
            "10.10.1.55",
            "->",
            "10.10.2.10:8443/tcp",
            "--explain",
        ],
    );
    assert_code(&out, 0);
    let txt = stdout(&out);
    assert!(txt.contains("Verdict : autorisé"), "trace : {txt}");
    assert!(txt.contains("fw-lab-01"), "trace : {txt}");
    assert!(txt.contains("filtre de sortie"), "trace : {txt}");
    assert!(txt.contains("route retenue"), "trace : {txt}");
}

#[test]
fn path_sur_modele_partiel_est_non_ferme() {
    // La fixture augmentée d'une directive inconnue sur une interface :
    // fidélité partielle → aucun verdict ferme sur un chemin qui traverse
    // l'équipement (§6.3), code de sortie dédié 3.
    let tmp = TempDir::new().expect("répertoire temporaire");
    let exotique = format!(
        "{BASIC}config system interface\n    edit \"lan\"\n        set gadget-quantique enable\n    next\nend\n"
    );
    std::fs::write(tmp.path().join("partiel.conf"), exotique).expect("écriture");
    let out = calque(tmp.path(), &["import", "partiel.conf"]);
    assert_code(&out, 0);
    assert!(stdout(&out).contains("PARTIEL"), "avertissement d'import");

    let out = calque(
        tmp.path(),
        &["path", "10.10.1.55", "->", "10.10.2.10:8443/tcp"],
    );
    assert_code(&out, 3);
    let txt = stdout(&out);
    assert!(txt.contains("NON FERME"), "sortie path : {txt}");
}

// ---------------------------------------------------------------------------
// test (flows.yaml)
// ---------------------------------------------------------------------------

/// Trois flux sur la fixture : un allow vrai (CIDR résolu en première
/// adresse hôte), un deny vrai (zone symbolique résolue), et un allow
/// volontairement faux.
const FLOWS: &str = "\
flows:
  - name: les postes joignent le serveur web de la dmz
    from: 10.10.1.50/31
    to: 10.10.2.10
    port: 8443/tcp
    expect: allow

  - name: la dmz est isolée du lan
    from: 10.10.2.10
    to: lan
    port: 445/tcp
    expect: deny

  - name: la dmz joint le lan (volontairement faux)
    from: 10.10.2.10
    to: 10.10.1.55
    port: 80/tcp
    expect: allow
";

#[test]
fn test_texte_avec_un_flux_en_echec() {
    let tmp = projet_importe();
    std::fs::write(tmp.path().join("flows.yaml"), FLOWS).expect("écriture flows.yaml");
    let out = calque(tmp.path(), &["test"]);
    assert_code(&out, 1);
    let txt = stdout(&out);
    assert!(txt.contains("ROMPU"), "sortie test : {txt}");
    assert!(
        txt.contains("3 flux testé(s), 1 échec(s)."),
        "sortie test : {txt}"
    );
    // Les deux flux conformes sont OK, avec la règle décisive.
    assert!(txt.contains("OK"), "sortie test : {txt}");
    assert!(txt.contains("règle 3"), "justification : {txt}");
}

#[test]
fn test_junit_contient_failure() {
    let tmp = projet_importe();
    std::fs::write(tmp.path().join("flows.yaml"), FLOWS).expect("écriture flows.yaml");
    let out = calque(tmp.path(), &["test", "--format", "junit"]);
    assert_code(&out, 1);
    let txt = stdout(&out);
    assert!(
        txt.contains(r#"<testsuite name="calque" tests="3" failures="1">"#),
        "junit : {txt}"
    );
    assert!(txt.contains("<failure"), "junit : {txt}");
    assert!(
        txt.contains("volontairement faux"),
        "le flux en échec est nommé : {txt}"
    );
}

#[test]
fn test_extremite_non_resolue_compte_en_echec() {
    let tmp = projet_importe();
    let flows = "\
flows:
  - name: zone inexistante
    from: vlan-fantome
    to: 10.10.2.10
    port: 443/tcp
    expect: allow
";
    std::fs::write(tmp.path().join("flows.yaml"), flows).expect("écriture flows.yaml");
    let out = calque(tmp.path(), &["test"]);
    assert_code(&out, 1);
    let txt = stdout(&out);
    assert!(txt.contains("extrémité non résolue"), "sortie test : {txt}");
    assert!(txt.contains("vlan-fantome"), "sortie test : {txt}");
}

// ---------------------------------------------------------------------------
// plan
// ---------------------------------------------------------------------------

#[test]
fn plan_sans_changement_est_calme() {
    let tmp = projet_importe();
    // La candidate est identique au modèle courant : rien ne change.
    std::fs::write(tmp.path().join("candidate.conf"), BASIC).expect("écriture candidate");
    let out = calque(tmp.path(), &["plan", "--candidate", "candidate.conf"]);
    assert_code(&out, 0);
    let txt = stdout(&out);
    assert!(
        txt.contains("Aucun changement de comportement détecté."),
        "sortie plan : {txt}"
    );
}

#[test]
fn plan_detecte_un_flux_rompu() {
    let tmp = projet_importe();
    // La candidate passe la politique 2 (lan-vers-dmz-web) en refus.
    let candidate = BASIC.replace(
        "set dstaddr \"h-srv-web\"\n        set action accept",
        "set dstaddr \"h-srv-web\"\n        set action deny",
    );
    assert_ne!(candidate, BASIC, "le remplacement doit avoir porté");
    std::fs::write(tmp.path().join("candidate.conf"), candidate).expect("écriture candidate");
    let flows = "\
flows:
  - name: les postes joignent le serveur web de la dmz
    from: 10.10.1.55
    to: 10.10.2.10
    port: 8443/tcp
    expect: allow
";
    std::fs::write(tmp.path().join("flows.yaml"), flows).expect("écriture flows.yaml");

    let out = calque(tmp.path(), &["plan", "--candidate", "candidate.conf"]);
    assert_code(&out, 1);
    let txt = stdout(&out);
    assert!(txt.contains("ROMPU"), "sortie plan : {txt}");
    assert!(txt.contains("avant : autorisé"), "avant/après : {txt}");
    assert!(txt.contains("après : refusé"), "avant/après : {txt}");
    assert!(txt.contains("règle 2"), "la règle décisive : {txt}");
}

// ---------------------------------------------------------------------------
// topology check
// ---------------------------------------------------------------------------

#[test]
fn topology_check_sur_un_seul_equipement() {
    let tmp = projet_importe();
    // Un seul équipement : rien à inférer, aucune erreur (les interfaces
    // isolées sont des infos, souvent normales pour le WAN).
    let out = calque(tmp.path(), &["topology", "check"]);
    assert_code(&out, 0);
    let txt = stdout(&out);
    assert!(
        txt.contains("Aucun lien inféré par sous-réseau."),
        "sortie topologie : {txt}"
    );
}

#[test]
fn topology_check_signale_un_lien_declare_casse() {
    let tmp = projet_importe();
    let topo = "\
links:
  - a: {device: fw-lab-01, iface: wan}
    b: {device: fw-core, iface: port1}
";
    std::fs::write(tmp.path().join("topology.yaml"), topo).expect("écriture topology.yaml");
    let out = calque(tmp.path(), &["topology", "check"]);
    assert_code(&out, 1);
    let txt = stdout(&out);
    assert!(
        txt.contains("1 lien(s) déclaré(s) chargé(s)"),
        "sortie topologie : {txt}"
    );
    assert!(txt.contains("fw-core"), "sortie topologie : {txt}");
    assert!(txt.contains("erreur"), "sortie topologie : {txt}");
}
