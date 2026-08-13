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

/// Non-régression du dispatch d'import : la sélection se fait par
/// ADAPTATEUR (score de détection), jamais par `Vendor` — chacun des cinq
/// formats du corpus doit s'importer avec son propre adaptateur. Le cas
/// FortiGate export YAML vs CLI (même `Vendor`) est celui qui a cassé.
#[test]
fn import_dispatch_tous_les_formats_du_corpus() {
    let fixtures: &[(&str, &str)] = &[
        (
            "basic.conf",
            include_str!("../../../corpus/fortigate/basic.conf"),
        ),
        (
            "basic-export.yaml",
            include_str!("../../../corpus/fortigate/basic-export.yaml"),
        ),
        (
            "cisco.conf",
            include_str!("../../../corpus/cisco_ios/basic.conf"),
        ),
        (
            "opnsense.xml",
            include_str!("../../../corpus/opnsense/basic.xml"),
        ),
        (
            "basic.nft",
            include_str!("../../../corpus/nftables/basic.nft"),
        ),
    ];
    for (nom, contenu) in fixtures {
        let tmp = TempDir::new().expect("répertoire temporaire");
        std::fs::write(tmp.path().join(nom), contenu).expect("écriture de la fixture");
        let out = calque(tmp.path(), &["import", nom]);
        assert_code(&out, 0);
        let txt = stdout(&out);
        assert!(
            txt.contains("1 configuration(s) importée(s)"),
            "import de {nom} : {txt}"
        );
        // Aucune fixture ne doit s'importer vide : le mauvais adaptateur
        // produirait 0 interface (c'était le symptôme du bug).
        assert!(
            !txt.contains("(0 interface(s)"),
            "import de {nom} vide — mauvais adaptateur choisi : {txt}"
        );
    }
}

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
fn path_json_est_structure() {
    let tmp = projet_importe();
    let out = calque(
        tmp.path(),
        &[
            "path",
            "10.10.1.55",
            "->",
            "10.10.2.10:8443/tcp",
            "--format",
            "json",
        ],
    );
    assert_code(&out, 0);
    let v: serde_json::Value = serde_json::from_str(&stdout(&out)).expect("sortie JSON valide");
    assert_eq!(v["verdict"], "Allowed");
    let hops = v["hops"].as_array().expect("tableau hops");
    assert!(!hops.is_empty(), "au moins un saut");
    assert_eq!(hops[0]["device"], "fw-lab-01");
    // La justification règle par règle est structurée, span compris.
    let decisions = hops[0]["decisions"].as_array().expect("tableau decisions");
    assert!(
        decisions.iter().any(|d| d["rule"] == "2"),
        "la règle décisive est présente : {decisions:?}"
    );
}

#[test]
fn path_json_refuse_garde_le_code_de_sortie() {
    let tmp = projet_importe();
    // Politique 3 : z-dmz → lan refusé ; le JSON est la seule sortie et
    // le code de sortie reste 1.
    let out = calque(
        tmp.path(),
        &[
            "path",
            "10.10.2.10",
            "->",
            "10.10.1.55:445/tcp",
            "--format",
            "json",
        ],
    );
    assert_code(&out, 1);
    let v: serde_json::Value = serde_json::from_str(&stdout(&out)).expect("sortie JSON valide");
    assert_eq!(v["verdict"], "Denied");
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
fn test_json_est_structure() {
    let tmp = projet_importe();
    std::fs::write(tmp.path().join("flows.yaml"), FLOWS).expect("écriture flows.yaml");
    let out = calque(tmp.path(), &["test", "--format", "json"]);
    assert_code(&out, 1);
    let v: serde_json::Value = serde_json::from_str(&stdout(&out)).expect("sortie JSON valide");
    assert_eq!(v["tests"], 3);
    assert_eq!(v["failures"], 1);
    let results = v["results"].as_array().expect("tableau results");
    assert_eq!(results.len(), 3);
    // Le flux volontairement faux est ROMPU, avec attendu/obtenu.
    let broken = results
        .iter()
        .find(|r| r["status"] == "Broken")
        .expect("un flux en échec");
    assert_eq!(broken["expected"], "allow");
    assert_eq!(broken["actual"], "deny");
    assert!(
        broken["name"]
            .as_str()
            .expect("nom du flux")
            .contains("volontairement faux"),
        "le flux en échec est nommé : {broken:?}"
    );
    // Les flux conformes portent leur justification (règle décisive).
    assert!(
        results
            .iter()
            .any(|r| r["status"] == "Ok"
                && r["detail"].as_str().is_some_and(|d| d.contains("règle"))),
        "justification présente : {results:?}"
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
// reach (mode symbolique)
// ---------------------------------------------------------------------------

#[test]
fn reach_to_trouve_le_flux_autorise() {
    let tmp = projet_importe();
    // Politique 2 de la fixture : r-postes (10.10.1.50-69) → h-srv-web
    // (10.10.2.10) sur TCP-8443. Le rapport doit trouver ce flux, citer la
    // règle décisive et donner un paquet exemple.
    let out = calque(tmp.path(), &["reach", "--to", "10.10.2.10:8443/tcp"]);
    assert_code(&out, 0);
    let txt = stdout(&out);
    assert!(
        txt.contains("Tout ce qui peut atteindre 10.10.2.10:8443/tcp"),
        "sortie reach : {txt}"
    );
    assert!(txt.contains("entrée fw-lab-01/lan"), "sortie reach : {txt}");
    // L'ensemble couvre la plage r-postes (10.10.1.50-69) : son premier
    // préfixe apparaît dans le résumé.
    assert!(txt.contains("10.10.1.50/31"), "l'ensemble résumé : {txt}");
    assert!(txt.contains("exemple"), "le paquet exemple : {txt}");
    assert!(
        txt.contains("autorisé par la règle 2"),
        "la règle décisive : {txt}"
    );
    assert!(txt.contains("ligne 82"), "la ligne d'origine : {txt}");
}

#[test]
fn reach_from_liste_ce_que_la_dmz_atteint() {
    let tmp = projet_importe();
    // Politique 5 : h-srv-web (10.10.2.10) → wan, tout service. La route
    // par défaut sort par « wan », interface sans lien modélisé : le
    // rapport contient donc des parts non décidables, affichées
    // honnêtement, et le code de sortie est 3 (rapport non ferme, §6.3).
    let out = calque(tmp.path(), &["reach", "--from", "10.10.2.10"]);
    assert_code(&out, 3);
    let txt = stdout(&out);
    assert!(
        txt.contains("Tout ce que 10.10.2.10 peut atteindre"),
        "sortie reach : {txt}"
    );
    assert!(txt.contains("entrée fw-lab-01/dmz"), "sortie reach : {txt}");
    assert!(
        txt.contains("autorisé par la règle 5"),
        "la règle décisive : {txt}"
    );
    assert!(
        txt.contains("part(s) non décidable(s)"),
        "les parts indécidables sont affichées : {txt}"
    );
    assert!(txt.contains("NON FERME"), "sortie reach : {txt}");
}

#[test]
fn reach_to_zone_du_modele() {
    let tmp = projet_importe();
    // La zone z-dmz de la fixture couvre le sous-réseau 10.10.2.0/24.
    let out = calque(tmp.path(), &["reach", "--to", "z-dmz:8443/tcp"]);
    assert_code(&out, 0);
    let txt = stdout(&out);
    assert!(
        txt.contains("la zone « z-dmz » (10.10.2.0/24):8443/tcp"),
        "sortie reach : {txt}"
    );
    assert!(
        txt.contains("autorisé par la règle 2"),
        "la règle décisive : {txt}"
    );
}

#[test]
fn reach_zone_inconnue_erreur_claire() {
    let tmp = projet_importe();
    let out = calque(tmp.path(), &["reach", "--to", "vlan-fantome"]);
    assert_code(&out, 1);
    let txt = stderr(&out);
    // (miette replie le message : on vérifie le début de la phrase.)
    assert!(txt.contains("vlan-fantome"), "stderr : {txt}");
    assert!(
        txt.contains("ne correspond ni à une adresse"),
        "l'erreur est claire : {txt}"
    );
}

#[test]
fn reach_json_est_structure() {
    let tmp = projet_importe();
    let out = calque(
        tmp.path(),
        &["reach", "--to", "10.10.2.10:8443/tcp", "--format", "json"],
    );
    assert_code(&out, 0);
    let v: serde_json::Value = serde_json::from_str(&stdout(&out)).expect("sortie JSON valide");
    let flows = v["flows"].as_array().expect("tableau flows");
    assert!(!flows.is_empty(), "au moins un flux");
    assert_eq!(flows[0]["entry"], "fw-lab-01/lan");
}

// ---------------------------------------------------------------------------
// model dead-rules
// ---------------------------------------------------------------------------

#[test]
fn dead_rules_fixture_saine() {
    let tmp = projet_importe();
    // La fixture n'a pas de règle morte : les zones des politiques sont
    // deux à deux incompatibles (et la politique 4, désactivée, n'est pas
    // importée).
    let out = calque(tmp.path(), &["model", "dead-rules"]);
    assert_code(&out, 0);
    let txt = stdout(&out);
    assert!(txt.contains("Aucune règle morte"), "sortie : {txt}");
    assert!(
        txt.contains("1 équipement(s) analysé(s), 0 règle(s) morte(s), 0 exclue(s)."),
        "sortie : {txt}"
    );
}

#[test]
fn dead_rules_detecte_une_regle_masquee() {
    // La fixture augmentée d'une politique 6 identique à la 2 (mêmes
    // zones, mêmes objets) mais en refus : entièrement masquée par la 2.
    // L'edit est inséré DANS le bloc `config firewall policy` existant
    // (le dernier bloc de la fixture), pas dans un second bloc.
    let tmp = TempDir::new().expect("répertoire temporaire");
    let tronc = BASIC
        .trim_end()
        .strip_suffix("end")
        .expect("la fixture se termine par le `end` du bloc de politiques");
    let augmentee = format!(
        "{tronc}    edit 6\n        set name \"doublon-mort\"\n        \
         set srcintf \"lan\"\n        set dstintf \"z-dmz\"\n        set srcaddr \"r-postes\"\n        \
         set dstaddr \"h-srv-web\"\n        set action deny\n        set schedule \"always\"\n        \
         set service \"TCP-8443\"\n    next\nend\n"
    );
    std::fs::write(tmp.path().join("masque.conf"), augmentee).expect("écriture");
    let out = calque(tmp.path(), &["import", "masque.conf"]);
    assert_code(&out, 0);

    let out = calque(tmp.path(), &["model", "dead-rules"]);
    assert_code(&out, 0);
    let txt = stdout(&out);
    assert!(txt.contains("MASQUÉE"), "sortie : {txt}");
    assert!(txt.contains("règle 6"), "la règle morte : {txt}");
    assert!(
        txt.contains("masquée par : la règle 2"),
        "le masque : {txt}"
    );
    assert!(txt.contains("ligne 82"), "la ligne du masque : {txt}");
    assert!(txt.contains("paquet témoin"), "le témoin : {txt}");
    assert!(
        txt.contains("1 équipement(s) analysé(s), 1 règle(s) morte(s), 0 exclue(s)."),
        "sortie : {txt}"
    );
}

#[test]
fn dead_rules_json_est_structure() {
    let tmp = projet_importe();
    let out = calque(tmp.path(), &["model", "dead-rules", "--format", "json"]);
    assert_code(&out, 0);
    let v: serde_json::Value = serde_json::from_str(&stdout(&out)).expect("sortie JSON valide");
    assert_eq!(v["devices"], 1);
    assert_eq!(v["rules"].as_array().expect("tableau rules").len(), 0);
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
// scrub (§10, §11.4)
// ---------------------------------------------------------------------------

#[test]
fn scrub_un_fichier_vers_stdout() {
    let tmp = TempDir::new().expect("répertoire temporaire");
    std::fs::write(tmp.path().join("basic.conf"), BASIC).expect("écriture de la fixture");
    let out = calque(tmp.path(), &["scrub", "basic.conf"]);
    assert_code(&out, 0);
    let txt = stdout(&out);

    // Aucune adresse ni nom d'origine ne subsiste.
    for original in ["10.10.1.1", "10.10.2.10", "10.200.0.2", "fw-lab-01"] {
        assert!(!txt.contains(original), "« {original} » a fui : {txt}");
    }
    // La structure survit : directives, masques et numéros intacts.
    assert!(txt.contains("config firewall policy"), "structure : {txt}");
    assert!(txt.contains("255.255.255.0"), "masque intact : {txt}");
    assert!(txt.contains("edit 2"), "identifiants de règles : {txt}");
    assert!(txt.contains("set tcp-portrange 8443"), "ports : {txt}");
    // Le rappel §11.4 est sur stderr (la sortie redirigée reste propre).
    let err = stderr(&out);
    assert!(err.contains("pas un chiffrement"), "rappel §11.4 : {err}");
    assert!(!txt.contains("pas un chiffrement"), "stdout propre : {txt}");

    // La sortie se ré-analyse : l'import du résultat anonymisé passe.
    std::fs::write(tmp.path().join("anon.conf"), &txt).expect("écriture du résultat");
    let out = calque(tmp.path(), &["import", "anon.conf"]);
    assert_code(&out, 0);
    assert!(
        stdout(&out).contains("FortiGate"),
        "le résultat reste une configuration FortiGate"
    );
}

#[test]
fn scrub_multi_fichiers_coherent() {
    let tmp = TempDir::new().expect("répertoire temporaire");
    // La même adresse dans deux fichiers : le remplacement doit être
    // identique des deux côtés (un seul Scrubber pour tout l'appel).
    std::fs::write(
        tmp.path().join("a.conf"),
        "set ip 10.77.66.55 255.255.255.0\n",
    )
    .expect("écriture a.conf");
    std::fs::write(tmp.path().join("b.conf"), "ping 10.77.66.55\n").expect("écriture b.conf");

    let out = calque(tmp.path(), &["scrub", "a.conf", "b.conf"]);
    assert_code(&out, 0);
    let txt = stdout(&out);
    assert!(txt.contains("2 fichier(s) anonymisé(s)."), "récap : {txt}");
    assert!(txt.contains("a.anon.conf"), "nommage : {txt}");

    let a = std::fs::read_to_string(tmp.path().join("a.anon.conf")).expect("a.anon.conf");
    let b = std::fs::read_to_string(tmp.path().join("b.anon.conf")).expect("b.anon.conf");
    assert!(!a.contains("10.77.66.55"), "a anonymisé : {a}");
    assert!(!b.contains("10.77.66.55"), "b anonymisé : {b}");
    // Le remplacement extrait de b se retrouve tel quel dans a.
    let remplacement = b
        .trim()
        .strip_prefix("ping ")
        .expect("b garde sa structure")
        .to_owned();
    assert!(
        a.contains(&format!("set ip {remplacement} 255.255.255.0")),
        "cohérence inter-fichiers : a = {a}, remplacement = {remplacement}"
    );
}

#[test]
fn scrub_map_ecrit_la_table_de_correspondance() {
    let tmp = TempDir::new().expect("répertoire temporaire");
    std::fs::write(tmp.path().join("basic.conf"), BASIC).expect("écriture de la fixture");
    let out = calque(tmp.path(), &["scrub", "basic.conf", "--map", "table.tsv"]);
    assert_code(&out, 0);

    let table = std::fs::read_to_string(tmp.path().join("table.tsv")).expect("table.tsv");
    // L'avertissement de tête.
    assert!(
        table.starts_with("# Table de correspondance"),
        "en-tête : {table}"
    );
    assert!(
        table.contains("ne jamais publier"),
        "avertissement : {table}"
    );
    // Une correspondance connue : le hostname de la fixture.
    assert!(
        table.contains("fw-lab-01\tanon-host-1"),
        "correspondance hostname : {table}"
    );
    // Les adresses y sont, en original<TAB>remplacement.
    assert!(table.contains("10.10.2.10\t"), "adresse : {table}");
}

#[test]
fn scrub_refuse_d_ecraser_sans_force() {
    let tmp = TempDir::new().expect("répertoire temporaire");
    std::fs::write(tmp.path().join("a.conf"), "ping 10.1.2.3\n").expect("écriture a.conf");
    std::fs::write(tmp.path().join("b.conf"), "ping 10.4.5.6\n").expect("écriture b.conf");
    std::fs::write(tmp.path().join("a.anon.conf"), "sentinelle\n").expect("écriture sentinelle");

    let out = calque(tmp.path(), &["scrub", "a.conf", "b.conf"]);
    assert_code(&out, 1);
    let err = stderr(&out);
    assert!(err.contains("existe déjà"), "refus : {err}");
    assert!(err.contains("--force"), "l'aide mentionne --force : {err}");
    // Rien n'a été écrit : la sentinelle est intacte, b n'a pas de sortie.
    let sentinelle = std::fs::read_to_string(tmp.path().join("a.anon.conf")).expect("sentinelle");
    assert_eq!(sentinelle, "sentinelle\n");
    assert!(
        !tmp.path().join("b.anon.conf").exists(),
        "aucune sortie partielle"
    );

    // Avec --force, l'écrasement est accepté.
    let out = calque(tmp.path(), &["scrub", "a.conf", "b.conf", "--force"]);
    assert_code(&out, 0);
    let a = std::fs::read_to_string(tmp.path().join("a.anon.conf")).expect("a.anon.conf");
    assert_ne!(a, "sentinelle\n", "la sortie a bien remplacé la sentinelle");
    assert!(!a.contains("10.1.2.3"), "et elle est anonymisée : {a}");
}

#[test]
fn scrub_fichier_introuvable_et_non_utf8() {
    let tmp = TempDir::new().expect("répertoire temporaire");
    // Introuvable : erreur claire, pas de panique.
    let out = calque(tmp.path(), &["scrub", "fantome.conf"]);
    assert_code(&out, 1);
    assert!(
        stderr(&out).contains("fantome.conf"),
        "le fichier est nommé : {}",
        stderr(&out)
    );

    // Non-UTF8 : message clair, pas de panique.
    std::fs::write(tmp.path().join("binaire.conf"), [0xff, 0xfe, 0x00, 0x42])
        .expect("écriture binaire");
    let out = calque(tmp.path(), &["scrub", "binaire.conf"]);
    assert_code(&out, 1);
    assert!(
        stderr(&out).contains("UTF-8"),
        "l'encodage est expliqué : {}",
        stderr(&out)
    );
}

// ---------------------------------------------------------------------------
// bornes de taille (audit R1)
// ---------------------------------------------------------------------------

#[test]
fn flows_trop_gros_refuse_proprement() {
    let tmp = projet_importe();
    // 4 Mo + 1 octet de commentaires : refusé AVANT le parseur YAML.
    let gros = "#".repeat(4 * 1024 * 1024 + 1);
    std::fs::write(tmp.path().join("flows.yaml"), gros).expect("écriture flows.yaml");
    let out = calque(tmp.path(), &["test"]);
    assert_code(&out, 1);
    let err = stderr(&out);
    assert!(err.contains("limite"), "la borne est expliquée : {err}");
    assert!(err.contains("4 Mo"), "la borne est chiffrée : {err}");
    assert!(err.contains("flows.yaml"), "le fichier est nommé : {err}");
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
