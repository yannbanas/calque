//! Tests de bout en bout du scrub sur la fixture FortiGate du corpus,
//! plus les garanties transversales : cohérence inter-fichiers, secrets,
//! plages de documentation, masques, idempotence, entrées hostiles.

use std::collections::HashMap;
use std::net::Ipv4Addr;

use calque_parse::{fortigate, fortigate_yaml, ConfigNode};
use calque_scrub::Scrubber;
use ipnet::Ipv4Net;

const FIXTURE: &str = include_str!("../../../corpus/fortigate/basic.conf");
const FIXTURE_YAML: &str = include_str!("../../../corpus/fortigate/basic-export.yaml");

/// Tous les noms choisis par l'utilisateur dans la fixture.
const NOMS_ORIGINAUX: &[&str] = &[
    "fw-lab-01",
    "lan",
    "dmz",
    "wan",
    "z-dmz",
    "h-srv-web",
    "r-postes",
    "g-serveurs",
    "TCP-8443",
    "APP-SYNC",
    "g-apps",
    "lan-vers-wan",
    "lan-vers-dmz-web",
    "dmz-isolement",
    "ancienne-regle",
    "dmz-vers-wan",
];

/// Toutes les adresses de la fixture (les masques n'en font pas partie).
const ADRESSES_ORIGINALES: &[&str] = &[
    "10.10.1.1",
    "10.10.2.1",
    "10.200.0.2",
    "10.200.0.1",
    "10.10.2.10",
    "10.10.1.50",
    "10.10.1.69",
];

/// Les runs `[0-9.]` d'un texte : pour chercher une adresse en tant que
/// lexème entier, sans faux positif de sous-chaîne (10.10.1.1 ⊂ 10.10.1.19).
fn lexemes_numeriques(texte: &str) -> Vec<&str> {
    let mut runs = Vec::new();
    let b = texte.as_bytes();
    let mut i = 0usize;
    while i < b.len() {
        if b[i].is_ascii_digit() || b[i] == b'.' {
            let d = i;
            while i < b.len() && (b[i].is_ascii_digit() || b[i] == b'.') {
                i += 1;
            }
            runs.push(&texte[d..i]);
        } else {
            i += 1;
        }
    }
    runs
}

/// Comparateur de forme : mêmes mots-clés, même nombre d'arguments, même
/// nombre d'enfants, récursivement.
fn meme_forme(a: &ConfigNode, b: &ConfigNode) -> bool {
    a.keyword == b.keyword
        && a.args.len() == b.args.len()
        && a.children.len() == b.children.len()
        && a.children
            .iter()
            .zip(b.children.iter())
            .all(|(x, y)| meme_forme(x, y))
}

fn table(s: &Scrubber) -> HashMap<String, String> {
    s.mapping()
        .map(|(o, r)| (o.to_owned(), r.to_owned()))
        .collect()
}

// ---------------------------------------------------------------------
// (a) La fixture : plus aucune trace, même forme, sous-réseaux préservés
// ---------------------------------------------------------------------

#[test]
fn fixture_plus_aucun_nom_ni_adresse_d_origine() {
    let mut s = Scrubber::new();
    let sortie = s.scrub(FIXTURE);

    // Les noms sans homonyme d'énumération : absents partout.
    for nom in NOMS_ORIGINAUX {
        if matches!(*nom, "lan" | "dmz" | "wan") {
            // `lan`/`dmz`/`wan` existent AUSSI comme valeurs de `set role`
            // (énumérations constructeur, jamais touchées) : on vérifie
            // que plus aucune occurrence CITÉE — donc une référence — ne
            // subsiste.
            assert!(
                !sortie.contains(&format!("\"{nom}\"")),
                "référence citée à {nom} restée"
            );
        } else {
            assert!(!sortie.contains(nom), "nom {nom} resté dans la sortie");
        }
    }
    // Les énumérations et mots-clés, eux, sont intacts.
    for garde in [
        "set role lan",
        "set role dmz",
        "set role wan",
        "set action accept",
        "set action deny",
        "\"all\"",
        "\"ALL\"",
        "\"always\"",
    ] {
        assert!(sortie.contains(garde), "{garde} aurait dû rester");
    }

    // Les adresses : absentes en tant que lexèmes entiers.
    let lexemes = lexemes_numeriques(&sortie);
    for adresse in ADRESSES_ORIGINALES {
        assert!(
            !lexemes.contains(adresse),
            "adresse {adresse} restée dans la sortie"
        );
    }
    // Les masques ne sont PAS des adresses : intacts.
    for masque in ["255.255.255.0", "255.255.255.252", "255.255.255.255"] {
        assert!(lexemes.contains(&masque), "masque {masque} altéré");
    }
}

#[test]
fn fixture_la_sortie_reparse_en_un_arbre_de_meme_forme() {
    let mut s = Scrubber::new();
    let sortie = s.scrub(FIXTURE);

    let avant = fortigate::parse(FIXTURE, "avant.conf").expect("fixture valide");
    let apres = fortigate::parse(&sortie, "apres.conf").expect("la sortie doit rester analysable");

    assert_eq!(avant.roots.len(), apres.roots.len());
    for (a, b) in avant.roots.iter().zip(apres.roots.iter()) {
        assert!(
            meme_forme(a, b),
            "forme altérée sous `{} {}`",
            a.keyword,
            a.args_joined()
        );
    }
}

#[test]
fn fixture_relations_de_sous_reseau_preservees() {
    let mut s = Scrubber::new();
    s.scrub(FIXTURE);
    let t = table(&s);
    let m = |o: &str| -> Ipv4Addr { t[o].parse().expect("remplacement IPv4") };

    // 10.10.1.1, 10.10.1.50 et 10.10.1.69 sont dans le même /24 : leurs
    // remplacements aussi (et le /24 image est le même pour les trois).
    let reseau = Ipv4Net::new(m("10.10.1.1"), 24).unwrap().trunc();
    assert!(reseau.contains(&m("10.10.1.50")));
    assert!(reseau.contains(&m("10.10.1.69")));

    // 10.10.2.1 est dans un AUTRE /24 (mais le même /16) : préservé.
    assert!(!reseau.contains(&m("10.10.2.1")));
    let seize = Ipv4Net::new(m("10.10.1.1"), 16).unwrap().trunc();
    assert!(seize.contains(&m("10.10.2.1")));

    // L'interface wan 10.200.0.2/30 et sa passerelle 10.200.0.1 restent
    // dans un même /30 — la longueur de préfixe survit exactement.
    let trente = Ipv4Net::new(m("10.200.0.2"), 30).unwrap().trunc();
    assert!(trente.contains(&m("10.200.0.1")));
    assert_ne!(m("10.200.0.2"), m("10.200.0.1"));

    // Et le 10/8 (RFC1918) reste dans le 10/8 : l'adressage reste privé.
    for a in ADRESSES_ORIGINALES {
        assert_eq!(m(a).octets()[0], 10, "{a} sorti du 10/8");
    }
}

// ---------------------------------------------------------------------
// (a bis) L'export YAML FortiOS : mêmes garanties que le format CLI
// ---------------------------------------------------------------------

#[test]
fn yaml_format_reconnu_et_plus_aucun_nom_ni_adresse_d_origine() {
    let mut s = Scrubber::new();
    let (sortie, rapport) = s.scrub_avec_rapport(FIXTURE_YAML);

    // Le cas réel qui a motivé ce durcissement : l'export YAML est
    // désormais un format RECONNU de la passe 1.
    assert!(rapport.format_reconnu);
    assert_eq!(rapport.format, Some("fortigate-yaml"));

    for nom in NOMS_ORIGINAUX {
        if matches!(*nom, "lan" | "dmz" | "wan") {
            // `lan`/`dmz`/`wan` existent AUSSI comme valeurs de `role:`
            // (énumérations constructeur, jamais touchées) : plus aucune
            // occurrence citée (référence) NI déclarée (`- lan:`).
            assert!(
                !sortie.contains(&format!("\"{nom}\"")),
                "référence citée à {nom} restée"
            );
            assert!(
                !sortie.contains(&format!("- {nom}:")),
                "déclaration `- {nom}:` restée"
            );
        } else {
            assert!(!sortie.contains(nom), "nom {nom} resté dans la sortie");
        }
    }
    // Les énumérations, elles, sont intactes.
    for garde in [
        "role: lan",
        "role: dmz",
        "role: wan",
        "action: accept",
        "action: deny",
        "\"all\"",
        "\"ALL\"",
        "\"always\"",
    ] {
        assert!(sortie.contains(garde), "{garde} aurait dû rester");
    }

    // Les adresses : absentes en tant que lexèmes entiers ; les masques
    // qui les suivent sont intacts.
    let lexemes = lexemes_numeriques(&sortie);
    for adresse in ADRESSES_ORIGINALES {
        assert!(!lexemes.contains(adresse), "adresse {adresse} restée");
    }
    for masque in ["255.255.255.0", "255.255.255.252", "255.255.255.255"] {
        assert!(lexemes.contains(&masque), "masque {masque} altéré");
    }
}

#[test]
fn yaml_la_sortie_reparse_en_un_arbre_de_meme_forme() {
    let mut s = Scrubber::new();
    let sortie = s.scrub(FIXTURE_YAML);

    let avant = fortigate_yaml::parse(FIXTURE_YAML, "avant.yaml").expect("fixture valide");
    let apres =
        fortigate_yaml::parse(&sortie, "apres.yaml").expect("la sortie doit rester analysable");

    assert_eq!(avant.roots.len(), apres.roots.len());
    for (a, b) in avant.roots.iter().zip(apres.roots.iter()) {
        assert!(
            meme_forme(a, b),
            "forme altérée sous `{} {}`",
            a.keyword,
            a.args_joined()
        );
    }
}

#[test]
fn yaml_relations_de_sous_reseau_preservees() {
    let mut s = Scrubber::new();
    s.scrub(FIXTURE_YAML);
    let t = table(&s);
    let m = |o: &str| -> Ipv4Addr { t[o].parse().expect("remplacement IPv4") };

    // Même /24 pour les trois adresses du LAN, /24 distinct (même /16)
    // pour la DMZ, /30 commun à l'interface wan et sa passerelle.
    let reseau = Ipv4Net::new(m("10.10.1.1"), 24).unwrap().trunc();
    assert!(reseau.contains(&m("10.10.1.50")));
    assert!(reseau.contains(&m("10.10.1.69")));
    assert!(!reseau.contains(&m("10.10.2.1")));
    let seize = Ipv4Net::new(m("10.10.1.1"), 16).unwrap().trunc();
    assert!(seize.contains(&m("10.10.2.1")));
    let trente = Ipv4Net::new(m("10.200.0.2"), 30).unwrap().trunc();
    assert!(trente.contains(&m("10.200.0.1")));
}

#[test]
fn yaml_idempotence_et_coherence_avec_le_format_cli() {
    let mut s = Scrubber::new();
    let une = s.scrub(FIXTURE_YAML);
    // Re-scruber la sortie ne change plus rien.
    assert_eq!(s.scrub(&une), une);
    // Deux appels identiques : même sortie.
    assert_eq!(s.scrub(FIXTURE_YAML), une);

    // Le même parc en CLI et en YAML sur un même Scrubber : mêmes
    // remplacements partout (la table est partagée).
    let mut parc = Scrubber::new();
    parc.scrub(FIXTURE);
    let t = table(&parc);
    let sortie = parc.scrub(FIXTURE_YAML);
    assert!(sortie.contains(&format!("- {}:", t["h-srv-web"])));
    assert!(sortie.contains(&format!("srcintf: \"{}\"", t["lan"])));
    assert!(sortie.contains(&format!("hostname: \"{}\"", t["fw-lab-01"])));
}

#[test]
fn yaml_secrets_et_certificats_caviardes_noms_anonymises() {
    let mut s = Scrubber::new();
    let entree = concat!(
        "#config-version=FGT60F-7.0.5-FW-build0304-220328:opmode=0:vdom=0:user=admin\n",
        "system_snmp_sysinfo:\n",
        "    location: \"Salle B12\"\n",
        "    contact-info: \"equipe-reseau\"\n",
        "system_ddns:\n",
        "    - maj-dns:\n",
        "        ddns-domain: \"fw.exemple.test\"\n",
        "system_admin:\n",
        "    - admin:\n",
        "        password: [ENC, U0VDUkVUMTIz]\n",
        "        old-password: [ENC, QU5DSUVOOTk=]\n",
        "vpn_ipsec_phase1-interface:\n",
        "    - vers-site-b:\n",
        "        psksecret: [ENC, Q0xFRlBBUlRBR0VF]\n",
        "vpn_certificate_local:\n",
        "    - cert-un:\n",
        "        private-key: \"-----BEGIN RSA PRIVATE KEY-----PEMSECRET-----END RSA PRIVATE KEY-----\"\n",
        "        certificate: \"-----BEGIN CERTIFICATE-----FGT60F0000000001-----END CERTIFICATE-----\"\n",
        "user_ldap:\n",
        "    - srv-annuaire:\n",
        "        username: \"lecteur-annuaire\"\n",
        "        dn: \"dc=exemple,dc=test\"\n",
        "        password: [ENC, TERBUFNFQ1JFVA==]\n"
    );
    let (sortie, rapport) = s.scrub_avec_rapport(entree);
    assert!(rapport.format_reconnu);

    // Secrets et blobs : disparus, et JAMAIS dans le mapping.
    for secret in [
        "U0VDUkVUMTIz",
        "QU5DSUVOOTk=",
        "Q0xFRlBBUlRBR0VF",
        "PEMSECRET",
        "TERBUFNFQ1JFVA==",
        "BEGIN RSA PRIVATE KEY",
        "FGT60F0000000001", // numéro de série dans le certificat
    ] {
        assert!(!sortie.contains(secret), "secret {secret} resté");
        for (o, r) in s.mapping() {
            assert!(
                !o.contains(secret) && !r.contains(secret),
                "secret {secret} dans le mapping"
            );
        }
    }
    assert!(sortie.contains("password: SUPPRIME"));
    assert!(sortie.contains("old-password: SUPPRIME"));
    assert!(sortie.contains("psksecret: SUPPRIME"));
    assert!(sortie.contains("private-key: SUPPRIME"));
    // Certificat : motif DISTINCT, documenté.
    assert!(sortie.contains("certificate: SUPPRIME-CERT"));

    // Les identifiants, eux, sont anonymisés (pas des secrets).
    for nom in [
        "Salle B12",
        "equipe-reseau",
        "fw.exemple.test",
        "vers-site-b",
        "cert-un",
        "srv-annuaire",
        "lecteur-annuaire",
        "dc=exemple,dc=test",
        "maj-dns",
    ] {
        assert!(!sortie.contains(nom), "identifiant {nom} resté");
    }
    // Et la sortie reparse toujours comme un export YAML.
    fortigate_yaml::parse(&sortie, "apres.yaml").expect("la sortie doit rester analysable");
}

// ---------------------------------------------------------------------
// (a ter) Format inconnu : le rapport le dit, l'appelant peut prévenir
// ---------------------------------------------------------------------

#[test]
fn format_inconnu_signale_dans_le_rapport() {
    let mut s = Scrubber::new();
    let (_, rapport) = s.scrub_avec_rapport(
        "Bonjour,\n\nceci est un texte quelconque qui n'est la configuration de rien.\n\
         Le serveur 10.9.9.9 repond au ping.\n",
    );
    assert!(!rapport.format_reconnu, "rien ici n'est un format connu");
    assert_eq!(rapport.format, None);

    // Les formats connus, eux, sont bien étiquetés.
    let mut s = Scrubber::new();
    let (_, rapport) = s.scrub_avec_rapport(FIXTURE);
    assert_eq!(rapport.format, Some("fortigate"));
    let mut s = Scrubber::new();
    let (_, rapport) = s.scrub_avec_rapport(FIXTURE_YAML);
    assert_eq!(rapport.format, Some("fortigate-yaml"));
    let mut s = Scrubber::new();
    let ios = "hostname r1\ninterface GigabitEthernet0/0\n ip address 10.0.0.1 255.255.255.0\n";
    let (_, rapport) = s.scrub_avec_rapport(ios);
    assert_eq!(rapport.format, Some("cisco-ios"));
}

// ---------------------------------------------------------------------
// (b) Cohérence entre fichiers scrubés par le même Scrubber
// ---------------------------------------------------------------------

#[test]
fn coherence_inter_fichiers_meme_mapping() {
    let mut s = Scrubber::new();
    let premiere = s.scrub(FIXTURE);
    let t = table(&s);

    // Un second fichier du même parc réutilise les mêmes remplacements.
    let second = concat!(
        "config firewall address\n",
        "    edit \"h-srv-web\"\n",
        "        set subnet 10.10.2.10 255.255.255.255\n",
        "    next\n",
        "end\n",
        "config firewall policy\n",
        "    edit 1\n",
        "        set srcintf \"lan\"\n",
        "        set dstaddr \"h-srv-web\"\n",
        "    next\n",
        "end\n"
    );
    let sortie = s.scrub(second);
    assert!(sortie.contains(&format!("edit \"{}\"", t["h-srv-web"])));
    assert!(sortie.contains(&format!("set srcintf \"{}\"", t["lan"])));
    assert!(sortie.contains(&format!("set subnet {} 255.255.255.255", t["10.10.2.10"])));
    // Le premier fichier n'aurait pas changé : mêmes entrées, mêmes sorties.
    assert_eq!(s.scrub(FIXTURE), premiere);
}

// ---------------------------------------------------------------------
// (c) Secrets : supprimés, et jamais dans le mapping
// ---------------------------------------------------------------------

#[test]
fn secrets_supprimes_et_hors_mapping() {
    let mut s = Scrubber::new();
    let entree = concat!(
        "config system admin\n",
        "    edit \"admin\"\n",
        "        set password ENC SGVsbG8tc2VjcmV0\n",
        "    next\n",
        "end\n",
        "config vpn ipsec phase1-interface\n",
        "    edit \"vers-site-b\"\n",
        "        set psksecret \"cle-partagee-42\"\n",
        "    next\n",
        "end\n",
        "enable secret 5 $1$abcd$efgh\n",
        "snmp-server community interne-ro RO\n"
    );
    let sortie = s.scrub(entree);

    for secret in [
        "SGVsbG8tc2VjcmV0",
        "cle-partagee-42",
        "$1$abcd$efgh",
        "interne-ro",
    ] {
        assert!(!sortie.contains(secret), "secret {secret} resté");
        for (o, r) in s.mapping() {
            assert!(
                !o.contains(secret) && !r.contains(secret),
                "secret {secret} dans le mapping"
            );
        }
    }
    assert!(sortie.contains("set password SUPPRIME"));
    assert!(sortie.contains("set psksecret SUPPRIME"));
    assert!(sortie.contains("enable secret SUPPRIME"));
    assert!(sortie.contains("snmp-server community SUPPRIME RO"));
    // Le nom du tunnel, lui, est bien anonymisé (pas un secret).
    assert!(!sortie.contains("vers-site-b"));
}

// ---------------------------------------------------------------------
// (d) Plages de documentation et adresses spéciales : intactes
// ---------------------------------------------------------------------

#[test]
fn plages_de_documentation_et_speciales_intactes() {
    let mut s = Scrubber::new();
    let entree = concat!(
        "ping 192.0.2.7\n",
        "ping 198.51.100.20\n",
        "ping 203.0.113.9\n",
        "ping 127.0.0.1\n",
        "ping 224.0.0.5\n",
        "ping 169.254.10.20\n",
        "ip route 0.0.0.0 0.0.0.0 10.7.7.1\n",
        "broadcast 255.255.255.255\n",
        "ping6 2001:db8::42\n",
        "ping6 fe80::1\n"
    );
    let sortie = s.scrub(entree);
    for intacte in [
        "192.0.2.7",
        "198.51.100.20",
        "203.0.113.9",
        "127.0.0.1",
        "224.0.0.5",
        "169.254.10.20",
        "0.0.0.0 0.0.0.0",
        "255.255.255.255",
        "2001:db8::42",
        "fe80::1",
    ] {
        assert!(sortie.contains(intacte), "{intacte} aurait dû rester");
    }
    // La vraie adresse de la ligne de route, elle, a changé.
    assert!(!lexemes_numeriques(&sortie).contains(&"10.7.7.1"));
    // Et rien de tout cela n'entre dans le mapping, sauf 10.7.7.1.
    let t = table(&s);
    assert_eq!(t.len(), 1);
    assert!(t.contains_key("10.7.7.1"));
}

// ---------------------------------------------------------------------
// (e) Masques et jokers : jamais anonymisés
// ---------------------------------------------------------------------

#[test]
fn masques_et_jokers_jamais_anonymises() {
    let mut s = Scrubber::new();
    let sortie = s.scrub(concat!(
        "    set ip 10.44.55.66 255.255.254.0\n",
        "access-list 5 permit 10.44.0.0 0.0.255.255\n",
        "network 10.44.55.0 mask 255.255.255.128\n"
    ));
    for masque in ["255.255.254.0", "0.0.255.255", "255.255.255.128"] {
        assert!(sortie.contains(masque), "masque {masque} altéré");
        assert!(
            !table(&s).contains_key(masque),
            "masque {masque} dans le mapping"
        );
    }
    assert!(!lexemes_numeriques(&sortie).contains(&"10.44.55.66"));
}

// ---------------------------------------------------------------------
// (f) Idempotence et stabilité
// ---------------------------------------------------------------------

#[test]
fn idempotence_et_stabilite() {
    let mut s = Scrubber::new();
    let une = s.scrub(FIXTURE);
    // Re-scruber la sortie ne change plus rien.
    assert_eq!(s.scrub(&une), une);
    // Deux appels identiques sur le même Scrubber : même sortie.
    assert_eq!(s.scrub(FIXTURE), une);
    // Et un Scrubber neuf, graine fixe oblige, produit la même chose.
    let mut s2 = Scrubber::new();
    assert_eq!(s2.scrub(FIXTURE), une);
}

// ---------------------------------------------------------------------
// (g) Entrées hostiles : jamais de panique
// ---------------------------------------------------------------------

#[test]
fn entrees_hostiles_sans_panique() {
    let geante = "10.0.0.1 ".repeat(200_000);
    let cas: Vec<String> = vec![
        String::new(),
        "\u{0}\u{1}\u{2} binaire \u{fffd}\u{fffd}".to_owned(),
        "\"".to_owned(),
        "\\\"".repeat(1000),
        "config\n\"\nend".to_owned(),
        "end\nend\nnext\n".to_owned(),
        "edit \"\u{1f980} caf\u{e9}\"\n".to_owned(),
        "set password".to_owned(),
        "set psksecret \"jamais ferme\nligne2\nligne3".to_owned(),
        "999.999.999.999 1.2.3.4.5 10.10.10 :::::: 1:2:3:4:5:6:7:8".to_owned(),
        "a".repeat(2_000_000),
        geante,
        "config system interface\n    edit \"p1".to_owned(),
        "\n\r\n\n".to_owned(),
    ];
    for entree in &cas {
        let mut s = Scrubber::new();
        let sortie = s.scrub(entree);
        // Idempotence même sur du bruit.
        assert_eq!(s.scrub(&sortie), sortie);
    }
    // Et tout le corpus hostile d'un coup, sur un seul Scrubber partagé.
    let mut s = Scrubber::new();
    for entree in &cas {
        let _ = s.scrub(entree);
    }
}
