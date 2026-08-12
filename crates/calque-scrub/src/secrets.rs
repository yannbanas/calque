//! Suppression des secrets — AVANT toute autre passe.
//!
//! La valeur d'un secret est remplacée par le mot `SUPPRIME` et n'entre
//! JAMAIS dans la table de correspondance : un secret ne se transpose
//! pas, il disparaît. Les motifs sont volontairement larges (§11.4) :
//! mieux vaut caviarder un réglage anodin que laisser passer une clé.
//!
//! Cas couverts, côté FortiOS :
//! - `set <clé> ...` où la clé contient `passw`, `pwd`, `secret`, `psk`,
//!   `passphrase`, ou est `key` / se termine par `key` (private-key,
//!   authkey, psksecret, ppk-secret, auth-pwd, login-passwd...) ;
//! - `set <clé> ENC <blob>` quel que soit le nom de la clé ;
//! - valeurs citées multi-lignes (clés privées PEM) : la première ligne
//!   devient `set <clé> SUPPRIME`, les lignes de continuation sont
//!   supprimées jusqu'au guillemet fermant.
//!
//! Côté export YAML FortiOS (`clé: valeur`), mêmes règles de clé :
//! - `password: [ENC, <blob>]`, `passwd:`, `old-password:`,
//!   `psksecret: [ENC, <blob>]`, `private-key: "<PEM sur une ligne>"`,
//!   toute clé finissant par `-key` ou contenant passw/pwd/secret/psk/
//!   passphrase → `clé: SUPPRIME`, le blob `ENC` entier disparaît
//!   (jamais dans la table de correspondance) ;
//! - `<clé>: ENC …` ou `<clé>: [ENC, …]` quel que soit le nom de la clé ;
//! - `certificate:` / `public-key:` (et `…-certificate:`) : la valeur est
//!   caviardée avec le motif distinct `SUPPRIME-CERT` — un certificat
//!   n'est pas un secret au sens strict, mais son sujet/CN embarque le
//!   numéro de série de l'équipement, un identifiant.
//!
//! Côté Cisco IOS : `enable secret|password`, `username ... password|secret`,
//! `snmp-server community` (et `location`/`contact`, identifiants de site),
//! `crypto isakmp key` (l'adresse du pair est conservée), `tacacs-server` /
//! `radius-server ... key`, `key-string`, `ntp authentication-key`.

use crate::texte::nb_guillemets;

/// Redige les secrets d'un texte complet, ligne à ligne. Pur, sans E/S.
pub(crate) fn rediger(entree: &str) -> String {
    let mut sortie: Vec<String> = Vec::new();
    // Une valeur citée de secret reste ouverte : on supprime les lignes
    // jusqu'à celle qui referme le guillemet (elle comprise).
    let mut saut_citation = false;
    for brute in entree.split('\n') {
        let (contenu, cr) = match brute.strip_suffix('\r') {
            Some(c) => (c, "\r"),
            None => (brute, ""),
        };
        if saut_citation {
            if nb_guillemets(contenu) % 2 == 1 {
                saut_citation = false;
            }
            continue;
        }
        match rediger_ligne(contenu) {
            None => sortie.push(format!("{contenu}{cr}")),
            Some((ligne, saut)) => {
                sortie.push(format!("{ligne}{cr}"));
                saut_citation = saut;
            }
        }
    }
    sortie.join("\n")
}

/// La clé d'un `set` FortiOS porte-t-elle un secret ?
fn cle_secrete_fortios(cle: &str) -> bool {
    cle.contains("passw")
        || cle.contains("pwd")
        || cle.contains("secret")
        || cle.contains("psk")
        || cle.contains("passphrase")
        || cle == "key"
        || cle.ends_with("key")
}

/// La clé désigne-t-elle un certificat ou une clé publique ? Caviardés
/// avec le motif distinct `SUPPRIME-CERT` (identifiant, pas secret).
fn cle_certificat(cle: &str) -> bool {
    cle == "certificate" || cle == "public-key" || cle.ends_with("-certificate")
}

/// `clé: valeur` d'un export YAML FortiOS : la clé brute (telle qu'écrite)
/// et la valeur, si la ligne a cette forme. Le `:` séparateur doit être
/// collé à la clé et suivi d'un blanc — les lignes Cisco (`enable secret
/// x`, blanc avant tout `:`) et les scalaires (`10.0.0.1:443`) ne
/// matchent pas.
fn couper_cle_yaml(coupe: &str) -> Option<(&str, &str)> {
    let b = coupe.as_bytes();
    for (i, &octet) in b.iter().enumerate() {
        if octet == b':' {
            if i == 0 || (i + 1 < b.len() && !b[i + 1].is_ascii_whitespace()) {
                return None;
            }
            return Some((&coupe[..i], &coupe[i + 1..]));
        }
        if octet.is_ascii_whitespace() {
            return None;
        }
    }
    None
}

/// Redige une ligne si elle porte un secret. Renvoie la ligne réécrite et
/// `true` si une valeur citée reste ouverte (continuation à supprimer).
fn rediger_ligne(contenu: &str) -> Option<(String, bool)> {
    let coupe = contenu.trim_start();
    let retrait = &contenu[..contenu.len() - coupe.len()];
    let lex: Vec<&str> = coupe.split_whitespace().collect();
    let premier = *lex.first()?;

    // --- FortiOS : `set <clé> <valeur...>` ---
    if premier == "set" && lex.len() >= 3 {
        let cle = lex[1].trim_matches('"').to_ascii_lowercase();
        let enc = lex[2].trim_start_matches('"') == "ENC";
        if cle_secrete_fortios(&cle) || enc {
            let saut = nb_guillemets(contenu) % 2 == 1;
            return Some((format!("{retrait}set {} SUPPRIME", lex[1]), saut));
        }
        return None;
    }

    // --- Export YAML FortiOS : `clé: valeur` ---
    if !coupe.starts_with("- ") {
        if let Some((cle_brute, valeur)) = couper_cle_yaml(coupe) {
            let cle = cle_brute.trim_matches('"').to_ascii_lowercase();
            let v = valeur.trim();
            if !v.is_empty() {
                if cle_certificat(&cle) {
                    let saut = nb_guillemets(contenu) % 2 == 1;
                    return Some((format!("{retrait}{cle_brute}: SUPPRIME-CERT"), saut));
                }
                let enc = v == "ENC"
                    || v.starts_with("ENC ")
                    || v.strip_prefix('[')
                        .is_some_and(|r| r.trim_start().starts_with("ENC"));
                if cle_secrete_fortios(&cle) || enc {
                    let saut = nb_guillemets(contenu) % 2 == 1;
                    return Some((format!("{retrait}{cle_brute}: SUPPRIME"), saut));
                }
            }
            return None;
        }
    }

    // --- Cisco IOS ---
    match premier {
        "enable" if lex.len() >= 3 && matches!(lex[1], "secret" | "password") => {
            Some((format!("{retrait}enable {} SUPPRIME", lex[1]), false))
        }
        "username" => {
            let pos = lex
                .iter()
                .position(|l| *l == "password" || *l == "secret")?;
            if pos + 1 >= lex.len() {
                return None; // pas de valeur à supprimer
            }
            Some((
                format!("{retrait}{} SUPPRIME", lex[..=pos].join(" ")),
                false,
            ))
        }
        "snmp-server" if lex.len() >= 3 && lex[1] == "community" => {
            let mut morceaux = vec!["snmp-server", "community", "SUPPRIME"];
            morceaux.extend(&lex[3..]);
            Some((format!("{retrait}{}", morceaux.join(" ")), false))
        }
        // Localisation et contact : pas des secrets au sens strict, mais
        // des identifiants de site — caviardés plutôt que transposés.
        "snmp-server" if lex.len() >= 3 && matches!(lex[1], "location" | "contact") => {
            Some((format!("{retrait}snmp-server {} SUPPRIME", lex[1]), false))
        }
        "crypto" if lex.len() >= 4 && lex[1] == "isakmp" && lex[2] == "key" => {
            // `crypto isakmp key SECRET address 10.0.0.1` : la clé saute,
            // le pair reste (il sera anonymisé par la passe adresses).
            let queue = lex
                .iter()
                .position(|l| *l == "address" || *l == "hostname")
                .map(|p| format!(" {}", lex[p..].join(" ")))
                .unwrap_or_default();
            Some((format!("{retrait}crypto isakmp key SUPPRIME{queue}"), false))
        }
        "tacacs-server" | "radius-server" => {
            let pos = lex.iter().position(|l| *l == "key")?;
            if pos + 1 >= lex.len() {
                return None;
            }
            Some((
                format!("{retrait}{} SUPPRIME", lex[..=pos].join(" ")),
                false,
            ))
        }
        "key-string" if lex.len() >= 2 => Some((format!("{retrait}key-string SUPPRIME"), false)),
        "ntp" if lex.len() >= 5 && lex[1] == "authentication-key" => {
            Some((format!("{retrait}{} SUPPRIME", lex[..4].join(" ")), false))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secrets_fortios_caviardes() {
        for (avant, apres) in [
            ("    set passwd ENC AbC123==", "    set passwd SUPPRIME"),
            ("    set password motdepasse", "    set password SUPPRIME"),
            (
                "    set psksecret \"tres secret\"",
                "    set psksecret SUPPRIME",
            ),
            ("    set ppk-secret ENC xxxx", "    set ppk-secret SUPPRIME"),
            ("    set auth-pwd abc", "    set auth-pwd SUPPRIME"),
            ("    set login-passwd abc", "    set login-passwd SUPPRIME"),
            ("    set passphrase \"a b\"", "    set passphrase SUPPRIME"),
            ("    set authkey secretkey", "    set authkey SUPPRIME"),
            // Valeur ENC : clé quelconque, caviardée quand même.
            ("    set inconnu ENC ZmF1eA==", "    set inconnu SUPPRIME"),
        ] {
            assert_eq!(rediger(avant), apres);
        }
    }

    #[test]
    fn cle_privee_multiligne_supprimee_entierement() {
        let avant = concat!(
            "config vpn certificate local\n",
            "    edit \"cert-1\"\n",
            "        set private-key \"-----BEGIN RSA PRIVATE KEY-----\n",
            "AAAA\n",
            "BBBB\n",
            "-----END RSA PRIVATE KEY-----\"\n",
            "        set comments \"apres\"\n",
            "    next\n",
            "end\n"
        );
        let apres = rediger(avant);
        assert!(apres.contains("set private-key SUPPRIME\n"));
        assert!(!apres.contains("BEGIN RSA"));
        assert!(!apres.contains("AAAA"));
        assert!(apres.contains("set comments \"apres\""));
    }

    #[test]
    fn secrets_cisco_caviardes() {
        for (avant, attendu) in [
            ("enable secret 5 $1$abcd", "enable secret SUPPRIME"),
            ("enable password motdepasse", "enable password SUPPRIME"),
            (
                "username bob privilege 15 password 7 0822455D0A16",
                "username bob privilege 15 password SUPPRIME",
            ),
            (
                "snmp-server community interne RO",
                "snmp-server community SUPPRIME RO",
            ),
            (
                "snmp-server location Salle B12, Paris",
                "snmp-server location SUPPRIME",
            ),
            (
                "crypto isakmp key motsecret address 10.9.9.9",
                "crypto isakmp key SUPPRIME address 10.9.9.9",
            ),
            ("tacacs-server key 7 secret", "tacacs-server key SUPPRIME"),
            ("  key-string abcdef", "  key-string SUPPRIME"),
            (
                "ntp authentication-key 1 md5 secret123",
                "ntp authentication-key 1 md5 SUPPRIME",
            ),
        ] {
            assert_eq!(rediger(avant), attendu, "{avant}");
        }
    }

    #[test]
    fn secrets_yaml_caviardes() {
        for (avant, apres) in [
            (
                "        password: [ENC, U0VDUkVUMTIz]",
                "        password: SUPPRIME",
            ),
            ("        passwd: motdepasse", "        passwd: SUPPRIME"),
            (
                "        old-password: [ENC, QU5DSUVO]",
                "        old-password: SUPPRIME",
            ),
            (
                "        psksecret: [ENC, Q0xFRg==]",
                "        psksecret: SUPPRIME",
            ),
            (
                "        private-key: \"-----BEGIN RSA PRIVATE KEY-----AAAA-----END RSA PRIVATE KEY-----\"",
                "        private-key: SUPPRIME",
            ),
            ("        auth-pwd: \"abc\"", "        auth-pwd: SUPPRIME"),
            ("        ppk-secret: xyz", "        ppk-secret: SUPPRIME"),
            ("        passphrase: \"a b\"", "        passphrase: SUPPRIME"),
            // Valeur `ENC` (nue ou en liste) : clé quelconque, caviardée.
            (
                "        inconnu: [ENC, ZmF1eA==]",
                "        inconnu: SUPPRIME",
            ),
            ("        inconnu: ENC ZmF1eA==", "        inconnu: SUPPRIME"),
        ] {
            assert_eq!(rediger(avant), apres, "{avant}");
        }
    }

    /// Un certificat n'est pas un secret au sens strict mais son CN porte
    /// le numéro de série de l'équipement : motif distinct SUPPRIME-CERT.
    #[test]
    fn certificats_yaml_caviardes_avec_motif_distinct() {
        for (avant, apres) in [
            (
                "        certificate: \"-----BEGIN CERTIFICATE-----FGT60F0000000001-----END CERTIFICATE-----\"",
                "        certificate: SUPPRIME-CERT",
            ),
            (
                "        public-key: \"ssh-rsa AAAAB3Nza fw-serie\"",
                "        public-key: SUPPRIME-CERT",
            ),
            (
                "        ca-certificate: \"blob\"",
                "        ca-certificate: SUPPRIME-CERT",
            ),
        ] {
            assert_eq!(rediger(avant), apres, "{avant}");
        }
    }

    #[test]
    fn lignes_yaml_ordinaires_intactes() {
        let texte = concat!(
            "system_global:\n",
            "    hostname: \"fw\"\n",
            "    admin-sport: 44301\n",
            "system_interface:\n",
            "    - wan1:\n",
            "        ip: [192.0.2.1, 255.255.255.248]\n",
            "        allowaccess: [ping, https]\n"
        );
        assert_eq!(rediger(texte), texte);
        // Une clé sans valeur (ouverture de bloc) n'est jamais touchée.
        assert_eq!(rediger("    gui-dashboard:"), "    gui-dashboard:");
    }

    #[test]
    fn lignes_ordinaires_intactes_et_fins_de_ligne_preservees() {
        let texte = "config system global\r\n    set hostname \"fw\"\r\nend\r\n";
        assert_eq!(rediger(texte), texte);
        assert_eq!(rediger(""), "");
        assert_eq!(rediger("set password"), "set password"); // pas de valeur
    }

    #[test]
    fn idempotence_de_la_redaction() {
        let une = rediger("    set psksecret ENC abc\nenable secret 5 x\n");
        assert_eq!(rediger(&une), une);
    }
}
