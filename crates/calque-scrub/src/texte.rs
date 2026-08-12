//! Petits outils lexicaux, sans dépendance : segmentation d'une ligne en
//! zones citées / brutes (reconstruction au caractère près), découpage en
//! lexèmes tolérant, reconnaissance des remplacements déjà anonymes.
//!
//! Tous les balayages se font sur les octets mais ne coupent les chaînes
//! qu'à des positions ASCII : jamais de panique au milieu d'un caractère
//! UTF-8 multi-octets.

/// Un morceau de ligne : soit du texte brut, soit l'intérieur d'une zone
/// entre guillemets doubles (`ferme == false` si le guillemet fermant
/// manque — la reconstruction n'en ajoute alors pas).
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Seg<'a> {
    Brut(&'a str),
    Citee { interieur: &'a str, ferme: bool },
}

/// Découpe une ligne en segments cités / bruts. La concaténation des
/// segments (avec leurs guillemets) redonne la ligne à l'octet près.
pub(crate) fn segmenter(ligne: &str) -> Vec<Seg<'_>> {
    let b = ligne.as_bytes();
    let mut segs = Vec::new();
    let mut debut = 0usize;
    let mut i = 0usize;
    while i < b.len() {
        if b[i] == b'"' {
            if debut < i {
                segs.push(Seg::Brut(&ligne[debut..i]));
            }
            let int_debut = i + 1;
            let mut j = int_debut;
            let mut ferme = false;
            while j < b.len() {
                match b[j] {
                    // `\"` et `\\` ne ferment pas la zone citée.
                    b'\\' if j + 1 < b.len() && (b[j + 1] == b'"' || b[j + 1] == b'\\') => j += 2,
                    b'"' => {
                        ferme = true;
                        break;
                    }
                    _ => j += 1,
                }
            }
            let fin = j.min(b.len());
            segs.push(Seg::Citee {
                interieur: &ligne[int_debut..fin],
                ferme,
            });
            i = if ferme { fin + 1 } else { b.len() };
            debut = i;
        } else {
            i += 1;
        }
    }
    if debut < b.len() {
        segs.push(Seg::Brut(&ligne[debut..]));
    }
    segs
}

/// Découpe une ligne en lexèmes, guillemets résolus (`"a b"` = un lexème,
/// échappements `\"` et `\\` dépliés), tolérant aux guillemets non fermés.
/// Même convention que le tokenizer de calque-parse, en mode indulgent.
pub(crate) fn decouper_lexemes(ligne: &str) -> Vec<String> {
    let mut lexemes = Vec::new();
    let mut courant = String::new();
    let mut en_cours = false;
    let mut chars = ligne.chars();
    while let Some(c) = chars.next() {
        if c.is_whitespace() {
            if en_cours {
                lexemes.push(std::mem::take(&mut courant));
                en_cours = false;
            }
            continue;
        }
        if c == '"' {
            en_cours = true;
            loop {
                match chars.next() {
                    None | Some('"') => break,
                    Some('\\') => {
                        if let Some(e) = chars.next() {
                            courant.push(e);
                        }
                    }
                    Some(autre) => courant.push(autre),
                }
            }
            continue;
        }
        en_cours = true;
        courant.push(c);
    }
    if en_cours {
        lexemes.push(courant);
    }
    lexemes
}

/// `s` est-il un remplacement déjà produit par le scrub (`anon-<type>-<n>`
/// ou `SUPPRIME`) ? Sert à l'idempotence : on ne ré-anonymise jamais.
pub(crate) fn est_anonyme(s: &str) -> bool {
    if s == "SUPPRIME" {
        return true;
    }
    let Some(reste) = s.strip_prefix("anon-") else {
        return false;
    };
    let Some((genre, numero)) = reste.split_once('-') else {
        return false;
    };
    !genre.is_empty()
        && genre.chars().all(|c| c.is_ascii_lowercase())
        && !numero.is_empty()
        && numero.chars().all(|c| c.is_ascii_digit())
}

/// Nombre de guillemets non échappés sur la ligne (parité = une zone
/// citée reste ouverte). Sert au saut des secrets multi-lignes.
pub(crate) fn nb_guillemets(ligne: &str) -> usize {
    let mut n = 0usize;
    let mut echappe = false;
    for c in ligne.chars() {
        if echappe {
            echappe = false;
            continue;
        }
        match c {
            '\\' => echappe = true,
            '"' => n += 1,
            _ => {}
        }
    }
    n
}

#[cfg(test)]
mod tests {
    use super::*;

    fn recoller(segs: &[Seg<'_>]) -> String {
        let mut s = String::new();
        for seg in segs {
            match seg {
                Seg::Brut(t) => s.push_str(t),
                Seg::Citee { interieur, ferme } => {
                    s.push('"');
                    s.push_str(interieur);
                    if *ferme {
                        s.push('"');
                    }
                }
            }
        }
        s
    }

    #[test]
    fn segmentation_reversible_a_l_octet_pres() {
        for ligne in [
            r#"    set alias "port1 lan""#,
            r#"set member "a" "b" "c""#,
            r#"pas de guillemets 10.0.0.1"#,
            r#"guillemet "non ferme"#,
            r#"echappe "a \" b" fin"#,
            r#""" vide"#,
            "accents é\u{00e9} \"caf\u{00e9}\"",
            "",
        ] {
            assert_eq!(recoller(&segmenter(ligne)), ligne, "{ligne:?}");
        }
    }

    #[test]
    fn segmentation_identifie_les_zones_citees() {
        let segs = segmenter(r#"set alias "port1 lan" x"#);
        assert_eq!(
            segs,
            vec![
                Seg::Brut("set alias "),
                Seg::Citee {
                    interieur: "port1 lan",
                    ferme: true
                },
                Seg::Brut(" x"),
            ]
        );
    }

    #[test]
    fn lexemes_avec_guillemets() {
        assert_eq!(
            decouper_lexemes(r#"  edit "port1 lan"  suite"#),
            vec!["edit", "port1 lan", "suite"]
        );
        assert_eq!(decouper_lexemes(""), Vec::<String>::new());
        assert_eq!(decouper_lexemes(r#"a "coupe"#), vec!["a", "coupe"]);
    }

    #[test]
    fn motif_anonyme() {
        assert!(est_anonyme("anon-host-1"));
        assert!(est_anonyme("anon-intf-42"));
        assert!(est_anonyme("SUPPRIME"));
        assert!(!est_anonyme("anon-host-"));
        assert!(!est_anonyme("anon--1"));
        assert!(!est_anonyme("anonyme-1"));
        assert!(!est_anonyme("fw-lab-01"));
    }

    #[test]
    fn parite_des_guillemets() {
        assert_eq!(nb_guillemets(r#"set key "ouvert"#), 1);
        assert_eq!(nb_guillemets(r#"set key "ferme""#), 2);
        assert_eq!(nb_guillemets(r#"echappe \" seul"#), 0);
    }
}
