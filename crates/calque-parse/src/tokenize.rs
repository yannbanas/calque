//! Tokenizer de lignes, commun aux formats texte.
//!
//! Découpe une ligne en mots, en respectant les guillemets doubles
//! (`"port1 lan"` = un seul mot, style FortiGate) et les échappements
//! `\"` et `\\` à l'intérieur des guillemets. Les lignes vides et les
//! commentaires `#` sont signalés par `Ok(None)` — c'est l'appelant qui
//! garde le compte des lignes d'origine.

/// Guillemet ouvert et jamais refermé sur la ligne. L'appelant y ajoute
/// le fichier et la ligne pour construire une `ParseError` complète.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct UnterminatedQuote;

/// Découpe `line` en mots. Renvoie `Ok(None)` pour une ligne vide ou un
/// commentaire (`#` en premier caractère non blanc).
///
/// En mode `lenient`, un guillemet non refermé se ferme en fin de ligne
/// au lieu de produire une erreur — utile pour Cisco, où les textes
/// libres (descriptions) peuvent contenir un guillemet isolé.
pub(crate) fn tokenize(
    line: &str,
    lenient: bool,
) -> Result<Option<Vec<String>>, UnterminatedQuote> {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return Ok(None);
    }

    let mut tokens = Vec::new();
    let mut current = String::new();
    // Distinct de `current.is_empty()` : `""` est un argument vide valide.
    let mut has_token = false;
    let mut chars = trimmed.chars();

    while let Some(c) = chars.next() {
        if c.is_whitespace() {
            if has_token {
                tokens.push(std::mem::take(&mut current));
                has_token = false;
            }
            continue;
        }
        if c == '"' {
            // Portion entre guillemets : concaténée au mot en cours
            // (`abc"d e"` donne le mot `abcd e`).
            has_token = true;
            loop {
                match chars.next() {
                    None => {
                        if lenient {
                            break;
                        }
                        return Err(UnterminatedQuote);
                    }
                    Some('"') => break,
                    Some('\\') => match chars.next() {
                        None => {
                            if lenient {
                                current.push('\\');
                                break;
                            }
                            return Err(UnterminatedQuote);
                        }
                        Some(escaped) => current.push(escaped),
                    },
                    Some(other) => current.push(other),
                }
            }
            continue;
        }
        has_token = true;
        current.push(c);
    }
    if has_token {
        tokens.push(current);
    }
    Ok(Some(tokens))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn toks(line: &str) -> Vec<String> {
        tokenize(line, false)
            .expect("ligne valide")
            .expect("ligne non vide")
    }

    #[test]
    fn decoupage_simple() {
        assert_eq!(
            toks("set ip 10.0.0.1 255.255.255.0"),
            ["set", "ip", "10.0.0.1", "255.255.255.0"]
        );
    }

    #[test]
    fn guillemets_groupent_les_mots() {
        assert_eq!(
            toks(r#"set alias "port1 lan""#),
            ["set", "alias", "port1 lan"]
        );
    }

    #[test]
    fn guillemets_vides_donnent_un_argument_vide() {
        assert_eq!(toks(r#"set comment """#), ["set", "comment", ""]);
    }

    #[test]
    fn echappements_dans_les_guillemets() {
        assert_eq!(
            toks(r#"set comment "guillemet \" et barre \\ internes""#),
            ["set", "comment", r#"guillemet " et barre \ internes"#]
        );
    }

    #[test]
    fn vides_et_commentaires_ignores() {
        assert_eq!(tokenize("", false), Ok(None));
        assert_eq!(tokenize("   \t ", false), Ok(None));
        assert_eq!(tokenize("# un commentaire", false), Ok(None));
        assert_eq!(tokenize("#config-version=FGVM64-7.4.1", false), Ok(None));
    }

    #[test]
    fn diese_en_milieu_de_ligne_est_un_caractere_normal() {
        assert_eq!(toks("set hostname fw#1"), ["set", "hostname", "fw#1"]);
    }

    #[test]
    fn guillemet_non_ferme_strict_et_tolerant() {
        assert_eq!(
            tokenize(r#"set alias "coupe"#, false),
            Err(UnterminatedQuote)
        );
        assert_eq!(
            tokenize(r#"description Bob's "lien"#, true),
            Ok(Some(vec![
                "description".to_owned(),
                "Bob's".to_owned(),
                "lien".to_owned()
            ]))
        );
    }
}
