//! Nettoyage des sorties de terminal — module PUR.
//!
//! Les équipements réseau polluent leurs sorties d'artefacts de terminal :
//! invites de pagination (`--More--`), retours chariot qui réécrivent la
//! ligne, retours arrière (`\x08`) qui effacent l'invite, séquences
//! d'échappement ANSI. Ce module les neutralise AVANT que les parseurs et
//! les adaptateurs ne voient le texte.
//!
//! Ordre de traitement, documenté et testé sur transcripts piégeux
//! (`corpus/collect/`) :
//!
//! 1. découpage en lignes (`\n`), le `\r` final d'un CRLF étant retiré ;
//! 2. dans chaque ligne, application des retours chariot RESTANTS comme un
//!    terminal : le segment après `\r` réécrit le début de la ligne ;
//! 3. application des retours arrière `\x08` (effacement du caractère
//!    précédent) ;
//! 4. suppression des séquences ANSI CSI (`ESC [ … lettre`) ;
//! 5. suppression des invites de pagination (`--More--` et variantes),
//!    ainsi que du blanc qu'elles laissent.

/// Invites de pagination connues, cherchées comme sous-chaînes exactes
/// APRÈS les étapes terminal (CR, backspace, ANSI).
const MORE_PROMPTS: &[&str] = &["--More-- ", "--More--", "--more--", " More: "];

/// Nettoie une sortie brute de terminal (voir la documentation du module).
pub fn clean_output(raw: &str) -> String {
    let ends_with_newline = raw.ends_with('\n');
    let mut lines: Vec<&str> = raw.split('\n').collect();
    if ends_with_newline {
        // Le découpage produit un segment vide final : ce n'est pas une ligne.
        lines.pop();
    }
    let mut out = String::with_capacity(raw.len());
    for line in lines {
        let line = line.strip_suffix('\r').unwrap_or(line);
        let mut cleaned = strip_ansi(&apply_backspaces(&apply_carriage_returns(line)));
        for prompt in MORE_PROMPTS {
            if cleaned.contains(prompt) {
                cleaned = cleaned.replace(prompt, "");
            }
        }
        out.push_str(cleaned.trim_end());
        out.push('\n');
    }
    if !ends_with_newline {
        out.pop();
    }
    out
}

/// Applique les retours chariot comme un terminal : chaque segment après
/// un `\r` réécrit la ligne depuis la colonne 0, le reste de l'ancienne
/// ligne restant visible s'il dépasse.
fn apply_carriage_returns(line: &str) -> String {
    let mut screen = String::new();
    for segment in line.split('\r') {
        if segment.len() >= screen.len() {
            screen = segment.to_owned();
        } else {
            let tail = screen
                .get(segment.len()..)
                .map(str::to_owned)
                .unwrap_or_default();
            screen = format!("{segment}{tail}");
        }
    }
    screen
}

/// Applique les retours arrière `\x08` : chacun efface le caractère
/// précédent (c'est ainsi que FortiGate efface son invite `--More--`).
fn apply_backspaces(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    for c in line.chars() {
        if c == '\u{8}' {
            out.pop();
        } else {
            out.push(c);
        }
    }
    out
}

/// Supprime les séquences ANSI CSI : `ESC [ paramètres lettre`.
fn strip_ansi(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' {
            if chars.peek() == Some(&'[') {
                chars.next();
                // Consomme jusqu'à la lettre finale (incluse).
                for e in chars.by_ref() {
                    if e.is_ascii_alphabetic() {
                        break;
                    }
                }
            }
            // Un ESC isolé est simplement retiré.
        } else {
            out.push(c);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crlf_et_lignes_simples() {
        assert_eq!(clean_output("a\r\nb\r\n"), "a\nb\n");
        assert_eq!(clean_output("a\nb"), "a\nb");
    }

    #[test]
    fn pagination_cisco_effacee_par_retour_chariot() {
        // IOS affiche ` --More-- ` puis efface la ligne avec \r + espaces
        // + \r avant d'écrire la suite.
        let raw = " --More-- \r          \rinterface GigabitEthernet0/1\n";
        assert_eq!(clean_output(raw), "interface GigabitEthernet0/1\n");
    }

    #[test]
    fn pagination_fortigate_effacee_par_retours_arriere() {
        // FortiGate efface `--More--` avec des \x08.
        let raw = "--More--\u{8}\u{8}\u{8}\u{8}\u{8}\u{8}\u{8}\u{8}set status enable\n";
        assert_eq!(clean_output(raw), "set status enable\n");
    }

    #[test]
    fn invite_residuelle_supprimee() {
        assert_eq!(clean_output("--More--\ntexte\n"), "\ntexte\n");
        assert_eq!(clean_output("a --More-- b\n"), "a b\n");
    }

    #[test]
    fn sequences_ansi_supprimees() {
        assert_eq!(clean_output("\u{1b}[7m--More--\u{1b}[m\nx\n"), "\nx\n");
        assert_eq!(clean_output("a\u{1b}[Kb\n"), "ab\n");
    }
}
