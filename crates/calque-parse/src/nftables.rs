//! Analyseur du format nftables : arbre par ACCOLADES (§6.1, §6.4).
//!
//! Couvre les fichiers de règles (`/etc/nftables.conf`) et la sortie de
//! `nft list ruleset`. `table inet filtre { chain entree { … } }` devient
//! des nœuds imbriqués ; une ligne peut porter plusieurs énoncés séparés
//! par `;` (`type filter hook input priority 0; policy drop;`) → un nœud
//! par énoncé. Les commentaires `#` (dont le shebang `#!/usr/sbin/nft -f`),
//! les chaînes entre guillemets et la continuation de ligne `\` sont gérés.
//!
//! ## Accolade de bloc ou ensemble anonyme ?
//!
//! Le format emploie `{ … }` pour DEUX choses : les blocs (`table`,
//! `chain`, `set`…) et les ensembles anonymes (`tcp dport { 22, 443 }`).
//! La distinction est FORMELLE, pas sémantique : dans la grammaire
//! nftables, seuls certains mots-clés d'en-tête ouvrent un bloc (voir
//! [`BLOCK_KEYWORDS`], plus `ct helper|timeout|expectation`, avec
//! tolérance d'un `add`/`create` initial pour les scripts impératifs).
//! Toute autre accolade reste DANS l'énoncé : ses jetons (`{`, valeurs,
//! `,`, `}`) deviennent des arguments du nœud, et la couche 2 en fait des
//! valeurs multiples du pavé. Un ensemble anonyme peut se replier sur
//! plusieurs lignes (sortie de `nft list ruleset` pour les longs
//! ensembles) : l'énoncé continue jusqu'à l'accolade fermante, et le span
//! du nœud couvre alors toutes les lignes.
//!
//! ## Ponctuation conservée
//!
//! Les virgules deviennent des arguments `,` à part entière : c'est ce
//! qui permet à la couche 2 de distinguer `ct state established,related`
//! (une liste de valeurs) d'une suite de mots indépendants. `{` et `}`
//! des ensembles anonymes sont conservés de la même façon.
//!
//! ## `include`
//!
//! `include "fichier"` devient une feuille `include` : la RÉSOLUTION de
//! l'inclusion est de l'entrée-sortie, donc HORS de la couche 1 (crate
//! pur, §1). C'est à l'appelant (couche CLI) de lire le fichier inclus et
//! de l'analyser à son tour ; la couche 2 diagnostique toute inclusion
//! non résolue et dégrade la fidélité (§6.3).

use crate::error::ParseError;
use crate::tree::{ConfigNode, ConfigTree, MAX_DEPTH};

/// Mots-clés dont l'énoncé ouvre un BLOC quand une accolade `{` le suit.
/// C'est de la connaissance du FORMAT (grammaire nftables), pas de la
/// sémantique constructeur : les règles de filtrage, elles, ne commencent
/// jamais par ces mots-clés (une accolade y est donc un ensemble anonyme).
const BLOCK_KEYWORDS: &[&str] = &[
    "table",
    "chain",
    "set",
    "map",
    "flowtable",
    "counter",
    "quota",
    "limit",
    "secmark",
    "synproxy",
];

/// Sous-commandes de `ct` qui ouvrent un bloc (`ct helper h { … }`), par
/// opposition aux expressions de règle (`ct state established … accept`).
const CT_BLOCK_KEYWORDS: &[&str] = &["helper", "timeout", "expectation"];

/// Nombre de jetons conservés dans l'en-tête d'un message d'erreur.
const HEADER_EXCERPT: usize = 6;

/// Un jeton du flux lexical. Les fins de ligne sont des jetons : elles
/// terminent un énoncé (sauf à l'intérieur d'un ensemble anonyme replié).
#[derive(Debug, PartialEq, Eq)]
enum Tok {
    Word(String),
    Open,
    Close,
    Semi,
    Comma,
    Newline,
}

/// Analyse un fichier de règles nftables complet.
///
/// Aucune sémantique : les mots-clés inconnus deviennent des feuilles,
/// c'est la couche 2 qui décidera de leur sort (§6.3 : ne jamais deviner).
pub fn parse(input: &str, filename: &str) -> Result<ConfigTree, ParseError> {
    let tokens = lex(input, filename)?;

    let mut roots: Vec<ConfigNode> = Vec::new();
    let mut stack: Vec<ConfigNode> = Vec::new();
    // L'énoncé en cours de constitution, avec ses lignes de début/fin.
    let mut stmt: Vec<String> = Vec::new();
    let mut stmt_line: u32 = 0;
    let mut stmt_end: u32 = 0;
    // Profondeur d'ensembles anonymes ouverts DANS l'énoncé courant.
    let mut inline_depth: usize = 0;
    let mut inline_line: u32 = 0;

    for (tok, line) in tokens {
        match tok {
            Tok::Word(w) => {
                if stmt.is_empty() {
                    stmt_line = line;
                }
                stmt.push(w);
                stmt_end = line;
            }
            Tok::Comma => {
                if stmt.is_empty() {
                    stmt_line = line;
                }
                stmt.push(",".to_owned());
                stmt_end = line;
            }
            Tok::Open => {
                if inline_depth == 0 && is_block_header(&stmt) {
                    if stack.len() >= MAX_DEPTH {
                        return Err(ParseError::TooDeep {
                            file: filename.to_owned(),
                            line,
                            limit: MAX_DEPTH,
                        });
                    }
                    let keyword = stmt.remove(0);
                    let args = std::mem::take(&mut stmt);
                    stack.push(ConfigNode::new(keyword, args, filename, stmt_line));
                } else {
                    // Ensemble anonyme : l'accolade reste dans l'énoncé.
                    if stmt.is_empty() {
                        stmt_line = line;
                    }
                    if inline_depth == 0 {
                        inline_line = line;
                    }
                    inline_depth += 1;
                    stmt.push("{".to_owned());
                    stmt_end = line;
                }
            }
            Tok::Close => {
                if inline_depth > 0 {
                    inline_depth -= 1;
                    stmt.push("}".to_owned());
                    stmt_end = line;
                } else {
                    // `}` termine l'énoncé en cours puis ferme le bloc.
                    flush_stmt(
                        &mut stmt, stmt_line, stmt_end, &mut stack, &mut roots, filename,
                    );
                    match stack.pop() {
                        None => {
                            return Err(ParseError::OrphanCloseBrace {
                                file: filename.to_owned(),
                                line,
                            })
                        }
                        Some(mut node) => {
                            node.span.end_line = Some(line);
                            attach(&mut stack, &mut roots, node);
                        }
                    }
                }
            }
            Tok::Semi => {
                // La grammaire nftables n'admet pas de `;` dans un
                // ensemble anonyme : en rencontrer un révèle une accolade
                // jamais refermée. On ne devine pas où elle aurait dû
                // l'être.
                if inline_depth > 0 {
                    return Err(ParseError::UnclosedBlock {
                        file: filename.to_owned(),
                        header: excerpt(&stmt),
                        line: inline_line,
                    });
                }
                flush_stmt(
                    &mut stmt, stmt_line, stmt_end, &mut stack, &mut roots, filename,
                );
            }
            Tok::Newline => {
                // Dans un ensemble anonyme replié, l'énoncé continue.
                if inline_depth == 0 {
                    flush_stmt(
                        &mut stmt, stmt_line, stmt_end, &mut stack, &mut roots, filename,
                    );
                }
            }
        }
    }

    // Fin de fichier : le lexeur émet toujours une fin de ligne finale,
    // donc l'énoncé courant est déjà vidé — sauf ensemble anonyme ouvert.
    if inline_depth > 0 {
        return Err(ParseError::UnclosedBlock {
            file: filename.to_owned(),
            header: excerpt(&stmt),
            line: inline_line,
        });
    }
    if let Some(node) = stack.last() {
        return Err(ParseError::UnclosedBlock {
            file: filename.to_owned(),
            header: header_of(node),
            line: node.span.line,
        });
    }

    Ok(ConfigTree {
        roots,
        file: filename.to_owned(),
    })
}

/// L'énoncé courant ouvre-t-il un bloc ? Voir [`BLOCK_KEYWORDS`]. Les
/// formes impératives (`add table inet t { … }`) sont tolérées. Un énoncé
/// qui contient déjà une accolade d'ensemble anonyme n'ouvre jamais un
/// bloc.
fn is_block_header(stmt: &[String]) -> bool {
    if stmt.iter().any(|t| t == "{" || t == "}") {
        return false;
    }
    let words: Vec<&str> = stmt.iter().map(String::as_str).collect();
    let head = match words.split_first() {
        Some((&"add" | &"create", rest)) => rest,
        _ => words.as_slice(),
    };
    match head.first() {
        Some(&"ct") => matches!(head.get(1), Some(k) if CT_BLOCK_KEYWORDS.contains(k)),
        Some(k) => BLOCK_KEYWORDS.contains(k),
        None => false,
    }
}

/// Vide l'énoncé courant en une feuille rattachée au bloc ouvert le plus
/// proche. Un énoncé replié sur plusieurs lignes porte un `end_line`.
fn flush_stmt(
    stmt: &mut Vec<String>,
    line: u32,
    end: u32,
    stack: &mut [ConfigNode],
    roots: &mut Vec<ConfigNode>,
    filename: &str,
) {
    if stmt.is_empty() {
        return;
    }
    let keyword = stmt.remove(0);
    let args = std::mem::take(stmt);
    let mut node = ConfigNode::new(keyword, args, filename, line);
    if end > line {
        node.span.end_line = Some(end);
    }
    attach(stack, roots, node);
}

/// Rattache `node` au bloc ouvert le plus proche, ou aux racines.
fn attach(stack: &mut [ConfigNode], roots: &mut Vec<ConfigNode>, node: ConfigNode) {
    match stack.last_mut() {
        Some(parent) => parent.children.push(node),
        None => roots.push(node),
    }
}

/// Reconstruit l'en-tête d'un bloc pour les messages d'erreur.
fn header_of(node: &ConfigNode) -> String {
    if node.args.is_empty() {
        node.keyword.clone()
    } else {
        format!("{} {}", node.keyword, node.args_joined())
    }
}

/// Les premiers jetons d'un énoncé, pour un message d'erreur.
fn excerpt(stmt: &[String]) -> String {
    let mut out = stmt
        .iter()
        .take(HEADER_EXCERPT)
        .cloned()
        .collect::<Vec<_>>()
        .join(" ");
    if stmt.len() > HEADER_EXCERPT {
        out.push_str(" …");
    }
    out
}

/// Découpe l'entrée en jetons, en gardant la ligne d'origine de chacun.
///
/// - `#` ouvre un commentaire jusqu'à la fin de la ligne ;
/// - `"…"` est un mot unique (échappements `\"` et `\\`), qui ne peut pas
///   franchir une fin de ligne ;
/// - `\` en fin de ligne joint la ligne suivante (aucune fin de ligne
///   n'est émise) ;
/// - `{ } ; ,` sont des jetons de ponctuation autonomes ; tout le reste
///   (adresses, `@ensemble`, `$variable`, `!=`, nombres négatifs…) forme
///   des mots.
fn lex(input: &str, filename: &str) -> Result<Vec<(Tok, u32)>, ParseError> {
    let mut tokens: Vec<(Tok, u32)> = Vec::new();
    let mut line: u32 = 1;
    let mut word = String::new();
    // Distinct de `word.is_empty()` : `""` est un mot vide valide.
    let mut has_word = false;
    let mut chars = input.chars().peekable();

    macro_rules! flush_word {
        () => {
            if has_word {
                tokens.push((Tok::Word(std::mem::take(&mut word)), line));
                has_word = false;
            }
        };
    }

    while let Some(c) = chars.next() {
        match c {
            '\n' => {
                flush_word!();
                tokens.push((Tok::Newline, line));
                line += 1;
            }
            '#' => {
                flush_word!();
                while chars.peek().is_some_and(|&n| n != '\n') {
                    chars.next();
                }
            }
            '"' => {
                let start_line = line;
                loop {
                    match chars.next() {
                        None | Some('\n') => {
                            return Err(ParseError::UnterminatedQuote {
                                file: filename.to_owned(),
                                line: start_line,
                            })
                        }
                        Some('"') => break,
                        Some('\\') => match chars.next() {
                            None => {
                                return Err(ParseError::UnterminatedQuote {
                                    file: filename.to_owned(),
                                    line: start_line,
                                })
                            }
                            Some(escaped) => {
                                if escaped == '\n' {
                                    line += 1;
                                }
                                word.push(escaped);
                            }
                        },
                        Some(other) => word.push(other),
                    }
                }
                has_word = true;
            }
            '\\' => {
                // Continuation de ligne : `\` suivi de la fin de ligne
                // (formes \n et \r\n). Sinon, un `\` ordinaire dans un mot.
                if chars.peek() == Some(&'\r') {
                    chars.next();
                }
                if chars.peek() == Some(&'\n') {
                    chars.next();
                    flush_word!();
                    line += 1;
                } else {
                    word.push('\\');
                    has_word = true;
                }
            }
            '{' => {
                flush_word!();
                tokens.push((Tok::Open, line));
            }
            '}' => {
                flush_word!();
                tokens.push((Tok::Close, line));
            }
            ';' => {
                flush_word!();
                tokens.push((Tok::Semi, line));
            }
            ',' => {
                flush_word!();
                tokens.push((Tok::Comma, line));
            }
            c if c.is_whitespace() => flush_word!(),
            c => {
                word.push(c);
                has_word = true;
            }
        }
    }
    if has_word {
        tokens.push((Tok::Word(word), line));
    }
    // Fin de fichier : équivaut à une fin de ligne, pour que l'appelant
    // n'ait qu'un seul chemin de terminaison d'énoncé.
    tokens.push((Tok::Newline, line));
    Ok(tokens)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tree::tests_support::span;

    /// Extrait réaliste : shebang, `flush ruleset`, `define`, table inet
    /// avec ensemble nommé (éléments repliés sur deux lignes), chaînes de
    /// base (deux énoncés par ligne), ensemble anonyme, saut, `include`.
    const EXTRAIT: &str = r#"#!/usr/sbin/nft -f
# Fixture de test — adressage RFC1918 inventé.

flush ruleset

define net_admin = 10.20.30.0/24

table inet filtre {
    set postes {
        type ipv4_addr
        elements = { 10.20.40.0/26,
                     10.20.42.7 }
    }

    chain entree {
        type filter hook input priority 0; policy drop;
        ct state established,related accept
        iifname "lo" accept
        ip saddr $net_admin tcp dport { 22, 443 } accept
    }

    chain transit {
        type filter hook forward priority 0; policy drop;
        iifname "lan0" oifname "wan0" jump sortie_lan
    }
}

include "extra.nft"
"#;

    #[test]
    fn structure_de_l_extrait_realiste() {
        let tree = parse(EXTRAIT, "regles.nft").expect("extrait valide");
        assert_eq!(tree.file, "regles.nft");

        // Racines : flush, define, table, include (le shebang et les
        // commentaires disparaissent).
        let keywords: Vec<&str> = tree.roots.iter().map(|n| n.keyword.as_str()).collect();
        assert_eq!(keywords, ["flush", "define", "table", "include"]);
        assert_eq!(tree.roots[0].args, ["ruleset"]);
        assert_eq!(tree.roots[1].args, ["net_admin", "=", "10.20.30.0/24"]);
        assert_eq!(tree.roots[3].args, ["extra.nft"]);

        // La table : un set et deux chaînes.
        let table = tree.child("table").expect("table");
        assert_eq!(table.args_joined(), "inet filtre");
        assert_eq!(table.children.len(), 3);

        // Le set : les éléments repliés forment UN énoncé, accolades et
        // virgules conservées comme arguments.
        let set = table.child("set").expect("set postes");
        assert_eq!(set.arg(0), Some("postes"));
        let elements = set.child("elements").expect("elements");
        assert_eq!(
            elements.args,
            ["=", "{", "10.20.40.0/26", ",", "10.20.42.7", "}"]
        );

        // La chaîne entree : `type …; policy …;` donne DEUX nœuds.
        let entree = table
            .children_named("chain")
            .find(|c| c.arg(0) == Some("entree"))
            .expect("chain entree");
        let kws: Vec<&str> = entree.children.iter().map(|n| n.keyword.as_str()).collect();
        assert_eq!(kws, ["type", "policy", "ct", "iifname", "ip"]);
        assert_eq!(
            entree.children[0].args,
            ["filter", "hook", "input", "priority", "0"]
        );
        assert_eq!(entree.children[1].args, ["drop"]);

        // Liste de valeurs : la virgule est un argument à part entière.
        assert_eq!(
            entree.children[2].args,
            ["state", "established", ",", "related", "accept"]
        );

        // Guillemets résolus : `"lo"` devient l'argument `lo`.
        assert_eq!(entree.children[3].args, ["lo", "accept"]);

        // Ensemble anonyme dans une règle : accolades conservées.
        assert_eq!(
            entree.children[4].args,
            [
                "saddr",
                "$net_admin",
                "tcp",
                "dport",
                "{",
                "22",
                ",",
                "443",
                "}",
                "accept"
            ]
        );
    }

    #[test]
    fn spans_exacts_lignes_d_origine_preservees() {
        let tree = parse(EXTRAIT, "regles.nft").expect("extrait valide");

        // La table ouvre ligne 8 et ferme ligne 26.
        let table = tree.child("table").expect("table");
        assert_eq!(table.span, span("regles.nft", 8, Some(26)));

        // Le set : lignes 9 à 13 ; ses éléments repliés couvrent 11–12.
        let set = table.child("set").expect("set");
        assert_eq!(set.span, span("regles.nft", 9, Some(13)));
        let elements = set.child("elements").expect("elements");
        assert_eq!(elements.span, span("regles.nft", 11, Some(12)));

        // Deux énoncés sur la même ligne : même ligne, pas de end_line.
        let entree = table.child("chain").expect("entree");
        assert_eq!(entree.span, span("regles.nft", 15, Some(20)));
        assert_eq!(entree.children[0].span, span("regles.nft", 16, None));
        assert_eq!(entree.children[1].span, span("regles.nft", 16, None));

        // Feuille de premier niveau après la table.
        assert_eq!(tree.roots[3].span, span("regles.nft", 28, None));
    }

    #[test]
    fn instantane_de_l_arbre() {
        let tree = parse(EXTRAIT, "regles.nft").expect("extrait valide");
        insta::assert_debug_snapshot!(tree);
    }

    #[test]
    fn blocs_imbriques_sur_une_seule_ligne() {
        let tree = parse(
            "table inet t { chain c { udp dport 53 accept } }\n",
            "t.nft",
        )
        .expect("bloc en une ligne");
        let table = &tree.roots[0];
        assert_eq!(table.span, span("t.nft", 1, Some(1)));
        let chain = table.child("chain").expect("chain");
        let rule = chain.child("udp").expect("règle");
        assert_eq!(rule.args, ["dport", "53", "accept"]);
    }

    #[test]
    fn continuation_de_ligne() {
        let input =
            "table ip t {\n  chain c {\n    ip saddr 10.0.0.0/8 \\\n       accept\n  }\n}\n";
        let tree = parse(input, "t.nft").expect("continuation valide");
        let rule = tree.roots[0]
            .child("chain")
            .and_then(|c| c.child("ip"))
            .expect("règle");
        assert_eq!(rule.args, ["saddr", "10.0.0.0/8", "accept"]);
        // L'énoncé couvre les deux lignes physiques.
        assert_eq!(rule.span, span("t.nft", 3, Some(4)));
    }

    #[test]
    fn guillemets_vides_et_espaces() {
        let tree = parse(
            "table inet t {\n chain c {\n log prefix \"\" comment \"a b\"\n }\n}\n",
            "t.nft",
        )
        .expect("valide");
        let rule = tree.roots[0]
            .child("chain")
            .and_then(|c| c.child("log"))
            .expect("log");
        assert_eq!(rule.args, ["prefix", "", "comment", "a b"]);
    }

    #[test]
    fn diese_ouvre_un_commentaire_hors_guillemets_seulement() {
        let tree = parse(
            "table inet t {\n chain c {\n accept comment \"pas un # commentaire\" # vrai commentaire\n }\n}\n",
            "t.nft",
        )
        .expect("valide");
        let rule = tree.roots[0]
            .child("chain")
            .and_then(|c| c.child("accept"))
            .expect("accept");
        assert_eq!(rule.args, ["comment", "pas un # commentaire"]);
    }

    #[test]
    fn accolade_orpheline_avec_la_bonne_ligne() {
        let err = parse("table inet t {\n}\n}\n", "t.nft").expect_err("accolade orpheline");
        assert_eq!(
            err,
            ParseError::OrphanCloseBrace {
                file: "t.nft".to_owned(),
                line: 3,
            }
        );
        assert_eq!(err.line(), 3);
        assert_eq!(err.file(), "t.nft");
    }

    #[test]
    fn bloc_jamais_ferme_en_fin_de_fichier() {
        let err = parse("table inet filtre {\n    chain entree {\n", "t.nft")
            .expect_err("bloc non fermé");
        // Le bloc fautif est le plus profond resté ouvert.
        assert_eq!(
            err,
            ParseError::UnclosedBlock {
                file: "t.nft".to_owned(),
                header: "chain entree".to_owned(),
                line: 2,
            }
        );
    }

    #[test]
    fn ensemble_anonyme_jamais_ferme() {
        // Par fin de fichier.
        let err = parse(
            "table inet t {\n chain c {\n tcp dport { 22, 443\n",
            "t.nft",
        )
        .expect_err("ensemble non fermé");
        assert_eq!(
            err,
            ParseError::UnclosedBlock {
                file: "t.nft".to_owned(),
                header: "tcp dport { 22 , 443".to_owned(),
                line: 3,
            }
        );

        // Par un `;` : la grammaire n'admet pas de `;` dans un ensemble.
        let err = parse(
            "table inet t {\n chain c {\n tcp dport { 22; accept\n }\n}\n",
            "t.nft",
        )
        .expect_err("`;` dans un ensemble");
        assert_eq!(
            err,
            ParseError::UnclosedBlock {
                file: "t.nft".to_owned(),
                header: "tcp dport { 22".to_owned(),
                line: 3,
            }
        );
    }

    #[test]
    fn guillemet_non_ferme_signale_avec_la_ligne() {
        let err = parse(
            "table inet t {\n chain c {\n iifname \"lan0\n }\n}\n",
            "t.nft",
        )
        .expect_err("guillemet non fermé");
        assert_eq!(
            err,
            ParseError::UnterminatedQuote {
                file: "t.nft".to_owned(),
                line: 3,
            }
        );
    }

    #[test]
    fn entree_vide_donne_un_arbre_vide() {
        let tree = parse("", "vide.nft").expect("vide est valide");
        assert!(tree.roots.is_empty());
        let tree = parse("# seulement des commentaires\n\n", "vide.nft").expect("valide");
        assert!(tree.roots.is_empty());
    }

    /// §11.3 — une imbrication hostile plus profonde que la limite est
    /// refusée AVANT de construire l'arbre.
    #[test]
    fn imbrication_hostile_refusee_a_la_limite() {
        let profondeur = MAX_DEPTH + 1;
        let mut input = String::new();
        for _ in 0..profondeur {
            input.push_str("chain a {\n");
        }
        for _ in 0..profondeur {
            input.push_str("}\n");
        }
        let err = parse(&input, "hostile.nft").expect_err("trop profond");
        assert_eq!(
            err,
            ParseError::TooDeep {
                file: "hostile.nft".to_owned(),
                line: MAX_DEPTH as u32 + 1,
                limit: MAX_DEPTH,
            }
        );

        // Juste SOUS la limite : accepté, l'arbre est complet.
        let mut ok = String::new();
        for _ in 0..MAX_DEPTH {
            ok.push_str("chain a {\n");
        }
        for _ in 0..MAX_DEPTH {
            ok.push_str("}\n");
        }
        let tree = parse(&ok, "profond.nft").expect("sous la limite");
        assert_eq!(tree.roots.len(), 1);
    }

    /// Une avalanche d'accolades d'ensemble anonyme ne fait pas déborder
    /// la pile : la profondeur en ligne est un simple compteur.
    #[test]
    fn accolades_en_ligne_hostiles_sans_panique() {
        let mut input = String::from("x ");
        for _ in 0..10_000 {
            input.push('{');
        }
        for _ in 0..10_000 {
            input.push('}');
        }
        input.push('\n');
        let tree = parse(&input, "t.nft").expect("compteur, pas de récursion");
        assert_eq!(tree.roots.len(), 1);
        assert_eq!(tree.roots[0].keyword, "x");
    }

    /// La forme impérative `add table … { … }` ouvre bien un bloc.
    #[test]
    fn forme_imperative_toleree() {
        let tree = parse("add table inet t {\n chain c {\n }\n}\n", "t.nft").expect("valide");
        assert_eq!(tree.roots[0].keyword, "add");
        assert_eq!(tree.roots[0].args, ["table", "inet", "t"]);
        assert!(tree.roots[0].child("chain").is_some());
    }
}
