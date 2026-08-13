//! Analyseur du format XML (§6.1, §6.4 : « pfSense / OPNsense —
//! configuration en XML, donc analyseur presque gratuit »).
//!
//! ## Correspondance XML → arbre générique
//!
//! - chaque ÉLÉMENT devient un [`ConfigNode`] : `keyword` = nom de
//!   l'élément, enfants récursifs ;
//! - le TEXTE de l'élément (texte + CDATA concaténés, entités standard
//!   décodées) est découpé sur les blancs et devient `args` — c'est la
//!   convention des autres analyseurs (« les mots suivants »), et
//!   `args_joined()` restitue la valeur à une espace près ;
//! - chaque ATTRIBUT devient un argument `@nom=valeur`, placé AVANT les
//!   jetons du texte (le préfixe `@` marque la provenance). Rien n'est
//!   perdu en silence ;
//! - le `span` porte le VRAI numéro de ligne de la balise ouvrante, et
//!   `end_line` la ligne de la balise fermante quand l'élément s'étend
//!   sur plusieurs lignes (convention de `SourceSpan` : `None` pour un
//!   élément tenant sur une seule ligne).
//!
//! ## Sûreté (§11.3 — l'entrée est hostile par hypothèse)
//!
//! - **Pas de XXE possible.** `quick-xml` ne résout NI les entités
//!   externes NI les entités définies par une DTD : un `<!DOCTYPE …>` est
//!   lu comme un événement inerte et jamais interprété, et une entité
//!   non standard (`&xxe;`) est une erreur d'analyse, pas une lecture de
//!   fichier. Seules les cinq entités prédéfinies (`&amp;` `&lt;` `&gt;`
//!   `&apos;` `&quot;`) et les références numériques (`&#233;`) sont
//!   décodées.
//! - **Profondeur bornée** par [`MAX_DEPTH`], comme les autres
//!   analyseurs : au-delà, `ParseError::TooDeep` AVANT de construire
//!   l'arbre.
//! - XML malformé (balise non appariée, attribut illisible…) →
//!   [`ParseError::MalformedXml`] avec la ligne fautive ; document
//!   tronqué (balise jamais refermée) → [`ParseError::UnclosedBlock`].
//!   Jamais de panique.
//!
//! Tolérances documentées : un éventuel BOM de tête est ignoré, et une
//! forêt de plusieurs éléments racines est acceptée (l'arbre générique
//! est une forêt ; c'est la couche 2 qui exige sa racine).

use quick_xml::events::{BytesStart, Event};
use quick_xml::Reader;

use crate::error::ParseError;
use crate::tree::{ConfigNode, ConfigTree, MAX_DEPTH};

/// Un élément ouvert, en cours de construction sur la pile.
struct Frame {
    node: ConfigNode,
    /// Fragments de texte accumulés (texte + CDATA), découpés en `args`
    /// à la fermeture — le découpage NE peut PAS se faire fragment par
    /// fragment, sinon `R&amp;D` (deux fragments autour de l'entité)
    /// deviendrait deux jetons.
    text: String,
}

/// Positions des fins de ligne, pour convertir un décalage d'octets du
/// lecteur en numéro de ligne 1-indexé.
struct LineIndex {
    newlines: Vec<usize>,
}

impl LineIndex {
    fn new(input: &str) -> Self {
        Self {
            newlines: input
                .bytes()
                .enumerate()
                .filter_map(|(i, b)| (b == b'\n').then_some(i))
                .collect(),
        }
    }

    /// Ligne (1-indexée) contenant l'octet `offset`.
    fn line_of(&self, offset: usize) -> u32 {
        let n = self.newlines.partition_point(|&p| p < offset);
        u32::try_from(n + 1).unwrap_or(u32::MAX)
    }
}

/// Analyse un document XML complet en arbre de configuration générique.
///
/// Aucune sémantique : le sens des éléments (`<interfaces>`, `<filter>`…)
/// vit dans la couche 2 (`calque-vendors`).
pub fn parse(input: &str, filename: &str) -> Result<ConfigTree, ParseError> {
    // BOM UTF-8 toléré en tête (fichiers exportés depuis Windows).
    let input = input.strip_prefix('\u{feff}').unwrap_or(input);
    let lines = LineIndex::new(input);
    let mut reader = Reader::from_str(input);
    // Configuration PAR DÉFAUT de quick-xml, volontairement conservée :
    // `check_end_names = true` (balises mal appariées rejetées), pas
    // d'expansion des éléments vides, et surtout AUCUNE résolution
    // d'entités DTD ni d'entités externes (voir l'en-tête du module).

    let mut roots: Vec<ConfigNode> = Vec::new();
    let mut stack: Vec<Frame> = Vec::new();

    loop {
        // Décalage du PROCHAIN événement : c'est le début de la balise
        // (ou du texte) qui va être lu — donc sa vraie ligne d'origine.
        let offset = offset_of(&reader);
        let line = lines.line_of(offset);
        match reader.read_event() {
            Err(e) => {
                let at = usize::try_from(reader.error_position()).unwrap_or(usize::MAX);
                return Err(ParseError::MalformedXml {
                    file: filename.to_owned(),
                    line: lines.line_of(at),
                    message: e.to_string(),
                });
            }
            Ok(Event::Start(start)) => {
                if stack.len() >= MAX_DEPTH {
                    return Err(ParseError::TooDeep {
                        file: filename.to_owned(),
                        line,
                        limit: MAX_DEPTH,
                    });
                }
                let node = element_node(&start, filename, line, &lines, &reader)?;
                stack.push(Frame {
                    node,
                    text: String::new(),
                });
            }
            Ok(Event::Empty(start)) => {
                // `<vide/>` : une feuille, attachée sans passer par la
                // pile (profondeur inchangée, déjà bornée par le parent).
                let node = element_node(&start, filename, line, &lines, &reader)?;
                attach(&mut stack, &mut roots, node);
            }
            Ok(Event::End(_)) => {
                // `check_end_names` garantit l'appariement : une balise
                // fermante orpheline a déjà été rejetée par le lecteur.
                // On reste néanmoins défensif — jamais de panique.
                let Some(mut frame) = stack.pop() else {
                    return Err(ParseError::MalformedXml {
                        file: filename.to_owned(),
                        line,
                        message: "balise fermante sans balise ouvrante".to_owned(),
                    });
                };
                frame
                    .node
                    .args
                    .extend(frame.text.split_whitespace().map(str::to_owned));
                if line != frame.node.span.line {
                    frame.node.span.end_line = Some(line);
                }
                attach(&mut stack, &mut roots, frame.node);
            }
            Ok(Event::Text(t)) => {
                // Ligne du premier caractère NON BLANC : un fragment de
                // texte commence souvent au saut de ligne précédent.
                let lead = t.iter().take_while(|b| b.is_ascii_whitespace()).count();
                // Depuis quick-xml 0.41, les événements Text ne portent
                // plus d'entités (elles arrivent en `GeneralRef`) : ici,
                // seulement décodage + normalisation des fins de ligne.
                let text = t.xml10_content().map_err(|e| ParseError::MalformedXml {
                    file: filename.to_owned(),
                    line,
                    message: e.to_string(),
                })?;
                match stack.last_mut() {
                    Some(frame) => frame.text.push_str(&text),
                    None => {
                        // Du texte hors de tout élément n'a pas de place
                        // dans l'arbre : le perdre en silence est exclu.
                        if !text.trim().is_empty() {
                            return Err(ParseError::MalformedXml {
                                file: filename.to_owned(),
                                line: lines.line_of(offset + lead),
                                message: "texte hors de tout élément".to_owned(),
                            });
                        }
                    }
                }
            }
            Ok(Event::CData(c)) => {
                let lead = c.iter().take_while(|b| b.is_ascii_whitespace()).count();
                // Contenu CDATA : littéral, aucune entité à décoder.
                let text = String::from_utf8_lossy(&c);
                match stack.last_mut() {
                    Some(frame) => frame.text.push_str(&text),
                    None => {
                        if !text.trim().is_empty() {
                            return Err(ParseError::MalformedXml {
                                file: filename.to_owned(),
                                line: lines.line_of(offset + lead),
                                message: "section CDATA hors de tout élément".to_owned(),
                            });
                        }
                    }
                }
            }
            // Depuis quick-xml 0.41, une référence d'entité (`&amp;`,
            // `&#38;`…) est un événement distinct du texte. Les entités
            // prédéfinies et les références numériques sont résolues par
            // le résolveur du crate ; une entité inconnue (DTD, externe)
            // reste une ERREUR — jamais résolue (pas de XXE, en-tête).
            Ok(Event::GeneralRef(r)) => {
                let name = r.decode().map_err(|e| ParseError::MalformedXml {
                    file: filename.to_owned(),
                    line,
                    message: e.to_string(),
                })?;
                let raw = format!("&{name};");
                let resolved =
                    quick_xml::escape::unescape(&raw).map_err(|e| ParseError::MalformedXml {
                        file: filename.to_owned(),
                        line,
                        message: format!("référence d'entité « &{name}; » : {e}"),
                    })?;
                match stack.last_mut() {
                    Some(frame) => frame.text.push_str(&resolved),
                    None => {
                        return Err(ParseError::MalformedXml {
                            file: filename.to_owned(),
                            line,
                            message: "référence d'entité hors de tout élément".to_owned(),
                        });
                    }
                }
            }
            // Déclaration `<?xml …?>`, commentaires, instructions de
            // traitement : sans contenu de configuration. Un `<!DOCTYPE>`
            // est lu mais JAMAIS résolu (pas de XXE, voir l'en-tête).
            Ok(Event::Decl(_) | Event::Comment(_) | Event::PI(_) | Event::DocType(_)) => {}
            Ok(Event::Eof) => break,
        }
    }

    // Fin de fichier : tout élément resté ouvert est fautif (document
    // tronqué). Le plus profond est signalé, avec sa ligne d'OUVERTURE.
    if let Some(frame) = stack.last() {
        return Err(ParseError::UnclosedBlock {
            file: filename.to_owned(),
            header: format!("<{}>", frame.node.keyword),
            line: frame.node.span.line,
        });
    }

    Ok(ConfigTree {
        roots,
        file: filename.to_owned(),
    })
}

/// Décalage d'octets du prochain événement à lire.
fn offset_of(reader: &Reader<&[u8]>) -> usize {
    usize::try_from(reader.buffer_position()).unwrap_or(usize::MAX)
}

/// Construit le nœud d'un élément : nom → `keyword`, attributs → args
/// `@nom=valeur`. Le texte viendra s'ajouter à la fermeture.
fn element_node(
    start: &BytesStart<'_>,
    filename: &str,
    line: u32,
    lines: &LineIndex,
    reader: &Reader<&[u8]>,
) -> Result<ConfigNode, ParseError> {
    let keyword = String::from_utf8_lossy(start.name().as_ref()).into_owned();
    let mut args = Vec::new();
    for attr in start.attributes() {
        let attr = attr.map_err(|e| ParseError::MalformedXml {
            file: filename.to_owned(),
            line: lines.line_of(offset_of(reader)),
            message: e.to_string(),
        })?;
        let key = String::from_utf8_lossy(attr.key.as_ref()).into_owned();
        let value = attr
            .normalized_value(quick_xml::XmlVersion::default())
            .map_err(|e| ParseError::MalformedXml {
                file: filename.to_owned(),
                line: lines.line_of(offset_of(reader)),
                message: e.to_string(),
            })?;
        args.push(format!("@{key}={value}"));
    }
    Ok(ConfigNode::new(keyword, args, filename, line))
}

/// Rattache `node` à l'élément ouvert le plus proche, ou aux racines.
fn attach(stack: &mut [Frame], roots: &mut Vec<ConfigNode>, node: ConfigNode) {
    match stack.last_mut() {
        Some(parent) => parent.node.children.push(node),
        None => roots.push(node),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tree::tests_support::span;

    /// Extrait réaliste d'un config.xml OPNsense : déclaration XML,
    /// attributs, élément vide, entités, CDATA, texte multi-lignes.
    const EXTRAIT: &str = r#"<?xml version="1.0"?>
<opnsense>
  <version>23.7</version>
  <interfaces>
    <lan>
      <if>vtnet1</if>
      <descr>R&amp;D &#233;tage 2</descr>
      <enable>1</enable>
      <ipaddr>10.10.1.1</ipaddr>
      <subnet>24</subnet>
    </lan>
  </interfaces>
  <filter>
    <rule uuid="9b2f1c04-5d1e-4d8e-9f3a-000000000001">
      <type>pass</type>
      <descr><![CDATA[règle <historique> & sans filet]]></descr>
      <source><any/></source>
    </rule>
  </filter>
  <aliases>
    <alias>
      <name>n_postes</name>
      <content>10.10.1.0/24
10.10.3.0/24</content>
    </alias>
  </aliases>
</opnsense>
"#;

    #[test]
    fn structure_de_l_extrait_realiste() {
        let tree = parse(EXTRAIT, "config.xml").expect("extrait valide");
        assert_eq!(tree.file, "config.xml");
        assert_eq!(tree.roots.len(), 1);

        let root = &tree.roots[0];
        assert_eq!(root.keyword, "opnsense");
        assert!(root.args.is_empty());
        assert_eq!(root.children.len(), 4);

        // Feuille à texte simple.
        assert_eq!(root.child("version").and_then(|n| n.arg(0)), Some("23.7"));

        // Entités standard et référence numérique décodées ; le texte est
        // découpé sur les blancs, args_joined() restitue la valeur.
        let lan = root
            .child("interfaces")
            .and_then(|n| n.child("lan"))
            .expect("interface lan");
        let descr = lan.child("descr").expect("descr");
        assert_eq!(descr.args, ["R&D", "étage", "2"]);
        assert_eq!(descr.args_joined(), "R&D étage 2");

        // Attribut → argument `@nom=valeur`.
        let rule = root
            .child("filter")
            .and_then(|n| n.child("rule"))
            .expect("règle");
        assert_eq!(
            rule.arg(0),
            Some("@uuid=9b2f1c04-5d1e-4d8e-9f3a-000000000001")
        );

        // CDATA : contenu littéral, jamais interprété.
        let cdata = rule.child("descr").expect("descr CDATA");
        assert_eq!(cdata.args_joined(), "règle <historique> & sans filet");

        // Élément vide `<any/>` : une feuille sans args ni enfants.
        let any = rule
            .child("source")
            .and_then(|n| n.child("any"))
            .expect("any");
        assert!(any.args.is_empty() && any.children.is_empty());

        // Texte multi-lignes : un jeton par valeur.
        let content = root
            .child("aliases")
            .and_then(|n| n.child("alias"))
            .and_then(|n| n.child("content"))
            .expect("content");
        assert_eq!(content.args, ["10.10.1.0/24", "10.10.3.0/24"]);
    }

    #[test]
    fn spans_exacts_lignes_d_origine() {
        let tree = parse(EXTRAIT, "config.xml").expect("extrait valide");
        let root = &tree.roots[0];

        // <opnsense> : lignes 2 à 27.
        assert_eq!(root.span, span("config.xml", 2, Some(27)));

        // Feuille sur une seule ligne : end_line = None (convention
        // SourceSpan : « dernière ligne si l'élément s'étend »).
        assert_eq!(root.child("version").unwrap().span.line, 3);
        assert_eq!(root.child("version").unwrap().span.end_line, None);

        // Blocs imbriqués : lignes réelles d'ouverture et de fermeture.
        let interfaces = root.child("interfaces").unwrap();
        assert_eq!(interfaces.span, span("config.xml", 4, Some(12)));
        let lan = interfaces.child("lan").unwrap();
        assert_eq!(lan.span, span("config.xml", 5, Some(11)));

        // La règle du filtre, plus bas dans le fichier.
        let rule = root.child("filter").unwrap().child("rule").unwrap();
        assert_eq!(rule.span, span("config.xml", 14, Some(18)));

        // <content> s'étend sur deux lignes (23 à 24).
        let content = root
            .child("aliases")
            .unwrap()
            .child("alias")
            .unwrap()
            .child("content")
            .unwrap();
        assert_eq!(content.span, span("config.xml", 23, Some(24)));
    }

    #[test]
    fn instantane_de_l_arbre() {
        let tree = parse(EXTRAIT, "config.xml").expect("extrait valide");
        insta::assert_debug_snapshot!(tree);
    }

    #[test]
    fn entree_vide_donne_un_arbre_vide() {
        let tree = parse("", "vide.xml").expect("vide est valide");
        assert!(tree.roots.is_empty());
        // Un BOM seul aussi.
        assert!(parse("\u{feff}", "bom.xml").unwrap().roots.is_empty());
    }

    #[test]
    fn bom_de_tete_tolere_sans_decaler_les_lignes() {
        let tree = parse("\u{feff}<a>\n<b>1</b>\n</a>\n", "bom.xml").expect("BOM toléré");
        assert_eq!(tree.roots[0].span, span("bom.xml", 1, Some(3)));
        assert_eq!(tree.roots[0].child("b").unwrap().span.line, 2);
    }

    #[test]
    fn balise_jamais_refermee_document_tronque() {
        let err = parse("<opnsense>\n  <filter>\n", "tronque.xml").expect_err("tronqué");
        assert_eq!(
            err,
            ParseError::UnclosedBlock {
                file: "tronque.xml".to_owned(),
                header: "<filter>".to_owned(),
                line: 2,
            }
        );
        assert_eq!(err.line(), 2);
        assert_eq!(err.file(), "tronque.xml");
    }

    #[test]
    fn balises_mal_appariees_rejetees_avec_la_ligne() {
        let err = parse("<a>\n  <b>\n</a>\n", "t.xml").expect_err("mal apparié");
        match err {
            ParseError::MalformedXml { file, line, .. } => {
                assert_eq!(file, "t.xml");
                assert_eq!(line, 3, "la ligne du `</a>` fautif");
            }
            other => panic!("MalformedXml attendu : {other:?}"),
        }
    }

    #[test]
    fn entite_inconnue_rejetee_jamais_resolue() {
        // Le vecteur XXE classique : une entité déclarée en DTD. La DTD
        // n'est JAMAIS interprétée, donc l'entité est inconnue → erreur.
        let input = "<!DOCTYPE r [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>\n<r>&xxe;</r>\n";
        let err = parse(input, "xxe.xml").expect_err("entité inconnue");
        match err {
            ParseError::MalformedXml { line, message, .. } => {
                assert_eq!(line, 2);
                // Le contenu du fichier visé n'apparaît évidemment pas.
                assert!(!message.contains("root:"), "{message}");
            }
            other => panic!("MalformedXml attendu : {other:?}"),
        }
    }

    #[test]
    fn texte_hors_de_tout_element_rejete() {
        let err = parse("<a>1</a>\ndu texte orphelin\n", "t.xml").expect_err("texte orphelin");
        match err {
            ParseError::MalformedXml { line, message, .. } => {
                assert_eq!(line, 2);
                // Le texte lui-même ne fuit pas dans le message (il
                // pourrait porter un secret).
                assert!(!message.contains("orphelin"), "{message}");
            }
            other => panic!("MalformedXml attendu : {other:?}"),
        }
    }

    #[test]
    fn foret_de_racines_acceptee() {
        // Toléré en couche 1 (documenté) : la couche 2 exige sa racine.
        let tree = parse("<a>1</a><b>2</b>", "t.xml").expect("forêt");
        assert_eq!(tree.roots.len(), 2);
        assert_eq!(tree.roots[1].keyword, "b");
    }

    /// §11.3 — même limite et même comportement que les autres
    /// analyseurs : refusé AVANT de construire l'arbre.
    #[test]
    fn imbrication_hostile_refusee_a_la_limite() {
        let profondeur = MAX_DEPTH + 1;
        let mut input = String::new();
        for _ in 0..profondeur {
            input.push_str("<a>");
        }
        for _ in 0..profondeur {
            input.push_str("</a>");
        }
        let err = parse(&input, "hostile.xml").expect_err("trop profond");
        assert_eq!(
            err,
            ParseError::TooDeep {
                file: "hostile.xml".to_owned(),
                line: 1,
                limit: MAX_DEPTH,
            }
        );

        // Juste SOUS la limite : accepté, l'arbre est complet.
        let mut ok = String::new();
        for _ in 0..MAX_DEPTH {
            ok.push_str("<a>");
        }
        for _ in 0..MAX_DEPTH {
            ok.push_str("</a>");
        }
        let tree = parse(&ok, "profond.xml").expect("sous la limite");
        assert_eq!(tree.roots.len(), 1);
    }

    #[test]
    fn entrees_hostiles_sans_panique() {
        for raw in [
            "<",
            "<a",
            "<a><![CDATA[jamais fermé",
            "<a attr=\"non fermé></a>",
            "<a>&#xD800;</a>", // référence numérique invalide (surrogate)
            "</seule>",
            "<a>&amp</a>",
            "<?xml version=\"1.0\"?><?pi?><!-- commentaire --><!DOCTYPE a>",
        ] {
            // Ok ou Err structurée : tout sauf une panique.
            let _ = parse(raw, "hostile.xml");
        }
    }
}
