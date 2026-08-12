//! Analyseur du format Cisco IOS : arbre PAR INDENTATION (§6.1).
//!
//! Une ligne plus indentée que la précédente devient son enfant. Une pile
//! de niveaux absorbe les indentations irrégulières : on remonte jusqu'au
//! premier ancêtre STRICTEMENT moins indenté. Les `!` sont des
//! séparateurs/commentaires, et `banner ... ^C` ouvre un bloc littéral
//! sauté jusqu'au délimiteur de fermeture.

use crate::error::ParseError;
use crate::tokenize::tokenize;
use crate::tree::{ConfigNode, ConfigTree};

/// Analyse une configuration Cisco IOS / IOS-XE.
pub fn parse(input: &str, filename: &str) -> Result<ConfigTree, ParseError> {
    let lines: Vec<&str> = input.lines().collect();
    let mut roots: Vec<ConfigNode> = Vec::new();
    // Pile de niveaux : (largeur d'indentation, nœud en construction).
    let mut stack: Vec<(usize, ConfigNode)> = Vec::new();

    let mut index = 0;
    while index < lines.len() {
        let raw = lines[index];
        let line = index as u32 + 1;
        let trimmed = raw.trim();

        // Vides, séparateurs `!` et commentaires `#` : ignorés, mais les
        // numéros de ligne d'origine restent exacts.
        if trimmed.is_empty() || trimmed.starts_with('!') || trimmed.starts_with('#') {
            index += 1;
            continue;
        }

        let indent = indent_width(raw);

        // `banner motd ^C ... ^C` : bloc littéral à sauter jusqu'au
        // délimiteur, sans interpréter son contenu.
        if trimmed == "banner" || trimmed.starts_with("banner ") || trimmed.starts_with("banner\t")
        {
            let (node, next_index) = parse_banner(&lines, index, filename)?;
            pop_to(indent, &mut stack, &mut roots);
            // Une bannière n'a jamais d'enfants : rattachée directement,
            // jamais empilée.
            attach(&mut stack, &mut roots, node);
            index = next_index;
            continue;
        }

        // Mode tolérant : un guillemet isolé dans un texte libre
        // (description...) ne doit pas faire échouer l'analyse.
        let mut tokens = match tokenize(raw, true) {
            Ok(Some(t)) if !t.is_empty() => t,
            _ => {
                index += 1;
                continue;
            }
        };
        let keyword = tokens.remove(0);
        let node = ConfigNode::new(keyword, tokens, filename, line);

        // On referme tout ce qui est au moins aussi indenté, puis on
        // empile : les lignes suivantes plus indentées deviendront des
        // enfants de ce nœud.
        pop_to(indent, &mut stack, &mut roots);
        stack.push((indent, node));
        index += 1;
    }

    // Fin de fichier : vider la pile (tout niveau >= 0 est refermé).
    pop_to(0, &mut stack, &mut roots);

    Ok(ConfigTree {
        roots,
        file: filename.to_owned(),
    })
}

/// Largeur d'indentation en colonnes (tabulation = taquets de 8).
fn indent_width(line: &str) -> usize {
    let mut width = 0;
    for c in line.chars() {
        match c {
            ' ' => width += 1,
            '\t' => width += 8 - (width % 8),
            _ => break,
        }
    }
    width
}

/// Referme tous les nœuds de la pile indentés d'au moins `indent`
/// colonnes, en les rattachant à leur parent (ou aux racines).
fn pop_to(indent: usize, stack: &mut Vec<(usize, ConfigNode)>, roots: &mut Vec<ConfigNode>) {
    while stack.last().is_some_and(|(i, _)| *i >= indent) {
        if let Some((_, node)) = stack.pop() {
            attach(stack, roots, node);
        }
    }
}

/// Rattache `node` au sommet de pile ou aux racines, en étendant le span
/// du parent jusqu'à la dernière ligne de l'enfant.
fn attach(stack: &mut [(usize, ConfigNode)], roots: &mut Vec<ConfigNode>, node: ConfigNode) {
    match stack.last_mut() {
        Some((_, parent)) => {
            let child_end = node.span.end_line.unwrap_or(node.span.line);
            parent.span.end_line = Some(child_end.max(parent.span.line));
            parent.children.push(node);
        }
        None => roots.push(node),
    }
}

/// Analyse une ligne `banner <type> <délim>...` à partir de `lines[start]`
/// et saute le bloc littéral jusqu'au délimiteur de fermeture.
///
/// Renvoie le nœud (feuille `banner`, args = [type], span couvrant tout le
/// bloc) et l'indice de la première ligne APRÈS le bloc.
fn parse_banner(
    lines: &[&str],
    start: usize,
    filename: &str,
) -> Result<(ConfigNode, usize), ParseError> {
    let line = start as u32 + 1;
    let trimmed = lines[start].trim();

    // Après « banner » : le type (motd, login, exec...), puis le délimiteur.
    let rest = trimmed["banner".len()..].trim_start();
    let btype: String = rest.chars().take_while(|c| !c.is_whitespace()).collect();
    let after_type = rest[btype.len()..].trim_start();

    let mut node = ConfigNode::new(
        "banner".to_owned(),
        if btype.is_empty() {
            vec![]
        } else {
            vec![btype]
        },
        filename,
        line,
    );

    // Délimiteur : soit la notation `^C` (deux caractères), soit le
    // premier caractère (ex. `#`). En son absence, feuille simple.
    let delim: String = if after_type.starts_with('^') && after_type.len() >= 2 {
        after_type.chars().take(2).collect()
    } else {
        match after_type.chars().next() {
            Some(c) => c.to_string(),
            None => return Ok((node, start + 1)),
        }
    };

    // Le texte peut se refermer sur la même ligne (bannière d'une ligne).
    let after_delim = &after_type[delim.len()..];
    if after_delim.contains(delim.as_str()) {
        return Ok((node, start + 1));
    }

    // Sinon, sauter les lignes jusqu'à celle qui contient le délimiteur.
    for (offset, candidate) in lines.iter().enumerate().skip(start + 1) {
        if candidate.contains(delim.as_str()) {
            node.span.end_line = Some(offset as u32 + 1);
            return Ok((node, offset + 1));
        }
    }

    Err(ParseError::UnterminatedBanner {
        file: filename.to_owned(),
        line,
        delim,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tree::tests_support::span;

    /// Extrait réaliste : hostname, bannière multi-lignes, interfaces
    /// indentées, ACL étendue.
    const EXTRAIT: &str = "\
version 15.2
!
hostname sw-01
!
banner motd ^C
  Acces reserve a l'administration.
  Toute connexion est journalisee.
^C
!
interface GigabitEthernet0/1
 description liaison vers fw-01
 ip address 10.0.20.1 255.255.255.0
 no shutdown
!
interface GigabitEthernet0/2
 switchport mode access
 switchport access vlan 20
!
ip access-list extended ACL-COMPTA
 permit tcp 10.0.10.0 0.0.0.255 host 10.0.20.5 eq 445
 deny ip any any log
!
end
";

    #[test]
    fn structure_de_l_extrait_realiste() {
        let tree = parse(EXTRAIT, "sw-01.conf").expect("extrait valide");

        // Racines : version, hostname, banner, 2 interfaces, ip, end.
        let keywords: Vec<&str> = tree.roots.iter().map(|n| n.keyword.as_str()).collect();
        assert_eq!(
            keywords,
            [
                "version",
                "hostname",
                "banner",
                "interface",
                "interface",
                "ip",
                "end"
            ]
        );

        assert_eq!(tree.child("hostname").and_then(|n| n.arg(0)), Some("sw-01"));

        // interface GigabitEthernet0/1 : trois enfants indentés.
        let gi1 = tree.child("interface").expect("Gi0/1");
        assert_eq!(gi1.arg(0), Some("GigabitEthernet0/1"));
        assert_eq!(gi1.children.len(), 3);
        assert_eq!(
            gi1.child("description").map(|n| n.args_joined()),
            Some("liaison vers fw-01".to_owned())
        );
        assert_eq!(
            gi1.child("no").map(|n| n.args_joined()),
            Some("shutdown".to_owned())
        );

        // Deux interfaces distinctes au même niveau.
        assert_eq!(tree.children_named("interface").count(), 2);

        // L'ACL et ses deux entrées.
        let acl = tree.child("ip").expect("ip access-list");
        assert_eq!(acl.args_joined(), "access-list extended ACL-COMPTA");
        assert_eq!(acl.children.len(), 2);
        assert_eq!(acl.children[0].keyword, "permit");
        assert_eq!(acl.children[1].keyword, "deny");
        assert_eq!(acl.children[0].arg(5), Some("eq"));
    }

    #[test]
    fn spans_exacts() {
        let tree = parse(EXTRAIT, "sw-01.conf").expect("extrait valide");

        assert_eq!(
            tree.child("version").map(|n| n.span.clone()),
            Some(span("sw-01.conf", 1, None))
        );

        // La bannière couvre les lignes 5 à 8 (délimiteur de fermeture).
        let banner = tree.child("banner").expect("banner");
        assert_eq!(banner.arg(0), Some("motd"));
        assert!(banner.children.is_empty());
        assert_eq!(banner.span, span("sw-01.conf", 5, Some(8)));

        // Gi0/1 : ligne 10, dernier enfant ligne 13.
        let gi1 = tree.child("interface").expect("Gi0/1");
        assert_eq!(gi1.span, span("sw-01.conf", 10, Some(13)));
        assert_eq!(gi1.children[1].span, span("sw-01.conf", 12, None));

        // ACL : ligne 19, dernière entrée ligne 21.
        let acl = tree.child("ip").expect("acl");
        assert_eq!(acl.span, span("sw-01.conf", 19, Some(21)));
    }

    #[test]
    fn instantane_de_l_arbre() {
        let tree = parse(EXTRAIT, "sw-01.conf").expect("extrait valide");
        insta::assert_debug_snapshot!(tree);
    }

    #[test]
    fn indentation_irreguliere_geree_par_la_pile() {
        // Le retour de 3 à 2 colonnes doit rattacher `standby` à
        // l'interface, pas à `ip address`.
        let input = "\
interface GigabitEthernet0/3
   ip address 10.0.30.1 255.255.255.0
  standby 1 ip 10.0.30.254
interface GigabitEthernet0/4
";
        let tree = parse(input, "t.conf").expect("valide");
        assert_eq!(tree.roots.len(), 2);
        let gi3 = &tree.roots[0];
        assert_eq!(gi3.children.len(), 2);
        assert_eq!(gi3.children[0].keyword, "ip");
        assert_eq!(gi3.children[1].keyword, "standby");
        assert!(gi3.children[0].children.is_empty());
    }

    #[test]
    fn imbrication_profonde() {
        // Trois niveaux : politique QoS avec classes imbriquées.
        let input = "\
policy-map PM-WAN
 class VOIX
  priority percent 30
 class class-default
  fair-queue
";
        let tree = parse(input, "t.conf").expect("valide");
        let pm = &tree.roots[0];
        assert_eq!(pm.children_named("class").count(), 2);
        let voix = pm.child("class").expect("class VOIX");
        assert_eq!(
            voix.child("priority").map(|n| n.args_joined()),
            Some("percent 30".to_owned())
        );
        assert_eq!(pm.span, span("t.conf", 1, Some(5)));
    }

    #[test]
    fn banniere_sur_une_seule_ligne() {
        let input = "banner login #Acces restreint#\nhostname r1\n";
        let tree = parse(input, "t.conf").expect("valide");
        assert_eq!(tree.roots[0].keyword, "banner");
        assert_eq!(tree.roots[0].arg(0), Some("login"));
        assert_eq!(tree.roots[0].span, span("t.conf", 1, None));
        assert_eq!(tree.roots[1].keyword, "hostname");
    }

    #[test]
    fn banniere_jamais_refermee() {
        let input = "hostname r1\nbanner motd ^C\n  texte sans fin\n";
        let err = parse(input, "t.conf").expect_err("bannière ouverte");
        assert_eq!(
            err,
            ParseError::UnterminatedBanner {
                file: "t.conf".to_owned(),
                line: 2,
                delim: "^C".to_owned(),
            }
        );
        assert_eq!(err.line(), 2);
    }

    #[test]
    fn guillemet_isole_tolere() {
        // Un guillemet isolé dans une description ne doit pas faire
        // échouer l'analyse (mode tolérant).
        let input = "interface Gi0/1\n description lien \"principal\n";
        let tree = parse(input, "t.conf").expect("tolérant");
        let desc = tree.roots[0].child("description").expect("description");
        assert_eq!(desc.args_joined(), "lien principal");
    }

    #[test]
    fn entree_vide_ou_commentaires_seuls() {
        assert!(parse("", "t.conf").expect("vide").roots.is_empty());
        assert!(parse("!\n! rien\n!\n", "t.conf")
            .expect("séparateurs")
            .roots
            .is_empty());
    }
}
