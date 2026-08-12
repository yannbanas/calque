//! Analyseur du format FortiGate : arbre PAR BLOCS (§6.1).
//!
//! `config <chemin...>` ouvre un bloc fermé par `end`, `edit <id>` ouvre
//! un sous-bloc fermé par `next`, `set`/`unset` sont des feuilles.
//! Les blocs s'imbriquent librement (`config` dans `edit`, etc.).
//!
//! L'en-tête `#config-version=...` des exports réels commence par `#`,
//! donc il est ignoré comme tout commentaire — mais les numéros de ligne
//! d'origine sont préservés dans les spans.

use crate::error::ParseError;
use crate::tokenize::tokenize;
use crate::tree::{ConfigNode, ConfigTree};

/// Nature d'un bloc ouvert : décide quel mot-clé le referme.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FrameKind {
    /// Ouvert par `config`, fermé par `end`.
    Config,
    /// Ouvert par `edit`, fermé par `next`.
    Edit,
}

/// Un bloc en cours de construction sur la pile.
struct Frame {
    kind: FrameKind,
    node: ConfigNode,
}

/// Analyse une configuration FortiGate complète.
///
/// Aucune sémantique : les mots-clés inconnus deviennent des feuilles,
/// c'est la couche 2 qui décidera de leur sort (§6.3 : ne jamais deviner).
pub fn parse(input: &str, filename: &str) -> Result<ConfigTree, ParseError> {
    let mut roots: Vec<ConfigNode> = Vec::new();
    let mut stack: Vec<Frame> = Vec::new();

    for (index, raw) in input.lines().enumerate() {
        let line = index as u32 + 1;
        let mut tokens = match tokenize(raw, false) {
            Ok(Some(t)) if !t.is_empty() => t,
            Ok(_) => continue, // ligne vide ou commentaire
            Err(_) => {
                return Err(ParseError::UnterminatedQuote {
                    file: filename.to_owned(),
                    line,
                })
            }
        };
        let keyword = tokens.remove(0);
        let args = tokens;

        match keyword.as_str() {
            "config" => stack.push(Frame {
                kind: FrameKind::Config,
                node: ConfigNode::new(keyword, args, filename, line),
            }),
            "edit" => stack.push(Frame {
                kind: FrameKind::Edit,
                node: ConfigNode::new(keyword, args, filename, line),
            }),
            "end" => {
                // `end` ferme le bloc `config` le plus proche. Comme sur
                // l'équipement réel, il referme au passage les `edit`
                // restés ouverts à l'intérieur.
                if !stack.iter().any(|f| f.kind == FrameKind::Config) {
                    return Err(ParseError::OrphanEnd {
                        file: filename.to_owned(),
                        line,
                    });
                }
                while let Some(mut frame) = stack.pop() {
                    frame.node.span.end_line = Some(line);
                    let closes_config = frame.kind == FrameKind::Config;
                    attach(&mut stack, &mut roots, frame.node);
                    if closes_config {
                        break;
                    }
                }
            }
            "next" => match stack.last().map(|f| f.kind) {
                Some(FrameKind::Edit) => {
                    if let Some(mut frame) = stack.pop() {
                        frame.node.span.end_line = Some(line);
                        attach(&mut stack, &mut roots, frame.node);
                    }
                }
                // `next` hors de tout `edit` (ou directement sous un
                // `config`) : orphelin.
                _ => {
                    return Err(ParseError::OrphanNext {
                        file: filename.to_owned(),
                        line,
                    })
                }
            },
            // `set`, `unset`, et tout mot-clé inattendu : une feuille.
            _ => attach(
                &mut stack,
                &mut roots,
                ConfigNode::new(keyword, args, filename, line),
            ),
        }
    }

    // Fin de fichier : la pile doit être vide, sinon le bloc le plus
    // profond (le premier resté ouvert en partant de la fin) est fautif.
    if let Some(frame) = stack.last() {
        let header = header_of(&frame.node);
        return Err(ParseError::UnclosedBlock {
            file: filename.to_owned(),
            header,
            line: frame.node.span.line,
        });
    }

    Ok(ConfigTree {
        roots,
        file: filename.to_owned(),
    })
}

/// Rattache `node` au bloc ouvert le plus proche, ou aux racines.
fn attach(stack: &mut [Frame], roots: &mut Vec<ConfigNode>, node: ConfigNode) {
    match stack.last_mut() {
        Some(parent) => parent.node.children.push(node),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tree::tests_support::span;

    /// Extrait réaliste : en-tête `#config-version`, interfaces avec
    /// valeurs entre guillemets, adresses, politiques à plusieurs `edit`,
    /// et un `config` imbriqué dans un `edit`.
    const EXTRAIT: &str = r#"#config-version=FGVM64-7.4.1-FW-build2463-230830:opmode=0:vdom=0
config system interface
    edit "port1"
        set vdom "root"
        set ip 192.168.1.99 255.255.255.0
        set allowaccess ping https ssh
        set alias "port1 lan"
        config ipv6
            set ip6-allowaccess ping
        end
    next
    edit "port2"
        set vdom "root"
        set ip 10.0.20.1 255.255.255.0
    next
end

config firewall address
    edit "SRV-FICHIERS"
        set subnet 10.0.20.5 255.255.255.255
    next
    edit "LAN-COMPTA"
        set subnet 10.0.10.0 255.255.255.0
    next
end

config firewall policy
    edit 1
        set name "compta vers serveur de fichiers"
        set srcintf "port1"
        set dstintf "port2"
        set srcaddr "LAN-COMPTA"
        set dstaddr "SRV-FICHIERS"
        set action accept
        set schedule "always"
        set service "SMB" "HTTPS"
    next
    edit 2
        set srcintf "any"
        set dstintf "any"
        set action deny
        unset status
    next
end
"#;

    #[test]
    fn structure_de_l_extrait_realiste() {
        let tree = parse(EXTRAIT, "fw-01.conf").expect("extrait valide");
        assert_eq!(tree.file, "fw-01.conf");
        assert_eq!(tree.roots.len(), 3);

        // config system interface : deux interfaces.
        let iface = &tree.roots[0];
        assert_eq!(iface.keyword, "config");
        assert_eq!(iface.args_joined(), "system interface");
        assert_eq!(iface.children_named("edit").count(), 2);

        let port1 = iface.child("edit").expect("edit port1");
        assert_eq!(port1.arg(0), Some("port1"));
        // La valeur entre guillemets est UN SEUL argument.
        let alias = port1.child("alias").is_none();
        assert!(alias, "alias est un `set`, pas un mot-clé racine");
        let set_alias = port1
            .children_named("set")
            .find(|n| n.arg(0) == Some("alias"))
            .expect("set alias");
        assert_eq!(set_alias.arg(1), Some("port1 lan"));
        assert_eq!(set_alias.args.len(), 2);

        // Le `config ipv6` est bien imbriqué DANS l'edit port1.
        let ipv6 = port1.child("config").expect("config ipv6 imbriqué");
        assert_eq!(ipv6.args_joined(), "ipv6");
        assert_eq!(
            ipv6.child("set").and_then(|n| n.arg(0)),
            Some("ip6-allowaccess")
        );

        // config firewall policy : deux politiques, service multi-valeurs.
        let policy = tree
            .children_named("config")
            .find(|n| n.args_joined() == "firewall policy")
            .expect("config firewall policy");
        let edits: Vec<_> = policy.children_named("edit").collect();
        assert_eq!(edits.len(), 2);
        assert_eq!(edits[0].arg(0), Some("1"));
        let service = edits[0]
            .children_named("set")
            .find(|n| n.arg(0) == Some("service"))
            .expect("set service");
        assert_eq!(&service.args[1..], ["SMB", "HTTPS"]);
        // `unset` est une feuille comme une autre.
        assert_eq!(
            edits[1].child("unset").and_then(|n| n.arg(0)),
            Some("status")
        );
    }

    #[test]
    fn spans_exacts_lignes_d_origine_preservees() {
        let tree = parse(EXTRAIT, "fw-01.conf").expect("extrait valide");

        // `#config-version` occupe la ligne 1 : le premier bloc commence
        // ligne 2 et se ferme sur le `end` ligne 16.
        let iface = &tree.roots[0];
        assert_eq!(iface.span, span("fw-01.conf", 2, Some(16)));

        // edit "port1" : lignes 3 à 11 (fermé par `next`).
        let port1 = iface.child("edit").expect("port1");
        assert_eq!(port1.span, span("fw-01.conf", 3, Some(11)));

        // Feuille : `set alias` ligne 7, sans end_line.
        let set_alias = port1
            .children_named("set")
            .find(|n| n.arg(0) == Some("alias"))
            .expect("set alias");
        assert_eq!(set_alias.span, span("fw-01.conf", 7, None));

        // Bloc imbriqué : config ipv6, lignes 8 à 10.
        let ipv6 = port1.child("config").expect("ipv6");
        assert_eq!(ipv6.span, span("fw-01.conf", 8, Some(10)));

        // Deuxième bloc racine après une ligne vide : lignes 18 à 25.
        assert_eq!(tree.roots[1].span, span("fw-01.conf", 18, Some(25)));

        // Politique 2 : edit ligne 38, next ligne 43.
        let policy = &tree.roots[2];
        let edit2 = policy
            .children_named("edit")
            .find(|n| n.arg(0) == Some("2"))
            .expect("edit 2");
        assert_eq!(edit2.span.line, 38);
        assert_eq!(edit2.span.end_line, Some(43));
    }

    #[test]
    fn instantane_de_l_arbre() {
        let tree = parse(EXTRAIT, "fw-01.conf").expect("extrait valide");
        insta::assert_debug_snapshot!(tree);
    }

    #[test]
    fn bloc_non_ferme_en_fin_de_fichier() {
        let input = "config system interface\n    edit \"port1\"\n        set vdom \"root\"\n";
        let err = parse(input, "tronque.conf").expect_err("bloc non fermé");
        assert_eq!(
            err,
            ParseError::UnclosedBlock {
                file: "tronque.conf".to_owned(),
                header: "edit port1".to_owned(),
                line: 2,
            }
        );
        assert_eq!(err.line(), 2);
        assert_eq!(err.file(), "tronque.conf");
    }

    #[test]
    fn config_non_ferme_sans_edit() {
        let input = "config firewall address\n";
        let err = parse(input, "t.conf").expect_err("config non fermé");
        assert_eq!(
            err,
            ParseError::UnclosedBlock {
                file: "t.conf".to_owned(),
                header: "config firewall address".to_owned(),
                line: 1,
            }
        );
    }

    #[test]
    fn next_orphelin_avec_la_bonne_ligne() {
        // `next` directement sous un `config`, sans `edit` ouvert.
        let input = "config system interface\nnext\nend\n";
        let err = parse(input, "t.conf").expect_err("next orphelin");
        assert_eq!(
            err,
            ParseError::OrphanNext {
                file: "t.conf".to_owned(),
                line: 2,
            }
        );
    }

    #[test]
    fn end_orphelin_avec_la_bonne_ligne() {
        let input = "# commentaire\nend\n";
        let err = parse(input, "t.conf").expect_err("end orphelin");
        assert_eq!(
            err,
            ParseError::OrphanEnd {
                file: "t.conf".to_owned(),
                line: 2,
            }
        );
    }

    #[test]
    fn end_referme_un_edit_reste_ouvert() {
        // Comportement de l'équipement réel : `end` sauve et referme tout
        // le bloc `config`, y compris l'`edit` en cours.
        let input = "config system interface\n    edit \"port1\"\n        set vdom \"root\"\nend\n";
        let tree = parse(input, "t.conf").expect("end referme l'edit");
        let iface = &tree.roots[0];
        assert_eq!(iface.span.end_line, Some(4));
        let port1 = iface.child("edit").expect("port1");
        assert_eq!(port1.span.end_line, Some(4));
        assert_eq!(port1.children.len(), 1);
    }

    #[test]
    fn guillemet_non_ferme_signale_avec_la_ligne() {
        let input = "config system interface\n    edit \"port1\n";
        let err = parse(input, "t.conf").expect_err("guillemet non fermé");
        assert_eq!(
            err,
            ParseError::UnterminatedQuote {
                file: "t.conf".to_owned(),
                line: 2,
            }
        );
    }

    #[test]
    fn entree_vide_donne_un_arbre_vide() {
        let tree = parse("", "vide.conf").expect("vide est valide");
        assert!(tree.roots.is_empty());
    }
}
