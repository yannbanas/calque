//! Analyseur de l'export YAML FortiOS (couche 1, §6.1).
//!
//! Certains outils d'export FortiGate 7.x produisent la configuration au
//! format YAML plutôt qu'au format CLI `config`/`edit`/`set` :
//!
//! ```yaml
//! #config-version=FGT90G-7.4.12-FW-build2902-260505:opmode=0:vdom=0:user=admin
//! system_global:                 # → config system global
//!     hostname: "fw-exemple"     # → set hostname "fw-exemple"
//! system_interface:              # → config system interface
//!     - wan1:                    # → edit "wan1"
//!         ip: [192.0.2.1, 255.255.255.248]   # → set ip 192.0.2.1 255.255.255.248
//! ```
//!
//! CONTRAT CLÉ : l'arbre produit a la MÊME FORME que celui de
//! [`crate::fortigate::parse`] sur la configuration CLI équivalente —
//! nœuds `config <chemin…>` / `edit <id>` / `set <clé> <args…>` — si bien
//! que l'adaptateur FortiGate de la couche 2 le consomme tel quel.
//!
//! Règles de traduction :
//! - une clé qui OUVRE un bloc (`system_interface:`, `gui-dashboard:`)
//!   devient `config`, son chemin étant la clé découpée sur `_`
//!   (`system_snmp_sysinfo` → `system snmp sysinfo` ; les TIRETS restent
//!   dans les mots : `firewall_internet-service-name` →
//!   `firewall internet-service-name`) ;
//! - une entrée `- nom:` devient `edit nom` (nom cité ou non, avec
//!   espaces, numérique…) ;
//! - une clé à valeur (`clé: valeur`, `clé: [a, b]`, `clé: "a b"`)
//!   devient `set clé …` ; la valeur `~`/`null` donne un `set clé` nu ;
//! - une section ou une entrée sans corps donne un bloc vide.
//!
//! Analyse À LA MAIN, ligne à ligne (pas de bibliothèque YAML) : les
//! `SourceSpan` portent les numéros de ligne EXACTS du fichier d'origine,
//! et l'entrée est non fiable (§11.3) — profondeur bornée par
//! [`MAX_DEPTH`], zéro panique, toute anomalie devient une [`ParseError`]
//! avec sa ligne. Indentation de référence : 4 espaces, mais toute
//! indentation cohérente est acceptée (les tabulations comptent 4
//! colonnes). Les octets non ASCII (UTF-8 double-encodé compris) passent
//! tels quels.

use crate::error::ParseError;
use crate::tokenize::tokenize;
use crate::tree::{ConfigNode, ConfigTree, MAX_DEPTH};

/// Nature d'un bloc ouvert.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FrameKind {
    /// Ouvert par une clé sans valeur (`system_interface:`).
    Config,
    /// Ouvert par une entrée de liste (`- wan1:`).
    Edit,
}

/// Un bloc en cours de construction sur la pile.
struct Frame {
    kind: FrameKind,
    /// Colonne de la clé (`Config`) ou du tiret (`Edit`).
    indent: usize,
    /// Colonne des entrées `- nom:` déjà vues sous ce bloc (`Config`
    /// uniquement) : les entrées suivantes doivent s'y aligner.
    item_indent: Option<usize>,
    node: ConfigNode,
    /// Dernière ligne de contenu rattachée à ce bloc (pour `end_line`).
    last_line: u32,
}

/// La valeur d'une ligne `clé: …`, une fois analysée.
enum Valeur {
    /// Pas de valeur : la clé ouvre un bloc (ou une section vide).
    Bloc,
    /// Une valeur scalaire ou une liste, aplatie en arguments.
    Args(Vec<String>),
}

/// Analyse un export YAML FortiOS complet. `filename` est le nom rapporté
/// dans tous les `SourceSpan`.
pub fn parse(input: &str, filename: &str) -> Result<ConfigTree, ParseError> {
    let mut roots: Vec<ConfigNode> = Vec::new();
    let mut stack: Vec<Frame> = Vec::new();

    for (index, brute) in input.lines().enumerate() {
        let line = index as u32 + 1;
        let (indent, contenu) = indentation(brute);
        let contenu = contenu.trim_end();
        if contenu.is_empty() || contenu.starts_with('#') {
            continue; // ligne vide ou commentaire (dont l'en-tête #config-version=)
        }

        if let Some(reste) = detacher_tiret(contenu) {
            // --- entrée de liste `- nom:` → edit ---
            let nom = nom_d_entree(reste, filename, line)?;
            depiler_pour_entree(&mut stack, &mut roots, indent, filename, line)?;
            ensure_depth(&stack, filename, line)?;
            if let Some(parent) = stack.last_mut() {
                parent.item_indent.get_or_insert(indent);
            }
            stack.push(Frame {
                kind: FrameKind::Edit,
                indent,
                item_indent: None,
                node: ConfigNode::new("edit".to_owned(), vec![nom], filename, line),
                last_line: line,
            });
            continue;
        }

        // --- ligne `clé:` ou `clé: valeur` ---
        let (cle, valeur) = couper_cle(contenu, filename, line)?;
        depiler_pour_cle(&mut stack, &mut roots, indent);
        match analyser_valeur(valeur, filename, line)? {
            Valeur::Bloc => {
                ensure_depth(&stack, filename, line)?;
                stack.push(Frame {
                    kind: FrameKind::Config,
                    indent,
                    item_indent: None,
                    node: ConfigNode::new(
                        "config".to_owned(),
                        chemin_de_config(&cle),
                        filename,
                        line,
                    ),
                    last_line: line,
                });
            }
            Valeur::Args(valeurs) => {
                let mut args = Vec::with_capacity(1 + valeurs.len());
                args.push(cle);
                args.extend(valeurs);
                attacher(
                    &mut stack,
                    &mut roots,
                    ConfigNode::new("set".to_owned(), args, filename, line),
                    line,
                );
            }
        }
    }

    // Fin de fichier : tous les blocs encore ouverts se ferment sur leur
    // dernière ligne de contenu.
    while !stack.is_empty() {
        fermer_sommet(&mut stack, &mut roots);
    }

    Ok(ConfigTree {
        roots,
        file: filename.to_owned(),
    })
}

// ---------------------------------------------------------------------------
// Pile
// ---------------------------------------------------------------------------

/// Refuse d'empiler au-delà de la limite de sûreté (§11.3).
fn ensure_depth(stack: &[Frame], filename: &str, line: u32) -> Result<(), ParseError> {
    if stack.len() >= MAX_DEPTH {
        return Err(ParseError::TooDeep {
            file: filename.to_owned(),
            line,
            limit: MAX_DEPTH,
        });
    }
    Ok(())
}

/// Ferme le bloc au sommet : `end_line` = dernière ligne de contenu, et
/// le nœud rejoint son parent (ou les racines).
fn fermer_sommet(stack: &mut Vec<Frame>, roots: &mut Vec<ConfigNode>) {
    if let Some(mut frame) = stack.pop() {
        frame.node.span.end_line = Some(frame.last_line);
        match stack.last_mut() {
            Some(parent) => {
                parent.last_line = parent.last_line.max(frame.last_line);
                parent.node.children.push(frame.node);
            }
            None => roots.push(frame.node),
        }
    }
}

/// Rattache une feuille au bloc ouvert le plus proche, ou aux racines.
fn attacher(stack: &mut [Frame], roots: &mut Vec<ConfigNode>, node: ConfigNode, line: u32) {
    match stack.last_mut() {
        Some(parent) => {
            parent.last_line = parent.last_line.max(line);
            parent.node.children.push(node);
        }
        None => roots.push(node),
    }
}

/// Ferme les blocs jusqu'à trouver celui auquel appartient une ligne
/// `clé…` d'indentation `indent` : une clé vit STRICTEMENT plus indentée
/// que l'ouverture de son bloc.
fn depiler_pour_cle(stack: &mut Vec<Frame>, roots: &mut Vec<ConfigNode>, indent: usize) {
    while let Some(frame) = stack.last() {
        if indent > frame.indent {
            break;
        }
        fermer_sommet(stack, roots);
    }
}

/// Ferme les blocs jusqu'à trouver le bloc `config` auquel appartient une
/// entrée `- nom:` d'indentation `indent`. Les entrées d'un même bloc
/// s'alignent sur la colonne de la première.
fn depiler_pour_entree(
    stack: &mut Vec<Frame>,
    roots: &mut Vec<ConfigNode>,
    indent: usize,
    filename: &str,
    line: u32,
) -> Result<(), ParseError> {
    loop {
        let Some(frame) = stack.last() else {
            return Err(inattendue(
                filename,
                line,
                "entrée « - » hors de toute section",
            ));
        };
        match frame.kind {
            FrameKind::Edit => {
                if indent <= frame.indent {
                    fermer_sommet(stack, roots); // entrée sœur ou d'un bloc englobant
                } else {
                    return Err(inattendue(
                        filename,
                        line,
                        "entrée « - » sans clé de bloc dans le corps d'une entrée",
                    ));
                }
            }
            FrameKind::Config => {
                if indent < frame.indent {
                    fermer_sommet(stack, roots);
                    continue;
                }
                match frame.item_indent {
                    // Première entrée du bloc : elle fixe la colonne.
                    None => return Ok(()),
                    Some(colonne) if indent == colonne => return Ok(()),
                    Some(colonne) if indent < colonne => fermer_sommet(stack, roots),
                    Some(_) => {
                        return Err(inattendue(
                            filename,
                            line,
                            "entrée « - » plus indentée que les entrées précédentes du bloc",
                        ))
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Lecture d'une ligne
// ---------------------------------------------------------------------------

/// Colonne du premier caractère non blanc (tabulation = 4 colonnes) et
/// reste de la ligne.
fn indentation(ligne: &str) -> (usize, &str) {
    let mut colonnes = 0usize;
    for (i, c) in ligne.char_indices() {
        match c {
            ' ' => colonnes += 1,
            '\t' => colonnes += 4,
            _ => return (colonnes, &ligne[i..]),
        }
    }
    (colonnes, "")
}

/// `- reste` → `Some(reste)` si la ligne est une entrée de liste,
/// `None` sinon (un `-` collé au premier mot n'est pas une entrée).
fn detacher_tiret(contenu: &str) -> Option<&str> {
    let reste = contenu.strip_prefix('-')?;
    if reste.starts_with(char::is_whitespace) {
        Some(reste.trim_start())
    } else {
        None
    }
}

/// Le nom d'une entrée `- nom:` (cité ou non, espaces autorisés).
fn nom_d_entree(reste: &str, filename: &str, line: u32) -> Result<String, ParseError> {
    let reste = reste.trim_end();
    if let Some(apres_guillemet) = reste.strip_prefix('"') {
        let Some((nom, apres)) = lire_citation(apres_guillemet) else {
            return Err(ParseError::UnterminatedQuote {
                file: filename.to_owned(),
                line,
            });
        };
        if apres.trim_start() != ":" {
            return Err(inattendue(filename, line, "entrée citée sans « : » final"));
        }
        if nom.trim().is_empty() {
            return Err(inattendue(filename, line, "entrée « - » au nom vide"));
        }
        return Ok(nom);
    }
    let Some(nom) = reste.strip_suffix(':') else {
        return Err(inattendue(filename, line, "entrée « - » sans « : » final"));
    };
    let nom = nom.trim();
    if nom.is_empty() {
        return Err(inattendue(filename, line, "entrée « - » au nom vide"));
    }
    Ok(nom.to_owned())
}

/// Découpe `clé: valeur` : la clé (guillemets résolus) et la valeur brute
/// (possiblement vide). Le `:` séparateur doit être suivi d'un blanc ou
/// de la fin de ligne, comme en YAML.
fn couper_cle<'a>(
    contenu: &'a str,
    filename: &str,
    line: u32,
) -> Result<(String, &'a str), ParseError> {
    if let Some(apres_guillemet) = contenu.strip_prefix('"') {
        let Some((cle, apres)) = lire_citation(apres_guillemet) else {
            return Err(ParseError::UnterminatedQuote {
                file: filename.to_owned(),
                line,
            });
        };
        let apres = apres.trim_start();
        let Some(valeur) = apres.strip_prefix(':') else {
            return Err(inattendue(filename, line, "clé citée sans « : »"));
        };
        if !(valeur.is_empty() || valeur.starts_with(char::is_whitespace)) {
            return Err(inattendue(filename, line, "« : » collé à la valeur"));
        }
        return Ok((cle, valeur));
    }
    let b = contenu.as_bytes();
    for (i, &octet) in b.iter().enumerate() {
        if octet == b':' {
            if i + 1 < b.len() && !b[i + 1].is_ascii_whitespace() {
                return Err(inattendue(
                    filename,
                    line,
                    "« : » collé à la valeur (ni « clé: valeur », ni « - nom: »)",
                ));
            }
            if i == 0 {
                return Err(inattendue(filename, line, "clé vide avant « : »"));
            }
            return Ok((contenu[..i].to_owned(), &contenu[i + 1..]));
        }
        if octet.is_ascii_whitespace() {
            return Err(inattendue(
                filename,
                line,
                "ligne sans « clé: » (blanc rencontré avant « : »)",
            ));
        }
    }
    Err(inattendue(filename, line, "ligne sans « : »"))
}

/// Lit une valeur citée après son guillemet ouvrant (échappements `\x`
/// dépliés, mêmes règles que le tokenizer CLI). Renvoie le contenu et le
/// reste de la ligne après le guillemet fermant, ou `None` si la citation
/// n'est jamais refermée.
fn lire_citation(s: &str) -> Option<(String, &str)> {
    let mut valeur = String::new();
    let mut chars = s.char_indices();
    while let Some((i, c)) = chars.next() {
        match c {
            '"' => return Some((valeur, &s[i + 1..])),
            '\\' => match chars.next() {
                Some((_, echappe)) => valeur.push(echappe),
                None => return None,
            },
            autre => valeur.push(autre),
        }
    }
    None
}

/// Analyse la partie valeur d'une ligne `clé: …`.
fn analyser_valeur(brut: &str, filename: &str, line: u32) -> Result<Valeur, ParseError> {
    let v = brut.trim();
    if v.is_empty() || v.starts_with('#') {
        return Ok(Valeur::Bloc); // pas de valeur : la clé ouvre un bloc
    }
    if v == "~" || v == "null" {
        return Ok(Valeur::Args(Vec::new()));
    }
    if let Some(interieur) = v.strip_prefix('[') {
        return liste_flux(interieur, filename, line);
    }
    // Scalaire : mêmes règles que le tokenizer CLI — une valeur citée est
    // UN argument, une valeur nue se découpe sur les blancs.
    match tokenize(v, false) {
        Ok(Some(tokens)) => Ok(Valeur::Args(tokens)),
        Ok(None) => Ok(Valeur::Bloc), // inatteignable (v non vide, non `#`)
        Err(_) => Err(ParseError::UnterminatedQuote {
            file: filename.to_owned(),
            line,
        }),
    }
}

/// Une liste en flux `[a, "b c", 10.0.0.1]` (après le `[` ouvrant),
/// aplatie en arguments dans l'ordre.
fn liste_flux(interieur: &str, filename: &str, line: u32) -> Result<Valeur, ParseError> {
    let b = interieur.as_bytes();
    let mut morceaux: Vec<&str> = Vec::new();
    let mut debut = 0usize;
    let mut i = 0usize;
    let mut fermeture: Option<usize> = None;
    while i < b.len() {
        match b[i] {
            b'"' => {
                // Zone citée : les virgules et crochets n'y comptent pas.
                i += 1;
                loop {
                    if i >= b.len() {
                        return Err(ParseError::UnterminatedQuote {
                            file: filename.to_owned(),
                            line,
                        });
                    }
                    match b[i] {
                        b'\\' if i + 1 < b.len() => i += 2,
                        b'"' => break,
                        _ => i += 1,
                    }
                }
                i += 1; // guillemet fermant
            }
            b',' => {
                morceaux.push(&interieur[debut..i]);
                debut = i + 1;
                i += 1;
            }
            b']' => {
                fermeture = Some(i);
                break;
            }
            _ => i += 1,
        }
    }
    let Some(fin) = fermeture else {
        return Err(inattendue(filename, line, "liste « [ » jamais refermée"));
    };
    morceaux.push(&interieur[debut..fin]);
    let apres = interieur[fin + 1..].trim_start();
    if !apres.is_empty() && !apres.starts_with('#') {
        return Err(inattendue(filename, line, "contenu inattendu après « ] »"));
    }

    let mut args = Vec::new();
    for morceau in morceaux {
        let morceau = morceau.trim();
        if morceau.is_empty() || morceau == "~" || morceau == "null" {
            continue;
        }
        match tokenize(morceau, false) {
            Ok(Some(tokens)) => args.extend(tokens),
            Ok(None) => {}
            // Défensif : les guillemets ont déjà été appariés ci-dessus.
            Err(_) => {
                return Err(ParseError::UnterminatedQuote {
                    file: filename.to_owned(),
                    line,
                })
            }
        }
    }
    Ok(Valeur::Args(args))
}

/// Chemin d'un bloc `config` : la clé découpée sur `_` (les tirets
/// restent dans les mots).
fn chemin_de_config(cle: &str) -> Vec<String> {
    cle.split('_')
        .filter(|m| !m.is_empty())
        .map(str::to_owned)
        .collect()
}

/// Construit une erreur « ligne inattendue » avec sa position.
fn inattendue(filename: &str, line: u32, detail: &str) -> ParseError {
    ParseError::UnexpectedLine {
        file: filename.to_owned(),
        line,
        detail: detail.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fortigate;
    use calque_model::SourceSpan;

    /// Export YAML couvrant les particularités du format : section
    /// scalaire, entrées avec listes et valeurs citées, section vide,
    /// entrée vide, `~`, nom d'edit avec espaces, clés composées par
    /// `_` (tirets préservés), imbrication à plusieurs niveaux, edit
    /// numérique, route par objet adresse, secret `[ENC, …]`.
    const EXPORT: &str = r#"#config-version=FGT90G-7.4.12-FW-build2902-260505:opmode=0:vdom=0:user=admin
#conf_file_ver=733597594196766

system_global:
    hostname: "fw-exemple"
    admin-sport: 44301
    timezone: "Europe/Paris"
system_console:
system_interface:
    - wan1:
        vdom: "root"
        ip: [192.0.2.1, 255.255.255.248]
        allowaccess: [ping, https]
        member: ["a", "b"]
        type: physical
    - port1:
system_snmp_sysinfo:
    status: enable
    location: "Salle Machines"
firewall_internet-service-name:
    - Service Distant:
        type: default
firewall_policy:
    - 52:
        name: "LAN vers WAN"
        srcintf: "lan"
        dstaddr: ["OBJ-A", "OBJ-B"]
        action: accept
        nat: enable
router_static:
    - 1:
        dst: [10.0.0.0, 255.255.0.0]
        gateway: 10.1.1.254
        device: "port2"
    - 2:
        dstaddr: "OBJ-RESEAU"
        blackhole: enable
        distance: 254
system_admin:
    - admin:
        password: [ENC, XXXX]
        accprofile: ~
        gui-dashboard:
            - 11:
                name: "Status"
                widget:
                    - 1:
                        width: 1
    - logo_x:
"#;

    /// La MÊME configuration, écrite au format CLI : l'arbre des deux
    /// doit avoir un contenu identique (spans mis à part).
    const CLI_EQUIVALENT: &str = r#"config system global
    set hostname "fw-exemple"
    set admin-sport 44301
    set timezone "Europe/Paris"
end
config system console
end
config system interface
    edit "wan1"
        set vdom "root"
        set ip 192.0.2.1 255.255.255.248
        set allowaccess ping https
        set member "a" "b"
        set type physical
    next
    edit "port1"
    next
end
config system snmp sysinfo
    set status enable
    set location "Salle Machines"
end
config firewall internet-service-name
    edit "Service Distant"
        set type default
    next
end
config firewall policy
    edit 52
        set name "LAN vers WAN"
        set srcintf "lan"
        set dstaddr "OBJ-A" "OBJ-B"
        set action accept
        set nat enable
    next
end
config router static
    edit 1
        set dst 10.0.0.0 255.255.0.0
        set gateway 10.1.1.254
        set device "port2"
    next
    edit 2
        set dstaddr "OBJ-RESEAU"
        set blackhole enable
        set distance 254
    next
end
config system admin
    edit "admin"
        set password ENC XXXX
        set accprofile
        config gui-dashboard
            edit 11
                set name "Status"
                config widget
                    edit 1
                        set width 1
                    next
                end
            next
        end
    next
    edit "logo_x"
    next
end
"#;

    /// Copie d'un nœud avec tous les spans neutralisés : ne laisse que
    /// le CONTENU (mot-clé, arguments, enfants) pour la comparaison.
    fn sans_spans(n: &ConfigNode) -> ConfigNode {
        ConfigNode {
            keyword: n.keyword.clone(),
            args: n.args.clone(),
            children: n.children.iter().map(sans_spans).collect(),
            span: SourceSpan::new("", 0),
        }
    }

    #[test]
    fn meme_forme_que_l_equivalent_cli() {
        let yaml = parse(EXPORT, "export.yaml").expect("export valide");
        let cli = fortigate::parse(CLI_EQUIVALENT, "equiv.conf").expect("équivalent valide");

        let yaml_nu: Vec<ConfigNode> = yaml.roots.iter().map(sans_spans).collect();
        let cli_nu: Vec<ConfigNode> = cli.roots.iter().map(sans_spans).collect();
        assert_eq!(
            yaml_nu, cli_nu,
            "l'arbre YAML doit avoir le même contenu que l'arbre CLI"
        );
    }

    #[test]
    fn spans_exacts_du_fichier_yaml() {
        let tree = parse(EXPORT, "export.yaml").expect("export valide");

        // `system_global:` ligne 4, dernier `set` ligne 7.
        let global = &tree.roots[0];
        assert_eq!(global.span.file, "export.yaml");
        assert_eq!(global.span.line, 4);
        assert_eq!(global.span.end_line, Some(7));
        // Feuille : `hostname:` ligne 5, sans end_line.
        assert_eq!(global.children[0].span.line, 5);
        assert_eq!(global.children[0].span.end_line, None);

        // Section vide ligne 8 : fermée sur elle-même.
        let console = &tree.roots[1];
        assert_eq!(console.args_joined(), "system console");
        assert_eq!(console.span.line, 8);
        assert_eq!(console.span.end_line, Some(8));

        // `- wan1:` ligne 10, dernier attribut ligne 15.
        let iface = &tree.roots[2];
        let wan1 = iface.child("edit").expect("edit wan1");
        assert_eq!(wan1.span.line, 10);
        assert_eq!(wan1.span.end_line, Some(15));

        // L'imbrication profonde : `widget:` ligne 46, `width:` ligne 48.
        let admin_block = tree
            .children_named("config")
            .find(|n| n.args_joined() == "system admin")
            .expect("config system admin");
        let admin = admin_block.child("edit").expect("edit admin");
        let dashboard = admin.child("config").expect("config gui-dashboard");
        let onze = dashboard.child("edit").expect("edit 11");
        let widget = onze.child("config").expect("config widget");
        assert_eq!(widget.span.line, 46);
        assert_eq!(widget.span.end_line, Some(48));
    }

    #[test]
    fn particularites_du_format() {
        let tree = parse(EXPORT, "export.yaml").expect("export valide");

        // Clé composée : `system_snmp_sysinfo` → chemin à trois mots.
        assert!(tree
            .children_named("config")
            .any(|n| n.args_joined() == "system snmp sysinfo"));
        // Les tirets restent dans les mots.
        assert!(tree
            .children_named("config")
            .any(|n| n.args_joined() == "firewall internet-service-name"));

        // Nom d'edit avec espaces, non cité.
        let isn = tree
            .children_named("config")
            .find(|n| n.args_joined() == "firewall internet-service-name")
            .expect("bloc internet-service-name");
        assert_eq!(
            isn.child("edit").and_then(|n| n.arg(0)),
            Some("Service Distant")
        );

        // Entrée sans corps : edit sans enfant.
        let iface = tree
            .children_named("config")
            .find(|n| n.args_joined() == "system interface")
            .expect("system interface");
        let port1 = iface
            .children_named("edit")
            .find(|n| n.arg(0) == Some("port1"))
            .expect("edit port1");
        assert!(port1.children.is_empty());

        // `~` : un `set` nu (clé sans valeur).
        let admin = tree
            .children_named("config")
            .find(|n| n.args_joined() == "system admin")
            .and_then(|n| n.child("edit"))
            .expect("edit admin");
        let accprofile = admin
            .children_named("set")
            .find(|n| n.arg(0) == Some("accprofile"))
            .expect("set accprofile");
        assert_eq!(accprofile.args.len(), 1);

        // `[ENC, XXXX]` : aplati en arguments, comme le CLI.
        let password = admin
            .children_named("set")
            .find(|n| n.arg(0) == Some("password"))
            .expect("set password");
        assert_eq!(&password.args[..], ["password", "ENC", "XXXX"]);

        // Route par objet adresse : simple `set dstaddr`.
        let statiques = tree
            .children_named("config")
            .find(|n| n.args_joined() == "router static")
            .expect("router static");
        let deux = statiques
            .children_named("edit")
            .find(|n| n.arg(0) == Some("2"))
            .expect("edit 2");
        assert_eq!(
            deux.children_named("set")
                .find(|n| n.arg(0) == Some("dstaddr"))
                .and_then(|n| n.arg(1)),
            Some("OBJ-RESEAU")
        );
    }

    #[test]
    fn octets_double_encodes_passent_tels_quels() {
        // `é` double-encodé (Ã©) : préservé à l'octet près.
        let entree = "system_global:\n    hostname: \"unitÃ© centrale\"\n";
        let tree = parse(entree, "t.yaml").expect("valide");
        let set = tree.roots[0].child("set").expect("set hostname");
        assert_eq!(set.arg(1), Some("unitÃ© centrale"));
    }

    #[test]
    fn crlf_et_lignes_vides_tolerees() {
        let entree = "system_global:\r\n\r\n    hostname: \"fw\"\r\n\r\n";
        let tree = parse(entree, "t.yaml").expect("valide");
        assert_eq!(tree.roots.len(), 1);
        assert_eq!(tree.roots[0].children.len(), 1);
    }

    #[test]
    fn entree_vide_donne_un_arbre_vide() {
        let tree = parse("", "vide.yaml").expect("vide est valide");
        assert!(tree.roots.is_empty());
        let tree = parse("# rien\n\n", "vide.yaml").expect("commentaires seuls");
        assert!(tree.roots.is_empty());
    }

    #[test]
    fn erreurs_avec_la_bonne_ligne() {
        // Ligne sans `:`.
        let err = parse("system_global:\n    du texte sans cle\n", "t.yaml")
            .expect_err("ligne sans deux-points");
        assert_eq!(err.line(), 2);
        assert!(matches!(err, ParseError::UnexpectedLine { .. }));

        // Entrée sans `:` final.
        let err = parse("system_interface:\n    - wan1\n", "t.yaml").expect_err("entrée sans :");
        assert_eq!(err.line(), 2);

        // Entrée hors de toute section.
        let err = parse("- wan1:\n", "t.yaml").expect_err("entrée orpheline");
        assert_eq!(err.line(), 1);

        // Guillemet jamais refermé (le PEM tient sur UNE ligne : une
        // citation ouverte est une vraie erreur).
        let err = parse("system_global:\n    hostname: \"coupe\n", "t.yaml")
            .expect_err("guillemet non fermé");
        assert_eq!(
            err,
            ParseError::UnterminatedQuote {
                file: "t.yaml".to_owned(),
                line: 2,
            }
        );

        // Liste jamais refermée.
        let err = parse(
            "system_interface:\n    - wan1:\n        ip: [1.2.3.4,\n",
            "t.yaml",
        )
        .expect_err("liste non fermée");
        assert_eq!(err.line(), 3);
    }

    /// §11.3 — l'imbrication hostile est refusée à la limite commune.
    #[test]
    fn imbrication_hostile_refusee_a_la_limite() {
        let mut hostile = String::new();
        for i in 0..=MAX_DEPTH {
            for _ in 0..i {
                hostile.push(' ');
            }
            hostile.push_str("a:\n");
        }
        let err = parse(&hostile, "hostile.yaml").expect_err("trop profond");
        assert_eq!(
            err,
            ParseError::TooDeep {
                file: "hostile.yaml".to_owned(),
                line: MAX_DEPTH as u32 + 1,
                limit: MAX_DEPTH,
            }
        );

        // Juste sous la limite : accepté.
        let mut ok = String::new();
        for i in 0..MAX_DEPTH {
            for _ in 0..i {
                ok.push(' ');
            }
            ok.push_str("a:\n");
        }
        let tree = parse(&ok, "profond.yaml").expect("sous la limite");
        assert_eq!(tree.roots.len(), 1);
    }

    /// Entrées hostiles : `Ok` ou `Err`, jamais de panique.
    #[test]
    fn entrees_hostiles_sans_panique() {
        let cas: Vec<String> = vec![
            String::new(),
            "\u{0}\u{1} binaire \u{fffd}".to_owned(),
            ":".to_owned(),
            ": valeur\n".to_owned(),
            "-\n".to_owned(),
            "- :\n".to_owned(),
            "- \"\":\n".to_owned(),
            "a:\n - b:\n     - c:\n".to_owned(),
            "a: [\"non ferme\n".to_owned(),
            "a: ]\n".to_owned(),
            "\"cle: \n".to_owned(),
            "\"a\"x: v\n".to_owned(),
            "a:b\n".to_owned(),
            "\t\ta:\n\tb: c\n".to_owned(),
            "a: ~\n~: b\n".to_owned(),
            "x: ".to_owned() + &"[".repeat(10_000),
            "a:\n".repeat(50_000),
            " ".repeat(100_000) + "a: b",
        ];
        for entree in &cas {
            let _ = parse(entree, "hostile.yaml");
        }
    }
}
