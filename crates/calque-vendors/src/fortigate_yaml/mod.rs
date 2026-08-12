//! Adaptateur pour l'export YAML FortiOS — couche 2 (§6.2, §6.4).
//!
//! Certains outils d'export FortiGate 7.x produisent la configuration au
//! format YAML (`system_interface:` / `- wan1:` / `ip: [a, m]`) plutôt
//! qu'au format CLI. La couche 1 [`calque_parse::fortigate_yaml`] rend un
//! arbre de MÊME FORME que celui du CLI (`config`/`edit`/`set`) : toute
//! la sémantique est donc RÉUTILISÉE telle quelle en déléguant la
//! conversion à l'adaptateur FortiGate existant — mêmes choix de
//! modélisation, mêmes diagnostics (§6.3 : ne jamais deviner), même
//! discipline sur les directives inconnues.

use calque_model::{Diagnostic, SourceSpan, Vendor};

use crate::fortigate::FortigateAdapter;
use crate::{AdapterOutput, Confidence, ConfigTree, VendorAdapter};

/// L'adaptateur de l'export YAML FortiOS.
#[derive(Debug, Default, Clone, Copy)]
pub struct FortigateYamlAdapter;

impl FortigateYamlAdapter {
    /// Commodité : analyse le texte brut avec l'analyseur YAML de
    /// `calque-parse` (couche 1) puis convertit en IR. `file` est le nom
    /// rapporté dans tous les `SourceSpan`.
    pub fn import_str(&self, raw: &str, file: &str) -> Result<AdapterOutput, Vec<Diagnostic>> {
        let tree = calque_parse::fortigate_yaml::parse(raw, file).map_err(|e| {
            vec![Diagnostic::error(
                e.to_string(),
                Some(SourceSpan::new(e.file(), e.line())),
            )]
        })?;
        self.to_ir(&tree)
    }
}

impl VendorAdapter for FortigateYamlAdapter {
    fn label(&self) -> &'static str {
        "FortiGate (export YAML)"
    }

    fn import_str(&self, raw: &str, file: &str) -> Result<AdapterOutput, Vec<Diagnostic>> {
        FortigateYamlAdapter::import_str(self, raw, file)
    }

    fn vendor(&self) -> Vendor {
        // Le constructeur est le même que pour le format CLI : seul le
        // format de fichier diffère.
        Vendor::Fortigate
    }

    /// Reconnaissance de l'export YAML : l'en-tête `#config-version=`
    /// PLUS la structure YAML (sections `clé:` en colonne 0, entrées
    /// `- nom:`, clés indentées `clé: valeur`) et l'ABSENCE des lignes
    /// `config `/`edit `/`set `/`end` du format CLI. Un export CLI
    /// classique ne matche pas ce détecteur (plafonné à 20), et l'export
    /// YAML ne matche pas l'adaptateur CLI (il n'a ni `edit` ni `end`).
    fn detect(&self, raw: &str) -> Confidence {
        let mut score: u32 = 0;
        if raw.contains("#config-version=") {
            score += 40;
        }
        let mut section = false; // `system_global:` en colonne 0
        let mut entree = false; // `- nom:`
        let mut cle_indentee = false; // `    clé: valeur`
        let mut structure_cli = false; // `config `/`edit `/`set `/`end`
        for ligne in raw.lines() {
            let coupe = ligne.trim_end();
            let contenu = coupe.trim_start();
            let indent = coupe.len() - contenu.len();
            if contenu.is_empty() || contenu.starts_with('#') {
                continue;
            }
            if indent == 0
                && contenu.len() > 1
                && contenu.ends_with(':')
                && !contenu.contains(char::is_whitespace)
                && contenu.starts_with(|c: char| c.is_ascii_alphanumeric())
            {
                section = true;
            }
            if contenu.starts_with("- ") && contenu.ends_with(':') {
                entree = true;
            }
            if indent > 0
                && !contenu.starts_with('-')
                && (contenu.ends_with(':') || contenu.contains(": "))
            {
                cle_indentee = true;
            }
            if contenu == "end"
                || contenu == "next"
                || contenu.starts_with("config ")
                || contenu.starts_with("edit ")
                || contenu.starts_with("set ")
            {
                structure_cli = true;
            }
        }
        if section {
            score += 25;
        }
        if entree {
            score += 15;
        }
        if cle_indentee {
            score += 10;
        }
        if structure_cli {
            // Des lignes CLI : ce n'est pas un export YAML, quels que
            // soient les autres motifs.
            score = score.min(20);
        }
        Confidence::new(score.min(100) as u8)
    }

    /// L'arbre YAML a la même forme que l'arbre CLI (contrat de la
    /// couche 1) : la conversion est celle de l'adaptateur FortiGate.
    fn to_ir(&self, tree: &ConfigTree) -> Result<AdapterOutput, Vec<Diagnostic>> {
        FortigateAdapter.to_ir(tree)
    }
}
