//! L'arbre de configuration générique (§6.1) — commun à tous les formats.
//!
//! Aucune sémantique constructeur : un nœud est un mot-clé, des arguments,
//! des enfants, et l'endroit exact d'où il vient dans le fichier source.

use calque_model::SourceSpan;
use serde::{Deserialize, Serialize};

/// Un nœud de l'arbre générique.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfigNode {
    /// Premier mot de la ligne (ex. `config`, `edit`, `set`, `interface`).
    pub keyword: String,
    /// Les mots suivants, guillemets déjà résolus (`"port1 lan"` = un seul argument).
    pub args: Vec<String>,
    /// Sous-nœuds (contenu du bloc, ou lignes plus indentées).
    pub children: Vec<ConfigNode>,
    /// Fichier + lignes d'origine. `end_line` couvre le bloc entier.
    pub span: SourceSpan,
}

impl ConfigNode {
    /// Construit une feuille (aucun enfant) située à `line`.
    pub(crate) fn new(keyword: String, args: Vec<String>, file: &str, line: u32) -> Self {
        Self {
            keyword,
            args,
            children: Vec::new(),
            span: SourceSpan::new(file, line),
        }
    }

    /// Tous les enfants directs dont le mot-clé est `keyword`.
    pub fn children_named<'a>(
        &'a self,
        keyword: &'a str,
    ) -> impl Iterator<Item = &'a ConfigNode> + 'a {
        self.children.iter().filter(move |c| c.keyword == keyword)
    }

    /// Le premier enfant direct dont le mot-clé est `keyword`.
    pub fn child(&self, keyword: &str) -> Option<&ConfigNode> {
        self.children.iter().find(|c| c.keyword == keyword)
    }

    /// Le `index`-ième argument, s'il existe.
    pub fn arg(&self, index: usize) -> Option<&str> {
        self.args.get(index).map(String::as_str)
    }

    /// Tous les arguments joints par une espace (utile pour les chemins
    /// FortiGate : `config system interface` → `system interface`).
    pub fn args_joined(&self) -> String {
        self.args.join(" ")
    }
}

/// La racine d'un fichier analysé : une forêt de nœuds de premier niveau.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfigTree {
    pub roots: Vec<ConfigNode>,
    /// Nom du fichier d'origine, tel que fourni à `parse`.
    pub file: String,
}

impl ConfigTree {
    /// Tous les nœuds racines dont le mot-clé est `keyword`.
    pub fn children_named<'a>(
        &'a self,
        keyword: &'a str,
    ) -> impl Iterator<Item = &'a ConfigNode> + 'a {
        self.roots.iter().filter(move |c| c.keyword == keyword)
    }

    /// Le premier nœud racine dont le mot-clé est `keyword`.
    pub fn child(&self, keyword: &str) -> Option<&ConfigNode> {
        self.roots.iter().find(|c| c.keyword == keyword)
    }
}

/// Petits utilitaires partagés entre les modules de test du crate.
#[cfg(test)]
pub(crate) mod tests_support {
    use calque_model::SourceSpan;

    pub(crate) fn span(file: &str, line: u32, end_line: Option<u32>) -> SourceSpan {
        SourceSpan {
            file: file.to_owned(),
            line,
            end_line,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn noeud(keyword: &str, args: &[&str]) -> ConfigNode {
        ConfigNode::new(
            keyword.to_owned(),
            args.iter().map(|s| s.to_string()).collect(),
            "test.conf",
            1,
        )
    }

    #[test]
    fn navigation_de_base() {
        let mut parent = noeud("config", &["system", "interface"]);
        parent.children.push(noeud("edit", &["port1"]));
        parent.children.push(noeud("edit", &["port2"]));
        parent.children.push(noeud("set", &["vdom", "root"]));

        assert_eq!(parent.children_named("edit").count(), 2);
        assert_eq!(parent.child("set").and_then(|n| n.arg(0)), Some("vdom"));
        assert_eq!(parent.child("absent"), None);
        assert_eq!(parent.arg(1), Some("interface"));
        assert_eq!(parent.arg(9), None);
        assert_eq!(parent.args_joined(), "system interface");
    }
}
