//! Erreurs structurées de la couche 1. Chaque variante porte le fichier
//! et la ligne fautive : un diagnostic sans origine ne vaut rien (§3.3).

use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ParseError {
    /// Un `end` rencontré alors qu'aucun bloc `config` n'est ouvert.
    #[error("{file}, ligne {line} : « end » sans bloc « config » ouvert")]
    OrphanEnd { file: String, line: u32 },

    /// Un `next` rencontré alors qu'aucun bloc `edit` n'est ouvert.
    #[error("{file}, ligne {line} : « next » sans bloc « edit » ouvert")]
    OrphanNext { file: String, line: u32 },

    /// Un bloc ouvert (`config` ou `edit`) jamais fermé en fin de fichier.
    /// `line` est la ligne d'OUVERTURE du bloc fautif.
    #[error("{file} : bloc « {header} » ouvert ligne {line} et jamais fermé")]
    UnclosedBlock {
        file: String,
        /// En-tête du bloc tel qu'écrit (ex. « edit "port1" »).
        header: String,
        line: u32,
    },

    /// Guillemet double ouvert et jamais refermé sur la ligne.
    #[error("{file}, ligne {line} : guillemet ouvert et jamais refermé")]
    UnterminatedQuote { file: String, line: u32 },

    /// Bannière Cisco (`banner ... ^C`) dont le délimiteur de fermeture
    /// n'apparaît jamais avant la fin du fichier.
    #[error("{file}, ligne {line} : bannière ouverte (délimiteur « {delim} ») et jamais refermée")]
    UnterminatedBanner {
        file: String,
        line: u32,
        delim: String,
    },
}

impl ParseError {
    /// Fichier concerné.
    pub fn file(&self) -> &str {
        match self {
            ParseError::OrphanEnd { file, .. }
            | ParseError::OrphanNext { file, .. }
            | ParseError::UnclosedBlock { file, .. }
            | ParseError::UnterminatedQuote { file, .. }
            | ParseError::UnterminatedBanner { file, .. } => file,
        }
    }

    /// Ligne fautive (ligne d'ouverture pour un bloc non fermé).
    pub fn line(&self) -> u32 {
        match self {
            ParseError::OrphanEnd { line, .. }
            | ParseError::OrphanNext { line, .. }
            | ParseError::UnclosedBlock { line, .. }
            | ParseError::UnterminatedQuote { line, .. }
            | ParseError::UnterminatedBanner { line, .. } => *line,
        }
    }
}
