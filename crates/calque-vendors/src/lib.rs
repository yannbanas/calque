//! calque-vendors — COUCHE 2 : la sémantique constructeur (§6.2 de
//! CALQUE-ARCHITECTURE.md).
//!
//! Ce crate est PUR (§1) : il prend du texte ou un arbre de configuration
//! générique (produit par `calque-parse`, couche 1) en entrée et rend la
//! représentation intermédiaire (`calque-model`) en sortie. Aucune
//! entrée-sortie, aucune horloge, aucun `panic!` sur une entrée externe.
//!
//! ## Le principe qui protège le projet (§6.3)
//!
//! > Ne jamais deviner. En cas de directive non comprise, produire un
//! > diagnostic et marquer le résultat comme incomplet.
//!
//! Chaque adaptateur accumule un `Diagnostic` (avec `SourceSpan`) pour
//! TOUTE directive ou bloc non reconnu, et rend `Fidelity::Partial` dès
//! qu'il y en a un. Rien n'est ignoré en silence.
//!
//! ## Écarts documentés vis-à-vis du md (§6.2)
//!
//! Le md donne :
//!
//! ```text
//! fn to_ir(&self, tree: &ConfigNode) -> Result<Device, Vec<Diagnostic>>;
//! ```
//!
//! Deux écarts délibérés :
//!
//! 1. **L'entrée est un [`ConfigTree`]**, pas un `ConfigNode` : la
//!    couche 1 réelle (`calque-parse`) rend une forêt de nœuds de premier
//!    niveau accompagnée du nom de fichier, ce qui évite un nœud racine
//!    synthétique artificiel. Chaque nœud reste exactement le
//!    `ConfigNode { keyword, args, children, span }` de §6.1.
//!
//! 2. **La sortie est un [`AdapterOutput`]**, pas un simple `Device` :
//!    §6.3 exige que la fidélité du modèle sorte AUSSI de l'analyse.
//!    - `device`   : l'équipement modélisé ;
//!    - `fidelity` : `Complete`, ou `Partial` listant tout ce qui n'a
//!      pas été compris ;
//!    - `notes`    : diagnostics informatifs qui ne dégradent PAS la
//!      fidélité (ex. « politique 4 désactivée, ignorée ») — ils
//!      relèvent du constat, pas de l'incompréhension.
//!
//! `Err(Vec<Diagnostic>)` reste réservé aux échecs totaux (arbre vide ou
//! inexploitable) : dans ce cas aucun modèle n'est rendu du tout.

pub mod fortigate;

use calque_model::{Device, Diagnostic, Fidelity, Vendor};
// L'arbre générique de la couche 1 (§6.1), re-exporté pour les
// consommateurs de ce crate.
pub use calque_parse::{ConfigNode, ConfigTree};

// ---------------------------------------------------------------------------
// Confiance de détection
// ---------------------------------------------------------------------------

/// Score de confiance 0..=100 rendu par [`VendorAdapter::detect`].
///
/// 0 signifie « ce n'est certainement pas ce constructeur », 100 « c'en
/// est certainement un ». La détection automatique (`calque import --dir`)
/// choisit l'adaptateur au score le plus élevé, à condition qu'il soit
/// [`Confidence::is_confident`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Confidence(u8);

impl Confidence {
    pub const NONE: Confidence = Confidence(0);
    pub const CERTAIN: Confidence = Confidence(100);

    /// Construit un score, plafonné à 100.
    pub fn new(score: u8) -> Self {
        Self(score.min(100))
    }

    pub fn score(self) -> u8 {
        self.0
    }

    /// Seuil au-delà duquel la détection automatique accepte l'adaptateur.
    pub fn is_confident(self) -> bool {
        self.0 >= 60
    }
}

// ---------------------------------------------------------------------------
// Sortie d'un adaptateur
// ---------------------------------------------------------------------------

/// Ce que rend un adaptateur : le modèle ET sa fidélité (§6.3),
/// plus des notes informatives. Voir l'écart documenté en tête de crate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdapterOutput {
    pub device: Device,
    /// `Complete` si TOUTE la configuration a été comprise, sinon
    /// `Partial` avec la liste exhaustive de ce qui ne l'a pas été.
    pub fidelity: Fidelity,
    /// Diagnostics informatifs (severité `Info`/`Warning`) qui ne
    /// remettent pas en cause la fidélité du modèle : éléments compris
    /// mais volontairement écartés (règle désactivée, route désactivée…).
    pub notes: Vec<Diagnostic>,
}

// ---------------------------------------------------------------------------
// Le trait des adaptateurs (§6.2)
// ---------------------------------------------------------------------------

/// Un adaptateur constructeur : couche 2, du sens, pas de la syntaxe.
///
/// C'est ici que vit la connaissance du constructeur : où sont accrochés
/// les filtres, comment se nomment les zones, quel est le comportement
/// par défaut.
pub trait VendorAdapter {
    fn vendor(&self) -> Vendor;

    /// Reconnaissance automatique du constructeur à partir du texte brut.
    fn detect(&self, raw: &str) -> Confidence;

    /// Convertit l'arbre générique (couche 1, §6.1) en représentation
    /// intermédiaire, avec sa fidélité (§6.3).
    fn to_ir(&self, tree: &ConfigTree) -> Result<AdapterOutput, Vec<Diagnostic>>;
}

/// Tous les adaptateurs connus, dans l'ordre de la feuille de route (§6.4).
/// Sert à la détection automatique.
pub fn all_adapters() -> Vec<Box<dyn VendorAdapter>> {
    vec![Box::new(fortigate::FortigateAdapter)]
}
