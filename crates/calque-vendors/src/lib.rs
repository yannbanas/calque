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

pub mod cisco_ios;
pub mod fortigate;
pub mod fortigate_yaml;
pub mod nftables;
pub mod opnsense;

use calque_model::{Device, Diagnostic, Fidelity, Vendor};

/// Extrait d'une directive pour un message de diagnostic : le mot-clé et
/// au plus `keep` arguments, le reste étant remplacé par « … ».
///
/// Règle de sûreté (§11.4) : les VALEURS d'une directive non comprise ne
/// vont jamais dans un diagnostic — une directive inconnue peut porter un
/// secret (`crypto isakmp key S3CRET …`, `ip ftp password …`,
/// `ppp chap password …`). Le `SourceSpan` suffit à retrouver la ligne
/// exacte dans le fichier source.
pub(crate) fn directive_excerpt(keyword: &str, args: &[String], keep: usize) -> String {
    let mut out = String::from(keyword);
    for arg in args.iter().take(keep) {
        out.push(' ');
        out.push_str(arg);
    }
    if args.len() > keep {
        out.push_str(" …");
    }
    out
}
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

    /// Libellé humain de l'ADAPTATEUR (pas seulement du constructeur) :
    /// deux adaptateurs peuvent servir le même constructeur sous deux
    /// formats (ex. FortiGate CLI et FortiGate export YAML) — les messages
    /// de détection doivent pouvoir les distinguer.
    fn label(&self) -> &'static str;

    /// Reconnaissance automatique du constructeur à partir du texte brut.
    fn detect(&self, raw: &str) -> Confidence;

    /// Convertit l'arbre générique (couche 1, §6.1) en représentation
    /// intermédiaire, avec sa fidélité (§6.3).
    fn to_ir(&self, tree: &ConfigTree) -> Result<AdapterOutput, Vec<Diagnostic>>;

    /// Chaîne complète : couche 1 propre à l'adaptateur + `to_ir`.
    /// C'est LE point d'entrée de l'import : la sélection d'adaptateur se
    /// fait par valeur de `detect`, jamais par `Vendor` (deux adaptateurs
    /// peuvent partager le même constructeur).
    fn import_str(&self, raw: &str, file: &str) -> Result<AdapterOutput, Vec<Diagnostic>>;
}

/// Tous les adaptateurs connus, dans l'ordre de la feuille de route (§6.4).
/// Sert à la détection automatique.
pub fn all_adapters() -> Vec<Box<dyn VendorAdapter>> {
    vec![
        Box::new(fortigate::FortigateAdapter),
        Box::new(fortigate_yaml::FortigateYamlAdapter),
        Box::new(cisco_ios::CiscoIosAdapter),
        Box::new(opnsense::OpnsenseAdapter),
        Box::new(nftables::NftablesAdapter),
    ]
}

// ---------------------------------------------------------------------------
// Détection + import sur `&str` (l'entrée de bibliothèque, sans I/O)
// ---------------------------------------------------------------------------

/// Le score de détection d'un adaptateur, pour les messages d'erreur :
/// « FortiGate (CLI) : 100/100 ».
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetectionScore {
    /// Libellé humain de l'adaptateur ([`VendorAdapter::label`]).
    pub adapter: &'static str,
    pub vendor: Vendor,
    pub confidence: Confidence,
}

/// Résumé humain d'une liste de scores :
/// « FortiGate (CLI) : 100/100, Cisco IOS : 0/100, … ».
pub fn score_summary(scores: &[DetectionScore]) -> String {
    scores
        .iter()
        .map(|s| format!("{} : {}/100", s.adapter, s.confidence.score()))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Ce que [`detect_and_import`] rend en cas de succès : la sortie de
/// l'adaptateur retenu, plus l'identité de ce dernier (deux adaptateurs
/// peuvent servir le même constructeur — l'appelant doit pouvoir dire
/// lequel a gagné).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetectedImport {
    pub output: AdapterOutput,
    pub vendor: Vendor,
    /// Libellé humain de l'adaptateur retenu ([`VendorAdapter::label`]).
    pub adapter: &'static str,
}

/// Pourquoi [`detect_and_import`] a échoué. Les variantes portent les
/// données structurées (scores, diagnostics) : l'appelant peut soit
/// afficher le `Display` français tel quel, soit reconstruire son propre
/// message avec le contexte qu'il possède (chemin de fichier…).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DetectImportError {
    /// Aucun adaptateur n'atteint le seuil de confiance
    /// ([`Confidence::is_confident`]) : jamais de supposition (§6.3).
    Unrecognized { scores: Vec<DetectionScore> },
    /// Plusieurs adaptateurs à égalité au meilleur score : impossible de
    /// choisir sans deviner (§6.3).
    Ambiguous { scores: Vec<DetectionScore> },
    /// L'adaptateur retenu n'a rendu aucun modèle (échec total :
    /// arbre vide ou inexploitable).
    Import {
        vendor: Vendor,
        /// Libellé humain de l'adaptateur retenu.
        adapter: &'static str,
        diagnostics: Vec<Diagnostic>,
    },
}

impl DetectImportError {
    /// Les scores de détection, quand l'échec vient de la détection.
    pub fn scores(&self) -> Option<&[DetectionScore]> {
        match self {
            DetectImportError::Unrecognized { scores }
            | DetectImportError::Ambiguous { scores } => Some(scores),
            DetectImportError::Import { .. } => None,
        }
    }
}

impl std::fmt::Display for DetectImportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DetectImportError::Unrecognized { scores } => write!(
                f,
                "constructeur non reconnu (scores de détection : {})",
                score_summary(scores)
            ),
            DetectImportError::Ambiguous { scores } => write!(
                f,
                "détection ambiguë (scores de détection : {})",
                score_summary(scores)
            ),
            DetectImportError::Import {
                adapter,
                diagnostics,
                ..
            } => {
                let details = diagnostics
                    .iter()
                    .map(|d| match &d.span {
                        Some(span) => format!("  - {span} : {}", d.message),
                        None => format!("  - {}", d.message),
                    })
                    .collect::<Vec<_>>()
                    .join("\n");
                write!(f, "import impossible ({adapter} détecté) :\n{details}")
            }
        }
    }
}

impl std::error::Error for DetectImportError {}

/// Détecte le constructeur d'une configuration donnée en TEXTE (meilleur
/// score [`VendorAdapter::detect`] parmi [`all_adapters`], au-dessus du
/// seuil de confiance) et la convertit en représentation intermédiaire.
///
/// C'est le point d'entrée de bibliothèque de l'import : aucune
/// entrée-sortie — le texte arrive de l'appelant (la CLI lit le fichier
/// elle-même ; un consommateur comme Constat fournit une configuration
/// historique). `label` est le libellé de source porté par tous les
/// `SourceSpan` du modèle (un chemin de fichier, un identifiant
/// d'archive…) : c'est lui qui rend chaque verdict justifiable.
///
/// Sélection par ADAPTATEUR, jamais par [`Vendor`] : deux adaptateurs
/// peuvent servir le même constructeur sous deux formats (FortiGate CLI
/// et FortiGate export YAML) — c'est le score de `detect` qui départage.
/// Sous le seuil, ou à égalité entre plusieurs adaptateurs : erreur
/// structurée listant les scores — jamais de supposition (§6.3).
pub fn detect_and_import(raw: &str, label: &str) -> Result<DetectedImport, DetectImportError> {
    let adapters = all_adapters();
    let scores: Vec<DetectionScore> = adapters
        .iter()
        .map(|a| DetectionScore {
            adapter: a.label(),
            vendor: a.vendor(),
            confidence: a.detect(raw),
        })
        .collect();
    let best = scores
        .iter()
        .map(|s| s.confidence)
        .max()
        .unwrap_or(Confidence::NONE);
    if !best.is_confident() {
        return Err(DetectImportError::Unrecognized { scores });
    }
    let winners: Vec<usize> = scores
        .iter()
        .enumerate()
        .filter(|(_, s)| s.confidence == best)
        .map(|(i, _)| i)
        .collect();
    if winners.len() > 1 {
        return Err(DetectImportError::Ambiguous { scores });
    }
    let adapter = &adapters[winners[0]];
    let output =
        adapter
            .import_str(raw, label)
            .map_err(|diagnostics| DetectImportError::Import {
                vendor: adapter.vendor(),
                adapter: adapter.label(),
                diagnostics,
            })?;
    Ok(DetectedImport {
        output,
        vendor: adapter.vendor(),
        adapter: adapter.label(),
    })
}
