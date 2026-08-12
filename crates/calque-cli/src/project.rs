//! Le « projet » `.calque/` — persistance du modèle entre deux commandes.
//!
//! Choix documenté : `calque import` sérialise le `Network` et sa
//! `Fidelity` en JSON dans `.calque/model.json`, dans le répertoire
//! courant. Les autres commandes (`model check`, `path`, `test`…) le
//! relisent. Un seul fichier JSON : simple, lisible, versionnable, et
//! largement suffisant pour des modèles de quelques dizaines
//! d'équipements. Si un jour la taille pose problème, on découpera par
//! équipement — le format est interne et non contractuel.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use calque_model::{DeviceId, Fidelity, Network};
use miette::{miette, Context, IntoDiagnostic};
use serde::{Deserialize, Serialize};

pub const PROJECT_DIR: &str = ".calque";
pub const MODEL_FILE: &str = "model.json";

/// Ce que `.calque/model.json` contient.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Project {
    /// Le modèle du réseau (équipements + topologie).
    pub network: Network,
    /// La fidélité globale du modèle (§6.3) : fusion des fidélités par
    /// équipement. Ce que les analyseurs n'ont pas compris est listé ici,
    /// jamais deviné.
    pub fidelity: Fidelity,
    /// Les fichiers importés, pour information.
    pub imported_files: Vec<String>,
    /// Le fichier d'origine de chaque équipement — c'est ce qui permet à
    /// `calque path` de savoir si une directive non comprise touche un
    /// équipement traversé (§6.3).
    #[serde(default)]
    pub device_files: BTreeMap<DeviceId, String>,
    /// La fidélité de chaque équipement, pour que réimporter un fichier
    /// REMPLACE ses diagnostics au lieu de les accumuler.
    #[serde(default)]
    pub device_fidelity: BTreeMap<DeviceId, Fidelity>,
}

impl Default for Project {
    fn default() -> Self {
        Self {
            network: Network::default(),
            fidelity: Fidelity::Complete,
            imported_files: Vec::new(),
            device_files: BTreeMap::new(),
            device_fidelity: BTreeMap::new(),
        }
    }
}

impl Project {
    /// Recalcule la fidélité globale à partir des fidélités par équipement.
    pub fn recompute_fidelity(&mut self) {
        self.fidelity = self
            .device_fidelity
            .values()
            .cloned()
            .fold(Fidelity::Complete, Fidelity::merge);
    }

    /// La fidélité d'un équipement donné (Complete si inconnue : les
    /// projets écrits par une version antérieure n'ont pas ce détail,
    /// mais leur fidélité globale reste vérifiée par ailleurs).
    pub fn fidelity_of(&self, device: &DeviceId) -> &Fidelity {
        self.device_fidelity
            .get(device)
            .unwrap_or(&Fidelity::Complete)
    }
}

fn model_path(root: &Path) -> PathBuf {
    root.join(PROJECT_DIR).join(MODEL_FILE)
}

/// Charge le projet depuis `<root>/.calque/model.json`.
pub fn load(root: &Path) -> miette::Result<Project> {
    let path = model_path(root);
    if !path.exists() {
        return Err(miette!(
            help = "lancez d'abord `calque import <fichier>` ou `calque import --dir <répertoire>`",
            "aucun projet trouvé : {} n'existe pas",
            path.display()
        ));
    }
    let raw = std::fs::read_to_string(&path)
        .into_diagnostic()
        .wrap_err_with(|| format!("lecture de {} impossible", path.display()))?;
    serde_json::from_str(&raw)
        .into_diagnostic()
        .wrap_err_with(|| {
            format!(
                "{} est illisible (format interne changé ? supprimez le répertoire {} et réimportez)",
                path.display(),
                PROJECT_DIR
            )
        })
}

/// Charge le projet s'il existe, sinon rend un projet vide (utilisé par
/// `calque import`, qui a le droit de partir de zéro).
pub fn load_or_default(root: &Path) -> miette::Result<Project> {
    if model_path(root).exists() {
        load(root)
    } else {
        Ok(Project::default())
    }
}

/// Écrit le projet dans `<root>/.calque/model.json`.
pub fn save(root: &Path, project: &Project) -> miette::Result<()> {
    let dir = root.join(PROJECT_DIR);
    std::fs::create_dir_all(&dir)
        .into_diagnostic()
        .wrap_err_with(|| format!("création de {} impossible", dir.display()))?;
    let path = model_path(root);
    let raw = serde_json::to_string_pretty(project)
        .into_diagnostic()
        .wrap_err("sérialisation du modèle impossible")?;
    std::fs::write(&path, raw)
        .into_diagnostic()
        .wrap_err_with(|| format!("écriture de {} impossible", path.display()))
}
