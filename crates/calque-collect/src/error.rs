//! Les erreurs de la collecte. `thiserror` ici ; la conversion en
//! diagnostics `miette` vit dans `calque-cli`.
//!
//! Règle : AUCUN secret dans un message d'erreur — jamais de mot de
//! passe, jamais de contenu de clé privée. Les messages portent l'hôte,
//! la commande, l'empreinte de clé publique : rien de sensible.

use std::fmt;

/// Erreur de collecte (transport ou vérification de profil).
#[derive(Debug, thiserror::Error)]
pub enum CollectError {
    /// Une commande d'un profil contient un jeton interdit : violation du
    /// principe n° 1 (lecture seule, toujours).
    #[error(
        "commande refusée (lecture seule, §13) : « {command} » contient le jeton interdit « {token} »"
    )]
    ForbiddenCommand { command: String, token: String },

    /// Une commande hors de la liste blanche du profil a été demandée au
    /// transport (défense en profondeur).
    #[error("commande hors liste blanche du profil {profile} : « {command} »")]
    NotWhitelisted { profile: String, command: String },

    /// Connexion TCP/SSH impossible.
    #[error("connexion à {host} impossible : {source}")]
    Connect {
        host: String,
        #[source]
        source: std::io::Error,
    },

    /// Erreur de la pile SSH.
    #[error("erreur SSH avec {host} : {detail}")]
    Ssh { host: String, detail: String },

    /// Authentification refusée par l'équipement.
    #[error(
        "authentification refusée par {host} pour l'utilisateur « {user} » (méthode : {method})"
    )]
    AuthFailed {
        host: String,
        user: String,
        method: &'static str,
    },

    /// Clé privée illisible.
    #[error("clé privée illisible ({path}) : {detail}")]
    KeyFile { path: String, detail: String },

    /// Clé d'hôte inconnue et `--accept-new` absent : REFUS par défaut.
    #[error(
        "clé d'hôte inconnue pour {host} : {fingerprint}\n\
         Par défaut, Calque REFUSE une clé jamais vue (protection contre \
         l'interception). Vérifiez l'empreinte auprès de l'équipement, puis \
         relancez avec --accept-new pour l'enregistrer — option risquée si \
         l'empreinte n'a pas été vérifiée."
    )]
    HostKeyUnknown { host: String, fingerprint: String },

    /// Clé d'hôte DIFFÉRENTE de celle enregistrée : refus, TOUJOURS
    /// (même avec `--accept-new`) — c'est la signature d'une interception
    /// possible ou d'un remplacement d'équipement.
    #[error(
        "la clé d'hôte de {host} a CHANGÉ : enregistrée {known}, reçue {received}.\n\
         Refus systématique (interception possible). Si l'équipement a \
         réellement changé de clé, supprimez sa ligne de {known_hosts} et \
         recommencez."
    )]
    HostKeyMismatch {
        host: String,
        known: String,
        received: String,
        known_hosts: String,
    },

    /// Délai dépassé.
    #[error("délai dépassé ({context})")]
    Timeout { context: String },

    /// Le constructeur n'a pas pu être détecté à partir des sondes.
    #[error(
        "constructeur non détecté sur {host} : ni « get system status » ni \
         « show version » n'ont rendu une signature reconnue (FortiGate, Cisco IOS). \
         Précisez --vendor fortigate|cisco_ios si vous savez ce que c'est — \
         Calque ne devine jamais (§6.3)."
    )]
    VendorNotDetected { host: String },

    /// Aucun profil de collecte pour ce constructeur.
    #[error("aucun profil de collecte pour le constructeur {vendor}")]
    NoProfile { vendor: String },

    /// Entrée-sortie locale (fichier known_hosts…).
    #[error("{context} : {source}")]
    Io {
        context: String,
        #[source]
        source: std::io::Error,
    },
}

/// Le transport doit pouvoir convertir les erreurs russh (exigé par le
/// trait `Handler`). Le détail est stringifié : l'appelant n'a pas besoin
/// de dépendre de russh pour lire l'erreur.
#[cfg(feature = "ssh")]
impl From<russh::Error> for CollectError {
    fn from(e: russh::Error) -> Self {
        CollectError::Ssh {
            host: String::new(),
            detail: e.to_string(),
        }
    }
}

/// Affichage d'une empreinte de clé d'hôte (type + empreinte SHA-256),
/// sans dépendre de russh dans la signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostKeyDisplay {
    pub algorithm: String,
    pub sha256: String,
}

impl fmt::Display for HostKeyDisplay {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.algorithm, self.sha256)
    }
}
