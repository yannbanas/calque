//! Le transport SSH — la SEULE partie de la collecte qui touche le
//! réseau. Volontairement mince : se connecter, s'authentifier, envoyer
//! les commandes du profil (et rien d'autre — liste blanche revérifiée à
//! l'envoi), capturer les sorties. Toute l'interprétation vit dans les
//! modules purs (`parse`, `detect`, `clean`).
//!
//! Pile retenue : `russh` (client SSH asynchrone en Rust pur, §9 du md),
//! backend cryptographique `ring`. `tokio` est confiné ici, dans une
//! runtime mono-thread interne : l'API publique est SYNCHRONE.
//!
//! ## Vérification de la clé d'hôte
//!
//! Par défaut, une clé jamais vue est REFUSÉE — pas de « trust always »
//! silencieux. `accept_new: true` (option `--accept-new` du CLI,
//! documentée comme risquée) enregistre une clé inconnue dans le fichier
//! `known_hosts` du projet. Une clé qui DIFFÈRE de celle enregistrée est
//! refusée dans tous les cas : c'est la signature d'une interception
//! possible, et il faut un geste manuel (supprimer la ligne) pour passer.
//!
//! ## Secrets
//!
//! Le mot de passe ne sort jamais de ce module : pas de `Debug` dessus
//! (implémentation manuelle expurgée), jamais dans une erreur ni un log.
//!
//! ## Exécution des commandes
//!
//! Chaque commande part dans un canal `exec` SSH séparé, SANS
//! pseudo-terminal : FortiOS comme IOS acceptent ce mode (c'est celui de
//! `ssh user@equipement commande`), et l'essentiel de la pagination est un
//! artefact de pseudo-terminal qui disparaît avec lui. Les réglages
//! `terminal …` du profil Cisco sont envoyés quand même (inoffensifs), et
//! [`crate::clean::clean_output`] neutralise les résidus (`--More--`,
//! retours chariot) pour les transcripts capturés autrement.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use calque_model::Vendor;
use russh::client;
use russh::keys::{HashAlg, PrivateKeyWithHashAlg};
use russh::ChannelMsg;

use crate::clean::clean_output;
use crate::detect::{classify_fortigate_status, classify_show_version};
use crate::error::CollectError;
use crate::parse::fortigate::parse_system_status;
use crate::profile::{profile_for, CollectProfile, CISCO_IOS, FORTIGATE};

// ---------------------------------------------------------------------------
// Paramètres
// ---------------------------------------------------------------------------

/// Méthode d'authentification.
pub enum Auth {
    /// Mot de passe (venu d'une variable d'environnement ou d'une saisie
    /// sans écho — JAMAIS d'un argument de ligne de commande).
    Password(String),
    /// Clé privée : chemin du fichier (OpenSSH/PEM), et sa phrase de
    /// passe éventuelle.
    KeyFile {
        path: PathBuf,
        passphrase: Option<String>,
    },
}

impl std::fmt::Debug for Auth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Auth::Password(_) => f.write_str("Auth::Password(«expurgé»)"),
            Auth::KeyFile { path, .. } => f
                .debug_struct("Auth::KeyFile")
                .field("path", path)
                .field("passphrase", &"«expurgé»")
                .finish(),
        }
    }
}

/// Paramètres de connexion.
#[derive(Debug)]
pub struct SshParams {
    pub host: String,
    pub port: u16,
    pub user: String,
    pub auth: Auth,
    /// Délai appliqué à la connexion ET à chaque commande.
    pub timeout: Duration,
    /// Accepter (et enregistrer) une clé d'hôte jamais vue. Risqué :
    /// aucune protection contre une interception à la PREMIÈRE connexion.
    pub accept_new: bool,
    /// Le fichier des clés d'hôtes connues (une ligne par hôte :
    /// `hôte:port type-de-clé base64`).
    pub known_hosts: PathBuf,
}

impl SshParams {
    fn host_label(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

/// Ce que la collecte rapporte : les sorties BRUTES (nettoyées des
/// artefacts de terminal), à interpréter par les modules purs.
#[derive(Debug, Clone)]
pub struct CollectedDevice {
    pub vendor: Vendor,
    pub profile_label: &'static str,
    /// Le nom d'hôte si la sonde l'apprend (FortiGate : `get system status`).
    pub hostname: Option<String>,
    pub probe_output: String,
    /// La configuration complète, prête pour les adaptateurs de
    /// `calque-vendors`.
    pub config: String,
    /// Les sorties des commandes de voisinage : (commande, sortie).
    pub neighbor_outputs: Vec<(String, String)>,
}

// ---------------------------------------------------------------------------
// Clé d'hôte
// ---------------------------------------------------------------------------

/// Ce que le contrôle de clé d'hôte a constaté (partagé avec le handler).
#[derive(Debug, Clone, Default)]
enum KeyEvent {
    #[default]
    Match,
    /// Clé inconnue refusée (pas de --accept-new).
    RefusedUnknown { fingerprint: String },
    /// Clé inconnue acceptée (--accept-new) : à enregistrer.
    AcceptedNew {
        line_value: String,
        fingerprint: String,
    },
    /// Clé différente de l'enregistrée : refusée, toujours.
    Mismatch { known: String, received: String },
}

struct HostKeyHandler {
    /// La valeur enregistrée pour cet hôte (`type base64`), s'il y en a une.
    known: Option<String>,
    accept_new: bool,
    event: Arc<Mutex<KeyEvent>>,
}

impl client::Handler for HostKeyHandler {
    type Error = CollectError;

    async fn check_server_key(
        &mut self,
        server_public_key: &russh::keys::PublicKey,
    ) -> Result<bool, Self::Error> {
        let received = key_line_value(server_public_key);
        let fingerprint = format!(
            "{} {}",
            server_public_key.algorithm(),
            server_public_key.fingerprint(HashAlg::Sha256)
        );
        let mut event = self.event.lock().unwrap_or_else(|p| p.into_inner());
        match &self.known {
            Some(known) if *known == received => {
                *event = KeyEvent::Match;
                Ok(true)
            }
            Some(known) => {
                *event = KeyEvent::Mismatch {
                    known: known.clone(),
                    received,
                };
                Ok(false)
            }
            None if self.accept_new => {
                *event = KeyEvent::AcceptedNew {
                    line_value: received,
                    fingerprint,
                };
                Ok(true)
            }
            None => {
                *event = KeyEvent::RefusedUnknown { fingerprint };
                Ok(false)
            }
        }
    }
}

/// La valeur enregistrable d'une clé publique : `type base64`, telle que
/// l'écrit OpenSSH (sans le commentaire).
fn key_line_value(key: &russh::keys::PublicKey) -> String {
    // `to_openssh` rend `type base64 [commentaire]` ; on garde deux champs.
    let openssh = key.to_openssh().map(|s| s.to_string()).unwrap_or_default();
    openssh
        .split_whitespace()
        .take(2)
        .collect::<Vec<_>>()
        .join(" ")
}

/// Cherche la clé enregistrée pour `host_label` dans le fichier
/// `known_hosts` (format : `hôte:port type base64`, une ligne par hôte).
fn lookup_known_host(path: &PathBuf, host_label: &str) -> Result<Option<String>, CollectError> {
    if !path.exists() {
        return Ok(None);
    }
    let raw = std::fs::read_to_string(path).map_err(|e| CollectError::Io {
        context: format!("lecture de {}", path.display()),
        source: e,
    })?;
    for line in raw.lines() {
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        let mut fields = t.split_whitespace();
        if fields.next() == Some(host_label) {
            let value: Vec<&str> = fields.take(2).collect();
            if value.len() == 2 {
                return Ok(Some(value.join(" ")));
            }
        }
    }
    Ok(None)
}

/// Enregistre la clé d'un hôte nouvellement accepté (`--accept-new`).
fn append_known_host(
    path: &PathBuf,
    host_label: &str,
    line_value: &str,
) -> Result<(), CollectError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| CollectError::Io {
            context: format!("création de {}", parent.display()),
            source: e,
        })?;
    }
    let mut contents = if path.exists() {
        std::fs::read_to_string(path).map_err(|e| CollectError::Io {
            context: format!("lecture de {}", path.display()),
            source: e,
        })?
    } else {
        String::from(
            "# Clés d'hôtes acceptées par `calque collect` (une ligne : hôte:port type base64).\n",
        )
    };
    if !contents.is_empty() && !contents.ends_with('\n') {
        contents.push('\n');
    }
    contents.push_str(&format!("{host_label} {line_value}\n"));
    std::fs::write(path, contents).map_err(|e| CollectError::Io {
        context: format!("écriture de {}", path.display()),
        source: e,
    })
}

// ---------------------------------------------------------------------------
// Collecte
// ---------------------------------------------------------------------------

/// Collecte un équipement : connexion, authentification, détection du
/// constructeur (si `vendor_hint` est `None`), configuration complète,
/// tables de voisinage. Synchrone : la runtime asynchrone est un détail
/// interne.
pub fn collect_device(
    params: &SshParams,
    vendor_hint: Option<Vendor>,
) -> Result<CollectedDevice, CollectError> {
    // Les profils embarqués sont revérifiés à CHAQUE exécution : si une
    // commande d'écriture se glissait dans le code, la collecte refuse de
    // démarrer (principe n° 1, défense en profondeur).
    for profile in crate::profile::all_profiles() {
        profile.verify_read_only()?;
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| CollectError::Io {
            context: "démarrage de la runtime interne".to_owned(),
            source: e,
        })?;
    runtime.block_on(collect_async(params, vendor_hint))
}

async fn collect_async(
    params: &SshParams,
    vendor_hint: Option<Vendor>,
) -> Result<CollectedDevice, CollectError> {
    let host_label = params.host_label();
    let known = lookup_known_host(&params.known_hosts, &host_label)?;
    let event = Arc::new(Mutex::new(KeyEvent::default()));
    let handler = HostKeyHandler {
        known,
        accept_new: params.accept_new,
        event: Arc::clone(&event),
    };

    let config = Arc::new(client::Config::default());
    let connect = client::connect(config, (params.host.as_str(), params.port), handler);
    let mut handle = match tokio::time::timeout(params.timeout, connect).await {
        Err(_) => {
            return Err(CollectError::Timeout {
                context: format!("connexion à {host_label}"),
            })
        }
        Ok(Err(e)) => {
            // Si le refus vient du contrôle de clé d'hôte, le dire
            // précisément plutôt que « erreur SSH ».
            let ev = event.lock().unwrap_or_else(|p| p.into_inner()).clone();
            return Err(match ev {
                KeyEvent::RefusedUnknown { fingerprint } => CollectError::HostKeyUnknown {
                    host: host_label,
                    fingerprint,
                },
                KeyEvent::Mismatch { known, received } => CollectError::HostKeyMismatch {
                    host: host_label,
                    known,
                    received,
                    known_hosts: params.known_hosts.display().to_string(),
                },
                _ => with_host(e, &host_label),
            });
        }
        Ok(Ok(h)) => h,
    };

    // Clé nouvellement acceptée : l'enregistrer tout de suite (et le dire).
    if let KeyEvent::AcceptedNew {
        line_value,
        fingerprint,
    } = event.lock().unwrap_or_else(|p| p.into_inner()).clone()
    {
        append_known_host(&params.known_hosts, &host_label, &line_value)?;
        eprintln!(
            "Attention : clé d'hôte de {host_label} acceptée et enregistrée sur votre demande \
             (--accept-new) : {fingerprint}. Vérifiez cette empreinte auprès de l'équipement — \
             une première connexion interceptée resterait indétectée."
        );
    }

    // Authentification.
    let auth_result = match &params.auth {
        Auth::Password(password) => handle
            .authenticate_password(params.user.as_str(), password.as_str())
            .await
            .map_err(|e| with_host(e.into(), &host_label))?,
        Auth::KeyFile { path, passphrase } => {
            let key = russh::keys::load_secret_key(path, passphrase.as_deref()).map_err(|e| {
                CollectError::KeyFile {
                    path: path.display().to_string(),
                    detail: e.to_string(),
                }
            })?;
            let hash = handle
                .best_supported_rsa_hash()
                .await
                .map_err(|e| with_host(e.into(), &host_label))?
                .flatten();
            handle
                .authenticate_publickey(
                    params.user.as_str(),
                    PrivateKeyWithHashAlg::new(Arc::new(key), hash),
                )
                .await
                .map_err(|e| with_host(e.into(), &host_label))?
        }
    };
    if !auth_result.success() {
        return Err(CollectError::AuthFailed {
            host: host_label,
            user: params.user.clone(),
            method: match &params.auth {
                Auth::Password(_) => "mot de passe",
                Auth::KeyFile { .. } => "clé publique",
            },
        });
    }

    // Détection du constructeur (jamais devinée : sondes + signatures).
    let (profile, probe_output) = match vendor_hint {
        Some(v) => {
            let profile = profile_for(v).ok_or_else(|| CollectError::NoProfile {
                vendor: format!("{v:?}"),
            })?;
            let out = run_command(&handle, profile, profile.probe, params).await?;
            (profile, out)
        }
        None => {
            let forti_out = run_command(&handle, &FORTIGATE, FORTIGATE.probe, params).await?;
            if classify_fortigate_status(&forti_out).is_some() {
                (&FORTIGATE, forti_out)
            } else {
                let ios_out = run_command(&handle, &CISCO_IOS, CISCO_IOS.probe, params).await?;
                if classify_show_version(&ios_out).is_some() {
                    (&CISCO_IOS, ios_out)
                } else {
                    return Err(CollectError::VendorNotDetected { host: host_label });
                }
            }
        }
    };

    // Réglages d'environnement de session (pagination), sorties ignorées.
    for cmd in profile.setup {
        let _ = run_command(&handle, profile, cmd, params).await?;
    }

    // La configuration, puis les voisins.
    let config_output = run_command(&handle, profile, profile.config, params).await?;
    let mut neighbor_outputs = Vec::with_capacity(profile.neighbors.len());
    for cmd in profile.neighbors {
        let out = run_command(&handle, profile, cmd, params).await?;
        neighbor_outputs.push(((*cmd).to_owned(), out));
    }

    let hostname = match profile.vendor {
        Vendor::Fortigate => parse_system_status(&probe_output).hostname,
        _ => None,
    };

    let _ = handle
        .disconnect(russh::Disconnect::ByApplication, "", "fr")
        .await;

    Ok(CollectedDevice {
        vendor: profile.vendor,
        profile_label: profile.label,
        hostname,
        probe_output,
        config: config_output,
        neighbor_outputs,
    })
}

/// Envoie UNE commande (canal `exec` dédié) et capture sa sortie nettoyée.
///
/// Défense en profondeur : la commande doit appartenir à la liste blanche
/// du profil ET repasser le contrôle lecture seule, sinon refus local —
/// rien ne part sur le réseau.
async fn run_command(
    handle: &client::Handle<HostKeyHandler>,
    profile: &CollectProfile,
    cmd: &str,
    params: &SshParams,
) -> Result<String, CollectError> {
    if !profile.allows(cmd) {
        return Err(CollectError::NotWhitelisted {
            profile: profile.label.to_owned(),
            command: cmd.to_owned(),
        });
    }
    if let Some(token) = crate::profile::forbidden_token(cmd) {
        return Err(CollectError::ForbiddenCommand {
            command: cmd.to_owned(),
            token: token.to_owned(),
        });
    }

    let host_label = params.host_label();
    let work = async {
        let mut channel = handle.channel_open_session().await?;
        channel.exec(true, cmd).await?;
        let mut bytes: Vec<u8> = Vec::new();
        while let Some(msg) = channel.wait().await {
            match msg {
                ChannelMsg::Data { data } => bytes.extend_from_slice(&data),
                // Certains équipements écrivent sur le canal stderr.
                ChannelMsg::ExtendedData { data, .. } => bytes.extend_from_slice(&data),
                ChannelMsg::Close => break,
                _ => {}
            }
        }
        Ok::<Vec<u8>, russh::Error>(bytes)
    };
    let bytes = match tokio::time::timeout(params.timeout, work).await {
        Err(_) => {
            return Err(CollectError::Timeout {
                context: format!("commande « {cmd} » sur {host_label}"),
            })
        }
        Ok(Err(e)) => return Err(with_host(e.into(), &host_label)),
        Ok(Ok(b)) => b,
    };
    Ok(clean_output(&String::from_utf8_lossy(&bytes)))
}

/// Complète une erreur SSH avec l'hôte concerné (la conversion
/// `From<russh::Error>` ne le connaît pas).
fn with_host(e: CollectError, host: &str) -> CollectError {
    match e {
        CollectError::Ssh { detail, .. } => CollectError::Ssh {
            host: host.to_owned(),
            detail,
        },
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_des_parametres_n_expose_aucun_secret() {
        let params = SshParams {
            host: "192.0.2.1".into(),
            port: 22,
            user: "admin".into(),
            auth: Auth::Password("tr3s-s3cret".into()),
            timeout: Duration::from_secs(10),
            accept_new: false,
            known_hosts: PathBuf::from(".calque/known_hosts"),
        };
        let debug = format!("{params:?}");
        assert!(
            !debug.contains("tr3s-s3cret"),
            "secret dans Debug : {debug}"
        );
        assert!(debug.contains("expurgé"));

        let auth = Auth::KeyFile {
            path: PathBuf::from("id_ed25519"),
            passphrase: Some("phrase".into()),
        };
        let debug = format!("{auth:?}");
        assert!(!debug.contains("phrase\""), "secret dans Debug : {debug}");
    }

    #[test]
    fn known_hosts_aller_retour() {
        let dir = std::env::temp_dir().join(format!("calque-collect-test-{}", std::process::id()));
        let path = dir.join("known_hosts");
        let _ = std::fs::remove_file(&path);
        assert_eq!(lookup_known_host(&path, "192.0.2.1:22").unwrap(), None);
        append_known_host(&path, "192.0.2.1:22", "ssh-ed25519 AAAAC3Nza").unwrap();
        append_known_host(&path, "192.0.2.2:22", "ssh-ed25519 AUTRE").unwrap();
        assert_eq!(
            lookup_known_host(&path, "192.0.2.1:22").unwrap().as_deref(),
            Some("ssh-ed25519 AAAAC3Nza")
        );
        assert_eq!(
            lookup_known_host(&path, "192.0.2.9:22").unwrap().as_deref(),
            None
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
