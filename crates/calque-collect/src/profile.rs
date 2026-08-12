//! Profils de collecte par constructeur — module PUR.
//!
//! Un profil est la liste FERMÉE des commandes que la collecte a le droit
//! d'envoyer à un équipement. Principe n° 1 du projet (§13) : **lecture
//! seule, toujours**. Aucune commande de configuration, jamais — et un
//! test (`tous_les_profils_sont_en_lecture_seule`) refuse tout profil qui
//! contiendrait un jeton interdit (`configure`, `edit`, `set`, `write`,
//! `copy`, `reload`…).
//!
//! Le transport (`ssh`, feature du crate) refuse d'envoyer une commande
//! qui n'appartient pas au profil : la liste blanche est vérifiée une
//! deuxième fois au moment de l'envoi (défense en profondeur).

use calque_model::Vendor;

use crate::error::CollectError;

/// Jetons interdits : si l'un d'eux apparaît comme MOT ENTIER dans une
/// commande d'un profil, le profil est refusé. La liste est
/// volontairement large — mieux vaut refuser une commande de lecture
/// exotique que laisser passer une écriture.
pub const FORBIDDEN_TOKENS: &[&str] = &[
    "configure",
    "config",
    "edit",
    "set",
    "unset",
    "write",
    "copy",
    "reload",
    "reboot",
    "shutdown",
    "delete",
    "erase",
    "clear",
    "execute",
    "restore",
    "format",
    "install",
    "upgrade",
];

/// Un profil de collecte : les commandes à exécuter sur un constructeur
/// donné. Toutes en LECTURE SEULE stricte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CollectProfile {
    pub vendor: Vendor,
    /// Libellé humain (« FortiGate », « Cisco IOS »).
    pub label: &'static str,
    /// Commande d'identification (détection automatique du constructeur).
    pub probe: &'static str,
    /// Commandes d'environnement de session, envoyées avant la collecte.
    ///
    /// Uniquement des réglages de TERMINAL, portée session, sans effet sur
    /// la configuration de l'équipement (ex. `terminal length 0` sur
    /// Cisco IOS : supprime la pagination pour la session courante).
    /// FortiGate n'en a pas : couper sa pagination exigerait
    /// `config system console` — une commande de CONFIGURATION, donc
    /// interdite ici ; les artefacts `--More--` résiduels sont nettoyés
    /// par [`crate::clean::clean_output`] à la place.
    pub setup: &'static [&'static str],
    /// La commande qui rend la configuration complète (à passer aux
    /// adaptateurs de `calque-vendors`).
    pub config: &'static str,
    /// Les commandes de voisinage (LLDP/CDP).
    pub neighbors: &'static [&'static str],
}

/// Profil FortiGate.
///
/// - `get system status` : identification (hostname, version FortiOS) ;
/// - `show` : la configuration non-défaut complète, le format que
///   l'adaptateur FortiGate de `calque-vendors` lit déjà ;
/// - `diagnose lldprx neighbor summary all` : le résumé des voisins LLDP
///   reçus (FortiOS 7.x ; le parseur est testé sur transcripts
///   enregistrés, voir `corpus/collect/fortigate/`).
pub const FORTIGATE: CollectProfile = CollectProfile {
    vendor: Vendor::Fortigate,
    label: "FortiGate",
    probe: "get system status",
    setup: &[],
    config: "show",
    neighbors: &["diagnose lldprx neighbor summary all"],
};

/// Profil Cisco IOS / IOS-XE.
///
/// - `show version` : identification ;
/// - `terminal length 0` / `terminal width 511` : réglages de terminal,
///   portée session, pour neutraliser la pagination — des commandes de
///   lecture d'environnement, pas de configuration ;
/// - `show running-config` : la configuration complète ;
/// - `show lldp neighbors detail` et `show cdp neighbors detail` : les
///   deux tables de voisinage (LLDP normalisé + CDP propriétaire, souvent
///   seul activé sur les parcs anciens).
pub const CISCO_IOS: CollectProfile = CollectProfile {
    vendor: Vendor::CiscoIos,
    label: "Cisco IOS",
    probe: "show version",
    setup: &["terminal length 0", "terminal width 511"],
    config: "show running-config",
    neighbors: &["show lldp neighbors detail", "show cdp neighbors detail"],
};

/// Tous les profils connus.
pub fn all_profiles() -> &'static [CollectProfile] {
    &[FORTIGATE, CISCO_IOS]
}

/// Le profil d'un constructeur, s'il existe.
pub fn profile_for(vendor: Vendor) -> Option<&'static CollectProfile> {
    all_profiles().iter().find(|p| p.vendor == vendor)
}

impl CollectProfile {
    /// Toutes les commandes que ce profil peut envoyer — LA liste blanche.
    pub fn allowed_commands(&self) -> Vec<&'static str> {
        let mut out = vec![self.probe];
        out.extend_from_slice(self.setup);
        out.push(self.config);
        out.extend_from_slice(self.neighbors);
        out
    }

    /// Une commande est-elle dans la liste blanche de ce profil ?
    /// Comparaison EXACTE (après trim) : pas de préfixe, pas de joker.
    pub fn allows(&self, cmd: &str) -> bool {
        let cmd = cmd.trim();
        self.allowed_commands().contains(&cmd)
    }

    /// Vérifie que TOUTES les commandes du profil sont en lecture seule :
    /// aucun jeton interdit ([`FORBIDDEN_TOKENS`]) comme mot entier.
    pub fn verify_read_only(&self) -> Result<(), CollectError> {
        for cmd in self.allowed_commands() {
            if let Some(token) = forbidden_token(cmd) {
                return Err(CollectError::ForbiddenCommand {
                    command: cmd.to_owned(),
                    token: token.to_owned(),
                });
            }
        }
        Ok(())
    }
}

/// Le premier jeton interdit d'une commande, s'il y en a un. Chaque mot
/// (séparé par des blancs) est comparé en entier, insensiblement à la
/// casse : `show running-config` passe, `configure terminal` non.
pub fn forbidden_token(cmd: &str) -> Option<&'static str> {
    cmd.split_whitespace().find_map(|word| {
        FORBIDDEN_TOKENS
            .iter()
            .find(|t| word.eq_ignore_ascii_case(t))
            .copied()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// LE test exigé par le principe n° 1 : tout profil embarqué est en
    /// lecture seule stricte.
    #[test]
    fn tous_les_profils_sont_en_lecture_seule() {
        for profile in all_profiles() {
            profile
                .verify_read_only()
                .unwrap_or_else(|e| panic!("profil {} : {e}", profile.label));
        }
    }

    /// Un profil qui contiendrait une commande d'écriture est refusé —
    /// pour chacun des jetons de la mission.
    #[test]
    fn un_profil_avec_commande_d_ecriture_est_refuse() {
        for bad in [
            "configure terminal",
            "config system console",
            "edit 1",
            "set output standard",
            "write memory",
            "copy running-config startup-config",
            "reload",
        ] {
            let profile = CollectProfile {
                vendor: Vendor::Unknown,
                label: "test",
                probe: "show version",
                setup: &[],
                config: bad,
                // `config` est un champ ; la commande interdite est testée
                // partout où elle pourrait se glisser via allowed_commands.
                neighbors: &[],
            };
            let err = profile.verify_read_only().expect_err(bad);
            assert!(
                matches!(err, CollectError::ForbiddenCommand { .. }),
                "erreur inattendue pour « {bad} » : {err}"
            );
        }
    }

    #[test]
    fn les_jetons_interdits_sont_des_mots_entiers() {
        // `running-config` contient « config » comme sous-chaîne mais pas
        // comme mot : autorisé.
        assert_eq!(forbidden_token("show running-config"), None);
        assert_eq!(forbidden_token("show lldp neighbors detail"), None);
        assert_eq!(forbidden_token("terminal length 0"), None);
        assert_eq!(
            forbidden_token("diagnose lldprx neighbor summary all"),
            None
        );
        // Mots entiers, peu importe la casse et la position.
        assert_eq!(forbidden_token("Configure terminal"), Some("configure"));
        assert_eq!(forbidden_token("config system console"), Some("config"));
        assert_eq!(forbidden_token("show | set x"), Some("set"));
    }

    #[test]
    fn liste_blanche_exacte() {
        assert!(CISCO_IOS.allows("show running-config"));
        assert!(CISCO_IOS.allows("  show running-config  "));
        // Pas de préfixe : une commande rallongée n'est PAS couverte.
        assert!(!CISCO_IOS.allows("show running-config | redirect tftp:"));
        assert!(!CISCO_IOS.allows("show ip route"));
        assert!(FORTIGATE.allows("show"));
        assert!(!FORTIGATE.allows("show full-configuration"));
    }
}
