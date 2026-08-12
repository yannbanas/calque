//! La confrontation au réel (§11.2) : le modèle prédit, le réseau tranche.
//!
//! Deux moitiés soigneusement séparées :
//!
//! - [`cross`] : la logique de confrontation, PURE, testée exhaustivement
//!   sans réseau — c'est elle qui décide ce qu'on a le droit de conclure ;
//! - [`probe_tcp`] : la sonde, IMPURE (une connexion TCP réelle avec
//!   délai), quelques lignes seulement.
//!
//! ## L'honnêteté du verdict — lisez ceci avant d'accuser le modèle
//!
//! La sonde part de la MACHINE COURANTE, pas de la source déclarée du
//! flux : les chemins peuvent différer. Et une observation TCP est
//! ambiguë par nature :
//!
//! - un refus (RST) peut venir du service éteint sur la destination…
//!   ou d'un pare-feu qui rejette poliment (`reject`, `send-deny-packet`) —
//!   il ne prouve PAS que le filtrage laisse passer ;
//! - un silence (délai dépassé) peut venir d'un filtrage `drop`, d'un
//!   hôte éteint, ou d'un réseau lent — il ne prouve rien ;
//! - seule une POIGNÉE DE MAIN COMPLÈTE (connexion établie) prouve
//!   quelque chose de ferme : le chemin réseau est ouvert de bout en bout.
//!
//! D'où l'unique divergence FERME : le modèle dit `deny` et la connexion
//! s'établit. Tout le reste est rapporté avec sa nuance, jamais en
//! accusation.

use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

/// Ce que le MODÈLE prédit pour un flux (réduit de `Verdict`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModelSays {
    Allow,
    /// Refusé, pas de route, ou boucle : le modèle prédit que ça ne passe pas.
    Deny,
    /// Verdict non ferme (modèle partiel, `Unknown`) : rien à confronter.
    NotFirm,
}

/// Ce que la sonde TCP a OBSERVÉ.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RealObservation {
    /// Poignée de main complète : le chemin réseau est ouvert, le service
    /// répond.
    Reachable,
    /// RST reçu : QUELQU'UN a refusé — le service (port fermé) ou un
    /// pare-feu qui rejette. Indistinguable d'ici.
    Refused,
    /// Silence jusqu'au délai : filtrage `drop`, hôte éteint, ou réseau
    /// lent. Indistinguable d'ici.
    TimedOut,
    /// Injoignable (ICMP unreachable, pas de route locale…).
    Unreachable,
}

impl RealObservation {
    pub fn label(self) -> &'static str {
        match self {
            RealObservation::Reachable => "joignable (connexion établie)",
            RealObservation::Refused => "refusé (RST — service fermé OU pare-feu qui rejette)",
            RealObservation::TimedOut => "silence (délai dépassé — filtré OU hôte éteint)",
            RealObservation::Unreachable => "injoignable (ICMP/route locale)",
        }
    }
}

/// Le verdict croisé d'un flux.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CrossVerdict {
    /// Modèle et réel s'accordent.
    Concordant,
    /// Concordant côté RÉSEAU : le modèle autorise, et un RST est revenu —
    /// le service est probablement éteint, le filtrage n'est pas en cause.
    ConcordantServiceDown,
    /// DIVERGENCE FERME : le modèle refuse, la connexion s'établit.
    /// C'est un bogue du modèle (ou un modèle périmé), avec le cas de
    /// test tout prêt.
    FirmDivergence,
    /// Indéterminé : l'observation ne permet pas de trancher (voir la
    /// documentation du module). Le rapport n'accuse pas le modèle.
    Indeterminate,
}

/// La confrontation — PURE. C'est ici que vit toute la prudence.
pub fn cross(model: ModelSays, real: RealObservation) -> CrossVerdict {
    match (model, real) {
        // Rien de ferme côté modèle : rien à confronter.
        (ModelSays::NotFirm, _) => CrossVerdict::Indeterminate,

        // Le modèle autorise.
        (ModelSays::Allow, RealObservation::Reachable) => CrossVerdict::Concordant,
        (ModelSays::Allow, RealObservation::Refused) => CrossVerdict::ConcordantServiceDown,
        // Silence ou injoignable : service/hôte éteint ? filtrage réel plus
        // strict ? La sonde ne part pas de la vraie source : indéterminé.
        (ModelSays::Allow, RealObservation::TimedOut)
        | (ModelSays::Allow, RealObservation::Unreachable) => CrossVerdict::Indeterminate,

        // Le modèle refuse.
        (ModelSays::Deny, RealObservation::Reachable) => CrossVerdict::FirmDivergence,
        // Un RST peut être le rejet du pare-feu lui-même : cohérent avec
        // un deny, PAS une divergence.
        (ModelSays::Deny, RealObservation::Refused) => CrossVerdict::Indeterminate,
        (ModelSays::Deny, RealObservation::TimedOut)
        | (ModelSays::Deny, RealObservation::Unreachable) => CrossVerdict::Concordant,
    }
}

/// La sonde TCP — IMPURE, minuscule : une tentative de connexion avec
/// délai depuis la machine courante, classée en [`RealObservation`].
pub fn probe_tcp(addr: SocketAddr, timeout: Duration) -> RealObservation {
    match TcpStream::connect_timeout(&addr, timeout) {
        Ok(stream) => {
            // Fermeture propre immédiate : la sonde n'échange aucune donnée.
            drop(stream);
            RealObservation::Reachable
        }
        Err(e) => match e.kind() {
            std::io::ErrorKind::ConnectionRefused | std::io::ErrorKind::ConnectionReset => {
                RealObservation::Refused
            }
            std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock => {
                RealObservation::TimedOut
            }
            _ => RealObservation::Unreachable,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// La table de confrontation complète, cas par cas — c'est le contrat
    /// d'honnêteté du §11.2.
    #[test]
    fn la_table_de_confrontation() {
        use CrossVerdict::*;
        use ModelSays::*;
        use RealObservation::*;

        assert_eq!(cross(Allow, Reachable), Concordant);
        assert_eq!(cross(Allow, Refused), ConcordantServiceDown);
        assert_eq!(cross(Allow, TimedOut), Indeterminate);
        assert_eq!(cross(Allow, Unreachable), Indeterminate);

        assert_eq!(cross(Deny, Reachable), FirmDivergence);
        assert_eq!(cross(Deny, Refused), Indeterminate);
        assert_eq!(cross(Deny, TimedOut), Concordant);
        assert_eq!(cross(Deny, Unreachable), Concordant);

        for real in [Reachable, Refused, TimedOut, Unreachable] {
            assert_eq!(cross(NotFirm, real), Indeterminate);
        }
    }

    /// La SEULE divergence ferme est deny + poignée de main complète.
    #[test]
    fn une_seule_divergence_ferme() {
        use ModelSays::*;
        use RealObservation::*;
        let mut firm = 0;
        for model in [Allow, Deny, NotFirm] {
            for real in [Reachable, Refused, TimedOut, Unreachable] {
                if cross(model, real) == CrossVerdict::FirmDivergence {
                    firm += 1;
                    assert_eq!((model, real), (Deny, Reachable));
                }
            }
        }
        assert_eq!(firm, 1);
    }

    /// Sonde sur boucle locale : une poignée de main réussie contre un
    /// écouteur réel ; contre le port qu'il vient de libérer, tout SAUF
    /// « joignable » (Windows re-tente après un RST : le refus peut se
    /// présenter en délai dépassé — précisément la nuance que `cross`
    /// traite avec prudence). Aucun réseau externe : 127.0.0.1 uniquement.
    #[test]
    fn sonde_sur_boucle_locale() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        let addr = listener.local_addr().expect("adresse locale");
        assert_eq!(
            probe_tcp(addr, Duration::from_millis(2000)),
            RealObservation::Reachable
        );
        drop(listener);
        // Plus personne n'écoute : refus (RST) ou délai selon la plateforme.
        assert_ne!(
            probe_tcp(addr, Duration::from_millis(1000)),
            RealObservation::Reachable
        );
    }
}
