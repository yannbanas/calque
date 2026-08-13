//! Erreurs d'évaluation du moteur.
//!
//! Principe §6.3 : ne jamais deviner. Chaque erreur ci-dessous signale un
//! élément manquant ou ambigu sur le chemin analysé ; le moteur la convertit
//! en diagnostic et rend le verdict `Unknown` au lieu d'une supposition.

use std::net::IpAddr;

use calque_model::{Diagnostic, ObjectId, PolicyId, RuleId, SourceSpan};
use ipnet::IpNet;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EvalError {
    /// Objet adresse référencé par une règle mais absent du magasin.
    AddrObjectMissing { object: ObjectId },
    /// Objet service référencé par une règle mais absent du magasin.
    ServiceObjectMissing { object: ObjectId },
    /// Cycle dans les groupes d'objets ; `path` est le chemin fautif.
    ObjectCycle { path: Vec<ObjectId> },
    /// Chaîne de groupes imbriqués plus profonde que la borne de sûreté :
    /// une configuration hostile ne doit pas pouvoir faire déborder la pile
    /// sur le chemin qui décide du verdict (audit 2026-08-12, R2).
    GroupTooDeep { object: ObjectId, depth: usize },
    /// Politique accrochée au pipeline (ou cible d'un saut) introuvable.
    PolicyMissing { policy: PolicyId },
    /// Cycle de sauts entre politiques.
    JumpCycle { path: Vec<PolicyId> },
    /// Une règle d'ENTRÉE qui correspond au paquet contraint la zone de
    /// sortie (`to`), inconnue avant la décision de routage. Le moteur
    /// attend les contraintes de zone de sortie sur les politiques de sortie.
    EgressZoneUnknownAtIngress { rule: RuleId, source: SourceSpan },
    /// DNAT accordé par une politique de SORTIE : la décision de routage est
    /// déjà prise, réécrire la destination serait incohérent.
    DnatAfterRouting {
        rule: Option<RuleId>,
        source: Option<SourceSpan>,
    },
    /// Plus de routes optimales divergentes (ECMP) que la borne d'évaluation
    /// par branches ([`crate::route::MAX_ECMP_ROUTES`]) : au-delà, le moteur
    /// refuse d'évaluer (verdict `Unknown`) plutôt que de deviner ou de
    /// tronquer silencieusement.
    EcmpTooWide {
        dst: IpAddr,
        prefix: IpNet,
        count: usize,
    },
    /// Incohérence du modèle empêchant de poursuivre (interface absente,
    /// prochain saut injoignable…).
    Inconsistent {
        message: String,
        span: Option<SourceSpan>,
    },
}

impl EvalError {
    /// L'origine de configuration associée, quand elle existe.
    fn span(&self) -> Option<SourceSpan> {
        match self {
            EvalError::EgressZoneUnknownAtIngress { source, .. } => Some(source.clone()),
            EvalError::DnatAfterRouting { source, .. } => source.clone(),
            EvalError::Inconsistent { span, .. } => span.clone(),
            _ => None,
        }
    }

    /// Conversion en diagnostic pour la trace (verdict `Unknown`).
    pub fn to_diagnostic(&self) -> Diagnostic {
        Diagnostic::error(self.to_string(), self.span())
    }
}

impl std::fmt::Display for EvalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EvalError::AddrObjectMissing { object } => {
                write!(f, "objet adresse « {object} » introuvable")
            }
            EvalError::ServiceObjectMissing { object } => {
                write!(f, "objet service « {object} » introuvable")
            }
            EvalError::ObjectCycle { path } => {
                let chain: Vec<&str> = path.iter().map(|o| o.as_str()).collect();
                write!(
                    f,
                    "cycle dans les groupes d'objets : {}",
                    chain.join(" -> ")
                )
            }
            EvalError::GroupTooDeep { object, depth } => write!(
                f,
                "groupes imbriqués trop profonds (> {depth}) à partir de \
                 l'objet « {object} »"
            ),
            EvalError::PolicyMissing { policy } => {
                write!(f, "politique « {policy} » introuvable")
            }
            EvalError::JumpCycle { path } => {
                let chain: Vec<&str> = path.iter().map(|p| p.as_str()).collect();
                write!(
                    f,
                    "cycle de sauts entre politiques : {}",
                    chain.join(" -> ")
                )
            }
            EvalError::EgressZoneUnknownAtIngress { rule, .. } => write!(
                f,
                "la règle « {rule} » contraint la zone de sortie dans un filtre \
                 d'entrée : zone inconnue avant routage"
            ),
            EvalError::DnatAfterRouting { rule, .. } => match rule {
                Some(r) => write!(
                    f,
                    "la règle « {r} » demande un DNAT après la décision de routage"
                ),
                None => write!(f, "DNAT demandé après la décision de routage"),
            },
            EvalError::EcmpTooWide { dst, prefix, count } => write!(
                f,
                "{count} routes optimales divergentes vers {dst} (préfixe {prefix}) : \
                 au-delà de la borne de {} branches évaluées, verdict indéterminé",
                crate::route::MAX_ECMP_ROUTES
            ),
            EvalError::Inconsistent { message, .. } => f.write_str(message),
        }
    }
}

impl std::error::Error for EvalError {}
