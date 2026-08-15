//! Évaluation ordonnée d'une politique : première correspondance gagne.
//!
//! En plus de la décision, l'évaluateur continue de parcourir les règles
//! POSTÉRIEURES à la règle décisive : chacune qui correspond aussi au paquet
//! reçoit une décision informationnelle `Outcome::Matched` dont
//! `shadowed_by` liste les règles antérieures qui la masquent (§5.2).

use calque_model::{
    Action, ConcretePacket, Device, Diagnostic, NatAction, Policy, Rule, RuleId, SourceSpan, ZoneId,
};

use crate::error::EvalError;
use crate::resolve::packet_matches_rule_opts;
use crate::trace::{Decision, Outcome, Stage};

/// Où le filtre est évalué dans la séquence de traitement, avec les zones
/// connues à ce point. En entrée, la zone de sortie n'est PAS encore connue
/// (le routage n'a pas eu lieu) : une règle d'entrée qui contraint `to` et
/// correspond au paquet produit une erreur plutôt qu'une supposition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FilterPoint {
    Ingress {
        in_zone: Option<ZoneId>,
    },
    Egress {
        in_zone: Option<ZoneId>,
        out_zone: Option<ZoneId>,
    },
}

impl FilterPoint {
    fn in_zone(&self) -> Option<&ZoneId> {
        match self {
            FilterPoint::Ingress { in_zone } | FilterPoint::Egress { in_zone, .. } => {
                in_zone.as_ref()
            }
        }
    }
}

/// Une autorisation de traduction d'adresse accordée par une règle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NatGrant {
    /// `None` quand la traduction vient de l'action par défaut.
    pub rule: Option<RuleId>,
    pub source: Option<SourceSpan>,
    pub action: NatAction,
}

/// Le résultat net d'une politique sur un paquet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FilterResult {
    Accept { nat: Option<NatGrant> },
    Deny,
}

/// Résultat complet : décisions pour la trace + diagnostics non bloquants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyEvaluation {
    pub decisions: Vec<Decision>,
    /// Problèmes rencontrés HORS du chemin décisif (ex. règle postérieure
    /// irrésoluble pendant le calcul des règles masquées) : signalés sans
    /// invalider le verdict.
    pub diagnostics: Vec<Diagnostic>,
    pub result: FilterResult,
}

/// Une contrainte de ZONE exclut-elle la règle pour ce paquet ? Les zones
/// (`from`/`to`) ne sont JAMAIS sur-approximées par le convertisseur : c'est
/// donc la seule exclusion FIABLE d'une règle sur-approximée, dont le pavé
/// (adresses/services), lui, n'est pas fiable. En entrée, la zone de sortie
/// n'est pas encore connue : une contrainte `to` ne peut pas exclure.
fn zone_excludes(rule: &Rule, point: &FilterPoint) -> bool {
    if let Some(from) = &rule.from {
        if point.in_zone() != Some(from) {
            return true;
        }
    }
    if let FilterPoint::Egress { out_zone, .. } = point {
        if let Some(to) = &rule.to {
            if out_zone.as_ref() != Some(to) {
                return true;
            }
        }
    }
    false
}

/// Une règle SUR-APPROXIMÉE atteinte à ce point de l'évaluation ordonnée
/// (aucune règle antérieure pleinement modélisée n'a tranché) peut décider
/// ce paquet EN RÉALITÉ, alors que le modèle ne le refléterait pas
/// fidèlement :
/// - sur-approximation MONOTONE (identité, `internet-service`, planification)
///   : si elle matche dans le modèle et devient décisive (accept), l'équipement
///   réel pourrait ne PAS matcher → la vraie décision serait plus loin →
///   risque de faux « autorisé » ;
/// - NÉGATION : le modèle matche le COMPLÉMENT de la réalité ; « ne matche
///   pas dans le modèle » ne garantit donc pas « ne matche pas en vrai », la
///   règle pourrait court-circuiter la vraie décision.
///
/// La seule exclusion fiable étant la zone (jamais approximée), on refuse de
/// trancher fermement dès qu'une règle approximée NON exclue par zone est
/// atteinte avant (ou à) la décision. `allow_partial` (`--allow-partial`)
/// lève ce refus : la règle est alors évaluée sur sa correspondance modèle,
/// verdict assumé sur la partie modélisée. On préfère `Unknown` de trop à un
/// ferme à tort (§6.3).
fn approximation_blocks(
    rule: &Rule,
    point: &FilterPoint,
    allow_partial: bool,
) -> Option<EvalError> {
    if allow_partial {
        return None;
    }
    let reason = rule.approximation.as_ref()?;
    if zone_excludes(rule, point) {
        return None;
    }
    Some(EvalError::ApproximatedRuleOnPath {
        rule: rule.id.clone(),
        source: rule.source.clone(),
        reason: reason.clone(),
    })
}

/// La règle s'applique-t-elle au paquet à ce point du pipeline
/// (zones + pavé, objets résolus tardivement) ?
fn rule_applies(
    device: &Device,
    rule: &Rule,
    pkt: &ConcretePacket,
    point: &FilterPoint,
    allow_partial: bool,
) -> Result<bool, EvalError> {
    // Zone d'entrée : connue aux deux points.
    if let Some(from) = &rule.from {
        if point.in_zone() != Some(from) {
            return Ok(false);
        }
    }
    match point {
        FilterPoint::Egress { out_zone, .. } => {
            if let Some(to) = &rule.to {
                if out_zone.as_ref() != Some(to) {
                    return Ok(false);
                }
            }
            packet_matches_rule_opts(&device.objects, &rule.matches, pkt, allow_partial)
        }
        FilterPoint::Ingress { .. } => {
            let matched =
                packet_matches_rule_opts(&device.objects, &rule.matches, pkt, allow_partial)?;
            // Ne jamais deviner : si la règle toucherait le paquet mais
            // dépend de la zone de sortie, on refuse de conclure.
            if matched && rule.to.is_some() {
                return Err(EvalError::EgressZoneUnknownAtIngress {
                    rule: rule.id.clone(),
                    source: rule.source.clone(),
                });
            }
            Ok(matched)
        }
    }
}

fn rule_decision(stage: Stage, rule: &Rule, outcome: Outcome) -> Decision {
    Decision {
        stage,
        rule: Some(rule.id.clone()),
        source: Some(rule.source.clone()),
        outcome,
        shadowed_by: Vec::new(),
    }
}

/// Transforme une action terminale en résultat de filtre.
fn terminal_result(rule: Option<&Rule>, action: &Action) -> Option<FilterResult> {
    match action {
        Action::Accept => Some(FilterResult::Accept { nat: None }),
        Action::Deny => Some(FilterResult::Deny),
        Action::Nat(nat) => Some(FilterResult::Accept {
            nat: Some(NatGrant {
                rule: rule.map(|r| r.id.clone()),
                source: rule.map(|r| r.source.clone()),
                action: nat.clone(),
            }),
        }),
        Action::Jump(_) => None,
    }
}

/// Évalue une politique cible d'un saut (récursif, avec détection de cycle).
/// Rend `None` si aucune règle terminale ne correspond : l'appelant reprend
/// alors à la règle suivante (sémantique des chaînes nftables).
#[allow(clippy::too_many_arguments)]
fn jump_eval(
    device: &Device,
    policy: &Policy,
    pkt: &ConcretePacket,
    point: &FilterPoint,
    stage: Stage,
    stack: &mut Vec<calque_model::PolicyId>,
    decisions: &mut Vec<Decision>,
    allow_partial: bool,
) -> Result<Option<FilterResult>, EvalError> {
    if stack.contains(&policy.id) {
        let mut path = stack.clone();
        path.push(policy.id.clone());
        return Err(EvalError::JumpCycle { path });
    }
    stack.push(policy.id.clone());
    let result = jump_eval_inner(
        device,
        policy,
        pkt,
        point,
        stage,
        stack,
        decisions,
        allow_partial,
    );
    stack.pop();
    result
}

#[allow(clippy::too_many_arguments)]
fn jump_eval_inner(
    device: &Device,
    policy: &Policy,
    pkt: &ConcretePacket,
    point: &FilterPoint,
    stage: Stage,
    stack: &mut Vec<calque_model::PolicyId>,
    decisions: &mut Vec<Decision>,
    allow_partial: bool,
) -> Result<Option<FilterResult>, EvalError> {
    for rule in &policy.rules {
        // Règle sur-approximée atteinte avant toute décision (voir
        // `approximation_blocks`) : verdict non ferme.
        if let Some(e) = approximation_blocks(rule, point, allow_partial) {
            return Err(e);
        }
        if !rule_applies(device, rule, pkt, point, allow_partial)? {
            continue;
        }
        match &rule.action {
            Action::Jump(pid) => {
                let target = device
                    .policies
                    .get(pid)
                    .ok_or_else(|| EvalError::PolicyMissing {
                        policy: pid.clone(),
                    })?;
                let mut sub = Vec::new();
                if let Some(res) = jump_eval(
                    device,
                    target,
                    pkt,
                    point,
                    stage,
                    stack,
                    &mut sub,
                    allow_partial,
                )? {
                    decisions.push(rule_decision(stage, rule, Outcome::Matched));
                    decisions.extend(sub);
                    return Ok(Some(res));
                }
                decisions.push(rule_decision(stage, rule, Outcome::NoMatch));
            }
            action => {
                let outcome = if matches!(action, Action::Deny) {
                    Outcome::Denied
                } else {
                    Outcome::Accepted
                };
                decisions.push(rule_decision(stage, rule, outcome));
                // `terminal_result` ne rend `None` que pour `Jump`,
                // traité au-dessus.
                return Ok(terminal_result(Some(rule), action));
            }
        }
    }
    Ok(None)
}

/// Évalue une politique complète sur un paquet concret.
///
/// Première correspondance gagne ; les règles postérieures qui correspondent
/// aussi reçoivent une décision `Matched` avec `shadowed_by` rempli.
///
/// Équivaut à [`evaluate_policy_opts`] avec `allow_partial = false` : une
/// règle sur-approximée sur le chemin rend `EvalError::ApproximatedRuleOnPath`
/// (verdict non ferme), un objet externe non résolu rend
/// `EvalError::ExternalUnresolved`.
pub fn evaluate_policy(
    device: &Device,
    policy: &Policy,
    pkt: &ConcretePacket,
    point: &FilterPoint,
    stage: Stage,
) -> Result<PolicyEvaluation, EvalError> {
    evaluate_policy_opts(device, policy, pkt, point, stage, false)
}

/// Comme [`evaluate_policy`], mais `allow_partial` (drapeau
/// `--allow-partial`) force l'évaluation sur la partie MODÉLISÉE : les règles
/// sur-approximées sont traitées sur leur correspondance modèle (sans
/// `Unknown`) et les objets externes non résolus comptent comme « ne matchent
/// pas ». Verdict assumé, à n'utiliser que sciemment (§6.3).
pub fn evaluate_policy_opts(
    device: &Device,
    policy: &Policy,
    pkt: &ConcretePacket,
    point: &FilterPoint,
    stage: Stage,
    allow_partial: bool,
) -> Result<PolicyEvaluation, EvalError> {
    let mut decisions = Vec::new();
    let mut diagnostics = Vec::new();
    let mut jump_stack = vec![policy.id.clone()];
    let mut terminal: Option<(usize, FilterResult)> = None;

    for (idx, rule) in policy.rules.iter().enumerate() {
        // Règle sur-approximée atteinte alors qu'aucune règle antérieure
        // pleinement modélisée n'a tranché (sinon on aurait déjà rompu la
        // boucle) : elle est AVANT ou À la décision et peut la changer en
        // réalité → verdict non ferme (voir `approximation_blocks`).
        if let Some(e) = approximation_blocks(rule, point, allow_partial) {
            return Err(e);
        }
        if !rule_applies(device, rule, pkt, point, allow_partial)? {
            continue;
        }
        match &rule.action {
            Action::Jump(pid) => {
                let target = device
                    .policies
                    .get(pid)
                    .ok_or_else(|| EvalError::PolicyMissing {
                        policy: pid.clone(),
                    })?;
                let mut sub = Vec::new();
                if let Some(res) = jump_eval(
                    device,
                    target,
                    pkt,
                    point,
                    stage,
                    &mut jump_stack,
                    &mut sub,
                    allow_partial,
                )? {
                    decisions.push(rule_decision(stage, rule, Outcome::Matched));
                    decisions.extend(sub);
                    terminal = Some((idx, res));
                } else {
                    // La cible n'a rien décidé : on continue après le saut.
                    decisions.push(rule_decision(stage, rule, Outcome::NoMatch));
                }
            }
            action => {
                let outcome = if matches!(action, Action::Deny) {
                    Outcome::Denied
                } else {
                    Outcome::Accepted
                };
                decisions.push(rule_decision(stage, rule, outcome));
                terminal = terminal_result(Some(rule), action).map(|r| (idx, r));
            }
        }
        if terminal.is_some() {
            break;
        }
    }

    let result = match terminal {
        Some((idx, res)) => {
            // Règles postérieures également couvrantes → masquées.
            let mut priors: Vec<RuleId> = vec![policy.rules[idx].id.clone()];
            for later in &policy.rules[idx + 1..] {
                match rule_applies(device, later, pkt, point, allow_partial) {
                    Ok(true) => {
                        decisions.push(Decision {
                            stage,
                            rule: Some(later.id.clone()),
                            source: Some(later.source.clone()),
                            outcome: Outcome::Matched,
                            shadowed_by: priors.clone(),
                        });
                        priors.push(later.id.clone());
                    }
                    Ok(false) => {}
                    // Une règle postérieure irrésoluble n'affecte pas le
                    // verdict : simple avertissement.
                    Err(e) => diagnostics.push(Diagnostic::warning(
                        format!(
                            "règle « {} » ignorée pendant le calcul des règles masquées : {e}",
                            later.id
                        ),
                        Some(later.source.clone()),
                    )),
                }
            }
            res
        }
        None => {
            decisions.push(Decision {
                stage,
                rule: None,
                source: None,
                outcome: Outcome::DefaultAction,
                shadowed_by: Vec::new(),
            });
            match &policy.default_action {
                Action::Accept => FilterResult::Accept { nat: None },
                Action::Deny => FilterResult::Deny,
                Action::Nat(nat) => FilterResult::Accept {
                    nat: Some(NatGrant {
                        rule: None,
                        source: None,
                        action: nat.clone(),
                    }),
                },
                Action::Jump(pid) => {
                    let target =
                        device
                            .policies
                            .get(pid)
                            .ok_or_else(|| EvalError::PolicyMissing {
                                policy: pid.clone(),
                            })?;
                    match jump_eval(
                        device,
                        target,
                        pkt,
                        point,
                        stage,
                        &mut jump_stack,
                        &mut decisions,
                        allow_partial,
                    )? {
                        Some(res) => res,
                        None => {
                            return Err(EvalError::Inconsistent {
                                message: format!(
                                    "l'action par défaut de la politique « {} » saute vers \
                                     « {pid} » qui ne rend aucun verdict",
                                    policy.id
                                ),
                                span: None,
                            })
                        }
                    }
                }
            }
        }
    };

    Ok(PolicyEvaluation {
        decisions,
        diagnostics,
        result,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use calque_model::{
        AddrExpr, DeviceId, PolicyId, PortRange, RuleMatch, Service, ServiceExpr, Vendor,
    };

    fn pkt445() -> ConcretePacket {
        ConcretePacket {
            src: "10.0.10.5".parse().expect("ip"),
            dst: "10.0.20.5".parse().expect("ip"),
            proto: 6,
            sport: 40000,
            dport: 445,
        }
    }

    fn rule(id: &str, action: Action, dport: Option<u16>, line: u32) -> Rule {
        Rule {
            id: RuleId::new(id),
            matches: RuleMatch {
                src: vec![AddrExpr::Net("10.0.10.0/24".parse().expect("net"))],
                dst: Vec::new(),
                services: match dport {
                    Some(p) => vec![ServiceExpr::Service(Service::tcp_dport(PortRange::single(
                        p,
                    )))],
                    None => Vec::new(),
                },
            },
            from: None,
            to: None,
            action,
            source: SourceSpan::new("test.conf", line),
            approximation: None,
        }
    }

    // Helper de test : évalue la politique sur le paquet de référence.
    // (Rien à voir avec un `eval()` dynamique : aucune exécution de code.)
    fn run_policy(policy: &Policy) -> PolicyEvaluation {
        let device = Device::new(DeviceId::new("d"), Vendor::Unknown);
        evaluate_policy(
            &device,
            policy,
            &pkt445(),
            &FilterPoint::Ingress { in_zone: None },
            Stage::IngressFilter,
        )
        .expect("évaluation")
    }

    #[test]
    fn premiere_correspondance_gagne_et_masque_les_suivantes() {
        let policy = Policy {
            id: PolicyId::new("p"),
            rules: vec![
                rule("5", Action::Deny, None, 50),
                rule("10", Action::Accept, Some(445), 100),
                rule("15", Action::Accept, Some(80), 150), // ne correspond pas
            ],
            default_action: Action::Deny,
        };
        let ev = run_policy(&policy);
        assert_eq!(ev.result, FilterResult::Deny);
        // Décision décisive : règle 5.
        assert_eq!(ev.decisions[0].rule, Some(RuleId::new("5")));
        assert_eq!(ev.decisions[0].outcome, Outcome::Denied);
        // Règle 10 : correspond mais masquée par la 5.
        let shadowed = ev
            .decisions
            .iter()
            .find(|d| d.rule == Some(RuleId::new("10")))
            .expect("décision pour la règle 10");
        assert_eq!(shadowed.outcome, Outcome::Matched);
        assert_eq!(shadowed.shadowed_by, vec![RuleId::new("5")]);
        // Règle 15 : ne correspond pas, aucune décision.
        assert!(ev
            .decisions
            .iter()
            .all(|d| d.rule != Some(RuleId::new("15"))));
    }

    #[test]
    fn action_par_defaut_quand_rien_ne_correspond() {
        let policy = Policy {
            id: PolicyId::new("p"),
            rules: vec![rule("10", Action::Accept, Some(80), 100)],
            default_action: Action::Deny,
        };
        let ev = run_policy(&policy);
        assert_eq!(ev.result, FilterResult::Deny);
        assert_eq!(
            ev.decisions.last().map(|d| d.outcome.clone()),
            Some(Outcome::DefaultAction)
        );
        assert_eq!(ev.decisions.last().and_then(|d| d.rule.clone()), None);
    }

    #[test]
    fn cycle_de_sauts_detecte() {
        // p -> q -> p : cycle. La règle de q doit correspondre au paquet
        // pour que le saut soit suivi.
        let mut device = Device::new(DeviceId::new("d"), Vendor::Unknown);
        let q = Policy {
            id: PolicyId::new("q"),
            rules: vec![rule("1", Action::Jump(PolicyId::new("p")), None, 10)],
            default_action: Action::Accept,
        };
        let p = Policy {
            id: PolicyId::new("p"),
            rules: vec![rule("1", Action::Jump(PolicyId::new("q")), None, 20)],
            default_action: Action::Accept,
        };
        device.policies.insert(q.id.clone(), q);
        device.policies.insert(p.id.clone(), p.clone());
        let res = evaluate_policy(
            &device,
            &p,
            &pkt445(),
            &FilterPoint::Ingress { in_zone: None },
            Stage::IngressFilter,
        );
        assert!(matches!(res, Err(EvalError::JumpCycle { .. })));
    }

    #[test]
    fn zone_de_sortie_en_ingress_refusee() {
        let mut r = rule("1", Action::Accept, None, 10);
        r.to = Some(ZoneId::new("wan"));
        let policy = Policy {
            id: PolicyId::new("p"),
            rules: vec![r],
            default_action: Action::Deny,
        };
        let device = Device::new(DeviceId::new("d"), Vendor::Unknown);
        let res = evaluate_policy(
            &device,
            &policy,
            &pkt445(),
            &FilterPoint::Ingress { in_zone: None },
            Stage::IngressFilter,
        );
        assert!(matches!(
            res,
            Err(EvalError::EgressZoneUnknownAtIngress { .. })
        ));
    }
}
