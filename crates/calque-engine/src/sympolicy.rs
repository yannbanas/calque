//! Évaluation SYMBOLIQUE d'une politique ordonnée (§5.3).
//!
//! Même sémantique que `policy.rs` (première correspondance gagne, zones,
//! sauts avec retomber-au-suivant, action par défaut), mais l'entrée est un
//! [`HeaderSet`] : à chaque règle, la part de l'ensemble qui correspond suit
//! l'action de la règle, le reste continue vers la règle suivante
//! (intersection / soustraction). Le résultat est une PARTITION de
//! l'ensemble d'entrée : les parts sont deux à deux disjointes et leur
//! union est l'entrée.
//!
//! Fidélité (§6.3) : toute part non décidable sans deviner (objet manquant,
//! cycle de groupes ou de sauts, règle d'entrée contraignant la zone de
//! sortie, borne [`MAX_CUBES`] atteinte) devient une part `Unknown`
//! accompagnée d'un diagnostic — jamais une supposition.

use calque_model::{Action, Device, Diagnostic, Policy, PolicyId, Rule};
use calque_space::{HeaderSet, HeaderSpace};

use crate::error::EvalError;
use crate::policy::{FilterPoint, NatGrant};
use crate::symbolic::rule_headerset;
use crate::trace::{Decision, Outcome, Stage};

/// Borne du nombre de pavés d'un ensemble en cours d'évaluation.
///
/// La soustraction itérée peut faire croître le nombre de pavés ; sur une
/// politique hostile (règles conçues pour fragmenter), l'évaluation
/// s'interrompt au-delà de cette borne et la part restante devient
/// `Unknown` (documentée par un diagnostic) plutôt que de diverger.
pub const MAX_CUBES: usize = 1024;

/// Le sort d'une part de l'ensemble d'entrée.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SymFilterResult {
    Accept {
        nat: Option<NatGrant>,
    },
    Deny,
    /// Part non décidable sans deviner (§6.3) ; voir `diagnostics`.
    Unknown,
}

/// Une part de la partition : un sous-ensemble, son sort, et la chaîne de
/// décisions qui l'a produit (règle décisive, sauts traversés, action par
/// défaut) — car la trace est le produit (§5.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SymbolicPart {
    pub set: HeaderSet,
    pub result: SymFilterResult,
    pub decisions: Vec<Decision>,
    pub diagnostics: Vec<Diagnostic>,
}

struct EvalCtx<'a> {
    device: &'a Device,
    point: &'a FilterPoint,
    stage: Stage,
}

/// Évalue une politique sur un ensemble : rend la partition complète.
///
/// Les parts sont disjointes et leur union est `input`. Une entrée vide
/// rend une partition vide.
pub fn evaluate_policy_symbolic(
    device: &Device,
    policy: &Policy,
    input: &HeaderSet,
    point: &FilterPoint,
    stage: Stage,
) -> Vec<SymbolicPart> {
    let mut out = Vec::new();
    if input.is_empty() {
        return out;
    }
    let ctx = EvalCtx {
        device,
        point,
        stage,
    };
    let mut stack = vec![policy.id.clone()];
    let remaining = eval_rules(
        &ctx,
        &policy.rules,
        input.clone(),
        &mut stack,
        &[],
        &mut out,
    );
    if remaining.is_empty() {
        return out;
    }

    // --- Action par défaut sur ce qui n'a correspondu à aucune règle ------
    let default_decision = Decision {
        stage,
        rule: None,
        source: None,
        outcome: Outcome::DefaultAction,
        shadowed_by: Vec::new(),
    };
    match &policy.default_action {
        Action::Accept => out.push(SymbolicPart {
            set: remaining,
            result: SymFilterResult::Accept { nat: None },
            decisions: vec![default_decision],
            diagnostics: Vec::new(),
        }),
        Action::Deny => out.push(SymbolicPart {
            set: remaining,
            result: SymFilterResult::Deny,
            decisions: vec![default_decision],
            diagnostics: Vec::new(),
        }),
        Action::Nat(nat) => out.push(SymbolicPart {
            set: remaining,
            result: SymFilterResult::Accept {
                nat: Some(NatGrant {
                    rule: None,
                    source: None,
                    action: nat.clone(),
                }),
            },
            decisions: vec![default_decision],
            diagnostics: Vec::new(),
        }),
        Action::Jump(pid) => match device.policies.get(pid) {
            None => out.push(unknown_part(
                remaining,
                vec![default_decision],
                EvalError::PolicyMissing {
                    policy: pid.clone(),
                }
                .to_diagnostic(),
            )),
            Some(target) => {
                if stack.contains(&target.id) {
                    let mut path = stack.clone();
                    path.push(target.id.clone());
                    out.push(unknown_part(
                        remaining,
                        vec![default_decision],
                        EvalError::JumpCycle { path }.to_diagnostic(),
                    ));
                } else {
                    stack.push(target.id.clone());
                    let undecided = eval_rules(
                        &ctx,
                        &target.rules,
                        remaining,
                        &mut stack,
                        std::slice::from_ref(&default_decision),
                        &mut out,
                    );
                    stack.pop();
                    if !undecided.is_empty() {
                        // Comme le moteur concret : un défaut qui saute vers
                        // une politique muette est une incohérence.
                        out.push(unknown_part(
                            undecided,
                            vec![default_decision],
                            Diagnostic::error(
                                format!(
                                    "l'action par défaut de la politique « {} » saute vers \
                                     « {pid} » qui ne rend aucun verdict",
                                    policy.id
                                ),
                                None,
                            ),
                        ));
                    }
                }
            }
        },
    }
    out
}

/// Parcourt les règles dans l'ordre en découpant `input`. Les parts décidées
/// sont poussées dans `out` (préfixées par `prefix`, la chaîne des sauts
/// traversés) ; le retour est la part NON décidée (retombée de toutes les
/// règles), qui revient à l'appelant (règle suivante ou action par défaut).
fn eval_rules(
    ctx: &EvalCtx<'_>,
    rules: &[Rule],
    input: HeaderSet,
    stack: &mut Vec<PolicyId>,
    prefix: &[Decision],
    out: &mut Vec<SymbolicPart>,
) -> HeaderSet {
    let mut remaining = input;
    for rule in rules {
        if remaining.is_empty() {
            break;
        }
        // Borne anti-fragmentation (voir MAX_CUBES).
        if remaining.cubes().len() > MAX_CUBES {
            out.push(unknown_part(
                remaining,
                prefix.to_vec(),
                Diagnostic::error(
                    format!(
                        "évaluation symbolique interrompue : plus de {MAX_CUBES} pavés \
                         (borne MAX_CUBES)"
                    ),
                    Some(rule.source.clone()),
                ),
            ));
            return HeaderSet::empty();
        }
        if zone_mismatch(rule, ctx.point) {
            continue;
        }
        let hs = match rule_headerset(&ctx.device.objects, &rule.matches) {
            Ok(hs) => hs,
            // Ne jamais deviner : règle irrésoluble → tout ce qui pouvait
            // l'atteindre devient Unknown.
            Err(e) => {
                out.push(unknown_part(
                    remaining,
                    prefix.to_vec(),
                    Diagnostic::error(
                        format!("règle « {} » irrésoluble : {e}", rule.id),
                        Some(rule.source.clone()),
                    ),
                ));
                return HeaderSet::empty();
            }
        };
        let part = remaining.intersect(&hs);
        if part.is_empty() {
            continue;
        }
        // Règle d'ENTRÉE contraignant la zone de sortie : la part touchée
        // est indécidable avant routage (même discipline que policy.rs).
        if matches!(ctx.point, FilterPoint::Ingress { .. }) && rule.to.is_some() {
            let e = EvalError::EgressZoneUnknownAtIngress {
                rule: rule.id.clone(),
                source: rule.source.clone(),
            };
            let mut decisions = prefix.to_vec();
            decisions.push(rule_decision(ctx.stage, rule, Outcome::Matched));
            out.push(unknown_part(part, decisions, e.to_diagnostic()));
            remaining = remaining.subtract(&hs);
            continue;
        }
        match &rule.action {
            Action::Jump(pid) => {
                remaining = remaining.subtract(&hs);
                match ctx.device.policies.get(pid) {
                    None => {
                        let mut decisions = prefix.to_vec();
                        decisions.push(rule_decision(ctx.stage, rule, Outcome::Matched));
                        out.push(unknown_part(
                            part,
                            decisions,
                            EvalError::PolicyMissing {
                                policy: pid.clone(),
                            }
                            .to_diagnostic(),
                        ));
                    }
                    Some(target) => {
                        if stack.contains(&target.id) {
                            let mut path = stack.clone();
                            path.push(target.id.clone());
                            let mut decisions = prefix.to_vec();
                            decisions.push(rule_decision(ctx.stage, rule, Outcome::Matched));
                            out.push(unknown_part(
                                part,
                                decisions,
                                EvalError::JumpCycle { path }.to_diagnostic(),
                            ));
                        } else {
                            stack.push(target.id.clone());
                            let mut sub_prefix = prefix.to_vec();
                            sub_prefix.push(rule_decision(ctx.stage, rule, Outcome::Matched));
                            let undecided =
                                eval_rules(ctx, &target.rules, part, stack, &sub_prefix, out);
                            stack.pop();
                            // La part non décidée par la cible retombe à la
                            // règle suivante (sémantique des chaînes).
                            remaining = remaining.union(&undecided);
                        }
                    }
                }
            }
            Action::Accept => {
                let mut decisions = prefix.to_vec();
                decisions.push(rule_decision(ctx.stage, rule, Outcome::Accepted));
                out.push(SymbolicPart {
                    set: part,
                    result: SymFilterResult::Accept { nat: None },
                    decisions,
                    diagnostics: Vec::new(),
                });
                remaining = remaining.subtract(&hs);
            }
            Action::Deny => {
                let mut decisions = prefix.to_vec();
                decisions.push(rule_decision(ctx.stage, rule, Outcome::Denied));
                out.push(SymbolicPart {
                    set: part,
                    result: SymFilterResult::Deny,
                    decisions,
                    diagnostics: Vec::new(),
                });
                remaining = remaining.subtract(&hs);
            }
            Action::Nat(nat) => {
                let mut decisions = prefix.to_vec();
                decisions.push(rule_decision(ctx.stage, rule, Outcome::Accepted));
                out.push(SymbolicPart {
                    set: part,
                    result: SymFilterResult::Accept {
                        nat: Some(NatGrant {
                            rule: Some(rule.id.clone()),
                            source: Some(rule.source.clone()),
                            action: nat.clone(),
                        }),
                    },
                    decisions,
                    diagnostics: Vec::new(),
                });
                remaining = remaining.subtract(&hs);
            }
        }
    }
    remaining
}

/// La règle est-elle hors de portée à ce point du pipeline (zones) ?
/// Même clé de partition que `policy.rs` : `from` connue partout, `to`
/// seulement en sortie (le cas `to` en entrée est traité par l'appelant).
fn zone_mismatch(rule: &Rule, point: &FilterPoint) -> bool {
    let in_zone = match point {
        FilterPoint::Ingress { in_zone } | FilterPoint::Egress { in_zone, .. } => in_zone.as_ref(),
    };
    if let Some(from) = &rule.from {
        if in_zone != Some(from) {
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

fn rule_decision(stage: Stage, rule: &Rule, outcome: Outcome) -> Decision {
    Decision {
        stage,
        rule: Some(rule.id.clone()),
        source: Some(rule.source.clone()),
        outcome,
        shadowed_by: Vec::new(),
    }
}

fn unknown_part(set: HeaderSet, decisions: Vec<Decision>, diag: Diagnostic) -> SymbolicPart {
    SymbolicPart {
        set,
        result: SymFilterResult::Unknown,
        decisions,
        diagnostics: vec![diag],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{net, rule, tcp, tcp_svc};
    use calque_model::{AddrExpr, DeviceId, RuleId, Vendor};
    use calque_space::{Cube, PortRanges, PrefixSet, ProtoSet};

    fn input_lan() -> HeaderSet {
        HeaderSet::from_cube(Cube::new(
            PrefixSet::from_net(net("10.0.10.0/24")),
            PrefixSet::full(),
            ProtoSet::full(),
            PortRanges::full(),
            PortRanges::full(),
        ))
    }

    fn assert_partition(input: &HeaderSet, parts: &[SymbolicPart]) {
        let mut union = HeaderSet::empty();
        for (i, p) in parts.iter().enumerate() {
            for q in &parts[i + 1..] {
                assert!(
                    p.set.intersect(&q.set).is_empty(),
                    "parts non disjointes : {:?} / {:?}",
                    p.set,
                    q.set
                );
            }
            union = union.union(&p.set);
        }
        assert!(
            union.contains_set(input) && input.contains_set(&union),
            "la partition ne couvre pas l'entrée"
        );
    }

    fn part_for<'a>(
        parts: &'a [SymbolicPart],
        pkt: &calque_model::ConcretePacket,
    ) -> &'a SymbolicPart {
        parts
            .iter()
            .find(|p| p.set.contains(pkt))
            .expect("une part doit contenir le paquet")
    }

    #[test]
    fn partition_ordonnee_couvre_l_entree() {
        let device = Device::new(DeviceId::new("d"), Vendor::Unknown);
        let policy = Policy {
            id: PolicyId::new("p"),
            rules: vec![
                rule(
                    "5",
                    vec![],
                    vec![],
                    vec![tcp_svc(23)],
                    None,
                    None,
                    Action::Deny,
                    50,
                ),
                rule(
                    "10",
                    vec![],
                    vec![AddrExpr::Net(net("10.0.20.5/32"))],
                    vec![],
                    None,
                    None,
                    Action::Accept,
                    100,
                ),
            ],
            default_action: Action::Deny,
        };
        let input = input_lan();
        let parts = evaluate_policy_symbolic(
            &device,
            &policy,
            &input,
            &FilterPoint::Ingress { in_zone: None },
            Stage::IngressFilter,
        );
        assert_partition(&input, &parts);

        // telnet → refusé par la règle 5, même vers 10.0.20.5.
        let p = part_for(&parts, &tcp("10.0.10.5", "10.0.20.5", 23));
        assert_eq!(p.result, SymFilterResult::Deny);
        assert_eq!(
            p.decisions.last().and_then(|d| d.rule.clone()),
            Some(RuleId::new("5"))
        );

        // smb vers 10.0.20.5 → accepté par la règle 10.
        let p = part_for(&parts, &tcp("10.0.10.5", "10.0.20.5", 445));
        assert_eq!(p.result, SymFilterResult::Accept { nat: None });
        assert_eq!(
            p.decisions.last().and_then(|d| d.rule.clone()),
            Some(RuleId::new("10"))
        );

        // smb ailleurs → action par défaut (refus).
        let p = part_for(&parts, &tcp("10.0.10.5", "10.0.30.5", 445));
        assert_eq!(p.result, SymFilterResult::Deny);
        assert_eq!(
            p.decisions.last().map(|d| d.outcome.clone()),
            Some(Outcome::DefaultAction)
        );
    }

    #[test]
    fn saut_symbolique_avec_retombee() {
        let mut device = Device::new(DeviceId::new("d"), Vendor::Unknown);
        // q n'accepte que le port 445 ; le reste retombe dans p.
        let q = Policy {
            id: PolicyId::new("q"),
            rules: vec![rule(
                "q1",
                vec![],
                vec![],
                vec![tcp_svc(445)],
                None,
                None,
                Action::Accept,
                10,
            )],
            default_action: Action::Deny, // ignorée lors d'un saut
        };
        let p = Policy {
            id: PolicyId::new("p"),
            rules: vec![rule(
                "p1",
                vec![],
                vec![AddrExpr::Net(net("10.0.20.0/24"))],
                vec![],
                None,
                None,
                Action::Jump(PolicyId::new("q")),
                20,
            )],
            default_action: Action::Deny,
        };
        device.policies.insert(q.id.clone(), q);
        device.policies.insert(p.id.clone(), p.clone());
        let input = input_lan();
        let parts = evaluate_policy_symbolic(
            &device,
            &p,
            &input,
            &FilterPoint::Ingress { in_zone: None },
            Stage::IngressFilter,
        );
        assert_partition(&input, &parts);

        // 445 vers 10.0.20.0/24 : décidé DANS q, chaîne p1 (Matched) puis q1.
        let acc = part_for(&parts, &tcp("10.0.10.5", "10.0.20.9", 445));
        assert_eq!(acc.result, SymFilterResult::Accept { nat: None });
        let ids: Vec<_> = acc
            .decisions
            .iter()
            .filter_map(|d| d.rule.clone())
            .collect();
        assert_eq!(ids, vec![RuleId::new("p1"), RuleId::new("q1")]);

        // 80 vers 10.0.20.0/24 : q muette → retombe → défaut de p (refus).
        let deny = part_for(&parts, &tcp("10.0.10.5", "10.0.20.9", 80));
        assert_eq!(deny.result, SymFilterResult::Deny);
        assert_eq!(
            deny.decisions.last().map(|d| d.outcome.clone()),
            Some(Outcome::DefaultAction)
        );
    }

    #[test]
    fn cycle_de_sauts_rend_unknown() {
        let mut device = Device::new(DeviceId::new("d"), Vendor::Unknown);
        let q = Policy {
            id: PolicyId::new("q"),
            rules: vec![rule(
                "q1",
                vec![],
                vec![],
                vec![],
                None,
                None,
                Action::Jump(PolicyId::new("p")),
                10,
            )],
            default_action: Action::Accept,
        };
        let p = Policy {
            id: PolicyId::new("p"),
            rules: vec![rule(
                "p1",
                vec![],
                vec![],
                vec![],
                None,
                None,
                Action::Jump(PolicyId::new("q")),
                20,
            )],
            default_action: Action::Accept,
        };
        device.policies.insert(q.id.clone(), q);
        device.policies.insert(p.id.clone(), p.clone());
        let input = input_lan();
        let parts = evaluate_policy_symbolic(
            &device,
            &p,
            &input,
            &FilterPoint::Ingress { in_zone: None },
            Stage::IngressFilter,
        );
        assert_partition(&input, &parts);
        assert!(parts.iter().all(|p| p.result == SymFilterResult::Unknown));
        assert!(parts
            .iter()
            .flat_map(|p| &p.diagnostics)
            .any(|d| d.message.contains("cycle")));
    }
}
