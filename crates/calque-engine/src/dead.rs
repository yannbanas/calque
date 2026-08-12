//! Règles mortes et masquées (S6).
//!
//! Pour chaque politique d'un équipement, une règle dont le pavé
//! ([`rule_headerset`]) est entièrement couvert par l'UNION des règles
//! antérieures est morte : aucune correspondance ne peut l'atteindre
//! (première correspondance gagne, §3.3). Une règle au pavé VIDE (objets
//! vides) est morte aussi, dans une catégorie distincte.
//!
//! Précisions de sémantique :
//! - **zones** : une règle antérieure ne compte comme masque que si elle
//!   s'applique dans TOUS les contextes de zones où la victime s'applique
//!   (même clé de partition que `policy.rs` : `from` antérieur absent ou
//!   égal, idem `to`) — deux règles à zones incompatibles ne se masquent
//!   pas ;
//! - **sauts** : une règle antérieure `Jump` peut retomber sans verdict,
//!   elle ne consomme donc pas le trafic et n'est PAS comptée comme masque
//!   (choix prudent : moins de règles déclarées mortes, jamais à tort) ;
//! - `masked_by` liste les règles masquantes dont l'intersection avec la
//!   victime est non vide, et `sample` donne un paquet concret masqué
//!   (échantillon de l'intersection, §4.1).
//!
//! Borne (entrées hostiles) : si l'union des masques dépasse
//! [`MAX_UNION_CUBES`] pavés, l'analyse s'abstient pour cette règle (elle
//! n'est PAS déclarée morte) : abstention sûre, jamais un faux positif.
//!
//! Fidélité (§6.3) : une règle irrésoluble (objet manquant, cycle) rend
//! une erreur — pas de rapport partiellement deviné.

use calque_model::{Action, ConcretePacket, Device, PolicyId, Rule, RuleId, SourceSpan};
use calque_space::{HeaderSet, HeaderSpace};
use serde::{Deserialize, Serialize};

use crate::error::EvalError;
use crate::symbolic::rule_headerset;

/// Borne du nombre de pavés de l'union des masques : au-delà, abstention
/// (sûre) pour la règle en cours d'analyse.
pub const MAX_UNION_CUBES: usize = 2048;

/// Pourquoi la règle est morte.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeadRuleKind {
    /// Le pavé de la règle est vide (objets ou groupes vides) : elle ne
    /// peut correspondre à aucun paquet.
    EmptySet,
    /// Entièrement couverte par l'union des règles antérieures.
    Shadowed,
}

/// Une règle masquante : identifiant et origine de configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Masker {
    pub rule: RuleId,
    pub source: SourceSpan,
}

/// Une règle morte, avec sa justification complète (la trace est le
/// produit, §5.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeadRule {
    pub policy: PolicyId,
    pub rule: RuleId,
    /// Fichier + ligne de la règle morte.
    pub source: SourceSpan,
    pub kind: DeadRuleKind,
    /// Les règles antérieures qui la masquent (intersection non vide).
    /// Vide pour `EmptySet`.
    pub masked_by: Vec<Masker>,
    /// Un paquet concret que la règle aurait traité mais qu'un masque
    /// capte avant elle. `None` pour `EmptySet`.
    pub sample: Option<ConcretePacket>,
}

/// Détecte les règles mortes de TOUTES les politiques de l'équipement.
///
/// Les politiques sont analysées indépendamment (y compris les cibles de
/// sauts, qui sont des politiques de l'équipement comme les autres).
pub fn dead_rules(device: &Device) -> Result<Vec<DeadRule>, EvalError> {
    let mut out = Vec::new();
    for policy in device.policies.values() {
        // Résolution unique de chaque pavé (les objets sont résolus tard,
        // §3.3) ; toute règle irrésoluble interrompt honnêtement l'analyse.
        let mut sets = Vec::with_capacity(policy.rules.len());
        for rule in &policy.rules {
            sets.push(rule_headerset(&device.objects, &rule.matches)?);
        }
        for (i, rule) in policy.rules.iter().enumerate() {
            let hs = &sets[i];
            if hs.is_empty() {
                out.push(DeadRule {
                    policy: policy.id.clone(),
                    rule: rule.id.clone(),
                    source: rule.source.clone(),
                    kind: DeadRuleKind::EmptySet,
                    masked_by: Vec::new(),
                    sample: None,
                });
                continue;
            }
            let mut cover = HeaderSet::empty();
            let mut maskers = Vec::new();
            let mut abstained = false;
            for (j, prior) in policy.rules.iter().enumerate().take(i) {
                // Un saut peut retomber sans verdict : il ne masque pas.
                if matches!(prior.action, Action::Jump(_)) {
                    continue;
                }
                if !zone_covers(prior, rule) {
                    continue;
                }
                // Test de disjonction direct (sans construire l'intersection) :
                // c'est le test exécuté n²/2 fois, il doit rester bon marché.
                if hs.is_disjoint(&sets[j]) {
                    continue;
                }
                maskers.push(Masker {
                    rule: prior.id.clone(),
                    source: prior.source.clone(),
                });
                cover = cover.union(&sets[j]);
                if cover.cubes().len() > MAX_UNION_CUBES {
                    abstained = true;
                    break;
                }
            }
            if abstained || maskers.is_empty() {
                continue;
            }
            if cover.contains_set(hs) {
                // La règle est morte : un paquet témoin de l'intersection
                // (= tout le pavé, puisqu'il est couvert).
                let sample = hs.intersect(&cover).sample();
                out.push(DeadRule {
                    policy: policy.id.clone(),
                    rule: rule.id.clone(),
                    source: rule.source.clone(),
                    kind: DeadRuleKind::Shadowed,
                    masked_by: maskers,
                    sample,
                });
            }
        }
    }
    Ok(out)
}

/// La règle antérieure s'applique-t-elle dans TOUS les contextes de zones
/// de la victime ? (`from`/`to` absents = tout contexte ; même clé de
/// partition que `policy.rs`.)
fn zone_covers(masker: &Rule, victim: &Rule) -> bool {
    let from_ok = masker.from.is_none() || masker.from == victim.from;
    let to_ok = masker.to.is_none() || masker.to == victim.to;
    from_ok && to_ok
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{net, rule};
    use calque_model::{AddrExpr, AddrObject, DeviceId, ObjectId, Policy, RuleMatch, Vendor};

    fn device_with(rules: Vec<Rule>) -> Device {
        let mut d = Device::new(DeviceId::new("fw1"), Vendor::Fortigate);
        let pid = PolicyId::new("p");
        d.policies.insert(
            pid.clone(),
            Policy {
                id: pid,
                rules,
                default_action: Action::Deny,
            },
        );
        d
    }

    fn find<'a>(dead: &'a [DeadRule], id: &str) -> Option<&'a DeadRule> {
        dead.iter().find(|d| d.rule == RuleId::new(id))
    }

    /// (e) Une règle strictement incluse dans une antérieure est morte,
    /// avec le bon masque et un paquet témoin valide ; une règle
    /// partiellement chevauchée ne l'est PAS.
    #[test]
    fn inclusion_stricte_morte_chevauchement_partiel_vivante() {
        let r10 = rule(
            "10",
            vec![AddrExpr::Net(net("10.0.10.0/24"))],
            vec![],
            vec![],
            None,
            None,
            Action::Accept,
            100,
        );
        let r20 = rule(
            "20",
            vec![AddrExpr::Net(net("10.0.10.128/25"))],
            vec![],
            vec![],
            None,
            None,
            Action::Deny,
            200,
        );
        let r30 = rule(
            "30",
            vec![AddrExpr::Net(net("10.0.0.0/16"))],
            vec![],
            vec![],
            None,
            None,
            Action::Deny,
            300,
        );
        let device = device_with(vec![r10.clone(), r20, r30]);
        let dead = dead_rules(&device).expect("analyse");

        // 20 ⊂ 10 : morte, masquée par la 10 seule, témoin valide.
        let d20 = find(&dead, "20").expect("règle 20 morte");
        assert_eq!(d20.kind, DeadRuleKind::Shadowed);
        // Le span pointe la règle morte elle-même (fichier + ligne).
        assert_eq!(d20.source, crate::testutil::span(200));
        let _ = r10; // (garde la règle nommée pour la lisibilité du test)
        let maskers: Vec<&RuleId> = d20.masked_by.iter().map(|m| &m.rule).collect();
        assert_eq!(maskers, vec![&RuleId::new("10")]);
        let sample = d20.sample.expect("paquet témoin");
        let hs20 = rule_headerset(
            &device.objects,
            &RuleMatch {
                src: vec![AddrExpr::Net(net("10.0.10.128/25"))],
                dst: vec![],
                services: vec![],
            },
        )
        .expect("pavé 20");
        let hs10 = rule_headerset(
            &device.objects,
            &RuleMatch {
                src: vec![AddrExpr::Net(net("10.0.10.0/24"))],
                dst: vec![],
                services: vec![],
            },
        )
        .expect("pavé 10");
        assert!(hs20.contains(&sample) && hs10.contains(&sample));

        // 30 chevauche 10 sans être incluse : PAS morte.
        assert!(find(&dead, "30").is_none());
        // 10 n'a aucune antérieure : PAS morte.
        assert!(find(&dead, "10").is_none());
    }

    /// Une règle au pavé vide (objet vide) est morte, catégorie distincte.
    #[test]
    fn objet_vide_categorie_distincte() {
        let mut device = device_with(vec![rule(
            "40",
            vec![AddrExpr::Object(ObjectId::new("VIDE"))],
            vec![],
            vec![],
            None,
            None,
            Action::Accept,
            400,
        )]);
        device
            .objects
            .addresses
            .insert(ObjectId::new("VIDE"), AddrObject::Nets(Vec::new()));
        let dead = dead_rules(&device).expect("analyse");
        let d = find(&dead, "40").expect("règle 40 morte");
        assert_eq!(d.kind, DeadRuleKind::EmptySet);
        assert!(d.masked_by.is_empty() && d.sample.is_none());
    }

    /// Zones from/to incompatibles : pas de masquage.
    #[test]
    fn zones_incompatibles_ne_masquent_pas() {
        // r1 (from lan) couvre tout src, mais r2 est limitée à from guest :
        // r1 ne s'applique pas dans le contexte guest → r2 vivante.
        let rules = vec![
            rule(
                "1",
                vec![],
                vec![],
                vec![],
                Some("lan"),
                None,
                Action::Deny,
                10,
            ),
            rule(
                "2",
                vec![AddrExpr::Net(net("10.0.10.0/24"))],
                vec![],
                vec![],
                Some("guest"),
                None,
                Action::Accept,
                20,
            ),
        ];
        let device = device_with(rules);
        let dead = dead_rules(&device).expect("analyse");
        assert!(find(&dead, "2").is_none());

        // À l'inverse, un masque SANS zone couvre tous les contextes :
        // une victime zonée est bien morte.
        let rules = vec![
            rule("1", vec![], vec![], vec![], None, None, Action::Deny, 10),
            rule(
                "2",
                vec![AddrExpr::Net(net("10.0.10.0/24"))],
                vec![],
                vec![],
                Some("guest"),
                None,
                Action::Accept,
                20,
            ),
        ];
        let device = device_with(rules);
        let dead = dead_rules(&device).expect("analyse");
        let d = find(&dead, "2").expect("règle 2 morte");
        assert_eq!(d.kind, DeadRuleKind::Shadowed);
    }

    /// Une règle antérieure `Jump` ne masque pas (elle peut retomber).
    #[test]
    fn saut_anterieur_ne_masque_pas() {
        let rules = vec![
            rule(
                "1",
                vec![],
                vec![],
                vec![],
                None,
                None,
                Action::Jump(PolicyId::new("q")),
                10,
            ),
            rule(
                "2",
                vec![AddrExpr::Net(net("10.0.10.0/24"))],
                vec![],
                vec![],
                None,
                None,
                Action::Accept,
                20,
            ),
        ];
        let device = device_with(rules);
        let dead = dead_rules(&device).expect("analyse");
        assert!(find(&dead, "2").is_none());
    }

    /// Une règle irrésoluble rend une erreur, jamais un rapport deviné.
    #[test]
    fn regle_irresoluble_rend_une_erreur() {
        let device = device_with(vec![rule(
            "1",
            vec![AddrExpr::Object(ObjectId::new("ABSENT"))],
            vec![],
            vec![],
            None,
            None,
            Action::Accept,
            10,
        )]);
        assert!(matches!(
            dead_rules(&device),
            Err(EvalError::AddrObjectMissing { .. })
        ));
    }

    /// Le masquage peut être COLLECTIF : deux moitiés antérieures couvrent
    /// ensemble la victime.
    #[test]
    fn masquage_collectif_par_union() {
        let rules = vec![
            rule(
                "1",
                vec![AddrExpr::Net(net("10.0.10.0/25"))],
                vec![],
                vec![],
                None,
                None,
                Action::Deny,
                10,
            ),
            rule(
                "2",
                vec![AddrExpr::Net(net("10.0.10.128/25"))],
                vec![],
                vec![],
                None,
                None,
                Action::Deny,
                20,
            ),
            rule(
                "3",
                vec![AddrExpr::Net(net("10.0.10.0/24"))],
                vec![],
                vec![],
                None,
                None,
                Action::Accept,
                30,
            ),
        ];
        let device = device_with(rules);
        let dead = dead_rules(&device).expect("analyse");
        let d = find(&dead, "3").expect("règle 3 morte");
        let maskers: Vec<&RuleId> = d.masked_by.iter().map(|m| &m.rule).collect();
        assert_eq!(maskers, vec![&RuleId::new("1"), &RuleId::new("2")]);
        assert!(d.sample.is_some());
    }
}
