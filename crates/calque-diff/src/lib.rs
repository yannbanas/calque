//! calque-diff — comparaison de deux modèles de réseau.
//!
//! Crate PUR (règle §1 de CALQUE-ARCHITECTURE.md) : données en entrée,
//! données en sortie, aucune entrée-sortie.
//!
//! C'est le socle de `calque plan` (§10.2), qui répond à « qu'est-ce qui
//! casse si j'applique ce changement ? ». La comparaison se fait en deux
//! temps :
//!
//! 1. **Comparaison structurelle** — implémentée ici : [`diff_networks`]
//!    produit un [`ModelDelta`] qui liste les équipements, interfaces,
//!    routes, objets et politiques ajoutés, retirés ou modifiés entre
//!    deux [`Network`]. Tous les types de `calque-model` sont `Eq`, la
//!    comparaison est donc exacte et déterministe.
//!
//! 2. **Comparaison de comportement** (S4) — implémentée dans [`plan`] :
//!    [`plan::plan`] rejoue chaque flux déclaré (`flows.yaml`) sur le
//!    modèle courant et sur le modèle candidat via `calque-engine`, puis
//!    classe les écarts dans un [`PlanReport`] : flux rompus, corrigés,
//!    changés, indécis, ouvertures nouvelles non déclarées (détection par
//!    SONDES, heuristique bornée et documentée — voir le rustdoc de
//!    [`plan`]), flux inchangés. Chaque écart porte sa justification
//!    avant/après : verdict + règle décisive (identifiant et
//!    fichier/ligne), car la trace est le produit (§5.2).

use std::collections::BTreeMap;

use calque_model::{
    Action, AddrObject, Device, DeviceId, IfaceId, Interface, Link, Network, ObjectId, Pipeline,
    Policy, PolicyId, Route, Rule, RuleId, ServiceObject, Vendor, VrfId, ZoneId,
};
use serde::{Deserialize, Serialize};

pub mod plan;

pub use plan::{
    plan, FlowDelta, FlowStatus, Justification, NewOpening, PlanReport, ResolvedFlow, UndecidedFlow,
};

// ---------------------------------------------------------------------------
// Le changement élémentaire
// ---------------------------------------------------------------------------

/// Un changement sur un élément identifié : ajouté, retiré, ou modifié
/// (avec les deux valeurs, pour que le rapport puisse expliquer).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Change<T> {
    Added(T),
    Removed(T),
    Modified { before: T, after: T },
}

impl<T> Change<T> {
    pub fn is_added(&self) -> bool {
        matches!(self, Change::Added(_))
    }
    pub fn is_removed(&self) -> bool {
        matches!(self, Change::Removed(_))
    }
    pub fn is_modified(&self) -> bool {
        matches!(self, Change::Modified { .. })
    }
}

/// Différence de deux `BTreeMap` clé par clé. Les valeurs égales (`Eq`)
/// ne produisent rien.
fn diff_map<K, V>(before: &BTreeMap<K, V>, after: &BTreeMap<K, V>) -> Vec<(K, Change<V>)>
where
    K: Ord + Clone,
    V: Eq + Clone,
{
    let mut out = Vec::new();
    for (k, vb) in before {
        match after.get(k) {
            None => out.push((k.clone(), Change::Removed(vb.clone()))),
            Some(va) if va != vb => out.push((
                k.clone(),
                Change::Modified {
                    before: vb.clone(),
                    after: va.clone(),
                },
            )),
            Some(_) => {}
        }
    }
    for (k, va) in after {
        if !before.contains_key(k) {
            out.push((k.clone(), Change::Added(va.clone())));
        }
    }
    out
}

/// Différence de deux séquences vues comme des MULTI-ensembles :
/// renvoie `(ajoutés, retirés)`. Chaque occurrence compte une fois, et
/// l'ordre d'origine est préservé dans les deux sorties.
///
/// Décompte via `BTreeMap` : O(n log n). L'ancienne version appariait par
/// balayage linéaire avec `Vec::remove` — quadratique, donc un déni de
/// service sur un modèle hostile aux dizaines de milliers de routes
/// (§11.3 : `calque plan` rejoue des configurations non fiables).
fn diff_multiset<T: Ord + Clone>(before: &[T], after: &[T]) -> (Vec<T>, Vec<T>) {
    let mut surplus: BTreeMap<&T, usize> = BTreeMap::new();
    for a in after {
        *surplus.entry(a).or_default() += 1;
    }
    let mut removed = Vec::new();
    for b in before {
        match surplus.get_mut(b) {
            Some(n) if *n > 0 => *n -= 1,
            _ => removed.push(b.clone()),
        }
    }
    // Ce qui reste en surplus côté `after` a été ajouté ; les occurrences
    // d'un même élément étant indiscernables, consommer les premières
    // rencontrées préserve un ordre déterministe.
    let mut added = Vec::new();
    for a in after {
        if let Some(n) = surplus.get_mut(a) {
            if *n > 0 {
                *n -= 1;
                added.push(a.clone());
            }
        }
    }
    (added, removed)
}

// ---------------------------------------------------------------------------
// Delta structurel
// ---------------------------------------------------------------------------

/// Différence structurelle entre deux [`Network`]. Produit par
/// [`diff_networks`]. Exhaustif au sens de `Eq` : si le delta est vide,
/// les deux modèles sont identiques.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelDelta {
    pub devices_added: Vec<DeviceId>,
    pub devices_removed: Vec<DeviceId>,
    /// Équipements présents des deux côtés mais différents.
    pub devices_changed: BTreeMap<DeviceId, DeviceDelta>,
    pub links_added: Vec<Link>,
    pub links_removed: Vec<Link>,
}

impl ModelDelta {
    /// Vrai si les deux modèles sont structurellement identiques.
    pub fn is_empty(&self) -> bool {
        self.devices_added.is_empty()
            && self.devices_removed.is_empty()
            && self.devices_changed.is_empty()
            && self.links_added.is_empty()
            && self.links_removed.is_empty()
    }
}

/// Différence entre deux versions d'un même équipement.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceDelta {
    /// `Some((avant, après))` si le constructeur détecté a changé.
    pub vendor_changed: Option<(Vendor, Vendor)>,
    pub interfaces: Vec<(IfaceId, Change<Interface>)>,
    /// Affectation des interfaces aux zones.
    pub zones: Vec<(ZoneId, Change<Vec<IfaceId>>)>,
    /// Tables de routage : VRF ajoutés/retirés et routes modifiées.
    pub vrfs: Vec<(VrfId, VrfChange)>,
    /// Objets adresse (groupes compris) — résolus tard (§3.3), donc un
    /// changement d'objet peut changer le comportement de N règles.
    pub addr_objects: Vec<(ObjectId, Change<AddrObject>)>,
    /// Objets service.
    pub service_objects: Vec<(ObjectId, Change<ServiceObject>)>,
    pub policies: Vec<(PolicyId, PolicyChange)>,
    /// `Some((avant, après))` si l'accrochage des politiques a changé.
    pub pipeline_changed: Option<(Pipeline, Pipeline)>,
}

impl DeviceDelta {
    pub fn is_empty(&self) -> bool {
        self.vendor_changed.is_none()
            && self.interfaces.is_empty()
            && self.zones.is_empty()
            && self.vrfs.is_empty()
            && self.addr_objects.is_empty()
            && self.service_objects.is_empty()
            && self.policies.is_empty()
            && self.pipeline_changed.is_none()
    }
}

/// Changement sur un VRF : apparition, disparition, ou routes modifiées.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VrfChange {
    Added {
        routes: Vec<Route>,
    },
    Removed {
        routes: Vec<Route>,
    },
    Modified {
        routes_added: Vec<Route>,
        routes_removed: Vec<Route>,
    },
}

/// Changement sur une politique de filtrage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicyChange {
    Added(Policy),
    Removed(Policy),
    Modified(PolicyDelta),
}

/// Différence fine entre deux versions d'une même politique.
///
/// Les règles sont appariées par [`RuleId`] (l'identifiant chez le
/// constructeur). ATTENTION : l'ordre des règles est sémantique (§3.3,
/// première correspondance gagne) — deux politiques aux règles
/// identiques mais réordonnées ont un comportement différent, d'où le
/// champ [`rules_reordered`](Self::rules_reordered).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyDelta {
    /// `Some((avant, après))` si l'action par défaut a changé.
    pub default_action_changed: Option<(Action, Action)>,
    /// Règles ajoutées, retirées ou modifiées, appariées par identifiant.
    pub rules: Vec<(RuleId, Change<Rule>)>,
    /// Vrai si l'ordre relatif des règles communes aux deux versions a
    /// changé — même sans ajout ni retrait, le comportement peut changer.
    pub rules_reordered: bool,
}

impl PolicyDelta {
    pub fn is_empty(&self) -> bool {
        self.default_action_changed.is_none() && self.rules.is_empty() && !self.rules_reordered
    }
}

// ---------------------------------------------------------------------------
// diff_networks
// ---------------------------------------------------------------------------

/// Compare deux modèles de réseau et liste toutes les différences
/// structurelles. Déterministe : les identifiants sortent triés
/// (`BTreeMap`), deux appels sur les mêmes données donnent le même delta.
pub fn diff_networks(before: &Network, after: &Network) -> ModelDelta {
    let mut delta = ModelDelta::default();

    for (id, change) in diff_map(&before.devices, &after.devices) {
        match change {
            Change::Added(_) => delta.devices_added.push(id),
            Change::Removed(_) => delta.devices_removed.push(id),
            Change::Modified { before, after } => {
                let d = diff_devices(&before, &after);
                debug_assert!(!d.is_empty(), "Device != mais delta vide");
                delta.devices_changed.insert(id, d);
            }
        }
    }

    let (links_added, links_removed) = diff_multiset(&before.links, &after.links);
    delta.links_added = links_added;
    delta.links_removed = links_removed;

    delta
}

/// Compare deux versions d'un même équipement.
pub fn diff_devices(before: &Device, after: &Device) -> DeviceDelta {
    let mut d = DeviceDelta {
        vendor_changed: (before.vendor != after.vendor).then_some((before.vendor, after.vendor)),
        interfaces: diff_map(&before.interfaces, &after.interfaces),
        zones: diff_map(&before.zones, &after.zones),
        vrfs: Vec::new(),
        addr_objects: diff_map(&before.objects.addresses, &after.objects.addresses),
        service_objects: diff_map(&before.objects.services, &after.objects.services),
        policies: Vec::new(),
        pipeline_changed: (before.pipeline != after.pipeline)
            .then(|| (before.pipeline.clone(), after.pipeline.clone())),
    };

    for (id, change) in diff_map(&before.vrfs, &after.vrfs) {
        let vc = match change {
            Change::Added(v) => VrfChange::Added { routes: v.routes },
            Change::Removed(v) => VrfChange::Removed { routes: v.routes },
            Change::Modified { before, after } => {
                let (routes_added, routes_removed) = diff_multiset(&before.routes, &after.routes);
                VrfChange::Modified {
                    routes_added,
                    routes_removed,
                }
            }
        };
        d.vrfs.push((id, vc));
    }

    for (id, change) in diff_map(&before.policies, &after.policies) {
        let pc = match change {
            Change::Added(p) => PolicyChange::Added(p),
            Change::Removed(p) => PolicyChange::Removed(p),
            Change::Modified { before, after } => {
                PolicyChange::Modified(diff_policies(&before, &after))
            }
        };
        d.policies.push((id, pc));
    }

    d
}

/// Compare deux versions d'une même politique, règle par règle.
pub fn diff_policies(before: &Policy, after: &Policy) -> PolicyDelta {
    let before_rules: BTreeMap<RuleId, Rule> = before
        .rules
        .iter()
        .map(|r| (r.id.clone(), r.clone()))
        .collect();
    let after_rules: BTreeMap<RuleId, Rule> = after
        .rules
        .iter()
        .map(|r| (r.id.clone(), r.clone()))
        .collect();

    // Ordre relatif des règles communes aux deux versions : s'il change,
    // le comportement peut changer même à contenu identique (§3.3).
    let common_before: Vec<&RuleId> = before
        .rules
        .iter()
        .map(|r| &r.id)
        .filter(|id| after_rules.contains_key(*id))
        .collect();
    let common_after: Vec<&RuleId> = after
        .rules
        .iter()
        .map(|r| &r.id)
        .filter(|id| before_rules.contains_key(*id))
        .collect();

    PolicyDelta {
        default_action_changed: (before.default_action != after.default_action)
            .then(|| (before.default_action.clone(), after.default_action.clone())),
        rules: diff_map(&before_rules, &after_rules),
        rules_reordered: common_before != common_after,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use calque_model::{AddrExpr, AdminState, NextHop, RouteOrigin, RuleMatch, SourceSpan, Vrf};

    fn iface(id: &str, addr: &str) -> Interface {
        let mut i = Interface::new(IfaceId::from(id));
        i.addrs.push(addr.parse().unwrap());
        i
    }

    fn rule(id: &str, action: Action, line: u32) -> Rule {
        Rule {
            id: RuleId::from(id),
            matches: RuleMatch::default(),
            from: None,
            to: None,
            action,
            source: SourceSpan::new("fw-01.conf", line),
        }
    }

    fn policy(id: &str, rules: Vec<Rule>) -> Policy {
        Policy {
            id: PolicyId::from(id),
            rules,
            default_action: Action::Deny,
        }
    }

    fn route(prefix: &str, metric: u32) -> Route {
        Route {
            prefix: prefix.parse().unwrap(),
            next_hop: NextHop::Ip("10.0.0.1".parse().unwrap()),
            metric,
            origin: RouteOrigin::Static,
            source: None,
        }
    }

    fn device(id: &str) -> Device {
        let mut d = Device::new(DeviceId::from(id), Vendor::Fortigate);
        d.interfaces
            .insert(IfaceId::from("port1"), iface("port1", "10.0.10.1/24"));
        d.vrfs.insert(
            VrfId::default_vrf(),
            Vrf {
                routes: vec![route("0.0.0.0/0", 10)],
            },
        );
        d.policies.insert(
            PolicyId::from("lan-vers-dmz"),
            policy(
                "lan-vers-dmz",
                vec![rule("1", Action::Accept, 100), rule("2", Action::Deny, 110)],
            ),
        );
        d
    }

    fn network(devices: Vec<Device>) -> Network {
        Network {
            devices: devices.into_iter().map(|d| (d.id.clone(), d)).collect(),
            links: Vec::new(),
        }
    }

    #[test]
    fn reseaux_identiques_delta_vide() {
        let n = network(vec![device("fw-01")]);
        let delta = diff_networks(&n, &n.clone());
        assert!(delta.is_empty());
        assert_eq!(delta, ModelDelta::default());
    }

    #[test]
    fn equipement_ajoute_et_retire() {
        let before = network(vec![device("fw-01")]);
        let after = network(vec![device("fw-02")]);
        let delta = diff_networks(&before, &after);
        assert_eq!(delta.devices_added, vec![DeviceId::from("fw-02")]);
        assert_eq!(delta.devices_removed, vec![DeviceId::from("fw-01")]);
        assert!(delta.devices_changed.is_empty());
    }

    #[test]
    fn interface_modifiee_et_ajoutee() {
        let before = network(vec![device("fw-01")]);
        let mut d = device("fw-01");
        // port1 passe administrativement down, port2 apparaît.
        d.interfaces.get_mut(&IfaceId::from("port1")).unwrap().state = AdminState::Down;
        d.interfaces
            .insert(IfaceId::from("port2"), iface("port2", "10.0.20.1/24"));
        let after = network(vec![d]);

        let delta = diff_networks(&before, &after);
        let dd = &delta.devices_changed[&DeviceId::from("fw-01")];
        assert_eq!(dd.interfaces.len(), 2);
        let by_id: BTreeMap<_, _> = dd.interfaces.iter().cloned().collect();
        assert!(by_id[&IfaceId::from("port1")].is_modified());
        assert!(by_id[&IfaceId::from("port2")].is_added());
    }

    #[test]
    fn route_ajoutee_et_retiree() {
        let before = network(vec![device("fw-01")]);
        let mut d = device("fw-01");
        let vrf = d.vrfs.get_mut(&VrfId::default_vrf()).unwrap();
        vrf.routes = vec![route("10.0.30.0/24", 5)];
        let after = network(vec![d]);

        let delta = diff_networks(&before, &after);
        let dd = &delta.devices_changed[&DeviceId::from("fw-01")];
        assert_eq!(dd.vrfs.len(), 1);
        match &dd.vrfs[0].1 {
            VrfChange::Modified {
                routes_added,
                routes_removed,
            } => {
                assert_eq!(routes_added, &vec![route("10.0.30.0/24", 5)]);
                assert_eq!(routes_removed, &vec![route("0.0.0.0/0", 10)]);
            }
            other => panic!("attendu Modified, obtenu {other:?}"),
        }
    }

    #[test]
    fn regle_modifiee_detectee_avec_son_identifiant() {
        let before = network(vec![device("fw-01")]);
        let mut d = device("fw-01");
        // La règle 2 passe de Deny à Accept — exactement le genre de
        // changement que `calque plan` doit faire remonter.
        let p = d.policies.get_mut(&PolicyId::from("lan-vers-dmz")).unwrap();
        p.rules[1] = rule("2", Action::Accept, 110);
        let after = network(vec![d]);

        let delta = diff_networks(&before, &after);
        let dd = &delta.devices_changed[&DeviceId::from("fw-01")];
        assert_eq!(dd.policies.len(), 1);
        match &dd.policies[0].1 {
            PolicyChange::Modified(pd) => {
                assert!(!pd.rules_reordered);
                assert_eq!(pd.rules.len(), 1);
                assert_eq!(pd.rules[0].0, RuleId::from("2"));
                assert!(pd.rules[0].1.is_modified());
            }
            other => panic!("attendu Modified, obtenu {other:?}"),
        }
    }

    #[test]
    fn reordonnancement_des_regles_detecte() {
        // Mêmes règles, ordre inversé : contenu identique, comportement
        // potentiellement différent (première correspondance gagne).
        let mut d1 = device("fw-01");
        let mut d2 = device("fw-01");
        let p1 = d1
            .policies
            .get_mut(&PolicyId::from("lan-vers-dmz"))
            .unwrap();
        let p2 = d2
            .policies
            .get_mut(&PolicyId::from("lan-vers-dmz"))
            .unwrap();
        p2.rules = vec![p1.rules[1].clone(), p1.rules[0].clone()];
        let _ = p1;

        let delta = diff_networks(&network(vec![d1]), &network(vec![d2]));
        let dd = &delta.devices_changed[&DeviceId::from("fw-01")];
        match &dd.policies[0].1 {
            PolicyChange::Modified(pd) => {
                assert!(pd.rules_reordered);
                assert!(pd.rules.is_empty(), "aucune règle ajoutée/retirée/modifiée");
            }
            other => panic!("attendu Modified, obtenu {other:?}"),
        }
    }

    #[test]
    fn objet_adresse_modifie() {
        // « à cause du groupe SRV-INTERNES qui a changé » (§3.3).
        let before = network(vec![device("fw-01")]);
        let mut d = device("fw-01");
        d.objects.addresses.insert(
            ObjectId::from("SRV-INTERNES"),
            AddrObject::Nets(vec!["10.0.20.0/24".parse().unwrap()]),
        );
        let after = network(vec![d]);

        let delta = diff_networks(&before, &after);
        let dd = &delta.devices_changed[&DeviceId::from("fw-01")];
        assert_eq!(dd.addr_objects.len(), 1);
        assert_eq!(dd.addr_objects[0].0, ObjectId::from("SRV-INTERNES"));
        assert!(dd.addr_objects[0].1.is_added());
    }

    #[test]
    fn diff_multiset_gere_les_doublons() {
        let before = vec![1, 2, 2, 3];
        let after = vec![2, 3, 3, 4];
        let (added, removed) = diff_multiset(&before, &after);
        assert_eq!(added, vec![3, 4]);
        assert_eq!(removed, vec![1, 2]);
    }

    #[test]
    fn rule_match_utilisable_dans_le_delta() {
        // Une règle dont seul le pavé change est bien vue comme modifiée.
        let mut r1 = rule("1", Action::Accept, 100);
        let mut r2 = r1.clone();
        r2.matches.src = vec![AddrExpr::Net("10.0.10.0/24".parse().unwrap())];
        let pd = diff_policies(&policy("p", vec![r1.clone()]), &policy("p", vec![r2]));
        assert_eq!(pd.rules.len(), 1);
        assert!(pd.rules[0].1.is_modified());
        // Et une politique identique ne produit rien.
        r1.matches = RuleMatch::default();
        let pd = diff_policies(&policy("p", vec![r1.clone()]), &policy("p", vec![r1]));
        assert!(pd.is_empty());
    }

    #[test]
    fn plan_report_par_defaut_est_calme() {
        let r = PlanReport::default();
        assert!(r.is_quiet());
        assert_eq!(r.changed_count(), 0);
    }
}
