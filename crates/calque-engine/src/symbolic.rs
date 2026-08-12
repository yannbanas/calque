//! Résolution SYMBOLIQUE d'une règle (§5.3) : le pavé syntaxique
//! (`RuleMatch`) devient un [`HeaderSet`] de `calque-space`.
//!
//! C'est le pendant ensembliste de `resolve.rs` : mêmes conventions
//! (vecteur vide = `Any`, résolution TARDIVE des objets via l'`ObjectStore`,
//! détection de cycle dans les groupes imbriqués), mais le résultat est un
//! ensemble de paquets au lieu d'un booléen sur UN paquet.
//!
//! Fidélité (§6.3) : un objet manquant ou un cycle produit une erreur,
//! jamais une supposition. Un objet VIDE (liste de réseaux vide) produit
//! honnêtement l'ensemble vide — c'est la matière première de la détection
//! des règles mortes (`dead.rs`).

use calque_model::{
    AddrExpr, AddrObject, ObjectId, ObjectStore, ProtoMatch, RuleMatch, Service, ServiceExpr,
    ServiceObject,
};
use calque_space::{Cube, HeaderSet, HeaderSpace, PortRanges, PrefixSet, ProtoSet};

use crate::error::EvalError;

/// Convertit le pavé syntaxique d'une règle en [`HeaderSet`].
///
/// - `src`/`dst` vides valent `Any` (tout l'espace d'adressage) ;
/// - `services` vide vaut `Any` (tout protocole, tous ports) ;
/// - un service couple protocole, port source et port destination : chaque
///   service résolu devient donc un pavé (les dimensions ne sont pas
///   indépendantes ENTRE services, seulement à l'intérieur d'un pavé) ;
/// - les groupes d'objets sont résolus récursivement, avec détection de
///   cycle (même discipline que `resolve.rs`).
pub fn rule_headerset(store: &ObjectStore, matches: &RuleMatch) -> Result<HeaderSet, EvalError> {
    let src = addr_exprs_set(store, &matches.src)?;
    let dst = addr_exprs_set(store, &matches.dst)?;
    if src.is_empty() || dst.is_empty() {
        return Ok(HeaderSet::empty());
    }
    match service_exprs_services(store, &matches.services)? {
        // `None` = Any : un seul pavé, dimensions service pleines.
        None => Ok(HeaderSet::from_cube(Cube::new(
            src,
            dst,
            ProtoSet::full(),
            PortRanges::full(),
            PortRanges::full(),
        ))),
        // Un pavé par service concret ; l'union rétablit la disjonction.
        Some(services) => Ok(HeaderSet::from_cubes(services.into_iter().map(|svc| {
            Cube::new(
                src.clone(),
                dst.clone(),
                proto_set(&svc),
                PortRanges::from_range(svc.sport),
                PortRanges::from_range(svc.dport),
            )
        }))),
    }
}

fn proto_set(svc: &Service) -> ProtoSet {
    match svc.proto {
        ProtoMatch::Any => ProtoSet::full(),
        ProtoMatch::Number(n) => ProtoSet::single(n),
    }
}

/// L'ensemble d'adresses couvert par une liste d'expressions (vide = Any).
fn addr_exprs_set(store: &ObjectStore, exprs: &[AddrExpr]) -> Result<PrefixSet, EvalError> {
    if exprs.is_empty() {
        return Ok(PrefixSet::full());
    }
    let mut out = PrefixSet::empty();
    for expr in exprs {
        match expr {
            AddrExpr::Any => return Ok(PrefixSet::full()),
            AddrExpr::Net(net) => out = out.union(&PrefixSet::from_net(*net)),
            AddrExpr::Object(id) => out = out.union(&addr_object_set(store, id, &mut Vec::new())?),
        }
    }
    Ok(out)
}

/// Résolution récursive d'un objet adresse en `PrefixSet`, avec détection
/// de cycle via la pile des objets en cours de résolution.
fn addr_object_set(
    store: &ObjectStore,
    id: &ObjectId,
    stack: &mut Vec<ObjectId>,
) -> Result<PrefixSet, EvalError> {
    if stack.contains(id) {
        let mut path = stack.clone();
        path.push(id.clone());
        return Err(EvalError::ObjectCycle { path });
    }
    crate::resolve::check_group_depth(stack, id)?;
    let obj = store
        .addresses
        .get(id)
        .ok_or_else(|| EvalError::AddrObjectMissing { object: id.clone() })?;
    match obj {
        AddrObject::Nets(nets) => Ok(PrefixSet::from_nets(nets.iter().copied())),
        AddrObject::Group(members) => {
            stack.push(id.clone());
            let mut out = PrefixSet::empty();
            for member in members {
                out = out.union(&addr_object_set(store, member, stack)?);
            }
            stack.pop();
            Ok(out)
        }
    }
}

/// Les services concrets couverts par une liste d'expressions.
/// `None` = Any (liste vide, ou une expression `Any` rencontrée).
fn service_exprs_services(
    store: &ObjectStore,
    exprs: &[ServiceExpr],
) -> Result<Option<Vec<Service>>, EvalError> {
    if exprs.is_empty() {
        return Ok(None);
    }
    let mut out = Vec::new();
    for expr in exprs {
        match expr {
            ServiceExpr::Any => return Ok(None),
            ServiceExpr::Service(svc) => out.push(*svc),
            ServiceExpr::Object(id) => {
                service_object_services(store, id, &mut Vec::new(), &mut out)?
            }
        }
    }
    Ok(Some(out))
}

/// Aplatit récursivement un objet service en liste de services concrets,
/// avec détection de cycle.
fn service_object_services(
    store: &ObjectStore,
    id: &ObjectId,
    stack: &mut Vec<ObjectId>,
    out: &mut Vec<Service>,
) -> Result<(), EvalError> {
    if stack.contains(id) {
        let mut path = stack.clone();
        path.push(id.clone());
        return Err(EvalError::ObjectCycle { path });
    }
    crate::resolve::check_group_depth(stack, id)?;
    let obj = store
        .services
        .get(id)
        .ok_or_else(|| EvalError::ServiceObjectMissing { object: id.clone() })?;
    match obj {
        ServiceObject::Services(services) => {
            out.extend(services.iter().copied());
            Ok(())
        }
        ServiceObject::Group(members) => {
            stack.push(id.clone());
            for member in members {
                service_object_services(store, member, stack, out)?;
            }
            stack.pop();
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resolve::packet_matches_rule;
    use crate::testutil::{net, tcp};
    use calque_model::PortRange;
    use calque_space::HeaderSpace;

    fn store() -> ObjectStore {
        let mut s = ObjectStore::default();
        s.addresses.insert(
            ObjectId::new("NET-LAN"),
            AddrObject::Nets(vec![net("10.0.10.0/24")]),
        );
        s.addresses.insert(
            ObjectId::new("GRP"),
            AddrObject::Group(vec![ObjectId::new("NET-LAN")]),
        );
        s.services.insert(
            ObjectId::new("SVC-SMB"),
            ServiceObject::Services(vec![Service::tcp_dport(PortRange::single(445))]),
        );
        s.services.insert(
            ObjectId::new("SVC-GRP"),
            ServiceObject::Group(vec![ObjectId::new("SVC-SMB")]),
        );
        s
    }

    #[test]
    fn chaine_hostile_bornee_en_symbolique_aussi() {
        // Même borne R2 que resolve.rs : une chaîne de groupes distincts
        // trop profonde rend une erreur propre, pas un débordement.
        let mut s = ObjectStore::default();
        for i in 0..10_000usize {
            s.addresses.insert(
                ObjectId::new(format!("G{i}")),
                AddrObject::Group(vec![ObjectId::new(format!("G{}", i + 1))]),
            );
        }
        s.addresses.insert(
            ObjectId::new("G10000"),
            AddrObject::Nets(vec![net("10.0.10.0/24")]),
        );
        let m = RuleMatch {
            src: vec![AddrExpr::Object(ObjectId::new("G0"))],
            dst: Vec::new(),
            services: Vec::new(),
        };
        assert!(matches!(
            rule_headerset(&s, &m),
            Err(EvalError::GroupTooDeep { .. })
        ));
    }

    #[test]
    fn groupes_imbriques_et_any() {
        // src = groupe imbriqué, dst vide (= Any), services = groupe de
        // services imbriqué.
        let m = RuleMatch {
            src: vec![AddrExpr::Object(ObjectId::new("GRP"))],
            dst: Vec::new(),
            services: vec![ServiceExpr::Object(ObjectId::new("SVC-GRP"))],
        };
        let hs = rule_headerset(&store(), &m).expect("résolution");
        assert!(hs.contains(&tcp("10.0.10.5", "198.51.100.7", 445)));
        // Hors du groupe source.
        assert!(!hs.contains(&tcp("10.0.99.5", "198.51.100.7", 445)));
        // Mauvais port.
        assert!(!hs.contains(&tcp("10.0.10.5", "198.51.100.7", 446)));
        // Mauvais protocole.
        let mut udp = tcp("10.0.10.5", "198.51.100.7", 445);
        udp.proto = 17;
        assert!(!hs.contains(&udp));
    }

    #[test]
    fn vecteurs_vides_valent_any() {
        let hs = rule_headerset(&ObjectStore::default(), &RuleMatch::default())
            .expect("résolution triviale");
        let full = HeaderSet::full();
        assert!(hs.contains_set(&full) && full.contains_set(&hs));
    }

    #[test]
    fn objet_vide_rend_l_ensemble_vide() {
        let mut s = ObjectStore::default();
        s.addresses
            .insert(ObjectId::new("VIDE"), AddrObject::Nets(Vec::new()));
        let m = RuleMatch {
            src: vec![AddrExpr::Object(ObjectId::new("VIDE"))],
            dst: Vec::new(),
            services: Vec::new(),
        };
        let hs = rule_headerset(&s, &m).expect("résolution");
        assert!(hs.is_empty());
    }

    #[test]
    fn cycle_et_objet_manquant() {
        let mut s = ObjectStore::default();
        s.addresses.insert(
            ObjectId::new("A"),
            AddrObject::Group(vec![ObjectId::new("B")]),
        );
        s.addresses.insert(
            ObjectId::new("B"),
            AddrObject::Group(vec![ObjectId::new("A")]),
        );
        let m = RuleMatch {
            src: vec![AddrExpr::Object(ObjectId::new("A"))],
            dst: Vec::new(),
            services: Vec::new(),
        };
        assert!(matches!(
            rule_headerset(&s, &m),
            Err(EvalError::ObjectCycle { .. })
        ));
        let m2 = RuleMatch {
            src: vec![AddrExpr::Object(ObjectId::new("ABSENT"))],
            dst: Vec::new(),
            services: Vec::new(),
        };
        assert!(matches!(
            rule_headerset(&s, &m2),
            Err(EvalError::AddrObjectMissing { .. })
        ));
    }

    #[test]
    fn coherence_avec_la_resolution_concrete() {
        // §4.3 : sur un panel de paquets, l'appartenance ensembliste doit
        // coïncider avec la correspondance concrète de resolve.rs.
        let s = store();
        let m = RuleMatch {
            src: vec![AddrExpr::Object(ObjectId::new("GRP"))],
            dst: vec![AddrExpr::Net(net("10.0.20.0/24"))],
            services: vec![
                ServiceExpr::Service(Service::tcp_dport(PortRange::single(445))),
                ServiceExpr::Service(Service::udp_dport(PortRange { start: 53, end: 53 })),
            ],
        };
        let hs = rule_headerset(&s, &m).expect("résolution");
        let mut panel = vec![
            tcp("10.0.10.5", "10.0.20.5", 445),
            tcp("10.0.10.5", "10.0.20.5", 446),
            tcp("10.0.10.5", "10.0.21.5", 445),
            tcp("10.0.99.5", "10.0.20.5", 445),
        ];
        let mut dns = tcp("10.0.10.5", "10.0.20.5", 53);
        dns.proto = 17;
        panel.push(dns);
        for pkt in &panel {
            assert_eq!(
                hs.contains(pkt),
                packet_matches_rule(&s, &m, pkt).expect("résolution concrète"),
                "désaccord symbolique/concret sur {pkt:?}"
            );
        }
    }
}
