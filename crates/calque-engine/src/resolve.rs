//! Résolution TARDIVE des objets (§3.3).
//!
//! La représentation intermédiaire garde les références (`AddrExpr::Object`,
//! `ServiceExpr::Object`) ; c'est ici qu'elles sont résolues, au moment de
//! l'évaluation, via l'`ObjectStore` de l'équipement. Les groupes peuvent
//! être imbriqués ; un cycle est détecté et rendu comme erreur, jamais
//! parcouru indéfiniment.

use std::net::IpAddr;

use calque_model::{
    AddrExpr, AddrObject, ConcretePacket, ObjectId, ObjectStore, ProtoMatch, RuleMatch, Service,
    ServiceExpr, ServiceObject,
};

use crate::error::EvalError;

/// Le paquet appartient-il au pavé syntaxique de la règle ?
///
/// Convention de `calque-model` : un vecteur vide équivaut à `Any`.
pub fn packet_matches_rule(
    store: &ObjectStore,
    matches: &RuleMatch,
    pkt: &ConcretePacket,
) -> Result<bool, EvalError> {
    if !addr_exprs_contain(store, &matches.src, &pkt.src)? {
        return Ok(false);
    }
    if !addr_exprs_contain(store, &matches.dst, &pkt.dst)? {
        return Ok(false);
    }
    service_exprs_match(store, &matches.services, pkt)
}

/// Une adresse appartient-elle à l'une des expressions (vide = Any) ?
fn addr_exprs_contain(
    store: &ObjectStore,
    exprs: &[AddrExpr],
    ip: &IpAddr,
) -> Result<bool, EvalError> {
    if exprs.is_empty() {
        return Ok(true);
    }
    for expr in exprs {
        if addr_expr_contains(store, expr, ip)? {
            return Ok(true);
        }
    }
    Ok(false)
}

fn addr_expr_contains(
    store: &ObjectStore,
    expr: &AddrExpr,
    ip: &IpAddr,
) -> Result<bool, EvalError> {
    match expr {
        AddrExpr::Any => Ok(true),
        AddrExpr::Net(net) => Ok(net.contains(ip)),
        AddrExpr::Object(id) => addr_object_contains(store, id, ip, &mut Vec::new()),
    }
}

/// Résolution récursive d'un objet adresse, avec détection de cycle via la
/// pile `stack` des objets en cours de résolution.
fn addr_object_contains(
    store: &ObjectStore,
    id: &ObjectId,
    ip: &IpAddr,
    stack: &mut Vec<ObjectId>,
) -> Result<bool, EvalError> {
    if stack.contains(id) {
        let mut path = stack.clone();
        path.push(id.clone());
        return Err(EvalError::ObjectCycle { path });
    }
    let obj = store
        .addresses
        .get(id)
        .ok_or_else(|| EvalError::AddrObjectMissing { object: id.clone() })?;
    match obj {
        AddrObject::Nets(nets) => Ok(nets.iter().any(|n| n.contains(ip))),
        AddrObject::Group(members) => {
            stack.push(id.clone());
            for member in members {
                if addr_object_contains(store, member, ip, stack)? {
                    stack.pop();
                    return Ok(true);
                }
            }
            stack.pop();
            Ok(false)
        }
    }
}

/// Le paquet correspond-il à l'une des expressions de service (vide = Any) ?
fn service_exprs_match(
    store: &ObjectStore,
    exprs: &[ServiceExpr],
    pkt: &ConcretePacket,
) -> Result<bool, EvalError> {
    if exprs.is_empty() {
        return Ok(true);
    }
    for expr in exprs {
        if service_expr_matches(store, expr, pkt)? {
            return Ok(true);
        }
    }
    Ok(false)
}

fn service_expr_matches(
    store: &ObjectStore,
    expr: &ServiceExpr,
    pkt: &ConcretePacket,
) -> Result<bool, EvalError> {
    match expr {
        ServiceExpr::Any => Ok(true),
        ServiceExpr::Service(svc) => Ok(service_matches(svc, pkt)),
        ServiceExpr::Object(id) => service_object_matches(store, id, pkt, &mut Vec::new()),
    }
}

fn service_object_matches(
    store: &ObjectStore,
    id: &ObjectId,
    pkt: &ConcretePacket,
    stack: &mut Vec<ObjectId>,
) -> Result<bool, EvalError> {
    if stack.contains(id) {
        let mut path = stack.clone();
        path.push(id.clone());
        return Err(EvalError::ObjectCycle { path });
    }
    let obj = store
        .services
        .get(id)
        .ok_or_else(|| EvalError::ServiceObjectMissing { object: id.clone() })?;
    match obj {
        ServiceObject::Services(services) => Ok(services.iter().any(|s| service_matches(s, pkt))),
        ServiceObject::Group(members) => {
            stack.push(id.clone());
            for member in members {
                if service_object_matches(store, member, pkt, stack)? {
                    stack.pop();
                    return Ok(true);
                }
            }
            stack.pop();
            Ok(false)
        }
    }
}

/// Correspondance concrète d'un service : protocole + intervalles de ports.
fn service_matches(svc: &Service, pkt: &ConcretePacket) -> bool {
    let proto_ok = match svc.proto {
        ProtoMatch::Any => true,
        ProtoMatch::Number(n) => n == pkt.proto,
    };
    proto_ok && svc.sport.contains(pkt.sport) && svc.dport.contains(pkt.dport)
}

#[cfg(test)]
mod tests {
    use super::*;
    use calque_model::PortRange;

    fn store() -> ObjectStore {
        let mut s = ObjectStore::default();
        s.addresses.insert(
            ObjectId::new("NET-LAN"),
            AddrObject::Nets(vec!["10.0.10.0/24".parse().expect("net")]),
        );
        s.addresses.insert(
            ObjectId::new("GRP"),
            AddrObject::Group(vec![ObjectId::new("NET-LAN")]),
        );
        s
    }

    fn pkt(dst_port: u16) -> ConcretePacket {
        ConcretePacket {
            src: "10.0.10.5".parse().expect("ip"),
            dst: "10.0.20.5".parse().expect("ip"),
            proto: 6,
            sport: 40000,
            dport: dst_port,
        }
    }

    #[test]
    fn groupe_imbrique_resolu() {
        let s = store();
        let ip: IpAddr = "10.0.10.5".parse().expect("ip");
        let expr = AddrExpr::Object(ObjectId::new("GRP"));
        assert_eq!(addr_expr_contains(&s, &expr, &ip), Ok(true));
        let dehors: IpAddr = "10.0.99.5".parse().expect("ip");
        assert_eq!(addr_expr_contains(&s, &expr, &dehors), Ok(false));
    }

    #[test]
    fn cycle_de_groupes_detecte() {
        let mut s = ObjectStore::default();
        s.addresses.insert(
            ObjectId::new("A"),
            AddrObject::Group(vec![ObjectId::new("B")]),
        );
        s.addresses.insert(
            ObjectId::new("B"),
            AddrObject::Group(vec![ObjectId::new("A")]),
        );
        let ip: IpAddr = "10.0.10.5".parse().expect("ip");
        let expr = AddrExpr::Object(ObjectId::new("A"));
        match addr_expr_contains(&s, &expr, &ip) {
            Err(EvalError::ObjectCycle { path }) => assert!(path.len() >= 3),
            other => panic!("cycle attendu, obtenu {other:?}"),
        }
    }

    #[test]
    fn objet_manquant_est_une_erreur() {
        let s = ObjectStore::default();
        let ip: IpAddr = "10.0.10.5".parse().expect("ip");
        let expr = AddrExpr::Object(ObjectId::new("ABSENT"));
        assert!(matches!(
            addr_expr_contains(&s, &expr, &ip),
            Err(EvalError::AddrObjectMissing { .. })
        ));
    }

    #[test]
    fn service_concret() {
        let svc = Service::tcp_dport(PortRange::single(445));
        assert!(service_matches(&svc, &pkt(445)));
        assert!(!service_matches(&svc, &pkt(446)));
        let mut udp = pkt(445);
        udp.proto = 17;
        assert!(!service_matches(&svc, &udp));
    }

    #[test]
    fn vecteurs_vides_valent_any() {
        let s = ObjectStore::default();
        let m = RuleMatch::default();
        assert_eq!(packet_matches_rule(&s, &m, &pkt(80)), Ok(true));
    }
}
