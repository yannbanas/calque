//! Aides de test partagées par les modules du mode symbolique
//! (mêmes petits réseaux construits en code que les tests d'`engine.rs`).

#![allow(dead_code)]

use std::net::IpAddr;

use calque_model::{
    Action, AddrExpr, ConcretePacket, Device, DeviceId, Endpoint, IfaceId, Interface, Link,
    LinkOrigin, Network, NextHop, Policy, PolicyId, PortRange, Route, RouteOrigin, Rule, RuleId,
    RuleMatch, Service, ServiceExpr, SourceSpan, Vendor, Vrf, VrfId, ZoneId,
};
use ipnet::IpNet;

pub fn ip(s: &str) -> IpAddr {
    s.parse().expect("adresse IP de test")
}

pub fn net(s: &str) -> IpNet {
    s.parse().expect("préfixe de test")
}

pub fn span(line: u32) -> SourceSpan {
    SourceSpan::new("fw-01.conf", line)
}

pub fn tcp(src: &str, dst: &str, dport: u16) -> ConcretePacket {
    ConcretePacket {
        src: ip(src),
        dst: ip(dst),
        proto: 6,
        sport: 40000,
        dport,
    }
}

pub fn iface(id: &str, addr: &str, zone: Option<&str>) -> Interface {
    let mut i = Interface::new(IfaceId::new(id));
    i.addrs = vec![net(addr)];
    i.zone = zone.map(ZoneId::new);
    i
}

#[allow(clippy::too_many_arguments)]
pub fn rule(
    id: &str,
    src: Vec<AddrExpr>,
    dst: Vec<AddrExpr>,
    services: Vec<ServiceExpr>,
    from: Option<&str>,
    to: Option<&str>,
    action: Action,
    line: u32,
) -> Rule {
    Rule {
        id: RuleId::new(id),
        matches: RuleMatch { src, dst, services },
        from: from.map(ZoneId::new),
        to: to.map(ZoneId::new),
        action,
        source: span(line),
    }
}

pub fn tcp_svc(dport: u16) -> ServiceExpr {
    ServiceExpr::Service(Service::tcp_dport(PortRange::single(dport)))
}

/// Le réseau de base à deux équipements (identique aux tests d'`engine.rs`) :
///
/// ```text
/// [hôtes 10.0.10.0/24] — lan[fw1]wan —— wan2[fw2]dmz — [hôtes 10.0.20.0/24]
///                          192.168.0.0/30
/// ```
pub fn base_network() -> Network {
    let mut fw1 = Device::new(DeviceId::new("fw1"), Vendor::Fortigate);
    for i in [
        iface("lan", "10.0.10.1/24", Some("lan")),
        iface("wan", "192.168.0.1/30", Some("wan")),
    ] {
        fw1.interfaces.insert(i.id.clone(), i);
    }
    fw1.vrfs.insert(
        VrfId::default_vrf(),
        Vrf {
            routes: vec![
                Route {
                    prefix: net("10.0.20.0/24"),
                    next_hop: NextHop::Ip(ip("192.168.0.2")),
                    metric: 10,
                    origin: RouteOrigin::Static,
                    source: Some(span(812)),
                },
                Route {
                    prefix: net("10.0.66.0/24"),
                    next_hop: NextHop::Drop,
                    metric: 10,
                    origin: RouteOrigin::Static,
                    source: Some(span(820)),
                },
            ],
        },
    );

    let mut fw2 = Device::new(DeviceId::new("fw2"), Vendor::Fortigate);
    for i in [
        iface("wan2", "192.168.0.2/30", None),
        iface("dmz", "10.0.20.1/24", Some("dmz")),
    ] {
        fw2.interfaces.insert(i.id.clone(), i);
    }
    fw2.vrfs.insert(VrfId::default_vrf(), Vrf::default());

    let mut network = Network::default();
    network.devices.insert(fw1.id.clone(), fw1);
    network.devices.insert(fw2.id.clone(), fw2);
    network.links.push(Link {
        a: Endpoint {
            device: DeviceId::new("fw1"),
            iface: IfaceId::new("wan"),
        },
        b: Endpoint {
            device: DeviceId::new("fw2"),
            iface: IfaceId::new("wan2"),
        },
        origin: LinkOrigin::Declared,
    });
    network
}

/// Accroche une politique de SORTIE sur fw1.
pub fn with_fw1_egress(rules: Vec<Rule>, default_action: Action) -> Network {
    let mut network = base_network();
    let fw1 = network.devices.get_mut(&DeviceId::new("fw1")).expect("fw1");
    let pid = PolicyId::new("fw1-out");
    fw1.policies.insert(
        pid.clone(),
        Policy {
            id: pid.clone(),
            rules,
            default_action,
        },
    );
    fw1.pipeline.egress.push(pid);
    network
}

/// La politique « standard » des tests : autorise le flux SMB vers le
/// serveur de fichiers, refuse telnet explicitement, refuse le reste.
pub fn standard_rules() -> Vec<Rule> {
    vec![
        rule(
            "10",
            vec![AddrExpr::Net(net("10.0.10.0/24"))],
            vec![AddrExpr::Net(net("10.0.20.5/32"))],
            vec![tcp_svc(445)],
            Some("lan"),
            Some("wan"),
            Action::Accept,
            100,
        ),
        rule(
            "20",
            vec![],
            vec![],
            vec![tcp_svc(23)],
            None,
            None,
            Action::Deny,
            200,
        ),
    ]
}
