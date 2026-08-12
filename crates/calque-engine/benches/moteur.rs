//! Benchs du moteur d'accessibilité (concret et symbolique).
//!
//! Réseaux DÉTERMINISTES construits en code (aucun aléa) : la topologie de
//! base à deux équipements des tests (`lan[fw1]wan — wan2[fw2]dmz`), avec
//! des politiques de taille paramétrée.
//!
//! Familles mesurées :
//! - `trace_packet` : paquet concret traversant une politique de
//!   1 000 / 5 000 règles (le paquet ne correspond qu'à la DERNIÈRE règle,
//!   c'est le pire cas du balayage linéaire) ;
//! - `reach_to` : accessibilité symbolique sur un réseau moyen
//!   (100 règles) ;
//! - `dead_rules` : détection des règles mortes sur 1 000 règles, en trois
//!   scénarios (disjointes, groupes réalistes avec règles réellement
//!   mortes, et le cas pathologique où l'union des masques grossit).

use std::hint::black_box;
use std::net::IpAddr;

use calque_engine::{dead_rules, reach_to, trace_packet, Verdict};
use calque_model::{
    Action, AddrExpr, ConcretePacket, Device, DeviceId, Endpoint, IfaceId, Interface, Link,
    LinkOrigin, Network, NextHop, Policy, PolicyId, PortRange, Route, RouteOrigin, Rule, RuleId,
    RuleMatch, Service, ServiceExpr, SourceSpan, Vendor, Vrf, VrfId, ZoneId,
};
use calque_space::{Cube, HeaderSet, PortRanges, PrefixSet, ProtoSet};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use ipnet::IpNet;

fn ip(s: &str) -> IpAddr {
    s.parse().expect("adresse IP de bench")
}

fn net(s: &str) -> IpNet {
    s.parse().expect("préfixe de bench")
}

fn iface(id: &str, addr: &str, zone: Option<&str>) -> Interface {
    let mut i = Interface::new(IfaceId::new(id));
    i.addrs = vec![net(addr)];
    i.zone = zone.map(ZoneId::new);
    i
}

fn rule(
    id: &str,
    src: Vec<AddrExpr>,
    services: Vec<ServiceExpr>,
    action: Action,
    line: u32,
) -> Rule {
    Rule {
        id: RuleId::new(id),
        matches: RuleMatch {
            src,
            dst: Vec::new(),
            services,
        },
        from: None,
        to: None,
        action,
        source: SourceSpan::new("bench.conf", line),
    }
}

fn tcp_svc(dport: u16) -> ServiceExpr {
    ServiceExpr::Service(Service::tcp_dport(PortRange::single(dport)))
}

/// Le réseau de base des tests du moteur : deux pare-feux reliés.
fn base_network() -> Network {
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
            routes: vec![Route {
                prefix: net("10.0.20.0/24"),
                next_hop: NextHop::Ip(ip("192.168.0.2")),
                metric: 10,
                origin: RouteOrigin::Static,
                source: None,
            }],
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

/// Accroche une politique de sortie de `n` règles sur fw1 : la règle i
/// autorise `10.0.10.0/24 → tcp/(10000 + i)`. Un paquet au port
/// `10000 + n - 1` ne correspond donc qu'à la dernière règle.
fn network_with_rules(n: u16) -> Network {
    let mut network = base_network();
    let rules: Vec<Rule> = (0..n)
        .map(|i| {
            rule(
                &format!("r{i}"),
                vec![AddrExpr::Net(net("10.0.10.0/24"))],
                vec![tcp_svc(10000 + i)],
                Action::Accept,
                100 + u32::from(i),
            )
        })
        .collect();
    let fw1 = network.devices.get_mut(&DeviceId::new("fw1")).expect("fw1");
    let pid = PolicyId::new("fw1-out");
    fw1.policies.insert(
        pid.clone(),
        Policy {
            id: pid.clone(),
            rules,
            default_action: Action::Deny,
        },
    );
    fw1.pipeline.egress.push(pid);
    network
}

fn bench_trace_packet(c: &mut Criterion) {
    let mut g = c.benchmark_group("trace_packet");
    for n in [1000u16, 5000] {
        let network = network_with_rules(n);
        let pkt = ConcretePacket {
            src: ip("10.0.10.5"),
            dst: ip("10.0.20.5"),
            proto: 6,
            sport: 40000,
            dport: 10000 + n - 1,
        };
        // Garde-fou : le paquet est bien accepté par la dernière règle.
        assert_eq!(trace_packet(&network, &pkt).verdict, Verdict::Allowed);
        g.bench_with_input(
            BenchmarkId::new("derniere_regle", n),
            &(network, pkt),
            |b, (network, pkt)| {
                b.iter(|| trace_packet(black_box(network), black_box(pkt)));
            },
        );
    }
    g.finish();
}

fn bench_reach_to(c: &mut Criterion) {
    let mut g = c.benchmark_group("reach_to");
    g.sample_size(20);
    // Réseau moyen : 100 règles.
    let network = network_with_rules(100);
    let target = HeaderSet::from_cube(Cube::new(
        PrefixSet::full(),
        PrefixSet::from_net(net("10.0.20.5/32")),
        ProtoSet::full(),
        PortRanges::full(),
        PortRanges::full(),
    ));
    // Garde-fou : le rapport trouve bien des flux autorisés.
    assert!(!reach_to(&network, &target).flows.is_empty());
    g.bench_with_input(
        BenchmarkId::new("reseau_moyen", 100),
        &(network, target),
        |b, (network, target)| {
            b.iter(|| reach_to(black_box(network), black_box(target)));
        },
    );
    g.finish();
}

/// Équipement à une politique de `rules` règles (pas besoin de topologie
/// pour `dead_rules`).
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

/// Scénario « disjointes » : n règles deux à deux disjointes (source ET
/// port distincts). Aucune n'est morte ; on mesure les n²/2 tests
/// d'intersection.
fn device_disjointes(n: u32) -> Device {
    device_with(
        (0..n)
            .map(|i| {
                rule(
                    &format!("r{i}"),
                    vec![AddrExpr::Net(net(&format!(
                        "10.{}.{}.0/24",
                        i / 200,
                        i % 200
                    )))],
                    vec![tcp_svc((1024 + (i % 30000) * 2) as u16)],
                    Action::Accept,
                    100 + i,
                )
            })
            .collect(),
    )
}

/// Scénario « groupes » : par groupe de quatre règles sur un même /24,
/// deux moitiés /25, puis le /24 entier (mort par UNION des moitiés), puis
/// un /26 (mort par inclusion). La moitié des règles est réellement morte,
/// les interactions restent locales au groupe — c'est le profil d'une
/// vraie politique avec des redondances.
fn device_groupes(n: u32) -> Device {
    let mut rules = Vec::with_capacity(n as usize);
    for k in 0..n / 4 {
        let (a, b) = (k / 200, k % 200);
        rules.push(rule(
            &format!("r{}a", k),
            vec![AddrExpr::Net(net(&format!("10.{a}.{b}.0/25")))],
            Vec::new(),
            Action::Deny,
            1000 + 4 * k,
        ));
        rules.push(rule(
            &format!("r{}b", k),
            vec![AddrExpr::Net(net(&format!("10.{a}.{b}.128/25")))],
            Vec::new(),
            Action::Deny,
            1001 + 4 * k,
        ));
        rules.push(rule(
            &format!("r{}c", k),
            vec![AddrExpr::Net(net(&format!("10.{a}.{b}.0/24")))],
            Vec::new(),
            Action::Accept,
            1002 + 4 * k,
        ));
        rules.push(rule(
            &format!("r{}d", k),
            vec![AddrExpr::Net(net(&format!("10.{a}.{b}.0/26")))],
            Vec::new(),
            Action::Accept,
            1003 + 4 * k,
        ));
    }
    device_with(rules)
}

/// Scénario « pathologique » : n − 1 règles étroites (source /24 et port
/// distincts) puis une règle large (10.0.0.0/8, tous ports). CHAQUE règle
/// antérieure intersecte la dernière : l'union des masques grossit jusqu'à
/// n − 1 pavés non fusionnables — c'est le pire cas du O(n²) documenté.
fn device_pathologique(n: u32) -> Device {
    let mut rules: Vec<Rule> = (0..n - 1)
        .map(|i| {
            rule(
                &format!("r{i}"),
                vec![AddrExpr::Net(net(&format!(
                    "10.{}.{}.0/24",
                    i / 200,
                    i % 200
                )))],
                vec![tcp_svc((1024 + (i % 30000) * 2) as u16)],
                Action::Deny,
                100 + i,
            )
        })
        .collect();
    rules.push(rule(
        "large",
        vec![AddrExpr::Net(net("10.0.0.0/8"))],
        Vec::new(),
        Action::Accept,
        100 + n,
    ));
    device_with(rules)
}

fn bench_dead_rules(c: &mut Criterion) {
    let mut g = c.benchmark_group("dead_rules");
    g.sample_size(10);

    let d = device_disjointes(1000);
    assert!(dead_rules(&d).expect("analyse").is_empty());
    g.bench_with_input(BenchmarkId::new("disjointes", 1000), &d, |b, d| {
        b.iter(|| dead_rules(black_box(d)).expect("analyse"));
    });

    let d = device_groupes(1000);
    assert_eq!(dead_rules(&d).expect("analyse").len(), 500);
    g.bench_with_input(BenchmarkId::new("groupes", 1000), &d, |b, d| {
        b.iter(|| dead_rules(black_box(d)).expect("analyse"));
    });

    for n in [50u32, 100, 200, 1000] {
        let d = device_pathologique(n);
        g.bench_with_input(BenchmarkId::new("pathologique", n), &d, |b, d| {
            b.iter(|| dead_rules(black_box(d)).expect("analyse"));
        });
    }
    g.finish();
}

criterion_group!(
    benches,
    bench_trace_packet,
    bench_reach_to,
    bench_dead_rules
);
criterion_main!(benches);
