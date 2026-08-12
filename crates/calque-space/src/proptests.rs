//! Tests par propriétés (§4.3) : l'algèbre doit obéir aux lois des
//! ensembles sur des dizaines de milliers de cas générés.
//!
//! Les stratégies sont volontairement biaisées vers un petit univers
//! (préfixes dans 10.0.0.0/8, ports usuels, tcp/udp) pour que les
//! intersections, soustractions et fusions soient souvent non triviales.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use calque_model::{ConcretePacket, PortRange};
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use proptest::prelude::*;

use crate::{Cube, HeaderSet, HeaderSpace, PortRanges, PrefixSet, ProtoSet};

// ---------------------------------------------------------------------------
// Stratégies
// ---------------------------------------------------------------------------

/// Un préfixe IPv4 dans 10.0.0.0/8 (longueur >= 8), pour favoriser les
/// chevauchements entre valeurs générées.
fn arb_ipv4_net() -> impl Strategy<Value = IpNet> {
    (0u32..16, 8u8..=32).prop_map(|(seed, len)| {
        let addr = Ipv4Addr::from(0x0A00_0000u32 | (seed << 12));
        match Ipv4Net::new(addr, len) {
            Ok(n) => IpNet::V4(n.trunc()),
            Err(_) => unreachable!("len <= 32 par construction"),
        }
    })
}

/// Un préfixe IPv6 dans 2001:db8::/32.
fn arb_ipv6_net() -> impl Strategy<Value = IpNet> {
    (0u128..8, 32u8..=64).prop_map(|(seed, len)| {
        let addr = Ipv6Addr::from((0x2001_0db8u128 << 96) | (seed << 80));
        match Ipv6Net::new(addr, len) {
            Ok(n) => IpNet::V6(n.trunc()),
            Err(_) => unreachable!("len <= 128 par construction"),
        }
    })
}

fn arb_net() -> impl Strategy<Value = IpNet> {
    prop_oneof![
        1 => Just(IpNet::V4(Ipv4Net::new(Ipv4Addr::UNSPECIFIED, 0).expect("0/0 valide"))),
        7 => arb_ipv4_net(),
        2 => arb_ipv6_net(),
    ]
}

fn arb_prefix_set() -> impl Strategy<Value = PrefixSet> {
    prop_oneof![
        1 => Just(PrefixSet::full()),
        8 => prop::collection::vec(arb_net(), 1..3).prop_map(PrefixSet::from_nets),
    ]
}

fn arb_proto_set() -> impl Strategy<Value = ProtoSet> {
    prop_oneof![
        2 => Just(ProtoSet::full()),
        4 => prop::sample::select(vec![1u8, 6, 17]).prop_map(ProtoSet::single),
        1 => any::<u8>().prop_map(ProtoSet::single),
        1 => Just(ProtoSet::from_protos([6u8, 17])),
    ]
}

fn arb_port_ranges() -> impl Strategy<Value = PortRanges> {
    prop_oneof![
        2 => Just(PortRanges::full()),
        4 => prop::sample::select(vec![22u16, 80, 443, 445]).prop_map(PortRanges::single),
        3 => (0u16..200, 0u16..200).prop_map(|(a, b)| {
            PortRanges::from_range(PortRange { start: a.min(b), end: a.max(b) })
        }),
    ]
}

fn arb_cube() -> impl Strategy<Value = Cube> {
    (
        arb_prefix_set(),
        arb_prefix_set(),
        arb_proto_set(),
        arb_port_ranges(),
        arb_port_ranges(),
    )
        .prop_map(|(src, dst, proto, sport, dport)| Cube::new(src, dst, proto, sport, dport))
}

fn arb_header_set() -> impl Strategy<Value = HeaderSet> {
    prop::collection::vec(arb_cube(), 0..3).prop_map(HeaderSet::from_cubes)
}

/// Une adresse concrète, biaisée vers 10.0.0.0/8 pour croiser souvent
/// les préfixes générés.
fn arb_ip() -> impl Strategy<Value = IpAddr> {
    prop_oneof![
        7 => (0u32..0x0001_0000).prop_map(|s| IpAddr::V4(Ipv4Addr::from(0x0A00_0000 | s))),
        1 => any::<u32>().prop_map(|s| IpAddr::V4(Ipv4Addr::from(s))),
        2 => (0u128..8).prop_map(|s| {
            IpAddr::V6(Ipv6Addr::from((0x2001_0db8u128 << 96) | (s << 80)))
        }),
    ]
}

fn arb_packet() -> impl Strategy<Value = ConcretePacket> {
    (
        arb_ip(),
        arb_ip(),
        prop_oneof![4 => prop::sample::select(vec![1u8, 6, 17]), 1 => any::<u8>()],
        prop_oneof![2 => 0u16..200, 1 => any::<u16>()],
        prop_oneof![4 => prop::sample::select(vec![22u16, 80, 443, 445]), 1 => any::<u16>()],
    )
        .prop_map(|(src, dst, proto, sport, dport)| ConcretePacket {
            src,
            dst,
            proto,
            sport,
            dport,
        })
}

// `Arbitrary` pour l'usage `a: Cube` / `a: HeaderSet` dans `proptest!`.
impl Arbitrary for Cube {
    type Parameters = ();
    type Strategy = BoxedStrategy<Cube>;
    fn arbitrary_with(_: ()) -> Self::Strategy {
        arb_cube().boxed()
    }
}

impl Arbitrary for HeaderSet {
    type Parameters = ();
    type Strategy = BoxedStrategy<HeaderSet>;
    fn arbitrary_with(_: ()) -> Self::Strategy {
        arb_header_set().boxed()
    }
}

/// Égalité ensembliste : inclusion mutuelle (la normalisation n'étant pas
/// canonique, on ne compare jamais par `Eq` structurel dans ces lois).
fn set_eq(a: &HeaderSet, b: &HeaderSet) -> bool {
    a.contains_set(b) && b.contains_set(a)
}

// ---------------------------------------------------------------------------
// Les lois (§4.3 et complément)
// ---------------------------------------------------------------------------

proptest! {
    // --- §4.3 -------------------------------------------------------------

    #[test]
    fn union_contient_les_operandes(a: HeaderSet, b: HeaderSet) {
        let u = a.union(&b);
        prop_assert!(u.contains_set(&a) && u.contains_set(&b));
    }

    #[test]
    fn soustraction_puis_intersection_est_vide(a: HeaderSet, b: HeaderSet) {
        prop_assert!(a.subtract(&b).intersect(&b).is_empty());
    }

    #[test]
    fn coherence_avec_le_concret(a: HeaderSet, p in arb_packet()) {
        // Le chemin symbolique et le chemin concret doivent s'accorder.
        prop_assert_eq!(a.contains(&p), a.cubes().iter().any(|c| c.contains(&p)));
    }

    // --- Idempotences et éléments neutres ----------------------------------

    #[test]
    fn normalisation_idempotente(a: HeaderSet) {
        // Reconstruire depuis les pavés d'une forme normalisée doit rendre
        // exactement la même structure.
        let b = HeaderSet::from_cubes(a.cubes().iter().cloned());
        prop_assert_eq!(a, b);
    }

    #[test]
    fn intersection_avec_soi(a: HeaderSet) {
        prop_assert!(set_eq(&a.intersect(&a), &a));
    }

    #[test]
    fn soustraction_de_soi_est_vide(a: HeaderSet) {
        prop_assert!(a.subtract(&a).is_empty());
    }

    #[test]
    fn union_avec_vide_et_intersection_avec_plein(a: HeaderSet) {
        prop_assert!(set_eq(&a.union(&HeaderSet::empty()), &a));
        prop_assert!(set_eq(&a.intersect(&HeaderSet::full()), &a));
        prop_assert!(a.subtract(&HeaderSet::full()).is_empty());
        prop_assert!(set_eq(&a.subtract(&HeaderSet::empty()), &a));
    }

    // --- Commutativité (au sens ensembliste) --------------------------------

    #[test]
    fn intersection_commutative(a: HeaderSet, b: HeaderSet) {
        prop_assert!(set_eq(&a.intersect(&b), &b.intersect(&a)));
    }

    #[test]
    fn union_commutative(a: HeaderSet, b: HeaderSet) {
        prop_assert!(set_eq(&a.union(&b), &b.union(&a)));
    }

    // --- Exactitude des opérations, vérifiée sur le concret ------------------

    #[test]
    fn union_exacte(a: HeaderSet, b: HeaderSet) {
        // Rien de plus que a et b dans l'union.
        prop_assert!(a.union(&b).subtract(&a).subtract(&b).is_empty());
    }

    #[test]
    fn intersection_incluse_dans_les_operandes(a: HeaderSet, b: HeaderSet) {
        let i = a.intersect(&b);
        prop_assert!(a.contains_set(&i) && b.contains_set(&i));
    }

    #[test]
    fn coherence_union_concret(a: HeaderSet, b: HeaderSet, p in arb_packet()) {
        prop_assert_eq!(a.union(&b).contains(&p), a.contains(&p) || b.contains(&p));
    }

    #[test]
    fn coherence_intersection_concret(a: HeaderSet, b: HeaderSet, p in arb_packet()) {
        prop_assert_eq!(a.intersect(&b).contains(&p), a.contains(&p) && b.contains(&p));
    }

    #[test]
    fn coherence_soustraction_concret(a: HeaderSet, b: HeaderSet, p in arb_packet()) {
        prop_assert_eq!(a.subtract(&b).contains(&p), a.contains(&p) && !b.contains(&p));
    }

    // --- sample() et invariants de structure --------------------------------

    #[test]
    fn sample_coherent_avec_is_empty(a: HeaderSet) {
        match a.sample() {
            Some(p) => prop_assert!(a.contains(&p)),
            None => prop_assert!(a.is_empty()),
        }
    }

    #[test]
    fn contains_set_reflexif(a: HeaderSet) {
        prop_assert!(a.contains_set(&a));
    }

    #[test]
    fn paves_toujours_disjoints_et_non_vides(a: HeaderSet, b: HeaderSet) {
        // L'invariant de HeaderSet doit tenir après chaque opération.
        for s in [a.union(&b), a.intersect(&b), a.subtract(&b)] {
            let cubes = s.cubes();
            for (i, x) in cubes.iter().enumerate() {
                prop_assert!(!x.is_empty());
                for y in &cubes[i + 1..] {
                    prop_assert!(x.intersect(y).is_empty());
                }
            }
        }
    }

    // --- Lois au niveau des dimensions --------------------------------------

    #[test]
    fn lois_prefixset(a in arb_prefix_set(), b in arb_prefix_set()) {
        // La forme des préfixes est canonique : Eq structurel = ensembliste.
        prop_assert_eq!(a.intersect(&b), b.intersect(&a));
        prop_assert_eq!(a.union(&b), b.union(&a));
        prop_assert!(a.subtract(&b).intersect(&b).is_empty());
        prop_assert_eq!(a.subtract(&b).union(&a.intersect(&b)), a.clone());
        prop_assert!(a.union(&b).contains_set(&a));
    }

    #[test]
    fn lois_portranges(a in arb_port_ranges(), b in arb_port_ranges()) {
        prop_assert_eq!(a.intersect(&b), b.intersect(&a));
        prop_assert_eq!(a.union(&b), b.union(&a));
        prop_assert!(a.subtract(&b).intersect(&b).is_empty());
        prop_assert_eq!(a.subtract(&b).union(&a.intersect(&b)), a.clone());
    }

    // --- Chemins directs contre définitions par soustraction ----------------
    // Les implémentations optimisées (inclusion et disjonction sans
    // allocation) doivent coïncider avec la définition ensembliste.

    #[test]
    fn contains_set_prefixes_coincide_avec_la_soustraction(
        a in arb_prefix_set(),
        b in arb_prefix_set(),
    ) {
        prop_assert_eq!(a.contains_set(&b), b.subtract(&a).is_empty());
    }

    #[test]
    fn contains_set_ports_coincide_avec_la_soustraction(
        a in arb_port_ranges(),
        b in arb_port_ranges(),
    ) {
        prop_assert_eq!(a.contains_set(&b), b.subtract(&a).is_empty());
    }

    #[test]
    fn is_disjoint_coincide_avec_l_intersection(a: HeaderSet, b: HeaderSet) {
        prop_assert_eq!(a.is_disjoint(&b), a.intersect(&b).is_empty());
        prop_assert_eq!(a.is_disjoint(&b), b.is_disjoint(&a));
    }

    #[test]
    fn contains_set_headerset_coincide_avec_la_soustraction(a: HeaderSet, b: HeaderSet) {
        prop_assert_eq!(a.contains_set(&b), b.subtract(&a).is_empty());
    }

    #[test]
    fn soustraction_de_cube_exacte(a: Cube, b: Cube) {
        // a \ b + (a ∩ b) recouvre exactement a, en pavés disjoints de b.
        let pieces = a.subtract(&b);
        let diff = HeaderSet::from_cubes(pieces.iter().cloned());
        let inter = HeaderSet::from_cube(a.intersect(&b));
        let whole = HeaderSet::from_cube(a.clone());
        prop_assert!(set_eq(&diff.union(&inter), &whole));
        for p in &pieces {
            prop_assert!(p.intersect(&b).is_empty());
        }
    }
}
