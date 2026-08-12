//! Benchs de l'algèbre de pavés (`HeaderSet`).
//!
//! Entrées DÉTERMINISTES : aucune source d'aléa, les familles de pavés
//! sont dérivées d'un simple compteur. Deux exécutions mesurent donc
//! exactement les mêmes opérations.
//!
//! Familles mesurées :
//! - `normalisation` : `from_cubes` sur n pavés disjoints (10/100/1000) ;
//! - `union`, `intersection`, `soustraction` : deux ensembles de n pavés
//!   (variantes disjointes et identiques) ;
//! - `fragmentation` : le cas pathologique des soustractions en chaîne
//!   (`full()` moins n flux, comme un « reste du deny par défaut »).

use std::hint::black_box;

use calque_model::PortRange;
use calque_space::{Cube, HeaderSet, HeaderSpace, PortRanges, PrefixSet, ProtoSet};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use ipnet::IpNet;

fn net(s: &str) -> IpNet {
    s.parse().expect("préfixe de bench valide")
}

/// Le pavé numéro `seed` : un flux réaliste (un /24 source, un /24
/// destination, tcp, un port de destination unique). Deux graines
/// distinctes donnent des pavés qui diffèrent d'AU MOINS deux dimensions
/// (src et dport) : les familles sont donc disjointes et sans fusion
/// possible — la forme normalisée est exactement la liste triée.
fn cube(seed: u32) -> Cube {
    let a = (seed / 200) % 200;
    let b = seed % 200;
    let src: IpNet = format!("10.{a}.{b}.0/24").parse().expect("src");
    let dst: IpNet = format!("172.16.{}.0/24", seed % 100).parse().expect("dst");
    Cube::new(
        PrefixSet::from_net(src),
        PrefixSet::from_net(dst),
        ProtoSet::single(6),
        PortRanges::full(),
        // Ports pairs : jamais adjacents, donc jamais fusionnés.
        PortRanges::single((1024 + (seed % 30000) * 2) as u16),
    )
}

/// Les pavés `offset..offset + n`, triés.
fn cubes(offset: u32, n: u32) -> Vec<Cube> {
    let mut v: Vec<Cube> = (offset..offset + n).map(cube).collect();
    v.sort();
    v
}

/// Construit un `HeaderSet` de n pavés SANS payer `from_cubes` (le coût de
/// `from_cubes` est précisément l'objet du bench `normalisation`, et il
/// serait prohibitif pour fabriquer les entrées des autres benchs).
///
/// Les pavés étant disjoints, non vides, sans fusion possible et triés
/// (cf. [`cube`]), la liste EST une forme normalisée valide : on passe par
/// la (dé)sérialisation serde, qui restitue la structure telle quelle.
/// L'équivalence avec `from_cubes` est vérifiée sur une petite taille au
/// démarrage du bench.
fn family(offset: u32, n: u32) -> HeaderSet {
    let v = serde_json::to_value(serde_json::json!({ "cubes": cubes(offset, n) }))
        .expect("sérialisation");
    serde_json::from_value(v).expect("HeaderSet valide par construction")
}

/// Garde-fou : la construction directe coïncide avec `from_cubes`.
fn verifie_la_construction() {
    let direct = family(0, 10);
    let normal = HeaderSet::from_cubes(cubes(0, 10));
    assert_eq!(direct, normal, "family() doit produire la forme normalisée");
}

const TAILLES: [u32; 3] = [10, 100, 1000];

fn bench_normalisation(c: &mut Criterion) {
    verifie_la_construction();
    let mut g = c.benchmark_group("normalisation");
    g.sample_size(10);
    for n in TAILLES {
        let input = cubes(0, n);
        g.bench_with_input(BenchmarkId::new("from_cubes", n), &input, |b, input| {
            b.iter(|| HeaderSet::from_cubes(black_box(input.iter().cloned())));
        });
    }
    g.finish();
}

fn bench_operations(c: &mut Criterion) {
    // Deux familles disjointes (graines 0.. et 40000..).
    for (nom, op) in [
        (
            "union",
            (|a, b| a.union(b)) as fn(&HeaderSet, &HeaderSet) -> HeaderSet,
        ),
        ("intersection", |a, b| a.intersect(b)),
        ("soustraction", |a, b| a.subtract(b)),
    ] {
        let mut g = c.benchmark_group(nom);
        g.sample_size(10);
        for n in TAILLES {
            let a = family(0, n);
            let b = family(40000, n);
            g.bench_with_input(BenchmarkId::new("disjoints", n), &(a, b), |bch, (a, b)| {
                bch.iter(|| op(black_box(a), black_box(b)));
            });
            // Variante « identiques » : toutes les paires se rencontrent.
            let a = family(0, n);
            let b = a.clone();
            g.bench_with_input(BenchmarkId::new("identiques", n), &(a, b), |bch, (a, b)| {
                bch.iter(|| op(black_box(a), black_box(b)));
            });
        }
        g.finish();
    }
}

/// Cas pathologique : soustractions en chaîne depuis l'espace entier.
/// C'est le motif « qu'est-ce qui reste après n règles ? » — chaque
/// soustraction fragmente le reste en davantage de pavés.
fn bench_fragmentation(c: &mut Criterion) {
    let mut g = c.benchmark_group("fragmentation");
    g.sample_size(10);
    for n in [4u32, 8, 16, 32, 64] {
        let regles: Vec<HeaderSet> = (0..n)
            .map(|i| {
                HeaderSet::flow(
                    net(&format!("10.0.{}.0/24", i % 250)),
                    net(&format!("10.64.{}.0/24", i % 250)),
                    6,
                    PortRange::single((1024 + i * 2) as u16),
                )
            })
            .collect();
        g.bench_with_input(BenchmarkId::new("chaine", n), &regles, |b, regles| {
            b.iter(|| {
                let mut reste = HeaderSet::full();
                for r in regles {
                    reste = reste.subtract(r);
                }
                black_box(reste)
            });
        });
    }
    g.finish();
}

criterion_group!(
    benches,
    bench_normalisation,
    bench_operations,
    bench_fragmentation
);
criterion_main!(benches);
