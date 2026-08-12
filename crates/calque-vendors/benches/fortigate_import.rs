//! Bench de l'import FortiGate complet (couche 1 : arbre générique,
//! puis couche 2 : conversion en représentation intermédiaire).
//!
//! NOTE : le générateur de configuration est une COPIE de celui de
//! `crates/calque-parse/benches/fortigate_parse.rs` (mêmes tailles, mêmes
//! directives) afin que « parse seul » et « import complet » soient
//! directement comparables. Les deux copies doivent rester identiques.

use std::fmt::Write as _;
use std::hint::black_box;

use calque_vendors::fortigate::FortigateAdapter;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

/// Dimensions d'une configuration synthétique.
struct Params {
    ifaces: usize,
    addrs: usize,
    services: usize,
    policies: usize,
}

/// Une configuration FortiOS synthétique et déterministe, dont chaque
/// directive est comprise par l'adaptateur (fidélité complète attendue).
fn config_synthetique(p: &Params) -> String {
    let mut s = String::with_capacity(64 * (p.ifaces * 7 + p.addrs * 4 + p.policies * 10));
    s.push_str("#config-version=FGVM64-7.4.1-FW-build0000-000000:opmode=0:vdom=0\n");
    s.push_str("config system global\n    set hostname \"fw-bench\"\nend\n");

    // --- Interfaces -------------------------------------------------------
    s.push_str("config system interface\n");
    for i in 0..p.ifaces {
        let _ = write!(
            s,
            "    edit \"port{i}\"\n        set vdom \"root\"\n        set ip 10.200.{i}.1 255.255.255.0\n        set allowaccess ping\n        set type physical\n    next\n",
        );
    }
    s.push_str("end\n");

    // --- Routes statiques (une par interface) -----------------------------
    s.push_str("config router static\n");
    for i in 0..p.ifaces {
        let _ = write!(
            s,
            "    edit {}\n        set dst 10.{}.0.0 255.255.0.0\n        set gateway 10.200.{i}.254\n        set device \"port{i}\"\n        set distance 10\n    next\n",
            i + 1,
            32 + i,
        );
    }
    s.push_str("end\n");

    // --- Objets d'adresse (moitié sous-réseaux, moitié plages) ------------
    s.push_str("config firewall address\n");
    for i in 0..p.addrs {
        let (a, b) = (i / 200, i % 200);
        if i % 2 == 0 {
            let _ = write!(
                s,
                "    edit \"h-{i}\"\n        set subnet 10.{a}.{b}.10 255.255.255.255\n    next\n",
            );
        } else {
            let _ = write!(
                s,
                "    edit \"h-{i}\"\n        set type iprange\n        set start-ip 10.{a}.{b}.50\n        set end-ip 10.{a}.{b}.69\n    next\n",
            );
        }
    }
    s.push_str("end\n");

    // --- Groupes d'adresses (par paquets de dix) --------------------------
    s.push_str("config firewall addrgrp\n");
    for g in 0..p.addrs / 10 {
        let members: Vec<String> = (g * 10..g * 10 + 10)
            .map(|i| format!("\"h-{i}\""))
            .collect();
        let _ = write!(
            s,
            "    edit \"g-{g}\"\n        set member {}\n    next\n",
            members.join(" "),
        );
    }
    s.push_str("end\n");

    // --- Services ---------------------------------------------------------
    s.push_str("config firewall service custom\n");
    for i in 0..p.services {
        let port = 1024 + (i % 30000) * 2;
        let _ = write!(
            s,
            "    edit \"TCP-{port}\"\n        set tcp-portrange {port}\n    next\n",
        );
    }
    s.push_str("end\n");

    // --- Politiques -------------------------------------------------------
    s.push_str("config firewall policy\n");
    for i in 0..p.policies {
        let port = 1024 + (i % p.services.max(1) % 30000) * 2;
        let _ = write!(
            s,
            "    edit {}\n        set name \"pol-{i}\"\n        set srcintf \"port{}\"\n        set dstintf \"port{}\"\n        set srcaddr \"h-{}\"\n        set dstaddr \"all\"\n        set action accept\n        set schedule \"always\"\n        set service \"TCP-{port}\"\n    next\n",
            i + 1,
            i % p.ifaces,
            (i + 1) % p.ifaces,
            i % p.addrs.max(1),
        );
    }
    s.push_str("end\n");
    s
}

/// Les trois tailles cibles (~1 000, ~10 000 et ~50 000 lignes).
fn tailles() -> Vec<(&'static str, Params)> {
    vec![
        (
            "1k",
            Params {
                ifaces: 10,
                addrs: 80,
                services: 40,
                policies: 60,
            },
        ),
        (
            "10k",
            Params {
                ifaces: 30,
                addrs: 800,
                services: 300,
                policies: 600,
            },
        ),
        (
            "50k",
            Params {
                ifaces: 60,
                addrs: 4000,
                services: 1500,
                policies: 3000,
            },
        ),
    ]
}

fn bench_import(c: &mut Criterion) {
    let mut g = c.benchmark_group("fortigate_import");
    g.sample_size(20);
    for (nom, p) in tailles() {
        let raw = config_synthetique(&p);
        let lignes = raw.lines().count() as u64;

        // Garde-fou de réalisme : la configuration doit être ENTIÈREMENT
        // comprise (sinon on mesurerait surtout l'accumulation de
        // diagnostics d'incompréhension).
        let sortie = FortigateAdapter
            .import_str(&raw, "bench.conf")
            .expect("import de la configuration synthétique");
        assert!(
            sortie.fidelity.is_complete(),
            "configuration « {nom} » partiellement comprise : {:?}",
            sortie.fidelity
        );
        eprintln!(
            "[bench] configuration « {nom} » : {lignes} lignes, {} politiques, {} objets d'adresse",
            sortie
                .device
                .policies
                .values()
                .map(|p| p.rules.len())
                .sum::<usize>(),
            sortie.device.objects.addresses.len(),
        );

        g.throughput(Throughput::Elements(lignes));
        g.bench_with_input(BenchmarkId::new("import_str", nom), &raw, |b, raw| {
            b.iter(|| {
                FortigateAdapter
                    .import_str(black_box(raw), "bench.conf")
                    .expect("configuration synthétique valide")
            });
        });
    }
    g.finish();
}

criterion_group!(benches, bench_import);
criterion_main!(benches);
