//! Tests de profondeur sur la fixture `corpus/fortigate/basic.conf`
//! (configuration fictive et anonyme, adressage RFC1918 inventé).
//!
//! La fixture est entièrement couverte par l'adaptateur : la fidélité
//! attendue est `Complete`. Un second test injecte des directives
//! exotiques et vérifie qu'elles produisent des diagnostics et
//! `Fidelity::Partial` (§6.3 : ne jamais deviner).

use calque_model::{
    Action, AddrExpr, AddrObject, AdminState, Device, Fidelity, IfaceId, Interface, NextHop,
    ObjectId, PolicyId, PortRange, ProtoMatch, RouteOrigin, ServiceExpr, ServiceObject, Severity,
    VrfId, ZoneId,
};
use calque_vendors::fortigate::FortigateAdapter;
use calque_vendors::{AdapterOutput, VendorAdapter};

/// La fixture, embarquée à la compilation (crate pur : aucune E/S).
const BASIC: &str = include_str!("../../../corpus/fortigate/basic.conf");
const FILE: &str = "basic.conf";

fn import_basic() -> AdapterOutput {
    FortigateAdapter
        .import_str(BASIC, FILE)
        .expect("la fixture doit produire un modèle")
}

fn iface<'a>(dev: &'a Device, name: &str) -> &'a Interface {
    dev.interfaces
        .get(&IfaceId::new(name))
        .unwrap_or_else(|| panic!("interface `{name}` absente"))
}

fn addr_obj<'a>(dev: &'a Device, name: &str) -> &'a AddrObject {
    dev.objects
        .addresses
        .get(&ObjectId::new(name))
        .unwrap_or_else(|| panic!("objet adresse `{name}` absent"))
}

fn svc_obj<'a>(dev: &'a Device, name: &str) -> &'a ServiceObject {
    dev.objects
        .services
        .get(&ObjectId::new(name))
        .unwrap_or_else(|| panic!("service `{name}` absent"))
}

// ---------------------------------------------------------------------------
// Détection
// ---------------------------------------------------------------------------

#[test]
fn detection_fortigate() {
    let adapter = FortigateAdapter;
    let c = adapter.detect(BASIC);
    assert!(c.is_confident(), "score détecté : {}", c.score());
    assert_eq!(
        c.score(),
        100,
        "tous les motifs de la fixture sont présents"
    );

    // Un texte Cisco IOS ne doit pas être pris pour du FortiGate.
    let ios = "hostname r1\ninterface GigabitEthernet0/0\n ip address 10.0.0.1 255.255.255.0\n!\n";
    assert!(!adapter.detect(ios).is_confident());
    assert_eq!(adapter.detect("").score(), 0);
}

// ---------------------------------------------------------------------------
// Fidélité : la fixture est entièrement comprise
// ---------------------------------------------------------------------------

#[test]
fn fidelite_complete_sur_la_fixture() {
    let out = import_basic();
    assert_eq!(
        out.fidelity,
        Fidelity::Complete,
        "la fixture ne contient que des directives gérées"
    );
    // La politique 4 désactivée produit une note Info — un constat,
    // pas une incompréhension.
    let infos: Vec<_> = out
        .notes
        .iter()
        .filter(|n| n.severity == Severity::Info)
        .collect();
    assert_eq!(infos.len(), 1);
    assert!(infos[0].message.contains("politique 4"));
    assert!(infos[0].message.contains("désactivée"));
}

// ---------------------------------------------------------------------------
// Interfaces et zones
// ---------------------------------------------------------------------------

#[test]
fn interfaces_adresses_et_etat() {
    let dev = import_basic().device;
    assert_eq!(
        dev.id.as_str(),
        "fw-lab-01",
        "le hostname prime sur le nom de fichier"
    );
    assert_eq!(dev.interfaces.len(), 3);

    let lan = iface(&dev, "lan");
    assert_eq!(lan.addrs, vec!["10.10.1.1/24".parse().unwrap()]);
    assert_eq!(lan.state, AdminState::Up);
    assert!(lan.members.is_empty());
    assert_eq!(lan.vrf, VrfId::default_vrf());

    let dmz = iface(&dev, "dmz");
    assert_eq!(dmz.addrs, vec!["10.10.2.1/24".parse().unwrap()]);
    assert_eq!(dmz.zone.as_ref().map(|z| z.as_str()), Some("z-dmz"));

    let wan = iface(&dev, "wan");
    assert_eq!(wan.addrs, vec!["10.200.0.2/30".parse().unwrap()]);
}

#[test]
fn zones_explicites_et_implicites() {
    let dev = import_basic().device;
    // z-dmz est déclarée ; lan et wan sont des zones implicites créées
    // parce que les politiques référencent ces interfaces directement.
    assert_eq!(dev.zones.len(), 3);
    assert_eq!(
        dev.zones.get(&ZoneId::new("z-dmz")),
        Some(&vec![IfaceId::new("dmz")])
    );
    assert_eq!(
        dev.zones.get(&ZoneId::new("lan")),
        Some(&vec![IfaceId::new("lan")])
    );
    assert_eq!(
        dev.zones.get(&ZoneId::new("wan")),
        Some(&vec![IfaceId::new("wan")])
    );
    // L'appartenance implicite est aussi visible côté interface.
    assert_eq!(
        iface(&dev, "lan").zone.as_ref().map(|z| z.as_str()),
        Some("lan")
    );
}

// ---------------------------------------------------------------------------
// Routage
// ---------------------------------------------------------------------------

#[test]
fn route_statique_par_defaut() {
    let dev = import_basic().device;
    let vrf = dev
        .vrfs
        .get(&VrfId::default_vrf())
        .expect("le VRF par défaut existe");
    assert_eq!(vrf.routes.len(), 1);
    let r = &vrf.routes[0];
    assert_eq!(r.prefix, "0.0.0.0/0".parse().unwrap());
    assert_eq!(r.next_hop, NextHop::Ip("10.200.0.1".parse().unwrap()));
    assert_eq!(r.metric, 10);
    assert_eq!(r.origin, RouteOrigin::Static);
    let span = r.source.as_ref().expect("une route porte son origine");
    assert_eq!(span.file, FILE);
    assert_eq!(span.line, 35); // ligne du `edit 1` de `config router static`
}

// ---------------------------------------------------------------------------
// Objets adresses et services
// ---------------------------------------------------------------------------

#[test]
fn objets_adresses_et_groupe() {
    let dev = import_basic().device;
    assert_eq!(dev.objects.addresses.len(), 3); // 2 objets + 1 groupe

    // Hôte /32.
    match addr_obj(&dev, "h-srv-web") {
        AddrObject::Nets(nets) => {
            assert_eq!(nets, &vec!["10.10.2.10/32".parse().unwrap()]);
        }
        other => panic!("h-srv-web devrait être des réseaux : {other:?}"),
    }

    // iprange 10.10.1.50-69 → décomposition CIDR EXACTE (5 préfixes).
    match addr_obj(&dev, "r-postes") {
        AddrObject::Nets(nets) => {
            let texte: Vec<String> = nets.iter().map(|n| n.to_string()).collect();
            assert_eq!(
                texte,
                vec![
                    "10.10.1.50/31",
                    "10.10.1.52/30",
                    "10.10.1.56/29",
                    "10.10.1.64/30",
                    "10.10.1.68/31",
                ]
            );
        }
        other => panic!("r-postes devrait être des réseaux : {other:?}"),
    }

    // Le groupe garde des RÉFÉRENCES (résolution tardive, §3.3).
    match addr_obj(&dev, "g-serveurs") {
        AddrObject::Group(members) => {
            let noms: Vec<&str> = members.iter().map(|m| m.as_str()).collect();
            assert_eq!(noms, vec!["h-srv-web", "r-postes"]);
        }
        other => panic!("g-serveurs devrait être un groupe : {other:?}"),
    }
}

#[test]
fn services_personnalises_et_groupe() {
    let dev = import_basic().device;
    assert_eq!(dev.objects.services.len(), 3); // 2 services + 1 groupe

    match svc_obj(&dev, "TCP-8443") {
        ServiceObject::Services(svcs) => {
            assert_eq!(svcs.len(), 1);
            assert_eq!(svcs[0].proto, ProtoMatch::Number(6));
            assert_eq!(svcs[0].dport, PortRange::single(8443));
            assert_eq!(svcs[0].sport, PortRange::ANY);
        }
        other => panic!("TCP-8443 : {other:?}"),
    }

    // APP-SYNC : forme `dstrange:srcrange` en TCP, plus un port UDP.
    match svc_obj(&dev, "APP-SYNC") {
        ServiceObject::Services(svcs) => {
            assert_eq!(svcs.len(), 2);
            assert_eq!(svcs[0].proto, ProtoMatch::Number(6));
            assert_eq!(
                svcs[0].dport,
                PortRange {
                    start: 7000,
                    end: 7010
                }
            );
            assert_eq!(
                svcs[0].sport,
                PortRange {
                    start: 1024,
                    end: 65535
                }
            );
            assert_eq!(svcs[1].proto, ProtoMatch::Number(17));
            assert_eq!(svcs[1].dport, PortRange::single(7000));
            assert_eq!(svcs[1].sport, PortRange::ANY);
        }
        other => panic!("APP-SYNC : {other:?}"),
    }

    match svc_obj(&dev, "g-apps") {
        ServiceObject::Group(members) => {
            let noms: Vec<&str> = members.iter().map(|m| m.as_str()).collect();
            assert_eq!(noms, vec!["TCP-8443", "APP-SYNC"]);
        }
        other => panic!("g-apps : {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Politique de filtrage
// ---------------------------------------------------------------------------

#[test]
fn politique_ordre_actions_et_spans() {
    let dev = import_basic().device;

    // La politique forward est accrochée en entrée (filtrage forward
    // FortiGate, choix documenté dans l'adaptateur).
    assert_eq!(dev.policies.len(), 1);
    let policy = dev
        .policies
        .get(&PolicyId::new("forward"))
        .expect("la politique forward existe");
    assert_eq!(dev.pipeline.ingress, vec![policy.id.clone()]);
    assert!(dev.pipeline.egress.is_empty());
    assert_eq!(policy.default_action, Action::Deny);

    // ORDRE SIGNIFICATIF : 1, 2, 3, 5 — la 4 (désactivée) est écartée.
    let ids: Vec<&str> = policy.rules.iter().map(|r| r.id.as_str()).collect();
    assert_eq!(ids, vec!["1", "2", "3", "5"]);

    // Règle 1 : lan → wan, tout, NAT activé.
    let r1 = &policy.rules[0];
    assert_eq!(r1.from.as_ref().map(|z| z.as_str()), Some("lan"));
    assert_eq!(r1.to.as_ref().map(|z| z.as_str()), Some("wan"));
    assert_eq!(r1.matches.src, vec![AddrExpr::Any]);
    assert_eq!(r1.matches.dst, vec![AddrExpr::Any]);
    assert_eq!(r1.matches.services, vec![ServiceExpr::Any]);
    assert!(
        matches!(r1.action, Action::Nat(_)),
        "`set nat enable` → Action::Nat"
    );

    // Règle 2 : références d'objets conservées (résolution tardive).
    let r2 = &policy.rules[1];
    assert_eq!(r2.from.as_ref().map(|z| z.as_str()), Some("lan"));
    assert_eq!(r2.to.as_ref().map(|z| z.as_str()), Some("z-dmz"));
    assert_eq!(
        r2.matches.src,
        vec![AddrExpr::Object(ObjectId::new("r-postes"))]
    );
    assert_eq!(
        r2.matches.dst,
        vec![AddrExpr::Object(ObjectId::new("h-srv-web"))]
    );
    assert_eq!(
        r2.matches.services,
        vec![ServiceExpr::Object(ObjectId::new("TCP-8443"))]
    );
    assert_eq!(r2.action, Action::Accept);

    // Règle 3 : refus explicite z-dmz → lan.
    let r3 = &policy.rules[2];
    assert_eq!(r3.from.as_ref().map(|z| z.as_str()), Some("z-dmz"));
    assert_eq!(r3.to.as_ref().map(|z| z.as_str()), Some("lan"));
    assert_eq!(r3.action, Action::Deny);

    // SourceSpan EXACTS de deux règles : la ligne du `edit`, la ligne du
    // `next` en fin. « La trace est le produit. »
    assert_eq!(r1.source.file, FILE);
    assert_eq!(r1.source.line, 71);
    assert_eq!(r1.source.end_line, Some(81));
    assert_eq!(r3.source.file, FILE);
    assert_eq!(r3.source.line, 92);
    assert_eq!(r3.source.end_line, Some(101));
}

// ---------------------------------------------------------------------------
// §6.3 — ne jamais deviner : directive exotique → diagnostic + Partial
// ---------------------------------------------------------------------------

#[test]
fn directive_exotique_degrade_la_fidelite() {
    // La fixture, augmentée d'un bloc inconnu et d'une directive
    // inconnue au sein d'un bloc géré.
    let exotique = format!(
        "{BASIC}config system replacemsg-group\n    edit \"exotique\"\n        set group-type utm\n    next\nend\nconfig system interface\n    edit \"lan\"\n        set gadget-quantique enable\n    next\nend\n"
    );
    let out = FortigateAdapter
        .import_str(&exotique, FILE)
        .expect("un modèle partiel doit tout de même sortir");

    let unsupported = match &out.fidelity {
        Fidelity::Partial { unsupported } => unsupported,
        Fidelity::Complete => panic!("une directive non comprise DOIT dégrader la fidélité"),
    };
    // Le bloc inconnu ET la directive inconnue sont diagnostiqués,
    // chacun avec son span. Rien n'est ignoré en silence.
    assert!(
        unsupported
            .iter()
            .any(|d| d.message.contains("replacemsg-group")),
        "le bloc inconnu doit être diagnostiqué : {unsupported:?}"
    );
    let gadget = unsupported
        .iter()
        .find(|d| d.message.contains("gadget-quantique"))
        .expect("la directive inconnue doit être diagnostiquée");
    let span = gadget.span.as_ref().expect("le diagnostic porte un span");
    assert_eq!(span.file, FILE);
    assert!(span.line > 123, "le span pointe dans le bloc ajouté");
}

// ---------------------------------------------------------------------------
// Robustesse : jamais de panique sur une entrée externe
// ---------------------------------------------------------------------------

#[test]
fn entrees_hostiles_sans_panique() {
    let adapter = FortigateAdapter;
    for raw in [
        "",
        "end\nend\nnext\n",
        "config firewall policy\n edit oops\n set action self-destruct\n",
        "set ip 999.999.999.999 not-a-mask\n",
        "config system interface\n edit \"x\n set ip 10.0.0.1 255.0.255.0\nend\n",
    ] {
        // Ok(modèle partiel) ou Err(diagnostics) : tout sauf une panique.
        let _ = adapter.import_str(raw, "hostile.conf");
    }
}
