//! Tests de profondeur sur la fixture `corpus/fortigate/basic.conf`
//! (configuration fictive et anonyme, adressage RFC1918 inventé).
//!
//! La fixture est entièrement couverte par l'adaptateur : la fidélité
//! attendue est `Complete`. Un second test injecte des directives
//! exotiques et vérifie qu'elles produisent des diagnostics et
//! `Fidelity::Partial` (§6.3 : ne jamais deviner).

use calque_model::{
    Action, AddrExpr, AddrObject, AdminState, Device, DnatTarget, ExternalKind, Fidelity, IfaceId,
    Interface, NatAction, NextHop, ObjectId, PolicyId, PortRange, ProtoMatch, RouteOrigin, Service,
    ServiceExpr, ServiceObject, Severity, VrfId, ZoneId,
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
    // Six constats Info (pas des incompréhensions) : health-check SD-WAN,
    // topologie du tunnel IPsec, les DEUX objets externes (fqdn + géo,
    // compris mais d'étendue à fournir — pas des lacunes), politique 4
    // désactivée, politique 7 éclatée (une règle par VIP).
    let infos: Vec<_> = out
        .notes
        .iter()
        .filter(|n| n.severity == Severity::Info)
        .collect();
    assert_eq!(infos.len(), 6, "{infos:?}");
    let dit = |motif: &str| infos.iter().any(|n| n.message.contains(motif));
    assert!(dit("health-check SD-WAN `hc-dns`"));
    assert!(infos
        .iter()
        .any(|n| n.message.contains("tunnel IPsec `vpn-site-a`")
            && n.message.contains("10.201.0.1")
            && n.message.contains("via `wan`")));
    assert!(dit("politique 4") && dit("désactivée"));
    assert!(dit("politique 7 éclatée"));
    // Les objets externes : compris (note Info), étendue à fournir.
    assert!(
        infos
            .iter()
            .any(|n| n.message.contains("fqdn-insights")
                && n.message.contains("insights.nutanix.com"))
    );
    assert!(infos
        .iter()
        .any(|n| n.message.contains("geo-fr") && n.message.contains("FR")));
    // Aucun avertissement : les objets externes ne dégradent PAS la
    // fidélité (ils sont compris), et toutes les références se résolvent.
    assert!(
        out.notes.iter().all(|n| n.severity == Severity::Info),
        "{:?}",
        out.notes
    );
}

/// Les objets `fqdn` et `geography` sont STOCKÉS en `External` (compris,
/// étendue externe), plus jamais jetés/exclus par « objet manquant ».
#[test]
fn objets_externes_fqdn_et_geography() {
    let dev = import_basic().device;
    assert_eq!(
        addr_obj(&dev, "fqdn-insights"),
        &AddrObject::External {
            kind: ExternalKind::Fqdn,
            hint: "insights.nutanix.com".to_owned(),
        }
    );
    assert_eq!(
        addr_obj(&dev, "geo-fr"),
        &AddrObject::External {
            kind: ExternalKind::Geography,
            hint: "FR".to_owned(),
        }
    );
}

/// Un `type wildcard-fqdn` (et un `type fqdn` dont la valeur porte un `*`)
/// deviennent un `External` de type WildcardFqdn, résoluble par clé exacte.
#[test]
fn objet_wildcard_fqdn_est_externe() {
    let conf = format!(
        "{BASIC}config firewall address\n    edit \"wild-explicite\"\n        \
         set type wildcard-fqdn\n        set wildcard-fqdn \"*.nutanix.com\"\n    next\n    \
         edit \"wild-implicite\"\n        set type fqdn\n        set fqdn \"*.example.com\"\n    \
         next\nend\n"
    );
    let out = FortigateAdapter
        .import_str(&conf, FILE)
        .expect("un modèle doit sortir");
    // L'objet externe ne dégrade pas la fidélité (il est compris).
    assert_eq!(out.fidelity, Fidelity::Complete, "{:?}", out.fidelity);
    assert_eq!(
        addr_obj(&out.device, "wild-explicite"),
        &AddrObject::External {
            kind: ExternalKind::WildcardFqdn,
            hint: "*.nutanix.com".to_owned(),
        }
    );
    assert_eq!(
        addr_obj(&out.device, "wild-implicite"),
        &AddrObject::External {
            kind: ExternalKind::WildcardFqdn,
            hint: "*.example.com".to_owned(),
        }
    );
}

/// §11.4 — le secret pré-partagé du tunnel IPsec ne fuit JAMAIS dans un
/// diagnostic, quelle que soit la sévérité.
#[test]
fn psksecret_absent_de_tous_les_diagnostics() {
    let out = import_basic();
    assert!(
        BASIC.contains("SecretFictifPartage"),
        "le secret est bien là"
    );
    for note in &out.notes {
        assert!(!note.message.contains("SecretFictifPartage"), "{note:?}");
    }
    if let Fidelity::Partial { unsupported } = &out.fidelity {
        for d in unsupported {
            assert!(!d.message.contains("SecretFictifPartage"), "{d:?}");
        }
    }
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
    assert_eq!(dev.interfaces.len(), 5);

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

    let wan2 = iface(&dev, "wan2");
    assert_eq!(wan2.addrs, vec!["10.200.4.2/30".parse().unwrap()]);

    // L'interface tunnel IPsec, sans adresse (type tunnel).
    let tunnel = iface(&dev, "vpn-site-a");
    assert!(tunnel.addrs.is_empty());
    assert_eq!(tunnel.state, AdminState::Up);
}

#[test]
fn zones_explicites_et_implicites() {
    let dev = import_basic().device;
    // z-dmz est déclarée ; lan, wan et vpn-site-a sont des zones
    // implicites créées parce que les politiques (et la politique IPsec
    // de sortie) référencent ces interfaces directement ; SD-WAN est la
    // zone des membres SD-WAN (les politiques `dstintf "SD-WAN"` doivent
    // s'appliquer quand le paquet sort par un membre).
    assert_eq!(dev.zones.len(), 5);
    assert_eq!(
        dev.zones.get(&ZoneId::new("SD-WAN")),
        Some(&vec![IfaceId::new("wan"), IfaceId::new("wan2")])
    );
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
    assert_eq!(
        dev.zones.get(&ZoneId::new("vpn-site-a")),
        Some(&vec![IfaceId::new("vpn-site-a")])
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
fn route_par_defaut_sdwan_une_route_par_membre() {
    let dev = import_basic().device;
    let vrf = dev
        .vrfs
        .get(&VrfId::default_vrf())
        .expect("le VRF par défaut existe");
    // La route par défaut `set sdwan-zone "SD-WAN"` (deux membres) est
    // développée en DEUX routes candidates de même préfixe et même
    // métrique (ECMP, évaluées par branches par le moteur), plus la
    // route par objet vers le site distant.
    assert_eq!(vrf.routes.len(), 3, "{:?}", vrf.routes);

    let r1 = &vrf.routes[0];
    assert_eq!(r1.prefix, "0.0.0.0/0".parse().unwrap());
    assert_eq!(r1.next_hop, NextHop::Ip("10.200.0.1".parse().unwrap()));
    assert_eq!(r1.metric, 10);
    assert_eq!(r1.origin, RouteOrigin::Static);

    let r2 = &vrf.routes[1];
    assert_eq!(r2.prefix, "0.0.0.0/0".parse().unwrap());
    assert_eq!(r2.next_hop, NextHop::Ip("10.200.4.1".parse().unwrap()));
    assert_eq!(r2.metric, 10);

    // Les deux candidates portent le span de la MÊME route source.
    for r in [r1, r2] {
        let span = r.source.as_ref().expect("une route porte son origine");
        assert_eq!(span.file, FILE);
        assert_eq!(span.line, 35); // `edit 1` de `config router static`
        assert_eq!(span.end_line, Some(39));
    }
}

#[test]
fn route_par_objet_adresse() {
    let dev = import_basic().device;
    let vrf = dev
        .vrfs
        .get(&VrfId::default_vrf())
        .expect("le VRF par défaut existe");
    // `set dstaddr "r-site-a"` (10.60.0.0/16) + `set device
    // "vpn-site-a"` → une route par préfixe de l'objet.
    let r = &vrf.routes[2];
    assert_eq!(r.prefix, "10.60.0.0/16".parse().unwrap());
    assert_eq!(r.next_hop, NextHop::Interface(IfaceId::new("vpn-site-a")));
    assert_eq!(r.metric, 15);
    assert_eq!(r.origin, RouteOrigin::Static);
    let span = r.source.as_ref().expect("une route porte son origine");
    assert_eq!(span.file, FILE);
    assert_eq!(span.line, 208); // `edit 2` du second bloc router static
    assert_eq!(span.end_line, Some(212));
}

// ---------------------------------------------------------------------------
// Objets adresses et services
// ---------------------------------------------------------------------------

#[test]
fn objets_adresses_et_groupe() {
    let dev = import_basic().device;
    // 4 objets + 1 groupe + 2 VIP + 1 groupe de VIP + 2 objets externes
    // (fqdn + géographie).
    assert_eq!(dev.objects.addresses.len(), 10);

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

// ---------------------------------------------------------------------------
// VIP : objets adresse résolus + groupe
// ---------------------------------------------------------------------------

#[test]
fn vips_resolus_en_objets_adresse() {
    let dev = import_basic().device;

    // Chaque VIP est un objet adresse portant son adresse EXTERNE : les
    // `dstaddr "vip-…"` des politiques se résolvent.
    assert_eq!(
        addr_obj(&dev, "vip-web-443"),
        &AddrObject::Nets(vec!["10.200.0.10/32".parse().unwrap()])
    );
    assert_eq!(
        addr_obj(&dev, "vip-un-pour-un"),
        &AddrObject::Nets(vec!["10.200.0.11/32".parse().unwrap()])
    );

    // Le groupe de VIP est un groupe d'objets adresse ordinaire.
    match addr_obj(&dev, "g-vips") {
        AddrObject::Group(members) => {
            let noms: Vec<&str> = members.iter().map(|m| m.as_str()).collect();
            assert_eq!(noms, vec!["vip-web-443", "vip-un-pour-un"]);
        }
        other => panic!("g-vips devrait être un groupe : {other:?}"),
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
    // FortiGate, choix documenté dans l'adaptateur) ; la politique de
    // sortie IPsec est testée à part.
    assert_eq!(dev.policies.len(), 2);
    let policy = dev
        .policies
        .get(&PolicyId::new("forward"))
        .expect("la politique forward existe");
    assert_eq!(dev.pipeline.ingress, vec![policy.id.clone()]);
    assert_eq!(policy.default_action, Action::Deny);

    // ORDRE SIGNIFICATIF : la 4 (désactivée) est écartée, la 7 est
    // ÉCLATÉE en une règle par VIP du groupe (identifiants suffixés).
    let ids: Vec<&str> = policy.rules.iter().map(|r| r.id.as_str()).collect();
    assert_eq!(
        ids,
        vec![
            "1",
            "2",
            "3",
            "5",
            "6",
            "7:vip-web-443",
            "7:vip-un-pour-un",
            "8",
            // La règle vers l'objet externe fqdn (résolution `--resolve`).
            "20"
        ]
    );

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
// VIP : DNAT porté par les règles, éclatement multi-VIP
// ---------------------------------------------------------------------------

#[test]
fn regle_vers_vip_porte_le_dnat() {
    let dev = import_basic().device;
    let policy = dev
        .policies
        .get(&PolicyId::new("forward"))
        .expect("la politique forward existe");

    // Règle 6 : un seul VIP à redirection de port — identifiant intact.
    let r6 = policy
        .rules
        .iter()
        .find(|r| r.id.as_str() == "6")
        .expect("règle 6");
    assert_eq!(r6.from.as_ref().map(|z| z.as_str()), Some("wan"));
    assert_eq!(r6.to.as_ref().map(|z| z.as_str()), Some("z-dmz"));
    assert_eq!(
        r6.matches.dst,
        vec![AddrExpr::Object(ObjectId::new("vip-web-443"))]
    );
    // `set protocol tcp` + `set extport 443` contraignent le service de
    // la règle (le `service "ALL"` d'origine est remplacé EXACTEMENT).
    assert_eq!(
        r6.matches.services,
        vec![ServiceExpr::Service(Service::tcp_dport(PortRange::single(
            443
        )))]
    );
    // La règle porte la redirection : extip:443 → mappedip:8443.
    assert_eq!(
        r6.action,
        Action::Nat(NatAction {
            snat: None,
            dnat: Some(DnatTarget {
                addr: "10.10.2.10".parse().unwrap(),
                port: Some(8443),
            }),
        })
    );
    assert_eq!(r6.source.line, 215);
    assert_eq!(r6.source.end_line, Some(224));
}

#[test]
fn regle_multi_vip_eclatee_une_regle_par_vip() {
    let dev = import_basic().device;
    let policy = dev
        .policies
        .get(&PolicyId::new("forward"))
        .expect("la politique forward existe");

    // Règle 7 (`dstaddr "g-vips"`) : deux VIP aux cibles DIFFÉRENTES →
    // deux règles, une par VIP, même span (celui du `edit 7`).
    let r7a = policy
        .rules
        .iter()
        .find(|r| r.id.as_str() == "7:vip-web-443")
        .expect("règle 7:vip-web-443");
    let r7b = policy
        .rules
        .iter()
        .find(|r| r.id.as_str() == "7:vip-un-pour-un")
        .expect("règle 7:vip-un-pour-un");

    assert_eq!(
        r7a.matches.dst,
        vec![AddrExpr::Object(ObjectId::new("vip-web-443"))]
    );
    assert_eq!(
        r7a.action,
        Action::Nat(NatAction {
            snat: None,
            dnat: Some(DnatTarget {
                addr: "10.10.2.10".parse().unwrap(),
                port: Some(8443),
            }),
        })
    );

    // VIP 1:1 : DNAT d'adresse seule, ports préservés, service d'origine
    // (`ALL`) conservé.
    assert_eq!(
        r7b.matches.dst,
        vec![AddrExpr::Object(ObjectId::new("vip-un-pour-un"))]
    );
    assert_eq!(r7b.matches.services, vec![ServiceExpr::Any]);
    assert_eq!(
        r7b.action,
        Action::Nat(NatAction {
            snat: None,
            dnat: Some(DnatTarget {
                addr: "10.10.2.11".parse().unwrap(),
                port: None,
            }),
        })
    );

    // Même origine : les deux règles remontent au `edit 7`.
    for r in [r7a, r7b] {
        assert_eq!(r.source.file, FILE);
        assert_eq!(r.source.line, 225);
        assert_eq!(r.source.end_line, Some(234));
    }
}

// ---------------------------------------------------------------------------
// IPsec : sélecteurs phase2 → politique de sortie sur le tunnel
// ---------------------------------------------------------------------------

#[test]
fn politique_ipsec_egress_sur_le_tunnel() {
    let dev = import_basic().device;

    // La politique `ipsec:vpn-site-a` est accrochée en SORTIE. Dans le
    // pipeline chaîné du moteur elle voit AUSSI le trafic hors tunnel :
    // défaut Accept, et le rejet FortiGate (« ce qui ne matche aucun
    // sélecteur est jeté ») est porté par la règle FINALE
    // `ipsec-implicit-deny`, scopée à la zone du tunnel.
    let pid = PolicyId::new("ipsec:vpn-site-a");
    assert_eq!(dev.pipeline.egress, vec![pid.clone()]);
    let policy = dev.policies.get(&pid).expect("la politique ipsec existe");
    assert_eq!(policy.default_action, Action::Accept);
    assert_eq!(policy.rules.len(), 2);
    let deny = &policy.rules[1];
    assert_eq!(deny.id.as_str(), "ipsec-implicit-deny");
    assert_eq!(deny.action, Action::Deny);
    assert_eq!(deny.to.as_ref().map(|z| z.as_str()), Some("vpn-site-a"));
    assert!(deny.matches.src.is_empty() && deny.matches.dst.is_empty());

    // Le sélecteur : src r-lan → dst r-site-a, Accept, zone de sortie =
    // l'interface tunnel.
    let sel = &policy.rules[0];
    assert_eq!(sel.id.as_str(), "vpn-site-a-p2");
    assert_eq!(sel.from, None);
    assert_eq!(sel.to.as_ref().map(|z| z.as_str()), Some("vpn-site-a"));
    assert_eq!(
        sel.matches.src,
        vec![AddrExpr::Object(ObjectId::new("r-lan"))]
    );
    assert_eq!(
        sel.matches.dst,
        vec![AddrExpr::Object(ObjectId::new("r-site-a"))]
    );
    assert!(sel.matches.services.is_empty(), "tous services");
    assert_eq!(sel.action, Action::Accept);

    // Span exact : le `edit "vpn-site-a-p2"` du bloc phase2.
    assert_eq!(sel.source.file, FILE);
    assert_eq!(sel.source.line, 171);
    assert_eq!(sel.source.end_line, Some(176));
}

#[test]
fn regle_vers_le_tunnel_ipsec() {
    let dev = import_basic().device;
    let policy = dev
        .policies
        .get(&PolicyId::new("forward"))
        .expect("la politique forward existe");
    // Règle 8 : lan → interface tunnel (zone implicite du même nom).
    let r8 = policy
        .rules
        .iter()
        .find(|r| r.id.as_str() == "8")
        .expect("règle 8");
    assert_eq!(r8.from.as_ref().map(|z| z.as_str()), Some("lan"));
    assert_eq!(r8.to.as_ref().map(|z| z.as_str()), Some("vpn-site-a"));
    assert_eq!(r8.action, Action::Accept);
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
    assert!(
        span.line > BASIC.lines().count() as u32,
        "le span pointe dans le bloc ajouté"
    );
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
