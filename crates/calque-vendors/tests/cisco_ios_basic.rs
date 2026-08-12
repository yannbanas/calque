//! Tests de profondeur sur la fixture `corpus/cisco_ios/basic.conf`
//! (configuration fictive et anonyme, adressage RFC1918 inventé).
//!
//! La fixture est entièrement couverte par l'adaptateur : la fidélité
//! attendue est `Complete` (chaque directive cosmétique est dans la
//! liste EXPLICITE des ignorables ; les secrets et l'ACL non accrochée
//! produisent des notes Info, pas des incompréhensions). Des tests
//! séparés vérifient que wildcard non contigu, NAT IOS et directives
//! inconnues produisent des diagnostics et `Fidelity::Partial` (§6.3 :
//! ne jamais deviner).

use calque_model::{
    Action, AddrExpr, AddrObject, AdminState, Device, Fidelity, IfaceId, Interface, NextHop,
    ObjectId, PolicyId, PortRange, ProtoMatch, RouteOrigin, Service, ServiceExpr, ServiceObject,
    Severity, Vendor, VrfId, ZoneId,
};
use calque_vendors::cisco_ios::CiscoIosAdapter;
use calque_vendors::fortigate::FortigateAdapter;
use calque_vendors::{all_adapters, AdapterOutput, VendorAdapter};

/// La fixture, embarquée à la compilation (crate pur : aucune E/S).
const BASIC: &str = include_str!("../../../corpus/cisco_ios/basic.conf");
/// La fixture FortiGate, pour la détection croisée.
const FORTIGATE_BASIC: &str = include_str!("../../../corpus/fortigate/basic.conf");
const FILE: &str = "basic.conf";

fn import_basic() -> AdapterOutput {
    CiscoIosAdapter
        .import_str(BASIC, FILE)
        .expect("la fixture doit produire un modèle")
}

fn import(raw: &str) -> AdapterOutput {
    CiscoIosAdapter
        .import_str(raw, "test.conf")
        .expect("un modèle (même partiel) doit sortir")
}

fn iface<'a>(dev: &'a Device, name: &str) -> &'a Interface {
    dev.interfaces
        .get(&IfaceId::new(name))
        .unwrap_or_else(|| panic!("interface `{name}` absente"))
}

fn policy<'a>(dev: &'a Device, name: &str) -> &'a calque_model::Policy {
    dev.policies
        .get(&PolicyId::new(name))
        .unwrap_or_else(|| panic!("politique `{name}` absente"))
}

fn unsupported_of(out: &AdapterOutput) -> &[calque_model::Diagnostic] {
    match &out.fidelity {
        Fidelity::Partial { unsupported } => unsupported,
        Fidelity::Complete => panic!("fidélité Complete alors que Partial était attendue"),
    }
}

// ---------------------------------------------------------------------------
// Détection — y compris croisée avec FortiGate
// ---------------------------------------------------------------------------

#[test]
fn detection_cisco_ios() {
    let adapter = CiscoIosAdapter;
    let c = adapter.detect(BASIC);
    assert!(c.is_confident(), "score détecté : {}", c.score());
    assert_eq!(
        c.score(),
        100,
        "tous les motifs de la fixture sont présents"
    );
    assert_eq!(adapter.detect("").score(), 0);
}

#[test]
fn detection_croisee_fortigate_cisco() {
    // Une configuration FortiGate ne doit pas être prise pour de l'IOS…
    assert!(
        !CiscoIosAdapter.detect(FORTIGATE_BASIC).is_confident(),
        "score IOS sur du FortiGate : {}",
        CiscoIosAdapter.detect(FORTIGATE_BASIC).score()
    );
    // …ni l'inverse.
    assert!(
        !FortigateAdapter.detect(BASIC).is_confident(),
        "score FortiGate sur de l'IOS : {}",
        FortigateAdapter.detect(BASIC).score()
    );
}

#[test]
fn detection_automatique_choisit_le_bon_adaptateur() {
    let best = all_adapters()
        .into_iter()
        .max_by_key(|a| a.detect(BASIC))
        .expect("au moins un adaptateur");
    assert_eq!(best.vendor(), Vendor::CiscoIos);
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
        "la fixture ne contient que des directives gérées ou listées ignorables"
    );
    // Trois constats Info : le secret, le groupe mixte, l'ACL 10 jamais
    // accrochée (référencée seulement par `access-class` sous `line vty`,
    // hors périmètre du trafic transitant).
    assert!(out.notes.iter().all(|n| n.severity == Severity::Info));
    assert_eq!(out.notes.len(), 3, "notes : {:?}", out.notes);
    assert!(out.notes[0].message.contains("secret"));
    assert!(out.notes[1].message.contains("og-admin"));
    assert!(out.notes[1].message.contains("mixte"));
    assert!(out.notes[2].message.contains("ACL `10`"));
    assert!(out.notes[2].message.contains("aucune interface"));
}

// ---------------------------------------------------------------------------
// Interfaces : adresses, secondaire, état, dot1Q
// ---------------------------------------------------------------------------

#[test]
fn interfaces_adresses_et_etat() {
    let dev = import_basic().device;
    assert_eq!(dev.vendor, Vendor::CiscoIos);
    assert_eq!(
        dev.id.as_str(),
        "rtr-lab-01",
        "le hostname prime sur le nom de fichier"
    );
    assert_eq!(dev.interfaces.len(), 5);

    // Gi0/0 : adresse primaire PUIS secondaire, ordre du fichier.
    let lan = iface(&dev, "GigabitEthernet0/0");
    assert_eq!(
        lan.addrs,
        vec![
            "10.20.1.1/24".parse().unwrap(),
            "10.20.11.1/24".parse().unwrap()
        ]
    );
    assert_eq!(lan.state, AdminState::Up);
    assert_eq!(lan.vrf, VrfId::default_vrf());
    assert_eq!(lan.vlan, None);

    // Sous-interface dot1Q : le VLAN vient de l'encapsulation.
    let invites = iface(&dev, "GigabitEthernet0/0.30");
    assert_eq!(invites.addrs, vec!["10.20.30.1/24".parse().unwrap()]);
    assert_eq!(invites.vlan, Some(30));

    let srv = iface(&dev, "GigabitEthernet0/1");
    assert_eq!(srv.addrs, vec!["10.20.2.1/24".parse().unwrap()]);
    assert_eq!(srv.state, AdminState::Up);

    let wan = iface(&dev, "GigabitEthernet0/2");
    assert_eq!(wan.addrs, vec!["10.200.1.2/30".parse().unwrap()]);

    // `shutdown` → AdminState::Down (ne pas modéliser ce qui est éteint).
    let secours = iface(&dev, "GigabitEthernet0/3");
    assert_eq!(secours.state, AdminState::Down);
    assert_eq!(secours.addrs, vec!["10.20.9.1/30".parse().unwrap()]);
}

#[test]
fn zones_implicites_des_interfaces_filtrantes() {
    let dev = import_basic().device;
    // Seules les interfaces portant une ACL reçoivent une zone implicite.
    assert_eq!(dev.zones.len(), 3);
    for name in [
        "GigabitEthernet0/0",
        "GigabitEthernet0/0.30",
        "GigabitEthernet0/1",
    ] {
        assert_eq!(
            dev.zones.get(&ZoneId::new(name)),
            Some(&vec![IfaceId::new(name)]),
            "zone implicite `{name}`"
        );
        assert_eq!(
            iface(&dev, name).zone.as_ref().map(|z| z.as_str()),
            Some(name)
        );
    }
    assert_eq!(iface(&dev, "GigabitEthernet0/2").zone, None);
}

// ---------------------------------------------------------------------------
// Routes statiques
// ---------------------------------------------------------------------------

#[test]
fn routes_statiques() {
    let dev = import_basic().device;
    let vrf = dev
        .vrfs
        .get(&VrfId::default_vrf())
        .expect("le VRF par défaut existe");
    assert_eq!(vrf.routes.len(), 2);

    // Route par défaut : passerelle IP, distance implicite 1.
    let r1 = &vrf.routes[0];
    assert_eq!(r1.prefix, "0.0.0.0/0".parse().unwrap());
    assert_eq!(r1.next_hop, NextHop::Ip("10.200.1.1".parse().unwrap()));
    assert_eq!(r1.metric, 1);
    assert_eq!(r1.origin, RouteOrigin::Static);
    let span = r1.source.as_ref().expect("une route porte son origine");
    assert_eq!(span.file, FILE);
    assert_eq!(span.line, 64);

    // Route sur interface de sortie, distance explicite → métrique.
    let r2 = &vrf.routes[1];
    assert_eq!(r2.prefix, "10.30.0.0/16".parse().unwrap());
    assert_eq!(
        r2.next_hop,
        NextHop::Interface(IfaceId::new("GigabitEthernet0/1"))
    );
    assert_eq!(r2.metric, 200);
    assert_eq!(r2.source.as_ref().map(|s| s.line), Some(65));
}

// ---------------------------------------------------------------------------
// Object-groups réseau
// ---------------------------------------------------------------------------

#[test]
fn object_groups_reseau() {
    let dev = import_basic().device;
    // og-serveurs + og-admin + l'objet auxiliaire du groupe mixte.
    assert_eq!(dev.objects.addresses.len(), 3);

    // `host` → /32, membre `RÉSEAU MASQUE` → préfixe (masque de
    // sous-réseau ici, PAS un wildcard).
    match dev.objects.addresses.get(&ObjectId::new("og-serveurs")) {
        Some(AddrObject::Nets(nets)) => assert_eq!(
            nets,
            &vec![
                "10.20.2.10/32".parse().unwrap(),
                "10.20.3.0/24".parse().unwrap()
            ]
        ),
        other => panic!("og-serveurs devrait être des réseaux : {other:?}"),
    }

    // Groupe MIXTE (group-object + host) : les membres directs sont
    // regroupés sous un objet auxiliaire — sémantique préservée.
    match dev.objects.addresses.get(&ObjectId::new("og-admin")) {
        Some(AddrObject::Group(members)) => {
            let noms: Vec<&str> = members.iter().map(|m| m.as_str()).collect();
            assert_eq!(noms, vec!["og-serveurs", "og-admin::membres-directs"]);
        }
        other => panic!("og-admin devrait être un groupe : {other:?}"),
    }
    match dev
        .objects
        .addresses
        .get(&ObjectId::new("og-admin::membres-directs"))
    {
        Some(AddrObject::Nets(nets)) => {
            assert_eq!(nets, &vec!["10.20.1.10/32".parse().unwrap()]);
        }
        other => panic!("l'objet auxiliaire devrait être des réseaux : {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Politiques : liaison in/out, ordre, contenu, spans
// ---------------------------------------------------------------------------

#[test]
fn liaison_des_acl_au_pipeline() {
    let dev = import_basic().device;
    assert_eq!(dev.policies.len(), 4);

    // in → ingress (ordre des interfaces du fichier), out → egress.
    assert_eq!(
        dev.pipeline.ingress,
        vec![PolicyId::new("ACL-ENTREE-LAN"), PolicyId::new("130")]
    );
    assert_eq!(dev.pipeline.egress, vec![PolicyId::new("ACL-SORTIE-SRV")]);

    // L'ACL 10 (référencée seulement sous `line vty`) existe mais n'est
    // pas branchée.
    assert!(dev.policies.contains_key(&PolicyId::new("10")));
}

#[test]
fn acl_etendue_regles_ordonnees_et_spans() {
    let dev = import_basic().device;
    let p = policy(&dev, "ACL-ENTREE-LAN");
    // Le `deny` implicite de toute ACL Cisco.
    assert_eq!(p.default_action, Action::Deny);

    // ORDRE SIGNIFICATIF : cinq entrées, index en base 1.
    let ids: Vec<&str> = p.rules.iter().map(|r| r.id.as_str()).collect();
    assert_eq!(ids, vec!["1", "2", "3", "4", "5"]);

    // Liaison `in` : from = zone implicite de l'interface, to = libre.
    for r in &p.rules {
        assert_eq!(
            r.from.as_ref().map(|z| z.as_str()),
            Some("GigabitEthernet0/0")
        );
        assert_eq!(r.to, None);
    }

    // Règle 1 : wildcard 0.0.0.255 → /24, host → /32, eq 445.
    let r1 = &p.rules[0];
    assert_eq!(r1.action, Action::Accept);
    assert_eq!(
        r1.matches.src,
        vec![AddrExpr::Net("10.20.1.0/24".parse().unwrap())]
    );
    assert_eq!(
        r1.matches.dst,
        vec![AddrExpr::Net("10.20.2.10/32".parse().unwrap())]
    );
    assert_eq!(
        r1.matches.services,
        vec![ServiceExpr::Service(Service {
            proto: ProtoMatch::Number(6),
            sport: PortRange::ANY,
            dport: PortRange::single(445),
        })]
    );

    // Règle 2 : référence d'object-group CONSERVÉE (résolution tardive,
    // §3.3) + range de ports.
    let r2 = &p.rules[1];
    assert_eq!(
        r2.matches.dst,
        vec![AddrExpr::Object(ObjectId::new("og-serveurs"))]
    );
    assert_eq!(
        r2.matches.services,
        vec![ServiceExpr::Service(Service {
            proto: ProtoMatch::Number(6),
            sport: PortRange::ANY,
            dport: PortRange {
                start: 8000,
                end: 8010
            },
        })]
    );

    // Règle 3 : `any` + nom de port IOS (`domain` = 53).
    let r3 = &p.rules[2];
    assert_eq!(r3.matches.src, vec![AddrExpr::Any]);
    assert_eq!(
        r3.matches.services,
        vec![ServiceExpr::Service(Service {
            proto: ProtoMatch::Number(17),
            sport: PortRange::ANY,
            dport: PortRange::single(53),
        })]
    );

    // Règle 4 : icmp sans ports.
    let r4 = &p.rules[3];
    assert_eq!(
        r4.matches.services,
        vec![ServiceExpr::Service(Service {
            proto: ProtoMatch::Number(1),
            sport: PortRange::ANY,
            dport: PortRange::ANY,
        })]
    );

    // Règle 5 : `deny ip any any log` → refus explicite, tout protocole.
    let r5 = &p.rules[4];
    assert_eq!(r5.action, Action::Deny);
    assert_eq!(r5.matches.src, vec![AddrExpr::Any]);
    assert_eq!(r5.matches.dst, vec![AddrExpr::Any]);
    assert_eq!(r5.matches.services, vec![ServiceExpr::Any]);

    // SourceSpan EXACTS de deux règles. « La trace est le produit. »
    assert_eq!(r1.source.file, FILE);
    assert_eq!(r1.source.line, 68);
    assert_eq!(r1.source.end_line, None);
    assert_eq!(r5.source.file, FILE);
    assert_eq!(r5.source.line, 72);
}

#[test]
fn acl_numerotee_etendue_et_standard() {
    let dev = import_basic().device;

    // ACL 130 (étendue, liée `in` sur la sous-interface dot1Q).
    let p130 = policy(&dev, "130");
    assert_eq!(p130.rules.len(), 3);
    for r in &p130.rules {
        assert_eq!(
            r.from.as_ref().map(|z| z.as_str()),
            Some("GigabitEthernet0/0.30")
        );
    }
    // `www` → 80.
    assert_eq!(
        p130.rules[0].matches.services,
        vec![ServiceExpr::Service(Service {
            proto: ProtoMatch::Number(6),
            sport: PortRange::ANY,
            dport: PortRange::single(80),
        })]
    );
    assert_eq!(
        p130.rules[0].matches.src,
        vec![AddrExpr::Net("10.20.30.0/24".parse().unwrap())]
    );
    assert_eq!(p130.rules[0].source.line, 82);
    assert_eq!(p130.rules[2].action, Action::Deny);

    // ACL 10 (standard) : SOURCE SEULE — destination et services libres.
    let p10 = policy(&dev, "10");
    assert_eq!(p10.rules.len(), 2, "le remark ne produit pas d'entrée");
    let r1 = &p10.rules[0];
    assert_eq!(r1.action, Action::Accept);
    assert_eq!(
        r1.matches.src,
        vec![AddrExpr::Net("10.20.1.0/24".parse().unwrap())]
    );
    assert!(r1.matches.dst.is_empty());
    assert!(r1.matches.services.is_empty());
    assert_eq!(r1.from, None, "ACL non accrochée : pas de zone");
    let r2 = &p10.rules[1];
    assert_eq!(r2.action, Action::Deny);
    assert_eq!(r2.matches.src, vec![AddrExpr::Any]);
    assert_eq!(p10.default_action, Action::Deny);
}

// ---------------------------------------------------------------------------
// L'ACL de sortie (out → egress, to = zone)
// ---------------------------------------------------------------------------

#[test]
fn acl_de_sortie_porte_la_zone_en_destination() {
    let dev = import_basic().device;
    let p = policy(&dev, "ACL-SORTIE-SRV");
    assert_eq!(p.rules.len(), 3);
    for r in &p.rules {
        assert_eq!(r.from, None);
        assert_eq!(
            r.to.as_ref().map(|z| z.as_str()),
            Some("GigabitEthernet0/1")
        );
    }
    assert_eq!(
        p.rules[0].matches.dst,
        vec![AddrExpr::Net("10.20.2.10/32".parse().unwrap())]
    );
}

// ---------------------------------------------------------------------------
// VRF : `vrf forwarding` + `ip route vrf` + Null0
// ---------------------------------------------------------------------------

#[test]
fn vrf_interface_routes_et_null0() {
    let out = import(
        "interface GigabitEthernet0/5\n \
           ip vrf forwarding CLIENTS\n \
           ip address 10.99.1.1 255.255.255.0\n\
         interface GigabitEthernet0/6\n \
           vrf forwarding CLIENTS\n \
           ip address 10.99.2.1 255.255.255.0\n\
         ip route vrf CLIENTS 0.0.0.0 0.0.0.0 10.99.1.254\n\
         ip route 10.66.0.0 255.255.0.0 Null0\n",
    );
    assert_eq!(out.fidelity, Fidelity::Complete);
    let dev = out.device;
    assert_eq!(iface(&dev, "GigabitEthernet0/5").vrf, VrfId::new("CLIENTS"));
    assert_eq!(iface(&dev, "GigabitEthernet0/6").vrf, VrfId::new("CLIENTS"));
    let clients = dev.vrfs.get(&VrfId::new("CLIENTS")).expect("VRF CLIENTS");
    assert_eq!(clients.routes.len(), 1);
    assert_eq!(
        clients.routes[0].next_hop,
        NextHop::Ip("10.99.1.254".parse().unwrap())
    );
    // `Null0` est la route de rejet idiomatique d'IOS.
    let defaut = dev.vrfs.get(&VrfId::default_vrf()).expect("VRF défaut");
    assert_eq!(defaut.routes[0].next_hop, NextHop::Drop);
    assert_eq!(defaut.routes[0].prefix, "10.66.0.0/16".parse().unwrap());
}

// ---------------------------------------------------------------------------
// Object-group service + référence dans une ACL
// ---------------------------------------------------------------------------

#[test]
fn object_group_service_et_reference_acl() {
    let out = import(
        "object-group service og-tunnels\n \
           esp\n \
           gre\n\
         object-group service og-flux-app\n \
           tcp eq 8443\n \
           udp range 5000 5010\n \
           tcp source gt 1024 eq 9000\n \
           group-object og-tunnels\n\
         interface GigabitEthernet0/0\n \
           ip address 10.0.0.1 255.255.255.0\n \
           ip access-group ACL-APP in\n\
         ip access-list extended ACL-APP\n \
           permit object-group og-flux-app any any\n",
    );
    assert_eq!(out.fidelity, Fidelity::Complete);
    let dev = out.device;

    match dev.objects.services.get(&ObjectId::new("og-tunnels")) {
        Some(ServiceObject::Services(svcs)) => {
            assert_eq!(svcs.len(), 2);
            assert_eq!(svcs[0].proto, ProtoMatch::Number(50)); // esp
            assert_eq!(svcs[1].proto, ProtoMatch::Number(47)); // gre
        }
        other => panic!("og-tunnels : {other:?}"),
    }

    // Groupe mixte : services directs sous l'objet auxiliaire.
    match dev.objects.services.get(&ObjectId::new("og-flux-app")) {
        Some(ServiceObject::Group(members)) => {
            let noms: Vec<&str> = members.iter().map(|m| m.as_str()).collect();
            assert_eq!(noms, vec!["og-tunnels", "og-flux-app::membres-directs"]);
        }
        other => panic!("og-flux-app : {other:?}"),
    }
    match dev
        .objects
        .services
        .get(&ObjectId::new("og-flux-app::membres-directs"))
    {
        Some(ServiceObject::Services(svcs)) => {
            assert_eq!(
                svcs[0],
                Service {
                    proto: ProtoMatch::Number(6),
                    sport: PortRange::ANY,
                    dport: PortRange::single(8443),
                }
            );
            assert_eq!(
                svcs[1],
                Service {
                    proto: ProtoMatch::Number(17),
                    sport: PortRange::ANY,
                    dport: PortRange {
                        start: 5000,
                        end: 5010
                    },
                }
            );
            // `tcp source gt 1024 eq 9000` : ports source ET destination.
            assert_eq!(
                svcs[2],
                Service {
                    proto: ProtoMatch::Number(6),
                    sport: PortRange {
                        start: 1025,
                        end: 65535
                    },
                    dport: PortRange::single(9000),
                }
            );
        }
        other => panic!("l'objet auxiliaire devrait être des services : {other:?}"),
    }

    // L'ACL garde la RÉFÉRENCE au groupe de services (résolution tardive).
    let p = policy(&dev, "ACL-APP");
    assert_eq!(
        p.rules[0].matches.services,
        vec![ServiceExpr::Object(ObjectId::new("og-flux-app"))]
    );
}

// ---------------------------------------------------------------------------
// §6.3 — ne jamais deviner
// ---------------------------------------------------------------------------

#[test]
fn wildcard_non_contigu_degrade_la_fidelite() {
    let out = import(
        "interface GigabitEthernet0/0\n \
           ip address 10.0.0.1 255.255.255.0\n \
           ip access-group ACL-BIZARRE in\n\
         ip access-list extended ACL-BIZARRE\n \
           permit tcp 10.0.0.0 0.0.254.255 any eq 80\n \
           deny ip any any\n",
    );
    let unsupported = unsupported_of(&out);
    let diag = unsupported
        .iter()
        .find(|d| d.message.contains("non contigu"))
        .expect("le wildcard non contigu doit être diagnostiqué");
    assert_eq!(diag.span.as_ref().map(|s| s.line), Some(5));
    // L'entrée n'est PAS devinée : seule l'entrée `deny` subsiste.
    let p = policy(&out.device, "ACL-BIZARRE");
    assert_eq!(p.rules.len(), 1);
    assert_eq!(p.rules[0].action, Action::Deny);
}

#[test]
fn nat_ios_diagnostique_jamais_ignore() {
    let out = import(
        "interface GigabitEthernet0/0\n \
           ip address 10.0.0.1 255.255.255.0\n \
           ip nat inside\n\
         ip nat inside source list 7 interface GigabitEthernet0/1 overload\n",
    );
    let unsupported = unsupported_of(&out);
    let nat_diags: Vec<_> = unsupported
        .iter()
        .filter(|d| d.message.contains("NAT IOS non modélisé"))
        .collect();
    assert_eq!(nat_diags.len(), 2, "chaque directive NAT est diagnostiquée");
}

#[test]
fn directive_inconnue_degrade_la_fidelite() {
    let out = import(
        "hostname r1\n\
         gadget-quantique actif\n\
         interface GigabitEthernet0/0\n \
           ip address 10.0.0.1 255.255.255.0\n \
           telepathie niveau 3\n\
         router ospf 1\n \
           network 10.0.0.0 0.0.0.255 area 0\n",
    );
    let unsupported = unsupported_of(&out);
    assert!(
        unsupported
            .iter()
            .any(|d| d.message.contains("gadget-quantique")),
        "directive de premier niveau inconnue : {unsupported:?}"
    );
    let telepathie = unsupported
        .iter()
        .find(|d| d.message.contains("telepathie"))
        .expect("directive d'interface inconnue diagnostiquée");
    assert_eq!(telepathie.span.as_ref().map(|s| s.line), Some(5));
    // Le routage dynamique ne peut pas être modélisé hors ligne.
    assert!(unsupported
        .iter()
        .any(|d| d.message.contains("routage dynamique")));
    // Le modèle sort quand même : l'interface est là.
    assert!(out
        .device
        .interfaces
        .contains_key(&IfaceId::new("GigabitEthernet0/0")));
}

#[test]
fn acl_inconnue_referencee_diagnostiquee() {
    let out = import(
        "interface GigabitEthernet0/0\n \
           ip address 10.0.0.1 255.255.255.0\n \
           ip access-group ACL-FANTOME in\n",
    );
    let unsupported = unsupported_of(&out);
    assert!(unsupported
        .iter()
        .any(|d| d.message.contains("ACL-FANTOME") && d.message.contains("inconnue")));
}

// ---------------------------------------------------------------------------
// Robustesse : jamais de panique sur une entrée externe
// ---------------------------------------------------------------------------

#[test]
fn entrees_hostiles_sans_panique() {
    let adapter = CiscoIosAdapter;
    for raw in [
        "",
        "!\n! rien\n!\n",
        "banner motd ^C\nsans fin",
        "interface\nip route\nip access-list extended\naccess-list abc permit\n",
        "ip route 999.9.9.9 255.255.0.0 10.0.0.1\n",
        "ip route 10.0.0.0 255.0.255.0 10.0.0.1\n",
        "access-list 130 permit tcp any eq teleport any\n",
        "access-list 99999 permit any\n",
        "interface Gi0/0\n ip address 10.0.0.1 255.0.255.0\n shutdown\n no\n",
        "object-group network\nobject-group service og-x\n plasma\n",
        "ip access-list extended X\n permit\n deny tcp host any\n 12 remark bizarre\n",
        "\u{0}\u{1} n'importe quoi \u{7f}\n\tinterface \"\n",
    ] {
        // Ok(modèle partiel) ou Err(diagnostics) : tout sauf une panique.
        let _ = adapter.import_str(raw, "hostile.conf");
    }
}
