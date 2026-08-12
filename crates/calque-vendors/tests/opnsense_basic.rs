//! Tests de profondeur sur la fixture `corpus/opnsense/basic.xml`
//! (configuration fictive et anonyme, adressage RFC1918 inventé).
//!
//! La fixture est entièrement couverte par l'adaptateur : la fidélité
//! attendue est `Complete`. D'autres tests exercent la détection (y
//! compris pfSense, format cousin), les diagnostics de directives
//! touchant le trafic (§6.3 : ne jamais deviner) et la robustesse face à
//! du XML hostile (§11.3 : jamais de panique).

use calque_model::{
    Action, AddrExpr, AddrObject, AdminState, Device, DnatTarget, Fidelity, IfaceId, Interface,
    NextHop, ObjectId, PolicyId, PortRange, ProtoMatch, RouteOrigin, Service, ServiceExpr,
    Severity, VrfId, ZoneId,
};
use calque_vendors::opnsense::OpnsenseAdapter;
use calque_vendors::{AdapterOutput, VendorAdapter};

/// La fixture, embarquée à la compilation (crate pur : aucune E/S).
const BASIC: &str = include_str!("../../../corpus/opnsense/basic.xml");
const FILE: &str = "basic.xml";

/// Les fixtures des autres constructeurs, pour la NON-détection.
const FORTIGATE: &str = include_str!("../../../corpus/fortigate/basic.conf");
const CISCO: &str = include_str!("../../../corpus/cisco_ios/basic.conf");

fn import_basic() -> AdapterOutput {
    OpnsenseAdapter
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
        .unwrap_or_else(|| panic!("alias `{name}` absent"))
}

// ---------------------------------------------------------------------------
// Détection
// ---------------------------------------------------------------------------

#[test]
fn detection_opnsense() {
    let adapter = OpnsenseAdapter;
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
fn non_detection_des_autres_constructeurs() {
    let adapter = OpnsenseAdapter;
    // Les fixtures FortiGate et Cisco IOS ne doivent JAMAIS être prises
    // pour un config.xml.
    assert_eq!(adapter.detect(FORTIGATE).score(), 0);
    assert_eq!(adapter.detect(CISCO).score(), 0);
    // Un XML quelconque sans racine connue non plus.
    assert_eq!(adapter.detect("<config><rule>1</rule></config>").score(), 0);
}

#[test]
fn detection_pfsense_format_cousin() {
    let adapter = OpnsenseAdapter;
    let pf = "<pfsense><interfaces><lan></lan></interfaces><filter></filter></pfsense>";
    assert!(adapter.detect(pf).is_confident());
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
        "la fixture ne contient que des éléments gérés"
    );
    // Deux notes Info attendues — des constats, pas des incompréhensions :
    // la règle 4 désactivée, et le NAT sortant automatique.
    let infos: Vec<_> = out
        .notes
        .iter()
        .filter(|n| n.severity == Severity::Info)
        .collect();
    assert_eq!(infos.len(), 2, "{infos:?}");
    assert!(infos
        .iter()
        .any(|n| n.message.contains("règle 4") && n.message.contains("désactivée")));
    assert!(infos
        .iter()
        .any(|n| n.message.contains("NAT sortant") && n.message.contains("automatic")));
}

// ---------------------------------------------------------------------------
// Interfaces et zones
// ---------------------------------------------------------------------------

#[test]
fn interfaces_adresses_et_etat() {
    let dev = import_basic().device;
    assert_eq!(
        dev.id.as_str(),
        "fw-opn-01",
        "le hostname prime sur le nom de fichier"
    );
    assert_eq!(dev.interfaces.len(), 3);

    let lan = iface(&dev, "lan");
    assert_eq!(lan.addrs, vec!["10.10.1.1/24".parse().unwrap()]);
    assert_eq!(lan.state, AdminState::Up);
    assert_eq!(lan.vrf, VrfId::default_vrf());

    let opt1 = iface(&dev, "opt1");
    assert_eq!(opt1.addrs, vec!["10.10.2.1/24".parse().unwrap()]);

    let wan = iface(&dev, "wan");
    assert_eq!(wan.addrs, vec!["10.200.0.2/30".parse().unwrap()]);
}

#[test]
fn zones_la_descr_est_l_alias_logique() {
    let dev = import_basic().device;
    assert_eq!(dev.zones.len(), 3);
    // Sans descr, la clé ; avec descr, le nom logique.
    assert_eq!(
        dev.zones.get(&ZoneId::new("lan")),
        Some(&vec![IfaceId::new("lan")])
    );
    assert_eq!(
        dev.zones.get(&ZoneId::new("dmz")),
        Some(&vec![IfaceId::new("opt1")]),
        "la descr `dmz` de opt1 nomme la zone"
    );
    assert_eq!(
        dev.zones.get(&ZoneId::new("WAN")),
        Some(&vec![IfaceId::new("wan")])
    );
    assert_eq!(
        iface(&dev, "opt1").zone.as_ref().map(|z| z.as_str()),
        Some("dmz")
    );
}

// ---------------------------------------------------------------------------
// Routage
// ---------------------------------------------------------------------------

#[test]
fn routes_par_defaut_et_statique() {
    let dev = import_basic().device;
    let vrf = dev
        .vrfs
        .get(&VrfId::default_vrf())
        .expect("le VRF par défaut existe");
    assert_eq!(vrf.routes.len(), 2);

    // Route par défaut : `<defaultgw>1</defaultgw>` sur GW_WAN.
    let dflt = &vrf.routes[0];
    assert_eq!(dflt.prefix, "0.0.0.0/0".parse().unwrap());
    assert_eq!(dflt.next_hop, NextHop::Ip("10.200.0.1".parse().unwrap()));
    assert_eq!(dflt.origin, RouteOrigin::Static);
    let span = dflt.source.as_ref().expect("une route porte son origine");
    assert_eq!(span.file, FILE);
    assert_eq!(span.line, 39); // ligne du <gateway_item> de GW_WAN

    // Route statique : passerelle résolue par son NOM (GW_LAB).
    let stat = &vrf.routes[1];
    assert_eq!(stat.prefix, "10.30.0.0/16".parse().unwrap());
    assert_eq!(stat.next_hop, NextHop::Ip("10.10.1.254".parse().unwrap()));
    let span = stat.source.as_ref().expect("origine");
    assert_eq!((span.file.as_str(), span.line), (FILE, 56)); // <route>
}

// ---------------------------------------------------------------------------
// Aliases (emplacement moderne <OPNsense><Firewall><Alias>)
// ---------------------------------------------------------------------------

#[test]
fn aliases_resolus_en_objets() {
    let dev = import_basic().device;
    assert_eq!(dev.objects.addresses.len(), 2);

    match addr_obj(&dev, "h_srv_web") {
        AddrObject::Nets(nets) => {
            assert_eq!(nets, &vec!["10.10.2.10/32".parse().unwrap()]);
        }
        other => panic!("h_srv_web devrait être des réseaux : {other:?}"),
    }

    // Contenu multi-lignes → une entrée par ligne.
    match addr_obj(&dev, "n_postes") {
        AddrObject::Nets(nets) => {
            assert_eq!(
                nets,
                &vec![
                    "10.10.1.0/24".parse().unwrap(),
                    "10.10.3.0/24".parse().unwrap(),
                ]
            );
        }
        other => panic!("n_postes devrait être des réseaux : {other:?}"),
    }
}

/// L'ancien emplacement (`<aliases>` à la racine, contenu séparé par des
/// espaces) est lu aussi — c'est la forme pfSense.
#[test]
fn aliases_ancien_emplacement() {
    let out = OpnsenseAdapter
        .import_str(
            "<pfsense><aliases><alias><name>g_srv</name><type>host</type>\
             <address>10.0.0.5 10.0.0.6</address><descr>serveurs</descr><detail/></alias>\
             </aliases></pfsense>",
            "pf.xml",
        )
        .expect("modèle pfSense");
    assert_eq!(out.fidelity, Fidelity::Complete, "{:?}", out.fidelity);
    // La note pfSense est présente.
    assert!(out
        .notes
        .iter()
        .any(|n| n.severity == Severity::Info && n.message.contains("pfsense")));
    match &out.device.objects.addresses[&ObjectId::new("g_srv")] {
        AddrObject::Nets(nets) => assert_eq!(
            nets,
            &vec![
                "10.0.0.5/32".parse().unwrap(),
                "10.0.0.6/32".parse().unwrap()
            ]
        ),
        other => panic!("g_srv : {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Politique de filtrage : ordre, actions, zones, spans
// ---------------------------------------------------------------------------

#[test]
fn politique_ordre_actions_et_spans() {
    let dev = import_basic().device;
    assert_eq!(dev.policies.len(), 2); // filter + dnat

    let policy = dev
        .policies
        .get(&PolicyId::new("filter"))
        .expect("la politique filter existe");
    // Default deny du pf généré par OPNsense.
    assert_eq!(policy.default_action, Action::Deny);

    // ORDRE DU FICHIER = ordre d'évaluation (quick par défaut) :
    // 1, 2, 3, 5 — la 4 (désactivée) est écartée.
    let ids: Vec<&str> = policy.rules.iter().map(|r| r.id.as_str()).collect();
    assert_eq!(
        ids,
        vec![
            "1 (postes vers serveur web de la dmz)",
            "2 (isolement de la dmz)",
            "3 (flux publie via la redirection de port)",
            "5 (sortie generale du lan)",
        ]
    );

    // Règle 1 : lan, tcp 8443, alias source et destination (résolution
    // tardive, §3.3).
    let r1 = &policy.rules[0];
    assert_eq!(r1.from.as_ref().map(|z| z.as_str()), Some("lan"));
    assert_eq!(r1.to, None, "pf ne connaît pas l'interface de sortie");
    assert_eq!(
        r1.matches.src,
        vec![AddrExpr::Object(ObjectId::new("n_postes"))]
    );
    assert_eq!(
        r1.matches.dst,
        vec![AddrExpr::Object(ObjectId::new("h_srv_web"))]
    );
    assert_eq!(
        r1.matches.services,
        vec![ServiceExpr::Service(Service {
            proto: ProtoMatch::Number(6),
            sport: PortRange::ANY,
            dport: PortRange::single(8443),
        })]
    );
    assert_eq!(r1.action, Action::Accept);

    // Règle 2 : block sur opt1 — la zone porte le nom logique `dmz`, et
    // `<network>` est résolu vers les sous-réseaux des interfaces.
    let r2 = &policy.rules[1];
    assert_eq!(r2.from.as_ref().map(|z| z.as_str()), Some("dmz"));
    assert_eq!(
        r2.matches.src,
        vec![AddrExpr::Net("10.10.2.0/24".parse().unwrap())]
    );
    assert_eq!(
        r2.matches.dst,
        vec![AddrExpr::Net("10.10.1.0/24".parse().unwrap())]
    );
    assert!(r2.matches.services.is_empty(), "aucun protocole = tout");
    assert_eq!(r2.action, Action::Deny);

    // Règle 3 : entrée WAN vers l'adresse TRADUITE de la redirection.
    let r3 = &policy.rules[2];
    assert_eq!(r3.from.as_ref().map(|z| z.as_str()), Some("WAN"));
    assert_eq!(r3.matches.src, vec![AddrExpr::Any]);
    assert_eq!(
        r3.matches.dst,
        vec![AddrExpr::Net("10.10.2.10/32".parse().unwrap())]
    );
    assert_eq!(r3.action, Action::Accept);

    // SourceSpan EXACTS : la ligne du `<rule>`, la ligne du `</rule>`.
    // « La trace est le produit. »
    assert_eq!(r1.source.file, FILE);
    assert_eq!((r1.source.line, r1.source.end_line), (63, Some(76)));
    assert_eq!((r2.source.line, r2.source.end_line), (77, Some(89)));
    assert_eq!((r3.source.line, r3.source.end_line), (90, Some(103)));
    let r5 = &policy.rules[3];
    assert_eq!((r5.source.line, r5.source.end_line), (118, Some(130)));
}

// ---------------------------------------------------------------------------
// NAT : redirection de port
// ---------------------------------------------------------------------------

#[test]
fn nat_redirection_de_port() {
    let dev = import_basic().device;
    let policy = dev
        .policies
        .get(&PolicyId::new("dnat"))
        .expect("la politique dnat existe");
    // Une redirection ne filtre pas : sans correspondance, le paquet
    // continue non traduit vers le filtre.
    assert_eq!(policy.default_action, Action::Accept);
    assert_eq!(policy.rules.len(), 1);

    let r = &policy.rules[0];
    assert_eq!(r.id.as_str(), "1 (publication du serveur web de la dmz)");
    assert_eq!(r.from.as_ref().map(|z| z.as_str()), Some("WAN"));
    assert_eq!(r.matches.src, vec![AddrExpr::Any]);
    // `<network>wanip</network>` → l'adresse de l'interface WAN en /32.
    assert_eq!(
        r.matches.dst,
        vec![AddrExpr::Net("10.200.0.2/32".parse().unwrap())]
    );
    assert_eq!(
        r.matches.services,
        vec![ServiceExpr::Service(Service {
            proto: ProtoMatch::Number(6),
            sport: PortRange::ANY,
            dport: PortRange::single(443),
        })]
    );
    match &r.action {
        Action::Nat(nat) => {
            assert_eq!(nat.snat, None);
            assert_eq!(
                nat.dnat,
                Some(DnatTarget {
                    addr: "10.10.2.10".parse().unwrap(),
                    port: Some(8443),
                })
            );
        }
        other => panic!("Action::Nat attendue : {other:?}"),
    }
    assert_eq!((r.source.line, r.source.end_line), (136, Some(150)));

    // Le pipeline applique le DNAT AVANT le filtre (rdr de pf) : le
    // filtre tranche sur la destination déjà traduite.
    assert_eq!(
        dev.pipeline.ingress,
        vec![PolicyId::new("dnat"), PolicyId::new("filter")]
    );
    assert!(dev.pipeline.egress.is_empty());
}

// ---------------------------------------------------------------------------
// §6.3 — ne jamais deviner : trafic non modélisé → diagnostic + Partial
// ---------------------------------------------------------------------------

#[test]
fn directive_trafic_non_modelisee_degrade_la_fidelite() {
    // La fixture, augmentée d'un tunnel OpenVPN et d'une VIP CARP : deux
    // dispositifs qui touchent le trafic sans être modélisés.
    let exotique = BASIC
        .replace(
            "<virtualip version=\"1.0.0\"/>",
            "<virtualip><vip><mode>carp</mode><subnet>10.10.1.3</subnet></vip></virtualip>",
        )
        .replace(
            "<unbound>",
            "<openvpn><openvpn-server><vpnid>1</vpnid></openvpn-server></openvpn><unbound>",
        );
    let out = OpnsenseAdapter
        .import_str(&exotique, FILE)
        .expect("un modèle partiel doit tout de même sortir");

    let unsupported = match &out.fidelity {
        Fidelity::Partial { unsupported } => unsupported,
        Fidelity::Complete => panic!("du trafic non modélisé DOIT dégrader la fidélité"),
    };
    assert!(
        unsupported.iter().any(|d| d.message.contains("openvpn")),
        "le tunnel doit être diagnostiqué : {unsupported:?}"
    );
    let vip = unsupported
        .iter()
        .find(|d| d.message.contains("virtuelle") && d.message.contains("carp"))
        .expect("la VIP CARP doit être diagnostiquée");
    let span = vip.span.as_ref().expect("le diagnostic porte un span");
    assert_eq!(span.file, FILE);
    assert!(span.line > 1);
    // Le modèle reste utilisable pour le reste.
    assert_eq!(out.device.interfaces.len(), 3);
}

/// Un élément inconnu au sein d'une règle est diagnostiqué par son NOM
/// seulement, et la règle n'entre pas à moitié comprise.
#[test]
fn element_inconnu_dans_une_regle() {
    let exotique = BASIC.replace(
        "<statetype>keep state</statetype>",
        "<gadget-quantique>S3CRET</gadget-quantique>",
    );
    let out = OpnsenseAdapter
        .import_str(&exotique, FILE)
        .expect("modèle partiel");
    let Fidelity::Partial { unsupported } = &out.fidelity else {
        panic!("élément inconnu → Partial");
    };
    let diag = unsupported
        .iter()
        .find(|d| d.message.contains("gadget-quantique"))
        .expect("diagnostiqué par son nom");
    assert!(!diag.message.contains("S3CRET"), "la valeur ne fuit pas");
    // La règle 5 (qui portait l'élément) est écartée, pas devinée.
    let policy = &out.device.policies[&PolicyId::new("filter")];
    assert_eq!(policy.rules.len(), 3);
}

// ---------------------------------------------------------------------------
// Robustesse : XML hostile, jamais de panique
// ---------------------------------------------------------------------------

#[test]
fn entrees_hostiles_sans_panique() {
    let adapter = OpnsenseAdapter;

    // XML malformé, tronqué, entités hostiles, DOCTYPE XXE : Ok(modèle
    // partiel) ou Err(diagnostics), tout sauf une panique.
    for raw in [
        "",
        "<",
        "<opnsense>",
        "<opnsense><filter></opnsense></filter>",
        "<opnsense><interfaces><lan><ipaddr>999.9.9.9</ipaddr></lan></interfaces></opnsense>",
        "<!DOCTYPE r [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><opnsense>&xxe;</opnsense>",
        "<opnsense><filter><rule><type>self-destruct</type></rule></filter></opnsense>",
        "pas du xml du tout",
    ] {
        let _ = adapter.import_str(raw, "hostile.xml");
    }

    // Imbrication hostile : refusée proprement par la couche 1.
    let mut deep = String::from("<opnsense>");
    for _ in 0..600 {
        deep.push_str("<a>");
    }
    let err = adapter
        .import_str(&deep, "profond.xml")
        .expect_err("trop profond");
    assert!(
        err[0].message.contains("limite de sûreté"),
        "{:?}",
        err[0].message
    );
}

/// Une erreur de syntaxe de la couche 1 remonte en diagnostic d'erreur
/// avec fichier et ligne.
#[test]
fn erreur_de_syntaxe_avec_fichier_et_ligne() {
    let err = OpnsenseAdapter
        .import_str("<opnsense>\n  <filter>\n", "tronque.xml")
        .expect_err("document tronqué");
    assert_eq!(err.len(), 1);
    assert_eq!(err[0].severity, Severity::Error);
    let span = err[0].span.as_ref().expect("span présent");
    assert_eq!(span.file, "tronque.xml");
    assert_eq!(span.line, 2);
}
