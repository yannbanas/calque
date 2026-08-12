//! Tests de profondeur sur la fixture `corpus/nftables/basic.nft`
//! (configuration fictive et anonyme, adressage RFC1918 inventé).
//!
//! La fixture est entièrement couverte par l'adaptateur : la fidélité
//! attendue est `Complete`, avec des notes `Info` pour ce qui est compris
//! mais écarté (`ct state established…`, règles sans verdict) et une note
//! `Warning` documentant l'approximation hôte/routeur. Des tests ciblés
//! vérifient ensuite chaque diagnostic (§6.3 : ne jamais deviner).

use calque_model::{
    Action, AddrExpr, AddrObject, Device, Fidelity, IfaceId, ObjectId, PolicyId, PortRange,
    ProtoMatch, RuleId, Service, ServiceExpr, ServiceObject, Severity, ZoneId,
};
use calque_vendors::cisco_ios::CiscoIosAdapter;
use calque_vendors::fortigate::FortigateAdapter;
use calque_vendors::nftables::NftablesAdapter;
use calque_vendors::{AdapterOutput, VendorAdapter};

/// La fixture, embarquée à la compilation (crate pur : aucune E/S).
const BASIC: &str = include_str!("../../../corpus/nftables/basic.nft");
const FORTIGATE: &str = include_str!("../../../corpus/fortigate/basic.conf");
const CISCO: &str = include_str!("../../../corpus/cisco_ios/basic.conf");
const FILE: &str = "basic.nft";

fn import_basic() -> AdapterOutput {
    NftablesAdapter
        .import_str(BASIC, FILE)
        .expect("la fixture doit produire un modèle")
}

fn import(raw: &str) -> AdapterOutput {
    NftablesAdapter
        .import_str(raw, "t.nft")
        .expect("un modèle doit sortir")
}

fn policy<'a>(dev: &'a Device, id: &str) -> &'a calque_model::Policy {
    dev.policies
        .get(&PolicyId::new(id))
        .unwrap_or_else(|| panic!("politique `{id}` absente"))
}

fn partial_messages(out: &AdapterOutput) -> Vec<&str> {
    match &out.fidelity {
        Fidelity::Partial { unsupported } => {
            unsupported.iter().map(|d| d.message.as_str()).collect()
        }
        Fidelity::Complete => Vec::new(),
    }
}

// ---------------------------------------------------------------------------
// Détection, croisée avec les autres constructeurs
// ---------------------------------------------------------------------------

#[test]
fn detection_nftables() {
    let adapter = NftablesAdapter;
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
fn detection_croisee_aucune_confusion() {
    // Les fixtures des autres constructeurs ne sont pas du nftables…
    let adapter = NftablesAdapter;
    assert!(!adapter.detect(FORTIGATE).is_confident());
    assert!(!adapter.detect(CISCO).is_confident());
    // …et la fixture nftables n'est ni du FortiGate ni du Cisco IOS.
    assert!(!FortigateAdapter.detect(BASIC).is_confident());
    assert!(!CiscoIosAdapter.detect(BASIC).is_confident());
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
        "la fixture ne contient que des directives gérées : {:?}",
        out.fidelity
    );

    // Notes Info : flush ruleset, 3 règles `ct state` sans `new`, la
    // règle `counter` seule, la règle `log` seule.
    let infos: Vec<_> = out
        .notes
        .iter()
        .filter(|n| n.severity == Severity::Info)
        .collect();
    assert_eq!(infos.len(), 6, "{infos:?}");
    let ct_infos: Vec<_> = infos
        .iter()
        .filter(|n| n.message.contains("analyse sans état"))
        .collect();
    assert_eq!(ct_infos.len(), 3, "{ct_infos:?}");
    // Chaque note ct porte le span de sa règle.
    let lines: Vec<u32> = ct_infos
        .iter()
        .map(|n| n.span.as_ref().expect("span présent").line)
        .collect();
    assert_eq!(lines, vec![24, 25, 37]);

    // Une seule note Warning : l'approximation hôte/routeur
    // (input + forward évaluées en séquence), qui ne dégrade PAS la
    // fidélité (verdict conservateur, jamais optimiste).
    let warnings: Vec<_> = out
        .notes
        .iter()
        .filter(|n| n.severity == Severity::Warning)
        .collect();
    assert_eq!(warnings.len(), 1, "{warnings:?}");
    assert!(warnings[0].message.contains("input") && warnings[0].message.contains("forward"));
}

// ---------------------------------------------------------------------------
// Chaînes → politiques, accroches et actions par défaut
// ---------------------------------------------------------------------------

#[test]
fn chaines_vers_politiques_et_pipeline() {
    let dev = import_basic().device;
    assert_eq!(
        dev.id.as_str(),
        "basic",
        "identifiant tiré du nom de fichier"
    );
    assert_eq!(dev.policies.len(), 4);

    // input puis forward en entrée, output en sortie.
    assert_eq!(
        dev.pipeline.ingress,
        vec![
            PolicyId::new("inet/filtre/entree"),
            PolicyId::new("inet/filtre/transit"),
        ]
    );
    assert_eq!(
        dev.pipeline.egress,
        vec![PolicyId::new("inet/filtre/sortie")]
    );

    // `policy drop` → Deny ; `policy accept` → Accept.
    assert_eq!(
        policy(&dev, "inet/filtre/entree").default_action,
        Action::Deny
    );
    assert_eq!(
        policy(&dev, "inet/filtre/transit").default_action,
        Action::Deny
    );
    assert_eq!(
        policy(&dev, "inet/filtre/sortie").default_action,
        Action::Accept
    );
    // La chaîne régulière n'est accrochée nulle part : cible de saut.
    let regular = policy(&dev, "inet/filtre/sortie_lan");
    assert!(!dev.pipeline.ingress.contains(&regular.id));
    assert!(!dev.pipeline.egress.contains(&regular.id));
}

#[test]
fn zones_implicites_par_interface() {
    let dev = import_basic().device;
    // lo, lan0, wan0 : une zone par interface nommée, l'interface créée à
    // la volée (un fichier nftables ne déclare pas d'inventaire).
    assert_eq!(dev.zones.len(), 3);
    for name in ["lo", "lan0", "wan0"] {
        assert_eq!(
            dev.zones.get(&ZoneId::new(name)),
            Some(&vec![IfaceId::new(name)]),
            "zone `{name}`"
        );
        let iface = dev.interfaces.get(&IfaceId::new(name)).expect("interface");
        assert_eq!(iface.zone.as_ref().map(|z| z.as_str()), Some(name));
        assert!(iface.addrs.is_empty(), "les adresses vivent côté système");
    }
}

// ---------------------------------------------------------------------------
// Règles : ordre, pavés, spans exacts
// ---------------------------------------------------------------------------

#[test]
fn regles_de_la_chaine_entree_ordre_et_spans() {
    let dev = import_basic().device;
    let entree = policy(&dev, "inet/filtre/entree");

    // ORDRE SIGNIFICATIF : les règles 1, 2 (ct state) et 7 (counter seul)
    // sont écartées avec note ; restent 3..6 dans l'ordre du fichier.
    let ids: Vec<&str> = entree.rules.iter().map(|r| r.id.as_str()).collect();
    assert_eq!(ids, vec!["3", "4", "5", "6"]);

    // Règle 3 : iifname "lo" accept — zone d'entrée, pavé sans contrainte.
    let r3 = &entree.rules[0];
    assert_eq!(r3.from.as_ref().map(|z| z.as_str()), Some("lo"));
    assert_eq!(r3.to, None);
    assert!(r3.matches.src.is_empty() && r3.matches.dst.is_empty());
    assert!(r3.matches.services.is_empty());
    assert_eq!(r3.action, Action::Accept);
    assert_eq!(r3.source.file, FILE);
    assert_eq!(r3.source.line, 27);
    assert_eq!(r3.source.end_line, None);

    // Règle 4 : $net_admin (référence d'objet, résolution tardive) et
    // ensemble anonyme { 22, 443 } → DEUX services tcp.
    let r4 = &entree.rules[1];
    assert_eq!(
        r4.matches.src,
        vec![AddrExpr::Object(ObjectId::new("net_admin"))]
    );
    assert_eq!(
        r4.matches.services,
        vec![
            ServiceExpr::Service(Service::tcp_dport(PortRange::single(22))),
            ServiceExpr::Service(Service::tcp_dport(PortRange::single(443))),
        ]
    );
    assert_eq!(r4.source.line, 28);

    // Règle 5 : @postes_surv → référence QUALIFIÉE par la table.
    let r5 = &entree.rules[2];
    assert_eq!(
        r5.matches.src,
        vec![AddrExpr::Object(ObjectId::new("inet/filtre/postes_surv"))]
    );
    assert_eq!(
        r5.matches.services,
        vec![ServiceExpr::Service(Service::udp_dport(PortRange::single(
            161
        )))]
    );
    assert_eq!(r5.source.line, 29);

    // Règle 6 : ip protocol icmp → protocole nu, ports libres.
    let r6 = &entree.rules[3];
    assert_eq!(
        r6.matches.services,
        vec![ServiceExpr::Service(Service {
            proto: ProtoMatch::Number(1),
            sport: PortRange::ANY,
            dport: PortRange::ANY,
        })]
    );
    assert_eq!(r6.source.line, 30);
}

#[test]
fn saut_resolu_vers_la_chaine_reguliere() {
    let dev = import_basic().device;
    let transit = policy(&dev, "inet/filtre/transit");

    let ids: Vec<&str> = transit.rules.iter().map(|r| r.id.as_str()).collect();
    assert_eq!(ids, vec!["2", "3"], "la règle ct (1) est écartée");

    // Règle 2 : drop d'un préfixe, littéral dans le pavé.
    let r2 = &transit.rules[0];
    assert_eq!(
        r2.matches.src,
        vec![AddrExpr::Net("192.168.99.0/24".parse().expect("net"))]
    );
    assert_eq!(r2.action, Action::Deny);
    assert_eq!(r2.source.line, 39);

    // Règle 3 : jump → la cible EXISTE et l'action est Jump.
    let r3 = &transit.rules[1];
    assert_eq!(r3.from.as_ref().map(|z| z.as_str()), Some("lan0"));
    assert_eq!(r3.to.as_ref().map(|z| z.as_str()), Some("wan0"));
    let Action::Jump(target) = &r3.action else {
        panic!("le saut doit être une Action::Jump : {:?}", r3.action);
    };
    assert_eq!(target.as_str(), "inet/filtre/sortie_lan");
    assert!(
        dev.policies.contains_key(target),
        "la politique cible du saut existe"
    );
    assert_eq!(r3.source.line, 40);

    // La cible : quatre règles, dont la plage de ports.
    let cible = policy(&dev, "inet/filtre/sortie_lan");
    assert_eq!(cible.rules.len(), 4);
    assert_eq!(
        cible.rules[1].matches.services,
        vec![ServiceExpr::Service(Service::tcp_dport(PortRange {
            start: 8080,
            end: 8090
        }))]
    );
    // meta l4proto icmp → protocole nu.
    assert_eq!(
        cible.rules[3].matches.services,
        vec![ServiceExpr::Service(Service {
            proto: ProtoMatch::Number(1),
            sport: PortRange::ANY,
            dport: PortRange::ANY,
        })]
    );
}

#[test]
fn chaine_de_sortie_accrochee_en_egress() {
    let dev = import_basic().device;
    let sortie = policy(&dev, "inet/filtre/sortie");
    // La règle `log` seule (2) est écartée ; reste la règle ntp.
    assert_eq!(sortie.rules.len(), 1);
    let r1 = &sortie.rules[0];
    assert_eq!(r1.id, RuleId::new("1"));
    assert_eq!(r1.to.as_ref().map(|z| z.as_str()), Some("wan0"));
    assert_eq!(
        r1.matches.services,
        vec![ServiceExpr::Service(Service::udp_dport(PortRange::single(
            123
        )))]
    );
    assert_eq!(r1.source.line, 55);
}

// ---------------------------------------------------------------------------
// Ensembles nommés et variables → objets (résolution tardive, §3.3)
// ---------------------------------------------------------------------------

#[test]
fn set_et_define_dans_le_magasin_d_objets() {
    let dev = import_basic().device;
    assert_eq!(dev.objects.addresses.len(), 2);

    // La variable `define` : objet global, non qualifié.
    match dev
        .objects
        .addresses
        .get(&ObjectId::new("net_admin"))
        .expect("net_admin")
    {
        AddrObject::Nets(nets) => {
            assert_eq!(nets, &vec!["10.20.30.0/24".parse().expect("net")]);
        }
        other => panic!("net_admin devrait être des réseaux : {other:?}"),
    }

    // L'ensemble nommé : objet qualifié `famille/table/nom`.
    match dev
        .objects
        .addresses
        .get(&ObjectId::new("inet/filtre/postes_surv"))
        .expect("postes_surv")
    {
        AddrObject::Nets(nets) => {
            let texte: Vec<String> = nets.iter().map(|n| n.to_string()).collect();
            assert_eq!(
                texte,
                vec!["10.20.40.0/26", "10.20.41.16/28", "10.20.42.7/32"]
            );
        }
        other => panic!("postes_surv devrait être des réseaux : {other:?}"),
    }

    // Aucun ensemble de ports dans la fixture : pas d'objet service.
    assert!(dev.objects.services.is_empty());
}

/// Un ensemble de ports (`type inet_service`) référencé par `tcp dport`
/// devient un objet service DÉRIVÉ, traçable vers l'ensemble d'origine.
#[test]
fn ensemble_de_ports_objet_derive() {
    let out = import(
        "table ip t {\n    set admin { type inet_service; elements = { 22, 8443 } }\n\
         \n    chain c {\n        type filter hook input priority 0; policy drop;\n        \
         tcp dport @admin accept\n    }\n}\n",
    );
    assert_eq!(out.fidelity, Fidelity::Complete);
    let rule = &policy(&out.device, "ip/t/c").rules[0];
    let oid = ObjectId::new("ip/t/admin:tcp:dport");
    assert_eq!(
        rule.matches.services,
        vec![ServiceExpr::Object(oid.clone())]
    );
    match out.device.objects.services.get(&oid).expect("objet dérivé") {
        ServiceObject::Services(svcs) => {
            assert_eq!(
                svcs,
                &vec![
                    Service::tcp_dport(PortRange::single(22)),
                    Service::tcp_dport(PortRange::single(8443)),
                ]
            );
        }
        other => panic!("objet dérivé inattendu : {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// `ct state` : Info documentée, jamais Partial
// ---------------------------------------------------------------------------

#[test]
fn ct_state_note_info_sans_degrader_la_fidelite() {
    let out = import(
        "table inet t {\n    chain c {\n        type filter hook input priority 0; policy drop;\n        \
         ct state established,related accept\n        tcp dport 22 accept\n    }\n}\n",
    );
    // La fidélité reste COMPLÈTE : le verdict d'un flux initiateur ne
    // dépend pas de la règle écartée (analyse sans état, choix documenté).
    assert_eq!(out.fidelity, Fidelity::Complete);
    let info = out
        .notes
        .iter()
        .find(|n| n.severity == Severity::Info && n.message.contains("ct state"))
        .expect("note Info pour la règle ct");
    assert!(info.message.contains("analyse sans état"), "{info:?}");
    // La règle ct n'apparaît pas ; la règle ssh garde son ordinal (2).
    let rules = &policy(&out.device, "inet/t/c").rules;
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0].id, RuleId::new("2"));
}

/// `ct state new` : la condition est VRAIE pour le paquet initiateur, la
/// contrainte est retirée sans approximation — la règle reste.
#[test]
fn ct_state_new_garde_la_regle() {
    let out = import(
        "table inet t {\n    chain c {\n        type filter hook input priority 0; policy drop;\n        \
         ct state new tcp dport 25 drop\n    }\n}\n",
    );
    assert_eq!(out.fidelity, Fidelity::Complete);
    let rules = &policy(&out.device, "inet/t/c").rules;
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0].action, Action::Deny);
    assert_eq!(
        rules[0].matches.services,
        vec![ServiceExpr::Service(Service::tcp_dport(PortRange::single(
            25
        )))]
    );
}

// ---------------------------------------------------------------------------
// Diagnostics : familles hors modèle, NAT, goto, reject, inconnu…
// ---------------------------------------------------------------------------

#[test]
fn famille_arp_hors_modele_partial() {
    let out = import("table arp raw {\n    chain c {\n        counter\n    }\n}\n");
    let msgs = partial_messages(&out);
    assert!(
        msgs.iter()
            .any(|m| m.contains("arp") && m.contains("hors modèle")),
        "{msgs:?}"
    );
    assert!(out.device.policies.is_empty(), "rien n'est modélisé");
}

#[test]
fn ip6_mappe_dans_une_table_inet() {
    let out = import(
        "table inet t {\n    chain c {\n        type filter hook input priority 0; policy drop;\n        \
         ip6 saddr 2001:db8:bad::/48 drop\n    }\n}\n",
    );
    assert_eq!(out.fidelity, Fidelity::Complete);
    let rule = &policy(&out.device, "inet/t/c").rules[0];
    assert_eq!(
        rule.matches.src,
        vec![AddrExpr::Net("2001:db8:bad::/48".parse().expect("net"))]
    );
}

#[test]
fn masquerade_diagnostique_non_modelise() {
    let out = import(
        "table ip nat {\n    chain post {\n        type nat hook postrouting priority srcnat; policy accept;\n        \
         oifname \"wan0\" masquerade\n    }\n}\n",
    );
    let msgs = partial_messages(&out);
    // Diagnostiqué DEUX fois : la chaîne `type nat` non accrochée, et la
    // règle `masquerade` elle-même.
    assert!(
        msgs.iter().any(|m| m.contains("type nat")),
        "chaîne nat : {msgs:?}"
    );
    assert!(
        msgs.iter()
            .any(|m| m.contains("masquerade") && m.contains("non modélisée")),
        "règle masquerade : {msgs:?}"
    );
    assert!(out.device.pipeline.ingress.is_empty() && out.device.pipeline.egress.is_empty());
}

#[test]
fn goto_modelise_comme_jump_avec_note() {
    let out = import(
        "table inet t {\n    chain c {\n        type filter hook input priority 0; policy drop;\n        \
         goto autre\n    }\n    chain autre {\n        accept\n    }\n}\n",
    );
    assert_eq!(out.fidelity, Fidelity::Complete, "goto est compris");
    let rule = &policy(&out.device, "inet/t/c").rules[0];
    assert_eq!(rule.action, Action::Jump(PolicyId::new("inet/t/autre")));
    let note = out
        .notes
        .iter()
        .find(|n| n.severity == Severity::Warning && n.message.contains("goto"))
        .expect("note sur la nuance de retombée");
    assert!(note.message.contains("retombée"), "{note:?}");
}

#[test]
fn reject_est_un_refus_avec_note() {
    let out = import(
        "table inet t {\n    chain c {\n        type filter hook input priority 0; policy accept;\n        \
         tcp dport 113 reject with tcp reset comment \"ident\"\n    }\n}\n",
    );
    assert_eq!(out.fidelity, Fidelity::Complete);
    let rule = &policy(&out.device, "inet/t/c").rules[0];
    assert_eq!(rule.action, Action::Deny);
    assert!(out
        .notes
        .iter()
        .any(|n| n.severity == Severity::Info && n.message.contains("reject")));
}

#[test]
fn return_inconditionnel_termine_la_chaine() {
    let out = import(
        "table inet t {\n    chain c {\n        type filter hook input priority 0; policy drop;\n        \
         tcp dport 22 accept\n        return\n        tcp dport 23 accept\n    }\n}\n",
    );
    assert_eq!(out.fidelity, Fidelity::Complete);
    // La règle après le `return` est du code mort : écartée avec note.
    let rules = &policy(&out.device, "inet/t/c").rules;
    assert_eq!(rules.len(), 1);
    assert!(
        out.notes.iter().any(|n| n.message.contains("code mort")),
        "{:?}",
        out.notes
    );

    // Un `return` CONDITIONNEL, lui, n'est pas modélisable : Partial.
    let out = import(
        "table inet t {\n    chain c {\n        type filter hook input priority 0; policy drop;\n        \
         ip saddr 10.0.0.0/8 return\n    }\n}\n",
    );
    let msgs = partial_messages(&out);
    assert!(
        msgs.iter()
            .any(|m| m.contains("return") && m.contains("conditionnel")),
        "{msgs:?}"
    );
}

#[test]
fn saut_vers_chaine_inconnue_ou_de_base_diagnostique() {
    let out = import(
        "table inet t {\n    chain c {\n        type filter hook input priority 0; policy drop;\n        \
         jump fantome\n    }\n}\n",
    );
    let msgs = partial_messages(&out);
    assert!(msgs.iter().any(|m| m.contains("fantome")), "{msgs:?}");
    // Le modèle ne contient pas de saut cassé (le moteur planterait).
    assert!(policy(&out.device, "inet/t/c").rules.is_empty());

    let out = import(
        "table inet t {\n    chain a {\n        type filter hook input priority 0; policy drop;\n        \
         jump b\n    }\n    chain b {\n        type filter hook forward priority 0; policy drop;\n    }\n}\n",
    );
    let msgs = partial_messages(&out);
    assert!(
        msgs.iter().any(|m| m.contains("chaîne de base")),
        "{msgs:?}"
    );
}

#[test]
fn expression_inconnue_degrade_la_fidelite() {
    let out = import(
        "table inet t {\n    chain c {\n        type filter hook input priority 0; policy drop;\n        \
         meta skuid 1000 accept\n        tcp dport 22 accept\n    }\n}\n",
    );
    let msgs = partial_messages(&out);
    assert!(
        msgs.iter().any(|m| m.contains("meta skuid")),
        "l'expression inconnue est diagnostiquée : {msgs:?}"
    );
    // La règle comprise reste, avec son ordinal du fichier.
    let rules = &policy(&out.device, "inet/t/c").rules;
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0].id, RuleId::new("2"));
}

#[test]
fn include_non_resolu_degrade_la_fidelite() {
    let out = import("include \"autres-regles.nft\"\ntable inet t {\n    chain c {\n    }\n}\n");
    let msgs = partial_messages(&out);
    assert!(
        msgs.iter()
            .any(|m| m.contains("include") && m.contains("incomplet")),
        "{msgs:?}"
    );
}

#[test]
fn politique_par_defaut_absente_vaut_accept() {
    // Comportement documenté de nftables : sans `policy`, une chaîne de
    // base accepte.
    let out = import(
        "table inet t {\n    chain c {\n        type filter hook input priority 0\n    }\n}\n",
    );
    assert_eq!(out.fidelity, Fidelity::Complete);
    assert_eq!(
        policy(&out.device, "inet/t/c").default_action,
        Action::Accept
    );
}

// ---------------------------------------------------------------------------
// Robustesse : jamais de panique sur une entrée externe
// ---------------------------------------------------------------------------

#[test]
fn entrees_hostiles_sans_panique() {
    let adapter = NftablesAdapter;
    for raw in [
        "",
        "}\n}\n{\n",
        "table\ntable inet\ntable inet t {\n",
        "table inet t { chain c { tcp dport { 22, } accept } }",
        "table inet t { chain c { type filter hook input priority beaucoup; policy peut-etre; } }",
        "define x =\ndefine y = $x\ninclude\n",
        "table inet t { chain c { jump c } }",
        "table inet t { set s { type ipv4_addr; elements = { 999.9.9.9 } } }",
        "table ip6 t { chain c { ip saddr 10.0.0.1 accept } }",
        "flush ruleset extra\nadd rule inet t c accept\n",
    ] {
        // Ok(modèle partiel) ou Err(diagnostics) : tout sauf une panique.
        let _ = adapter.import_str(raw, "hostile.nft");
    }
}

/// Un saut circulaire est accepté à l'import (le moteur le détecte à
/// l'évaluation) mais les deux politiques existent, sans panique.
#[test]
fn sauts_croises_importes_sans_panique() {
    let out = import(
        "table inet t {\n    chain a {\n        jump b\n    }\n    chain b {\n        jump a\n    }\n}\n",
    );
    assert_eq!(out.fidelity, Fidelity::Complete);
    assert!(out.device.policies.contains_key(&PolicyId::new("inet/t/a")));
    assert!(out.device.policies.contains_key(&PolicyId::new("inet/t/b")));
}
