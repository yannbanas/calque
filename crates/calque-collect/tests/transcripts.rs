//! Les parseurs de collecte contre les transcripts enregistrés de
//! `corpus/collect/` — AUCUN réseau requis : c'est là qu'est l'essentiel
//! de la valeur de test de la collecte (le transport SSH, lui, exige un
//! équipement réel et n'est pas testable ici).
//!
//! Les transcripts sont INVENTÉS mais réalistes : formats observés sur
//! IOS 15.x / IOS-XE 16.x et FortiOS 7.x, avec des pièges volontaires
//! (bannières, pagination `--More--`, retours chariot, retours arrière).

use calque_collect::clean::clean_output;
use calque_collect::detect::{classify_fortigate_status, classify_show_version};
use calque_collect::ifname::normalize_ifname;
use calque_collect::parse::cisco::{parse_cdp_neighbors_detail, parse_lldp_neighbors_detail};
use calque_collect::parse::fortigate::{parse_lldprx_summary, parse_system_status};
use calque_collect::parse::neighbors_to_links;
use calque_collect::Neighbor;
use calque_model::{DeviceId, LinkOrigin, Vendor};

macro_rules! transcript {
    ($chemin:literal) => {
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../corpus/collect/",
            $chemin
        ))
    };
}

// ---------------------------------------------------------------------------
// Cisco IOS
// ---------------------------------------------------------------------------

#[test]
fn cisco_lldp_deux_voisins() {
    let parsed =
        parse_lldp_neighbors_detail(transcript!("cisco_ios/show_lldp_neighbors_detail.txt"));
    assert_eq!(parsed.warnings, Vec::<String>::new());
    assert_eq!(
        parsed.neighbors,
        vec![
            Neighbor {
                local_iface: "GigabitEthernet0/1".into(),
                remote_device: "sw-acces-01".into(),
                remote_iface: "GigabitEthernet0/24".into(),
            },
            Neighbor {
                // Te1/0/48 est bien abrégé DIFFÉREMMENT des deux côtés.
                local_iface: "TenGigabitEthernet1/0/48".into(),
                // Le FQDN LLDP est ramené au nom court.
                remote_device: "sw-coeur-01".into(),
                remote_iface: "TenGigabitEthernet1/1/1".into(),
            },
        ]
    );
}

#[test]
fn cisco_cdp_deux_voisins() {
    let parsed = parse_cdp_neighbors_detail(transcript!("cisco_ios/show_cdp_neighbors_detail.txt"));
    assert_eq!(parsed.warnings, Vec::<String>::new());
    assert_eq!(
        parsed.neighbors,
        vec![
            Neighbor {
                local_iface: "GigabitEthernet0/1".into(),
                remote_device: "sw-acces-01".into(),
                remote_iface: "GigabitEthernet0/24".into(),
            },
            Neighbor {
                local_iface: "GigabitEthernet0/2".into(),
                // Le numéro de série entre parenthèses (Nexus/ISR) est retiré.
                remote_device: "rt-agence-02".into(),
                remote_iface: "GigabitEthernet0/0/1".into(),
            },
        ]
    );
}

/// LLDP et CDP voient le même voisin sur Gi0/1 sous des formes
/// différentes : après normalisation, le lien ne compte qu'une fois.
#[test]
fn cisco_lldp_et_cdp_fusionnent_sans_doublon() {
    let lldp = parse_lldp_neighbors_detail(transcript!("cisco_ios/show_lldp_neighbors_detail.txt"));
    let cdp = parse_cdp_neighbors_detail(transcript!("cisco_ios/show_cdp_neighbors_detail.txt"));
    let mut all = lldp.neighbors;
    all.extend(cdp.neighbors);
    let links = neighbors_to_links(&DeviceId::new("sw-agence-01"), &all);
    // 4 voisins parsés, mais Gi0/1→sw-acces-01:Gi0/24 est vu deux fois.
    assert_eq!(links.len(), 3);
    assert!(links.iter().all(|l| l.origin == LinkOrigin::Lldp));
    assert!(links.iter().all(|l| l.a.device.as_str() == "sw-agence-01"));
}

/// Le transcript piège : bannière d'accueil (contenant même la chaîne
/// `--More--`), invite de pagination vidéo-inversée effacée au retour
/// chariot, invite de l'équipement. Le nettoyage + parseur y survivent.
#[test]
fn cisco_lldp_avec_banniere_et_pagination() {
    let brut = transcript!("cisco_ios/lldp_avec_banniere_et_pagination.raw");
    let propre = clean_output(brut);
    assert!(
        !propre.contains("\u{1b}"),
        "séquences ANSI résiduelles : {propre:?}"
    );
    let parsed = parse_lldp_neighbors_detail(&propre);
    assert_eq!(parsed.warnings, Vec::<String>::new());
    assert_eq!(
        parsed.neighbors,
        vec![
            Neighbor {
                local_iface: "GigabitEthernet0/1".into(),
                remote_device: "sw-acces-01".into(),
                remote_iface: "GigabitEthernet0/24".into(),
            },
            Neighbor {
                local_iface: "GigabitEthernet0/2".into(),
                remote_device: "rt-agence-02".into(),
                remote_iface: "GigabitEthernet0/0/1".into(),
            },
        ]
    );
}

#[test]
fn cisco_show_version_reconnu() {
    let out = transcript!("cisco_ios/show_version.txt");
    assert_eq!(classify_show_version(out), Some(Vendor::CiscoIos));
    assert_eq!(classify_fortigate_status(out), None);
}

// ---------------------------------------------------------------------------
// FortiGate
// ---------------------------------------------------------------------------

#[test]
fn fortigate_statut_systeme() {
    let out = transcript!("fortigate/get_system_status.txt");
    assert_eq!(classify_fortigate_status(out), Some(Vendor::Fortigate));
    assert_eq!(classify_show_version(out), None);
    let status = parse_system_status(out);
    assert_eq!(status.hostname.as_deref(), Some("fw-agence-01"));
    assert!(status.version.as_deref().unwrap().contains("v7.2.5"));
}

#[test]
fn fortigate_lldp_deux_voisins() {
    let parsed = parse_lldprx_summary(transcript!(
        "fortigate/diagnose_lldprx_neighbor_summary.txt"
    ));
    assert_eq!(parsed.warnings, Vec::<String>::new());
    assert_eq!(
        parsed.neighbors,
        vec![
            Neighbor {
                // Les noms FortiGate ne sont pas des abréviations Cisco :
                // rendus tels quels.
                local_iface: "port1".into(),
                remote_device: "sw-acces-01".into(),
                // …mais le port DISTANT annoncé par un Cisco est normalisé.
                remote_iface: "GigabitEthernet0/23".into(),
            },
            Neighbor {
                local_iface: "wan1".into(),
                remote_device: "rt-operateur-01".into(),
                remote_iface: "GigabitEthernet0/0/0".into(),
            },
        ]
    );
}

/// Le piège FortiGate : l'invite `--More--` effacée à coups de retours
/// arrière (`\x08`) au beau milieu du tableau.
#[test]
fn fortigate_lldp_avec_pagination() {
    let brut = transcript!("fortigate/lldprx_avec_pagination.raw");
    let propre = clean_output(brut);
    assert!(
        !propre.contains("--More--"),
        "pagination résiduelle : {propre:?}"
    );
    let parsed = parse_lldprx_summary(&propre);
    assert_eq!(parsed.warnings, Vec::<String>::new());
    assert_eq!(parsed.neighbors.len(), 2);
    assert_eq!(parsed.neighbors[1].local_iface, "port3");
    assert_eq!(parsed.neighbors[1].remote_device, "srv-hyperviseur");
    assert_eq!(parsed.neighbors[1].remote_iface, "ens192");
}

// ---------------------------------------------------------------------------
// Normalisation croisée : la propriété qui fait tenir la fusion des liens
// ---------------------------------------------------------------------------

/// Les deux graphies d'un même port convergent : c'est ce qui permet à un
/// lien vu de deux équipements (ou de deux protocoles) de se recouper.
#[test]
fn normalisation_convergente() {
    for (a, b) in [
        ("Gi0/24", "GigabitEthernet0/24"),
        ("Te1/1/1", "TenGigabitEthernet1/1/1"),
        ("Po10", "Port-channel10"),
        ("Fa0/24", "FastEthernet0/24"),
    ] {
        assert_eq!(normalize_ifname(a), normalize_ifname(b), "{a} vs {b}");
    }
}
