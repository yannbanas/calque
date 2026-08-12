//! Transformation des adresses IP : automorphisme d'arbre de préfixes.
//!
//! Le principe : une adresse est vue comme un chemin dans l'arbre binaire
//! des préfixes. À chaque profondeur, le bit est éventuellement inversé,
//! et la décision d'inversion ne dépend QUE de la graine et du préfixe
//! déjà lu. Deux adresses qui partagent leurs `k` premiers bits partagent
//! donc exactement leurs `k` premiers bits de sortie — les relations de
//! sous-réseau et les longueurs de préfixe sont préservées à l'identique
//! (dans les deux sens : rien ne « rentre » dans un préfixe par accident).
//!
//! C'est un cas particulier du schéma « même octet d'entrée au même
//! niveau → même octet de sortie » : l'image d'un octet ne dépend que des
//! octets qui le précèdent.
//!
//! **Branches épinglées** : le long du chemin des préfixes listés dans
//! [`PINS_V4`]/[`PINS_V6`], l'inversion est forcée à zéro. Conséquences :
//! - les plages épinglées sont stables comme ENSEMBLES (10/8 reste dans
//!   10/8, 172.16/12 dans 172.16/12, 192.168/16 dans 192.168/16) ;
//! - aucune adresse extérieure ne peut être envoyée DANS une plage
//!   épinglée — donc jamais de collision avec les plages spéciales et de
//!   documentation, qui sont rendues inchangées.
//!
//! Le prix, documenté honnêtement : les tout premiers bits d'une adresse
//! sont peu (voire pas) transformés. Le but est la préservation de la
//! structure, pas un chiffrement — la table de correspondance reste de
//! toute façon à protéger.

use std::net::{Ipv4Addr, Ipv6Addr};

/// Graine fixe et publique du brouillage (déterminisme total, §11.4).
/// La sécurité ne repose PAS sur cette graine mais sur la garde de la
/// table de correspondance ; elle est fixée pour que deux exécutions —
/// et deux machines — produisent exactement la même sortie.
pub(crate) const GRAINE: u64 = 0x5EED_CA1C_0DE0_0001;

const ETIQUETTE_V4: u64 = 0x76_34;
const ETIQUETTE_V6: u64 = 0x76_36;

/// Préfixes IPv4 épinglés : (préfixe aligné à gauche, longueur en bits).
const PINS_V4: &[(u32, u32)] = &[
    (0x0000_0000, 8),  // 0.0.0.0/8 (« ce réseau », jokers 0.x)
    (0x0A00_0000, 8),  // 10.0.0.0/8 (RFC1918, stable comme ensemble)
    (0x7F00_0000, 8),  // 127.0.0.0/8 (boucle locale)
    (0xA9FE_0000, 16), // 169.254.0.0/16 (lien local)
    (0xAC10_0000, 12), // 172.16.0.0/12 (RFC1918)
    (0xC000_0200, 24), // 192.0.2.0/24 (documentation)
    (0xC0A8_0000, 16), // 192.168.0.0/16 (RFC1918)
    (0xC633_6400, 24), // 198.51.100.0/24 (documentation)
    (0xCB00_7100, 24), // 203.0.113.0/24 (documentation)
    (0xE000_0000, 3),  // 224.0.0.0/3 (multicast, réservé, diffusion)
];

/// Préfixes IPv6 épinglés.
const PINS_V6: &[(u128, u32)] = &[
    (0, 8),                  // ::/8 (non spécifiée, compatibles v4)
    (1, 128),                // ::1/128 (boucle locale)
    (0x2001_0db8 << 96, 32), // 2001:db8::/32 (documentation)
    (0xfc << 120, 7),        // fc00::/7 (ULA : reste une ULA)
    (0xfe80 << 112, 10),     // fe80::/10 (lien local)
    (0xff << 120, 8),        // ff00::/8 (multicast)
];

/// Adresses IPv4 rendues strictement inchangées.
pub(crate) fn speciale_v4(a: Ipv4Addr) -> bool {
    let v = u32::from(a);
    (v >> 24) == 0            // 0.0.0.0/8 (dont 0.0.0.0 et les jokers 0.x)
        || (v >> 24) == 127   // boucle locale
        || (v >> 16) == 0xA9FE // 169.254/16 lien local
        || (v >> 29) == 0b111 // 224.0.0.0/3 : multicast + réservé + 255.255.255.255
        || (v >> 8) == 0x00C0_0002 // 192.0.2.0/24
        || (v >> 8) == 0x00C6_3364 // 198.51.100.0/24
        || (v >> 8) == 0x00CB_0071 // 203.0.113.0/24
}

/// Adresses IPv6 rendues strictement inchangées (au mieux, documenté).
pub(crate) fn speciale_v6(a: Ipv6Addr) -> bool {
    let s = a.segments();
    a.is_unspecified()
        || a.is_loopback()
        || (s[0] & 0xffc0) == 0xfe80 // lien local
        || (s[0] >> 8) == 0xff       // multicast
        || (s[0] == 0x2001 && s[1] == 0x0db8) // documentation
}

/// `v` est-il un masque de sous-réseau valide (uns contigus puis zéros) ?
fn masque_valide(v: u32) -> bool {
    v.leading_ones() + v.trailing_zeros() >= 32
}

/// Masque de sous-réseau OU masque joker (wildcard) valide.
pub(crate) fn masque_ou_joker(a: Ipv4Addr) -> bool {
    let v = u32::from(a);
    masque_valide(v) || masque_valide(!v)
}

/// Mélangeur splitmix64 : la seule source de « hasard », entièrement
/// déterminée par la graine.
fn melange64(mut x: u64) -> u64 {
    x = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = x;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// Le préfixe (`prof` premiers bits) est-il sur le chemin d'un pin v4 ?
fn sur_chemin_pin_v4(prof: u32, prefixe: u32) -> bool {
    if prof == 0 {
        return true; // le préfixe vide est sur le chemin de tous les pins
    }
    PINS_V4
        .iter()
        .any(|&(p, l)| prof < l && (p >> (32 - prof)) == prefixe)
}

fn sur_chemin_pin_v6(prof: u32, prefixe: u128) -> bool {
    if prof == 0 {
        return true;
    }
    PINS_V6
        .iter()
        .any(|&(p, l)| prof < l && (p >> (128 - prof)) == prefixe)
}

/// Décision d'inversion du bit à la profondeur `prof`, préfixe `prefixe`.
fn bascule_v4(prof: u32, prefixe: u32) -> u32 {
    let cle = ((prof as u64) << 40) | prefixe as u64;
    (melange64(GRAINE ^ ETIQUETTE_V4 ^ cle) & 1) as u32
}

fn bascule_v6(prof: u32, prefixe: u128) -> u128 {
    let mut h = melange64(GRAINE ^ ETIQUETTE_V6 ^ prof as u64);
    h = melange64(h ^ (prefixe as u64));
    h = melange64(h ^ ((prefixe >> 64) as u64));
    (h & 1) as u128
}

/// Transforme une adresse IPv4 (automorphisme de l'arbre des préfixes).
pub(crate) fn transformer_v4(a: Ipv4Addr) -> Ipv4Addr {
    let e = u32::from(a);
    let mut s = 0u32;
    for prof in 0..32 {
        let bit = (e >> (31 - prof)) & 1;
        let prefixe = if prof == 0 { 0 } else { e >> (32 - prof) };
        let inv = if sur_chemin_pin_v4(prof, prefixe) {
            0
        } else {
            bascule_v4(prof, prefixe)
        };
        s = (s << 1) | (bit ^ inv);
    }
    Ipv4Addr::from(s)
}

/// Transforme une adresse IPv6 (même principe, 128 bits — au mieux).
pub(crate) fn transformer_v6(a: Ipv6Addr) -> Ipv6Addr {
    let e = u128::from(a);
    let mut s = 0u128;
    for prof in 0..128 {
        let bit = (e >> (127 - prof)) & 1;
        let prefixe = if prof == 0 { 0 } else { e >> (128 - prof) };
        let inv = if sur_chemin_pin_v6(prof, prefixe) {
            0
        } else {
            bascule_v6(prof, prefixe)
        };
        s = (s << 1) | (bit ^ inv);
    }
    Ipv6Addr::from(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Longueur du préfixe commun de deux adresses IPv4.
    fn prefixe_commun(a: Ipv4Addr, b: Ipv4Addr) -> u32 {
        (u32::from(a) ^ u32::from(b)).leading_zeros()
    }

    #[test]
    fn l_automorphisme_preserve_les_prefixes_communs() {
        // Échantillon pseudo-aléatoire déterministe de paires : la longueur
        // du préfixe commun doit être EXACTEMENT conservée.
        let mut g = 42u64;
        for _ in 0..2000 {
            g = melange64(g);
            let a = Ipv4Addr::from(g as u32);
            g = melange64(g);
            // Forcer des préfixes communs variés en tronquant le xor.
            let decalage = (g % 33) as u32;
            let brouillage = (melange64(g) as u32).checked_shr(decalage).unwrap_or(0);
            let b = Ipv4Addr::from(u32::from(a) ^ brouillage);
            let (ta, tb) = (transformer_v4(a), transformer_v4(b));
            assert_eq!(
                prefixe_commun(a, b),
                prefixe_commun(ta, tb),
                "préfixe commun altéré pour {a} / {b}"
            );
        }
    }

    #[test]
    fn les_plages_epinglees_sont_stables_et_jamais_atteintes() {
        let mut g = 7u64;
        for _ in 0..4000 {
            g = melange64(g);
            let a = Ipv4Addr::from(g as u32);
            if speciale_v4(a) {
                continue;
            }
            let t = transformer_v4(a);
            // Jamais transformée VERS une plage spéciale.
            assert!(!speciale_v4(t), "{a} envoyée sur l'adresse spéciale {t}");
            // Les plages privées restent dans leur plage.
            let (va, vt) = (u32::from(a), u32::from(t));
            if va >> 24 == 10 {
                assert_eq!(vt >> 24, 10);
            }
            if va >> 20 == 0xAC1 {
                assert_eq!(vt >> 20, 0xAC1);
            }
            if va >> 16 == 0xC0A8 {
                assert_eq!(vt >> 16, 0xC0A8);
            }
        }
    }

    #[test]
    fn transformation_injective_sur_un_echantillon() {
        use std::collections::HashSet;
        let mut entrees = HashSet::new();
        let mut sorties = HashSet::new();
        let mut g = 99u64;
        for _ in 0..4000 {
            g = melange64(g);
            let a = u32::from(Ipv4Addr::from(g as u32));
            let t = u32::from(transformer_v4(Ipv4Addr::from(a)));
            if entrees.insert(a) {
                assert!(sorties.insert(t), "collision sur {}", Ipv4Addr::from(t));
            }
        }
    }

    #[test]
    fn masques_et_jokers_reconnus() {
        for m in [
            "255.255.255.0",
            "255.255.255.252",
            "255.0.0.0",
            "128.0.0.0",
            "0.0.0.0",
        ] {
            assert!(masque_ou_joker(m.parse().unwrap()), "{m}");
        }
        for j in ["0.0.0.255", "0.0.255.255", "0.0.0.3", "0.0.0.1"] {
            assert!(masque_ou_joker(j.parse().unwrap()), "{j}");
        }
        for a in ["10.0.0.1", "192.168.1.99", "203.0.113.7", "255.255.0.255"] {
            assert!(!masque_ou_joker(a.parse().unwrap()), "{a}");
        }
    }

    #[test]
    fn adresses_speciales_v4() {
        for s in [
            "0.0.0.0",
            "255.255.255.255",
            "127.0.0.1",
            "224.0.0.5",
            "169.254.1.1",
            "192.0.2.7",
            "198.51.100.20",
            "203.0.113.9",
        ] {
            assert!(speciale_v4(s.parse().unwrap()), "{s}");
        }
        for n in ["10.0.0.1", "192.168.1.1", "8.8.8.8", "172.16.0.1"] {
            assert!(!speciale_v4(n.parse().unwrap()), "{n}");
        }
    }

    #[test]
    fn ipv6_prefixes_et_speciales() {
        assert!(speciale_v6("::1".parse().unwrap()));
        assert!(speciale_v6("fe80::1".parse().unwrap()));
        assert!(speciale_v6("ff02::1".parse().unwrap()));
        assert!(speciale_v6("2001:db8::42".parse().unwrap()));
        let a: Ipv6Addr = "fd00::10".parse().unwrap();
        let b: Ipv6Addr = "fd00::20".parse().unwrap();
        let (ta, tb) = (transformer_v6(a), transformer_v6(b));
        // Une ULA reste une ULA (fc00::/7 épinglé).
        assert_eq!(ta.segments()[0] & 0xfe00, 0xfc00);
        // Préfixe commun /121 préservé.
        let commun = (u128::from(a) ^ u128::from(b)).leading_zeros();
        assert_eq!(commun, (u128::from(ta) ^ u128::from(tb)).leading_zeros());
    }
}
