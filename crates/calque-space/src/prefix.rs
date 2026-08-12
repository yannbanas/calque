//! `PrefixSet` — un ensemble d'adresses IP représenté par des préfixes CIDR.
//!
//! Invariant : la liste est NORMALISÉE — préfixes tronqués (bits d'hôte à
//! zéro), triés, sans préfixe contenu dans un autre, et agrégés (deux
//! moitiés d'un même parent sont fusionnées en leur parent). Cette forme
//! est canonique : l'égalité dérivée est donc l'égalité ensembliste.
//!
//! Propriété clé des préfixes CIDR : deux préfixes sont soit disjoints,
//! soit l'un contient l'autre (structure laminaire). Cela simplifie
//! l'intersection et rend la suppression des contenus linéaire après tri.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use serde::{Deserialize, Serialize};

/// Ensemble de préfixes IP (IPv4 et IPv6), normalisé.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct PrefixSet {
    /// Toujours sous forme normalisée (voir la doc du module).
    prefixes: Vec<IpNet>,
}

// ---------------------------------------------------------------------------
// Arithmétique de bits sur les préfixes
//
// Un préfixe est vu comme (famille, adresse dans les `w` bits de poids
// faible d'un u128, longueur). w = 32 pour IPv4, 128 pour IPv6.
// ---------------------------------------------------------------------------

/// Décompose un préfixe en (est_v6, adresse, longueur, largeur).
fn parts(n: &IpNet) -> (bool, u128, u8, u8) {
    match n {
        IpNet::V4(v) => (false, u128::from(u32::from(v.addr())), v.prefix_len(), 32),
        IpNet::V6(v) => (true, u128::from(v.addr()), v.prefix_len(), 128),
    }
}

/// Reconstruit un préfixe. `len` est garanti valide par construction
/// (invariant interne, jamais issu d'une donnée externe).
fn from_bits(v6: bool, addr: u128, len: u8) -> IpNet {
    if v6 {
        IpNet::V6(Ipv6Net::new(Ipv6Addr::from(addr), len).expect("invariant interne : len <= 128"))
    } else {
        IpNet::V4(
            Ipv4Net::new(Ipv4Addr::from(addr as u32), len).expect("invariant interne : len <= 32"),
        )
    }
}

/// Les `len` bits de poids fort de l'adresse (0 si len == 0).
fn high_bits(addr: u128, len: u8, width: u8) -> u128 {
    if len == 0 {
        0
    } else {
        addr >> (width - len) // len >= 1 donc décalage <= 127
    }
}

/// Vrai si `a` contient `b` (au sens large : a == b compte).
fn net_contains(a: &IpNet, b: &IpNet) -> bool {
    let (af, aa, al, aw) = parts(a);
    let (bf, ba, bl, _) = parts(b);
    af == bf && al <= bl && high_bits(aa, al, aw) == high_bits(ba, al, aw)
}

/// Vrai si le préfixe `a` contient l'adresse `ip`.
fn net_contains_ip(a: &IpNet, ip: &IpAddr) -> bool {
    let (af, aa, al, aw) = parts(a);
    let (pf, pa) = match ip {
        IpAddr::V4(v) => (false, u128::from(u32::from(*v))),
        IpAddr::V6(v) => (true, u128::from(*v)),
    };
    af == pf && high_bits(aa, al, aw) == high_bits(pa, al, aw)
}

/// Masque réseau du niveau `l` dans une largeur `w` (bits de poids faible).
fn level_mask(l: u8, w: u8) -> u128 {
    if l == 0 {
        return 0;
    }
    let width_mask = if w == 128 {
        u128::MAX
    } else {
        (1u128 << w) - 1
    };
    (u128::MAX << (w - l)) & width_mask // l >= 1 donc décalage <= 127
}

/// `a \ b` pour deux préfixes. Trois cas :
/// - `b` contient `a` : résultat vide ;
/// - disjoints : `a` inchangé ;
/// - `a` contient strictement `b` : on descend de `a` vers `b` niveau par
///   niveau en conservant à chaque étape la moitié que `b` ne prend pas.
///   Produit exactement `len(b) - len(a)` préfixes.
fn subtract_one(a: &IpNet, b: &IpNet) -> Vec<IpNet> {
    if net_contains(b, a) {
        return Vec::new();
    }
    if !net_contains(a, b) {
        return vec![*a];
    }
    let (v6, ba, bl, w) = parts(b);
    let (_, _, al, _) = parts(a);
    let mut out = Vec::with_capacity(usize::from(bl - al));
    for l in (al + 1)..=bl {
        // Ancêtre de b au niveau l, dont on garde le frère (bit l inversé).
        let bit = 1u128 << (w - l); // l >= 1 donc décalage <= 127
        let sibling = (ba & level_mask(l, w)) ^ bit;
        out.push(from_bits(v6, sibling, l));
    }
    out
}

/// Si `a` et `b` sont les deux moitiés d'un même parent (`a` la basse,
/// `b` la haute), rend le parent.
fn merge_siblings(a: &IpNet, b: &IpNet) -> Option<IpNet> {
    let (af, aa, al, aw) = parts(a);
    let (bf, ba, bl, _) = parts(b);
    if af != bf || al != bl || al == 0 {
        return None;
    }
    let size = 1u128 << (aw - al); // al >= 1 donc décalage <= 127
                                   // a doit être la moitié basse du parent (bit de niveau al à zéro)
                                   // et b la moitié haute correspondante.
    if (aa >> (aw - al)) & 1 == 0 && ba == aa + size {
        Some(from_bits(af, aa, al - 1))
    } else {
        None
    }
}

/// Normalise une liste quelconque de préfixes : tronque, trie, supprime
/// les contenus, agrège les frères jusqu'au point fixe (via une pile).
/// La forme obtenue est canonique pour l'ensemble représenté.
fn normalize(mut v: Vec<IpNet>) -> Vec<IpNet> {
    for n in &mut v {
        *n = n.trunc();
    }
    // L'ordre dérivé de IpNet est (famille, adresse, longueur) : un
    // conteneur précède toujours ses contenus.
    v.sort();
    v.dedup();

    // Suppression des préfixes contenus. Après tri, si un préfixe est
    // contenu dans un préfixe déjà gardé, c'est nécessairement le dernier
    // (les gardés sont deux à deux disjoints et triés par adresse).
    let mut kept: Vec<IpNet> = Vec::with_capacity(v.len());
    for n in v {
        if let Some(top) = kept.last() {
            if net_contains(top, &n) {
                continue;
            }
        }
        kept.push(n);
    }

    // Agrégation des frères. Les frères sont adjacents dans l'ordre trié,
    // et un parent fraîchement créé peut fusionner avec son propre frère :
    // d'où la boucle sur le sommet de pile.
    let mut out: Vec<IpNet> = Vec::with_capacity(kept.len());
    for n in kept {
        out.push(n);
        while out.len() >= 2 {
            let b = out[out.len() - 1];
            let a = out[out.len() - 2];
            match merge_siblings(&a, &b) {
                Some(parent) => {
                    out.pop();
                    out.pop();
                    out.push(parent);
                }
                None => break,
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------
// API publique
// ---------------------------------------------------------------------------

impl PrefixSet {
    /// L'espace d'adressage entier (IPv4 et IPv6).
    pub fn full() -> Self {
        Self {
            prefixes: vec![from_bits(false, 0, 0), from_bits(true, 0, 0)],
        }
    }

    /// Tout l'IPv4 (0.0.0.0/0).
    pub fn full_v4() -> Self {
        Self {
            prefixes: vec![from_bits(false, 0, 0)],
        }
    }

    pub fn empty() -> Self {
        Self {
            prefixes: Vec::new(),
        }
    }

    pub fn from_net(net: IpNet) -> Self {
        Self::from_nets([net])
    }

    pub fn from_nets(nets: impl IntoIterator<Item = IpNet>) -> Self {
        Self {
            prefixes: normalize(nets.into_iter().collect()),
        }
    }

    /// Les préfixes, sous forme normalisée.
    pub fn prefixes(&self) -> &[IpNet] {
        &self.prefixes
    }

    pub fn is_empty(&self) -> bool {
        self.prefixes.is_empty()
    }

    /// Intersection. Grâce à la structure laminaire des préfixes, pour
    /// chaque paire le résultat est le plus spécifique des deux (ou rien).
    pub fn intersect(&self, other: &Self) -> Self {
        let mut out = Vec::new();
        for a in &self.prefixes {
            for b in &other.prefixes {
                if net_contains(a, b) {
                    out.push(*b);
                } else if net_contains(b, a) {
                    out.push(*a);
                }
            }
        }
        Self {
            prefixes: normalize(out),
        }
    }

    pub fn union(&self, other: &Self) -> Self {
        let mut all = self.prefixes.clone();
        all.extend_from_slice(&other.prefixes);
        Self {
            prefixes: normalize(all),
        }
    }

    /// `self \ other` : chaque préfixe de `self` est raboté successivement
    /// par chaque préfixe de `other` (cf. `subtract_one`).
    pub fn subtract(&self, other: &Self) -> Self {
        let mut work = self.prefixes.clone();
        for b in &other.prefixes {
            work = work.iter().flat_map(|a| subtract_one(a, b)).collect();
        }
        Self {
            prefixes: normalize(work),
        }
    }

    /// Inclusion ensembliste : `other ⊆ self`.
    pub fn contains_set(&self, other: &Self) -> bool {
        other.subtract(self).is_empty()
    }

    pub fn contains_ip(&self, ip: &IpAddr) -> bool {
        self.prefixes.iter().any(|p| net_contains_ip(p, ip))
    }

    /// Une adresse représentative : l'adresse réseau du premier préfixe
    /// (IPv4 d'abord, par ordre de tri).
    pub fn sample_ip(&self) -> Option<IpAddr> {
        self.prefixes.first().map(|p| match p {
            IpNet::V4(v) => IpAddr::V4(v.network()),
            IpNet::V6(v) => IpAddr::V6(v.network()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn net(s: &str) -> IpNet {
        s.parse().expect("préfixe de test valide")
    }

    #[test]
    fn normalisation_agrege_les_freres() {
        let s = PrefixSet::from_nets([net("10.0.0.0/25"), net("10.0.0.128/25")]);
        assert_eq!(s.prefixes(), &[net("10.0.0.0/24")]);
    }

    #[test]
    fn normalisation_supprime_les_contenus() {
        let s = PrefixSet::from_nets([net("10.0.0.0/8"), net("10.1.2.0/24")]);
        assert_eq!(s.prefixes(), &[net("10.0.0.0/8")]);
    }

    #[test]
    fn normalisation_agrege_en_cascade() {
        // Les quatre /2 doivent remonter jusqu'à /0.
        let s = PrefixSet::from_nets([
            net("0.0.0.0/2"),
            net("64.0.0.0/2"),
            net("128.0.0.0/2"),
            net("192.0.0.0/2"),
        ]);
        assert_eq!(s.prefixes(), &[net("0.0.0.0/0")]);
    }

    #[test]
    fn soustraction_decompose() {
        // /8 moins /24 : 24 - 8 = 16 préfixes.
        let a = PrefixSet::from_net(net("10.0.0.0/8"));
        let b = PrefixSet::from_net(net("10.1.2.0/24"));
        let d = a.subtract(&b);
        assert_eq!(d.prefixes().len(), 16);
        // Exactitude : d ∪ b == a et d ∩ b == ∅.
        assert_eq!(d.union(&b), a);
        assert!(d.intersect(&b).is_empty());
        assert!(!d.contains_ip(&"10.1.2.3".parse().expect("ip")));
        assert!(d.contains_ip(&"10.1.3.1".parse().expect("ip")));
    }

    #[test]
    fn familles_separees() {
        let v4 = PrefixSet::from_net(net("10.0.0.0/8"));
        let v6 = PrefixSet::from_net(net("2001:db8::/32"));
        assert!(v4.intersect(&v6).is_empty());
        assert!(!v4.contains_ip(&"2001:db8::1".parse().expect("ip")));
        let u = v4.union(&v6);
        assert_eq!(u.prefixes().len(), 2);
        assert!(u.contains_ip(&"2001:db8::1".parse().expect("ip")));
    }

    #[test]
    fn full_contient_tout() {
        let f = PrefixSet::full();
        assert!(f.contains_ip(&"192.0.2.1".parse().expect("ip")));
        assert!(f.contains_ip(&"::1".parse().expect("ip")));
        assert!(f.subtract(&f).is_empty());
    }

    #[test]
    fn sample_est_contenu() {
        let s = PrefixSet::from_net(net("10.0.10.0/24"));
        let ip = s.sample_ip().expect("non vide");
        assert!(s.contains_ip(&ip));
        assert!(PrefixSet::empty().sample_ip().is_none());
    }
}
