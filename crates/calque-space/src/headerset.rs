//! `HeaderSet` — une union normalisée de pavés disjoints (§4.2).
//!
//! Invariants après chaque opération :
//! - aucun pavé vide ;
//! - pavés deux à deux disjoints (maintenu par construction : l'union est
//!   calculée comme A ∪ (B \ A)) ;
//! - fusion des pavés fusionnables (absorption, ou une seule dimension
//!   différente) jusqu'au point fixe, puis tri.
//!
//! La forme obtenue n'est PAS canonique (une union de pavés n'a pas de
//! forme minimale unique) : `Eq` est structurel. L'égalité ensembliste se
//! teste par inclusion mutuelle avec [`HeaderSet::contains_set`].

use calque_model::{ConcretePacket, PortRange};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};

use crate::cube::Cube;
use crate::HeaderSpace;

/// Union normalisée de pavés disjoints.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeaderSet {
    cubes: Vec<Cube>,
}

impl HeaderSet {
    /// Construit à partir d'un pavé (vide si le pavé est vide).
    pub fn from_cube(cube: Cube) -> Self {
        Self::normalized(vec![cube])
    }

    /// Construit l'union de pavés quelconques (éventuellement chevauchants) :
    /// chaque pavé est unionné à son tour, ce qui rétablit la disjonction.
    pub fn from_cubes(cubes: impl IntoIterator<Item = Cube>) -> Self {
        cubes
            .into_iter()
            .fold(Self::empty(), |acc, c| acc.union(&Self::from_cube(c)))
    }

    /// Constructeur pratique pour un flux (cf. [`Cube::from_flow`]).
    pub fn flow(src: IpNet, dst: IpNet, proto: u8, dport: PortRange) -> Self {
        Self::from_cube(Cube::from_flow(src, dst, proto, dport))
    }

    /// Les pavés, disjoints et triés.
    pub fn cubes(&self) -> &[Cube] {
        &self.cubes
    }

    /// Inclusion ensembliste : `other ⊆ self`.
    /// C'est la comparaison à utiliser pour l'égalité d'ensembles
    /// (dans les deux sens), `Eq` n'étant que structurel.
    pub fn contains_set(&self, other: &HeaderSet) -> bool {
        // Chemin rapide sans allocation : chaque pavé de `other` contenu
        // dans UN pavé de `self`. C'est SUFFISANT mais pas nécessaire
        // (un pavé peut être couvert par plusieurs pavés de `self`) :
        // en cas d'échec, on retombe sur le test exact par soustraction.
        if other
            .cubes
            .iter()
            .all(|b| self.cubes.iter().any(|a| a.contains_cube(b)))
        {
            return true;
        }
        other.subtract(self).is_empty()
    }

    /// Vrai si les deux ensembles n'ont aucun paquet en commun.
    ///
    /// Test direct, sans allocation : deux unions de pavés sont disjointes
    /// si et seulement si chaque paire de pavés est disjointe, et deux
    /// pavés sont disjoints dès qu'UNE dimension l'est.
    pub fn is_disjoint(&self, other: &HeaderSet) -> bool {
        self.cubes
            .iter()
            .all(|a| other.cubes.iter().all(|b| a.is_disjoint(b)))
    }

    /// Normalisation : suppression des pavés vides, fusions exactes
    /// jusqu'au point fixe, puis tri pour le déterminisme.
    ///
    /// Le point fixe est atteint INCRÉMENTALEMENT : chaque pavé est inséré
    /// par [`Self::insert_merged`] dans une liste maintenue sans paire
    /// fusionnable, ce qui évite de rebalayer toutes les paires après
    /// chaque fusion (l'ancien algorithme relançait un balayage complet et
    /// devenait cubique sur les grandes unions).
    ///
    /// Les fusions préservent la disjonction : l'union exacte de deux
    /// pavés disjoints du reste demeure disjointe du reste.
    ///
    /// COMPLEXITÉ ET BORNE (audit 2026-08-12, R3) : quadratique dans le
    /// nombre de pavés, sans garde interne — ce crate reste une algèbre
    /// pure et totale, il ne décide pas d'un budget. C'est à l'APPELANT de
    /// borner la fragmentation quand l'entrée est hostile : le moteur le
    /// fait (`MAX_CUBES` dans `calque-engine::symtrace`), et tout nouvel
    /// usage sur des ensembles issus d'une configuration non fiable doit
    /// faire de même.
    fn normalized(cubes: Vec<Cube>) -> Self {
        let mut out: Vec<Cube> = Vec::with_capacity(cubes.len());
        for c in cubes {
            if !c.is_empty() {
                Self::insert_merged(&mut out, c);
            }
        }
        out.sort();
        Self { cubes: out }
    }

    /// Insère `c` dans `out`, une liste SANS paire fusionnable (invariant
    /// d'entrée et de sortie), en cascadant les fusions : tant que `c`
    /// fusionne avec un élément, l'élément est retiré et le fusionné
    /// reprend sa place de candidat. Chaque cascade retire un élément de
    /// `out`, donc la boucle termine.
    fn insert_merged(out: &mut Vec<Cube>, mut c: Cube) {
        loop {
            let merged = out
                .iter()
                .enumerate()
                .find_map(|(i, existing)| existing.try_merge(&c).map(|m| (i, m)));
            match merged {
                Some((i, m)) => {
                    out.swap_remove(i);
                    c = m;
                }
                None => {
                    out.push(c);
                    return;
                }
            }
        }
    }
}

impl HeaderSpace for HeaderSet {
    fn full() -> Self {
        Self {
            cubes: vec![Cube::full()],
        }
    }

    fn empty() -> Self {
        Self { cubes: Vec::new() }
    }

    fn is_empty(&self) -> bool {
        // Invariant : aucun pavé vide, donc vide ssi aucun pavé.
        self.cubes.is_empty()
    }

    /// Intersection : distributivité sur l'union — toutes les paires,
    /// composante par composante. Deux familles disjointes donnent des
    /// intersections disjointes.
    fn intersect(&self, other: &Self) -> Self {
        let mut out = Vec::new();
        for a in &self.cubes {
            for b in &other.cubes {
                // Écarte les paires disjointes SANS construire l'intersection
                // (le test est sans allocation) : c'est le cas dominant sur
                // des ensembles peu chevauchants.
                if a.is_disjoint(b) {
                    continue;
                }
                out.push(a.intersect(b));
            }
        }
        Self::normalized(out)
    }

    /// Union disjointe : A ∪ B = A + (B \ A), ce qui maintient l'invariant
    /// de disjonction sans redécouper A.
    ///
    /// `self` étant déjà normalisé (sans paire fusionnable), seuls les
    /// morceaux de B \ A ont besoin d'être insérés avec fusion — inutile
    /// de re-normaliser A entier.
    fn union(&self, other: &Self) -> Self {
        let mut cubes = self.cubes.clone();
        for piece in other.subtract(self).cubes {
            Self::insert_merged(&mut cubes, piece);
        }
        cubes.sort();
        Self { cubes }
    }

    /// `self \ other` : chaque pavé de A est découpé successivement par
    /// chaque pavé de B (cf. [`Cube::subtract`]). Les morceaux issus de
    /// pavés disjoints restent disjoints.
    ///
    /// Deux économies mesurées sur les grands ensembles :
    /// - un pavé disjoint du soustracteur est DÉPLACÉ tel quel (aucune
    ///   copie, aucune découpe) ;
    /// - si aucun pavé n'a été découpé, le résultat est `self` inchangé,
    ///   déjà normalisé : la re-normalisation est inutile.
    fn subtract(&self, other: &Self) -> Self {
        let mut work = self.cubes.clone();
        let mut changed = false;
        for b in &other.cubes {
            if work.iter().all(|a| a.is_disjoint(b)) {
                continue;
            }
            changed = true;
            let mut next = Vec::with_capacity(work.len() + 4);
            for a in work {
                if a.is_disjoint(b) {
                    next.push(a);
                } else {
                    next.extend(a.subtract(b));
                }
            }
            work = next;
        }
        if changed {
            Self::normalized(work)
        } else {
            Self { cubes: work }
        }
    }

    fn contains(&self, pkt: &ConcretePacket) -> bool {
        self.cubes.iter().any(|c| c.contains(pkt))
    }

    fn sample(&self) -> Option<ConcretePacket> {
        self.cubes.first().and_then(Cube::sample)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn net(s: &str) -> IpNet {
        s.parse().expect("préfixe de test valide")
    }

    #[test]
    fn full_moins_regle_puis_reunion() {
        let full = HeaderSet::full();
        let b = HeaderSet::flow(
            net("10.0.10.0/24"),
            net("10.0.20.5/32"),
            6,
            PortRange::single(445),
        );
        let d = full.subtract(&b);
        assert!(d.intersect(&b).is_empty());
        // d ∪ b redonne l'espace entier (égalité ensembliste).
        let u = d.union(&b);
        assert!(u.contains_set(&full) && full.contains_set(&u));
    }

    #[test]
    fn union_de_paves_chevauchants() {
        let a = HeaderSet::flow(net("10.0.0.0/8"), net("0.0.0.0/0"), 6, PortRange::ANY);
        let b = HeaderSet::flow(net("10.0.10.0/24"), net("0.0.0.0/0"), 6, PortRange::ANY);
        // b ⊆ a : l'union doit être absorbée en a.
        let u = a.union(&b);
        assert_eq!(u, a);
        assert!(a.contains_set(&b));
        assert!(!b.contains_set(&a));
    }

    #[test]
    fn sample_donne_un_paquet_precis() {
        // §4.1 : « le flux 10.0.99.4 → 10.0.1.10:22 passe » doit être
        // illustrable par UN paquet.
        let s = HeaderSet::flow(
            net("10.0.99.4/32"),
            net("10.0.1.10/32"),
            6,
            PortRange::single(22),
        );
        let p = s.sample().expect("non vide");
        assert_eq!(p.src, "10.0.99.4".parse::<std::net::IpAddr>().expect("ip"));
        assert_eq!(p.dst, "10.0.1.10".parse::<std::net::IpAddr>().expect("ip"));
        assert_eq!((p.proto, p.dport), (6, 22));
        assert!(s.contains(&p));
    }

    #[test]
    fn vide_et_plein() {
        let e = HeaderSet::empty();
        assert!(e.is_empty());
        assert!(e.sample().is_none());
        let f = HeaderSet::full();
        assert!(!f.is_empty());
        assert!(f.contains_set(&e));
        assert!(f.subtract(&f).is_empty());
    }

    #[test]
    fn paves_disjoints_apres_operations() {
        let a = HeaderSet::flow(net("10.0.0.0/8"), net("0.0.0.0/0"), 6, PortRange::ANY);
        let b = HeaderSet::flow(net("10.0.10.0/24"), net("0.0.0.0/0"), 17, PortRange::ANY);
        let u = a.union(&b);
        for (i, x) in u.cubes().iter().enumerate() {
            for y in &u.cubes()[i + 1..] {
                assert!(x.intersect(y).is_empty(), "pavés non disjoints");
            }
        }
    }
}
