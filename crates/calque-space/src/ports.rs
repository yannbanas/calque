//! `PortRanges` — un ensemble de ports (0..=65535) représenté par des
//! intervalles inclusifs.
//!
//! Invariant : la liste est NORMALISÉE — intervalles valides, triés,
//! disjoints, et fusionnés dès qu'ils se chevauchent ou se touchent
//! (fin + 1 == début suivant). Cette forme est canonique, l'égalité
//! dérivée est donc ensembliste.

use calque_model::PortRange;
use serde::{Deserialize, Serialize};

/// Ensemble d'intervalles de ports inclusifs, normalisé.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct PortRanges {
    ranges: Vec<PortRange>,
}

/// Normalise : filtre les intervalles invalides, trie, fusionne les
/// chevauchants et les adjacents. Les calculs de bord passent par u32
/// pour éviter le débordement à 65535.
fn normalize(mut v: Vec<PortRange>) -> Vec<PortRange> {
    v.retain(|r| r.start <= r.end);
    v.sort();
    let mut out: Vec<PortRange> = Vec::with_capacity(v.len());
    for r in v {
        if let Some(last) = out.last_mut() {
            if u32::from(r.start) <= u32::from(last.end) + 1 {
                last.end = last.end.max(r.end);
                continue;
            }
        }
        out.push(r);
    }
    out
}

impl PortRanges {
    /// Tous les ports (0..=65535).
    pub fn full() -> Self {
        Self {
            ranges: vec![PortRange::ANY],
        }
    }

    pub fn empty() -> Self {
        Self { ranges: Vec::new() }
    }

    pub fn single(port: u16) -> Self {
        Self {
            ranges: vec![PortRange::single(port)],
        }
    }

    pub fn from_range(range: PortRange) -> Self {
        Self::from_ranges([range])
    }

    pub fn from_ranges(ranges: impl IntoIterator<Item = PortRange>) -> Self {
        Self {
            ranges: normalize(ranges.into_iter().collect()),
        }
    }

    /// Les intervalles, sous forme normalisée.
    pub fn ranges(&self) -> &[PortRange] {
        &self.ranges
    }

    pub fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }

    pub fn intersect(&self, other: &Self) -> Self {
        let mut out = Vec::new();
        for a in &self.ranges {
            for b in &other.ranges {
                let start = a.start.max(b.start);
                let end = a.end.min(b.end);
                if start <= end {
                    out.push(PortRange { start, end });
                }
            }
        }
        Self::from_ranges(out)
    }

    pub fn union(&self, other: &Self) -> Self {
        let mut all = self.ranges.clone();
        all.extend_from_slice(&other.ranges);
        Self::from_ranges(all)
    }

    /// `self \ other` : chaque intervalle de `self` est raboté par chaque
    /// intervalle de `other`, en gardant les morceaux à gauche et à droite.
    pub fn subtract(&self, other: &Self) -> Self {
        let mut work = self.ranges.clone();
        for b in &other.ranges {
            let mut next = Vec::with_capacity(work.len() + 1);
            for r in &work {
                if r.end < b.start || r.start > b.end {
                    // Disjoints : rien à raboter.
                    next.push(*r);
                    continue;
                }
                if r.start < b.start {
                    // r.start < b.start implique b.start >= 1.
                    next.push(PortRange {
                        start: r.start,
                        end: b.start - 1,
                    });
                }
                if r.end > b.end {
                    // r.end > b.end implique b.end <= 65534.
                    next.push(PortRange {
                        start: b.end + 1,
                        end: r.end,
                    });
                }
            }
            work = next;
        }
        Self::from_ranges(work)
    }

    /// Inclusion ensembliste : `other ⊆ self`.
    pub fn contains_set(&self, other: &Self) -> bool {
        other.subtract(self).is_empty()
    }

    pub fn contains_port(&self, port: u16) -> bool {
        self.ranges.iter().any(|r| r.contains(port))
    }

    /// Le plus petit port de l'ensemble.
    pub fn sample_port(&self) -> Option<u16> {
        self.ranges.first().map(|r| r.start)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pr(start: u16, end: u16) -> PortRange {
        PortRange { start, end }
    }

    #[test]
    fn normalisation_fusionne_chevauchants_et_adjacents() {
        let s = PortRanges::from_ranges([pr(10, 20), pr(15, 30), pr(31, 40), pr(50, 60)]);
        assert_eq!(s.ranges(), &[pr(10, 40), pr(50, 60)]);
    }

    #[test]
    fn soustraction_au_milieu() {
        let a = PortRanges::from_range(pr(0, 100));
        let b = PortRanges::from_range(pr(40, 60));
        let d = a.subtract(&b);
        assert_eq!(d.ranges(), &[pr(0, 39), pr(61, 100)]);
        assert!(d.intersect(&b).is_empty());
        assert_eq!(d.union(&b), a);
    }

    #[test]
    fn bornes_extremes() {
        let full = PortRanges::full();
        assert!(full.contains_port(0) && full.contains_port(65535));
        let d = full.subtract(&PortRanges::single(0));
        assert_eq!(d.ranges(), &[pr(1, 65535)]);
        let d = full.subtract(&PortRanges::single(65535));
        assert_eq!(d.ranges(), &[pr(0, 65534)]);
        assert!(full.subtract(&full).is_empty());
    }

    #[test]
    fn sample_est_contenu() {
        let s = PortRanges::from_range(pr(443, 445));
        assert_eq!(s.sample_port(), Some(443));
        assert!(PortRanges::empty().sample_port().is_none());
    }
}
