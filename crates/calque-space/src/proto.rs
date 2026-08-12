//! `ProtoSet` — un ensemble de numéros de protocole IP (0..=255).
//!
//! Représentation : un champ de 256 bits (quatre mots de 64 bits).
//! Cette forme est canonique, l'égalité dérivée est donc ensembliste.

use serde::{Deserialize, Serialize};

/// Ensemble de protocoles IP (6 = tcp, 17 = udp, 1 = icmp…).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ProtoSet {
    words: [u64; 4],
}

impl ProtoSet {
    pub fn full() -> Self {
        Self {
            words: [u64::MAX; 4],
        }
    }

    pub fn empty() -> Self {
        Self { words: [0; 4] }
    }

    pub fn single(proto: u8) -> Self {
        let mut s = Self::empty();
        s.insert(proto);
        s
    }

    pub fn from_protos(protos: impl IntoIterator<Item = u8>) -> Self {
        let mut s = Self::empty();
        for p in protos {
            s.insert(p);
        }
        s
    }

    fn insert(&mut self, proto: u8) {
        self.words[usize::from(proto) / 64] |= 1u64 << (u32::from(proto) % 64);
    }

    pub fn is_empty(&self) -> bool {
        self.words.iter().all(|w| *w == 0)
    }

    /// Nombre de protocoles dans l'ensemble.
    pub fn len(&self) -> u32 {
        self.words.iter().map(|w| w.count_ones()).sum()
    }

    /// Applique une opération bit à bit mot par mot.
    fn zip_words(&self, other: &Self, op: impl Fn(u64, u64) -> u64) -> Self {
        let mut words = [0u64; 4];
        for (w, (a, b)) in words
            .iter_mut()
            .zip(self.words.iter().zip(other.words.iter()))
        {
            *w = op(*a, *b);
        }
        Self { words }
    }

    pub fn intersect(&self, other: &Self) -> Self {
        self.zip_words(other, |a, b| a & b)
    }

    pub fn union(&self, other: &Self) -> Self {
        self.zip_words(other, |a, b| a | b)
    }

    pub fn subtract(&self, other: &Self) -> Self {
        self.zip_words(other, |a, b| a & !b)
    }

    /// Inclusion ensembliste : `other ⊆ self`.
    pub fn contains_set(&self, other: &Self) -> bool {
        other.subtract(self).is_empty()
    }

    pub fn contains_proto(&self, proto: u8) -> bool {
        self.words[usize::from(proto) / 64] & (1u64 << (u32::from(proto) % 64)) != 0
    }

    /// Le plus petit protocole de l'ensemble.
    pub fn sample_proto(&self) -> Option<u8> {
        for (i, w) in self.words.iter().enumerate() {
            if *w != 0 {
                // i <= 3 et trailing_zeros <= 63 : tient dans u8.
                return Some((i as u32 * 64 + w.trailing_zeros()) as u8);
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operations_de_base() {
        let tcp = ProtoSet::single(6);
        let udp = ProtoSet::single(17);
        let both = tcp.union(&udp);
        assert_eq!(both.len(), 2);
        assert!(both.contains_proto(6) && both.contains_proto(17));
        assert_eq!(both.subtract(&udp), tcp);
        assert!(tcp.intersect(&udp).is_empty());
        assert_eq!(both.sample_proto(), Some(6));
    }

    #[test]
    fn bornes() {
        let s = ProtoSet::from_protos([0u8, 255u8]);
        assert!(s.contains_proto(0) && s.contains_proto(255));
        assert_eq!(ProtoSet::full().len(), 256);
        assert_eq!(
            ProtoSet::full().subtract(&ProtoSet::full()),
            ProtoSet::empty()
        );
        assert_eq!(ProtoSet::empty().sample_proto(), None);
    }
}
