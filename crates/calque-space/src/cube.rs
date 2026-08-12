//! `Cube` — un pavé dans l'espace d'en-têtes à cinq dimensions
//! (src, dst, proto, sport, dport).
//!
//! Les dimensions sont indépendantes : l'intersection est composante par
//! composante (§4.2). La soustraction, elle, ne reste pas un pavé — c'est
//! la découpe classique d'un hyper-rectangle, dimension par dimension.

use calque_model::{ConcretePacket, PortRange};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};

use crate::ports::PortRanges;
use crate::prefix::PrefixSet;
use crate::proto::ProtoSet;

/// Un pavé : le produit cartésien de cinq ensembles, un par dimension.
/// Il est vide dès qu'une dimension est vide.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Cube {
    pub src: PrefixSet,
    pub dst: PrefixSet,
    pub proto: ProtoSet,
    pub sport: PortRanges,
    pub dport: PortRanges,
}

impl Cube {
    pub fn new(
        src: PrefixSet,
        dst: PrefixSet,
        proto: ProtoSet,
        sport: PortRanges,
        dport: PortRanges,
    ) -> Self {
        Self {
            src,
            dst,
            proto,
            sport,
            dport,
        }
    }

    /// L'espace entier.
    pub fn full() -> Self {
        Self {
            src: PrefixSet::full(),
            dst: PrefixSet::full(),
            proto: ProtoSet::full(),
            sport: PortRanges::full(),
            dport: PortRanges::full(),
        }
    }

    /// Constructeur pratique pour un flux : source, destination, protocole
    /// et port de destination ; le port source reste quelconque.
    pub fn from_flow(src: IpNet, dst: IpNet, proto: u8, dport: PortRange) -> Self {
        Self {
            src: PrefixSet::from_net(src),
            dst: PrefixSet::from_net(dst),
            proto: ProtoSet::single(proto),
            sport: PortRanges::full(),
            dport: PortRanges::from_range(dport),
        }
    }

    /// Un produit cartésien est vide dès qu'un facteur est vide.
    pub fn is_empty(&self) -> bool {
        self.src.is_empty()
            || self.dst.is_empty()
            || self.proto.is_empty()
            || self.sport.is_empty()
            || self.dport.is_empty()
    }

    /// Intersection composante par composante.
    pub fn intersect(&self, other: &Self) -> Self {
        Self {
            src: self.src.intersect(&other.src),
            dst: self.dst.intersect(&other.dst),
            proto: self.proto.intersect(&other.proto),
            sport: self.sport.intersect(&other.sport),
            dport: self.dport.intersect(&other.dport),
        }
    }

    /// Inclusion de pavés : `other ⊆ self` ssi chaque dimension de `other`
    /// est incluse dans celle de `self` (vrai aussi si `other` est vide).
    pub fn contains_cube(&self, other: &Self) -> bool {
        other.is_empty()
            || (self.src.contains_set(&other.src)
                && self.dst.contains_set(&other.dst)
                && self.proto.contains_set(&other.proto)
                && self.sport.contains_set(&other.sport)
                && self.dport.contains_set(&other.dport))
    }

    /// Vrai si les deux pavés n'ont aucun paquet en commun : il suffit
    /// qu'UNE dimension soit disjointe (produit cartésien). Test direct,
    /// sans allocation.
    pub fn is_disjoint(&self, other: &Self) -> bool {
        self.src.is_disjoint(&other.src)
            || self.dst.is_disjoint(&other.dst)
            || self.proto.intersect(&other.proto).is_empty()
            || self.sport.is_disjoint(&other.sport)
            || self.dport.is_disjoint(&other.dport)
    }

    /// `self \ other`, en pavés disjoints.
    ///
    /// Découpe dimension par dimension : à chaque étape, la part de `rest`
    /// qui sort de `other` sur la dimension courante forme un pavé du
    /// résultat, puis `rest` est resserré sur `other` pour cette dimension.
    /// Ce qui reste à la fin est inclus dans `other` et disparaît.
    /// Produit au plus un pavé par dimension (cinq ici), car chaque
    /// dimension est un ensemble fermé par soustraction.
    pub fn subtract(&self, other: &Self) -> Vec<Cube> {
        if self.is_empty() {
            return Vec::new();
        }
        if other.is_empty() {
            return vec![self.clone()];
        }
        let mut out: Vec<Cube> = Vec::with_capacity(5);
        let mut rest = self.clone();

        // src
        let outside = rest.src.subtract(&other.src);
        if !outside.is_empty() {
            let mut piece = rest.clone();
            piece.src = outside;
            out.push(piece);
        }
        rest.src = rest.src.intersect(&other.src);
        if rest.src.is_empty() {
            return out;
        }

        // dst
        let outside = rest.dst.subtract(&other.dst);
        if !outside.is_empty() {
            let mut piece = rest.clone();
            piece.dst = outside;
            out.push(piece);
        }
        rest.dst = rest.dst.intersect(&other.dst);
        if rest.dst.is_empty() {
            return out;
        }

        // proto
        let outside = rest.proto.subtract(&other.proto);
        if !outside.is_empty() {
            let mut piece = rest.clone();
            piece.proto = outside;
            out.push(piece);
        }
        rest.proto = rest.proto.intersect(&other.proto);
        if rest.proto.is_empty() {
            return out;
        }

        // sport
        let outside = rest.sport.subtract(&other.sport);
        if !outside.is_empty() {
            let mut piece = rest.clone();
            piece.sport = outside;
            out.push(piece);
        }
        rest.sport = rest.sport.intersect(&other.sport);
        if rest.sport.is_empty() {
            return out;
        }

        // dport
        let outside = rest.dport.subtract(&other.dport);
        if !outside.is_empty() {
            let mut piece = rest.clone();
            piece.dport = outside;
            out.push(piece);
        }
        // Le reste est désormais inclus dans `other` : il est soustrait.
        out
    }

    /// Tente une fusion EXACTE de deux pavés :
    /// - absorption si l'un contient l'autre ;
    /// - fusion sur une dimension si les quatre autres sont identiques
    ///   (les représentations des dimensions étant canoniques, l'égalité
    ///   structurelle est bien l'égalité ensembliste) :
    ///   (S1 × R) ∪ (S2 × R) = (S1 ∪ S2) × R.
    pub fn try_merge(&self, other: &Self) -> Option<Cube> {
        if self.contains_cube(other) {
            return Some(self.clone());
        }
        if other.contains_cube(self) {
            return Some(other.clone());
        }
        let d_src = self.src != other.src;
        let d_dst = self.dst != other.dst;
        let d_proto = self.proto != other.proto;
        let d_sport = self.sport != other.sport;
        let d_dport = self.dport != other.dport;
        let differing = u8::from(d_src)
            + u8::from(d_dst)
            + u8::from(d_proto)
            + u8::from(d_sport)
            + u8::from(d_dport);
        if differing != 1 {
            return None;
        }
        let mut merged = self.clone();
        if d_src {
            merged.src = self.src.union(&other.src);
        } else if d_dst {
            merged.dst = self.dst.union(&other.dst);
        } else if d_proto {
            merged.proto = self.proto.union(&other.proto);
        } else if d_sport {
            merged.sport = self.sport.union(&other.sport);
        } else {
            merged.dport = self.dport.union(&other.dport);
        }
        Some(merged)
    }

    /// Appartenance d'un paquet concret : toutes les dimensions à la fois.
    pub fn contains(&self, pkt: &ConcretePacket) -> bool {
        self.src.contains_ip(&pkt.src)
            && self.dst.contains_ip(&pkt.dst)
            && self.proto.contains_proto(pkt.proto)
            && self.sport.contains_port(pkt.sport)
            && self.dport.contains_port(pkt.dport)
    }

    /// Un paquet représentatif : un échantillon par dimension.
    pub fn sample(&self) -> Option<ConcretePacket> {
        Some(ConcretePacket {
            src: self.src.sample_ip()?,
            dst: self.dst.sample_ip()?,
            proto: self.proto.sample_proto()?,
            sport: self.sport.sample_port()?,
            dport: self.dport.sample_port()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn net(s: &str) -> IpNet {
        s.parse().expect("préfixe de test valide")
    }

    /// Le pavé de l'exemple §2 : une règle de pare-feu réelle.
    fn regle_445() -> Cube {
        Cube::from_flow(
            net("10.0.10.0/24"),
            net("10.0.20.5/32"),
            6,
            PortRange::single(445),
        )
    }

    #[test]
    fn contains_et_sample() {
        let c = regle_445();
        let p = c.sample().expect("pavé non vide");
        assert!(c.contains(&p));
        assert_eq!(p.proto, 6);
        assert_eq!(p.dport, 445);
        assert_eq!(p.dst, "10.0.20.5".parse::<std::net::IpAddr>().expect("ip"));
    }

    #[test]
    fn soustraction_exacte() {
        let full = Cube::full();
        let b = regle_445();
        let pieces = full.subtract(&b);
        // Une pièce par dimension resserrée (sport reste plein) : 4.
        assert_eq!(pieces.len(), 4);
        // Aucune pièce ne rencontre b, et chaque pièce est dans full.
        for p in &pieces {
            assert!(p.intersect(&b).is_empty());
            assert!(full.contains_cube(p));
        }
        // Le paquet type de b n'est dans aucune pièce.
        let pkt = b.sample().expect("non vide");
        assert!(pieces.iter().all(|p| !p.contains(&pkt)));
    }

    #[test]
    fn soustraction_disjointe_rend_le_pave() {
        let a = regle_445();
        let b = Cube::from_flow(
            net("192.168.0.0/16"),
            net("10.0.20.5/32"),
            6,
            PortRange::single(445),
        );
        assert_eq!(a.subtract(&b), vec![a.clone()]);
    }

    #[test]
    fn fusion_sur_une_dimension() {
        let a = Cube::from_flow(
            net("10.0.10.0/24"),
            net("10.0.20.5/32"),
            6,
            PortRange::single(445),
        );
        let b = Cube::from_flow(
            net("10.0.11.0/24"),
            net("10.0.20.5/32"),
            6,
            PortRange::single(445),
        );
        let m = a.try_merge(&b).expect("fusionnable");
        assert_eq!(m.src, PrefixSet::from_net(net("10.0.10.0/23")));
        // Deux dimensions différentes : pas de fusion.
        let c = Cube::from_flow(
            net("10.0.11.0/24"),
            net("10.0.20.6/32"),
            6,
            PortRange::single(445),
        );
        assert!(a.try_merge(&c).is_none());
    }
}
