//! Analyse des valeurs nftables : adresses et préfixes, plages de ports,
//! protocoles, priorités de chaîne. Fonctions pures, sans panique : toute
//! valeur inanalysable rend `None` (et la couche appelante produit un
//! `Diagnostic`, jamais une supposition — §6.3).

use std::net::IpAddr;

use calque_model::PortRange;
use ipnet::IpNet;

/// Famille d'adresses d'une table nftables.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Family {
    /// `table ip` — IPv4 seulement.
    V4,
    /// `table ip6` — IPv6 seulement.
    V6,
    /// `table inet` — IPv4 et IPv6.
    Both,
}

impl Family {
    /// La famille accepte-t-elle ce préfixe ?
    pub(super) fn accepts(self, net: &IpNet) -> bool {
        match self {
            Family::V4 => matches!(net, IpNet::V4(_)),
            Family::V6 => matches!(net, IpNet::V6(_)),
            Family::Both => true,
        }
    }
}

/// `10.20.30.0/24`, `10.20.42.7` (→ /32) ou `2001:db8::1` (→ /128).
/// Rend `None` pour tout le reste (plages `a-b`, noms, négations…).
pub(super) fn parse_net(token: &str) -> Option<IpNet> {
    if token.contains('/') {
        return token.parse::<IpNet>().ok();
    }
    let addr: IpAddr = token.parse().ok()?;
    // Préfixe hôte : /32 ou /128 selon la version. Les longueurs sont
    // valides par construction, mais on ne panique jamais (§11.3).
    IpNet::new(addr, if addr.is_ipv4() { 32 } else { 128 }).ok()
}

/// `445` ou `8080-8090` → `PortRange`. Rend `None` si un nombre est
/// invalide ou si la borne basse dépasse la borne haute.
pub(super) fn parse_port_range(token: &str) -> Option<PortRange> {
    match token.split_once('-') {
        Some((a, b)) => {
            let start: u16 = a.trim().parse().ok()?;
            let end: u16 = b.trim().parse().ok()?;
            (start <= end).then_some(PortRange { start, end })
        }
        None => {
            let p: u16 = token.trim().parse().ok()?;
            Some(PortRange::single(p))
        }
    }
}

/// Un protocole de couche 4 : nom nftables usuel ou numéro. On ne devine
/// pas les noms inconnus.
pub(super) fn parse_proto(token: &str) -> Option<u8> {
    match token {
        "tcp" => Some(6),
        "udp" => Some(17),
        "udplite" => Some(136),
        "icmp" => Some(1),
        "icmpv6" | "ipv6-icmp" => Some(58),
        "esp" => Some(50),
        "ah" => Some(51),
        "gre" => Some(47),
        "sctp" => Some(132),
        "igmp" => Some(2),
        "dccp" => Some(33),
        other => other.parse::<u8>().ok(),
    }
}

/// Priorité d'une chaîne de base : entier (éventuellement négatif) ou nom
/// standard nftables.
pub(super) fn parse_priority(token: &str) -> Option<i64> {
    match token {
        "raw" => Some(-300),
        "mangle" => Some(-150),
        "dstnat" => Some(-100),
        "filter" => Some(0),
        "security" => Some(50),
        "srcnat" => Some(100),
        "out" => Some(0),
        other => other.parse::<i64>().ok(),
    }
}

/// États de suivi de connexion reconnus (`ct state …`).
pub(super) fn is_ct_state(token: &str) -> bool {
    matches!(
        token,
        "new" | "established" | "related" | "invalid" | "untracked"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefixes_et_hotes() {
        assert_eq!(
            parse_net("10.20.30.0/24").map(|n| n.to_string()),
            Some("10.20.30.0/24".to_owned())
        );
        assert_eq!(
            parse_net("10.20.42.7").map(|n| n.to_string()),
            Some("10.20.42.7/32".to_owned())
        );
        assert_eq!(
            parse_net("2001:db8::1").map(|n| n.to_string()),
            Some("2001:db8::1/128".to_owned())
        );
        assert_eq!(parse_net("10.0.0.1-10.0.0.9"), None);
        assert_eq!(parse_net("pas-une-ip"), None);
        assert_eq!(parse_net("10.0.0.0/33"), None);
    }

    #[test]
    fn familles() {
        let v4 = parse_net("10.0.0.0/8").expect("v4");
        let v6 = parse_net("2001:db8::/32").expect("v6");
        assert!(Family::V4.accepts(&v4) && !Family::V4.accepts(&v6));
        assert!(!Family::V6.accepts(&v4) && Family::V6.accepts(&v6));
        assert!(Family::Both.accepts(&v4) && Family::Both.accepts(&v6));
    }

    #[test]
    fn plages_de_ports() {
        assert_eq!(parse_port_range("443"), Some(PortRange::single(443)));
        assert_eq!(
            parse_port_range("8080-8090"),
            Some(PortRange {
                start: 8080,
                end: 8090
            })
        );
        assert_eq!(parse_port_range("90-80"), None);
        assert_eq!(parse_port_range("70000"), None);
        assert_eq!(parse_port_range("ssh"), None); // nom de service : on ne devine pas
    }

    #[test]
    fn protocoles() {
        assert_eq!(parse_proto("tcp"), Some(6));
        assert_eq!(parse_proto("udp"), Some(17));
        assert_eq!(parse_proto("icmp"), Some(1));
        assert_eq!(parse_proto("ipv6-icmp"), Some(58));
        assert_eq!(parse_proto("47"), Some(47));
        assert_eq!(parse_proto("ospf"), None);
    }

    #[test]
    fn priorites() {
        assert_eq!(parse_priority("0"), Some(0));
        assert_eq!(parse_priority("-300"), Some(-300));
        assert_eq!(parse_priority("filter"), Some(0));
        assert_eq!(parse_priority("raw"), Some(-300));
        assert_eq!(parse_priority("plus-tard"), None);
    }

    #[test]
    fn etats_ct() {
        assert!(is_ct_state("new") && is_ct_state("established"));
        assert!(!is_ct_state("assured"));
    }
}
