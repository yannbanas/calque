//! Analyse des valeurs Cisco IOS : masques de sous-réseau, masques
//! GÉNÉRIQUES (wildcard, le complément d'un masque — piège classique),
//! numéros de protocole et noms de ports connus. Fonctions pures, sans
//! panique : toute valeur inanalysable rend `None` (et la couche
//! appelante produit un `Diagnostic`, jamais une supposition — §6.3).

use std::net::Ipv4Addr;

use ipnet::{IpNet, Ipv4Net};

/// `255.255.255.0` → `Some(24)`. Rend `None` si le masque n'est pas
/// contigu (ex. `255.0.255.0`) : on ne devine pas.
pub fn mask_to_prefix(mask: Ipv4Addr) -> Option<u8> {
    let m = u32::from(mask);
    let ones = m.count_ones();
    let expected = if ones == 0 {
        0
    } else {
        u32::MAX << (32 - ones)
    };
    // Sûr : ones <= 32, donc la conversion tient toujours dans u8.
    (m == expected).then_some(ones as u8)
}

/// Masque générique d'ACL (`0.0.0.255` → `Some(24)`). C'est le
/// COMPLÉMENT d'un masque de sous-réseau, PAS un masque : `0.0.0.255`
/// équivaut à `255.255.255.0`. Un wildcard non contigu (ex. `0.0.254.255`,
/// parfaitement légal chez Cisco pour des correspondances pair/impair)
/// rend `None` : non représentable en préfixe, jamais deviné.
pub fn wildcard_to_prefix(wildcard: Ipv4Addr) -> Option<u8> {
    mask_to_prefix(Ipv4Addr::from(!u32::from(wildcard)))
}

/// `("10.0.0.1", "255.255.255.0")` → `10.0.0.1/24` (bits d'hôte
/// CONSERVÉS : pour une interface, l'adresse compte autant que le
/// réseau). Rend `None` sur adresse invalide ou masque non contigu.
pub fn ip_mask_to_net(ip: &str, mask: &str) -> Option<IpNet> {
    let addr: Ipv4Addr = ip.parse().ok()?;
    let mask: Ipv4Addr = mask.parse().ok()?;
    let prefix = mask_to_prefix(mask)?;
    Ipv4Net::new(addr, prefix).ok().map(IpNet::V4)
}

/// Adresse + masque générique d'ACL → réseau NORMALISÉ (bits d'hôte
/// tronqués : `10.20.1.7 0.0.0.255` → `10.20.1.0/24`).
pub fn ip_wildcard_to_net(ip: Ipv4Addr, wildcard: Ipv4Addr) -> Option<IpNet> {
    let prefix = wildcard_to_prefix(wildcard)?;
    Ipv4Net::new(ip, prefix).ok().map(|n| IpNet::V4(n).trunc())
}

/// `"10.0.0.7"` → `10.0.0.7/32` (la forme `host A` des ACL).
pub fn host_net(ip: &str) -> Option<IpNet> {
    let addr: Ipv4Addr = ip.parse().ok()?;
    Ipv4Net::new(addr, 32).ok().map(IpNet::V4)
}

/// Décompose une plage d'adresses IPv4 inclusive en la plus petite liste
/// de préfixes CIDR la couvrant EXACTEMENT (le membre `range` d'un
/// `object-group network`). Rend une liste vide si `start > end`.
pub fn range_to_nets(start: Ipv4Addr, end: Ipv4Addr) -> Vec<IpNet> {
    let mut out = Vec::new();
    // Arithmétique en u64 pour éviter tout débordement à 255.255.255.255.
    let mut cur = u64::from(u32::from(start));
    let end = u64::from(u32::from(end));

    while cur <= end {
        // Le plus grand bloc aligné qui commence à `cur`…
        let align_bits = if cur == 0 {
            32
        } else {
            (cur.trailing_zeros()).min(32)
        };
        // …plafonné par ce qui reste à couvrir.
        let remaining = end - cur + 1; // >= 1
        let fit_bits = 63 - remaining.leading_zeros(); // floor(log2)
        let bits = align_bits.min(fit_bits).min(32);
        let prefix = (32 - bits) as u8;

        // Sûr par construction (cur tient sur 32 bits, prefix <= 32),
        // mais on ne panique jamais : un échec improbable est ignoré.
        if let Ok(net) = Ipv4Net::new(Ipv4Addr::from(cur as u32), prefix) {
            out.push(IpNet::V4(net));
        }
        cur += 1u64 << bits;
    }
    out
}

/// Le protocole d'une entrée d'ACL étendue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AclProto {
    /// `ip` : tout protocole IP.
    Any,
    /// Un protocole précis (6 = tcp, 17 = udp, 1 = icmp…).
    Number(u8),
}

/// Le jeton protocole d'une ACL : nom IOS connu ou numéro 0..=255.
/// Rend `None` pour un nom inconnu : on ne devine pas.
pub fn acl_proto(token: &str) -> Option<AclProto> {
    if let Ok(n) = token.parse::<u8>() {
        return Some(AclProto::Number(n));
    }
    let n = match token {
        "ip" => return Some(AclProto::Any),
        "icmp" => 1,
        "igmp" => 2,
        "ipinip" => 4,
        "tcp" => 6,
        "udp" => 17,
        "gre" => 47,
        "esp" => 50,
        "ahp" => 51,
        "eigrp" => 88,
        "ospf" => 89,
        "pim" => 103,
        "sctp" => 132,
        _ => return None,
    };
    Some(AclProto::Number(n))
}

/// Un jeton de port d'ACL : numéro 0..=65535 ou nom bien connu tel
/// qu'IOS les affiche (`www`, `domain`, `bootps`…). Rend `None` pour un
/// nom inconnu : on ne devine pas un numéro de port.
pub fn port_number(token: &str) -> Option<u16> {
    if let Ok(p) = token.parse::<u16>() {
        return Some(p);
    }
    let p = match token {
        "echo" => 7,
        "discard" => 9,
        "daytime" => 13,
        "chargen" => 19,
        "ftp-data" => 20,
        "ftp" => 21,
        "ssh" => 22,
        "telnet" => 23,
        "smtp" => 25,
        "time" => 37,
        "nicname" => 43,
        "domain" => 53,
        "bootps" => 67,
        "bootpc" => 68,
        "tftp" => 69,
        "gopher" => 70,
        "finger" => 79,
        "www" => 80,
        "hostname" => 101,
        "pop2" => 109,
        "pop3" => 110,
        "sunrpc" => 111,
        "ident" => 113,
        "nntp" => 119,
        "ntp" => 123,
        "netbios-ns" => 137,
        "netbios-dgm" => 138,
        "netbios-ss" => 139,
        "snmp" => 161,
        "snmptrap" => 162,
        "bgp" => 179,
        "irc" => 194,
        "ldap" => 389,
        "https" => 443,
        "isakmp" => 500,
        "exec" => 512,
        "login" => 513,
        "cmd" => 514,
        "syslog" => 514,
        "lpd" => 515,
        "talk" => 517,
        "rip" => 520,
        "uucp" => 540,
        "klogin" => 543,
        "kshell" => 544,
        "non500-isakmp" => 4500,
        _ => return None,
    };
    Some(p)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn masques() {
        assert_eq!(mask_to_prefix("255.255.255.0".parse().unwrap()), Some(24));
        assert_eq!(mask_to_prefix("255.255.255.255".parse().unwrap()), Some(32));
        assert_eq!(mask_to_prefix("0.0.0.0".parse().unwrap()), Some(0));
        // Masque non contigu : on ne devine pas.
        assert_eq!(mask_to_prefix("255.0.255.0".parse().unwrap()), None);
    }

    #[test]
    fn masques_generiques() {
        assert_eq!(wildcard_to_prefix("0.0.0.255".parse().unwrap()), Some(24));
        assert_eq!(wildcard_to_prefix("0.0.0.0".parse().unwrap()), Some(32));
        assert_eq!(
            wildcard_to_prefix("255.255.255.255".parse().unwrap()),
            Some(0)
        );
        assert_eq!(wildcard_to_prefix("0.0.3.255".parse().unwrap()), Some(22));
        // Wildcard non contigu (correspondance pair/impair) : refusé.
        assert_eq!(wildcard_to_prefix("0.0.254.255".parse().unwrap()), None);
    }

    #[test]
    fn adresse_et_masque() {
        let net = ip_mask_to_net("10.20.1.1", "255.255.255.0").unwrap();
        assert_eq!(net.to_string(), "10.20.1.1/24"); // bits d'hôte conservés
        assert_eq!(ip_mask_to_net("10.0.0.1", "255.0.255.0"), None);
        assert_eq!(ip_mask_to_net("pas-une-ip", "255.0.0.0"), None);
    }

    #[test]
    fn adresse_et_wildcard_normalises() {
        let net =
            ip_wildcard_to_net("10.20.1.7".parse().unwrap(), "0.0.0.255".parse().unwrap()).unwrap();
        assert_eq!(net.to_string(), "10.20.1.0/24"); // bits d'hôte tronqués
        assert_eq!(
            ip_wildcard_to_net("10.0.0.0".parse().unwrap(), "0.0.254.255".parse().unwrap()),
            None
        );
    }

    #[test]
    fn plage_vers_prefixes_exacts() {
        let nets = range_to_nets("10.0.0.0".parse().unwrap(), "10.0.0.255".parse().unwrap());
        assert_eq!(nets.len(), 1);
        assert_eq!(nets[0].to_string(), "10.0.0.0/24");
        assert!(range_to_nets("10.0.0.9".parse().unwrap(), "10.0.0.1".parse().unwrap()).is_empty());
    }

    #[test]
    fn protocoles_et_ports() {
        assert_eq!(acl_proto("ip"), Some(AclProto::Any));
        assert_eq!(acl_proto("tcp"), Some(AclProto::Number(6)));
        assert_eq!(acl_proto("udp"), Some(AclProto::Number(17)));
        assert_eq!(acl_proto("icmp"), Some(AclProto::Number(1)));
        assert_eq!(acl_proto("89"), Some(AclProto::Number(89)));
        assert_eq!(acl_proto("warp-drive"), None);

        assert_eq!(port_number("445"), Some(445));
        assert_eq!(port_number("www"), Some(80));
        assert_eq!(port_number("domain"), Some(53));
        assert_eq!(port_number("70000"), None); // > 65535
        assert_eq!(port_number("teleport"), None);
    }
}
