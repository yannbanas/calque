//! Analyse des valeurs FortiGate : adresses + masques, plages d'adresses,
//! plages de ports. Fonctions pures, sans panique : toute valeur
//! inanalysable rend `None` (et la couche appelante produit un
//! `Diagnostic`, jamais une supposition — §6.3).

use std::net::Ipv4Addr;

use calque_model::PortRange;
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

/// `("10.0.0.1", "255.255.255.0")` → `10.0.0.1/24` (bits d'hôte
/// CONSERVÉS : pour une interface, l'adresse compte autant que le
/// réseau). Accepte aussi la forme CIDR directe en premier argument
/// (`"10.0.0.0/24"`, masque ignoré).
pub fn ip_mask_to_net(ip: &str, mask: Option<&str>) -> Option<IpNet> {
    if ip.contains('/') {
        return ip.parse::<IpNet>().ok();
    }
    let addr: Ipv4Addr = ip.parse().ok()?;
    let mask: Ipv4Addr = mask?.parse().ok()?;
    let prefix = mask_to_prefix(mask)?;
    Ipv4Net::new(addr, prefix).ok().map(IpNet::V4)
}

/// Décompose une plage d'adresses IPv4 inclusive en la plus petite liste
/// de préfixes CIDR la couvrant EXACTEMENT (l'« iprange » FortiGate).
/// Rend une liste vide si `start > end`.
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

/// Un jeton de `tcp-portrange`/`udp-portrange` FortiGate :
/// `443`, `8000-8010`, ou `dstrange:srcrange` (`443:1024-65535`).
/// Rend `(destination, source)` ; la source vaut `PortRange::ANY` si
/// elle n'est pas précisée.
pub fn parse_port_token(token: &str) -> Option<(PortRange, PortRange)> {
    let (dst_part, src_part) = match token.split_once(':') {
        Some((d, s)) => (d, Some(s)),
        None => (token, None),
    };
    let dst = parse_range(dst_part)?;
    let src = match src_part {
        Some(s) => parse_range(s)?,
        None => PortRange::ANY,
    };
    Some((dst, src))
}

/// Une adresse IPv4 seule (`10.0.0.1`) ou une plage `a-b`
/// (`10.0.0.1-10.0.0.5`, forme des `extip`/`mappedip` FortiGate) →
/// `(début, fin)` inclusif ; une adresse seule rend `(a, a)`. Rend `None`
/// si une borne est invalide ou si la plage est inversée.
pub fn parse_ip_span(s: &str) -> Option<(Ipv4Addr, Ipv4Addr)> {
    match s.split_once('-') {
        Some((a, b)) => {
            let start: Ipv4Addr = a.trim().parse().ok()?;
            let end: Ipv4Addr = b.trim().parse().ok()?;
            (u32::from(start) <= u32::from(end)).then_some((start, end))
        }
        None => {
            let addr: Ipv4Addr = s.trim().parse().ok()?;
            Some((addr, addr))
        }
    }
}

/// Un port seul (`443`) ou une plage `a-b` (`8000-8010`, forme des
/// `extport`/`mappedport` FortiGate) → `(début, fin)` inclusif ; un port
/// seul rend `(p, p)`. Rend `None` si un nombre est invalide ou si la
/// plage est inversée.
pub fn parse_port_span(s: &str) -> Option<(u16, u16)> {
    let range = parse_range(s)?;
    Some((range.start, range.end))
}

/// `445` ou `8000-8010` → `PortRange`. Rend `None` si la borne basse
/// dépasse la borne haute ou si un nombre est invalide.
fn parse_range(s: &str) -> Option<PortRange> {
    match s.split_once('-') {
        Some((a, b)) => {
            let start: u16 = a.trim().parse().ok()?;
            let end: u16 = b.trim().parse().ok()?;
            (start <= end).then_some(PortRange { start, end })
        }
        None => {
            let p: u16 = s.trim().parse().ok()?;
            Some(PortRange::single(p))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn masques() {
        assert_eq!(mask_to_prefix("255.255.255.0".parse().unwrap()), Some(24));
        assert_eq!(mask_to_prefix("255.255.255.255".parse().unwrap()), Some(32));
        assert_eq!(mask_to_prefix("0.0.0.0".parse().unwrap()), Some(0));
        assert_eq!(mask_to_prefix("255.255.255.252".parse().unwrap()), Some(30));
        // Masque non contigu : on ne devine pas.
        assert_eq!(mask_to_prefix("255.0.255.0".parse().unwrap()), None);
    }

    #[test]
    fn ip_masque_conserve_l_hote() {
        let net = ip_mask_to_net("10.10.1.1", Some("255.255.255.0")).unwrap();
        assert_eq!(net.to_string(), "10.10.1.1/24");
        let cidr = ip_mask_to_net("10.10.2.0/24", None).unwrap();
        assert_eq!(cidr.to_string(), "10.10.2.0/24");
        assert_eq!(ip_mask_to_net("10.0.0.1", Some("255.0.255.0")), None);
        assert_eq!(ip_mask_to_net("pas-une-ip", Some("255.0.0.0")), None);
    }

    #[test]
    fn plage_vers_prefixes_exacts() {
        // 10.10.1.50..=10.10.1.69 → 5 préfixes exacts.
        let nets = range_to_nets("10.10.1.50".parse().unwrap(), "10.10.1.69".parse().unwrap());
        let texte: Vec<String> = nets.iter().map(|n| n.to_string()).collect();
        assert_eq!(
            texte,
            vec![
                "10.10.1.50/31",
                "10.10.1.52/30",
                "10.10.1.56/29",
                "10.10.1.64/30",
                "10.10.1.68/31",
            ]
        );

        // Une plage alignée donne un préfixe unique.
        let nets = range_to_nets("10.0.0.0".parse().unwrap(), "10.0.0.255".parse().unwrap());
        assert_eq!(nets.len(), 1);
        assert_eq!(nets[0].to_string(), "10.0.0.0/24");

        // Une adresse seule.
        let nets = range_to_nets("10.0.0.7".parse().unwrap(), "10.0.0.7".parse().unwrap());
        assert_eq!(nets[0].to_string(), "10.0.0.7/32");

        // Bornes inversées : vide, pas de panique.
        assert!(range_to_nets("10.0.0.9".parse().unwrap(), "10.0.0.1".parse().unwrap()).is_empty());

        // L'espace entier, sans débordement.
        let nets = range_to_nets(
            "0.0.0.0".parse().unwrap(),
            "255.255.255.255".parse().unwrap(),
        );
        assert_eq!(nets.len(), 1);
        assert_eq!(nets[0].to_string(), "0.0.0.0/0");
    }

    #[test]
    fn adresses_seules_et_plages() {
        let un = "10.0.0.7".parse::<Ipv4Addr>().unwrap();
        assert_eq!(parse_ip_span("10.0.0.7"), Some((un, un)));
        assert_eq!(
            parse_ip_span("10.0.0.1-10.0.0.5"),
            Some(("10.0.0.1".parse().unwrap(), "10.0.0.5".parse().unwrap()))
        );
        // Plage inversée, borne invalide : on ne devine pas.
        assert_eq!(parse_ip_span("10.0.0.9-10.0.0.1"), None);
        assert_eq!(parse_ip_span("10.0.0.999"), None);
        assert_eq!(parse_ip_span(""), None);
    }

    #[test]
    fn ports_seuls_et_plages() {
        assert_eq!(parse_port_span("443"), Some((443, 443)));
        assert_eq!(parse_port_span("8000-8010"), Some((8000, 8010)));
        assert_eq!(parse_port_span("10-5"), None);
        assert_eq!(parse_port_span("70000"), None);
        assert_eq!(parse_port_span("abc"), None);
    }

    #[test]
    fn plages_de_ports() {
        assert_eq!(
            parse_port_token("8443"),
            Some((PortRange::single(8443), PortRange::ANY))
        );
        assert_eq!(
            parse_port_token("8000-8010"),
            Some((
                PortRange {
                    start: 8000,
                    end: 8010
                },
                PortRange::ANY
            ))
        );
        // Forme dstrange:srcrange.
        assert_eq!(
            parse_port_token("7000-7010:1024-65535"),
            Some((
                PortRange {
                    start: 7000,
                    end: 7010
                },
                PortRange {
                    start: 1024,
                    end: 65535
                }
            ))
        );
        assert_eq!(parse_port_token("70000"), None); // > 65535
        assert_eq!(parse_port_token("10-5"), None); // bornes inversées
        assert_eq!(parse_port_token("abc"), None);
    }
}
