//! Analyse des valeurs OPNsense/pfSense : adresses, préfixes, ports,
//! protocoles. Fonctions pures, sans panique : toute valeur inanalysable
//! rend `None` (et la couche appelante produit un `Diagnostic`, jamais
//! une supposition — §6.3).

use std::net::IpAddr;

use calque_model::PortRange;
use ipnet::IpNet;

/// Adresse d'interface : `("10.10.1.1", Some("24"))` → `10.10.1.1/24`
/// (bits d'hôte CONSERVÉS : pour une interface, l'adresse compte autant
/// que le réseau). Sans `<subnet>`, l'adresse seule devient un /32 (ou
/// /128 en IPv6), fidèle au comportement du produit.
pub fn iface_addr(ipaddr: &str, subnet: Option<&str>) -> Option<IpNet> {
    let addr: IpAddr = ipaddr.parse().ok()?;
    let max = if addr.is_ipv4() { 32 } else { 128 };
    let prefix: u8 = match subnet {
        Some(s) => s.parse().ok()?,
        None => max,
    };
    IpNet::new(addr, prefix).ok()
}

/// Un réseau tel qu'écrit dans une règle ou un alias : forme CIDR
/// (`10.0.0.0/24`) ou adresse nue (`10.0.0.7` → /32). Les bits d'hôte
/// d'un réseau sont normalisés.
pub fn parse_net(s: &str) -> Option<IpNet> {
    if s.contains('/') {
        return s.parse::<IpNet>().ok().map(|n| n.trunc());
    }
    let addr: IpAddr = s.parse().ok()?;
    let max = if addr.is_ipv4() { 32 } else { 128 };
    IpNet::new(addr, max).ok()
}

/// Une adresse d'hôte STRICTE (pour un alias de type `host`) : jamais de
/// CIDR — un réseau dans un alias d'hôtes serait une divergence, pas une
/// tolérance.
pub fn parse_host(s: &str) -> Option<IpNet> {
    if s.contains('/') {
        return None;
    }
    parse_net(s)
}

/// Un port ou une plage : `443`, `8000-8010`, ou `8000:8010` (le fichier
/// écrit `-`, la syntaxe pf écrit `:` — les deux formes circulent).
/// Rend `None` si les bornes sont inversées ou invalides.
pub fn parse_port_spec(s: &str) -> Option<PortRange> {
    let (a, b) = match s.split_once('-').or_else(|| s.split_once(':')) {
        Some((a, b)) => (a, b),
        None => {
            let p: u16 = s.trim().parse().ok()?;
            return Some(PortRange::single(p));
        }
    };
    let start: u16 = a.trim().parse().ok()?;
    let end: u16 = b.trim().parse().ok()?;
    (start <= end).then_some(PortRange { start, end })
}

/// Nom de protocole pfSense/OPNsense → numéros de protocole IP.
/// `tcp/udp` couvre DEUX protocoles, d'où le vecteur. Rend `None` pour
/// un nom inconnu : on ne devine pas.
pub fn proto_numbers(name: &str) -> Option<Vec<u8>> {
    match name.to_ascii_lowercase().as_str() {
        "tcp" => Some(vec![6]),
        "udp" => Some(vec![17]),
        "tcp/udp" => Some(vec![6, 17]),
        "icmp" => Some(vec![1]),
        "igmp" => Some(vec![2]),
        "gre" => Some(vec![47]),
        "esp" => Some(vec![50]),
        "ah" => Some(vec![51]),
        "ospf" => Some(vec![89]),
        "carp" => Some(vec![112]),
        "pfsync" => Some(vec![240]),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adresses_d_interface() {
        assert_eq!(
            iface_addr("10.10.1.1", Some("24")).unwrap().to_string(),
            "10.10.1.1/24"
        );
        assert_eq!(
            iface_addr("10.10.1.1", None).unwrap().to_string(),
            "10.10.1.1/32"
        );
        assert_eq!(iface_addr("dhcp", Some("24")), None);
        assert_eq!(iface_addr("10.10.1.1", Some("33")), None);
        assert_eq!(
            iface_addr("fd00::1", Some("64")).unwrap().to_string(),
            "fd00::1/64"
        );
    }

    #[test]
    fn reseaux_et_hotes() {
        assert_eq!(
            parse_net("10.30.0.0/16").unwrap().to_string(),
            "10.30.0.0/16"
        );
        // Bits d'hôte normalisés pour un réseau.
        assert_eq!(
            parse_net("10.30.1.2/16").unwrap().to_string(),
            "10.30.0.0/16"
        );
        assert_eq!(parse_net("10.0.0.7").unwrap().to_string(), "10.0.0.7/32");
        assert_eq!(parse_net("pas-une-ip"), None);

        assert_eq!(parse_host("10.0.0.7").unwrap().to_string(), "10.0.0.7/32");
        // Un CIDR n'est PAS un hôte.
        assert_eq!(parse_host("10.0.0.0/24"), None);
    }

    #[test]
    fn ports() {
        assert_eq!(parse_port_spec("443"), Some(PortRange::single(443)));
        assert_eq!(
            parse_port_spec("8000-8010"),
            Some(PortRange {
                start: 8000,
                end: 8010
            })
        );
        assert_eq!(
            parse_port_spec("8000:8010"),
            Some(PortRange {
                start: 8000,
                end: 8010
            })
        );
        assert_eq!(parse_port_spec("70000"), None);
        assert_eq!(parse_port_spec("10-5"), None);
        assert_eq!(parse_port_spec("https"), None);
    }

    #[test]
    fn protocoles() {
        assert_eq!(proto_numbers("tcp"), Some(vec![6]));
        assert_eq!(proto_numbers("TCP/UDP"), Some(vec![6, 17]));
        assert_eq!(proto_numbers("carp"), Some(vec![112]));
        assert_eq!(proto_numbers("quantique"), None);
    }
}
