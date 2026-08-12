//! Parseurs des sorties FortiGate (FortiOS) — module PUR.
//!
//! - `get system status` : « clé: valeur » par lignes (hostname, version) ;
//! - `diagnose lldprx neighbor summary all` : tableau à colonnes séparées
//!   par des blancs, format observé sur FortiOS 7.x :
//!
//! ```text
//! Portname      Chassis            System-Name    Port-ID               TTL
//! ____________  _______________    ___________    __________________    ___
//! port1         00:09:0f:11:22:33  sw-coeur-01    Gi0/24                120
//! ```
//!
//! Le format exact varie d'une version de FortiOS à l'autre : le parseur
//! est prudent (une ligne de données qui n'a pas exactement 5 colonnes
//! produit un avertissement, jamais un voisin deviné) et il est testé sur
//! les transcripts enregistrés de `corpus/collect/fortigate/`.

use crate::ifname::{normalize_device_id, normalize_ifname};

use super::{Neighbor, ParsedNeighbors};

/// Ce que `get system status` apprend d'utile.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FortiStatus {
    pub hostname: Option<String>,
    pub version: Option<String>,
}

/// Parse `get system status`.
pub fn parse_system_status(output: &str) -> FortiStatus {
    let mut status = FortiStatus::default();
    for line in output.lines() {
        if let Some((key, value)) = line.split_once(':') {
            let value = value.trim();
            match key.trim() {
                "Hostname" => status.hostname = Some(value.to_owned()),
                "Version" => status.version = Some(value.to_owned()),
                _ => {}
            }
        }
    }
    status
}

/// Parse `diagnose lldprx neighbor summary all`.
pub fn parse_lldprx_summary(output: &str) -> ParsedNeighbors {
    let mut out = ParsedNeighbors::default();
    let mut in_table = false;
    for line in output.lines() {
        let t = line.trim();
        if t.is_empty() {
            continue;
        }
        let lower = t.to_ascii_lowercase();
        // L'en-tête ouvre le tableau.
        if lower.starts_with("portname") {
            in_table = true;
            continue;
        }
        if !in_table {
            continue;
        }
        // Ligne de soulignage sous l'en-tête.
        if t.chars().all(|c| c == '_' || c.is_whitespace()) {
            continue;
        }
        // L'invite (« FGT # ») ou tout autre texte ferme le tableau…
        // sauf si la ligne ressemble à une ligne de données.
        let fields: Vec<&str> = t.split_whitespace().collect();
        if fields.len() == 5 && fields[4].chars().all(|c| c.is_ascii_digit()) {
            out.neighbors.push(Neighbor {
                local_iface: normalize_ifname(fields[0]),
                remote_device: normalize_device_id(fields[2]),
                remote_iface: normalize_ifname(fields[3]),
            });
        } else if t.ends_with('#') || t.ends_with('$') {
            // Invite de shell : fin de la sortie.
            in_table = false;
        } else {
            out.warnings.push(format!(
                "ligne LLDP non comprise (attendu 5 colonnes port/chassis/système/port-distant/ttl) : « {t} »"
            ));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn statut_systeme() {
        let raw = "Version: FortiGate-60F v7.2.5,build1517,230706 (GA.F)\n\
                   Serial-Number: FGT60F0000000000\n\
                   Hostname: fw-01\n";
        let s = parse_system_status(raw);
        assert_eq!(s.hostname.as_deref(), Some("fw-01"));
        assert!(s.version.as_deref().unwrap_or("").contains("FortiGate-60F"));
    }

    #[test]
    fn ligne_non_comprise_produit_un_avertissement() {
        let raw = "Portname   Chassis   System-Name   Port-ID   TTL\n\
                   port1 00:09:0f:11:22:33 sw-01\n";
        let parsed = parse_lldprx_summary(raw);
        assert!(parsed.neighbors.is_empty());
        assert_eq!(parsed.warnings.len(), 1);
    }

    #[test]
    fn rien_avant_l_en_tete() {
        let raw = "quelque chose\nport1 a b c 120\n";
        // Pas d'en-tête « Portname » : rien n'est un voisin.
        assert_eq!(parse_lldprx_summary(raw), ParsedNeighbors::default());
    }
}
