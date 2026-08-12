//! Parseurs des sorties Cisco IOS — module PUR.
//!
//! Deux formats, tous deux « clé: valeur » par blocs :
//!
//! - `show lldp neighbors detail` : blocs séparés par des lignes de
//!   tirets, clés `Local Intf:`, `Port id:`, `System Name:` ;
//! - `show cdp neighbors detail` : blocs séparés par des lignes de
//!   tirets, clés `Device ID:` et la ligne double
//!   `Interface: X,  Port ID (outgoing port): Y`.
//!
//! Un bloc incomplet (port local sans port distant, etc.) produit un
//! AVERTISSEMENT, jamais un voisin deviné (§6.3).

use crate::ifname::{normalize_device_id, normalize_ifname};

use super::{Neighbor, ParsedNeighbors};

/// La valeur après `clé:` si la ligne commence par cette clé
/// (insensiblement à la casse).
fn value_after<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let trimmed = line.trim_start();
    if trimmed.len() >= key.len() && trimmed[..key.len()].eq_ignore_ascii_case(key) {
        Some(trimmed[key.len()..].trim())
    } else {
        None
    }
}

/// Une ligne de séparation de blocs (tirets).
fn is_separator(line: &str) -> bool {
    let t = line.trim();
    t.len() >= 4 && t.chars().all(|c| c == '-')
}

#[derive(Default)]
struct LldpBlock {
    local: Option<String>,
    chassis: Option<String>,
    port_id: Option<String>,
    system_name: Option<String>,
    saw_data: bool,
}

impl LldpBlock {
    /// Clôt le bloc : un voisin s'il est complet, un avertissement sinon.
    fn finish(self, out: &mut ParsedNeighbors) {
        if !self.saw_data {
            return;
        }
        // Le nom système peut manquer (équipement muet) : repli documenté
        // sur le chassis id, gardé TEL QUEL (une adresse MAC n'est pas un
        // FQDN : la normalisation de nom ne s'y applique pas), jamais sur
        // une valeur inventée.
        let remote = match self.system_name.filter(|s| !s.is_empty()) {
            Some(name) => Some(normalize_device_id(&name)),
            None => self.chassis.map(|c| c.trim().to_owned()),
        };
        match (self.local, self.port_id, remote) {
            (Some(local), Some(port), Some(device)) => out.neighbors.push(Neighbor {
                local_iface: normalize_ifname(&local),
                remote_device: device,
                remote_iface: normalize_ifname(&port),
            }),
            (local, port, device) => out.warnings.push(format!(
                "bloc LLDP incomplet ignoré (Local Intf: {}, Port id: {}, voisin: {})",
                local.as_deref().unwrap_or("?"),
                port.as_deref().unwrap_or("?"),
                device.as_deref().unwrap_or("?"),
            )),
        }
    }
}

/// Parse `show lldp neighbors detail`.
pub fn parse_lldp_neighbors_detail(output: &str) -> ParsedNeighbors {
    let mut out = ParsedNeighbors::default();
    let mut block = LldpBlock::default();
    for line in output.lines() {
        if is_separator(line) {
            std::mem::take(&mut block).finish(&mut out);
            continue;
        }
        if let Some(v) = value_after(line, "Local Intf:") {
            // Un nouveau `Local Intf` sans séparateur clôt aussi le bloc.
            if block.local.is_some() {
                std::mem::take(&mut block).finish(&mut out);
            }
            block.local = Some(v.to_owned());
            block.saw_data = true;
        } else if let Some(v) = value_after(line, "Chassis id:") {
            block.chassis = Some(v.to_owned());
            block.saw_data = true;
        } else if let Some(v) = value_after(line, "Port id:") {
            block.port_id = Some(v.to_owned());
            block.saw_data = true;
        } else if let Some(v) = value_after(line, "System Name:") {
            // IOS affiche `System Name: - ` quand le voisin n'en annonce pas.
            let v = v.trim_matches('-').trim();
            block.system_name = Some(v.to_owned());
            block.saw_data = true;
        }
    }
    block.finish(&mut out);
    out
}

#[derive(Default)]
struct CdpBlock {
    device: Option<String>,
    local: Option<String>,
    port_id: Option<String>,
    saw_data: bool,
}

impl CdpBlock {
    fn finish(self, out: &mut ParsedNeighbors) {
        if !self.saw_data {
            return;
        }
        match (self.local, self.port_id, self.device) {
            (Some(local), Some(port), Some(device)) => out.neighbors.push(Neighbor {
                local_iface: normalize_ifname(&local),
                remote_device: normalize_device_id(&device),
                remote_iface: normalize_ifname(&port),
            }),
            (local, port, device) => out.warnings.push(format!(
                "bloc CDP incomplet ignoré (Device ID: {}, Interface: {}, Port ID: {})",
                device.as_deref().unwrap_or("?"),
                local.as_deref().unwrap_or("?"),
                port.as_deref().unwrap_or("?"),
            )),
        }
    }
}

/// Parse `show cdp neighbors detail`.
pub fn parse_cdp_neighbors_detail(output: &str) -> ParsedNeighbors {
    let mut out = ParsedNeighbors::default();
    let mut block = CdpBlock::default();
    for line in output.lines() {
        if is_separator(line) {
            std::mem::take(&mut block).finish(&mut out);
            continue;
        }
        if let Some(v) = value_after(line, "Device ID:") {
            if block.device.is_some() {
                std::mem::take(&mut block).finish(&mut out);
            }
            block.device = Some(v.to_owned());
            block.saw_data = true;
        } else if let Some(rest) = value_after(line, "Interface:") {
            // `Interface: GigabitEthernet0/1,  Port ID (outgoing port): Gi0/24`
            block.saw_data = true;
            match rest.split_once(',') {
                Some((iface, tail)) => {
                    block.local = Some(iface.trim().to_owned());
                    if let Some(v) = value_after(tail, "Port ID (outgoing port):") {
                        block.port_id = Some(v.to_owned());
                    }
                }
                None => block.local = Some(rest.trim().to_owned()),
            }
        }
    }
    block.finish(&mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bloc_lldp_incomplet_produit_un_avertissement() {
        let raw = "Local Intf: Gi0/1\nTime remaining: 90 seconds\n";
        let parsed = parse_lldp_neighbors_detail(raw);
        assert!(parsed.neighbors.is_empty());
        assert_eq!(parsed.warnings.len(), 1);
        assert!(
            parsed.warnings[0].contains("Gi0/1"),
            "{:?}",
            parsed.warnings
        );
    }

    #[test]
    fn system_name_absent_replie_sur_chassis_id() {
        let raw = "Local Intf: Gi0/1\nChassis id: 0011.2233.4455\nPort id: 24\nSystem Name: - \n";
        let parsed = parse_lldp_neighbors_detail(raw);
        assert_eq!(parsed.neighbors.len(), 1);
        // Le chassis id (une MAC) est gardé tel quel, PAS traité en FQDN.
        assert_eq!(parsed.neighbors[0].remote_device, "0011.2233.4455");
    }

    #[test]
    fn sortie_vide() {
        assert_eq!(parse_lldp_neighbors_detail(""), ParsedNeighbors::default());
        assert_eq!(parse_cdp_neighbors_detail(""), ParsedNeighbors::default());
    }
}
