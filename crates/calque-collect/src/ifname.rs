//! Normalisation des noms de ports et d'équipements — module PUR.
//!
//! ## Pourquoi
//!
//! Les sorties LLDP/CDP abrègent les noms d'interfaces (`Gi0/1`) alors que
//! les configurations les écrivent en long (`GigabitEthernet0/1`). Pour
//! que les liens collectés se raccordent aux interfaces du modèle, tout le
//! monde est ramené à la FORME LONGUE canonique Cisco.
//!
//! ## Règles de normalisation (documentées, testées)
//!
//! - Le préfixe alphabétique du nom (lettres et tirets) est comparé,
//!   insensiblement à la casse, à une table d'abréviations connues ; le
//!   reste (numéros, `/`, `.`, `:`) est conservé tel quel.
//!   `Gi0/1`, `gi0/1`, `GigabitEthernet0/1` → `GigabitEthernet0/1`.
//! - Un préfixe inconnu est laissé TEL QUEL (trim) — ne jamais deviner :
//!   `port1` (FortiGate) reste `port1`.
//! - Les noms d'équipements : CDP rend souvent un FQDN
//!   (`sw-01.exemple.local`) voire un numéro de série entre parenthèses
//!   (Nexus). On garde le premier label DNS et on retire la parenthèse :
//!   `sw-01.exemple.local` → `sw-01`, `sw-01(FOC1234X)` → `sw-01`.
//!   LLDP (System Name) rend en général déjà le nom court.

/// Table préfixe (minuscules) → forme longue canonique. Les variantes
/// observées sur le terrain (`Gi`, `Gig`, `GigE`…) pointent vers la même
/// forme longue.
const PREFIXES: &[(&str, &str)] = &[
    ("gi", "GigabitEthernet"),
    ("gig", "GigabitEthernet"),
    ("gige", "GigabitEthernet"),
    ("gigabitethernet", "GigabitEthernet"),
    ("te", "TenGigabitEthernet"),
    ("ten", "TenGigabitEthernet"),
    ("tengige", "TenGigabitEthernet"),
    ("tengigabitethernet", "TenGigabitEthernet"),
    ("twe", "TwentyFiveGigE"),
    ("twentyfivegige", "TwentyFiveGigE"),
    ("tw", "TwoGigabitEthernet"),
    ("twogigabitethernet", "TwoGigabitEthernet"),
    ("fo", "FortyGigabitEthernet"),
    ("fortygigabitethernet", "FortyGigabitEthernet"),
    ("hu", "HundredGigE"),
    ("hundredgige", "HundredGigE"),
    ("fa", "FastEthernet"),
    ("fastethernet", "FastEthernet"),
    ("et", "Ethernet"),
    ("eth", "Ethernet"),
    ("ethernet", "Ethernet"),
    ("po", "Port-channel"),
    ("port-channel", "Port-channel"),
    ("lo", "Loopback"),
    ("loopback", "Loopback"),
    ("vl", "Vlan"),
    ("vlan", "Vlan"),
    ("se", "Serial"),
    ("serial", "Serial"),
    ("tu", "Tunnel"),
    ("tunnel", "Tunnel"),
    ("mgmt", "Management"),
    ("management", "Management"),
];

/// Normalise un nom d'interface vers la forme longue canonique (voir la
/// documentation du module). Un nom non reconnu est rendu tel quel (trim).
pub fn normalize_ifname(raw: &str) -> String {
    let raw = raw.trim();
    // Le préfixe alphabétique : lettres et tirets, jusqu'au premier
    // caractère qui n'en est pas un (chiffre, « / », « . », « : »).
    let split = raw
        .char_indices()
        .find(|(_, c)| !c.is_ascii_alphabetic() && *c != '-')
        .map(|(i, _)| i)
        .unwrap_or(raw.len());
    let (prefix, rest) = raw.split_at(split);
    if prefix.is_empty() {
        return raw.to_owned();
    }
    let lower = prefix.to_ascii_lowercase();
    match PREFIXES.iter().find(|(abbr, _)| **abbr == lower) {
        Some((_, canonical)) => format!("{canonical}{rest}"),
        None => raw.to_owned(),
    }
}

/// Normalise un identifiant d'équipement vu par LLDP/CDP (voir la
/// documentation du module) : coupe la parenthèse (numéro de série Nexus)
/// puis garde le premier label DNS. Rendu tel quel (trim) sinon.
pub fn normalize_device_id(raw: &str) -> String {
    let raw = raw.trim();
    let no_paren = match raw.find('(') {
        Some(i) => raw[..i].trim_end(),
        None => raw,
    };
    let first_label = no_paren.split('.').next().unwrap_or(no_paren).trim();
    if first_label.is_empty() {
        no_paren.to_owned()
    } else {
        first_label.to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn abreviations_cisco_vers_forme_longue() {
        assert_eq!(normalize_ifname("Gi0/1"), "GigabitEthernet0/1");
        assert_eq!(normalize_ifname("gi0/1"), "GigabitEthernet0/1");
        assert_eq!(normalize_ifname("GigabitEthernet0/1"), "GigabitEthernet0/1");
        assert_eq!(normalize_ifname("Te1/0/48"), "TenGigabitEthernet1/0/48");
        assert_eq!(normalize_ifname("Twe1/0/1"), "TwentyFiveGigE1/0/1");
        assert_eq!(normalize_ifname("Tw1/0/1"), "TwoGigabitEthernet1/0/1");
        assert_eq!(normalize_ifname("Fa0/24"), "FastEthernet0/24");
        assert_eq!(normalize_ifname("Po10"), "Port-channel10");
        assert_eq!(normalize_ifname("Port-channel10"), "Port-channel10");
        assert_eq!(normalize_ifname("Vl100"), "Vlan100");
        assert_eq!(normalize_ifname("Lo0"), "Loopback0");
        assert_eq!(normalize_ifname("Eth1/1"), "Ethernet1/1");
        assert_eq!(normalize_ifname("mgmt0"), "Management0");
    }

    #[test]
    fn prefixe_inconnu_rendu_tel_quel() {
        // Les noms FortiGate ne sont PAS des abréviations Cisco.
        assert_eq!(normalize_ifname("port1"), "port1");
        assert_eq!(normalize_ifname("wan1"), "wan1");
        assert_eq!(normalize_ifname("internal"), "internal");
        assert_eq!(normalize_ifname("  x1  "), "x1");
        assert_eq!(normalize_ifname(""), "");
    }

    #[test]
    fn identifiants_d_equipements() {
        assert_eq!(normalize_device_id("sw-01.exemple.local"), "sw-01");
        assert_eq!(normalize_device_id("sw-01(FOC1234X56Y)"), "sw-01");
        assert_eq!(normalize_device_id("sw-01"), "sw-01");
        assert_eq!(normalize_device_id("  fw-01  "), "fw-01");
        // Cas dégénéré : rien avant le point → rendu tel quel, sans supposer.
        assert_eq!(normalize_device_id(".local"), ".local");
    }
}
