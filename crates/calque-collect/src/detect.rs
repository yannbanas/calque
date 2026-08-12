//! Détection du constructeur à partir des sorties de sondes — module PUR.
//!
//! La collecte automatique (`--vendor auto`) envoie d'abord les commandes
//! d'identification des profils (`get system status`, `show version`) et
//! classe la sortie ici. Ne jamais deviner (§6.3) : une sortie qui ne
//! porte aucune signature nette rend `None`, et l'appelant demande à
//! l'utilisateur de préciser `--vendor`.

use calque_model::Vendor;

/// Classe la sortie de `get system status` (FortiGate).
pub fn classify_fortigate_status(output: &str) -> Option<Vendor> {
    let looks_forti = output.contains("FortiGate")
        || output.contains("FortiOS")
        || (output.contains("Version:") && output.contains("Forti"));
    looks_forti.then_some(Vendor::Fortigate)
}

/// Classe la sortie de `show version` (Cisco IOS / IOS-XE).
pub fn classify_show_version(output: &str) -> Option<Vendor> {
    let looks_ios = output.contains("Cisco IOS Software")
        || output.contains("Cisco IOS XE Software")
        || output.contains("Cisco Internetwork Operating System");
    looks_ios.then_some(Vendor::CiscoIos)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fortigate_reconnu() {
        let out = "Version: FortiGate-60F v7.2.5,build1517,230706 (GA.F)\nHostname: fw-01\n";
        assert_eq!(classify_fortigate_status(out), Some(Vendor::Fortigate));
    }

    #[test]
    fn cisco_reconnu() {
        let out = "Cisco IOS Software, C2960X Software (C2960X-UNIVERSALK9-M), Version 15.2(7)E7\n";
        assert_eq!(classify_show_version(out), Some(Vendor::CiscoIos));
    }

    #[test]
    fn sortie_inconnue_jamais_devinee() {
        assert_eq!(classify_fortigate_status("command not found"), None);
        assert_eq!(classify_show_version("% Invalid input"), None);
        // Une erreur Cisco sur `get system status` ne fait pas un FortiGate.
        assert_eq!(classify_fortigate_status("% Unknown command"), None);
    }
}
