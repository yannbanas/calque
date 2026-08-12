//! Adaptateur Cisco IOS / IOS-XE — couche 2, la sémantique (§6.2, §6.4,
//! jalon S5 : le test de qualité de la représentation intermédiaire).
//!
//! ## Choix de modélisation documentés
//!
//! - **Zones.** IOS n'a pas de zones (le pare-feu zonal ZBF n'est pas
//!   géré) : le filtrage est une ACL accrochée PAR INTERFACE et PAR
//!   DIRECTION (`ip access-group NOM in|out`). Même convention que
//!   l'adaptateur FortiGate : chaque interface portant au moins une ACL
//!   reçoit une zone IMPLICITE de son propre nom, contenant cette seule
//!   interface. Une liaison `in` produit des règles
//!   `from = zone(interface)` ; une liaison `out` des règles
//!   `to = zone(interface)`.
//!
//! - **Accrochage.** `in` → `Pipeline::ingress`, `out` →
//!   `Pipeline::egress` — c'est exactement la séquence de traitement du
//!   modèle (§3.1). Une politique par liaison, nommée comme l'ACL ; si
//!   la même ACL est accrochée plusieurs fois, les liaisons suivantes
//!   sont matérialisées sous `NOM@interface:direction`, avec une note
//!   (le champ `from`/`to` d'une règle ne porte qu'une zone).
//!
//! - **Action par défaut.** Toute ACL Cisco se termine par un `deny`
//!   implicite : `default_action = Deny`. Comportement documenté du
//!   produit, pas une supposition.
//!
//! - **Masques génériques (wildcard).** Les ACL utilisent le COMPLÉMENT
//!   d'un masque de sous-réseau (`0.0.0.255` = /24) — piège classique.
//!   Un wildcard non contigu (légal chez Cisco) n'est pas représentable
//!   en préfixe : diagnostic + `Fidelity::Partial`, jamais deviné.
//!
//! - **Identité des règles.** Chaque entrée d'ACL devient une `Rule`
//!   avec son numéro de séquence IOS s'il est écrit, sinon son index
//!   (base 1) dans l'ACL, et le `SourceSpan` exact de sa ligne.
//!
//! - **Routes statiques.** `ip route [vrf NOM] P M (IP|IFACE|Null0)
//!   [DISTANCE]` ; la distance administrative devient la métrique
//!   (1 par défaut), `Null0` devient `NextHop::Drop`. La forme
//!   `interface + passerelle` (deux prochains sauts dans le modèle) est
//!   diagnostiquée, pas approximée.
//!
//! - **NAT.** `ip nat inside|outside` et `ip nat ... source ...` ne
//!   sont PAS modélisés : diagnostic Warning explicite + Partial —
//!   ignorer une traduction d'adresse en silence fausserait tous les
//!   verdicts en aval.
//!
//! - **Routage dynamique** (`router ospf|bgp|eigrp...`) : les routes
//!   apprises ne sont pas dans le fichier → diagnostic + Partial.
//!
//! - **Directives ignorables.** La liste EXPLICITE des directives sans
//!   effet sur le filtrage/routage du trafic transitant (version,
//!   service, ntp, logging, snmp-server, line, banner, spanning-tree,
//!   clock, aaa, crypto pki, license…) vit dans `convert.rs`
//!   (constantes `*_IGNORABLE`). Les secrets (`enable secret`,
//!   `username`) produisent une note Info « secret présent, non
//!   modélisé ». Tout le reste est diagnostiqué (§6.3) : jamais
//!   d'ignorance silencieuse, jamais de supposition.

mod convert;
mod values;

use calque_model::{Diagnostic, SourceSpan, Vendor};

use crate::{AdapterOutput, Confidence, ConfigTree, VendorAdapter};

/// Préfixes de noms d'interfaces caractéristiques d'IOS / IOS-XE.
const IFACE_PREFIXES: &[&str] = &[
    "GigabitEthernet",
    "FastEthernet",
    "TenGigabitEthernet",
    "TwentyFiveGigE",
    "FortyGigabitEthernet",
    "HundredGigE",
    "Ethernet",
    "Vlan",
    "Loopback",
    "Serial",
    "Port-channel",
    "Tunnel",
];

/// L'adaptateur Cisco IOS / IOS-XE (format texte à indentation).
#[derive(Debug, Default, Clone, Copy)]
pub struct CiscoIosAdapter;

impl CiscoIosAdapter {
    /// Commodité : analyse le texte brut avec le tokenizer Cisco IOS de
    /// `calque-parse` (couche 1) puis convertit en IR. `file` est le nom
    /// rapporté dans tous les `SourceSpan`.
    ///
    /// Une erreur de syntaxe de la couche 1 devient un `Diagnostic`
    /// d'erreur portant le fichier et la ligne fautive.
    pub fn import_str(&self, raw: &str, file: &str) -> Result<AdapterOutput, Vec<Diagnostic>> {
        let tree = calque_parse::cisco_ios::parse(raw, file).map_err(|e| {
            vec![Diagnostic::error(
                e.to_string(),
                Some(SourceSpan::new(e.file(), e.line())),
            )]
        })?;
        self.to_ir(&tree)
    }
}

impl VendorAdapter for CiscoIosAdapter {
    fn label(&self) -> &'static str {
        "Cisco IOS"
    }

    fn import_str(&self, raw: &str, file: &str) -> Result<AdapterOutput, Vec<Diagnostic>> {
        CiscoIosAdapter::import_str(self, raw, file)
    }

    fn vendor(&self) -> Vendor {
        Vendor::CiscoIos
    }

    /// Reconnaissance par motifs caractéristiques d'IOS : `version
    /// 15/16/17`, interfaces nommées (`GigabitEthernet…`, `Vlan…`),
    /// `ip access-list`, `hostname`, séparateurs `!` structurels,
    /// `ip route`. Les motifs structurels FortiGate (`#config-version=`,
    /// blocs `edit`/`next`) plafonnent le score : un fichier FortiOS ne
    /// doit jamais être pris pour de l'IOS.
    fn detect(&self, raw: &str) -> Confidence {
        let mut version = false;
        let mut iface = false;
        let mut acl = false;
        let mut host = false;
        let mut bang = false;
        let mut route = false;
        for line in raw.lines() {
            let t = line.trim();
            if t == "!" {
                bang = true;
            } else if t.starts_with("version 15")
                || t.starts_with("version 16")
                || t.starts_with("version 17")
            {
                version = true;
            } else if let Some(rest) = t.strip_prefix("interface ") {
                if IFACE_PREFIXES.iter().any(|p| rest.starts_with(p)) {
                    iface = true;
                }
            } else if t.starts_with("ip access-list ") {
                acl = true;
            } else if t.starts_with("hostname ") {
                host = true;
            } else if t.starts_with("ip route ") {
                route = true;
            }
        }
        let mut score: u32 = 0;
        if version {
            score += 25;
        }
        if iface {
            score += 30;
        }
        if acl {
            score += 15;
        }
        if host {
            score += 15;
        }
        if bang {
            score += 10;
        }
        if route {
            score += 5;
        }
        // Anti-motifs : la structure FortiOS.
        let fortigate_like = raw.contains("#config-version=")
            || (raw.lines().any(|l| l.trim() == "next")
                && raw.lines().any(|l| l.trim_start().starts_with("edit ")));
        if fortigate_like {
            score = score.min(30);
        }
        Confidence::new(score.min(100) as u8)
    }

    fn to_ir(&self, tree: &ConfigTree) -> Result<AdapterOutput, Vec<Diagnostic>> {
        convert::convert(tree)
    }
}
