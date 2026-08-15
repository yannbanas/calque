//! calque-policy — les tests de flux : la suite de tests du réseau.
//!
//! Crate PUR (règle §1 de CALQUE-ARCHITECTURE.md) : aucune entrée-sortie.
//! La lecture du fichier `flows.yaml` vit dans `calque-cli` ; ce crate ne
//! fait que désérialiser et valider le contenu.
//!
//! Le format du fichier de flux est celui du §10.1, volontairement minimal :
//!
//! ```yaml
//! flows:
//!   - name: la comptabilité accède au serveur de fichiers
//!     from: 10.0.10.0/24
//!     to:   10.0.20.5
//!     port: 445/tcp
//!     expect: allow
//! ```
//!
//! `from` et `to` acceptent une adresse IP, un préfixe CIDR, ou un nom
//! symbolique (`vlan-invite`, `groupe:commutateurs`). Les noms symboliques
//! sont gardés en chaîne NON RÉSOLUE dans le fichier ; leur résolution
//! contre le modèle et l'évaluation des flux (la brique de `calque test`)
//! vivent dans le module [`eval`] : [`evaluate_flow`], [`evaluate_flows`],
//! [`flow_packet`], et les types de résultat [`FlowResult`] /
//! [`FlowStatus`] (ré-exportés par `calque-report` pour compatibilité).

pub mod eval;

pub use eval::{
    evaluate_flow, evaluate_flows, flow_packet, FlowResult, FlowStatus, EPHEMERAL_SPORT,
};

use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

use ipnet::IpNet;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Le fichier de flux (§10.1)
// ---------------------------------------------------------------------------

/// Le contenu d'un `flows.yaml` : la suite de tests du réseau.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlowsFile {
    pub flows: Vec<FlowSpec>,
}

/// Un flux déclaré : « depuis X vers Y sur le port P, on attend allow/deny ».
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FlowSpec {
    pub name: String,
    pub from: EndpointSpec,
    pub to: EndpointSpec,
    pub port: PortSpec,
    pub expect: Expectation,
}

impl FlowSpec {
    /// Libellé court du flux, pour les rapports :
    /// `10.0.10.0/24 → 10.0.20.5:445/tcp`.
    pub fn flow_label(&self) -> String {
        format!("{} → {}:{}", self.from, self.to, self.port)
    }
}

// ---------------------------------------------------------------------------
// Extrémités : IP, CIDR, ou nom symbolique non résolu
// ---------------------------------------------------------------------------

/// Une extrémité de flux telle qu'écrite dans le fichier.
///
/// Le parsing ne peut pas échouer : ce qui n'est ni une adresse IP ni un
/// préfixe CIDR est gardé tel quel comme nom symbolique (`vlan-admin`,
/// `groupe:commutateurs`), à résoudre plus tard contre le modèle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(from = "String", into = "String")]
pub enum EndpointSpec {
    /// Une adresse précise : `10.0.20.5`.
    Ip(IpAddr),
    /// Un préfixe : `10.0.10.0/24`.
    Net(IpNet),
    /// Un nom symbolique non résolu : `vlan-invite`, `groupe:commutateurs`.
    Symbolic(String),
}

impl EndpointSpec {
    pub fn is_symbolic(&self) -> bool {
        matches!(self, EndpointSpec::Symbolic(_))
    }

    /// Une adresse concrète représentative de l'extrémité, si elle en a une.
    ///
    /// Pour un préfixe, c'est l'adresse du réseau (suffisante pour un test
    /// concret de version 1 ; le mode symbolique couvrira tout le préfixe).
    /// `None` pour un nom symbolique non résolu.
    pub fn sample_ip(&self) -> Option<IpAddr> {
        match self {
            EndpointSpec::Ip(ip) => Some(*ip),
            EndpointSpec::Net(net) => Some(net.addr()),
            EndpointSpec::Symbolic(_) => None,
        }
    }
}

impl From<String> for EndpointSpec {
    fn from(s: String) -> Self {
        let t = s.trim();
        if let Ok(ip) = t.parse::<IpAddr>() {
            EndpointSpec::Ip(ip)
        } else if let Ok(net) = t.parse::<IpNet>() {
            EndpointSpec::Net(net)
        } else {
            EndpointSpec::Symbolic(t.to_owned())
        }
    }
}

impl From<EndpointSpec> for String {
    fn from(e: EndpointSpec) -> Self {
        e.to_string()
    }
}

impl fmt::Display for EndpointSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EndpointSpec::Ip(ip) => write!(f, "{ip}"),
            EndpointSpec::Net(net) => write!(f, "{net}"),
            EndpointSpec::Symbolic(s) => f.write_str(s),
        }
    }
}

// ---------------------------------------------------------------------------
// Port : `445/tcp` ou `any`
// ---------------------------------------------------------------------------

/// Protocoles gérés dans un fichier de flux.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Proto {
    Tcp,
    Udp,
    /// Pour ICMP/ICMPv6, le « port » d'un flux dénote le TYPE ICMP
    /// (convention de `ConcretePacket` : `dport` = type). Ex. `8/icmp` =
    /// echo request (ping).
    Icmp,
    Icmp6,
}

impl Proto {
    /// Le numéro de protocole IP (6 = tcp, 17 = udp, 1 = icmp, 58 = icmpv6).
    pub fn number(self) -> u8 {
        match self {
            Proto::Tcp => 6,
            Proto::Udp => 17,
            Proto::Icmp => 1,
            Proto::Icmp6 => 58,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Proto::Tcp => "tcp",
            Proto::Udp => "udp",
            Proto::Icmp => "icmp",
            Proto::Icmp6 => "icmp6",
        }
    }
}

impl fmt::Display for Proto {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Le champ `port` d'un flux : `445/tcp`, `22/tcp`, ou `any`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub enum PortSpec {
    /// Tous les ports, tous les protocoles.
    Any,
    /// Un port de destination précis sur un protocole précis.
    One { port: u16, proto: Proto },
}

/// Erreur de parsing d'un champ `port`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PortSpecError {
    #[error("format de port invalide : « {0} » (attendu « PORT/PROTO », par exemple « 445/tcp », ou « any »)")]
    BadFormat(String),
    #[error("numéro de port invalide : « {0} » (attendu un entier entre 0 et 65535)")]
    BadPort(String),
    #[error("protocole inconnu : « {0} » (protocoles gérés : tcp, udp, icmp, icmp6)")]
    UnknownProto(String),
}

impl FromStr for PortSpec {
    type Err = PortSpecError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let t = s.trim();
        if t.eq_ignore_ascii_case("any") {
            return Ok(PortSpec::Any);
        }
        let Some((port_part, proto_part)) = t.split_once('/') else {
            return Err(PortSpecError::BadFormat(t.to_owned()));
        };
        let port: u16 = port_part
            .trim()
            .parse()
            .map_err(|_| PortSpecError::BadPort(port_part.trim().to_owned()))?;
        let proto = match proto_part.trim().to_ascii_lowercase().as_str() {
            "tcp" => Proto::Tcp,
            "udp" => Proto::Udp,
            "icmp" => Proto::Icmp,
            "icmp6" | "icmpv6" => Proto::Icmp6,
            other => return Err(PortSpecError::UnknownProto(other.to_owned())),
        };
        Ok(PortSpec::One { port, proto })
    }
}

impl TryFrom<String> for PortSpec {
    type Error = PortSpecError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        s.parse()
    }
}

impl From<PortSpec> for String {
    fn from(p: PortSpec) -> Self {
        p.to_string()
    }
}

impl fmt::Display for PortSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PortSpec::Any => f.write_str("any"),
            PortSpec::One { port, proto } => write!(f, "{port}/{proto}"),
        }
    }
}

// ---------------------------------------------------------------------------
// Attente
// ---------------------------------------------------------------------------

/// Ce que le flux est censé faire : passer ou être bloqué.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Expectation {
    Allow,
    Deny,
}

impl Expectation {
    pub fn as_str(self) -> &'static str {
        match self {
            Expectation::Allow => "allow",
            Expectation::Deny => "deny",
        }
    }
}

impl fmt::Display for Expectation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Le fichier de flux EXACT du §10.1 de CALQUE-ARCHITECTURE.md.
    const FLOWS_10_1: &str = r#"flows:
  - name: la comptabilité accède au serveur de fichiers
    from: 10.0.10.0/24
    to:   10.0.20.5
    port: 445/tcp
    expect: allow

  - name: le wifi invité est isolé de l'administration
    from: vlan-invite
    to:   vlan-admin
    port: any
    expect: deny

  - name: la supervision joint tous les commutateurs
    from: 10.0.99.10
    to:   groupe:commutateurs
    port: 22/tcp
    expect: allow
"#;

    #[test]
    fn deserialise_le_fichier_de_flux_du_md() {
        let f: FlowsFile = serde_yaml::from_str(FLOWS_10_1).expect("flows.yaml du §10.1");
        assert_eq!(f.flows.len(), 3);

        let a = &f.flows[0];
        assert_eq!(a.name, "la comptabilité accède au serveur de fichiers");
        assert_eq!(a.from, EndpointSpec::Net("10.0.10.0/24".parse().unwrap()));
        assert_eq!(a.to, EndpointSpec::Ip("10.0.20.5".parse().unwrap()));
        assert_eq!(
            a.port,
            PortSpec::One {
                port: 445,
                proto: Proto::Tcp
            }
        );
        assert_eq!(a.expect, Expectation::Allow);

        let b = &f.flows[1];
        assert_eq!(b.from, EndpointSpec::Symbolic("vlan-invite".into()));
        assert_eq!(b.to, EndpointSpec::Symbolic("vlan-admin".into()));
        assert_eq!(b.port, PortSpec::Any);
        assert_eq!(b.expect, Expectation::Deny);

        let c = &f.flows[2];
        assert_eq!(c.from, EndpointSpec::Ip("10.0.99.10".parse().unwrap()));
        // Le nom symbolique est gardé en chaîne NON résolue.
        assert_eq!(c.to, EndpointSpec::Symbolic("groupe:commutateurs".into()));
        assert_eq!(
            c.port,
            PortSpec::One {
                port: 22,
                proto: Proto::Tcp
            }
        );
    }

    #[test]
    fn erreur_sur_protocole_inconnu() {
        let yaml = r#"flows:
  - name: mauvais protocole
    from: 10.0.0.1
    to: 10.0.0.2
    port: 445/xyz
    expect: allow
"#;
        let err = serde_yaml::from_str::<FlowsFile>(yaml).unwrap_err();
        assert!(
            err.to_string().contains("protocole inconnu"),
            "message inattendu : {err}"
        );
    }

    #[test]
    fn erreurs_de_port_from_str() {
        assert_eq!("any".parse::<PortSpec>(), Ok(PortSpec::Any));
        assert_eq!(
            "445/tcp".parse::<PortSpec>(),
            Ok(PortSpec::One {
                port: 445,
                proto: Proto::Tcp
            })
        );
        assert!(matches!(
            "445/xyz".parse::<PortSpec>(),
            Err(PortSpecError::UnknownProto(p)) if p == "xyz"
        ));
        assert!(matches!(
            "445".parse::<PortSpec>(),
            Err(PortSpecError::BadFormat(_))
        ));
        assert!(matches!(
            "99999/tcp".parse::<PortSpec>(),
            Err(PortSpecError::BadPort(_))
        ));
    }

    #[test]
    fn libelle_de_flux() {
        let f: FlowsFile = serde_yaml::from_str(FLOWS_10_1).unwrap();
        assert_eq!(f.flows[0].flow_label(), "10.0.10.0/24 → 10.0.20.5:445/tcp");
        assert_eq!(f.flows[1].flow_label(), "vlan-invite → vlan-admin:any");
    }
}
