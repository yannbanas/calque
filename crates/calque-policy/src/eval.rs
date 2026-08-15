//! L'évaluation des flux déclarés contre un modèle (§10.1).
//!
//! C'est la brique de bibliothèque derrière `calque test` : un `FlowSpec`
//! (déclaré dans `flows.yaml` ou construit par l'appelant) est résolu en
//! paquet concret représentatif, tracé par `calque-engine`, et le verdict
//! est confronté à l'attente. Aucune entrée-sortie : le modèle et les
//! flux arrivent de l'appelant — la CLI lit ses fichiers elle-même, un
//! consommateur en bibliothèque (Constat) fournit ses configurations
//! historiques.
//!
//! Propriété d'honnêteté (§6.3), intacte ici : c'est le MOTEUR qui décide de
//! la fermeté du verdict. Un chemin dont la décision dépend d'une lacune de
//! modélisation SUR le chemin (règle sur-approximée, objet externe non
//! résolu, cycle, ECMP divergent…) rend `Verdict::Unknown` → le flux est
//! compté en échec avec la raison précise, jamais deviné. Une lacune HORS du
//! chemin décisif ne dégrade plus le verdict (c'était trop conservateur : un
//! flux bien modélisé était déclaré non ferme à cause d'une directive sans
//! rapport ailleurs dans la configuration).

use std::net::IpAddr;

use calque_engine::Trace;
use calque_model::{ConcretePacket, Network, ZoneId};
use serde::{Deserialize, Serialize};

use crate::{EndpointSpec, FlowSpec, PortSpec};

/// Le port source utilisé pour construire un paquet concret quand
/// l'utilisateur n'en précise pas : un port éphémère représentatif
/// (40000, dans l'intervalle éphémère de fait de la plupart des piles).
/// Le mode symbolique couvrira tout l'intervalle ; en mode concret, un
/// paquet précis suffit et ce choix est affiché tel quel dans la trace.
pub const EPHEMERAL_SPORT: u16 = 40000;

// ---------------------------------------------------------------------------
// Résultats de tests de flux (§10.1, vocabulaire §10.2)
// ---------------------------------------------------------------------------

/// Statut d'un flux, avec le vocabulaire du §10.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FlowStatus {
    /// Le flux se comporte comme déclaré.
    Ok,
    /// ROMPU — le flux ne se comporte plus comme déclaré.
    Broken,
    /// CORRIGÉ — le flux se comporte de nouveau comme déclaré.
    Fixed,
    /// NOUVEAU — une accessibilité qu'aucun flux déclaré ne couvrait.
    New,
}

impl FlowStatus {
    /// Préfixe affiché dans la sortie texte.
    pub fn prefix(self) -> &'static str {
        match self {
            FlowStatus::Ok => "OK",
            FlowStatus::Broken => "ROMPU",
            FlowStatus::Fixed => "CORRIGÉ",
            FlowStatus::New => "NOUVEAU",
        }
    }

    /// Ce statut compte-t-il comme un échec (code de sortie non nul,
    /// `<failure>` JUnit) ? ROMPU évidemment ; NOUVEAU aussi, car une
    /// ouverture non déclarée est exactement le type d'erreur qui crée
    /// une brèche de segmentation (§10.2).
    pub fn is_failure(self) -> bool {
        matches!(self, FlowStatus::Broken | FlowStatus::New)
    }
}

impl std::fmt::Display for FlowStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.prefix())
    }
}

/// Le résultat d'un flux testé.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlowResult {
    /// Le nom déclaré dans `flows.yaml`.
    pub name: String,
    /// Libellé du flux : `10.0.10.0/24 → 10.0.20.5:445/tcp`.
    pub flow: String,
    /// Comportement attendu (`allow` / `deny`).
    pub expected: String,
    /// Comportement observé sur le modèle, si le test a pu tourner.
    pub actual: Option<String>,
    pub status: FlowStatus,
    /// Justification : la règle qui décide, ou la raison d'un échec.
    pub detail: Option<String>,
}

// ---------------------------------------------------------------------------
// Résolution des extrémités d'un flux
// ---------------------------------------------------------------------------

/// Résout une extrémité de flux en adresse concrète représentative :
/// IP telle quelle ; préfixe CIDR → première adresse hôte ; nom symbolique
/// → zone du modèle (première adresse d'hôte d'un sous-réseau d'une
/// interface membre, hors adresse de l'interface elle-même). Échec → raison
/// honnête, jamais une supposition.
fn resolve_endpoint(network: &Network, e: &EndpointSpec) -> Result<IpAddr, String> {
    match e {
        EndpointSpec::Ip(ip) => Ok(*ip),
        EndpointSpec::Net(net) => net
            .hosts()
            .next()
            .ok_or_else(|| format!("le préfixe {net} ne contient aucune adresse hôte")),
        EndpointSpec::Symbolic(name) => resolve_zone_sample(network, name),
    }
}

/// Résout un nom symbolique comme zone du modèle et rend une adresse
/// d'hôte représentative d'un sous-réseau d'une interface membre.
fn resolve_zone_sample(network: &Network, name: &str) -> Result<IpAddr, String> {
    let zone = ZoneId::new(name);
    let mut hits: Vec<(&calque_model::Device, &Vec<calque_model::IfaceId>)> = network
        .devices
        .values()
        .filter_map(|d| d.zones.get(&zone).map(|members| (d, members)))
        .collect();
    let (device, members) = match hits.len() {
        0 => return Err(format!("« {name} » ne correspond à aucune zone du modèle")),
        1 => hits.pop().expect("hits.len() == 1"),
        _ => {
            let list = hits
                .iter()
                .map(|(d, _)| format!("« {} »", d.id))
                .collect::<Vec<_>>()
                .join(", ");
            return Err(format!(
                "la zone « {name} » existe sur plusieurs équipements ({list}) : ambigu"
            ));
        }
    };
    for member in members {
        let Some(iface) = device.interfaces.get(member) else {
            continue;
        };
        for addr in &iface.addrs {
            // La première adresse d'hôte du sous-réseau qui n'est pas
            // l'adresse de l'interface : elle représente un hôte de la
            // zone, pas la passerelle.
            if let Some(host) = addr.hosts().find(|h| *h != addr.addr()) {
                return Ok(host);
            }
        }
    }
    Err(format!(
        "la zone « {name} » (équipement « {} ») n'a aucun sous-réseau exploitable",
        device.id
    ))
}

/// Construit le paquet concret représentatif d'un flux déclaré : les
/// extrémités sont résolues (voir la rustdoc du module) et `port: any`
/// devient un paquet représentatif 80/tcp — la note qui l'explique est
/// rendue avec le résultat (la couverture complète de l'intervalle relève
/// du mode symbolique).
pub fn flow_packet(
    network: &Network,
    flow: &FlowSpec,
) -> Result<(ConcretePacket, Option<String>), String> {
    let src = resolve_endpoint(network, &flow.from)?;
    let dst = resolve_endpoint(network, &flow.to)?;
    let (proto, dport, port_note) = match flow.port {
        PortSpec::One { port, proto } => (proto.number(), port, None),
        PortSpec::Any => (
            6,
            80,
            Some(
                "port « any » testé avec un paquet représentatif 80/tcp \
                 (couverture complète au mode symbolique)"
                    .to_owned(),
            ),
        ),
    };
    Ok((
        ConcretePacket {
            src,
            dst,
            proto,
            // ICMP/ICMPv6 : `dport` = type, `sport` = code (convention de
            // `ConcretePacket`) — on teste le code 0. Sinon port source
            // éphémère représentatif.
            sport: if matches!(proto, 1 | 58) {
                0
            } else {
                EPHEMERAL_SPORT
            },
            dport,
        },
        port_note,
    ))
}

// ---------------------------------------------------------------------------
// Justification du verdict
// ---------------------------------------------------------------------------

/// La justification du verdict : la dernière décision portée par une règle
/// (ou au moins par une origine de configuration), libellée comme dans les
/// traces rendues — « filtre de sortie : accepté (règle 2, fw.conf ligne 82) ».
fn deciding_rule(trace: &Trace) -> Option<String> {
    trace
        .hops
        .iter()
        .rev()
        .flat_map(|h| h.decisions.iter().rev())
        .find(|d| d.rule.is_some() || d.source.is_some())
        .map(|d| {
            let mut s = format!("{} : {}", d.stage, d.outcome);
            if let Some(rule) = &d.rule {
                s.push_str(&format!(" (règle {rule}"));
                if let Some(span) = &d.source {
                    s.push_str(&format!(", {span}"));
                }
                s.push(')');
            } else if let Some(span) = &d.source {
                s.push_str(&format!(" ({span})"));
            }
            s
        })
}

// ---------------------------------------------------------------------------
// Évaluation d'un flux
// ---------------------------------------------------------------------------

/// Évalue un flux déclaré contre le modèle. Un flux qui ne se comporte
/// pas comme déclaré — ou qu'on ne peut pas évaluer sans deviner — rend
/// un [`FlowResult`] en échec, jamais une erreur fatale.
///
/// - `network` : le modèle, PRÉPARÉ par
///   [`calque_engine::prepare_for_engine`] (idempotent : préparer un
///   modèle déjà préparé ne change rien). Un modèle non préparé ne produit
///   jamais un verdict faux — le moteur refuse honnêtement (`Unknown`)
///   d'évaluer une contrainte de zone de sortie au point d'entrée.
/// - `allow_partial` : `false` (défaut de `calque test`) rend NON FERME
///   (`Unknown`, compté en échec) tout flux dont la décision dépend d'une
///   lacune SUR le chemin — règle sur-approximée (`groups`, `internet-service`,
///   négation…) ou objet externe non résolu ; une lacune HORS du chemin
///   décisif n'a plus aucun effet. `true` (drapeau `--allow-partial`) force
///   le verdict sur la seule partie modélisée — assumé (§6.3).
///
/// # Exemple — le chemin bibliothèque complet
///
/// Du texte de configuration au verdict, sans toucher au disque :
///
/// ```
/// use calque_engine::{infer_links_from_subnets, prepare_for_engine};
/// use calque_model::Network;
/// use calque_policy::{evaluate_flow, Expectation, FlowSpec, FlowStatus};
/// use calque_vendors::detect_and_import;
///
/// // 1. Une configuration en mémoire (chez Constat : une configuration
/// //    historique signée ; ici, un FortiGate minimal).
/// let raw = r#"#config-version=FGT60F-7.0.5-FW-build0304-220328:opmode=0:vdom=0
/// config system global
///     set hostname "fw-doc"
/// end
/// config system interface
///     edit "lan"
///         set vdom "root"
///         set ip 10.0.1.1 255.255.255.0
///         set type physical
///         set role lan
///     next
///     edit "dmz"
///         set vdom "root"
///         set ip 10.0.2.1 255.255.255.0
///         set type physical
///         set role dmz
///     next
/// end
/// config firewall policy
///     edit 1
///         set name "lan-vers-dmz"
///         set srcintf "lan"
///         set dstintf "dmz"
///         set srcaddr "all"
///         set dstaddr "all"
///         set action accept
///         set schedule "always"
///         set service "ALL"
///     next
/// end
/// "#;
///
/// // 2. Détection + import (sans I/O), fidélité comprise.
/// let imported = detect_and_import(raw, "fw-doc.conf").expect("import");
/// assert!(imported.output.fidelity.is_complete());
///
/// // 3. Le modèle : équipements + topologie inférée + préparation moteur.
/// let mut network = Network::default();
/// network
///     .devices
///     .insert(imported.output.device.id.clone(), imported.output.device);
/// let inferred = infer_links_from_subnets(&network);
/// network.links.extend(inferred);
/// let network = prepare_for_engine(&network);
///
/// // 4. Un flux déclaré, évalué contre le modèle.
/// let flow = FlowSpec {
///     name: "le lan joint le serveur de la dmz".into(),
///     from: String::from("10.0.1.50").into(),
///     to: String::from("10.0.2.10").into(),
///     port: "443/tcp".parse().expect("port valide"),
///     expect: Expectation::Allow,
/// };
/// let result = evaluate_flow(&network, &flow, false);
/// assert_eq!(result.status, FlowStatus::Ok);
/// assert_eq!(result.actual.as_deref(), Some("allow"));
/// ```
pub fn evaluate_flow(network: &Network, spec: &FlowSpec, allow_partial: bool) -> FlowResult {
    let broken = |actual: Option<String>, detail: String| FlowResult {
        name: spec.name.clone(),
        flow: spec.flow_label(),
        expected: spec.expect.to_string(),
        actual,
        status: FlowStatus::Broken,
        detail: Some(detail),
    };

    // Résolution des extrémités (documentée dans l'aide de `calque test`).
    let (packet, port_note) = match flow_packet(network, spec) {
        Ok(x) => x,
        Err(reason) => {
            return broken(
                None,
                format!("extrémité non résolue : {reason} — flux compté en échec (§6.3)"),
            )
        }
    };
    // C'est le moteur qui décide de la fermeté : une lacune SUR le chemin
    // décisif (règle sur-approximée, objet externe non résolu…) sort en
    // `Unknown` — compté en échec avec la raison précise ci-dessous. Une
    // lacune HORS du chemin n'a plus d'effet. `allow_partial` force le
    // verdict sur la partie modélisée.
    let trace = calque_engine::trace_packet_opts(network, &packet, allow_partial);

    let actual = match trace.verdict {
        calque_engine::Verdict::Allowed => "allow",
        calque_engine::Verdict::Denied
        | calque_engine::Verdict::NoRoute
        | calque_engine::Verdict::Loop => "deny",
        calque_engine::Verdict::Unknown => "unknown",
    };
    let as_declared = actual == spec.expect.as_str();
    let status = if as_declared && !matches!(trace.verdict, calque_engine::Verdict::Unknown) {
        FlowStatus::Ok
    } else {
        FlowStatus::Broken
    };

    let mut detail = deciding_rule(&trace);
    if matches!(trace.verdict, calque_engine::Verdict::Unknown) {
        let reasons = trace
            .diagnostics
            .iter()
            .map(|d| d.message.clone())
            .collect::<Vec<_>>()
            .join(" ; ");
        detail = Some(match detail {
            Some(d) => format!("{d}\n          {reasons}"),
            None => reasons,
        });
    }
    if let Some(note) = port_note {
        detail = Some(match detail {
            Some(d) => format!("{d}\n          {note}"),
            None => note,
        });
    }

    FlowResult {
        name: spec.name.clone(),
        flow: spec.flow_label(),
        expected: spec.expect.to_string(),
        actual: Some(actual.to_owned()),
        status,
        detail,
    }
}

/// Évalue un lot de flux déclarés, dans l'ordre donné — la brique de
/// `calque test` et du va-et-vient Constat ↔ Calque (un `FlowResult` par
/// flux, jamais d'erreur fatale). Mêmes exigences que [`evaluate_flow`] :
/// modèle préparé ; `allow_partial` = drapeau `--allow-partial`.
pub fn evaluate_flows(
    network: &Network,
    specs: &[FlowSpec],
    allow_partial: bool,
) -> Vec<FlowResult> {
    specs
        .iter()
        .map(|spec| evaluate_flow(network, spec, allow_partial))
        .collect()
}
