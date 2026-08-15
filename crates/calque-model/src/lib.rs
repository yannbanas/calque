//! calque-model — la représentation intermédiaire de Calque.
//!
//! Crate PUR (règle §1 de CALQUE-ARCHITECTURE.md) : aucune dépendance
//! au-delà de `serde` et `ipnet`. Pas d'entrée-sortie, pas d'horloge,
//! pas de réseau.
//!
//! Les objets (groupes d'adresses et de services) sont résolus TARD
//! (§3.3) : la représentation intermédiaire garde les références
//! (`AddrExpr::Object`, `ServiceExpr::Object`) et le moteur les résout
//! à l'évaluation via l'`ObjectStore`.

use std::collections::BTreeMap;
use std::net::IpAddr;

use ipnet::IpNet;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Identifiants
// ---------------------------------------------------------------------------

macro_rules! id_type {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        #[derive(
            Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
        )]
        #[serde(transparent)]
        pub struct $name(pub String);

        impl $name {
            pub fn new(s: impl Into<String>) -> Self {
                Self(s.into())
            }
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl From<&str> for $name {
            fn from(s: &str) -> Self {
                Self(s.to_owned())
            }
        }
    };
}

id_type!(DeviceId);
id_type!(IfaceId);
id_type!(ZoneId);
id_type!(VrfId);
id_type!(PolicyId);
id_type!(
    /// Identifiant de règle CHEZ LE CONSTRUCTEUR (ex. « 12 » pour une
    /// politique FortiGate, « 34 » pour une entrée d'ACL Cisco).
    RuleId
);
id_type!(ObjectId);

pub type VlanId = u16;

impl VrfId {
    /// Le VRF par défaut, quand l'équipement n'en déclare aucun.
    pub fn default_vrf() -> Self {
        Self("default".to_owned())
    }
}

// ---------------------------------------------------------------------------
// Traçabilité
// ---------------------------------------------------------------------------

/// Fichier + ligne d'origine d'un élément de configuration.
///
/// « C'est le produit » (§3.3) : chaque verdict doit pouvoir remonter
/// jusqu'à la ligne de configuration qui l'a produit.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct SourceSpan {
    pub file: String,
    /// Première ligne (1-indexée).
    pub line: u32,
    /// Dernière ligne si l'élément s'étend sur un bloc.
    pub end_line: Option<u32>,
}

impl SourceSpan {
    pub fn new(file: impl Into<String>, line: u32) -> Self {
        Self {
            file: file.into(),
            line,
            end_line: None,
        }
    }
}

impl std::fmt::Display for SourceSpan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ligne {}", self.file, self.line)
    }
}

// ---------------------------------------------------------------------------
// Réseau et équipements
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Network {
    pub devices: BTreeMap<DeviceId, Device>,
    /// Topologie physique (déclarée ou inférée, cf. §7).
    pub links: Vec<Link>,
}

/// Une extrémité de lien : un port d'un équipement.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Endpoint {
    pub device: DeviceId,
    pub iface: IfaceId,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Link {
    pub a: Endpoint,
    pub b: Endpoint,
    /// D'où vient ce lien (LLDP, fichier déclaré, inférence par sous-réseau).
    pub origin: LinkOrigin,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum LinkOrigin {
    Lldp,
    Declared,
    InferredFromSubnet,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Vendor {
    Fortigate,
    CiscoIos,
    Opnsense,
    Nftables,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Device {
    pub id: DeviceId,
    pub vendor: Vendor,
    pub interfaces: BTreeMap<IfaceId, Interface>,
    pub zones: BTreeMap<ZoneId, Vec<IfaceId>>,
    pub vrfs: BTreeMap<VrfId, Vrf>,
    /// Groupes d'adresses et de services, résolus tard (§3.3).
    pub objects: ObjectStore,
    /// Les politiques de filtrage de l'équipement.
    pub policies: BTreeMap<PolicyId, Policy>,
    /// Où les politiques sont accrochées dans la séquence de traitement.
    pub pipeline: Pipeline,
}

impl Device {
    pub fn new(id: DeviceId, vendor: Vendor) -> Self {
        Self {
            id,
            vendor,
            interfaces: BTreeMap::new(),
            zones: BTreeMap::new(),
            vrfs: BTreeMap::new(),
            objects: ObjectStore::default(),
            policies: BTreeMap::new(),
            pipeline: Pipeline::default(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AdminState {
    Up,
    /// Ne pas modéliser ce qui est éteint (§3.2).
    Down,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Interface {
    pub id: IfaceId,
    pub addrs: Vec<IpNet>,
    pub vlan: Option<VlanId>,
    pub zone: Option<ZoneId>,
    pub vrf: VrfId,
    pub state: AdminState,
    /// Membres pour les agrégats et les ponts.
    pub members: Vec<IfaceId>,
}

impl Interface {
    pub fn new(id: IfaceId) -> Self {
        Self {
            id,
            addrs: Vec::new(),
            vlan: None,
            zone: None,
            vrf: VrfId::default_vrf(),
            state: AdminState::Up,
            members: Vec::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// Routage
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Vrf {
    /// Routes, à évaluer par plus long préfixe puis métrique.
    pub routes: Vec<Route>,
}

// `Ord` (dérivé, ordre structurel) permet aux consommateurs — dont
// `calque-diff` — de comparer des listes de routes en O(n log n) plutôt
// qu'en quadratique : une configuration hostile aux dizaines de milliers
// de routes ne doit pas transformer `calque plan` en déni de service.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Route {
    pub prefix: IpNet,
    pub next_hop: NextHop,
    pub metric: u32,
    pub origin: RouteOrigin,
    pub source: Option<SourceSpan>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum NextHop {
    Ip(IpAddr),
    Interface(IfaceId),
    /// Route de rejet explicite (blackhole).
    Drop,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum RouteOrigin {
    Static,
    Connected,
    Dynamic,
}

// ---------------------------------------------------------------------------
// Objets — résolus tard
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjectStore {
    pub addresses: BTreeMap<ObjectId, AddrObject>,
    pub services: BTreeMap<ObjectId, ServiceObject>,
}

/// Le TYPE d'un objet adresse dont l'étendue est INCONNUE hors ligne
/// (§6.3 : on ne devine jamais). Le `hint` associé est ce qu'il faut
/// fournir à l'humain pour résoudre l'objet (le nom de domaine, le code
/// pays…).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ExternalKind {
    /// Objet `type fqdn` : un nom de domaine (ex. `insights.nutanix.com`).
    Fqdn,
    /// Objet `type wildcard-fqdn` : un motif de domaine (ex. `*.nutanix.com`).
    WildcardFqdn,
    /// Objet `type geography` : un pays (ex. code `FR`).
    Geography,
}

impl std::fmt::Display for ExternalKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            ExternalKind::Fqdn => "fqdn",
            ExternalKind::WildcardFqdn => "wildcard-fqdn",
            ExternalKind::Geography => "geography",
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AddrObject {
    Nets(Vec<IpNet>),
    /// Groupe : références vers d'autres objets adresse.
    Group(Vec<ObjectId>),
    /// Objet dont l'étendue est INCONNUE hors ligne : un `fqdn`, un
    /// `wildcard-fqdn` ou une zone `geography`. L'objet EST compris (son
    /// type et son `hint` — nom de domaine ou code pays — sont connus),
    /// seule son étendue en préfixes IP est externe.
    ///
    /// Sémantique : un `External` NON résolu se comporte comme un objet
    /// VIDE côté correspondance — il ne matche aucun paquet. MAIS
    /// l'évaluation ne l'IGNORE pas en silence : le moteur le SIGNALE
    /// (`EvalError::ExternalUnresolved` → verdict non ferme quand l'objet
    /// est sur le chemin décisif), « je ne peux pas trancher fermement car
    /// cet objet a une étendue externe non fournie » (§6.3). Fournir ses
    /// préfixes via [`resolve_external`] le transforme en [`AddrObject::Nets`]
    /// et le rend pleinement analysable.
    External {
        kind: ExternalKind,
        hint: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ServiceObject {
    Services(Vec<Service>),
    Group(Vec<ObjectId>),
}

/// Intervalle de ports inclusif.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct PortRange {
    pub start: u16,
    pub end: u16,
}

impl PortRange {
    pub const ANY: PortRange = PortRange {
        start: 0,
        end: 65535,
    };

    pub fn single(p: u16) -> Self {
        Self { start: p, end: p }
    }

    pub fn contains(&self, p: u16) -> bool {
        self.start <= p && p <= self.end
    }

    /// L'intervalle commun aux deux, ou `None` s'ils sont disjoints.
    pub fn intersect(self, other: PortRange) -> Option<PortRange> {
        let start = self.start.max(other.start);
        let end = self.end.min(other.end);
        (start <= end).then_some(PortRange { start, end })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProtoMatch {
    Any,
    /// Numéro de protocole IP (6 = tcp, 17 = udp, 1 = icmp…).
    Number(u8),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Service {
    pub proto: ProtoMatch,
    pub sport: PortRange,
    pub dport: PortRange,
}

impl Service {
    pub fn tcp_dport(range: PortRange) -> Self {
        Self {
            proto: ProtoMatch::Number(6),
            sport: PortRange::ANY,
            dport: range,
        }
    }

    pub fn udp_dport(range: PortRange) -> Self {
        Self {
            proto: ProtoMatch::Number(17),
            sport: PortRange::ANY,
            dport: range,
        }
    }

    /// Le service commun aux deux (protocole ET intervalles de ports),
    /// ou `None` s'ils sont disjoints. `ProtoMatch::Any` s'accorde avec
    /// tout numéro concret ; deux numéros distincts sont disjoints.
    pub fn intersect(self, other: Service) -> Option<Service> {
        let proto = match (self.proto, other.proto) {
            (ProtoMatch::Any, p) | (p, ProtoMatch::Any) => p,
            (ProtoMatch::Number(a), ProtoMatch::Number(b)) if a == b => ProtoMatch::Number(a),
            _ => return None,
        };
        Some(Service {
            proto,
            sport: self.sport.intersect(other.sport)?,
            dport: self.dport.intersect(other.dport)?,
        })
    }
}

// ---------------------------------------------------------------------------
// Résolution des objets externes depuis un fichier fourni par l'humain
// ---------------------------------------------------------------------------

/// Un objet [`AddrObject::External`] resté NON résolu : son `hint` n'était
/// pas présent dans la table de correspondances fournie.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnresolvedExternal {
    pub object: ObjectId,
    pub kind: ExternalKind,
    pub hint: String,
}

/// Le bilan d'un appel à [`resolve_external`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExternalResolution {
    /// Nombre d'objets externes remplacés par leurs préfixes.
    pub resolved: usize,
    /// Les objets externes restés non résolus (hint absent de la table).
    pub unresolved: Vec<UnresolvedExternal>,
}

/// Remplace, dans l'`ObjectStore` de `device`, chaque
/// [`AddrObject::External`] dont le `hint` figure dans `resolutions` par un
/// [`AddrObject::Nets`] portant les préfixes fournis. Fonction PURE (§1) :
/// aucune entrée-sortie, aucune requête, aucune supposition — la résolution
/// ne vient QUE de la table `resolutions` construite par l'humain (§6.3).
///
/// Les `wildcard-fqdn` sont résolus par correspondance EXACTE de clé : la
/// table doit contenir la clé telle qu'écrite dans la configuration (par
/// ex. `*.example.com`) — il n'y a AUCUN filtrage par motif à l'évaluation.
///
/// Ce qui n'est pas dans la table reste `External` (jamais deviné) et
/// figure dans [`ExternalResolution::unresolved`].
pub fn resolve_external(
    device: &mut Device,
    resolutions: &BTreeMap<String, Vec<IpNet>>,
) -> ExternalResolution {
    let mut out = ExternalResolution::default();
    for (id, obj) in device.objects.addresses.iter_mut() {
        let AddrObject::External { kind, hint } = obj else {
            continue;
        };
        match resolutions.get(hint.as_str()) {
            Some(nets) => {
                *obj = AddrObject::Nets(nets.clone());
                out.resolved += 1;
            }
            None => out.unresolved.push(UnresolvedExternal {
                object: id.clone(),
                kind: *kind,
                hint: hint.clone(),
            }),
        }
    }
    out
}

/// Liste les objets [`AddrObject::External`] non résolus d'un équipement,
/// sans rien modifier — pour un récapitulatif honnête (« fournissez leurs
/// préfixes via `--resolve` »).
pub fn unresolved_externals(device: &Device) -> Vec<UnresolvedExternal> {
    device
        .objects
        .addresses
        .iter()
        .filter_map(|(id, obj)| match obj {
            AddrObject::External { kind, hint } => Some(UnresolvedExternal {
                object: id.clone(),
                kind: *kind,
                hint: hint.clone(),
            }),
            _ => None,
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Règles et politiques
// ---------------------------------------------------------------------------

/// Expression d'adresse telle qu'écrite dans la configuration.
/// La résolution vers des préfixes concrets se fait à l'évaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AddrExpr {
    Any,
    Net(IpNet),
    Object(ObjectId),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ServiceExpr {
    Any,
    Service(Service),
    Object(ObjectId),
}

/// Le « pavé » syntaxique d'une règle. Convention : un vecteur vide
/// équivaut à `Any` (les parseurs peuvent omettre une dimension).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleMatch {
    pub src: Vec<AddrExpr>,
    pub dst: Vec<AddrExpr>,
    pub services: Vec<ServiceExpr>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Action {
    Accept,
    Deny,
    /// Accepte ET traduit (SNAT/DNAT).
    Nat(NatAction),
    /// Saut vers une autre politique (chaînes nftables, etc.).
    Jump(PolicyId),
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NatAction {
    /// Traduction de source (pool ou adresse d'interface).
    pub snat: Option<IpNet>,
    /// Traduction de destination (VIP).
    pub dnat: Option<DnatTarget>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnatTarget {
    pub addr: IpAddr,
    pub port: Option<u16>,
}

/// Une règle de filtrage : un pavé + une action (§3.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rule {
    pub id: RuleId,
    pub matches: RuleMatch,
    pub from: Option<ZoneId>,
    pub to: Option<ZoneId>,
    pub action: Action,
    /// Fichier + ligne, pour la traçabilité. Jamais optionnel :
    /// une règle sans origine ne peut pas justifier un verdict.
    pub source: SourceSpan,
    /// La correspondance de cette règle est SUR-APPROXIMÉE — le modèle peut
    /// la faire matcher PLUS largement que l'équipement réel (restriction par
    /// identité `groups`/`users`/`fsso-groups`, jeux d'IP prédéfinis
    /// `internet-service`, négation `*-negate`, `nat46`/`nat64`…). Le
    /// convertisseur laisse ces clés en `unsupported` (fidélité `Partial`)
    /// mais construit tout de même la règle ; ce champ porte la RAISON courte
    /// pour que le moteur rende un verdict NON FERME (`Unknown`) dès qu'une
    /// décision peut dépendre d'une telle règle sur le chemin (§6.3 : jamais
    /// de faux « autorisé »). `None` = correspondance fidèle, sans risque de
    /// sur-approximation. Champ pur et sérialisable ; `#[serde(default)]`
    /// pour rester compatible avec un modèle sérialisé avant son ajout.
    #[serde(default)]
    pub approximation: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Policy {
    pub id: PolicyId,
    /// ORDRE SIGNIFICATIF : première correspondance gagne (§3.3).
    pub rules: Vec<Rule>,
    pub default_action: Action,
}

/// Où les filtres sont accrochés dans la séquence de traitement (§3.1) :
/// entrée → filtre d'entrée → DNAT → routage → filtre de sortie → SNAT → sortie.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pipeline {
    pub ingress: Vec<PolicyId>,
    pub egress: Vec<PolicyId>,
}

// ---------------------------------------------------------------------------
// Paquet concret
// ---------------------------------------------------------------------------

/// Un paquet précis, utilisé pour les traces et pour `sample()` (§4.1).
///
/// **Convention ICMP** (proto 1) et **ICMPv6** (proto 58) : ces protocoles
/// n'ont pas de ports. On réutilise les deux dimensions de ports pour
/// porter le type et le code, sans ajouter de dimension à l'algèbre :
/// `dport` = type ICMP, `sport` = code ICMP. Ainsi un service « echo
/// request » (type 8) se modélise `dport ∈ {8}`, et le reste du moteur
/// (correspondance, espace d'en-têtes) fonctionne sans cas particulier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ConcretePacket {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub proto: u8,
    pub sport: u16,
    pub dport: u16,
}

// ---------------------------------------------------------------------------
// Diagnostics et fidélité
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    Info,
    Warning,
    Error,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Diagnostic {
    pub severity: Severity,
    pub message: String,
    pub span: Option<SourceSpan>,
}

impl Diagnostic {
    pub fn warning(message: impl Into<String>, span: Option<SourceSpan>) -> Self {
        Self {
            severity: Severity::Warning,
            message: message.into(),
            span,
        }
    }

    pub fn error(message: impl Into<String>, span: Option<SourceSpan>) -> Self {
        Self {
            severity: Severity::Error,
            message: message.into(),
            span,
        }
    }
}

/// Ne jamais deviner (§6.3) : toute sortie porte son niveau de fidélité,
/// et l'outil refuse un verdict ferme sur un modèle partiel touchant le
/// chemin analysé.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Fidelity {
    Complete,
    Partial { unsupported: Vec<Diagnostic> },
}

impl Fidelity {
    pub fn is_complete(&self) -> bool {
        matches!(self, Fidelity::Complete)
    }

    /// Combine deux fidélités : partiel si l'une des deux l'est.
    pub fn merge(self, other: Fidelity) -> Fidelity {
        match (self, other) {
            (Fidelity::Complete, f) => f,
            (f, Fidelity::Complete) => f,
            (Fidelity::Partial { unsupported: mut a }, Fidelity::Partial { unsupported: b }) => {
                a.extend(b);
                Fidelity::Partial { unsupported: a }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fidelity_merge_reste_partielle() {
        let p = Fidelity::Partial {
            unsupported: vec![Diagnostic::warning("directive inconnue", None)],
        };
        assert!(!Fidelity::Complete.merge(p.clone()).is_complete());
        assert!(!p.merge(Fidelity::Complete).is_complete());
        assert!(Fidelity::Complete.merge(Fidelity::Complete).is_complete());
    }

    fn device_with(addresses: Vec<(&str, AddrObject)>) -> Device {
        let mut dev = Device::new(DeviceId::new("d"), Vendor::Fortigate);
        for (name, obj) in addresses {
            dev.objects.addresses.insert(ObjectId::new(name), obj);
        }
        dev
    }

    #[test]
    fn resolve_external_remplace_les_resolus_laisse_les_autres() {
        let mut dev = device_with(vec![
            (
                "fqdn-a",
                AddrObject::External {
                    kind: ExternalKind::Fqdn,
                    hint: "insights.nutanix.com".to_owned(),
                },
            ),
            (
                "geo-fr",
                AddrObject::External {
                    kind: ExternalKind::Geography,
                    hint: "FR".to_owned(),
                },
            ),
            // Un objet ordinaire n'est jamais touché.
            (
                "net-lan",
                AddrObject::Nets(vec!["10.0.0.0/8".parse().unwrap()]),
            ),
        ]);
        let mut map: BTreeMap<String, Vec<IpNet>> = BTreeMap::new();
        map.insert(
            "insights.nutanix.com".to_owned(),
            vec!["52.10.0.0/16".parse().unwrap()],
        );
        // « FR » n'est PAS fourni : il doit rester non résolu (jamais deviné).

        let bilan = resolve_external(&mut dev, &map);
        assert_eq!(bilan.resolved, 1);
        assert_eq!(bilan.unresolved.len(), 1);
        assert_eq!(bilan.unresolved[0].hint, "FR");
        assert_eq!(bilan.unresolved[0].kind, ExternalKind::Geography);

        // fqdn-a est devenu des préfixes ; geo-fr reste External ; net-lan
        // intact.
        assert_eq!(
            dev.objects.addresses.get(&ObjectId::new("fqdn-a")),
            Some(&AddrObject::Nets(vec!["52.10.0.0/16".parse().unwrap()]))
        );
        assert!(matches!(
            dev.objects.addresses.get(&ObjectId::new("geo-fr")),
            Some(AddrObject::External { .. })
        ));
        assert_eq!(
            dev.objects.addresses.get(&ObjectId::new("net-lan")),
            Some(&AddrObject::Nets(vec!["10.0.0.0/8".parse().unwrap()]))
        );
    }

    #[test]
    fn resolve_external_wildcard_par_cle_exacte() {
        let mut dev = device_with(vec![(
            "wild",
            AddrObject::External {
                kind: ExternalKind::WildcardFqdn,
                hint: "*.nutanix.com".to_owned(),
            },
        )]);
        // Une clé qui n'est PAS le motif exact ne résout rien : aucun glob.
        let mut map: BTreeMap<String, Vec<IpNet>> = BTreeMap::new();
        map.insert(
            "www.nutanix.com".to_owned(),
            vec!["52.0.0.0/8".parse().unwrap()],
        );
        let bilan = resolve_external(&mut dev, &map);
        assert_eq!(bilan.resolved, 0);
        assert_eq!(bilan.unresolved.len(), 1);

        // Avec la clé EXACTE, l'objet est résolu.
        map.insert(
            "*.nutanix.com".to_owned(),
            vec!["52.0.0.0/8".parse().unwrap()],
        );
        let bilan = resolve_external(&mut dev, &map);
        assert_eq!(bilan.resolved, 1);
        assert!(bilan.unresolved.is_empty());
        assert_eq!(
            dev.objects.addresses.get(&ObjectId::new("wild")),
            Some(&AddrObject::Nets(vec!["52.0.0.0/8".parse().unwrap()]))
        );
    }

    #[test]
    fn unresolved_externals_liste_sans_modifier() {
        let dev = device_with(vec![
            (
                "fqdn-a",
                AddrObject::External {
                    kind: ExternalKind::Fqdn,
                    hint: "a.example.com".to_owned(),
                },
            ),
            ("net", AddrObject::Nets(vec!["10.0.0.0/8".parse().unwrap()])),
        ]);
        let list = unresolved_externals(&dev);
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].object, ObjectId::new("fqdn-a"));
    }

    #[test]
    fn external_kind_display() {
        assert_eq!(ExternalKind::Fqdn.to_string(), "fqdn");
        assert_eq!(ExternalKind::WildcardFqdn.to_string(), "wildcard-fqdn");
        assert_eq!(ExternalKind::Geography.to_string(), "geography");
    }

    #[test]
    fn port_range_contains() {
        assert!(PortRange::ANY.contains(0));
        assert!(PortRange::ANY.contains(65535));
        let r = PortRange::single(445);
        assert!(r.contains(445));
        assert!(!r.contains(446));
    }
}
