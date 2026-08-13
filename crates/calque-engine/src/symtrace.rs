//! Propagation SYMBOLIQUE (§5.3) : le même moteur que `engine.rs`, mais en
//! propageant un [`HeaderSet`] au lieu d'un `ConcretePacket`.
//!
//! La sortie est un ARBRE ([`SymbolicTrace`]) : un ensemble peut se scinder
//! à chaque étape — règles d'une politique (`sympolicy.rs`), embranchement
//! de routage (partition de la dimension destination par plus long préfixe),
//! livraison locale, adresses portées par des équipements modélisés sur le
//! réseau connecté de sortie. Chaque sous-ensemble terminal porte son
//! verdict, la chaîne des décisions qui l'a produit, et un paquet concret
//! représentatif (`sample()`, §4.1).
//!
//! Fidélité (§6.3) : toute part que le modèle ne permet pas de décider
//! (objet manquant, cycle, topologie incomplète ou ambiguë, borne atteinte)
//! reçoit le verdict `Unknown` avec un diagnostic — jamais une supposition.
//! Mais le moteur répond FERMEMENT quand le périmètre modélisé le permet
//! (même sémantique que le moteur concret, `engine.rs`) :
//!
//! - SORTIE DE PÉRIMÈTRE : une part routée par une interface SANS lien vers
//!   des destinations qui n'appartiennent à AUCUN réseau du modèle devient
//!   un ensemble terminal `Allowed` avec la décision `Outcome::ExitsModel`
//!   (le critère précis est celui d'`engine.rs`). Les destinations couvertes
//!   par un réseau modélisé mais injoignables restent un trou de topologie
//!   interne → `Unknown`. `reach_to`/`reach_from` en bénéficient : une cible
//!   externe au modèle devient atteignable « en sortie de périmètre ».
//! - ECMP : chaque route candidate est évaluée comme une branche complète ;
//!   pour chaque sous-ensemble, le verdict est FERME là où toutes les
//!   branches s'accordent (intersection des unions par verdict), et
//!   `Unknown` diagnostiqué là où elles divergent. Limite documentée : si
//!   une branche applique une traduction d'adresse après l'embranchement,
//!   la comparaison inter-branches (exprimée après traduction) n'est plus
//!   fiable → toute la part devient `Unknown` (prudent, jamais un verdict
//!   ferme erroné). Bornes : [`crate::route::MAX_ECMP_ROUTES`] par
//!   recherche, [`crate::engine::MAX_ECMP_TOTAL_BRANCHES`] en cumulé.
//!
//! NAT symbolique — limites documentées :
//! - un DNAT réécrit la dimension destination en SINGLETON (adresse cible,
//!   et port cible s'il est fixé) : la correspondance inverse (quelle
//!   destination d'origine a produit quelle destination traduite) n'est pas
//!   conservée dans l'ensemble propagé — elle reste lisible dans la chaîne
//!   de décisions (`Outcome::Rewritten`) ;
//! - un SNAT vers un pool retient l'adresse représentative `pool.addr()`,
//!   comme le moteur concret ;
//! - ces réécritures étant non injectives, un ensemble APRÈS NAT peut
//!   représenter plusieurs paquets d'origine par paquet traduit ; les
//!   ensembles terminaux sont exprimés dans l'espace APRÈS traduction.
//!
//! Bornes (terminaison sur entrées hostiles) : [`MAX_DEPTH`], [`MAX_NODES`]
//! et [`MAX_CUBES`](crate::sympolicy::MAX_CUBES). Toute borne atteinte
//! produit un verdict `Unknown` documenté, jamais un résultat faux.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use calque_model::{
    AdminState, ConcretePacket, Device, DeviceId, Diagnostic, Endpoint, IfaceId, Network, NextHop,
    RuleId, Severity, SourceSpan, VrfId, ZoneId,
};
use calque_space::{Cube, HeaderSet, HeaderSpace, PortRanges, PrefixSet, ProtoSet};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};

use crate::engine::MAX_ECMP_TOTAL_BRANCHES;
use crate::error::EvalError;
use crate::policy::{FilterPoint, NatGrant};
use crate::route::{EcmpRoute, MAX_ECMP_ROUTES};
use crate::sympolicy::{evaluate_policy_symbolic, SymFilterResult, MAX_CUBES};
use crate::trace::{Decision, Outcome, Stage, Verdict};

/// Profondeur maximale de l'arbre (équipements traversés par branche).
/// La détection de boucle borne déjà la profondeur au nombre d'équipements
/// du modèle ; cette constante protège en plus contre un modèle hostile
/// démesuré. Au-delà : verdict `Unknown`.
pub const MAX_DEPTH: usize = 64;

/// Nombre total de nœuds de l'arbre (tous embranchements confondus).
/// Au-delà : les sous-ensembles restants reçoivent le verdict `Unknown`.
pub const MAX_NODES: usize = 4096;

/// L'arbre de propagation symbolique.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SymbolicTrace {
    /// Absent si le point d'entrée est invalide ou l'ensemble initial vide
    /// (voir `diagnostics`).
    pub root: Option<SymbolicNode>,
    pub diagnostics: Vec<Diagnostic>,
}

impl SymbolicTrace {
    /// Tous les sous-ensembles terminaux de l'arbre (parcours en
    /// profondeur). Leur union est l'ensemble d'entrée.
    pub fn verdict_sets(&self) -> Vec<&SymbolicVerdictSet> {
        let mut out = Vec::new();
        if let Some(root) = &self.root {
            collect_terminals(root, &mut out);
        }
        out
    }

    /// Les sous-ensembles terminaux portant ce verdict.
    pub fn sets_with(&self, verdict: Verdict) -> Vec<&SymbolicVerdictSet> {
        self.verdict_sets()
            .into_iter()
            .filter(|s| s.verdict == verdict)
            .collect()
    }
}

fn collect_terminals<'a>(node: &'a SymbolicNode, out: &mut Vec<&'a SymbolicVerdictSet>) {
    out.extend(node.terminals.iter());
    for branch in &node.branches {
        collect_terminals(&branch.child, out);
    }
}

/// La traversée symbolique d'un équipement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SymbolicNode {
    pub device: DeviceId,
    pub in_iface: IfaceId,
    /// L'ensemble entrant dans l'équipement (avant filtres et NAT).
    pub set_in: HeaderSet,
    /// Les sous-ensembles dont le sort se décide ICI (refus, livraison,
    /// pas de route, boucle, indécidable).
    pub terminals: Vec<SymbolicVerdictSet>,
    /// Les sous-ensembles qui poursuivent vers un équipement suivant.
    pub branches: Vec<SymbolicBranch>,
}

/// Un sous-ensemble qui quitte l'équipement vers un voisin.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SymbolicBranch {
    pub out_iface: IfaceId,
    /// L'ensemble sortant (après traductions d'adresse).
    pub set_out: HeaderSet,
    pub child: Box<SymbolicNode>,
}

/// Un sous-ensemble terminal : verdict + justification + exemple concret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SymbolicVerdictSet {
    pub verdict: Verdict,
    pub set: HeaderSet,
    /// La chaîne des décisions décisives depuis le point d'entrée
    /// (chaque décision est étiquetée par son équipement).
    pub decisions: Vec<SymbolicDecision>,
    /// Jamais vide quand le verdict est `Unknown` (§6.3).
    pub diagnostics: Vec<Diagnostic>,
    /// Un paquet représentatif du sous-ensemble (§4.1).
    pub sample: Option<ConcretePacket>,
}

/// Une décision de la chaîne, étiquetée par l'équipement qui l'a prise.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SymbolicDecision {
    pub device: DeviceId,
    pub decision: Decision,
}

/// Propage un ensemble depuis un point d'entrée explicite.
///
/// C'est le point d'entrée du mode symbolique ; `reach.rs` l'appelle pour
/// chaque interface d'entrée du réseau. L'union des ensembles terminaux de
/// l'arbre est l'ensemble initial (aucun paquet perdu, aucun inventé).
pub fn symbolic_trace_from(network: &Network, entry: &Endpoint, set: &HeaderSet) -> SymbolicTrace {
    let valid = network
        .devices
        .get(&entry.device)
        .and_then(|d| d.interfaces.get(&entry.iface))
        .map(|i| i.state == AdminState::Up)
        .unwrap_or(false);
    if !valid {
        return SymbolicTrace {
            root: None,
            diagnostics: vec![Diagnostic::error(
                format!(
                    "point d'entrée {}/{} absent du modèle ou désactivé",
                    entry.device, entry.iface
                ),
                None,
            )],
        };
    }
    if set.is_empty() {
        return SymbolicTrace {
            root: None,
            diagnostics: vec![Diagnostic {
                severity: Severity::Info,
                message: "ensemble initial vide : rien à propager".to_owned(),
                span: None,
            }],
        };
    }
    let mut walker = Walker {
        network,
        nodes_left: MAX_NODES,
        ecmp_budget: MAX_ECMP_TOTAL_BRANCHES,
        model_nets: model_networks(network),
    };
    let root = walker.propagate(
        &entry.device,
        &entry.iface,
        set.clone(),
        &BTreeSet::new(),
        &[],
        0,
    );
    SymbolicTrace {
        root: Some(root),
        diagnostics: Vec::new(),
    }
}

// ---------------------------------------------------------------------------
// Mise en œuvre
// ---------------------------------------------------------------------------

/// Une part de trafic en cours de traversée d'un équipement.
#[derive(Clone)]
struct FlowPart {
    set: HeaderSet,
    chain: Vec<SymbolicDecision>,
    /// SNAT accordé mais différé (appliqué après le filtre de sortie),
    /// comme dans le moteur concret.
    pending_snat: Option<NatGrant>,
}

/// Contexte d'un équipement en cours de traversée.
struct DeviceCtx<'a> {
    device: &'a Device,
    in_zone: Option<ZoneId>,
    visited: &'a BTreeSet<DeviceId>,
    depth: usize,
}

/// Le sort d'une région de destinations dans la table de routage.
enum RouteKind {
    Forward {
        out_iface: IfaceId,
        gateway: Option<IpAddr>,
        source: Option<SourceSpan>,
    },
    /// Plusieurs routes optimales divergentes : chaque candidate est une
    /// branche, évaluée puis recombinée par verdict (voir l'en-tête).
    Ecmp {
        routes: Vec<EcmpRoute>,
    },
    Blackhole {
        source: Option<SourceSpan>,
    },
    /// Interface éteinte, prochain saut injoignable, borne ECMP dépassée…
    Undecidable {
        message: String,
    },
}

struct Walker<'a> {
    network: &'a Network,
    nodes_left: usize,
    /// Budget CUMULÉ de branches ECMP (même borne que le moteur concret,
    /// [`MAX_ECMP_TOTAL_BRANCHES`]).
    ecmp_budget: usize,
    /// Les réseaux portés par les interfaces actives du modèle : la moitié
    /// « destination » du critère de sortie de périmètre.
    model_nets: PrefixSet,
}

impl<'a> Walker<'a> {
    /// Traverse UN équipement (séquence §3.1) et récurse sur les branches.
    fn propagate(
        &mut self,
        device_id: &DeviceId,
        in_iface_id: &IfaceId,
        set_in: HeaderSet,
        visited: &BTreeSet<DeviceId>,
        chain: &[SymbolicDecision],
        depth: usize,
    ) -> SymbolicNode {
        let network = self.network;
        let mut node = SymbolicNode {
            device: device_id.clone(),
            in_iface: in_iface_id.clone(),
            set_in: set_in.clone(),
            terminals: Vec::new(),
            branches: Vec::new(),
        };
        if set_in.is_empty() {
            return node;
        }
        // --- Bornes (terminaison garantie sur entrées hostiles) ----------
        if depth > MAX_DEPTH || self.nodes_left == 0 {
            node.terminals.push(terminal(
                Verdict::Unknown,
                set_in,
                chain.to_vec(),
                vec![Diagnostic::error(
                    format!(
                        "borne de propagation atteinte (MAX_DEPTH = {MAX_DEPTH}, \
                         MAX_NODES = {MAX_NODES}) : arbre tronqué"
                    ),
                    None,
                )],
            ));
            return node;
        }
        self.nodes_left -= 1;
        // --- Boucle de routage : équipement déjà traversé sur la branche --
        if visited.contains(device_id) {
            node.terminals.push(terminal(
                Verdict::Loop,
                set_in,
                chain.to_vec(),
                vec![Diagnostic::error(
                    format!("boucle de routage : « {device_id} » déjà traversé"),
                    None,
                )],
            ));
            return node;
        }
        if set_in.cubes().len() > MAX_CUBES {
            node.terminals.push(terminal(
                Verdict::Unknown,
                set_in,
                chain.to_vec(),
                vec![Diagnostic::error(
                    format!(
                        "ensemble trop fragmenté (plus de {MAX_CUBES} pavés) : borne MAX_CUBES"
                    ),
                    None,
                )],
            ));
            return node;
        }
        let Some(device) = network.devices.get(device_id) else {
            node.terminals.push(terminal(
                Verdict::Unknown,
                set_in,
                chain.to_vec(),
                vec![Diagnostic::error(
                    format!("équipement « {device_id} » absent du modèle"),
                    None,
                )],
            ));
            return node;
        };
        let in_ok = device
            .interfaces
            .get(in_iface_id)
            .map(|i| i.state == AdminState::Up)
            .unwrap_or(false);
        if !in_ok {
            node.terminals.push(terminal(
                Verdict::Unknown,
                set_in,
                chain.to_vec(),
                vec![Diagnostic::error(
                    format!(
                        "le trafic entre par « {device_id}/{in_iface_id} » absente ou désactivée"
                    ),
                    None,
                )],
            ));
            return node;
        }
        let in_vrf = device
            .interfaces
            .get(in_iface_id)
            .map(|i| i.vrf.clone())
            .unwrap_or_else(VrfId::default_vrf);
        let mut visited2 = visited.clone();
        visited2.insert(device_id.clone());
        let in_zone = zone_of(device, in_iface_id);

        let mut parts = vec![FlowPart {
            set: set_in,
            chain: chain.to_vec(),
            pending_snat: None,
        }];

        // --- Filtres d'entrée (DNAT appliqué au fil de l'eau) -------------
        let ingress_point = FilterPoint::Ingress {
            in_zone: in_zone.clone(),
        };
        for pid in &device.pipeline.ingress {
            let Some(policy) = device.policies.get(pid) else {
                let diag = EvalError::PolicyMissing {
                    policy: pid.clone(),
                }
                .to_diagnostic();
                for fp in parts.drain(..) {
                    node.terminals.push(terminal(
                        Verdict::Unknown,
                        fp.set,
                        fp.chain,
                        vec![diag.clone()],
                    ));
                }
                break;
            };
            let mut next = Vec::new();
            for fp in parts {
                for sp in evaluate_policy_symbolic(
                    device,
                    policy,
                    &fp.set,
                    &ingress_point,
                    Stage::IngressFilter,
                ) {
                    let mut chain2 = fp.chain.clone();
                    chain2.extend(sp.decisions.into_iter().map(|d| SymbolicDecision {
                        device: device.id.clone(),
                        decision: d,
                    }));
                    match sp.result {
                        SymFilterResult::Deny => node.terminals.push(terminal(
                            Verdict::Denied,
                            sp.set,
                            chain2,
                            sp.diagnostics,
                        )),
                        SymFilterResult::Unknown => node.terminals.push(terminal(
                            Verdict::Unknown,
                            sp.set,
                            chain2,
                            sp.diagnostics,
                        )),
                        SymFilterResult::Accept { nat } => {
                            let mut set = sp.set;
                            let mut pending = fp.pending_snat.clone();
                            if let Some(grant) = nat {
                                if let Some(dnat) = &grant.action.dnat {
                                    set = rewrite_dst(&set, dnat.addr, dnat.port);
                                    chain2.push(SymbolicDecision {
                                        device: device.id.clone(),
                                        decision: nat_decision(
                                            grant.rule.clone(),
                                            grant.source.clone(),
                                        ),
                                    });
                                }
                                if grant.action.snat.is_some() {
                                    pending = Some(grant);
                                }
                            }
                            next.push(FlowPart {
                                set,
                                chain: chain2,
                                pending_snat: pending,
                            });
                        }
                    }
                }
            }
            parts = next;
        }

        // --- Livraison locale : adresses portées par l'équipement ---------
        let owned: Vec<IpNet> = device
            .interfaces
            .values()
            .filter(|i| i.state == AdminState::Up)
            .flat_map(|i| i.addrs.iter().map(|a| IpNet::from(a.addr())))
            .collect();
        if !owned.is_empty() {
            let owned_hs = dst_restriction(&PrefixSet::from_nets(owned));
            let mut kept = Vec::new();
            for mut fp in parts {
                let local = fp.set.intersect(&owned_hs);
                if !local.is_empty() {
                    node.terminals.push(terminal(
                        Verdict::Allowed,
                        local,
                        fp.chain.clone(),
                        Vec::new(),
                    ));
                    fp.set = fp.set.subtract(&owned_hs);
                }
                if !fp.set.is_empty() {
                    kept.push(fp);
                }
            }
            parts = kept;
        }

        // --- Routage : partition par plus long préfixe --------------------
        let regions = partition_routes(device, &in_vrf);
        let mut forwarded: Vec<(IfaceId, Option<IpAddr>, FlowPart)> = Vec::new();
        let mut ecmp_parts: Vec<(Vec<EcmpRoute>, FlowPart)> = Vec::new();
        for fp in parts {
            let mut rest = fp.set.clone();
            for (region, kind) in &regions {
                if rest.is_empty() {
                    break;
                }
                let region_hs = dst_restriction(region);
                let sub = rest.intersect(&region_hs);
                if sub.is_empty() {
                    continue;
                }
                rest = rest.subtract(&region_hs);
                match kind {
                    RouteKind::Blackhole { source } => {
                        let mut chain2 = fp.chain.clone();
                        chain2.push(SymbolicDecision {
                            device: device.id.clone(),
                            decision: Decision {
                                stage: Stage::Route,
                                rule: None,
                                source: source.clone(),
                                outcome: Outcome::RouteDrop,
                                shadowed_by: Vec::new(),
                            },
                        });
                        node.terminals
                            .push(terminal(Verdict::NoRoute, sub, chain2, Vec::new()));
                    }
                    RouteKind::Undecidable { message } => {
                        node.terminals.push(terminal(
                            Verdict::Unknown,
                            sub,
                            fp.chain.clone(),
                            vec![Diagnostic::error(message.clone(), None)],
                        ));
                    }
                    RouteKind::Forward {
                        out_iface,
                        gateway,
                        source,
                    } => {
                        let mut chain2 = fp.chain.clone();
                        chain2.push(SymbolicDecision {
                            device: device.id.clone(),
                            decision: Decision {
                                stage: Stage::Route,
                                rule: None,
                                source: source.clone(),
                                outcome: Outcome::RouteFound,
                                shadowed_by: Vec::new(),
                            },
                        });
                        forwarded.push((
                            out_iface.clone(),
                            *gateway,
                            FlowPart {
                                set: sub,
                                chain: chain2,
                                pending_snat: fp.pending_snat.clone(),
                            },
                        ));
                    }
                    RouteKind::Ecmp { routes } => {
                        // La décision de routage de chaque branche est
                        // ajoutée par `ecmp_part`.
                        ecmp_parts.push((
                            routes.clone(),
                            FlowPart {
                                set: sub,
                                chain: fp.chain.clone(),
                                pending_snat: fp.pending_snat.clone(),
                            },
                        ));
                    }
                }
            }
            // Destinations sans aucune route.
            if !rest.is_empty() {
                let mut chain2 = fp.chain.clone();
                chain2.push(SymbolicDecision {
                    device: device.id.clone(),
                    decision: Decision {
                        stage: Stage::Route,
                        rule: None,
                        source: None,
                        outcome: Outcome::NoRoute,
                        shadowed_by: Vec::new(),
                    },
                });
                node.terminals
                    .push(terminal(Verdict::NoRoute, rest, chain2, Vec::new()));
            }
        }

        // --- Filtre de sortie, SNAT, livraison ou lien --------------------
        let ctx = DeviceCtx {
            device,
            in_zone,
            visited: &visited2,
            depth,
        };
        for (out_iface, gateway, fpart) in forwarded {
            self.forward_part(&mut node, &ctx, &out_iface, gateway, fpart);
        }
        for (routes, fpart) in ecmp_parts {
            self.ecmp_part(&mut node, &ctx, &routes, fpart);
        }
        node
    }

    /// Filtre de sortie + SNAT, puis livraison sur le réseau connecté de
    /// sortie, traversée du lien physique ou sortie de périmètre.
    fn forward_part(
        &mut self,
        node: &mut SymbolicNode,
        ctx: &DeviceCtx<'_>,
        out_iface_id: &IfaceId,
        gateway: Option<IpAddr>,
        part: FlowPart,
    ) {
        let device = ctx.device;
        let Some(out_iface) = device.interfaces.get(out_iface_id) else {
            node.terminals.push(terminal(
                Verdict::Unknown,
                part.set,
                part.chain,
                vec![Diagnostic::error(
                    format!(
                        "interface de sortie « {}/{out_iface_id} » absente du modèle",
                        device.id
                    ),
                    None,
                )],
            ));
            return;
        };
        let egress_point = FilterPoint::Egress {
            in_zone: ctx.in_zone.clone(),
            out_zone: zone_of(device, out_iface_id),
        };
        let mut parts = vec![part];
        for pid in &device.pipeline.egress {
            let Some(policy) = device.policies.get(pid) else {
                let diag = EvalError::PolicyMissing {
                    policy: pid.clone(),
                }
                .to_diagnostic();
                for fp in parts.drain(..) {
                    node.terminals.push(terminal(
                        Verdict::Unknown,
                        fp.set,
                        fp.chain,
                        vec![diag.clone()],
                    ));
                }
                break;
            };
            let mut next = Vec::new();
            for fp in parts {
                for sp in evaluate_policy_symbolic(
                    device,
                    policy,
                    &fp.set,
                    &egress_point,
                    Stage::EgressFilter,
                ) {
                    let mut chain2 = fp.chain.clone();
                    chain2.extend(sp.decisions.into_iter().map(|d| SymbolicDecision {
                        device: device.id.clone(),
                        decision: d,
                    }));
                    match sp.result {
                        SymFilterResult::Deny => node.terminals.push(terminal(
                            Verdict::Denied,
                            sp.set,
                            chain2,
                            sp.diagnostics,
                        )),
                        SymFilterResult::Unknown => node.terminals.push(terminal(
                            Verdict::Unknown,
                            sp.set,
                            chain2,
                            sp.diagnostics,
                        )),
                        SymFilterResult::Accept { nat } => {
                            let mut pending = fp.pending_snat.clone();
                            if let Some(grant) = nat {
                                if grant.action.dnat.is_some() {
                                    // Trop tard pour réécrire la destination
                                    // (même discipline que le moteur concret).
                                    let diag = EvalError::DnatAfterRouting {
                                        rule: grant.rule.clone(),
                                        source: grant.source.clone(),
                                    }
                                    .to_diagnostic();
                                    node.terminals.push(terminal(
                                        Verdict::Unknown,
                                        sp.set,
                                        chain2,
                                        vec![diag],
                                    ));
                                    continue;
                                }
                                if grant.action.snat.is_some() {
                                    pending = Some(grant);
                                }
                            }
                            next.push(FlowPart {
                                set: sp.set,
                                chain: chain2,
                                pending_snat: pending,
                            });
                        }
                    }
                }
            }
            parts = next;
        }

        // SNAT : réécriture de la source APRÈS le filtre de sortie.
        for fp in &mut parts {
            if let Some(grant) = fp.pending_snat.take() {
                if let Some(pool) = grant.action.snat {
                    fp.set = rewrite_src(&fp.set, pool.addr());
                    fp.chain.push(SymbolicDecision {
                        device: device.id.clone(),
                        decision: nat_decision(grant.rule, grant.source),
                    });
                }
            }
        }

        // Livraison sur le réseau connecté de sortie, ou lien physique.
        let connected = PrefixSet::from_nets(out_iface.addrs.iter().map(|a| a.trunc()));
        for fp in parts {
            let (delivered, rest) = if connected.is_empty() {
                (HeaderSet::empty(), fp.set.clone())
            } else {
                let hs = dst_restriction(&connected);
                (fp.set.intersect(&hs), fp.set.subtract(&hs))
            };
            if !delivered.is_empty() {
                self.deliver_connected(
                    node,
                    ctx,
                    out_iface_id,
                    &connected,
                    FlowPart {
                        set: delivered,
                        chain: fp.chain.clone(),
                        pending_snat: None,
                    },
                );
            }
            if !rest.is_empty() {
                self.traverse_link(
                    node,
                    ctx,
                    out_iface_id,
                    gateway,
                    FlowPart {
                        set: rest,
                        chain: fp.chain,
                        pending_snat: None,
                    },
                );
            }
        }
    }

    /// Évalue une part sur CHAQUE route candidate d'un ECMP, puis recombine
    /// par verdict : FERME là où toutes les branches s'accordent
    /// (intersection des unions par verdict), `Unknown` diagnostiqué là où
    /// elles divergent — même sémantique que le moteur concret. Les
    /// terminaux fermes portent la chaîne de la PREMIÈRE branche (choix
    /// documenté) précédée d'une décision `EcmpAgreed`.
    fn ecmp_part(
        &mut self,
        node: &mut SymbolicNode,
        ctx: &DeviceCtx<'_>,
        routes: &[EcmpRoute],
        part: FlowPart,
    ) {
        let ifaces: Vec<IfaceId> = routes.iter().map(|r| r.out_iface.clone()).collect();
        if routes.len() > self.ecmp_budget {
            node.terminals.push(terminal(
                Verdict::Unknown,
                part.set,
                part.chain,
                vec![Diagnostic::error(
                    format!(
                        "borne de bifurcation ECMP atteinte \
                         ({MAX_ECMP_TOTAL_BRANCHES} branches cumulées) : part indéterminée"
                    ),
                    None,
                )],
            ));
            return;
        }
        self.ecmp_budget -= routes.len();

        // Chaque branche est évaluée dans un nœud TEMPORAIRE isolé ; seuls
        // ses ensembles terminaux sont recombinés (l'arborescence détaillée
        // des branches n'est pas conservée — documenté).
        let base_chain_len = part.chain.len();
        let mut branch_terms: Vec<Vec<SymbolicVerdictSet>> = Vec::with_capacity(routes.len());
        let mut nat_seen = false;
        for r in routes {
            let mut tmp = SymbolicNode {
                device: ctx.device.id.clone(),
                in_iface: node.in_iface.clone(),
                set_in: part.set.clone(),
                terminals: Vec::new(),
                branches: Vec::new(),
            };
            let mut chain2 = part.chain.clone();
            chain2.push(SymbolicDecision {
                device: ctx.device.id.clone(),
                decision: Decision {
                    stage: Stage::Route,
                    rule: None,
                    source: r.source.clone(),
                    outcome: Outcome::RouteFound,
                    shadowed_by: Vec::new(),
                },
            });
            self.forward_part(
                &mut tmp,
                ctx,
                &r.out_iface,
                r.gateway,
                FlowPart {
                    set: part.set.clone(),
                    chain: chain2,
                    pending_snat: part.pending_snat.clone(),
                },
            );
            let mut terms: Vec<&SymbolicVerdictSet> = Vec::new();
            collect_terminals(&tmp, &mut terms);
            let owned: Vec<SymbolicVerdictSet> = terms.into_iter().cloned().collect();
            // Limite documentée (en-tête) : une traduction d'adresse APRÈS
            // l'embranchement rend la comparaison inter-branches non fiable
            // (ensembles exprimés après traduction).
            nat_seen |= owned.iter().any(|t| {
                t.decisions
                    .iter()
                    .skip(base_chain_len)
                    .any(|d| d.decision.stage == Stage::Nat)
            });
            branch_terms.push(owned);
        }

        let list = ifaces
            .iter()
            .map(|i| i.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        if nat_seen {
            node.terminals.push(terminal(
                Verdict::Unknown,
                part.set,
                part.chain,
                vec![Diagnostic::error(
                    format!(
                        "ECMP via {list} avec traduction d'adresse sur une branche : \
                         comparaison inter-branches non fiable, part indéterminée \
                         (prudence — jamais un verdict ferme erroné)"
                    ),
                    None,
                )],
            ));
            return;
        }

        // Recombinaison par verdict : l'accord est l'intersection des
        // unions par branche.
        let mut firm_union = HeaderSet::empty();
        for verdict in [
            Verdict::Allowed,
            Verdict::Denied,
            Verdict::NoRoute,
            Verdict::Loop,
            Verdict::Unknown,
        ] {
            let mut agreement: Option<HeaderSet> = None;
            for terms in &branch_terms {
                let u = terms
                    .iter()
                    .filter(|t| t.verdict == verdict)
                    .fold(HeaderSet::empty(), |acc, t| acc.union(&t.set));
                agreement = Some(match agreement {
                    None => u,
                    Some(a) => a.intersect(&u),
                });
            }
            let Some(agreement) = agreement else { continue };
            if agreement.is_empty() {
                continue;
            }
            let Some(first) = branch_terms.first() else {
                continue;
            };
            for t in first.iter().filter(|t| t.verdict == verdict) {
                let firm = t.set.intersect(&agreement);
                if firm.is_empty() {
                    continue;
                }
                let mut decisions = t.decisions.clone();
                decisions.insert(
                    base_chain_len.min(decisions.len()),
                    SymbolicDecision {
                        device: ctx.device.id.clone(),
                        decision: Decision {
                            stage: Stage::Route,
                            rule: None,
                            source: None,
                            outcome: Outcome::EcmpAgreed {
                                ifaces: ifaces.clone(),
                            },
                            shadowed_by: Vec::new(),
                        },
                    },
                );
                firm_union = firm_union.union(&firm);
                node.terminals.push(SymbolicVerdictSet {
                    verdict,
                    sample: firm.sample(),
                    set: firm,
                    decisions,
                    diagnostics: t.diagnostics.clone(),
                });
            }
        }

        // Le reste : les branches divergent → `Unknown` diagnostiqué avec
        // les interfaces en cause.
        let rem = part.set.subtract(&firm_union);
        if !rem.is_empty() {
            let mut chain2 = part.chain;
            chain2.push(SymbolicDecision {
                device: ctx.device.id.clone(),
                decision: Decision {
                    stage: Stage::Route,
                    rule: None,
                    source: None,
                    outcome: Outcome::EcmpDiverged { ifaces },
                    shadowed_by: Vec::new(),
                },
            });
            node.terminals.push(terminal(
                Verdict::Unknown,
                rem,
                chain2,
                vec![Diagnostic::error(
                    format!(
                        "routes multiples et divergentes (ECMP) via {list} : verdicts \
                         divergents selon la branche — part indéterminée (§6.3)"
                    ),
                    None,
                )],
            ));
        }
    }

    /// La destination est sur le réseau connecté de sortie : les adresses
    /// portées par des équipements modélisés y entrent (leurs filtres
    /// s'appliquent), le reste est un hôte atteint (`Allowed`).
    fn deliver_connected(
        &mut self,
        node: &mut SymbolicNode,
        ctx: &DeviceCtx<'_>,
        out_iface_id: &IfaceId,
        connected: &PrefixSet,
        fp: FlowPart,
    ) {
        let network = self.network;
        // Adresses du réseau connecté portées par un équipement modélisé.
        let mut owners: BTreeMap<IpAddr, Vec<Endpoint>> = BTreeMap::new();
        for d in network.devices.values() {
            for i in d.interfaces.values() {
                if i.state != AdminState::Up {
                    continue;
                }
                for a in &i.addrs {
                    if connected.contains_ip(&a.addr()) {
                        owners.entry(a.addr()).or_default().push(Endpoint {
                            device: d.id.clone(),
                            iface: i.id.clone(),
                        });
                    }
                }
            }
        }
        let mut rest = fp.set.clone();
        for (addr, ends) in owners {
            if rest.is_empty() {
                break;
            }
            let single = dst_restriction(&PrefixSet::from_net(IpNet::from(addr)));
            let sub = rest.intersect(&single);
            if sub.is_empty() {
                continue;
            }
            rest = rest.subtract(&single);
            if ends.len() > 1 {
                node.terminals.push(terminal(
                    Verdict::Unknown,
                    sub,
                    fp.chain.clone(),
                    vec![Diagnostic::error(
                        format!("adresse {addr} portée par plusieurs équipements : modèle ambigu"),
                        None,
                    )],
                ));
                continue;
            }
            let end = &ends[0];
            if end.device == ctx.device.id {
                // Adresse du présent équipement : déjà couverte par la
                // livraison locale en amont ; par prudence, atteinte.
                node.terminals.push(terminal(
                    Verdict::Allowed,
                    sub,
                    fp.chain.clone(),
                    Vec::new(),
                ));
                continue;
            }
            let child = self.propagate(
                &end.device,
                &end.iface,
                sub.clone(),
                ctx.visited,
                &fp.chain,
                ctx.depth + 1,
            );
            node.branches.push(SymbolicBranch {
                out_iface: out_iface_id.clone(),
                set_out: sub,
                child: Box::new(child),
            });
        }
        // Hôtes non modélisés du réseau connecté : atteints.
        if !rest.is_empty() {
            node.terminals
                .push(terminal(Verdict::Allowed, rest, fp.chain, Vec::new()));
        }
    }

    /// Traverse le lien physique vers l'équipement voisin — ou, s'il n'y a
    /// AUCUN lien, applique le critère de sortie de périmètre (même
    /// sémantique que le moteur concret, voir l'en-tête du module) : les
    /// destinations hors de tout réseau modélisé SORTENT (`Allowed` +
    /// décision `ExitsModel`), celles couvertes par un réseau modélisé
    /// restent un trou de topologie interne (`Unknown`).
    fn traverse_link(
        &mut self,
        node: &mut SymbolicNode,
        ctx: &DeviceCtx<'_>,
        out_iface_id: &IfaceId,
        gateway: Option<IpAddr>,
        fp: FlowPart,
    ) {
        let network = self.network;
        let mut peers: Vec<&Endpoint> = Vec::new();
        for link in &network.links {
            if link.a.device == ctx.device.id && link.a.iface == *out_iface_id {
                peers.push(&link.b);
            } else if link.b.device == ctx.device.id && link.b.iface == *out_iface_id {
                peers.push(&link.a);
            }
        }
        let peer = match peers.len() {
            0 => {
                let (inside, outside) = if self.model_nets.is_empty() {
                    (HeaderSet::empty(), fp.set.clone())
                } else {
                    let model_hs = dst_restriction(&self.model_nets);
                    (fp.set.intersect(&model_hs), fp.set.subtract(&model_hs))
                };
                if !inside.is_empty() {
                    // Trou de topologie INTERNE : jamais « autorisé » (§6.3).
                    node.terminals.push(terminal(
                        Verdict::Unknown,
                        inside,
                        fp.chain.clone(),
                        vec![Diagnostic::error(
                            format!(
                                "topologie incomplète : aucun lien depuis \
                                 {}/{out_iface_id} et destinations dans le périmètre \
                                 modélisé",
                                ctx.device.id
                            ),
                            None,
                        )],
                    ));
                }
                if !outside.is_empty() {
                    // SORTIE DE PÉRIMÈTRE : verdict ferme, décision explicite.
                    let mut chain2 = fp.chain;
                    chain2.push(SymbolicDecision {
                        device: ctx.device.id.clone(),
                        decision: Decision {
                            stage: Stage::Route,
                            rule: None,
                            source: None,
                            outcome: Outcome::ExitsModel {
                                iface: out_iface_id.clone(),
                                gateway,
                            },
                            shadowed_by: Vec::new(),
                        },
                    });
                    node.terminals
                        .push(terminal(Verdict::Allowed, outside, chain2, Vec::new()));
                }
                return;
            }
            1 => peers[0],
            _ => {
                node.terminals.push(terminal(
                    Verdict::Unknown,
                    fp.set,
                    fp.chain,
                    vec![Diagnostic::error(
                        format!(
                            "topologie ambiguë : plusieurs liens depuis {}/{out_iface_id}",
                            ctx.device.id
                        ),
                        None,
                    )],
                ));
                return;
            }
        };
        let peer_up = network
            .devices
            .get(&peer.device)
            .and_then(|d| d.interfaces.get(&peer.iface))
            .map(|i| i.state == AdminState::Up);
        match peer_up {
            Some(true) => {
                let child = self.propagate(
                    &peer.device,
                    &peer.iface,
                    fp.set.clone(),
                    ctx.visited,
                    &fp.chain,
                    ctx.depth + 1,
                );
                node.branches.push(SymbolicBranch {
                    out_iface: out_iface_id.clone(),
                    set_out: fp.set,
                    child: Box::new(child),
                });
            }
            Some(false) => node.terminals.push(terminal(
                Verdict::Unknown,
                fp.set,
                fp.chain,
                vec![Diagnostic::error(
                    format!(
                        "l'extrémité distante {}/{} est désactivée",
                        peer.device, peer.iface
                    ),
                    None,
                )],
            )),
            None => node.terminals.push(terminal(
                Verdict::Unknown,
                fp.set,
                fp.chain,
                vec![Diagnostic::error(
                    format!(
                        "l'extrémité distante {}/{} est absente du modèle",
                        peer.device, peer.iface
                    ),
                    None,
                )],
            )),
        }
    }
}

// ---------------------------------------------------------------------------
// Aides
// ---------------------------------------------------------------------------

/// Partition de l'espace destination par plus long préfixe correspondant
/// dans le VRF (routes déclarées + routes connectées dérivées, départage
/// par métrique — même sémantique que `route.rs`). Les régions rendues sont
/// deux à deux disjointes ; les destinations hors de toute région n'ont
/// aucune route.
fn partition_routes(device: &Device, vrf_id: &VrfId) -> Vec<(PrefixSet, RouteKind)> {
    struct Cand {
        metric: u32,
        next_hop: NextHop,
        source: Option<SourceSpan>,
    }
    let mut groups: BTreeMap<IpNet, Vec<Cand>> = BTreeMap::new();
    if let Some(vrf) = device.vrfs.get(vrf_id) {
        for route in &vrf.routes {
            groups.entry(route.prefix.trunc()).or_default().push(Cand {
                metric: route.metric,
                next_hop: route.next_hop.clone(),
                source: route.source.clone(),
            });
        }
    }
    for iface in device.interfaces.values() {
        if iface.state != AdminState::Up || iface.vrf != *vrf_id {
            continue;
        }
        for addr in &iface.addrs {
            groups.entry(addr.trunc()).or_default().push(Cand {
                metric: 0,
                next_hop: NextHop::Interface(iface.id.clone()),
                source: None,
            });
        }
    }
    let prefixes: Vec<IpNet> = groups.keys().copied().collect();
    let mut out = Vec::new();
    for (prefix, cands) in &groups {
        // La région du préfixe P : P moins tous les préfixes candidats plus
        // longs (le plus long préfixe gagne ; les préfixes disjoints ne
        // retirent rien).
        let longer = PrefixSet::from_nets(
            prefixes
                .iter()
                .copied()
                .filter(|p| p.prefix_len() > prefix.prefix_len()),
        );
        let region = PrefixSet::from_net(*prefix).subtract(&longer);
        if region.is_empty() {
            continue;
        }
        let Some(best_metric) = cands.iter().map(|c| c.metric).min() else {
            continue;
        };
        let winners: Vec<&Cand> = cands.iter().filter(|c| c.metric == best_metric).collect();
        let Some(first) = winners.first() else {
            continue;
        };
        // Prochains sauts DISTINCTS parmi les meilleures routes (l'ordre de
        // la table est conservé ; les doublons comptent pour un).
        let mut distinct: Vec<&Cand> = Vec::new();
        for c in &winners {
            if !distinct.iter().any(|d| d.next_hop == c.next_hop) {
                distinct.push(c);
            }
        }
        let kind = if distinct.len() > 1 {
            // ECMP : chaque candidate devient une branche (même sémantique
            // que le moteur concret, mêmes bornes).
            if distinct.len() > MAX_ECMP_ROUTES {
                RouteKind::Undecidable {
                    message: format!(
                        "{} routes optimales divergentes pour le préfixe {prefix} : \
                         au-delà de la borne de {MAX_ECMP_ROUTES} branches évaluées",
                        distinct.len()
                    ),
                }
            } else if distinct.iter().any(|c| c.next_hop == NextHop::Drop) {
                RouteKind::Undecidable {
                    message: format!(
                        "routes optimales mêlant transfert et rejet pour le préfixe \
                         {prefix} : modèle incohérent"
                    ),
                }
            } else {
                let mut routes = Vec::with_capacity(distinct.len());
                let mut fail: Option<String> = None;
                for c in &distinct {
                    match resolve_forward(device, vrf_id, &c.next_hop, prefix) {
                        Ok((out_iface, gateway)) => routes.push(EcmpRoute {
                            out_iface,
                            gateway,
                            source: c.source.clone(),
                        }),
                        Err(message) => {
                            fail = Some(message);
                            break;
                        }
                    }
                }
                match fail {
                    Some(message) => RouteKind::Undecidable { message },
                    None => RouteKind::Ecmp { routes },
                }
            }
        } else {
            match &first.next_hop {
                NextHop::Drop => RouteKind::Blackhole {
                    source: first.source.clone(),
                },
                other => match resolve_forward(device, vrf_id, other, prefix) {
                    Ok((out_iface, gateway)) => RouteKind::Forward {
                        out_iface,
                        gateway,
                        source: first.source.clone(),
                    },
                    Err(message) => RouteKind::Undecidable { message },
                },
            }
        };
        out.push((region, kind));
    }
    out
}

/// Résout un prochain saut de TRANSFERT (jamais `Drop`) en interface de
/// sortie + passerelle éventuelle ; message d'indécidabilité sinon (même
/// règle que `route.rs`).
fn resolve_forward(
    device: &Device,
    vrf_id: &VrfId,
    next_hop: &NextHop,
    prefix: &IpNet,
) -> Result<(IfaceId, Option<IpAddr>), String> {
    match next_hop {
        NextHop::Drop => Err(format!(
            "route de rejet inattendue au transfert (préfixe {prefix})"
        )),
        NextHop::Interface(iface_id) => {
            let up = device
                .interfaces
                .get(iface_id)
                .map(|i| i.state == AdminState::Up)
                .unwrap_or(false);
            if up {
                Ok((iface_id.clone(), None))
            } else {
                Err(format!(
                    "la route {prefix} pointe vers l'interface « {iface_id} » \
                     absente ou désactivée"
                ))
            }
        }
        NextHop::Ip(gw) => match resolve_gateway(device, vrf_id, gw) {
            Some(out_iface) => Ok((out_iface, Some(*gw))),
            None => Err(format!(
                "prochain saut {gw} injoignable : aucune interface active du VRF \
                 « {vrf_id} » ne porte un réseau le contenant"
            )),
        },
    }
}

/// Les réseaux portés par les interfaces ACTIVES du modèle : la moitié
/// « destination » du critère de sortie de périmètre (voir `engine.rs`).
fn model_networks(network: &Network) -> PrefixSet {
    PrefixSet::from_nets(
        network
            .devices
            .values()
            .flat_map(|d| d.interfaces.values())
            .filter(|i| i.state == AdminState::Up)
            .flat_map(|i| i.addrs.iter().map(|a| a.trunc())),
    )
}

/// L'interface de sortie vers un prochain saut IP (même règle que
/// `route.rs` : plus long réseau connecté du VRF qui le contient).
fn resolve_gateway(device: &Device, vrf_id: &VrfId, gw: &IpAddr) -> Option<IfaceId> {
    let mut best: Option<(u8, IfaceId)> = None;
    for iface in device.interfaces.values() {
        if iface.state != AdminState::Up || iface.vrf != *vrf_id {
            continue;
        }
        for addr in &iface.addrs {
            if addr.contains(gw) {
                let len = addr.prefix_len();
                let better = match &best {
                    Some((blen, _)) => len > *blen,
                    None => true,
                };
                if better {
                    best = Some((len, iface.id.clone()));
                }
            }
        }
    }
    best.map(|(_, i)| i)
}

/// La zone d'une interface : champ de l'interface, sinon la table des zones
/// de l'équipement (même règle que `engine.rs`).
fn zone_of(device: &Device, iface_id: &IfaceId) -> Option<ZoneId> {
    if let Some(iface) = device.interfaces.get(iface_id) {
        if iface.zone.is_some() {
            return iface.zone.clone();
        }
    }
    device
        .zones
        .iter()
        .find(|(_, members)| members.contains(iface_id))
        .map(|(zone, _)| zone.clone())
}

/// L'espace entier restreint à `dst ∈ prefixes`.
fn dst_restriction(prefixes: &PrefixSet) -> HeaderSet {
    HeaderSet::from_cube(Cube::new(
        PrefixSet::full(),
        prefixes.clone(),
        ProtoSet::full(),
        PortRanges::full(),
        PortRanges::full(),
    ))
}

/// DNAT symbolique : la dimension destination devient le singleton cible
/// (et le port destination, s'il est fixé). Voir les limites en tête de
/// module.
fn rewrite_dst(set: &HeaderSet, addr: IpAddr, port: Option<u16>) -> HeaderSet {
    HeaderSet::from_cubes(set.cubes().iter().map(|c| {
        let mut c = c.clone();
        c.dst = PrefixSet::from_net(IpNet::from(addr));
        if let Some(p) = port {
            c.dport = PortRanges::single(p);
        }
        c
    }))
}

/// SNAT symbolique : la dimension source devient le singleton représentatif
/// du pool. Voir les limites en tête de module.
fn rewrite_src(set: &HeaderSet, addr: IpAddr) -> HeaderSet {
    HeaderSet::from_cubes(set.cubes().iter().map(|c| {
        let mut c = c.clone();
        c.src = PrefixSet::from_net(IpNet::from(addr));
        c
    }))
}

fn nat_decision(rule: Option<RuleId>, source: Option<SourceSpan>) -> Decision {
    Decision {
        stage: Stage::Nat,
        rule,
        source,
        outcome: Outcome::Rewritten,
        shadowed_by: Vec::new(),
    }
}

fn terminal(
    verdict: Verdict,
    set: HeaderSet,
    decisions: Vec<SymbolicDecision>,
    diagnostics: Vec<Diagnostic>,
) -> SymbolicVerdictSet {
    let sample = set.sample();
    SymbolicVerdictSet {
        verdict,
        set,
        decisions,
        diagnostics,
        sample,
    }
}

// ---------------------------------------------------------------------------
// Tests : cohérence symbolique/concret (§4.3), embranchements, boucles, NAT.
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::trace_packet;
    use crate::testutil::{
        base_network, iface, ip, net, rule, standard_rules, tcp_svc, with_fw1_egress,
    };
    use calque_model::{
        Action, AddrExpr, DnatTarget, NatAction, PolicyId, PortRange, Route, RouteOrigin,
    };

    fn entry(device: &str, ifname: &str) -> Endpoint {
        Endpoint {
            device: DeviceId::new(device),
            iface: IfaceId::new(ifname),
        }
    }

    fn set_src_dst(src: &str, dst: &str) -> HeaderSet {
        HeaderSet::from_cube(Cube::new(
            PrefixSet::from_net(net(src)),
            PrefixSet::from_net(net(dst)),
            ProtoSet::full(),
            PortRanges::full(),
            PortRanges::full(),
        ))
    }

    fn union_of(sets: &[&SymbolicVerdictSet]) -> HeaderSet {
        sets.iter()
            .fold(HeaderSet::empty(), |acc, s| acc.union(&s.set))
    }

    /// LE test (§4.3) : le symbolique et le concret doivent s'accorder.
    /// Chaque paquet échantillonné d'un sous-ensemble terminal doit recevoir
    /// le même verdict du moteur concret.
    #[test]
    fn coherence_symbolique_concret() {
        let network = with_fw1_egress(standard_rules(), Action::Deny);
        let start = set_src_dst("10.0.10.0/24", "10.0.20.0/24");
        let trace = symbolic_trace_from(&network, &entry("fw1", "lan"), &start);
        let sets = trace.verdict_sets();
        assert!(!sets.is_empty());

        // L'arbre est une PARTITION de l'entrée : rien de perdu, rien
        // d'inventé.
        let union = union_of(&sets);
        assert!(union.contains_set(&start) && start.contains_set(&union));

        // Chaque pavé de chaque sous-ensemble fournit un paquet témoin,
        // rejoué dans le moteur concret.
        let mut checked = 0;
        for vs in &sets {
            for cube in vs.set.cubes() {
                let pkt = cube.sample().expect("pavé non vide");
                let concrete = trace_packet(&network, &pkt);
                assert_eq!(
                    concrete.verdict, vs.verdict,
                    "désaccord symbolique/concret sur {pkt:?}"
                );
                checked += 1;
            }
        }
        assert!(checked >= 3, "trop peu de paquets vérifiés ({checked})");

        // L'ensemble Allowed est EXACTEMENT le flux de la règle 10.
        let allowed = union_of(&trace.sets_with(Verdict::Allowed));
        let expected = HeaderSet::flow(
            net("10.0.10.0/24"),
            net("10.0.20.5/32"),
            6,
            PortRange::single(445),
        );
        assert!(allowed.contains_set(&expected) && expected.contains_set(&allowed));
    }

    /// Un embranchement de routage scinde l'ensemble en deux branches aux
    /// verdicts différents : refus local vers la DMZ, autorisation via fw2.
    #[test]
    fn embranchement_scinde_en_deux_verdicts() {
        let mut network = with_fw1_egress(
            vec![rule(
                "60",
                vec![],
                vec![AddrExpr::Net(net("10.0.40.0/24"))],
                vec![],
                None,
                None,
                Action::Deny,
                600,
            )],
            Action::Accept,
        );
        let fw1 = network.devices.get_mut(&DeviceId::new("fw1")).expect("fw1");
        let dmz2 = iface("dmz2", "10.0.40.1/24", Some("dmz2"));
        fw1.interfaces.insert(dmz2.id.clone(), dmz2);

        let start = HeaderSet::from_cubes([
            Cube::from_flow(
                net("10.0.10.0/24"),
                net("10.0.20.0/24"),
                6,
                PortRange::single(445),
            ),
            Cube::from_flow(
                net("10.0.10.0/24"),
                net("10.0.40.0/24"),
                6,
                PortRange::single(445),
            ),
        ]);
        let trace = symbolic_trace_from(&network, &entry("fw1", "lan"), &start);

        // Partition complète.
        let union = union_of(&trace.verdict_sets());
        assert!(union.contains_set(&start) && start.contains_set(&union));

        // Une seule branche (vers fw2) ; le refus DMZ est terminal sur fw1.
        let root = trace.root.as_ref().expect("racine");
        assert_eq!(root.branches.len(), 1);
        assert_eq!(root.branches[0].child.device, DeviceId::new("fw2"));

        // Refusé : la DMZ, moins l'adresse propre de fw1 (livrée localement).
        let denied = union_of(&trace.sets_with(Verdict::Denied));
        let dmz_flow = HeaderSet::flow(
            net("10.0.10.0/24"),
            net("10.0.40.0/24"),
            6,
            PortRange::single(445),
        );
        let own = HeaderSet::flow(
            net("10.0.10.0/24"),
            net("10.0.40.1/32"),
            6,
            PortRange::single(445),
        );
        let expected_denied = dmz_flow.subtract(&own);
        assert!(denied.contains_set(&expected_denied) && expected_denied.contains_set(&denied));

        // Autorisé : tout le flux vers 10.0.20.0/24 (via fw2), plus
        // l'adresse propre 10.0.40.1.
        let allowed = union_of(&trace.sets_with(Verdict::Allowed));
        let expected_allowed = HeaderSet::flow(
            net("10.0.10.0/24"),
            net("10.0.20.0/24"),
            6,
            PortRange::single(445),
        )
        .union(&own);
        assert!(allowed.contains_set(&expected_allowed) && expected_allowed.contains_set(&allowed));

        // Cohérence concrète des deux côtés de l'embranchement.
        for vs in trace.verdict_sets() {
            let pkt = vs.sample.expect("terminal non vide");
            assert_eq!(trace_packet(&network, &pkt).verdict, vs.verdict);
        }
    }

    #[test]
    fn boucle_detectee_symboliquement() {
        let mut network = base_network();
        for (dev, gw) in [("fw1", "192.168.0.2"), ("fw2", "192.168.0.1")] {
            network
                .devices
                .get_mut(&DeviceId::new(dev))
                .and_then(|d| d.vrfs.get_mut(&VrfId::default_vrf()))
                .expect("vrf")
                .routes
                .push(Route {
                    prefix: net("10.0.30.0/24"),
                    next_hop: NextHop::Ip(ip(gw)),
                    metric: 10,
                    origin: RouteOrigin::Static,
                    source: None,
                });
        }
        let start = set_src_dst("10.0.10.0/24", "10.0.30.0/24");
        let trace = symbolic_trace_from(&network, &entry("fw1", "lan"), &start);
        let loops = trace.sets_with(Verdict::Loop);
        assert_eq!(loops.len(), 1);
        // Tout l'ensemble boucle.
        assert!(loops[0].set.contains_set(&start) && start.contains_set(&loops[0].set));
        assert!(!loops[0].diagnostics.is_empty());
    }

    #[test]
    fn dnat_symbolique_reecrit_la_destination() {
        let mut network = base_network();
        let fw1 = network.devices.get_mut(&DeviceId::new("fw1")).expect("fw1");
        let pid = PolicyId::new("fw1-vip");
        fw1.policies.insert(
            pid.clone(),
            calque_model::Policy {
                id: pid.clone(),
                rules: vec![rule(
                    "1",
                    vec![],
                    vec![AddrExpr::Net(net("203.0.113.10/32"))],
                    vec![tcp_svc(80)],
                    None,
                    None,
                    Action::Nat(NatAction {
                        snat: None,
                        dnat: Some(DnatTarget {
                            addr: ip("10.0.20.5"),
                            port: Some(8080),
                        }),
                    }),
                    300,
                )],
                default_action: Action::Accept,
            },
        );
        fw1.pipeline.ingress.push(pid);

        let start = HeaderSet::flow(
            net("10.0.10.0/24"),
            net("203.0.113.10/32"),
            6,
            PortRange::single(80),
        );
        let trace = symbolic_trace_from(&network, &entry("fw1", "lan"), &start);
        let allowed = trace.sets_with(Verdict::Allowed);
        assert_eq!(allowed.len(), 1);
        // L'ensemble terminal est exprimé APRÈS traduction.
        let expected = HeaderSet::flow(
            net("10.0.10.0/24"),
            net("10.0.20.5/32"),
            6,
            PortRange::single(8080),
        );
        assert!(allowed[0].set.contains_set(&expected) && expected.contains_set(&allowed[0].set));
        // La chaîne de décisions porte la réécriture et sa règle.
        let nat = allowed[0]
            .decisions
            .iter()
            .find(|d| d.decision.stage == Stage::Nat)
            .expect("décision NAT");
        assert_eq!(nat.decision.outcome, Outcome::Rewritten);
        assert_eq!(nat.decision.rule, Some(RuleId::new("1")));
        // Cohérence concrète.
        let pkt = allowed[0].sample.expect("non vide");
        // Le paquet témoin est post-NAT : rejouer l'original correspondant.
        let mut original = pkt;
        original.dst = ip("203.0.113.10");
        original.dport = 80;
        assert_eq!(trace_packet(&network, &original).verdict, Verdict::Allowed);
    }

    #[test]
    fn point_d_entree_invalide_et_ensemble_vide() {
        let network = base_network();
        let t = symbolic_trace_from(&network, &entry("fw1", "absente"), &HeaderSet::full());
        assert!(t.root.is_none() && !t.diagnostics.is_empty());
        let t = symbolic_trace_from(&network, &entry("fw1", "lan"), &HeaderSet::empty());
        assert!(t.root.is_none() && !t.diagnostics.is_empty());
    }

    // -----------------------------------------------------------------------
    // Sortie de périmètre et ECMP : même sémantique que le moteur concret,
    // vérifiée par rejeu concret de chaque pavé terminal (§4.3).
    // -----------------------------------------------------------------------

    use crate::testutil::{ecmp_network, single_device_network, with_fw_egress};

    /// Rejoue dans le moteur concret un paquet témoin de chaque pavé de
    /// chaque terminal : les deux modes doivent s'accorder.
    fn assert_concrete_agreement(network: &Network, trace: &SymbolicTrace) -> usize {
        let mut checked = 0;
        for vs in trace.verdict_sets() {
            for cube in vs.set.cubes() {
                let pkt = cube.sample().expect("pavé non vide");
                assert_eq!(
                    trace_packet(network, &pkt).verdict,
                    vs.verdict,
                    "désaccord symbolique/concret sur {pkt:?}"
                );
                checked += 1;
            }
        }
        checked
    }

    /// (e) Sortie de périmètre : la part acceptée par le filtre et routée
    /// hors du modèle devient un terminal `Allowed` portant la décision
    /// `ExitsModel` ; le reste est refusé. Cohérence concrète rejouée.
    #[test]
    fn sortie_de_perimetre_symbolique_coherente_avec_le_concret() {
        let network = with_fw_egress(
            single_device_network(),
            vec![rule(
                "10",
                vec![AddrExpr::Net(net("10.0.10.0/24"))],
                vec![],
                vec![tcp_svc(443)],
                Some("lan"),
                Some("wan"),
                Action::Accept,
                100,
            )],
            Action::Deny,
        );
        let start = set_src_dst("10.0.10.0/24", "203.0.113.0/24");
        let trace = symbolic_trace_from(&network, &entry("fw", "lan"), &start);

        // Partition complète : rien de perdu, rien d'inventé.
        let union = union_of(&trace.verdict_sets());
        assert!(union.contains_set(&start) && start.contains_set(&union));

        // L'ensemble Allowed est EXACTEMENT le flux de la règle 10, et il
        // porte la décision de sortie de périmètre (wan1, passerelle).
        let allowed = trace.sets_with(Verdict::Allowed);
        assert!(!allowed.is_empty());
        let allowed_union = union_of(&allowed);
        let expected = HeaderSet::flow(
            net("10.0.10.0/24"),
            net("203.0.113.0/24"),
            6,
            calque_model::PortRange::single(443),
        );
        assert!(allowed_union.contains_set(&expected) && expected.contains_set(&allowed_union));
        for vs in &allowed {
            let exits = vs
                .decisions
                .iter()
                .find(|d| matches!(d.decision.outcome, Outcome::ExitsModel { .. }))
                .expect("décision ExitsModel");
            assert_eq!(
                exits.decision.outcome,
                Outcome::ExitsModel {
                    iface: IfaceId::new("wan1"),
                    gateway: Some(ip("198.51.100.1")),
                }
            );
        }
        // Aucune part indécidable : le périmètre modélisé répond fermement.
        assert!(trace.sets_with(Verdict::Unknown).is_empty());

        assert!(assert_concrete_agreement(&network, &trace) >= 2);
    }

    /// (e) ECMP dont toutes les branches s'accordent : verdict ferme, avec
    /// la décision `EcmpAgreed`. Cohérence concrète rejouée (le moteur
    /// concret évalue les mêmes branches).
    #[test]
    fn ecmp_symbolique_verdict_identique_est_ferme() {
        let network = with_fw_egress(ecmp_network(), vec![], Action::Accept);
        let start = set_src_dst("10.0.10.0/24", "8.8.8.0/24");
        let trace = symbolic_trace_from(&network, &entry("fw", "lan"), &start);

        let union = union_of(&trace.verdict_sets());
        assert!(union.contains_set(&start) && start.contains_set(&union));

        // Tout est autorisé, fermement, avec l'embranchement documenté.
        let allowed = trace.sets_with(Verdict::Allowed);
        let allowed_union = union_of(&allowed);
        assert!(allowed_union.contains_set(&start) && start.contains_set(&allowed_union));
        let vs = allowed.first().expect("terminal Allowed");
        assert!(vs.decisions.iter().any(|d| {
            d.decision.outcome
                == Outcome::EcmpAgreed {
                    ifaces: vec![IfaceId::new("wan1"), IfaceId::new("wan2")],
                }
        }));
        // La justification suit la première branche : sortie via wan1.
        assert!(vs.decisions.iter().any(|d| matches!(
            &d.decision.outcome,
            Outcome::ExitsModel { iface, .. } if *iface == IfaceId::new("wan1")
        )));

        assert!(assert_concrete_agreement(&network, &trace) >= 1);
    }

    /// (e) ECMP aux verdicts divergents (une branche filtrée en sortie,
    /// l'autre non) : la part devient `Unknown` diagnostiqué — et le moteur
    /// concret dit la même chose sur chaque paquet témoin.
    #[test]
    fn ecmp_symbolique_divergent_rend_unknown() {
        let network = with_fw_egress(
            ecmp_network(),
            vec![rule(
                "50",
                vec![],
                vec![],
                vec![],
                None,
                Some("wan2z"),
                Action::Deny,
                500,
            )],
            Action::Accept,
        );
        let start = set_src_dst("10.0.10.0/24", "8.8.8.0/24");
        let trace = symbolic_trace_from(&network, &entry("fw", "lan"), &start);

        let union = union_of(&trace.verdict_sets());
        assert!(union.contains_set(&start) && start.contains_set(&union));

        // Toute la part diverge : wan1 autorise (sortie de périmètre),
        // wan2 refuse (règle 50) → Unknown diagnostiqué.
        let unknown = trace.sets_with(Verdict::Unknown);
        let unknown_union = union_of(&unknown);
        assert!(unknown_union.contains_set(&start) && start.contains_set(&unknown_union));
        let vs = unknown.first().expect("terminal Unknown");
        assert!(vs.decisions.iter().any(|d| {
            d.decision.outcome
                == Outcome::EcmpDiverged {
                    ifaces: vec![IfaceId::new("wan1"), IfaceId::new("wan2")],
                }
        }));
        assert!(vs
            .diagnostics
            .iter()
            .any(|d| d.message.contains("divergentes")));

        assert!(assert_concrete_agreement(&network, &trace) >= 1);
    }
}
