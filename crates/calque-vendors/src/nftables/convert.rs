//! Conversion arbre générique → représentation intermédiaire pour
//! nftables. Voir l'en-tête de `mod.rs` pour les choix de modélisation.
//!
//! Discipline §6.3, appliquée partout dans ce module :
//! - une expression COMPRISE et porteuse de sens → mappée vers le modèle ;
//! - une expression COMPRISE et sans effet sur le verdict d'un flux
//!   initiateur (`counter`, `log`, `comment`, `ct state established…`) →
//!   acceptée explicitement, avec note `Info` quand une règle entière est
//!   écartée ;
//! - tout le reste → `Diagnostic` avec span, accumulé dans
//!   `Fidelity::Partial`. Jamais d'ignorance silencieuse.

use std::collections::BTreeMap;

use calque_model::{
    Action, AddrExpr, AddrObject, Device, DeviceId, Diagnostic, Fidelity, IfaceId, Interface,
    ObjectId, Policy, PolicyId, PortRange, ProtoMatch, Rule, RuleId, RuleMatch, Service,
    ServiceExpr, ServiceObject, Severity, SourceSpan, Vendor, ZoneId,
};

use super::values::{self, Family};
use crate::{directive_excerpt, AdapterOutput, ConfigNode, ConfigTree};

/// Rang d'accroche en entrée : les chaînes `input` avant les chaînes
/// `forward`, puis par priorité croissante, puis par ordre d'apparition.
const RANK_INPUT: u8 = 0;
const RANK_FORWARD: u8 = 1;

pub(super) fn convert(tree: &ConfigTree) -> Result<AdapterOutput, Vec<Diagnostic>> {
    if tree.roots.is_empty() {
        return Err(vec![Diagnostic::error(
            "configuration vide ou inexploitable : aucun énoncé reconnu",
            Some(SourceSpan::new(tree.file.as_str(), 1)),
        )]);
    }
    let mut conv = Converter::new(tree);
    conv.run(tree);
    Ok(conv.finish())
}

// ---------------------------------------------------------------------------
// Contexte d'une table
// ---------------------------------------------------------------------------

/// Ce que la passe 1 sait d'une chaîne (avant conversion des règles).
#[derive(Debug, Clone)]
struct ChainMeta {
    /// `Some` pour une chaîne de base (`type … hook … priority …`).
    base: Option<BaseMeta>,
}

#[derive(Debug, Clone)]
struct BaseMeta {
    typ: String,
    hook: String,
    priority: i64,
    /// `policy accept|drop`, absent = accept (comportement documenté de
    /// nftables, pas une supposition).
    policy: Option<Action>,
}

struct TableCtx {
    family: Family,
    /// Préfixe qualifiant les identifiants : `inet/filtre`.
    qual: String,
    chains: BTreeMap<String, ChainMeta>,
}

impl TableCtx {
    fn policy_id(&self, chain: &str) -> PolicyId {
        PolicyId::new(format!("{}/{chain}", self.qual))
    }
    fn object_id(&self, name: &str) -> ObjectId {
        ObjectId::new(format!("{}/{name}", self.qual))
    }
}

// ---------------------------------------------------------------------------
// Le convertisseur
// ---------------------------------------------------------------------------

struct Converter {
    device: Device,
    /// Ce qui n'a PAS été compris → `Fidelity::Partial` (§6.3).
    unsupported: Vec<Diagnostic>,
    /// Constats informatifs qui ne dégradent pas la fidélité.
    notes: Vec<Diagnostic>,
    /// Variables `define` : nom → valeurs brutes (jetons). Les variables
    /// d'adresses sont AUSSI enregistrées dans l'`ObjectStore` (résolution
    /// tardive, §3.3) sous leur nom.
    defines: BTreeMap<String, Vec<String>>,
    /// Ensembles nommés de ports (`type inet_service`), par identifiant
    /// qualifié. Le protocole n'est connu qu'à l'usage (`tcp dport @s`) :
    /// un objet service dérivé est créé à ce moment-là (voir mod.rs).
    port_sets: BTreeMap<String, Vec<PortRange>>,
    /// Accroches d'entrée : (rang, priorité, ordre d'apparition, politique).
    ingress: Vec<(u8, i64, usize, PolicyId)>,
    /// Accroches de sortie : (priorité, ordre d'apparition, politique).
    egress: Vec<(i64, usize, PolicyId)>,
    seq: usize,
}

impl Converter {
    fn new(tree: &ConfigTree) -> Self {
        // Un fichier nftables ne porte pas de nom d'hôte : l'identifiant
        // vient du nom de fichier.
        let id = DeviceId::new(file_stem(&tree.file));
        Self {
            device: Device::new(id, Vendor::Nftables),
            unsupported: Vec::new(),
            notes: Vec::new(),
            defines: BTreeMap::new(),
            port_sets: BTreeMap::new(),
            ingress: Vec::new(),
            egress: Vec::new(),
            seq: 0,
        }
    }

    fn finish(mut self) -> AdapterOutput {
        // Accroche des chaînes de base : `input` puis `forward` en
        // entrée, `output` en sortie, chaque groupe par priorité
        // croissante (ordre d'évaluation nftables entre chaînes d'un même
        // hook) puis par ordre d'apparition.
        self.ingress.sort();
        self.egress.sort();
        let has_input = self.ingress.iter().any(|(r, ..)| *r == RANK_INPUT);
        let has_forward = self.ingress.iter().any(|(r, ..)| *r == RANK_FORWARD);
        for (.., pid) in self.ingress.drain(..) {
            self.device.pipeline.ingress.push(pid);
        }
        for (.., pid) in self.egress.drain(..) {
            self.device.pipeline.egress.push(pid);
        }
        // Hôte ou routeur : dans le noyau, un paquet traverse `input` OU
        // `forward` selon qu'il est destiné à l'hôte ou en transit. Le
        // moteur évalue toutes les politiques d'entrée en séquence : quand
        // les DEUX chaînes existent, le modèle est donc PLUS RESTRICTIF
        // que l'équipement (jamais optimiste — un refus en trop plutôt
        // qu'une autorisation en trop). On le signale sans dégrader la
        // fidélité : chaque directive a bien été comprise.
        if has_input && has_forward {
            self.notes.push(Diagnostic::warning(
                "chaînes `input` et `forward` toutes deux accrochées en entrée : le modèle \
                 les évalue en séquence alors que le noyau n'en traverse qu'une selon que le \
                 trafic est destiné à l'hôte ou en transit ; le verdict est conservateur \
                 (jamais optimiste)",
                None,
            ));
        }
        let fidelity = if self.unsupported.is_empty() {
            Fidelity::Complete
        } else {
            Fidelity::Partial {
                unsupported: self.unsupported,
            }
        };
        AdapterOutput {
            device: self.device,
            fidelity,
            notes: self.notes,
        }
    }

    // -- accumulation de diagnostics ------------------------------------

    fn unsupported(&mut self, message: String, span: &SourceSpan) {
        self.unsupported
            .push(Diagnostic::warning(message, Some(span.clone())));
    }

    fn note_info(&mut self, message: String, span: &SourceSpan) {
        self.notes.push(Diagnostic {
            severity: Severity::Info,
            message,
            span: Some(span.clone()),
        });
    }

    fn note_warning(&mut self, message: String, span: &SourceSpan) {
        self.notes
            .push(Diagnostic::warning(message, Some(span.clone())));
    }

    // -- parcours de premier niveau -------------------------------------

    fn run(&mut self, tree: &ConfigTree) {
        for node in &tree.roots {
            match node.keyword.as_str() {
                "table" => self.table_block(node),
                "define" => self.define_stmt(node),
                "include" => self.unsupported(
                    "`include` non résolu (la lecture du fichier inclus est de \
                     l'entrée-sortie, hors de l'analyse pure) : modèle incomplet"
                        .to_owned(),
                    &node.span,
                ),
                "flush" if node.arg(0) == Some("ruleset") => self.note_info(
                    "`flush ruleset` compris : remise à zéro de l'état courant, sans effet \
                     sur un modèle construit hors ligne"
                        .to_owned(),
                    &node.span,
                ),
                _ => self.unsupported(
                    format!(
                        "directive de premier niveau `{}` non gérée",
                        directive_excerpt(&node.keyword, &node.args, 2)
                    ),
                    &node.span,
                ),
            }
        }
    }

    // -- define ----------------------------------------------------------

    /// `define nom = valeur` ou `define nom = { v1, v2 }`. Les variables
    /// d'adresses deviennent des objets (résolution tardive, §3.3) ; les
    /// variables de ports alimentent `port_sets` (objet service dérivé à
    /// l'usage) ; les autres restent des jetons bruts (interfaces…).
    fn define_stmt(&mut self, node: &ConfigNode) {
        let (Some(name), Some("=")) = (node.arg(0), node.arg(1)) else {
            self.unsupported(
                "`define` sans la forme `define nom = valeur`".to_owned(),
                &node.span,
            );
            return;
        };
        let values: Vec<String> = node.args[2..]
            .iter()
            .filter(|t| !matches!(t.as_str(), "{" | "}" | ","))
            .cloned()
            .collect();
        if values.is_empty() {
            self.unsupported(format!("`define {name}` sans valeur"), &node.span);
            return;
        }
        if values.iter().any(|v| v.starts_with('$')) {
            // Une variable qui en référence une autre : l'expansion en
            // cascade n'est pas gérée, on ne devine pas sa valeur finale.
            self.unsupported(
                format!("`define {name}` référence une autre variable : non géré"),
                &node.span,
            );
            return;
        }
        if self.defines.contains_key(name) {
            self.unsupported(
                format!(
                    "variable `{name}` redéfinie : la nouvelle définition remplace la première"
                ),
                &node.span,
            );
        }
        let nets: Vec<_> = values.iter().filter_map(|v| values::parse_net(v)).collect();
        if nets.len() == values.len() {
            self.device
                .objects
                .addresses
                .insert(ObjectId::new(name), AddrObject::Nets(nets));
        } else {
            let ports: Vec<_> = values
                .iter()
                .filter_map(|v| values::parse_port_range(v))
                .collect();
            if ports.len() == values.len() {
                self.port_sets.insert(name.to_owned(), ports);
            }
            // Sinon : valeurs libres (noms d'interface…), utilisables là
            // où un jeton brut suffit ; un usage inadapté est diagnostiqué
            // au point d'usage.
        }
        self.defines.insert(name.to_owned(), values);
    }

    // -- table -----------------------------------------------------------

    fn table_block(&mut self, node: &ConfigNode) {
        let (Some(family_str), Some(name)) = (node.arg(0), node.arg(1)) else {
            self.unsupported("`table` sans famille ou sans nom".to_owned(), &node.span);
            return;
        };
        let family = match family_str {
            "ip" => Family::V4,
            "ip6" => Family::V6,
            "inet" => Family::Both,
            // arp/bridge/netdev filtrent hors du modèle IP de Calque.
            "arp" | "bridge" | "netdev" => {
                self.unsupported(
                    format!("table `{family_str} {name}` hors modèle (famille non IP) : ignorée"),
                    &node.span,
                );
                return;
            }
            other => {
                self.unsupported(
                    format!("famille de table `{other}` inconnue : table `{name}` ignorée"),
                    &node.span,
                );
                return;
            }
        };

        // Passe 1 : recenser les chaînes — les sauts se résolvent ainsi
        // quel que soit l'ordre de déclaration dans le fichier.
        let mut chains: BTreeMap<String, ChainMeta> = BTreeMap::new();
        for child in node.children_named("chain") {
            let Some(cname) = child.arg(0) else {
                self.unsupported("`chain` sans nom".to_owned(), &child.span);
                continue;
            };
            if child.args.len() > 1 {
                self.unsupported(
                    format!("arguments inattendus après `chain {cname}`"),
                    &child.span,
                );
            }
            if chains.contains_key(cname) {
                self.unsupported(
                    format!(
                        "chaîne `{cname}` redéfinie dans la table `{name}` : le second bloc \
                         est ignoré (l'équipement réel concaténerait les règles)"
                    ),
                    &child.span,
                );
                continue;
            }
            let meta = self.chain_meta(cname, child);
            chains.insert(cname.to_owned(), meta);
        }
        let ctx = TableCtx {
            family,
            qual: format!("{family_str}/{name}"),
            chains,
        };

        // Membres non-chaîne de la table.
        for child in &node.children {
            match child.keyword.as_str() {
                "chain" => {}
                "set" => self.set_block(&ctx, child),
                "define" => self.define_stmt(child),
                "include" => self.unsupported(
                    "`include` non résolu (entrée-sortie hors analyse) : modèle incomplet"
                        .to_owned(),
                    &child.span,
                ),
                // Compris, sans effet sur le verdict d'un flux initiateur.
                "counter" => self.note_info(
                    format!(
                        "compteur nommé `{}` : comptage seul, sans effet sur le verdict",
                        child.arg(0).unwrap_or("?")
                    ),
                    &child.span,
                ),
                "flowtable" => self.note_info(
                    format!(
                        "flowtable `{}` : accélère les flux ÉTABLIS, sans effet sur le \
                         verdict d'un flux initiateur (analyse sans état)",
                        child.arg(0).unwrap_or("?")
                    ),
                    &child.span,
                ),
                "quota" | "limit" => self.note_info(
                    format!(
                        "`{} {}` : déclaration seule, sans effet ; toute règle qui la \
                         référence sera diagnostiquée",
                        child.keyword,
                        child.arg(0).unwrap_or("?")
                    ),
                    &child.span,
                ),
                // Les correspondances portent des verdicts : les ignorer
                // fausserait le modèle.
                "map" => self.unsupported(
                    format!(
                        "correspondance `map {}` non modélisée (elle porte des valeurs ou \
                         des verdicts)",
                        child.arg(0).unwrap_or("?")
                    ),
                    &child.span,
                ),
                _ => self.unsupported(
                    format!(
                        "`{}` non géré dans la table `{name}`",
                        directive_excerpt(&child.keyword, &child.args, 2)
                    ),
                    &child.span,
                ),
            }
        }

        // Passe 2 : conversion des chaînes, dans l'ordre du fichier.
        for child in node.children_named("chain") {
            if let Some(cname) = child.arg(0) {
                if ctx.chains.contains_key(cname) {
                    self.chain_block(&ctx, cname, child);
                }
            }
        }
    }

    /// Lit les métadonnées d'une chaîne (`type … hook … priority …` et
    /// `policy …`) sans toucher aux règles.
    fn chain_meta(&mut self, cname: &str, node: &ConfigNode) -> ChainMeta {
        let mut base: Option<BaseMeta> = None;
        let mut policy: Option<Action> = None;
        for d in &node.children {
            match d.keyword.as_str() {
                "type" => {
                    if base.is_some() {
                        self.unsupported(
                            format!("chaîne `{cname}` : plusieurs énoncés `type`"),
                            &d.span,
                        );
                        continue;
                    }
                    base = self.parse_base(cname, d);
                }
                "policy" => match d.arg(0) {
                    Some("accept") => policy = Some(Action::Accept),
                    Some("drop") => policy = Some(Action::Deny),
                    other => self.unsupported(
                        format!(
                            "politique par défaut `{}` inconnue sur la chaîne `{cname}`",
                            other.unwrap_or("?")
                        ),
                        &d.span,
                    ),
                },
                _ => {}
            }
        }
        if let Some(b) = &mut base {
            b.policy = policy;
        } else if policy.is_some() {
            // `policy` sans `type` : nftables le refuse ; on ne devine
            // pas à quel hook ce serait accroché.
            self.unsupported(
                format!("`policy` sur la chaîne régulière `{cname}` (sans `type … hook …`)"),
                &node.span,
            );
        }
        ChainMeta { base }
    }

    /// `type filter hook input priority 0` → métadonnées de chaîne de base.
    fn parse_base(&mut self, cname: &str, d: &ConfigNode) -> Option<BaseMeta> {
        let Some(typ) = d.arg(0).map(str::to_owned) else {
            self.unsupported(
                format!("chaîne `{cname}` : énoncé `type` sans valeur"),
                &d.span,
            );
            return None;
        };
        let args: Vec<&str> = d.args.iter().map(String::as_str).collect();
        let hook = args
            .iter()
            .position(|&t| t == "hook")
            .and_then(|i| args.get(i + 1))
            .map(|s| (*s).to_owned());
        let prio_token = args
            .iter()
            .position(|&t| t == "priority")
            .and_then(|i| args.get(i + 1));
        let Some(hook) = hook else {
            self.unsupported(
                format!("chaîne `{cname}` : énoncé `type` sans `hook`"),
                &d.span,
            );
            return None;
        };
        let priority = match prio_token {
            Some(tok) => match values::parse_priority(tok) {
                Some(p) => p,
                None => {
                    self.unsupported(
                        format!(
                            "chaîne `{cname}` : priorité `{tok}` inanalysable (0 retenu \
                                 pour l'ordre d'accroche)"
                        ),
                        &d.span,
                    );
                    0
                }
            },
            None => {
                self.unsupported(
                    format!("chaîne `{cname}` : énoncé `type` sans `priority`"),
                    &d.span,
                );
                0
            }
        };
        Some(BaseMeta {
            typ,
            hook,
            priority,
            policy: None,
        })
    }

    // -- set ---------------------------------------------------------------

    fn set_block(&mut self, ctx: &TableCtx, node: &ConfigNode) {
        let Some(name) = node.arg(0) else {
            self.unsupported("`set` sans nom".to_owned(), &node.span);
            return;
        };
        let mut typ: Option<String> = None;
        let mut elements: Vec<String> = Vec::new();
        let mut broken = false;

        for d in &node.children {
            match d.keyword.as_str() {
                "type" => {
                    if d.args.len() > 1 {
                        // `type ipv4_addr . inet_service` : concaténation,
                        // hors modèle.
                        self.unsupported(
                            format!("ensemble `{name}` : type concaténé non géré"),
                            &d.span,
                        );
                        broken = true;
                    } else {
                        typ = d.arg(0).map(str::to_owned);
                    }
                }
                "flags" => {
                    for flag in d.args.iter().filter(|t| t.as_str() != ",") {
                        match flag.as_str() {
                            // Sans effet sur la valeur des éléments.
                            "interval" | "constant" => {}
                            "timeout" => self.note_info(
                                format!(
                                    "ensemble `{name}` : éléments à expiration, modèle figé \
                                     à l'import"
                                ),
                                &d.span,
                            ),
                            // Un ensemble dynamique est rempli à
                            // l'exécution : son contenu est inconnaissable
                            // hors ligne.
                            other => {
                                self.unsupported(
                                    format!(
                                        "ensemble `{name}` : drapeau `{other}` non géré \
                                         (contenu défini à l'exécution ?)"
                                    ),
                                    &d.span,
                                );
                                broken = true;
                            }
                        }
                    }
                }
                "elements" => {
                    // Forme attendue : `= { v1, v2, … }`.
                    let ok = d.arg(0) == Some("=")
                        && d.arg(1) == Some("{")
                        && d.args.last().map(String::as_str) == Some("}");
                    if !ok {
                        self.unsupported(
                            format!("ensemble `{name}` : forme `elements` inattendue"),
                            &d.span,
                        );
                        broken = true;
                        continue;
                    }
                    elements = d.args[2..d.args.len() - 1]
                        .iter()
                        .filter(|t| t.as_str() != ",")
                        .cloned()
                        .collect();
                }
                // Compris, sans effet sur les éléments.
                "size" | "auto-merge" | "comment" | "policy" | "gc-interval" => {}
                "timeout" => self.note_info(
                    format!("ensemble `{name}` : éléments à expiration, modèle figé à l'import"),
                    &d.span,
                ),
                _ => self.unsupported(
                    format!(
                        "`{}` non géré dans l'ensemble `{name}`",
                        directive_excerpt(&d.keyword, &d.args, 1)
                    ),
                    &d.span,
                ),
            }
        }
        if broken {
            return; // diagnostiqué ; un ensemble à moitié compris ne rentre pas.
        }

        let oid = ctx.object_id(name);
        match typ.as_deref() {
            Some(t @ ("ipv4_addr" | "ipv6_addr")) => {
                let fam = if t == "ipv6_addr" {
                    Family::V6
                } else {
                    Family::V4
                };
                let mut nets = Vec::new();
                for e in &elements {
                    match values::parse_net(e) {
                        Some(net) if fam.accepts(&net) => nets.push(net),
                        _ => {
                            self.unsupported(
                                format!(
                                    "élément inanalysable ou de mauvaise famille dans \
                                     l'ensemble `{name}`"
                                ),
                                &node.span,
                            );
                            return;
                        }
                    }
                }
                if self.device.objects.addresses.contains_key(&oid) {
                    self.unsupported(
                        format!(
                            "ensemble `{name}` redéfini : la nouvelle définition remplace \
                             la première"
                        ),
                        &node.span,
                    );
                }
                self.device
                    .objects
                    .addresses
                    .insert(oid, AddrObject::Nets(nets));
            }
            Some("inet_service") => {
                let mut ports = Vec::new();
                for e in &elements {
                    match values::parse_port_range(e) {
                        Some(r) => ports.push(r),
                        None => {
                            self.unsupported(
                                format!("port inanalysable dans l'ensemble `{name}`"),
                                &node.span,
                            );
                            return;
                        }
                    }
                }
                self.port_sets.insert(oid.as_str().to_owned(), ports);
            }
            Some(other) => self.unsupported(
                format!("type d'ensemble `{other}` non géré (`{name}`)"),
                &node.span,
            ),
            None => self.unsupported(format!("ensemble `{name}` sans `type`"), &node.span),
        }
    }

    // -- chaînes -----------------------------------------------------------

    fn chain_block(&mut self, ctx: &TableCtx, cname: &str, node: &ConfigNode) {
        let pid = ctx.policy_id(cname);
        let meta = ctx
            .chains
            .get(cname)
            .cloned()
            .unwrap_or(ChainMeta { base: None });

        let mut rules: Vec<Rule> = Vec::new();
        let mut index = 0usize;
        let mut truncated_at: Option<u32> = None;
        let mut dead = 0usize;
        for child in &node.children {
            if matches!(child.keyword.as_str(), "type" | "policy") {
                continue; // métadonnées déjà consommées.
            }
            index += 1;
            if truncated_at.is_some() {
                dead += 1;
                continue;
            }
            match self.convert_rule(ctx, cname, index, child) {
                RuleOutcome::Rule(r) => rules.push(*r),
                RuleOutcome::Omitted | RuleOutcome::Skipped => {}
                RuleOutcome::Truncate => truncated_at = Some(child.span.line),
            }
        }
        if let (Some(line), true) = (truncated_at, dead > 0) {
            self.note_info(
                format!(
                    "chaîne `{cname}` : {dead} règle(s) après le `return` inconditionnel de \
                     la ligne {line} sont du code mort, ignorées"
                ),
                &node.span,
            );
        }

        // Action par défaut :
        // - chaîne de base : `policy`, ou accept en son absence
        //   (comportement documenté de nftables) ;
        // - chaîne régulière : la retombée réelle est « retour à
        //   l'appelant », exactement la sémantique de saut du moteur
        //   (`Action::Jump` reprend après la règle quand la cible ne rend
        //   aucun verdict) — ce champ n'est alors jamais consulté. Deny
        //   par sûreté : si une évolution du moteur venait à le lire, un
        //   refus en trop vaut mieux qu'une autorisation en trop.
        let default_action = match &meta.base {
            Some(b) => b.policy.clone().unwrap_or(Action::Accept),
            None => Action::Deny,
        };

        self.device.policies.insert(
            pid.clone(),
            Policy {
                id: pid.clone(),
                rules,
                default_action,
            },
        );

        // Accroche au pipeline.
        if let Some(b) = &meta.base {
            self.seq += 1;
            match (b.typ.as_str(), b.hook.as_str()) {
                ("filter", "input") => self.ingress.push((RANK_INPUT, b.priority, self.seq, pid)),
                ("filter", "forward") => {
                    self.ingress.push((RANK_FORWARD, b.priority, self.seq, pid))
                }
                ("filter", "output") => self.egress.push((b.priority, self.seq, pid)),
                ("filter", other) => self.unsupported(
                    format!("chaîne `{cname}` : hook `{other}` non modélisé, chaîne non accrochée"),
                    &node.span,
                ),
                ("nat", _) => self.unsupported(
                    format!(
                        "chaîne `{cname}` : traduction d'adresse (`type nat`) non modélisée \
                         pour l'instant, chaîne non accrochée"
                    ),
                    &node.span,
                ),
                (other, _) => self.unsupported(
                    format!("chaîne `{cname}` : type `{other}` non modélisé, chaîne non accrochée"),
                    &node.span,
                ),
            }
        }
    }

    // -- règles ------------------------------------------------------------

    #[allow(clippy::too_many_lines)]
    fn convert_rule(
        &mut self,
        ctx: &TableCtx,
        cname: &str,
        index: usize,
        node: &ConfigNode,
    ) -> RuleOutcome {
        let mut toks: Vec<String> = Vec::with_capacity(node.args.len() + 1);
        toks.push(node.keyword.clone());
        toks.extend(node.args.iter().cloned());
        let span = node.span.clone();
        let label = format!("règle {index} de la chaîne `{cname}`");

        let mut src: Vec<AddrExpr> = Vec::new();
        let mut dst: Vec<AddrExpr> = Vec::new();
        let mut from: Option<ZoneId> = None;
        let mut to: Option<ZoneId> = None;
        // Contrainte de protocole nue (`meta l4proto`, `ip protocol`).
        let mut protos: Option<Vec<u8>> = None;
        let mut clauses: Vec<PortClause> = Vec::new();
        let mut action: Option<Action> = None;
        let mut wants_return = false;
        let mut i = 0usize;

        macro_rules! skip {
            ($($msg:tt)*) => {{
                self.unsupported(format!($($msg)*), &span);
                return RuleOutcome::Skipped;
            }};
        }

        while i < toks.len() {
            let tok = toks[i].as_str();
            match tok {
                "ip" | "ip6" => {
                    let v6 = tok == "ip6";
                    if (v6 && ctx.family == Family::V4) || (!v6 && ctx.family == Family::V6) {
                        skip!("{label} : expression `{tok}` étrangère à la famille de la table");
                    }
                    i += 1;
                    match toks.get(i).map(String::as_str) {
                        Some(dir @ ("saddr" | "daddr")) => {
                            i += 1;
                            let Some(vals) = read_values(&toks, &mut i) else {
                                skip!("{label} : `{tok} {dir}` sans valeur lisible");
                            };
                            let out = if dir == "saddr" { &mut src } else { &mut dst };
                            for v in vals {
                                match self.addr_expr(ctx, &v, v6, &label, &span) {
                                    Some(e) => out.push(e),
                                    None => return RuleOutcome::Skipped,
                                }
                            }
                        }
                        Some("protocol") if !v6 => {
                            i += 1;
                            let Some(vals) = read_values(&toks, &mut i) else {
                                skip!("{label} : `ip protocol` sans valeur lisible");
                            };
                            if protos.is_some() {
                                skip!("{label} : plusieurs contraintes de protocole");
                            }
                            let mut ps = Vec::new();
                            for v in &vals {
                                match values::parse_proto(v) {
                                    Some(p) => ps.push(p),
                                    None => skip!("{label} : protocole `{v}` inconnu"),
                                }
                            }
                            protos = Some(ps);
                        }
                        other => skip!(
                            "{label} : expression `{tok} {}` non gérée",
                            other.unwrap_or("?")
                        ),
                    }
                }
                "tcp" | "udp" => {
                    let proto: u8 = if tok == "tcp" { 6 } else { 17 };
                    i += 1;
                    let Some(dir @ ("dport" | "sport")) = toks.get(i).map(String::as_str) else {
                        skip!(
                            "{label} : expression `{tok} {}` non gérée",
                            toks.get(i).map(String::as_str).unwrap_or("?")
                        );
                    };
                    let dport = dir == "dport";
                    i += 1;
                    let Some(vals) = read_values(&toks, &mut i) else {
                        skip!("{label} : `{tok} {dir}` sans valeur lisible");
                    };
                    match self.port_clause(ctx, proto, dport, &vals, &label, &span) {
                        Some(c) => clauses.push(c),
                        None => return RuleOutcome::Skipped,
                    }
                }
                "meta" => {
                    i += 1;
                    if toks.get(i).map(String::as_str) != Some("l4proto") {
                        skip!(
                            "{label} : expression `meta {}` non gérée",
                            toks.get(i).map(String::as_str).unwrap_or("?")
                        );
                    }
                    i += 1;
                    let Some(vals) = read_values(&toks, &mut i) else {
                        skip!("{label} : `meta l4proto` sans valeur lisible");
                    };
                    if protos.is_some() {
                        skip!("{label} : plusieurs contraintes de protocole");
                    }
                    let mut ps = Vec::new();
                    for v in &vals {
                        match values::parse_proto(v) {
                            Some(p) => ps.push(p),
                            None => skip!("{label} : protocole `{v}` inconnu"),
                        }
                    }
                    protos = Some(ps);
                }
                "iifname" | "oifname" => {
                    let is_in = tok == "iifname";
                    i += 1;
                    let Some(vals) = read_values(&toks, &mut i) else {
                        skip!("{label} : `{tok}` sans valeur lisible");
                    };
                    if vals.len() != 1 {
                        // `Rule.from`/`Rule.to` ne portent qu'une zone :
                        // retenir la première serait faux pour les autres.
                        skip!("{label} : plusieurs interfaces pour `{tok}` non gérées");
                    }
                    let raw = &vals[0];
                    let name = if let Some(var) = raw.strip_prefix('$') {
                        match self.defines.get(var).cloned() {
                            Some(vs) if vs.len() == 1 => vs[0].clone(),
                            Some(_) => skip!(
                                "{label} : la variable `{var}` porte plusieurs valeurs \
                                 pour `{tok}`"
                            ),
                            None => skip!("{label} : variable `{var}` inconnue"),
                        }
                    } else if raw.starts_with('@') {
                        skip!("{label} : ensemble d'interfaces pour `{tok}` non géré");
                    } else {
                        raw.clone()
                    };
                    let zone = self.zone_for_interface(&name);
                    let slot = if is_in { &mut from } else { &mut to };
                    if slot.is_some() {
                        skip!("{label} : `{tok}` répété");
                    }
                    *slot = Some(zone);
                }
                "ct" => {
                    i += 1;
                    if toks.get(i).map(String::as_str) != Some("state") {
                        skip!(
                            "{label} : expression `ct {}` non gérée",
                            toks.get(i).map(String::as_str).unwrap_or("?")
                        );
                    }
                    i += 1;
                    let Some(states) = read_values(&toks, &mut i) else {
                        skip!("{label} : `ct state` sans valeur lisible");
                    };
                    for s in &states {
                        if !values::is_ct_state(s) {
                            skip!("{label} : état de connexion `{s}` inconnu");
                        }
                    }
                    // ANALYSE SANS ÉTAT — le choix le plus important de cet
                    // adaptateur. Le premier paquet d'un flux INITIATEUR est
                    // toujours en état `new` :
                    // - si la liste contient `new`, la condition est VRAIE
                    //   pour ce paquet : on retire la contrainte, sans
                    //   approximation ;
                    // - sinon (`established`, `related`, `invalid`,
                    //   `untracked`), la condition est FAUSSE pour ce
                    //   paquet : la règle ne participe JAMAIS au verdict
                    //   d'un flux initiateur, on l'écarte avec une note
                    //   Info. Un Warning + Partial serait injuste : le
                    //   verdict rendu reste EXACT pour le trafic
                    //   initiateur, seule chose que le moteur modélise.
                    //   L'omniprésent `ct state established,related accept`
                    //   dégraderait sinon la fidélité de toutes les
                    //   configurations nftables réelles sans raison.
                    if !states.iter().any(|s| s == "new") {
                        self.note_info(
                            format!(
                                "{label} : `ct state {}` ne concerne jamais le premier \
                                 paquet d'un flux initiateur (analyse sans état) : règle \
                                 écartée, verdict inchangé",
                                states.join(",")
                            ),
                            &span,
                        );
                        return RuleOutcome::Omitted;
                    }
                }
                // Compris, sans effet sur le verdict.
                "counter" => {
                    i += 1;
                    // Sortie de `nft list ruleset` : `counter packets N bytes M`.
                    if toks.get(i).map(String::as_str) == Some("packets") {
                        i = (i + 4).min(toks.len());
                    }
                }
                "log" => {
                    i += 1;
                    while matches!(
                        toks.get(i).map(String::as_str),
                        Some(
                            "prefix" | "level" | "group" | "snaplen" | "queue-threshold" | "flags"
                        )
                    ) {
                        i = (i + 2).min(toks.len());
                    }
                }
                "comment" => {
                    i += 1;
                    if i < toks.len() {
                        i += 1;
                    }
                }
                // Verdicts.
                "accept" => {
                    if action.is_some() {
                        skip!("{label} : plusieurs verdicts");
                    }
                    action = Some(Action::Accept);
                    i += 1;
                }
                "drop" => {
                    if action.is_some() {
                        skip!("{label} : plusieurs verdicts");
                    }
                    action = Some(Action::Deny);
                    i += 1;
                }
                "reject" => {
                    if action.is_some() {
                        skip!("{label} : plusieurs verdicts");
                    }
                    action = Some(Action::Deny);
                    self.note_info(
                        format!(
                            "{label} : `reject` modélisé comme un refus — l'équipement \
                             répond à l'émetteur (ICMP/RST) mais le verdict \
                             d'accessibilité est identique"
                        ),
                        &span,
                    );
                    i += 1;
                    // `reject with icmp type port-unreachable`, `with tcp reset`…
                    if toks.get(i).map(String::as_str) == Some("with") {
                        i += 1;
                        while i < toks.len() && toks[i] != "comment" {
                            i += 1;
                        }
                    }
                }
                "jump" | "goto" => {
                    if action.is_some() {
                        skip!("{label} : plusieurs verdicts");
                    }
                    i += 1;
                    let Some(target) = toks.get(i).cloned() else {
                        skip!("{label} : `{tok}` sans chaîne cible");
                    };
                    i += 1;
                    match ctx.chains.get(&target) {
                        None => skip!("{label} : `{tok}` vers la chaîne inconnue `{target}`"),
                        Some(m) if m.base.is_some() => {
                            skip!("{label} : `{tok}` vers la chaîne de base `{target}`")
                        }
                        Some(_) => {}
                    }
                    if tok == "goto" {
                        // Nuance de retombée : après un `goto`, si la
                        // chaîne cible ne rend aucun verdict, le noyau
                        // applique directement la politique de la chaîne
                        // de base, SANS reprendre après la règle. Le
                        // modèle (Jump) reprend après la règle : il peut
                        // donc consulter des règles que l'équipement
                        // n'aurait plus regardées.
                        self.note_warning(
                            format!(
                                "{label} : `goto {target}` modélisé comme `jump` — en cas \
                                 de retombée de la cible, l'équipement applique la \
                                 politique de la chaîne de base au lieu de reprendre \
                                 après la règle"
                            ),
                            &span,
                        );
                    }
                    action = Some(Action::Jump(ctx.policy_id(&target)));
                }
                "return" => {
                    wants_return = true;
                    i += 1;
                }
                "masquerade" | "snat" | "dnat" | "redirect" => {
                    skip!(
                        "{label} : traduction d'adresse (`{tok}`) non modélisée pour \
                         l'instant"
                    );
                }
                "limit" => {
                    skip!("{label} : `limit` rend le verdict dépendant du débit : non modélisable");
                }
                other => {
                    skip!("{label} : expression `{other}` non gérée");
                }
            }
        }

        // `return` : la chaîne rend la main à l'appelant.
        if wants_return {
            if action.is_some() {
                skip!("{label} : `return` combiné à un autre verdict");
            }
            let unconditional = src.is_empty()
                && dst.is_empty()
                && from.is_none()
                && to.is_none()
                && protos.is_none()
                && clauses.is_empty();
            if unconditional {
                // Exactement la retombée du moteur : plus aucune règle de
                // cette chaîne n'est consultée, l'appelant reprend.
                self.note_info(
                    format!("{label} : `return` inconditionnel — fin de la chaîne"),
                    &span,
                );
                return RuleOutcome::Truncate;
            }
            skip!(
                "{label} : `return` conditionnel non modélisable (le modèle ne sait pas \
                 interrompre une chaîne règle par règle)"
            );
        }

        let Some(action) = action else {
            // `counter`/`log` seuls : la règle observe, elle ne décide pas.
            self.note_info(
                format!(
                    "{label} : aucune décision (`counter`/`log` seulement) : sans effet \
                         sur le verdict, écartée"
                ),
                &span,
            );
            return RuleOutcome::Omitted;
        };

        let Some(services) = self.build_services(protos, clauses, &label, &span) else {
            return RuleOutcome::Skipped;
        };

        RuleOutcome::Rule(Box::new(Rule {
            id: RuleId::new(index.to_string()),
            matches: RuleMatch { src, dst, services },
            from,
            to,
            action,
            source: span,
            // nftables : les clauses non comprises sont déjà écartées (règle
            // sautée) ; aucune sur-approximation de correspondance résiduelle.
            approximation: None,
        }))
    }

    /// Une valeur d'adresse : préfixe/adresse littérale, `@ensemble` ou
    /// `$variable`. Rend `None` après diagnostic (la règle est écartée).
    fn addr_expr(
        &mut self,
        ctx: &TableCtx,
        value: &str,
        v6: bool,
        label: &str,
        span: &SourceSpan,
    ) -> Option<AddrExpr> {
        if let Some(set) = value.strip_prefix('@') {
            let oid = ctx.object_id(set);
            if !self.device.objects.addresses.contains_key(&oid) {
                self.unsupported(
                    format!(
                        "{label} : ensemble `@{set}` introuvable ou d'un type non-adresse : \
                         irrésoluble à l'évaluation"
                    ),
                    span,
                );
            }
            // Référence conservée (résolution tardive, §3.3), comme les
            // autres adaptateurs.
            return Some(AddrExpr::Object(oid));
        }
        if let Some(var) = value.strip_prefix('$') {
            let oid = ObjectId::new(var);
            if self.defines.contains_key(var) && self.device.objects.addresses.contains_key(&oid) {
                return Some(AddrExpr::Object(oid));
            }
            self.unsupported(
                format!("{label} : variable `${var}` inconnue ou sans valeur d'adresse"),
                span,
            );
            return None;
        }
        let fam = if v6 { Family::V6 } else { Family::V4 };
        match values::parse_net(value) {
            Some(net) if fam.accepts(&net) => Some(AddrExpr::Net(net)),
            Some(_) => {
                self.unsupported(
                    format!("{label} : adresse `{value}` de la mauvaise famille"),
                    span,
                );
                None
            }
            None => {
                self.unsupported(
                    format!("{label} : valeur d'adresse `{value}` inanalysable"),
                    span,
                );
                None
            }
        }
    }

    /// Une contrainte `tcp|udp dport|sport <valeurs>`. Les littéraux
    /// deviennent des plages ; `@ensemble` et `$variable` deviennent un
    /// objet service DÉRIVÉ (voir mod.rs). Rend `None` après diagnostic.
    fn port_clause(
        &mut self,
        ctx: &TableCtx,
        proto: u8,
        dport: bool,
        vals: &[String],
        label: &str,
        span: &SourceSpan,
    ) -> Option<PortClause> {
        // Référence : une seule, non mélangée à des littéraux.
        if let [single] = vals {
            let key = if let Some(set) = single.strip_prefix('@') {
                Some(ctx.object_id(set).as_str().to_owned())
            } else {
                single.strip_prefix('$').map(str::to_owned)
            };
            if let Some(key) = key {
                let Some(ranges) = self.port_sets.get(&key).cloned() else {
                    self.unsupported(
                        format!(
                            "{label} : `{single}` n'est pas un ensemble ou une variable de \
                             ports connu"
                        ),
                        span,
                    );
                    return None;
                };
                return Some(PortClause::Object {
                    id: self.derived_service_object(&key, proto, dport, &ranges),
                });
            }
        }
        if vals
            .iter()
            .any(|v| v.starts_with('@') || v.starts_with('$'))
        {
            self.unsupported(
                format!("{label} : mélange de références et de ports littéraux non géré"),
                span,
            );
            return None;
        }
        let mut ranges = Vec::new();
        for v in vals {
            match values::parse_port_range(v) {
                Some(r) => ranges.push(r),
                None => {
                    self.unsupported(
                        format!("{label} : port `{v}` inanalysable (nom de service ?)"),
                        span,
                    );
                    return None;
                }
            }
        }
        Some(PortClause::Literal {
            proto,
            dport,
            ranges,
        })
    }

    /// L'objet service dérivé d'un ensemble/variable de ports pour un
    /// protocole et une direction donnés. Créé une seule fois ; son nom
    /// (`…:tcp:dport`) garde la traçabilité vers l'ensemble d'origine.
    fn derived_service_object(
        &mut self,
        key: &str,
        proto: u8,
        dport: bool,
        ranges: &[PortRange],
    ) -> ObjectId {
        let proto_name = if proto == 6 { "tcp" } else { "udp" };
        let dir = if dport { "dport" } else { "sport" };
        let oid = ObjectId::new(format!("{key}:{proto_name}:{dir}"));
        self.device
            .objects
            .services
            .entry(oid.clone())
            .or_insert_with(|| {
                ServiceObject::Services(
                    ranges
                        .iter()
                        .map(|r| Service {
                            proto: ProtoMatch::Number(proto),
                            sport: if dport { PortRange::ANY } else { *r },
                            dport: if dport { *r } else { PortRange::ANY },
                        })
                        .collect(),
                )
            });
        oid
    }

    /// Combine contraintes de protocole et de ports en une dimension de
    /// services EXACTE (intersection, jamais une sur-approximation qui
    /// rendrait le verdict optimiste). Rend `None` après diagnostic.
    fn build_services(
        &mut self,
        protos: Option<Vec<u8>>,
        clauses: Vec<PortClause>,
        label: &str,
        span: &SourceSpan,
    ) -> Option<Vec<ServiceExpr>> {
        // Objet dérivé : seul, sans autre contrainte de service — sinon
        // l'intersection ne serait pas représentable par des références.
        let objects: Vec<ObjectId> = clauses
            .iter()
            .filter_map(|c| match c {
                PortClause::Object { id } => Some(id.clone()),
                PortClause::Literal { .. } => None,
            })
            .collect();
        if !objects.is_empty() {
            if objects.len() < clauses.len() || protos.is_some() {
                self.unsupported(
                    format!(
                        "{label} : un ensemble de ports combiné à d'autres contraintes de \
                         service n'est pas représentable"
                    ),
                    span,
                );
                return None;
            }
            return Some(objects.into_iter().map(ServiceExpr::Object).collect());
        }

        // Littéraux : un seul protocole possible par règle (un paquet n'en
        // a qu'un ; deux protocoles différents ne matchent jamais).
        let mut proto_of_clauses: Option<u8> = None;
        let mut dports: Vec<PortRange> = Vec::new();
        let mut sports: Vec<PortRange> = Vec::new();
        for c in &clauses {
            let PortClause::Literal {
                proto,
                dport,
                ranges,
            } = c
            else {
                continue;
            };
            match proto_of_clauses {
                None => proto_of_clauses = Some(*proto),
                Some(p) if p == *proto => {}
                Some(_) => {
                    self.unsupported(
                        format!(
                            "{label} : contraintes de ports sur deux protocoles différents \
                             (la règle ne peut jamais correspondre)"
                        ),
                        span,
                    );
                    return None;
                }
            }
            let out = if *dport { &mut dports } else { &mut sports };
            if !out.is_empty() {
                self.unsupported(
                    format!("{label} : contrainte de ports répétée dans la même direction"),
                    span,
                );
                return None;
            }
            out.extend(ranges.iter().copied());
        }

        match (proto_of_clauses, protos) {
            (None, None) => Some(Vec::new()), // aucune contrainte : Any.
            (None, Some(ps)) => Some(
                ps.into_iter()
                    .map(|p| {
                        ServiceExpr::Service(Service {
                            proto: ProtoMatch::Number(p),
                            sport: PortRange::ANY,
                            dport: PortRange::ANY,
                        })
                    })
                    .collect(),
            ),
            (Some(p), maybe_protos) => {
                // `meta l4proto { tcp, udp } tcp dport 22` : l'intersection
                // se réduit aux ports tcp ; un protocole listé sans
                // contrainte de port est éliminé par la contrainte de port.
                if let Some(ps) = maybe_protos {
                    if !ps.contains(&p) {
                        self.unsupported(
                            format!(
                                "{label} : contrainte de protocole incompatible avec les \
                                 ports (la règle ne peut jamais correspondre)"
                            ),
                            span,
                        );
                        return None;
                    }
                }
                let ds = if dports.is_empty() {
                    vec![PortRange::ANY]
                } else {
                    dports
                };
                let ss = if sports.is_empty() {
                    vec![PortRange::ANY]
                } else {
                    sports
                };
                let mut out = Vec::new();
                for d in &ds {
                    for s in &ss {
                        out.push(ServiceExpr::Service(Service {
                            proto: ProtoMatch::Number(p),
                            sport: *s,
                            dport: *d,
                        }));
                    }
                }
                Some(out)
            }
        }
    }

    /// La zone IMPLICITE d'une interface : une zone du même nom contenant
    /// cette seule interface (convention partagée avec les adaptateurs
    /// FortiGate et Cisco). Un fichier nftables ne déclare pas
    /// d'inventaire d'interfaces : l'interface référencée est créée à la
    /// volée, sans adresse (elles vivent côté système, pas dans le
    /// fichier de règles).
    fn zone_for_interface(&mut self, name: &str) -> ZoneId {
        let iface_id = IfaceId::new(name);
        let zid = ZoneId::new(name);
        let iface = self
            .device
            .interfaces
            .entry(iface_id.clone())
            .or_insert_with(|| Interface::new(iface_id.clone()));
        iface.zone = Some(zid.clone());
        self.device
            .zones
            .entry(zid.clone())
            .or_insert_with(|| vec![iface_id]);
        zid
    }
}

// ---------------------------------------------------------------------------
// Types auxiliaires
// ---------------------------------------------------------------------------

/// Le sort d'un énoncé de règle.
enum RuleOutcome {
    /// Une règle du modèle.
    Rule(Box<Rule>),
    /// Comprise et écartée (note émise) : `ct state established…`, règle
    /// sans verdict.
    Omitted,
    /// Non comprise : diagnostiquée, fidélité dégradée.
    Skipped,
    /// `return` inconditionnel : fin de la chaîne, la suite est du code
    /// mort.
    Truncate,
}

/// Une contrainte de ports d'une règle.
enum PortClause {
    Literal {
        proto: u8,
        /// `true` = dport, `false` = sport.
        dport: bool,
        ranges: Vec<PortRange>,
    },
    /// Référence à un ensemble/variable de ports, déjà dérivée en objet
    /// service.
    Object { id: ObjectId },
}

/// Lit une valeur ou un ensemble de valeurs à partir de `toks[*i]` :
/// `v`, `v1,v2` (virgules-jetons) ou `{ v1, v2 }`. Avance le curseur.
/// Rend `None` si rien n'est lisible (fin d'énoncé, accolade non fermée).
fn read_values(toks: &[String], i: &mut usize) -> Option<Vec<String>> {
    let mut out = Vec::new();
    if *i >= toks.len() {
        return None;
    }
    if toks[*i] == "{" {
        *i += 1;
        while *i < toks.len() && toks[*i] != "}" {
            if toks[*i] != "," {
                out.push(toks[*i].clone());
            }
            *i += 1;
        }
        if *i >= toks.len() {
            return None; // accolade jamais refermée dans l'énoncé.
        }
        *i += 1; // consomme `}`.
    } else {
        out.push(toks[*i].clone());
        *i += 1;
        // Liste `a,b,c` : la couche 1 a fait des virgules des jetons.
        while *i + 1 < toks.len() && toks[*i] == "," {
            out.push(toks[*i + 1].clone());
            *i += 2;
        }
    }
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

/// `regles/hote-01.nft` → `hote-01`. Repli pour nommer l'équipement (un
/// fichier nftables ne porte pas de nom d'hôte).
fn file_stem(path: &str) -> String {
    let name = path
        .rsplit(['/', '\\'])
        .next()
        .filter(|s| !s.is_empty())
        .unwrap_or(path);
    let stem = match name.rsplit_once('.') {
        Some((s, _)) if !s.is_empty() => s,
        _ => name,
    };
    if stem.is_empty() {
        "equipement".to_owned()
    } else {
        stem.to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nom_de_fichier_vers_identifiant() {
        assert_eq!(file_stem("regles/hote-01.nft"), "hote-01");
        assert_eq!(file_stem("C:\\regles\\hote-01.nft"), "hote-01");
        assert_eq!(file_stem("hote-01"), "hote-01");
        assert_eq!(file_stem(""), "equipement");
    }

    #[test]
    fn lecture_des_valeurs() {
        let toks: Vec<String> = ["{", "22", ",", "443", "}", "accept"]
            .iter()
            .map(|s| (*s).to_string())
            .collect();
        let mut i = 0;
        assert_eq!(
            read_values(&toks, &mut i),
            Some(vec!["22".into(), "443".into()])
        );
        assert_eq!(toks[i], "accept");

        let toks: Vec<String> = ["established", ",", "related", "accept"]
            .iter()
            .map(|s| (*s).to_string())
            .collect();
        let mut i = 0;
        assert_eq!(
            read_values(&toks, &mut i),
            Some(vec!["established".into(), "related".into()])
        );
        assert_eq!(toks[i], "accept");

        // Accolade jamais refermée : aucune valeur, pas de panique.
        let toks: Vec<String> = ["{", "22"].iter().map(|s| (*s).to_string()).collect();
        let mut i = 0;
        assert_eq!(read_values(&toks, &mut i), None);
    }
}
