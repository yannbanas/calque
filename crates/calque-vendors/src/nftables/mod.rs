//! Adaptateur nftables — couche 2, la sémantique (§6.2, §6.4).
//!
//! Couvre les fichiers de règles Linux (`/etc/nftables.conf`, scripts
//! `nft -f`) et la sortie de `nft list ruleset`. §6.4 : « utile pour les
//! tests et pour les hôtes ».
//!
//! ## Choix de modélisation documentés
//!
//! - **Chaînes de base → politiques accrochées.** `type filter hook
//!   input|forward` → `Pipeline::ingress` (les chaînes `input` avant les
//!   chaînes `forward`, puis par priorité croissante) ; `type filter hook
//!   output` → `Pipeline::egress`. LIMITE hôte vs routeur : dans le
//!   noyau, un paquet traverse `input` OU `forward` selon qu'il est
//!   destiné à l'hôte ou en transit ; le moteur, lui, évalue toutes les
//!   politiques d'entrée en séquence. Quand les deux chaînes existent, le
//!   modèle est donc PLUS RESTRICTIF que l'équipement (chaque chaîne ne
//!   peut qu'ajouter des refus) — jamais optimiste. Une note `Warning` le
//!   signale sans dégrader la fidélité : toutes les directives ont été
//!   comprises. Les hooks `prerouting`/`postrouting` et les types
//!   `nat`/`route` ne sont pas modélisés (diagnostic, `Partial`).
//!
//! - **Chaînes régulières** (sans `type … hook …`) : des politiques NON
//!   accrochées, cibles de `jump`. La retombée (« aucune règle ne
//!   correspond → retour à l'appelant, qui reprend après la règle de
//!   saut ») est EXACTEMENT la sémantique `Action::Jump` du moteur
//!   (`calque-engine::policy`). `goto` est modélisé comme `jump` avec une
//!   note `Warning` : en cas de retombée de la cible, l'équipement
//!   applique la politique de la chaîne de base au lieu de reprendre
//!   après la règle.
//!
//! - **Politique par défaut.** `policy accept|drop` → `default_action` ;
//!   absente → `accept` (comportement documenté de nftables, pas une
//!   supposition).
//!
//! - **Analyse SANS ÉTAT et `ct state`.** Le moteur modélise le premier
//!   paquet d'un flux initiateur, toujours en état `new`. Une règle
//!   `ct state established,related accept` — omniprésente — ne participe
//!   donc JAMAIS au verdict de ce paquet : elle est écartée avec une note
//!   `Info`, PAS un `Warning + Partial` qui dégraderait la fidélité de
//!   toutes les configurations nftables réelles alors que le verdict
//!   rendu reste exact. `ct state new …` : la condition est vraie pour le
//!   paquet initiateur, la contrainte est simplement retirée (exact, pas
//!   une approximation). Justification détaillée dans `convert.rs`.
//!
//! - **Zones.** Un fichier nftables ne déclare ni interfaces ni zones :
//!   `iifname "lan0"` crée une zone implicite `lan0` contenant une
//!   interface du même nom, créée à la volée sans adresse (convention
//!   partagée avec FortiGate et Cisco IOS).
//!
//! - **Ensembles et variables, résolus tard (§3.3).** Un ensemble nommé
//!   d'adresses (`set … type ipv4_addr`) devient un objet
//!   `famille/table/nom` de l'`ObjectStore`, référencé par
//!   `AddrExpr::Object` — la résolution a lieu à l'évaluation. Un
//!   ensemble de ports (`type inet_service`) n'a pas de protocole propre :
//!   à l'usage (`tcp dport @s`), un objet service DÉRIVÉ
//!   (`…/s:tcp:dport`) est créé, son nom gardant la traçabilité vers
//!   l'ensemble d'origine. `define` suit les mêmes règles (nom non
//!   qualifié : la variable est globale au fichier). Les ensembles
//!   anonymes `{ a, b }` deviennent plusieurs valeurs du pavé.
//!
//! - **`reject` → `Deny`** avec note : l'équipement répond à l'émetteur,
//!   mais le verdict d'accessibilité est identique. **`return`**
//!   inconditionnel → fin de la chaîne (les règles suivantes sont du code
//!   mort, note `Info`) ; conditionnel → non modélisable, diagnostic.
//!
//! - **NAT (`masquerade`, `snat`, `dnat`, `redirect`) : non modélisé pour
//!   l'instant** — diagnostic explicite et `Partial`, au niveau de la
//!   chaîne (`type nat`) comme au niveau de la règle.
//!
//! - **Tout le reste** (maps/vmaps, `limit`, ensembles dynamiques,
//!   `include` non résolu…) : diagnostic `Warning + Partial` si cela peut
//!   toucher le verdict d'un flux initiateur, note `Info` sinon
//!   (`counter`, `log`, `comment`, flowtables, quotas déclarés…). JAMAIS
//!   d'ignorance silencieuse (§6.3).

mod convert;
mod values;

use calque_model::{Diagnostic, SourceSpan, Vendor};

use crate::{AdapterOutput, Confidence, ConfigTree, VendorAdapter};

/// L'adaptateur nftables (fichiers de règles, sortie `nft list ruleset`).
#[derive(Debug, Default, Clone, Copy)]
pub struct NftablesAdapter;

impl NftablesAdapter {
    /// Commodité : analyse le texte brut avec le tokenizer nftables de
    /// `calque-parse` (couche 1) puis convertit en IR. `file` est le nom
    /// rapporté dans tous les `SourceSpan`.
    ///
    /// Une erreur de syntaxe de la couche 1 devient un `Diagnostic`
    /// d'erreur portant le fichier et la ligne fautive.
    pub fn import_str(&self, raw: &str, file: &str) -> Result<AdapterOutput, Vec<Diagnostic>> {
        let tree = calque_parse::nftables::parse(raw, file).map_err(|e| {
            vec![Diagnostic::error(
                e.to_string(),
                Some(SourceSpan::new(e.file(), e.line())),
            )]
        })?;
        self.to_ir(&tree)
    }
}

impl VendorAdapter for NftablesAdapter {
    fn label(&self) -> &'static str {
        "nftables"
    }

    fn import_str(&self, raw: &str, file: &str) -> Result<AdapterOutput, Vec<Diagnostic>> {
        NftablesAdapter::import_str(self, raw, file)
    }

    fn vendor(&self) -> Vendor {
        Vendor::Nftables
    }

    /// Reconnaissance par motifs caractéristiques du format : déclaration
    /// de table, chaîne de base (`type … hook …`), shebang `nft`,
    /// `flush ruleset`. Sans déclaration de table, rien d'exploitable :
    /// le score reste sous le seuil.
    fn detect(&self, raw: &str) -> Confidence {
        let mut shebang = false;
        let mut flush = false;
        let mut table = false;
        let mut chain = false;
        let mut hook = false;
        let mut policy = false;
        for line in raw.lines() {
            let t = line.trim();
            if t.starts_with("#!") && t.contains("nft") {
                shebang = true;
            } else if t == "flush ruleset" {
                flush = true;
            } else if ["ip ", "ip6 ", "inet ", "arp ", "bridge ", "netdev "]
                .iter()
                .any(|f| {
                    t.strip_prefix("table ")
                        .or_else(|| t.strip_prefix("add table "))
                        .is_some_and(|rest| rest.starts_with(f))
                })
            {
                table = true;
            } else if t.starts_with("chain ") && t.contains('{') {
                chain = true;
            } else if t.starts_with("type ") && t.contains(" hook ") {
                hook = true;
            } else if t.starts_with("policy accept") || t.starts_with("policy drop") {
                policy = true;
            }
        }
        let mut score: u32 = 0;
        if table {
            score += 35;
        }
        if hook {
            score += 30;
        }
        if chain {
            score += 15;
        }
        if shebang {
            score += 10;
        }
        if flush {
            score += 10;
        }
        if policy {
            score += 5;
        }
        if !table {
            // Sans table, pas de configuration nftables exploitable.
            score = score.min(40);
        }
        Confidence::new(score.min(100) as u8)
    }

    fn to_ir(&self, tree: &ConfigTree) -> Result<AdapterOutput, Vec<Diagnostic>> {
        convert::convert(tree)
    }
}
