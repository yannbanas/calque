//! Adaptateur FortiGate — couche 2, la sémantique (§6.2, §6.4).
//!
//! ## Choix de modélisation documentés
//!
//! - **Zones.** Chez FortiGate, une politique référence en `srcintf`/
//!   `dstintf` soit une zone (`config system zone`), soit directement une
//!   interface. Le modèle de Calque raisonne en zones : quand une
//!   politique référence une interface qui n'appartient à aucune zone
//!   explicite, on crée une zone IMPLICITE portant le nom de l'interface
//!   et contenant cette seule interface. C'est fidèle au comportement
//!   FortiGate (une interface hors zone se comporte comme une zone à un
//!   membre) et ce n'est pas une supposition.
//!
//! - **Accrochage de la politique.** FortiGate filtre le trafic
//!   TRANSITANT (forward path) : la décision est prise à l'entrée du
//!   paquet, en fonction du couple (interface d'entrée, interface de
//!   sortie prévue par le routage). On accroche donc l'unique politique
//!   `forward` dans `Pipeline::ingress`. Les champs `from`/`to` de chaque
//!   règle portent le couple de zones.
//!
//! - **Action par défaut.** Un FortiGate refuse tout trafic qu'aucune
//!   politique n'accepte : `default_action = Deny`.
//!
//! - **`set nat enable`.** C'est un SNAT vers l'adresse de l'interface de
//!   sortie ; la cible concrète n'est connue qu'à l'évaluation (elle
//!   dépend de l'interface de sortie). On modélise
//!   `Action::Nat(NatAction { snat: None, dnat: None })` : « accepte et
//!   traduit la source, cible résolue tardivement ».
//!
//! - **`config firewall vip` / `vipgrp`.** Un VIP compris devient un
//!   objet adresse `Nets([extip/32])` sous son nom, et toute règle qui
//!   l'ACCEPTE en `dstaddr` porte la redirection :
//!   `Action::Nat(NatAction { dnat: Some(…) })`, fusionnée avec la part
//!   de SNAT d'un éventuel `set nat enable`. Un port unique est mappé
//!   exactement (`extport` → `mappedport`) ; une plage de ports
//!   IDENTITAIRE devient un DNAT d'adresse seule (ports préservés) ; une
//!   plage réellement décalée ou une plage d'adresses externes n'est PAS
//!   représentable (`DnatTarget` porte une adresse et un port uniques) →
//!   diagnostic, jamais une approximation. Plusieurs VIP dans une même
//!   règle (ou via un `vipgrp`) ont chacun leur cible : la règle est
//!   ÉCLATÉE en une règle par VIP (identifiants suffixés `<n>:<vip>`,
//!   même span — exact et traçable). `set extintf` est compris et sans
//!   effet propre : la contrainte d'interface d'entrée est déjà portée
//!   par le `srcintf` des politiques référençant le VIP.
//!
//! - **Routes par objet** (`set dstaddr` sur une route statique) :
//!   l'objet (subnet, iprange, groupe) est résolu en UNE route par
//!   préfixe (mêmes saut, métrique et span). Objet irrésoluble (fqdn,
//!   géographie…) → diagnostic, pas de route devinée.
//!
//! - **`config system sdwan`.** Une route `set sdwan-zone <Z>` devient
//!   UNE route par membre actif de la zone (même préfixe, même
//!   métrique) : le moteur les traite en candidates ECMP évaluées par
//!   branches — « l'un des WAN », c'est le comportement voulu. Les
//!   `config service` SD-WAN (sélection de membre par flux) ne sont PAS
//!   modélisés → diagnostic Warning explicite (fidélité dégradée) ; les
//!   `health-check` (supervision) → note Info.
//!
//! - **`config vpn ipsec phase1/phase2-interface`.** La phase1 est de la
//!   topologie (passerelle distante, interface parente) → note Info ;
//!   l'interface tunnel du même nom vient de `config system interface`.
//!   Les SÉLECTEURS phase2 sont un vrai filtre : le FortiGate ne chiffre
//!   que le trafic correspondant à un sélecteur et JETTE le reste →
//!   politique de SORTIE `ipsec:<tunnel>` (une règle Accept par
//!   sélecteur, zone `to` = l'interface tunnel, `default_action = Deny`).
//!   Chiffrement et négociation (`proposal`, `dhgrp`, `psksecret`…) sont
//!   compris et sans effet sur le filtrage ; la valeur de `psksecret` ne
//!   sort JAMAIS dans un diagnostic (§11.4).
//!
//! - **Règles désactivées** (`set status disable`) : ignorées AVEC un
//!   diagnostic `Info` dans `AdapterOutput::notes` — c'est un constat,
//!   pas une incompréhension, donc la fidélité n'est pas dégradée.
//!
//! - **Directives non comprises** : chacune produit un `Diagnostic`
//!   (avec span) accumulé dans `Fidelity::Partial` (§6.3). JAMAIS
//!   d'ignorance silencieuse, JAMAIS de supposition. Les mots-clés
//!   cosmétiques connus (alias, description, couleur…) sont RECONNUS
//!   comme sans effet sur l'accessibilité : les accepter n'est pas
//!   deviner.

mod convert;
mod values;

use calque_model::{Diagnostic, SourceSpan, Vendor};

use crate::{AdapterOutput, Confidence, ConfigTree, VendorAdapter};

/// L'adaptateur FortiGate (FortiOS, format `config`/`edit`/`set`).
#[derive(Debug, Default, Clone, Copy)]
pub struct FortigateAdapter;

impl FortigateAdapter {
    /// Commodité : analyse le texte brut avec le tokenizer FortiGate de
    /// `calque-parse` (couche 1) puis convertit en IR. `file` est le nom
    /// rapporté dans tous les `SourceSpan`.
    ///
    /// Une erreur de syntaxe de la couche 1 devient un `Diagnostic`
    /// d'erreur portant le fichier et la ligne fautive.
    pub fn import_str(&self, raw: &str, file: &str) -> Result<AdapterOutput, Vec<Diagnostic>> {
        let tree = calque_parse::fortigate::parse(raw, file).map_err(|e| {
            vec![Diagnostic::error(
                e.to_string(),
                Some(SourceSpan::new(e.file(), e.line())),
            )]
        })?;
        self.to_ir(&tree)
    }
}

impl VendorAdapter for FortigateAdapter {
    fn label(&self) -> &'static str {
        "FortiGate (CLI)"
    }

    fn import_str(&self, raw: &str, file: &str) -> Result<AdapterOutput, Vec<Diagnostic>> {
        FortigateAdapter::import_str(self, raw, file)
    }

    fn vendor(&self) -> Vendor {
        Vendor::Fortigate
    }

    /// Reconnaissance par motifs caractéristiques du format FortiOS.
    /// `#config-version=` est quasi certain à lui seul ; les blocs
    /// `config …` typiques renforcent le score.
    fn detect(&self, raw: &str) -> Confidence {
        let mut score: u32 = 0;
        if raw.contains("#config-version=") {
            score += 60;
        }
        if raw.contains("config system interface") {
            score += 15;
        }
        if raw.contains("config firewall policy") {
            score += 15;
        }
        if raw.contains("config system global") {
            score += 10;
        }
        if raw.contains("config router static") {
            score += 10;
        }
        // La structure edit/next/end est nécessaire au format.
        let has_structure = raw.lines().any(|l| l.trim() == "next")
            && raw.lines().any(|l| l.trim() == "end")
            && raw.lines().any(|l| l.trim_start().starts_with("edit "));
        if has_structure {
            score += 10;
        } else {
            // Sans cette structure, ce n'est pas une configuration
            // FortiGate exploitable, quels que soient les autres motifs.
            score = score.min(30);
        }
        Confidence::new(score.min(100) as u8)
    }

    fn to_ir(&self, tree: &ConfigTree) -> Result<AdapterOutput, Vec<Diagnostic>> {
        convert::convert(tree)
    }
}
