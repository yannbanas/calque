//! Adaptateur OPNsense (et détection pfSense) — couche 2, la sémantique
//! (§6.2, §6.4 : « pfSense / OPNsense — configuration en XML, donc
//! analyseur presque gratuit »). La couche 1 est `calque_parse::xml`.
//!
//! ## Choix de modélisation documentés
//!
//! - **Interfaces et zones.** `<interfaces>` déclare des clés logiques
//!   (`wan`, `lan`, `optN`) que les règles référencent. Chaque interface
//!   devient une zone à un membre ; sa `<descr>` fait office d'ALIAS AU
//!   NOM LOGIQUE (l'`opt1` décrit « dmz » donne la zone `dmz`), sinon la
//!   clé elle-même. Une interface sans `<enable>` est désactivée : gardée
//!   dans le modèle mais `AdminState::Down` (§3.2), avec une note.
//!
//! - **Ordre et premier match.** L'ORDRE DU FICHIER est l'ordre
//!   d'évaluation. pf évalue nativement en DERNIER-match, mais OPNsense
//!   génère chaque règle avec le mot-clé `quick`, qui rend la PREMIÈRE
//!   correspondance décisive — c'est donc bien la sémantique
//!   « première correspondance gagne » du modèle (§3.3). Une règle
//!   portant explicitement `<quick>0</quick>` retombe dans le
//!   dernier-match : non modélisée, diagnostiquée.
//!
//! - **Action par défaut.** Le pf généré par OPNsense se termine par un
//!   refus implicite de tout ce qu'aucune règle n'autorise :
//!   `default_action = Deny`, et la politique `filter` existe même sans
//!   section `<filter>`. Comportement documenté du produit, pas une
//!   supposition.
//!
//! - **Accrochage.** Le filtrage pf est attaché à l'interface d'ENTRÉE
//!   (direction `in` par défaut) : politique `filter` dans
//!   `Pipeline::ingress`, `from` = zone de l'interface, `to` = `None`
//!   (une règle OPNsense ne connaît pas l'interface de sortie). `pass` →
//!   `Accept`, `block` ET `reject` → `Deny` (même verdict d'accessibilité,
//!   `reject` répond en plus — nuance sans effet sur « qui joint quoi »).
//!
//! - **NAT.** Les redirections de ports (`<nat><rule>`) forment la
//!   politique `dnat`, placée AVANT `filter` dans le pipeline : chez pf
//!   les `rdr` s'appliquent avant les règles de filtrage, qui voient la
//!   destination TRADUITE. `default_action = Accept` (une redirection ne
//!   filtre pas : sans correspondance, le paquet continue non traduit).
//!   Le NAT sortant `automatic`/`disabled` est une note ; `hybrid`,
//!   `advanced` et les règles manuelles sont diagnostiqués.
//!
//! - **Aliases.** Les deux emplacements sont lus : le moderne
//!   (`<OPNsense><Firewall><Alias>`, OPNsense ≥ 21, contenu séparé par
//!   des sauts de ligne) et l'ancien (`<aliases>` à la racine, séparé
//!   par des espaces — c'est aussi la forme pfSense). `host`/`network` →
//!   objets d'adresses, `port` → objets de services (protocole `Any` :
//!   l'alias vaut pour le protocole que la règle précise). Les objets
//!   sont résolus tard (§3.3) — sauf un alias de ports référencé par une
//!   règle À protocole, réduit à sa plage au moment de la conversion
//!   (l'intersection protocole × alias n'est pas représentable dans une
//!   `Rule`).
//!
//! - **Routage.** `<gateways>` nomme les passerelles ; `defaultgw` (ou
//!   `<defaultgw4>`) produit la route par défaut, `<staticroutes>` les
//!   routes statiques (métrique uniforme : OPNsense n'expose pas de
//!   distance).
//!
//! - **pfSense.** Racine `<pfsense>` : format cousin, converti par le
//!   même adaptateur avec une note ; les clés propres à pfSense qui ne
//!   sont pas comprises sont diagnostiquées au cas par cas, honnêtement,
//!   comme tout le reste (§6.3).
//!
//! - **Non modélisé mais touchant le trafic** (ipsec, openvpn,
//!   wireguard, shaper, CARP/`<virtualip>`, captive portal, règles
//!   flottantes, routage par politique…) : `Diagnostic` Warning +
//!   `Fidelity::Partial`. La liste EXPLICITE des sections ignorables
//!   (DHCP, DNS, NTP, SNMP, certificats, `<system>`…) vit dans
//!   `convert.rs`. Les secrets du fichier (mots de passe hachés, clés
//!   privées, communautés SNMP) ne sont JAMAIS recopiés dans un
//!   diagnostic : seul le NOM d'un élément non compris y figure (§11.4).

mod convert;
mod values;

use calque_model::{Diagnostic, SourceSpan, Vendor};

use crate::{AdapterOutput, Confidence, ConfigTree, VendorAdapter};

/// L'adaptateur OPNsense/pfSense (config.xml).
#[derive(Debug, Default, Clone, Copy)]
pub struct OpnsenseAdapter;

impl OpnsenseAdapter {
    /// Commodité : analyse le texte brut avec l'analyseur XML de
    /// `calque-parse` (couche 1) puis convertit en IR. `file` est le nom
    /// rapporté dans tous les `SourceSpan`.
    ///
    /// Une erreur de syntaxe de la couche 1 devient un `Diagnostic`
    /// d'erreur portant le fichier et la ligne fautive.
    pub fn import_str(&self, raw: &str, file: &str) -> Result<AdapterOutput, Vec<Diagnostic>> {
        let tree = calque_parse::xml::parse(raw, file).map_err(|e| {
            vec![Diagnostic::error(
                e.to_string(),
                Some(SourceSpan::new(e.file(), e.line())),
            )]
        })?;
        self.to_ir(&tree)
    }
}

impl VendorAdapter for OpnsenseAdapter {
    fn label(&self) -> &'static str {
        "OPNsense/pfSense"
    }

    fn import_str(&self, raw: &str, file: &str) -> Result<AdapterOutput, Vec<Diagnostic>> {
        OpnsenseAdapter::import_str(self, raw, file)
    }

    fn vendor(&self) -> Vendor {
        Vendor::Opnsense
    }

    /// Reconnaissance par la racine du document : `<opnsense>` est quasi
    /// certaine, `<pfsense>` (format cousin) l'est presque autant. Les
    /// sections caractéristiques renforcent le score. Sans l'une de ces
    /// racines, ce n'est pas un config.xml exploitable : zéro.
    fn detect(&self, raw: &str) -> Confidence {
        let mut score: u32 = 0;
        if raw.contains("<opnsense>") || raw.contains("<opnsense ") {
            score += 80;
        } else if raw.contains("<pfsense>") || raw.contains("<pfsense ") {
            score += 70;
        } else {
            return Confidence::NONE;
        }
        if raw.contains("<interfaces>") {
            score += 10;
        }
        if raw.contains("<filter>") {
            score += 5;
        }
        if raw.contains("<rule>") || raw.contains("<rule ") {
            score += 5;
        }
        Confidence::new(score.min(100) as u8)
    }

    fn to_ir(&self, tree: &ConfigTree) -> Result<AdapterOutput, Vec<Diagnostic>> {
        convert::convert(tree)
    }
}
