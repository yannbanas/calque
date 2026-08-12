//! Passe 1 : collecte des noms choisis par l'utilisateur, en s'appuyant
//! sur la STRUCTURE (jamais sur du flair lexical) :
//!
//! - FortiGate (format CLI OU export YAML — les deux arbres de
//!   calque-parse ont la même forme). Seuls sont des noms les arguments
//!   d'`edit` (interfaces, zones, objets d'adresse, services, plannings,
//!   tunnels, utilisateurs, administrateurs...) et les valeurs de
//!   certaines clés `set` à valeur libre : `hostname`, `alias`,
//!   `description`, `comment`, `comments`, `location`, `contact`,
//!   `contact-info` (SNMP), `fqdn`, `ddns-domain`, `username`, `dn`
//!   (LDAP), et `name` (règles de pare-feu). Les MOTS-CLÉS et les
//!   valeurs d'énumération (`accept`, `deny`, `enable`, `lan`...) ne
//!   sont jamais collectés. Si l'analyse CLI échoue (blocs cités
//!   multi-lignes d'une vraie configuration), un collecteur ligne à
//!   ligne indulgent prend le relais avec les mêmes règles.
//! - Cisco IOS : l'arbre de calque-parse. `hostname`, noms d'ACL
//!   (`ip access-list standard|extended`), `object-group`,
//!   `zone security`, et les queues de `description`.
//!
//! Chaque nom reçoit `anon-<type>-<n>`, stable par ordre de première
//! apparition et partagé entre tous les fichiers passés au même
//! [`Scrubber`](crate::Scrubber).

use std::net::{Ipv4Addr, Ipv6Addr};

use calque_parse::{cisco_ios, fortigate, fortigate_yaml, ConfigNode};

use crate::texte::{decouper_lexemes, est_anonyme};
use crate::{RapportScrub, Scrubber};

/// Où un nom peut être remplacé.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Portee {
    /// Uniquement comme contenu exact d'une zone entre guillemets — le
    /// régime FortiGate, où les références sont toujours citées. Évite de
    /// toucher une énumération homonyme (`set role lan` vs `edit "lan"`).
    Citee,
    /// Partout, à une frontière de mot près (noms d'hôte, ACL Cisco...).
    Libre,
}

/// Identifiants qui appartiennent au constructeur, jamais à l'utilisateur.
const LISTE_D_ARRET: &[&str] = &[
    "all", "any", "always", "none", "root", "default", "enable", "disable", "accept", "deny",
    "unknown",
];

/// Type d'objet (pour `anon-<type>-<n>`) selon le chemin du bloc `config`.
fn type_pour_chemin(chemin: &str) -> &'static str {
    if chemin.starts_with("system interface") {
        "intf"
    } else if chemin.contains("zone") {
        "zone"
    } else if chemin.starts_with("firewall service") {
        "svc"
    } else if chemin.starts_with("firewall schedule") {
        "sched"
    } else if chemin.starts_with("firewall addr")
        || chemin.starts_with("firewall vip")
        || chemin.starts_with("firewall ippool")
    {
        "addr"
    } else if chemin.starts_with("vpn") {
        "vpn"
    } else if chemin.starts_with("user") || chemin.starts_with("system admin") {
        "user"
    } else {
        "obj"
    }
}

/// Le texte ressemble-t-il à une configuration Cisco IOS ? L'analyseur
/// Cisco (par indentation) accepte à peu près n'importe quel texte : la
/// reconnaissance du FORMAT exige en plus un motif caractéristique.
fn ressemble_cisco(texte: &str) -> bool {
    texte.lines().any(|l| {
        let t = l.trim_start();
        t.starts_with("hostname ")
            || t.starts_with("interface ")
            || t.starts_with("ip access-list")
            || t.starts_with("access-list ")
            || t.starts_with("object-group ")
            || t.starts_with("zone security")
            || t.starts_with("ip route ")
            || t.starts_with("snmp-server ")
            || t.starts_with("enable secret")
            || t.starts_with("enable password")
    })
}

impl Scrubber {
    /// Passe 1 complète sur un texte déjà expurgé de ses secrets.
    /// Renvoie ce qui a été reconnu : quand `format_reconnu` est faux,
    /// AUCUNE collecte structurelle n'a pu avoir lieu et l'appelant doit
    /// prévenir que l'anonymisation est probablement incomplète.
    pub(crate) fn collecter(&mut self, texte: &str) -> RapportScrub {
        // 1. FortiGate au format CLI, par l'arbre.
        if let Ok(arbre) = fortigate::parse(texte, "scrub") {
            if arbre.roots.iter().any(|n| n.keyword == "config") {
                self.visiter_fortigate(&arbre.roots, "");
                return RapportScrub::reconnu("fortigate");
            }
        }
        // 2. Export YAML FortiOS : l'arbre a la MÊME forme que le CLI
        // (config/edit/set), la collecte structurelle est partagée.
        if let Ok(arbre) = fortigate_yaml::parse(texte, "scrub") {
            let structure = arbre
                .roots
                .iter()
                .any(|n| n.keyword == "config" && !n.children.is_empty());
            if structure {
                // On collecte dans tous les cas (plus de collecte = plus
                // sûr), mais on ne PRÉTEND reconnaître l'export FortiOS
                // qu'avec son en-tête ou de vraies entrées `- nom:`.
                self.visiter_fortigate(&arbre.roots, "");
                let export_fortios = texte.contains("#config-version=")
                    || arbre
                        .roots
                        .iter()
                        .any(|n| n.children.iter().any(|c| c.keyword == "edit"));
                if export_fortios {
                    return RapportScrub::reconnu("fortigate-yaml");
                }
                return RapportScrub::inconnu();
            }
        }
        // 3. Repli FortiGate CLI ligne à ligne (blocs cités multi-lignes
        // restants, exports abîmés...) : mêmes règles, en indulgent.
        let ressemble_fortigate = texte.lines().any(|l| {
            let t = l.trim_start();
            t == "config" || t.starts_with("config ")
        });
        if ressemble_fortigate {
            self.collecter_fortigate_lignes(texte);
            return RapportScrub::reconnu("fortigate-degrade");
        }
        // 4. Cisco IOS. L'analyse par indentation réussit sur presque
        // tout : la collecte a lieu dès qu'elle réussit (sûreté), mais le
        // format n'est RECONNU qu'avec un motif caractéristique.
        if let Ok(arbre) = cisco_ios::parse(texte, "scrub") {
            self.collecter_cisco(&arbre.roots);
            if ressemble_cisco(texte) {
                return RapportScrub::reconnu("cisco-ios");
            }
        }
        // Sinon : aucun nom collecté ; adresses et secrets sont tout de
        // même traités par les autres passes — d'où l'avertissement.
        RapportScrub::inconnu()
    }

    fn visiter_fortigate(&mut self, noeuds: &[ConfigNode], chemin: &str) {
        for n in noeuds {
            match n.keyword.as_str() {
                "config" => {
                    let interieur = n.args_joined().to_ascii_lowercase();
                    self.visiter_fortigate(&n.children, &interieur);
                }
                "edit" => {
                    if let Some(nom) = n.arg(0) {
                        self.enregistrer_nom(nom, type_pour_chemin(chemin), Portee::Citee);
                    }
                    self.visiter_fortigate(&n.children, chemin);
                }
                "set" => {
                    if let (Some(cle), true) = (n.arg(0), n.args.len() >= 2) {
                        let valeur = n.args[1..].join(" ");
                        self.collecter_valeur_libre(cle, &valeur, chemin);
                    }
                }
                _ => self.visiter_fortigate(&n.children, chemin),
            }
        }
    }

    /// Clés `set` à valeur libre (communes aux collecteurs FortiGate,
    /// format CLI comme export YAML).
    fn collecter_valeur_libre(&mut self, cle: &str, valeur: &str, chemin: &str) {
        match cle {
            "hostname" => self.enregistrer_nom(valeur, "host", Portee::Libre),
            "alias" => self.enregistrer_nom(valeur, "alias", Portee::Libre),
            // Textes libres : descriptions, localisation et contact SNMP.
            "description" | "comment" | "comments" | "location" | "contact" | "contact-info" => {
                self.enregistrer_nom(valeur, "desc", Portee::Citee);
            }
            "fqdn" | "ddns-domain" => self.enregistrer_nom(valeur, "fqdn", Portee::Libre),
            // Identifiants LDAP/annuaire : compte de liaison et DN de base.
            "username" => self.enregistrer_nom(valeur, "user", Portee::Libre),
            "dn" => self.enregistrer_nom(valeur, "user", Portee::Citee),
            "name" if chemin.contains("policy") => {
                self.enregistrer_nom(valeur, "regle", Portee::Citee);
            }
            // Communauté SNMP FortiOS : un secret déguisé en nom. Remplacée
            // par SUPPRIME, hors table de correspondance.
            "name" if chemin.contains("snmp") && !valeur.is_empty() && !est_anonyme(valeur) => {
                self.noms_cites
                    .entry(valeur.to_owned())
                    .or_insert_with(|| "SUPPRIME".to_owned());
            }
            _ => {}
        }
    }

    /// Repli indulgent quand l'arbre FortiGate ne se construit pas
    /// (valeurs citées multi-lignes restantes, exports abîmés...).
    fn collecter_fortigate_lignes(&mut self, texte: &str) {
        let mut chemins: Vec<String> = Vec::new();
        for ligne in texte.lines() {
            let lex = decouper_lexemes(ligne);
            let Some(premier) = lex.first() else { continue };
            match premier.as_str() {
                "config" => chemins.push(lex[1..].join(" ").to_ascii_lowercase()),
                "end" => {
                    chemins.pop();
                }
                "edit" => {
                    if let Some(nom) = lex.get(1) {
                        let chemin = chemins.last().map(String::as_str).unwrap_or("");
                        self.enregistrer_nom(nom, type_pour_chemin(chemin), Portee::Citee);
                    }
                }
                "set" if lex.len() >= 3 => {
                    let chemin = chemins.last().cloned().unwrap_or_default();
                    let valeur = lex[2..].join(" ");
                    self.collecter_valeur_libre(&lex[1], &valeur, &chemin);
                }
                _ => {}
            }
        }
    }

    fn collecter_cisco(&mut self, noeuds: &[ConfigNode]) {
        for n in noeuds {
            match n.keyword.as_str() {
                "hostname" => {
                    if let Some(v) = n.arg(0) {
                        self.enregistrer_nom(v, "host", Portee::Libre);
                    }
                }
                "ip" if n.arg(0) == Some("access-list") => {
                    if let Some(nom) = n.arg(2) {
                        self.enregistrer_nom(nom, "acl", Portee::Libre);
                    }
                }
                "object-group" => {
                    if let Some(nom) = n.arg(1) {
                        self.enregistrer_nom(nom, "obj", Portee::Libre);
                    }
                }
                "zone" if n.arg(0) == Some("security") => {
                    if let Some(nom) = n.arg(1) {
                        self.enregistrer_nom(nom, "zone", Portee::Libre);
                    }
                }
                "description" => {
                    let queue = n.args_joined();
                    self.enregistrer_description(&queue);
                }
                _ => {}
            }
            self.collecter_cisco(&n.children);
        }
    }

    /// Enregistre un nom déclaré, avec toutes les gardes : jamais un
    /// nombre nu (`edit 1`), jamais un identifiant constructeur, jamais un
    /// remplacement déjà anonyme, jamais une adresse IP (la passe adresses
    /// s'en charge, de façon cohérente), jamais deux fois.
    pub(crate) fn enregistrer_nom(&mut self, original: &str, genre: &str, portee: Portee) {
        let o = original.trim();
        if o.len() < 2
            || o.chars().all(|c| c.is_ascii_digit())
            || est_anonyme(o)
            || LISTE_D_ARRET.contains(&o.to_ascii_lowercase().as_str())
            || o.parse::<Ipv4Addr>().is_ok()
            || o.parse::<Ipv6Addr>().is_ok()
            || self.noms_cites.contains_key(o)
            || self.noms_libres.contains_key(o)
        {
            return;
        }
        let n = self.compteurs.entry(genre.to_owned()).or_insert(0);
        *n += 1;
        let remplacement = format!("anon-{genre}-{n}");
        self.table.insert(o.to_owned(), remplacement.clone());
        self.produits.insert(remplacement.clone());
        match portee {
            Portee::Citee => {
                self.noms_cites.insert(o.to_owned(), remplacement);
            }
            Portee::Libre => {
                self.noms_libres.insert(o.to_owned(), remplacement);
            }
        }
    }

    /// Queue d'une ligne `description` Cisco (texte libre non cité),
    /// normalisée en espaces simples pour un rappel fiable.
    pub(crate) fn enregistrer_description(&mut self, queue: &str) {
        let cle = queue.split_whitespace().collect::<Vec<_>>().join(" ");
        if cle.is_empty() || est_anonyme(&cle) || self.descriptions.contains_key(&cle) {
            return;
        }
        let n = self.compteurs.entry("desc".to_owned()).or_insert(0);
        *n += 1;
        let remplacement = format!("anon-desc-{n}");
        self.table.insert(cle.clone(), remplacement.clone());
        self.produits.insert(remplacement.clone());
        self.descriptions.insert(cle, remplacement);
    }
}
