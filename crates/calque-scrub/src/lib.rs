//! calque-scrub — anonymisation cohérente des configurations (§11.4).
//!
//! Remplace DE FAÇON COHÉRENTE les adresses, noms d'hôtes et identifiants
//! d'une configuration en PRÉSERVANT LA STRUCTURE : la sortie se ré-analyse
//! en un arbre de même forme, et les relations de sous-réseau survivent
//! (si A ∈ B avant, alors scrub(A) ∈ scrub(B) après, pour toute longueur
//! de préfixe — voir [`ip`]). Le comportement du modèle reste testable.
//!
//! Crate PUR : aucune entrée/sortie, aucune horloge, aucun aléa — la
//! graine du brouillage est fixe et documentée ([`ip::GRAINE`]). Deux
//! exécutions sur les mêmes textes donnent exactement la même sortie.
//! Aucune panique sur une entrée externe (§11.3).
//!
//! Les trois passes, dans l'ordre :
//! 1. **Secrets** ([`secrets`]) : mots de passe, clés pré-partagées,
//!    clés privées, communautés SNMP, valeurs `ENC`... → `SUPPRIME`,
//!    jamais dans la table de correspondance.
//! 2. **Noms** ([`noms`]) : collecte par la structure (calque-parse),
//!    remplacement `anon-<type>-<n>` stable par première apparition.
//! 3. **Adresses** : remplacement lexical par un automorphisme d'arbre de
//!    préfixes ([`ip`]) ; plages de documentation et spéciales inchangées ;
//!    masques et jokers reconnus par leur motif ET leur contexte (précédés
//!    d'une adresse sur la même ligne) et laissés intacts.
//!
//! Le même [`Scrubber`] peut traiter plusieurs fichiers : la table de
//! correspondance est partagée, donc tout un parc reste cohérent.

mod ip;
mod noms;
mod secrets;
mod texte;

use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::{Ipv4Addr, Ipv6Addr};

use texte::{segmenter, Seg};

/// L'anonymiseur. Réutilisable sur plusieurs fichiers : le mapping —
/// noms comme adresses — est conservé d'un appel à l'autre.
#[derive(Debug, Default)]
pub struct Scrubber {
    /// Table de correspondance publique original → remplacement
    /// (adresses, noms, descriptions — JAMAIS de secrets). Triée pour un
    /// parcours déterministe.
    table: BTreeMap<String, String>,
    /// Tout ce que le scrub a déjà produit : re-passé en entrée, un
    /// remplacement reste tel quel (idempotence).
    produits: HashSet<String>,
    /// Noms remplacés uniquement comme contenu exact d'une zone citée.
    noms_cites: HashMap<String, String>,
    /// Noms remplacés partout, à une frontière de mot.
    noms_libres: HashMap<String, String>,
    /// Queues de lignes `description` Cisco (clé normalisée en espaces).
    descriptions: HashMap<String, String>,
    /// Prochain numéro par type d'objet (`anon-<type>-<n>`).
    compteurs: BTreeMap<String, u32>,
}

impl Scrubber {
    /// Un anonymiseur vierge, au mapping vide.
    pub fn new() -> Self {
        Self::default()
    }

    /// Anonymise `entree` et renvoie le texte transformé. Chaque appel
    /// enrichit le mapping commun : passer plusieurs fichiers au même
    /// `Scrubber` garantit des remplacements identiques partout.
    pub fn scrub(&mut self, entree: &str) -> String {
        // Passe 0 : les secrets disparaissent avant toute analyse — une
        // clé privée multi-lignes ne doit même pas atteindre l'analyseur.
        let expurge = secrets::rediger(entree);
        // Passe 1 : collecte des noms déclarés, par la structure.
        self.collecter(&expurge);
        // Passe 2 : réécriture ligne à ligne, au caractère près.
        let mut lignes: Vec<String> = Vec::new();
        for brute in expurge.split('\n') {
            let (contenu, cr) = match brute.strip_suffix('\r') {
                Some(c) => (c, "\r"),
                None => (brute, ""),
            };
            let mut faite = self.traiter_ligne(contenu);
            faite.push_str(cr);
            lignes.push(faite);
        }
        lignes.join("\n")
    }

    /// La table de correspondance original → remplacement, triée par
    /// original. À conserver en lieu sûr : c'est elle qui permet de
    /// relire un diagnostic anonymisé. Les secrets n'y figurent jamais.
    pub fn mapping(&self) -> impl Iterator<Item = (&str, &str)> + '_ {
        self.table.iter().map(|(o, r)| (o.as_str(), r.as_str()))
    }

    // ------------------------------------------------------------------
    // Passe 2 : réécriture
    // ------------------------------------------------------------------

    fn traiter_ligne(&mut self, ligne: &str) -> String {
        // Ligne `description` Cisco : queue remplacée d'un bloc.
        let coupe = ligne.trim_start();
        if let Some(reste) = coupe.strip_prefix("description") {
            if reste.starts_with(char::is_whitespace) {
                let cle = reste.split_whitespace().collect::<Vec<_>>().join(" ");
                if let Some(r) = self.descriptions.get(&cle) {
                    let retrait = &ligne[..ligne.len() - coupe.len()];
                    return format!("{retrait}description {r}");
                }
            }
        }

        let mut sortie = String::with_capacity(ligne.len() + 16);
        let mut adresse_vue = false;
        for seg in segmenter(ligne) {
            match seg {
                Seg::Brut(t) => {
                    let apres_noms = self.remplacer_noms_libres(t);
                    sortie.push_str(&self.remplacer_adresses(&apres_noms, &mut adresse_vue));
                }
                Seg::Citee { interieur, ferme } => {
                    sortie.push('"');
                    match self.remplacement_exact(interieur) {
                        Some(r) => sortie.push_str(&r),
                        None => {
                            let apres_noms = self.remplacer_noms_libres(interieur);
                            sortie
                                .push_str(&self.remplacer_adresses(&apres_noms, &mut adresse_vue));
                        }
                    }
                    if ferme {
                        sortie.push('"');
                    }
                }
            }
        }
        sortie
    }

    /// Remplacement d'une zone citée entière (`"h-srv-web"` → `"anon-addr-1"`).
    fn remplacement_exact(&self, interieur: &str) -> Option<String> {
        self.noms_cites
            .get(interieur)
            .or_else(|| self.noms_libres.get(interieur))
            .cloned()
    }

    /// Remplace les noms « libres » aux frontières de mots. Un mot est une
    /// suite de `[A-Za-z0-9_.-]` ou d'octets non ASCII : un nom n'est
    /// jamais remplacé au milieu d'un identifiant plus long.
    fn remplacer_noms_libres(&self, texte: &str) -> String {
        fn octet_de_mot(b: u8) -> bool {
            b.is_ascii_alphanumeric() || b == b'_' || b == b'-' || b == b'.' || b >= 0x80
        }
        if self.noms_libres.is_empty() {
            return texte.to_owned();
        }
        let b = texte.as_bytes();
        let mut sortie = String::with_capacity(texte.len());
        let mut i = 0usize;
        while i < b.len() {
            let debut = i;
            if octet_de_mot(b[i]) {
                while i < b.len() && octet_de_mot(b[i]) {
                    i += 1;
                }
                let mot = &texte[debut..i];
                match self.noms_libres.get(mot) {
                    Some(r) => sortie.push_str(r),
                    None => sortie.push_str(mot),
                }
            } else {
                while i < b.len() && !octet_de_mot(b[i]) {
                    i += 1;
                }
                sortie.push_str(&texte[debut..i]);
            }
        }
        sortie
    }

    /// Détection lexicale et remplacement des adresses IPv4 (et IPv6, au
    /// mieux). `adresse_vue` porte le contexte de ligne pour les masques.
    fn remplacer_adresses(&mut self, texte: &str, adresse_vue: &mut bool) -> String {
        fn dans_charset(b: u8) -> bool {
            b.is_ascii_hexdigit() || b == b'.' || b == b':'
        }
        fn bloquant(b: u8) -> bool {
            b.is_ascii_alphanumeric() || b == b'_'
        }
        let b = texte.as_bytes();
        let mut sortie = String::with_capacity(texte.len());
        let mut i = 0usize;
        while i < b.len() {
            let debut = i;
            if dans_charset(b[i]) {
                while i < b.len() && dans_charset(b[i]) {
                    i += 1;
                }
                let course = &texte[debut..i];
                // Frontières : pas collé à un identifiant (sauf départ en
                // `:` — cas `libelle:10.0.0.1`).
                let prec_colle = debut > 0 && bloquant(b[debut - 1]) && !course.starts_with(':');
                let suiv_colle = i < b.len() && bloquant(b[i]);
                if prec_colle || suiv_colle {
                    sortie.push_str(course);
                } else {
                    sortie.push_str(&self.remplacer_course(course, adresse_vue));
                }
            } else {
                while i < b.len() && !dans_charset(b[i]) {
                    i += 1;
                }
                sortie.push_str(&texte[debut..i]);
            }
        }
        sortie
    }

    /// Une « course » lexicale (chiffres hexadécimaux, `.` et `:`) :
    /// IPv6 entière, ou morceaux IPv4 séparés par `:` (`1.2.3.4:443`).
    fn remplacer_course(&mut self, course: &str, adresse_vue: &mut bool) -> String {
        if course.contains(':') {
            if let Ok(a) = course.parse::<Ipv6Addr>() {
                return self.remplacer_v6(course, a);
            }
            let rogne = course.trim_end_matches(':');
            if rogne.len() < course.len() {
                if let Ok(a) = rogne.parse::<Ipv6Addr>() {
                    let mut s = self.remplacer_v6(rogne, a);
                    s.push_str(&course[rogne.len()..]);
                    return s;
                }
            }
            let morceaux: Vec<String> = course
                .split(':')
                .map(|m| self.remplacer_morceau_v4(m, adresse_vue))
                .collect();
            return morceaux.join(":");
        }
        self.remplacer_morceau_v4(course, adresse_vue)
    }

    /// Un morceau candidat IPv4, débarrassé de ses points de bordure
    /// (`10.0.0.1.` en fin de phrase reste reconnu).
    fn remplacer_morceau_v4(&mut self, morceau: &str, adresse_vue: &mut bool) -> String {
        let sans_tete = morceau.trim_start_matches('.');
        let tete = &morceau[..morceau.len() - sans_tete.len()];
        let coeur = sans_tete.trim_end_matches('.');
        let queue = &sans_tete[coeur.len()..];
        match coeur.parse::<Ipv4Addr>() {
            Ok(a) => format!("{tete}{}{queue}", self.remplacer_v4(coeur, a, adresse_vue)),
            Err(_) => morceau.to_owned(),
        }
    }

    fn remplacer_v4(&mut self, original: &str, a: Ipv4Addr, adresse_vue: &mut bool) -> String {
        // Idempotence : une adresse déjà produite par ce scrub reste là.
        if self.produits.contains(original) {
            *adresse_vue = true;
            return original.to_owned();
        }
        // Plages spéciales et de documentation : inchangées.
        if ip::speciale_v4(a) {
            *adresse_vue = true;
            return original.to_owned();
        }
        // Masque ou joker : motif valide ET précédé d'une adresse sur la
        // même ligne — ce n'est pas une adresse, on n'y touche pas.
        if *adresse_vue && ip::masque_ou_joker(a) {
            return original.to_owned();
        }
        *adresse_vue = true;
        if let Some(r) = self.table.get(original) {
            return r.clone();
        }
        let remplacement = ip::transformer_v4(a).to_string();
        self.table.insert(original.to_owned(), remplacement.clone());
        self.produits.insert(remplacement.clone());
        remplacement
    }

    fn remplacer_v6(&mut self, original: &str, a: Ipv6Addr) -> String {
        if self.produits.contains(original) {
            return original.to_owned();
        }
        // `::ffff:a.b.c.d` : c'est une IPv4 déguisée — même transformation
        // que la forme nue, pour rester cohérent.
        if let Some(v4) = a.to_ipv4_mapped() {
            if ip::speciale_v4(v4) {
                return original.to_owned();
            }
            if let Some(r) = self.table.get(original) {
                return r.clone();
            }
            let remplacement = ip::transformer_v4(v4).to_ipv6_mapped().to_string();
            self.table.insert(original.to_owned(), remplacement.clone());
            self.produits.insert(remplacement.clone());
            return remplacement;
        }
        if ip::speciale_v6(a) {
            return original.to_owned();
        }
        if let Some(r) = self.table.get(original) {
            return r.clone();
        }
        let remplacement = ip::transformer_v6(a).to_string();
        self.table.insert(original.to_owned(), remplacement.clone());
        self.produits.insert(remplacement.clone());
        remplacement
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn les_masques_suivent_une_adresse_les_adresses_changent() {
        let mut s = Scrubber::new();
        let sortie = s.scrub("    set ip 10.9.8.7 255.255.255.0\n");
        assert!(!sortie.contains("10.9.8.7"));
        assert!(sortie.contains(" 255.255.255.0"));
        // Joker Cisco après une adresse : intact.
        let sortie = s.scrub("access-list 10 permit ip 10.1.2.0 0.0.0.255\n");
        assert!(!sortie.contains("10.1.2.0"));
        assert!(sortie.contains(" 0.0.0.255"));
        // Masque non trivial (192.0.0.0 = /2) : intact aussi.
        let sortie = s.scrub("network 10.1.2.0 mask 192.0.0.0\n");
        assert!(sortie.contains("mask 192.0.0.0"));
    }

    #[test]
    fn hote_et_port_et_cidr() {
        let mut s = Scrubber::new();
        let sortie = s.scrub("serveur 10.20.30.40:8443 et 10.20.30.0/24\n");
        assert!(!sortie.contains("10.20.30.40"));
        assert!(sortie.contains(":8443"));
        assert!(sortie.contains("/24"));
        // Cohérence : même /24 des deux côtés.
        let t: Vec<(&str, &str)> = s.mapping().collect();
        let a = t.iter().find(|(o, _)| *o == "10.20.30.40").unwrap().1;
        let b = t.iter().find(|(o, _)| *o == "10.20.30.0").unwrap().1;
        let pa: std::net::Ipv4Addr = a.parse().unwrap();
        let pb: std::net::Ipv4Addr = b.parse().unwrap();
        assert_eq!(u32::from(pa) >> 8, u32::from(pb) >> 8);
    }

    #[test]
    fn ipv6_remplacee_et_speciales_conservees() {
        let mut s = Scrubber::new();
        let sortie = s.scrub("set ip6 fd12:3456::10/64\nping ::1\nping 2001:db8::7\n");
        assert!(!sortie.contains("fd12:3456::10"));
        assert!(sortie.contains("/64"));
        assert!(sortie.contains("::1"));
        assert!(sortie.contains("2001:db8::7"));
    }

    #[test]
    fn portranges_et_numeros_intacts() {
        let mut s = Scrubber::new();
        let texte =
            "        set tcp-portrange 7000-7010:1024-65535\n        set udp-portrange 7000\n";
        assert_eq!(s.scrub(texte), texte);
    }

    #[test]
    fn le_mapping_est_trie_et_expose() {
        let mut s = Scrubber::new();
        s.scrub("config system global\n    set hostname \"fw-un\"\nend\nping 10.3.2.1\n");
        let t: Vec<(&str, &str)> = s.mapping().collect();
        assert!(t.iter().any(|(o, r)| *o == "fw-un" && *r == "anon-host-1"));
        assert!(t.iter().any(|(o, _)| *o == "10.3.2.1"));
        let originaux: Vec<&str> = t.iter().map(|(o, _)| *o).collect();
        let mut tries = originaux.clone();
        tries.sort_unstable();
        assert_eq!(originaux, tries);
    }
}
