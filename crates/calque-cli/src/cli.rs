//! La structure de la ligne de commande (§10 de CALQUE-ARCHITECTURE.md).

use std::net::IpAddr;
use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};
use ipnet::IpNet;

/// Calque — lit les configurations d'équipements réseau, en construit un
/// modèle, et répond à « qui peut joindre quoi » et « qu'est-ce qui casse
/// si j'applique ce changement ». Lecture seule, toujours.
#[derive(Debug, Parser)]
#[command(name = "calque", version, about, max_term_width = 100)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Importer une ou plusieurs configurations dans le projet `.calque/`
    Import(ImportArgs),
    /// Vérifier le modèle
    Model {
        #[command(subcommand)]
        command: ModelCommand,
    },
    /// Interroger un chemin : `calque path 10.0.10.5 '->' 10.0.20.10:445/tcp`
    Path(PathArgs),
    /// Mode symbolique (§5.3) : tout ce qui peut atteindre une cible
    /// (`--to`), ou tout ce qu'une source peut atteindre (`--from`)
    Reach(ReachArgs),
    /// Exécuter la suite de flux (flows.yaml) ; code de sortie non nul si un flux échoue
    Test(TestArgs),
    /// Prévisualiser l'effet d'une configuration candidate : flux rompus,
    /// corrigés, et ouvertures que personne n'a demandées
    Plan(PlanArgs),
    /// Vérifier la topologie
    Topology {
        #[command(subcommand)]
        command: TopologyCommand,
    },
    /// Anonymiser une ou plusieurs configurations (§11.4) : adresses, noms
    /// et identifiants remplacés de façon cohérente, secrets supprimés
    Scrub(ScrubArgs),
    /// Collecter un équipement en ligne (SSH, LECTURE SEULE stricte) :
    /// configuration + voisins LLDP/CDP, importés dans le projet (S7)
    #[cfg(feature = "collect")]
    Collect(crate::collect_cmd::CollectArgs),
    /// Confronter le modèle au réel (§11.2) : les flux tcp de flows.yaml
    /// sont testés par de vraies connexions TCP depuis cette machine
    #[cfg(feature = "collect")]
    Verify(crate::collect_cmd::VerifyArgs),
}

#[derive(Debug, clap::Args)]
pub struct ImportArgs {
    /// Fichier de configuration à importer
    #[arg(
        value_name = "FICHIER",
        required_unless_present = "dir",
        conflicts_with = "dir"
    )]
    pub file: Option<PathBuf>,

    /// Importer tous les fichiers d'un répertoire (détection automatique du constructeur)
    #[arg(long, value_name = "RÉPERTOIRE")]
    pub dir: Option<PathBuf>,

    /// Nom à donner à l'équipement (par défaut : le nom du fichier)
    #[arg(long = "as", value_name = "NOM", conflicts_with = "dir")]
    pub name: Option<String>,

    /// Fichier de correspondances noms d'objets externes → préfixes IP,
    /// FOURNI par l'humain (§6.3 : Calque ne devine jamais). Résout les
    /// objets fqdn/wildcard-fqdn/geography irrésolubles hors ligne. Format
    /// YAML : deux sections `fqdn:` et `geography:`, chacune associant un
    /// nom (le domaine ou le code pays) à une liste de préfixes CIDR. Les
    /// wildcard-fqdn sont résolus par correspondance EXACTE de clé (pas de
    /// glob) — fournissez la clé telle quelle (ex. `"*.example.com"`). Ce
    /// qui n'y figure pas reste non résolu.
    #[arg(long, value_name = "FICHIER")]
    pub resolve: Option<PathBuf>,
}

#[derive(Debug, Subcommand)]
pub enum ModelCommand {
    /// Afficher la fidélité du modèle : complet, ou liste des directives non
    /// comprises. Code de sortie non nul si le modèle est partiel avec des
    /// diagnostics d'erreur.
    Check,
    /// Lister les règles mortes de chaque équipement : masquées par des
    /// règles antérieures, ou à l'ensemble vide (S6). Informatif : code de
    /// sortie 0, sauf erreur d'évaluation (objet irrésoluble, cycle).
    #[command(
        name = "dead-rules",
        after_help = "\
Pour chaque règle morte : la cause (MASQUÉE / ENSEMBLE VIDE), la règle et \
sa ligne d'origine, les règles antérieures qui la masquent (avec leurs \
lignes), et un paquet témoin que la règle aurait traité mais qu'un masque \
capte avant elle.

Analyse prudente : une règle n'est déclarée morte que si c'est prouvable \
(un saut antérieur ne masque pas ; en cas d'ensemble trop fragmenté, \
l'analyse s'abstient). Aucun faux positif, mais pas d'exhaustivité \
garantie sur des politiques hostiles."
    )]
    DeadRules {
        /// Format de sortie
        #[arg(long, value_enum, default_value_t = DataFormat::Text)]
        format: DataFormat,
    },
}

#[derive(Debug, Subcommand)]
pub enum TopologyCommand {
    /// Signaler les liens ambigus ou manquants (inférence par sous-réseau
    /// + liens déclarés dans topology.yaml, §7)
    Check {
        /// Fichier de liens déclarés (facultatif ; ignoré s'il n'existe pas).
        /// Format : `links: [{a: {device, iface}, b: {device, iface}}]`
        #[arg(long, value_name = "FICHIER", default_value = "topology.yaml")]
        topology: PathBuf,
    },
}

#[derive(Debug, clap::Args)]
#[command(after_help = "\
Le paquet tracé porte le port source éphémère 40000 (représentatif ; le mode \
symbolique couvrira tout l'intervalle).

Codes de sortie :
  0  autorisé (verdict ferme)
  1  refusé, pas de route ou boucle de routage — ou erreur d'exécution
  2  erreur d'utilisation de la ligne de commande
  3  verdict non ferme : trace indéterminée, ou modèle partiel touchant un \
équipement traversé (§6.3 — Calque ne devine jamais)")]
pub struct PathArgs {
    /// Adresse IP source
    #[arg(value_name = "SOURCE")]
    pub src: IpAddr,

    /// Le séparateur « -> » (entre guillemets dans la plupart des shells)
    #[arg(value_name = "->", allow_hyphen_values = true)]
    pub arrow: String,

    /// Destination, au format IP:PORT/PROTO (ex. 10.0.20.10:445/tcp)
    #[arg(value_name = "DESTINATION")]
    pub dst: String,

    /// Afficher la trace complète, règle par règle
    #[arg(long)]
    pub explain: bool,

    /// Format de sortie (json : la trace complète, structurée ; --explain
    /// est alors sans effet)
    #[arg(long, value_enum, default_value_t = DataFormat::Text)]
    pub format: DataFormat,
}

#[derive(Debug, clap::Args)]
#[command(after_help = "\
CIBLE et SOURCE acceptent : une adresse IP (10.0.20.5), un préfixe CIDR \
(10.0.20.0/24), IP:PORT/PROTO (10.0.20.5:445/tcp), CIDR:PORT/PROTO, ou un \
nom de zone du modèle (résolu comme dans `calque test` : les sous-réseaux \
des interfaces membres). Le port, s'il est donné, contraint toujours le \
port de DESTINATION (avec `--from` aussi : « qu'est-ce que cette source \
peut atteindre sur ce port »). Sans port : tous les ports, tous les \
protocoles. Les adresses IPv6 avec port ne sont pas encore gérées.

La propagation est symbolique (§5.3) : le rapport est AGRÉGÉ — pour chaque \
flux autorisé, le point d'entrée, l'ensemble (préfixes et ports résumés), \
un paquet exemple concret et la chaîne des règles décisives (fichier + \
ligne). Les parts que le modèle ne permet pas de décider sont listées \
honnêtement à la fin (§6.3), jamais devinées. Les ensembles sont exprimés \
APRÈS traductions d'adresse, et les sources ne sont pas restreintes aux \
réseaux topologiquement présents derrière chaque entrée (pas \
d'anti-usurpation modélisé : point de vue prudent d'exposition).

Codes de sortie :
  0  rapport ferme
  1  erreur d'exécution (cible invalide, zone inconnue…)
  2  erreur d'utilisation de la ligne de commande
  3  rapport NON FERME : parts non décidables, ou modèle partiel sur un \
équipement traversé (§6.3 — Calque ne devine jamais)")]
pub struct ReachArgs {
    /// Cible : tout ce qui peut ATTEINDRE cette destination
    #[arg(
        long,
        value_name = "CIBLE",
        required_unless_present = "from",
        conflicts_with = "from"
    )]
    pub to: Option<String>,

    /// Source : tout ce que cette source PEUT ATTEINDRE
    #[arg(long, value_name = "SOURCE")]
    pub from: Option<String>,

    /// Format de sortie
    #[arg(long, value_enum, default_value_t = DataFormat::Text)]
    pub format: DataFormat,
}

/// Format de sortie des rapports symboliques (`reach`, `model dead-rules`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum DataFormat {
    /// Texte lisible
    Text,
    /// JSON, pour les programmes
    Json,
}

#[derive(Debug, clap::Args)]
#[command(after_help = "\
Résolution des extrémités d'un flux (mode concret) :
  - une adresse IP est prise telle quelle ;
  - un préfixe CIDR est représenté par sa première adresse hôte ;
  - un nom symbolique est résolu comme ZONE du modèle (première adresse \
d'hôte d'un sous-réseau d'une interface membre, hors adresse de \
l'interface) ; sinon le flux est compté en échec « extrémité non résolue ».

Code de sortie non nul si au moins un flux ne se comporte pas comme déclaré.")]
pub struct TestArgs {
    /// Le fichier de flux à exécuter
    #[arg(long, value_name = "FICHIER", default_value = "flows.yaml")]
    pub flows: PathBuf,

    /// Format de sortie
    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    pub format: OutputFormat,

    /// Rendre les verdicts même sur un modèle PARTIEL (une configuration
    /// réelle l'est presque toujours : VPN, SD-WAN, profils UTM non
    /// modélisés). Sans ce drapeau, tout flux traversant un équipement à
    /// fidélité partielle est compté en échec « verdict non ferme »
    /// (§6.3). Avec, les verdicts s'appuient sur la partie modélisée —
    /// un avertissement le rappelle sur stderr.
    #[arg(long)]
    pub allow_partial: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum OutputFormat {
    /// Texte lisible
    Text,
    /// JUnit XML, pour l'intégration continue
    Junit,
    /// JSON, pour les programmes
    Json,
}

#[derive(Debug, clap::Args)]
#[command(after_help = "\
La candidate remplace l'équipement du modèle qui porte le même identifiant \
(hostname) — ou l'unique équipement du modèle s'il n'y en a qu'un. Les flux \
de flows.yaml sont rejoués sur les deux modèles ; les ouvertures non \
déclarées sont cherchées par sondes (échantillonnage : une absence de ligne \
NOUVEAU ne prouve rien avant le mode symbolique).

Code de sortie non nul si un flux est ROMPU ou si une ouverture NOUVEAU est \
détectée.")]
pub struct PlanArgs {
    /// La configuration candidate à comparer au modèle courant
    #[arg(long, value_name = "FICHIER")]
    pub candidate: PathBuf,

    /// Le fichier de flux à rejouer des deux côtés (facultatif : sans lui,
    /// seules les ouvertures nouvelles sont recherchées)
    #[arg(long, value_name = "FICHIER", default_value = "flows.yaml")]
    pub flows: PathBuf,

    /// Fichier de correspondances objets externes → préfixes (même format
    /// que `calque import --resolve`), appliqué DES DEUX CÔTÉS (modèle
    /// courant et candidate) pour une comparaison cohérente. Sans lui, les
    /// objets fqdn/geography non résolus du projet importé sont réutilisés
    /// tels quels.
    #[arg(long, value_name = "FICHIER")]
    pub resolve: Option<PathBuf>,
}

#[derive(Debug, clap::Args)]
#[command(after_help = "\
Le MÊME anonymiseur traite tous les fichiers d'un appel : une adresse ou un \
nom présent dans plusieurs fichiers reçoit partout le même remplacement — \
c'est cette cohérence inter-fichiers qui garde le comportement du modèle \
testable. Les secrets (mots de passe, clés, communautés SNMP) sont \
supprimés et ne figurent jamais dans la table de correspondance.

Sortie : sur la sortie standard pour un fichier unique \
(`calque scrub fw-01.conf > fw-01-anon.conf`) ; pour plusieurs fichiers ou \
avec --out-dir, écrit <nom>.anon.<ext> (ou le même nom dans le répertoire \
--out-dir) et affiche un récapitulatif. Un fichier existant n'est jamais \
écrasé sans --force. Cette commande ne touche pas au projet .calque/.

Rappel (§11.4) : relisez le résultat avant toute diffusion ; \
l'anonymisation est structurelle, pas un chiffrement.")]
pub struct ScrubArgs {
    /// Fichier(s) de configuration à anonymiser, avec le même anonymiseur
    #[arg(value_name = "FICHIER", required = true, num_args = 1..)]
    pub files: Vec<PathBuf>,

    /// Écrire les fichiers anonymisés dans ce répertoire (mêmes noms),
    /// créé au besoin
    #[arg(long, value_name = "RÉPERTOIRE")]
    pub out_dir: Option<PathBuf>,

    /// Écrire la table de correspondance original → remplacement dans ce
    /// fichier — à conserver en lieu sûr, ne jamais publier. Sans --map,
    /// la table n'est écrite nulle part
    #[arg(long, value_name = "FICHIER")]
    pub map: Option<PathBuf>,

    /// Écraser les fichiers de sortie qui existent déjà
    #[arg(long)]
    pub force: bool,
}

/// Destination d'un `calque path` : une adresse et un port/protocole.
///
/// Analyse « 10.0.20.10:445/tcp ». Le port est obligatoire pour un chemin
/// concret (le mode symbolique, qui acceptera `any`, arrive plus tard).
pub fn parse_dst_spec(s: &str) -> Result<(IpAddr, u16, calque_policy::Proto), String> {
    let Some((addr_part, port_part)) = s.rsplit_once(':') else {
        return Err(format!(
            "destination invalide : « {s} » (attendu IP:PORT/PROTO, par exemple 10.0.20.10:445/tcp)"
        ));
    };
    let addr: IpAddr = addr_part.trim().parse().map_err(|_| {
        format!(
            "adresse de destination invalide : « {} » (les adresses IPv6 ne sont pas encore gérées ici)",
            addr_part.trim()
        )
    })?;
    match port_part.parse::<calque_policy::PortSpec>() {
        Ok(calque_policy::PortSpec::One { port, proto }) => Ok((addr, port, proto)),
        Ok(calque_policy::PortSpec::Any) => Err(
            "précisez un port et un protocole pour un chemin concret (par exemple 445/tcp) ; \
             « any » sera géré par le mode symbolique (`calque reach`)"
                .to_owned(),
        ),
        Err(e) => Err(e.to_string()),
    }
}

// ---------------------------------------------------------------------------
// Spec de cible/source du mode symbolique (`calque reach`)
// ---------------------------------------------------------------------------

/// Une cible (ou source) de `calque reach`, telle qu'écrite : une adresse
/// ou un préfixe, éventuellement contraints à un port de destination — ou
/// un nom de zone à résoudre contre le modèle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReachSpec {
    /// `10.0.20.5`, `10.0.20.0/24`, `10.0.20.5:445/tcp`,
    /// `10.0.20.0/24:445/tcp`. Une IP nue devient son préfixe hôte.
    Addr {
        net: IpNet,
        port: Option<(u16, calque_policy::Proto)>,
    },
    /// `vlan-supervision`, `z-dmz:445/tcp` — résolu contre les zones du
    /// modèle (sous-réseaux des interfaces membres), comme dans
    /// `calque test`.
    Zone {
        name: String,
        port: Option<(u16, calque_policy::Proto)>,
    },
}

/// Analyse l'adresse seule : IP (→ préfixe hôte) ou préfixe CIDR.
fn parse_addr_part(s: &str) -> Option<IpNet> {
    if let Ok(ip) = s.parse::<IpAddr>() {
        return Some(IpNet::from(ip));
    }
    s.parse::<IpNet>().ok()
}

/// Analyse une CIBLE/SOURCE de `calque reach` : IP, CIDR, IP:PORT/PROTO,
/// CIDR:PORT/PROTO, ou nom de zone (éventuellement `zone:PORT/PROTO`).
///
/// `…:any` est accepté et équivaut à l'absence de contrainte de port.
/// Jamais de supposition : une partie port malformée derrière une adresse
/// valide est une erreur claire, pas un nom de zone.
pub fn parse_reach_spec(s: &str) -> Result<ReachSpec, String> {
    let t = s.trim();
    if t.is_empty() {
        return Err(
            "cible vide (attendu une IP, un CIDR, IP:PORT/PROTO, ou un nom de zone)".to_owned(),
        );
    }
    // La forme sans port d'abord (couvre aussi les adresses IPv6 nues,
    // dont les deux-points ne sont pas un séparateur de port).
    if let Some(net) = parse_addr_part(t) {
        return Ok(ReachSpec::Addr { net, port: None });
    }
    if let Some((addr_part, port_part)) = t.rsplit_once(':') {
        let addr_part = addr_part.trim();
        let port = match port_part.trim().parse::<calque_policy::PortSpec>() {
            Ok(calque_policy::PortSpec::One { port, proto }) => Some((port, proto)),
            Ok(calque_policy::PortSpec::Any) => None,
            Err(e) => {
                // Une adresse valide suivie d'un port malformé est une
                // erreur (ne jamais deviner) ; sinon, le tout est un nom
                // de zone (qui peut contenir des deux-points).
                if parse_addr_part(addr_part).is_some() {
                    return Err(format!("port invalide dans « {t} » : {e}"));
                }
                return Ok(ReachSpec::Zone {
                    name: t.to_owned(),
                    port: None,
                });
            }
        };
        if addr_part.is_empty() {
            return Err(format!(
                "cible invalide : « {t} » (adresse ou zone manquante avant le port)"
            ));
        }
        if let Some(net) = parse_addr_part(addr_part) {
            return Ok(ReachSpec::Addr { net, port });
        }
        return Ok(ReachSpec::Zone {
            name: addr_part.to_owned(),
            port,
        });
    }
    Ok(ReachSpec::Zone {
        name: t.to_owned(),
        port: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_dst_spec_ok() {
        let (addr, port, proto) = parse_dst_spec("10.0.20.10:445/tcp").unwrap();
        assert_eq!(addr, "10.0.20.10".parse::<IpAddr>().unwrap());
        assert_eq!(port, 445);
        assert_eq!(proto, calque_policy::Proto::Tcp);
    }

    #[test]
    fn parse_dst_spec_erreurs() {
        assert!(parse_dst_spec("10.0.20.10").is_err());
        assert!(parse_dst_spec("10.0.20.10:445/xyz").is_err());
        assert!(parse_dst_spec("10.0.20.10:any").is_err());
    }

    // -- parse_reach_spec ------------------------------------------------

    fn tcp(port: u16) -> Option<(u16, calque_policy::Proto)> {
        Some((port, calque_policy::Proto::Tcp))
    }

    #[test]
    fn parse_reach_spec_adresses() {
        // IP nue → préfixe hôte /32.
        assert_eq!(
            parse_reach_spec("10.0.20.5"),
            Ok(ReachSpec::Addr {
                net: "10.0.20.5/32".parse().unwrap(),
                port: None
            })
        );
        // CIDR.
        assert_eq!(
            parse_reach_spec("10.0.20.0/24"),
            Ok(ReachSpec::Addr {
                net: "10.0.20.0/24".parse().unwrap(),
                port: None
            })
        );
        // IP:PORT/PROTO.
        assert_eq!(
            parse_reach_spec("10.0.20.5:445/tcp"),
            Ok(ReachSpec::Addr {
                net: "10.0.20.5/32".parse().unwrap(),
                port: tcp(445)
            })
        );
        // CIDR:PORT/PROTO (udp).
        assert_eq!(
            parse_reach_spec("10.0.20.0/24:53/udp"),
            Ok(ReachSpec::Addr {
                net: "10.0.20.0/24".parse().unwrap(),
                port: Some((53, calque_policy::Proto::Udp))
            })
        );
        // `:any` équivaut à l'absence de contrainte.
        assert_eq!(
            parse_reach_spec("10.0.20.5:any"),
            Ok(ReachSpec::Addr {
                net: "10.0.20.5/32".parse().unwrap(),
                port: None
            })
        );
        // Une IPv6 nue est acceptée (les deux-points ne sont pas un port).
        assert_eq!(
            parse_reach_spec("2001:db8::1"),
            Ok(ReachSpec::Addr {
                net: "2001:db8::1/128".parse().unwrap(),
                port: None
            })
        );
    }

    #[test]
    fn parse_reach_spec_zones() {
        assert_eq!(
            parse_reach_spec("vlan-supervision"),
            Ok(ReachSpec::Zone {
                name: "vlan-supervision".into(),
                port: None
            })
        );
        // Zone avec port.
        assert_eq!(
            parse_reach_spec("z-dmz:8443/tcp"),
            Ok(ReachSpec::Zone {
                name: "z-dmz".into(),
                port: tcp(8443)
            })
        );
        // Un nom contenant des deux-points sans port valide reste un nom
        // de zone entier.
        assert_eq!(
            parse_reach_spec("groupe:commutateurs"),
            Ok(ReachSpec::Zone {
                name: "groupe:commutateurs".into(),
                port: None
            })
        );
    }

    #[test]
    fn parse_reach_spec_erreurs() {
        // Vide.
        assert!(parse_reach_spec("  ").is_err());
        // Adresse valide + port malformé : erreur claire, pas une zone.
        let err = parse_reach_spec("10.0.20.5:445/xyz").unwrap_err();
        assert!(err.contains("protocole inconnu"), "message : {err}");
        let err = parse_reach_spec("10.0.20.0/24:99999/tcp").unwrap_err();
        assert!(err.contains("port"), "message : {err}");
        // Port sans adresse ni zone.
        assert!(parse_reach_spec(":445/tcp").is_err());
    }

    #[test]
    fn reach_exige_to_ou_from_exclusifs() {
        assert!(Cli::try_parse_from(["calque", "reach"]).is_err());
        assert!(Cli::try_parse_from(["calque", "reach", "--to", "a", "--from", "b"]).is_err());
        let cli = Cli::try_parse_from(["calque", "reach", "--to", "10.0.20.5:445/tcp"]).unwrap();
        match cli.command {
            Command::Reach(args) => {
                assert_eq!(args.to.as_deref(), Some("10.0.20.5:445/tcp"));
                assert!(args.from.is_none());
                assert_eq!(args.format, DataFormat::Text);
            }
            other => panic!("commande inattendue : {other:?}"),
        }
        let cli = Cli::try_parse_from([
            "calque",
            "reach",
            "--from",
            "vlan-invite",
            "--format",
            "json",
        ])
        .unwrap();
        match cli.command {
            Command::Reach(args) => {
                assert_eq!(args.from.as_deref(), Some("vlan-invite"));
                assert_eq!(args.format, DataFormat::Json);
            }
            other => panic!("commande inattendue : {other:?}"),
        }
    }

    #[test]
    fn model_dead_rules_parse() {
        let cli = Cli::try_parse_from(["calque", "model", "dead-rules"]).unwrap();
        assert!(matches!(
            cli.command,
            Command::Model {
                command: ModelCommand::DeadRules {
                    format: DataFormat::Text
                }
            }
        ));
        let cli =
            Cli::try_parse_from(["calque", "model", "dead-rules", "--format", "json"]).unwrap();
        assert!(matches!(
            cli.command,
            Command::Model {
                command: ModelCommand::DeadRules {
                    format: DataFormat::Json
                }
            }
        ));
    }
}
