//! La structure de la ligne de commande (§10 de CALQUE-ARCHITECTURE.md).

use std::net::IpAddr;
use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};

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
}

#[derive(Debug, Subcommand)]
pub enum ModelCommand {
    /// Afficher la fidélité du modèle : complet, ou liste des directives non
    /// comprises. Code de sortie non nul si le modèle est partiel avec des
    /// diagnostics d'erreur.
    Check,
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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum OutputFormat {
    /// Texte lisible
    Text,
    /// JUnit XML, pour l'intégration continue
    Junit,
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
}
