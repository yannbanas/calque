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
    /// Prévisualiser l'effet d'une configuration candidate (arrive en S4)
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
    /// Afficher la fidélité du modèle : complet, ou liste des directives non comprises
    Check,
}

#[derive(Debug, Subcommand)]
pub enum TopologyCommand {
    /// Signaler les liens ambigus ou manquants
    Check,
}

#[derive(Debug, clap::Args)]
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
pub struct PlanArgs {
    /// La configuration candidate à comparer au modèle courant
    #[arg(long, value_name = "FICHIER")]
    pub candidate: PathBuf,
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
