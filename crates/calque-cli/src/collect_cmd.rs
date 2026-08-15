//! Les commandes de la feature `collect` : `calque collect` (S7) et
//! `calque verify --against-reality` (§11.2).
//!
//! ## Pourquoi il n'existe PAS d'option `--password`
//!
//! Un mot de passe passé en argument de ligne de commande est visible de
//! tous les processus de la machine (liste des processus), atterrit dans
//! l'historique du shell et dans les journaux d'audit. Le mot de passe
//! vient donc soit d'une variable d'environnement (`--password-env VAR`,
//! adaptée aux exécutions automatisées), soit d'une saisie SANS ÉCHO au
//! terminal (par défaut). Il n'apparaît jamais dans une erreur ni un log.

use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use calque_collect::reality::{cross, probe_tcp, CrossVerdict, ModelSays};
use calque_collect::ssh::{Auth, CollectedDevice, SshParams};
use calque_engine::Verdict;
use calque_model::Vendor;
use calque_policy::{PortSpec, Proto};
use clap::ValueEnum;
use miette::{miette, Context, IntoDiagnostic};

use crate::commands;
use crate::project;

// ---------------------------------------------------------------------------
// calque collect
// ---------------------------------------------------------------------------

/// Choix de constructeur sur la ligne de commande.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum VendorArg {
    /// Détection par sondes (`get system status`, `show version`)
    Auto,
    Fortigate,
    #[value(name = "cisco_ios")]
    CiscoIos,
}

#[derive(Debug, clap::Args)]
#[command(after_help = "\
LECTURE SEULE STRICTE (principe n° 1, §13) : la collecte n'envoie que les \
commandes de lecture de son profil (liste blanche testée : `show`, \
`get system status`, `show running-config`, `show lldp/cdp neighbors \
detail`, `diagnose lldprx neighbor summary all`, `terminal length/width`) — \
jamais une commande de configuration.

Mot de passe : PAS d'option --password (un argument est visible de tous \
les processus et des historiques de shell). Utilisez --password-env VAR, \
ou laissez la commande le demander sans écho. Sans --key ni \
--password-env, la saisie interactive est proposée.

Clé d'hôte : une clé JAMAIS VUE est refusée par défaut. --accept-new \
l'enregistre dans .calque/known_hosts — option RISQUÉE : une première \
connexion interceptée resterait indétectée ; vérifiez l'empreinte \
affichée. Une clé qui CHANGE est refusée dans tous les cas.

La configuration récupérée est importée comme un `calque import` normal \
(mêmes adaptateurs, même fidélité §6.3), puis les voisins LLDP/CDP sont \
fusionnés dans la topologie du projet (origine : LLDP).")]
pub struct CollectArgs {
    /// L'équipement : IP ou nom, avec port facultatif (10.0.0.1,
    /// 10.0.0.1:2222, [2001:db8::1]:22)
    #[arg(long, value_name = "IP[:PORT]")]
    pub host: String,

    /// L'utilisateur SSH
    #[arg(long, value_name = "UTILISATEUR")]
    pub user: String,

    /// Lire le mot de passe dans cette variable d'environnement
    #[arg(long = "password-env", value_name = "VAR", conflicts_with = "key")]
    pub password_env: Option<String>,

    /// S'authentifier avec cette clé privée (fichier OpenSSH/PEM)
    #[arg(long, value_name = "FICHIER")]
    pub key: Option<PathBuf>,

    /// Le constructeur, ou `auto` pour la détection par sondes
    #[arg(long, value_enum, default_value_t = VendorArg::Auto)]
    pub vendor: VendorArg,

    /// Écrire la configuration récupérée dans ce fichier (par défaut :
    /// .calque/collected/<hôte>.conf)
    #[arg(long = "save-config", value_name = "FICHIER")]
    pub save_config: Option<PathBuf>,

    /// Nom à donner à l'équipement dans le modèle (par défaut : son
    /// hostname, comme pour `calque import`)
    #[arg(long = "as", value_name = "NOM")]
    pub name: Option<String>,

    /// Accepter et enregistrer une clé d'hôte jamais vue — RISQUÉ,
    /// vérifiez l'empreinte affichée (voir l'aide plus bas)
    #[arg(long = "accept-new")]
    pub accept_new: bool,

    /// Délai (connexion et chaque commande), en millisecondes
    #[arg(long = "timeout-ms", value_name = "N", default_value_t = 15_000)]
    pub timeout_ms: u64,
}

/// Analyse `IP[:PORT]` (formes : `10.0.0.1`, `10.0.0.1:2222`, `hôte`,
/// `hôte:2222`, `[2001:db8::1]`, `[2001:db8::1]:22`, `2001:db8::1`).
pub fn parse_host_port(raw: &str) -> Result<(String, u16), String> {
    let t = raw.trim();
    if t.is_empty() {
        return Err("hôte vide".to_owned());
    }
    // IPv6 entre crochets, port facultatif.
    if let Some(rest) = t.strip_prefix('[') {
        let Some((host, after)) = rest.split_once(']') else {
            return Err(format!("« {t} » : crochet fermant manquant"));
        };
        let port = match after {
            "" => 22,
            p => p
                .strip_prefix(':')
                .and_then(|p| p.parse::<u16>().ok())
                .ok_or_else(|| format!("port invalide dans « {t} »"))?,
        };
        return Ok((host.to_owned(), port));
    }
    // Une IPv6 nue contient plusieurs « : » : pas de port.
    if t.matches(':').count() > 1 {
        return Ok((t.to_owned(), 22));
    }
    match t.split_once(':') {
        None => Ok((t.to_owned(), 22)),
        Some((host, port)) => {
            let port = port
                .parse::<u16>()
                .map_err(|_| format!("port invalide dans « {t} »"))?;
            if host.is_empty() {
                return Err(format!("hôte manquant dans « {t} »"));
            }
            Ok((host.to_owned(), port))
        }
    }
}

/// L'authentification choisie : clé, variable d'environnement, ou saisie
/// sans écho.
fn resolve_auth(args: &CollectArgs) -> miette::Result<Auth> {
    if let Some(key) = &args.key {
        if !key.exists() {
            return Err(miette!("clé privée introuvable : {}", key.display()));
        }
        return Ok(Auth::KeyFile {
            path: key.clone(),
            passphrase: None,
        });
    }
    if let Some(var) = &args.password_env {
        let password = std::env::var(var).map_err(|_| {
            miette!(
                help = "exportez la variable avant l'appel, ou omettez --password-env pour \
                        une saisie sans écho",
                "la variable d'environnement « {var} » est absente ou illisible"
            )
        })?;
        return Ok(Auth::Password(password));
    }
    // Saisie interactive sans écho — jamais d'argument en clair.
    let password = rpassword::prompt_password(format!(
        "Mot de passe SSH pour {}@{} : ",
        args.user, args.host
    ))
    .into_diagnostic()
    .wrap_err(
        "saisie du mot de passe impossible (terminal non interactif ? utilisez --password-env)",
    )?;
    Ok(Auth::Password(password))
}

/// Nom de fichier sûr pour la configuration collectée.
fn sanitize_for_filename(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '.' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// La clé privée était chiffrée ? On redemande la phrase de passe SANS
/// écho et on retente une fois.
fn retry_with_passphrase(
    args: &CollectArgs,
    params: &mut SshParams,
    err: calque_collect::CollectError,
) -> miette::Result<()> {
    let calque_collect::CollectError::KeyFile { .. } = &err else {
        return Err(into_miette(err));
    };
    let Some(key) = &args.key else {
        return Err(into_miette(err));
    };
    eprintln!("({err})");
    let passphrase = rpassword::prompt_password(format!(
        "Phrase de passe de {} (vide pour abandonner) : ",
        key.display()
    ))
    .into_diagnostic()
    .wrap_err("saisie de la phrase de passe impossible")?;
    if passphrase.is_empty() {
        return Err(into_miette(err));
    }
    params.auth = Auth::KeyFile {
        path: key.clone(),
        passphrase: Some(passphrase),
    };
    Ok(())
}

/// Convertit une erreur de collecte en diagnostic miette.
fn into_miette(e: calque_collect::CollectError) -> miette::Report {
    miette!("{e}")
}

pub fn collect(root: &Path, args: CollectArgs) -> miette::Result<ExitCode> {
    let (host, port) = parse_host_port(&args.host).map_err(|e| {
        miette!(
            help = "formes acceptées : 10.0.0.1, 10.0.0.1:2222, [2001:db8::1]:22",
            "{e}"
        )
    })?;
    let auth = resolve_auth(&args)?;
    let vendor_hint = match args.vendor {
        VendorArg::Auto => None,
        VendorArg::Fortigate => Some(Vendor::Fortigate),
        VendorArg::CiscoIos => Some(Vendor::CiscoIos),
    };

    let mut params = SshParams {
        host: host.clone(),
        port,
        user: args.user.clone(),
        auth,
        timeout: Duration::from_millis(args.timeout_ms.max(1)),
        accept_new: args.accept_new,
        known_hosts: root.join(project::PROJECT_DIR).join("known_hosts"),
    };

    println!("Connexion à {host}:{port} (lecture seule stricte, §13)…");
    let collected = match calque_collect::ssh::collect_device(&params, vendor_hint) {
        Ok(c) => c,
        Err(e) => {
            // Clé chiffrée : une relance avec phrase de passe saisie sans écho.
            retry_with_passphrase(&args, &mut params, e)?;
            calque_collect::ssh::collect_device(&params, vendor_hint).map_err(into_miette)?
        }
    };
    println!(
        "Équipement {} détecté{}.",
        collected.profile_label,
        collected
            .hostname
            .as_deref()
            .map(|h| format!(" (hostname : {h})"))
            .unwrap_or_default()
    );

    // 1. La configuration est écrite sur disque puis importée comme un
    // import normal : mêmes adaptateurs, même fidélité (§6.3), et le
    // fichier reste là pour `model check` (SourceSpan) et pour l'audit.
    let config_path = match &args.save_config {
        Some(p) => p.clone(),
        None => {
            let dir = root.join(project::PROJECT_DIR).join("collected");
            std::fs::create_dir_all(&dir)
                .into_diagnostic()
                .wrap_err_with(|| format!("création de {} impossible", dir.display()))?;
            dir.join(format!("{}.conf", sanitize_for_filename(&args.host)))
        }
    };
    std::fs::write(&config_path, &collected.config)
        .into_diagnostic()
        .wrap_err_with(|| format!("écriture de {} impossible", config_path.display()))?;
    println!("Configuration enregistrée dans {}.", config_path.display());

    let mut project = project::load_or_default(root)?;
    let device_id = commands::add_import(&mut project, &config_path, args.name.as_deref())?;

    // 2. Les voisins LLDP/CDP → liens de topologie (origine LLDP, la
    // source n° 1 du §7), fusionnés sans doublon.
    let (links, warnings) = neighbor_links(&device_id, &collected);
    for w in &warnings {
        println!("  avertissement : {w}");
    }
    let mut added = 0usize;
    for link in links {
        if !project
            .network
            .links
            .iter()
            .any(|e| commands::same_pair(e, &link))
        {
            println!(
                "  lien LLDP : {}/{} ↔ {}/{}",
                link.a.device, link.a.iface, link.b.device, link.b.iface
            );
            project.network.links.push(link);
            added += 1;
        }
    }
    println!("{added} lien(s) de voisinage ajouté(s) au modèle.");

    project::save(root, &project)?;
    println!(
        "Collecte terminée : {} équipement(s), {} lien(s) dans le modèle.",
        project.network.devices.len(),
        project.network.links.len()
    );
    if !project.fidelity.is_complete() {
        println!("Attention : le modèle est PARTIEL — lancez `calque model check` pour le détail.");
    }
    Ok(ExitCode::SUCCESS)
}

/// Interprète les sorties de voisinage avec les parseurs PURS de
/// calque-collect, selon le constructeur et la commande d'origine.
fn neighbor_links(
    device_id: &calque_model::DeviceId,
    collected: &CollectedDevice,
) -> (Vec<calque_model::Link>, Vec<String>) {
    let mut neighbors = Vec::new();
    let mut warnings = Vec::new();
    for (cmd, output) in &collected.neighbor_outputs {
        let parsed = match collected.vendor {
            Vendor::Fortigate => calque_collect::parse::fortigate::parse_lldprx_summary(output),
            Vendor::CiscoIos if cmd.contains("cdp") => {
                calque_collect::parse::cisco::parse_cdp_neighbors_detail(output)
            }
            Vendor::CiscoIos => calque_collect::parse::cisco::parse_lldp_neighbors_detail(output),
            _ => continue,
        };
        warnings.extend(parsed.warnings.iter().map(|w| format!("{cmd} : {w}")));
        neighbors.extend(parsed.neighbors);
    }
    (
        calque_collect::neighbors_to_links(device_id, &neighbors),
        warnings,
    )
}

// ---------------------------------------------------------------------------
// calque verify --against-reality (§11.2)
// ---------------------------------------------------------------------------

#[derive(Debug, clap::Args)]
#[command(after_help = "\
Pour chaque flux TCP de flows.yaml : le verdict du MODÈLE est calculé \
(comme `calque test`), puis une VRAIE connexion TCP est tentée depuis la \
machine courante vers destination:port, et les deux sont confrontés.

Honnêteté du rapport (§11.2) : la sonde ne part PAS de la source déclarée \
du flux mais de cette machine ; un refus (RST) peut venir du service \
éteint OU d'un pare-feu qui rejette ; un silence peut venir d'un filtrage \
OU d'un hôte éteint. Le rapport distingue « joignable », « refusé », \
« silence », « injoignable », et ne compte comme DIVERGENCE FERME qu'un \
seul cas indiscutable : le modèle refuse ET la poignée de main s'établit. \
Les flux udp/any sont signalés « non testables en TCP ».

Codes de sortie : 0 sans divergence ferme ; 1 si au moins une divergence \
ferme ; 2 erreur d'utilisation.")]
pub struct VerifyArgs {
    /// Confronter le modèle au réseau réel (obligatoire : c'est tout
    /// l'objet de la commande)
    #[arg(long = "against-reality")]
    pub against_reality: bool,

    /// Le fichier de flux à confronter
    #[arg(long, value_name = "FICHIER", default_value = "flows.yaml")]
    pub flows: PathBuf,

    /// Délai de chaque connexion TCP, en millisecondes
    #[arg(long = "timeout-ms", value_name = "N", default_value_t = 2_000)]
    pub timeout_ms: u64,
}

pub fn verify(root: &Path, args: VerifyArgs) -> miette::Result<ExitCode> {
    if !args.against_reality {
        return Err(miette!(
            help = "la confrontation au réel est l'objet de cette commande ; \
                    l'option est explicite pour qu'aucun script ne sonde un réseau par accident",
            "précisez --against-reality"
        ));
    }
    let project = project::load(root)?;
    let flows = commands::load_flows(&args.flows)?;
    let timeout = Duration::from_millis(args.timeout_ms.max(1));

    println!(
        "Confrontation au réel ({} flux, sonde TCP depuis CETTE machine — voir --help pour les nuances) :\n",
        flows.flows.len()
    );

    let mut firm = 0usize;
    let mut indeterminate = 0usize;
    let mut untestable = 0usize;

    for flow in &flows.flows {
        // Seul un flux TCP à port précis est testable par une connexion TCP.
        let (port, proto_tcp) = match flow.port {
            PortSpec::One { port, proto } => (port, proto == Proto::Tcp),
            PortSpec::Any => (0, false),
        };
        if !proto_tcp {
            untestable += 1;
            println!(
                "  NON TESTABLE  {} ({}) : port « {} » — une sonde TCP ne peut pas tester ce flux",
                flow.name,
                flow.flow_label(),
                flow.port
            );
            continue;
        }

        // Le verdict du MODÈLE, exactement comme `calque test`.
        let (packet, _) = match calque_policy::flow_packet(&project.network, flow) {
            Ok(x) => x,
            Err(reason) => {
                untestable += 1;
                println!(
                    "  NON TESTABLE  {} : extrémité non résolue — {reason}",
                    flow.name
                );
                continue;
            }
        };
        let trace = crate::backend::trace_concrete(&project.network, &packet);
        // C'est le moteur qui décide de la fermeté : un `Unknown` couvre
        // désormais les lacunes SUR le chemin (règle sur-approximée, objet
        // externe non résolu…). Une lacune HORS du chemin ne rend plus le
        // verdict non ferme.
        let model = match trace.verdict {
            Verdict::Allowed => ModelSays::Allow,
            Verdict::Denied | Verdict::NoRoute | Verdict::Loop => ModelSays::Deny,
            Verdict::Unknown => ModelSays::NotFirm,
        };

        // La sonde RÉELLE.
        let dst: IpAddr = packet.dst;
        let real = probe_tcp(SocketAddr::new(dst, port), timeout);

        let verdict = cross(model, real);
        let model_label = match model {
            ModelSays::Allow => "allow",
            ModelSays::Deny => "deny",
            ModelSays::NotFirm => "non ferme",
        };
        match verdict {
            CrossVerdict::Concordant => {
                println!(
                    "  CONCORDANT    {} : modèle={model_label}, réel={}",
                    flow.name,
                    real.label()
                );
            }
            CrossVerdict::ConcordantServiceDown => {
                println!(
                    "  CONCORDANT*   {} : modèle=allow, réel={} — le chemin réseau répond, \
                     le service semble éteint : le filtrage n'est pas mis en cause",
                    flow.name,
                    real.label()
                );
            }
            CrossVerdict::FirmDivergence => {
                firm += 1;
                println!(
                    "  DIVERGENCE    {} : le modèle dit deny, mais {}:{port} accepte une \
                     connexion depuis cette machine ({} → {}). Cas de test tout prêt : \
                     `calque path {} '->' {}:{port}/tcp --explain`",
                    flow.name, dst, packet.src, dst, packet.src, dst
                );
            }
            CrossVerdict::Indeterminate => {
                indeterminate += 1;
                println!(
                    "  INDÉTERMINÉ   {} : modèle={model_label}, réel={} — l'observation ne \
                     permet pas de trancher, le modèle n'est pas accusé",
                    flow.name,
                    real.label()
                );
            }
        }
    }

    println!(
        "\n{firm} divergence(s) ferme(s), {indeterminate} indéterminé(s), {untestable} non testable(s) \
         sur {} flux.",
        flows.flows.len()
    );
    Ok(if firm > 0 {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_host_port_formes() {
        assert_eq!(parse_host_port("10.0.0.1"), Ok(("10.0.0.1".to_owned(), 22)));
        assert_eq!(
            parse_host_port("10.0.0.1:2222"),
            Ok(("10.0.0.1".to_owned(), 2222))
        );
        assert_eq!(parse_host_port("fw-01"), Ok(("fw-01".to_owned(), 22)));
        assert_eq!(
            parse_host_port("[2001:db8::1]"),
            Ok(("2001:db8::1".to_owned(), 22))
        );
        assert_eq!(
            parse_host_port("[2001:db8::1]:2022"),
            Ok(("2001:db8::1".to_owned(), 2022))
        );
        // IPv6 nue : les deux-points ne sont pas un port.
        assert_eq!(
            parse_host_port("2001:db8::1"),
            Ok(("2001:db8::1".to_owned(), 22))
        );
        assert!(parse_host_port("10.0.0.1:abc").is_err());
        assert!(parse_host_port(":22").is_err());
        assert!(parse_host_port("").is_err());
        assert!(parse_host_port("[2001:db8::1").is_err());
    }

    #[test]
    fn les_commandes_collect_se_parsent() {
        use clap::Parser;
        let cli = crate::cli::Cli::try_parse_from([
            "calque",
            "collect",
            "--host",
            "10.0.0.1:2222",
            "--user",
            "audit",
            "--password-env",
            "CALQUE_SSH_PASS",
            "--vendor",
            "cisco_ios",
            "--save-config",
            "sw.conf",
            "--accept-new",
        ])
        .unwrap();
        match cli.command {
            crate::cli::Command::Collect(a) => {
                assert_eq!(a.host, "10.0.0.1:2222");
                assert_eq!(a.vendor, VendorArg::CiscoIos);
                assert!(a.accept_new);
                assert_eq!(a.password_env.as_deref(), Some("CALQUE_SSH_PASS"));
            }
            other => panic!("commande inattendue : {other:?}"),
        }
        // --password n'existe PAS (documenté) ; --key et --password-env
        // sont exclusifs.
        assert!(crate::cli::Cli::try_parse_from([
            "calque",
            "collect",
            "--host",
            "h",
            "--user",
            "u",
            "--password",
            "clair"
        ])
        .is_err());
        assert!(crate::cli::Cli::try_parse_from([
            "calque",
            "collect",
            "--host",
            "h",
            "--user",
            "u",
            "--key",
            "k",
            "--password-env",
            "V"
        ])
        .is_err());
    }

    #[test]
    fn la_commande_verify_se_parse() {
        use clap::Parser;
        let cli = crate::cli::Cli::try_parse_from([
            "calque",
            "verify",
            "--against-reality",
            "--flows",
            "flux.yaml",
            "--timeout-ms",
            "500",
        ])
        .unwrap();
        match cli.command {
            crate::cli::Command::Verify(a) => {
                assert!(a.against_reality);
                assert_eq!(a.flows, PathBuf::from("flux.yaml"));
                assert_eq!(a.timeout_ms, 500);
            }
            other => panic!("commande inattendue : {other:?}"),
        }
    }
}
