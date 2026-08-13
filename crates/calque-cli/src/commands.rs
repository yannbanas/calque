//! L'exécution des commandes.
//!
//! Toutes les erreurs passent par `miette` : jamais de panique sur une
//! entrée externe. Les textes sont en français.
//!
//! Codes de sortie : `run` rend un `ExitCode` pour distinguer un verdict
//! (refusé, non ferme, flux en échec…) d'une erreur d'exécution. Le détail
//! par commande est documenté dans l'aide (`cli.rs`).

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use calque_engine::{ReachReport, Trace};
use calque_model::{
    ConcretePacket, DeviceId, Endpoint, Fidelity, IfaceId, Link, LinkOrigin, Network, Severity,
    ZoneId,
};
use calque_policy::{flow_packet, Expectation, FlowsFile, Proto};
use calque_report::VerdictView;
use calque_space::{Cube, HeaderSet, PortRanges, PrefixSet, ProtoSet};
use miette::{miette, Context, IntoDiagnostic};

use crate::backend;
use crate::cli::{
    Cli, Command, DataFormat, ImportArgs, ModelCommand, OutputFormat, PathArgs, PlanArgs,
    ReachArgs, ReachSpec, ScrubArgs, TestArgs, TopologyCommand,
};
use crate::project::{self, Project};

/// Code de sortie « verdict non ferme » (§6.3), documenté dans l'aide.
const EXIT_NON_FIRM: u8 = 3;

pub fn run(cli: Cli) -> miette::Result<ExitCode> {
    let root = std::env::current_dir()
        .into_diagnostic()
        .wrap_err("répertoire courant illisible")?;
    match cli.command {
        Command::Import(args) => import(&root, args).map(|()| ExitCode::SUCCESS),
        Command::Model {
            command: ModelCommand::Check,
        } => model_check(&root),
        Command::Model {
            command: ModelCommand::DeadRules { format },
        } => model_dead_rules(&root, format),
        Command::Path(args) => path(&root, args),
        Command::Reach(args) => reach(&root, args),
        Command::Test(args) => test(&root, args),
        Command::Plan(args) => plan(&root, args),
        Command::Topology {
            command: TopologyCommand::Check { topology },
        } => topology_check(&root, &topology),
        // `scrub` est indépendant du projet `.calque/` : il ne lit et
        // n'écrit que les fichiers désignés par l'utilisateur.
        Command::Scrub(args) => scrub(args).map(|()| ExitCode::SUCCESS),
        #[cfg(feature = "collect")]
        Command::Collect(args) => crate::collect_cmd::collect(&root, args),
        #[cfg(feature = "collect")]
        Command::Verify(args) => crate::collect_cmd::verify(&root, args),
    }
}

// ---------------------------------------------------------------------------
// calque import
// ---------------------------------------------------------------------------

fn import(root: &Path, args: ImportArgs) -> miette::Result<()> {
    let mut project = project::load_or_default(root)?;
    let mut imported = 0usize;

    if let Some(dir) = &args.dir {
        let entries = std::fs::read_dir(dir)
            .into_diagnostic()
            .wrap_err_with(|| format!("lecture du répertoire {} impossible", dir.display()))?;
        let mut files: Vec<PathBuf> = entries
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| p.is_file())
            .collect();
        files.sort();
        if files.is_empty() {
            return Err(miette!("aucun fichier à importer dans {}", dir.display()));
        }
        for file in files {
            add_import(&mut project, &file, None)?;
            imported += 1;
        }
    } else if let Some(file) = &args.file {
        add_import(&mut project, file, args.name.as_deref())?;
        imported = 1;
    }

    project::save(root, &project)?;
    println!(
        "{imported} configuration(s) importée(s). Modèle : {} équipement(s).",
        project.network.devices.len()
    );
    if !project.fidelity.is_complete() {
        println!("Attention : le modèle est PARTIEL — lancez `calque model check` pour le détail.");
    }
    Ok(())
}

/// Importe un fichier dans le projet et rend l'identifiant de
/// l'équipement créé ou remplacé. `pub(crate)` : la collecte en ligne
/// (`collect_cmd`, feature `collect`) importe la configuration récupérée
/// par SSH EXACTEMENT comme un import de fichier.
pub(crate) fn add_import(
    project: &mut Project,
    file: &Path,
    name: Option<&str>,
) -> miette::Result<DeviceId> {
    let outcome = backend::import_config(file, name)?;
    println!(
        "{} : {} → équipement « {} » ({} interface(s), {} politique(s))",
        file.display(),
        backend::vendor_label(outcome.vendor),
        outcome.device.id,
        outcome.device.interfaces.len(),
        outcome.device.policies.len(),
    );
    for note in &outcome.notes {
        match &note.span {
            Some(span) => println!("  note : {} ({span})", note.message),
            None => println!("  note : {}", note.message),
        }
    }

    let id = outcome.device.id.clone();
    project.network.devices.insert(id.clone(), outcome.device);
    project
        .device_files
        .insert(id.clone(), file.display().to_string());
    project.device_fidelity.insert(id.clone(), outcome.fidelity);
    project.recompute_fidelity();
    let label = file.display().to_string();
    if !project.imported_files.contains(&label) {
        project.imported_files.push(label);
    }
    Ok(id)
}

// ---------------------------------------------------------------------------
// calque model check
// ---------------------------------------------------------------------------

fn model_check(root: &Path) -> miette::Result<ExitCode> {
    let project = project::load(root)?;
    let n_devices = project.network.devices.len();
    let n_ifaces: usize = project
        .network
        .devices
        .values()
        .map(|d| d.interfaces.len())
        .sum();
    println!(
        "Modèle : {n_devices} équipement(s), {n_ifaces} interface(s), {} lien(s).",
        project.network.links.len()
    );

    match &project.fidelity {
        Fidelity::Complete => {
            println!("Fidélité : COMPLÈTE — toutes les directives ont été comprises.");
            Ok(ExitCode::SUCCESS)
        }
        Fidelity::Partial { unsupported } => {
            println!(
                "Fidélité : PARTIELLE — {} directive(s) non comprise(s) (jamais devinées, §6.3) :\n",
                unsupported.len()
            );
            for d in unsupported {
                print_diagnostic(d);
            }
            println!(
                "\nL'outil refusera un verdict ferme sur tout chemin touché par ces directives."
            );
            let has_errors = unsupported.iter().any(|d| d.severity == Severity::Error);
            Ok(if has_errors {
                ExitCode::from(1)
            } else {
                ExitCode::SUCCESS
            })
        }
    }
}

/// Affiche un diagnostic joliment via miette : si le fichier d'origine est
/// lisible, l'extrait fautif est montré avec un curseur ; sinon, repli en
/// texte simple « fichier ligne N : message ».
fn print_diagnostic(d: &calque_model::Diagnostic) {
    use miette::{LabeledSpan, MietteDiagnostic, NamedSource, Report};

    let severity = match d.severity {
        Severity::Info => miette::Severity::Advice,
        Severity::Warning => miette::Severity::Warning,
        Severity::Error => miette::Severity::Error,
    };
    let label = match d.severity {
        Severity::Info => "info",
        Severity::Warning => "avertissement",
        Severity::Error => "erreur",
    };

    if let Some(span) = &d.span {
        if let Ok(src) = std::fs::read_to_string(&span.file) {
            if let Some(range) = line_byte_range(&src, span.line) {
                let diag = MietteDiagnostic::new(d.message.clone())
                    .with_severity(severity)
                    .with_label(LabeledSpan::at(range, "directive non comprise"));
                let report = Report::new(diag).with_source_code(NamedSource::new(&span.file, src));
                eprintln!("{report:?}");
                return;
            }
        }
        println!("  [{label}] {} : {}", span, d.message);
    } else {
        println!("  [{label}] {}", d.message);
    }
}

/// L'intervalle d'octets couvrant la ligne `line` (1-indexée) de `src`,
/// sans le saut de ligne final.
fn line_byte_range(src: &str, line: u32) -> Option<std::ops::Range<usize>> {
    let mut offset = 0usize;
    for (i, l) in src.split_inclusive('\n').enumerate() {
        let content = l.trim_end_matches(['\n', '\r']);
        if i as u32 + 1 == line {
            return Some(offset..offset + content.len().max(1));
        }
        offset += l.len();
    }
    None
}

// ---------------------------------------------------------------------------
// §6.3 — fidélité partielle sur le chemin
// ---------------------------------------------------------------------------

/// Les équipements traversés par la trace dont l'import est partiel :
/// un verdict qui les traverse n'est pas ferme (§6.3). Délègue à
/// `calque_policy::partial_devices_on_path`, sur la table de fidélité par
/// équipement du projet.
pub(crate) fn partial_devices_on_path(project: &Project, trace: &Trace) -> Vec<(DeviceId, usize)> {
    calque_policy::partial_devices_on_path(trace, &project.device_fidelity)
}

/// Affiche les diagnostics accumulés par le moteur pendant la trace.
fn print_trace_diagnostics(trace: &Trace) {
    for d in &trace.diagnostics {
        let label = match d.severity {
            Severity::Info => "info",
            Severity::Warning => "avertissement",
            Severity::Error => "erreur",
        };
        match &d.span {
            Some(span) => println!("  [{label}] {} : {}", span, d.message),
            None => println!("  [{label}] {}", d.message),
        }
    }
}

// ---------------------------------------------------------------------------
// calque path
// ---------------------------------------------------------------------------

fn path(root: &Path, args: PathArgs) -> miette::Result<ExitCode> {
    if args.arrow != "->" {
        return Err(miette!(
            help = "exemple : calque path 10.0.10.5 '->' 10.0.20.10:445/tcp",
            "syntaxe : calque path SOURCE '->' DESTINATION (reçu « {} » à la place de « -> »)",
            args.arrow
        ));
    }
    let (dst, dport, proto) = crate::cli::parse_dst_spec(&args.dst).map_err(|e| miette!("{e}"))?;
    let project = project::load(root)?;

    let packet = ConcretePacket {
        src: args.src,
        dst,
        proto: proto.number(),
        // Port source éphémère représentatif, documenté dans l'aide.
        sport: backend::EPHEMERAL_SPORT,
        dport,
    };
    let trace = backend::trace_concrete(&project.network, &packet);
    let view = backend::trace_to_view(&trace);

    match args.format {
        // JSON : la trace complète, structurée — rien d'autre sur stdout
        // (les avertissements texte ci-dessous ne concernent que le mode
        // texte, les codes de sortie restent identiques, comme `reach`).
        DataFormat::Json => println!("{}", calque_report::render_trace_json(&view)),
        DataFormat::Text if args.explain => {
            print!("{}", calque_report::render_trace_text(&view));
            if !trace.diagnostics.is_empty() {
                println!();
                print_trace_diagnostics(&trace);
            }
        }
        DataFormat::Text => {
            // La ligne de verdict porte la note de sortie de périmètre le
            // cas échéant : « autorisé (sort du périmètre modélisé via
            // wan1, passerelle …) » — jamais un « autorisé » trompeur.
            println!(
                "{} → {}:{}/{} : {}",
                packet.src,
                packet.dst,
                packet.dport,
                proto,
                view.verdict_line()
            );
            let devices: Vec<&str> = view.hops.iter().map(|h| h.device.as_str()).collect();
            if !devices.is_empty() {
                println!("chemin : {}", devices.join(" → "));
            }
            if let Some(rule) = deciding_rule(&view) {
                println!("décidé par : {rule}");
            }
            println!("(--explain pour la trace complète, règle par règle)");
        }
    }

    // Verdict indéterminé : le moteur n'a pas pu conclure sans deviner.
    if matches!(view.verdict, VerdictView::Unknown) {
        if args.format == DataFormat::Text {
            if !args.explain {
                print_trace_diagnostics(&trace);
            }
            println!("\nVerdict NON FERME (code de sortie {EXIT_NON_FIRM}).");
        }
        return Ok(ExitCode::from(EXIT_NON_FIRM));
    }

    // §6.3 : un équipement traversé a un import partiel → pas de verdict
    // ferme, même si le moteur a conclu sur ce que le modèle contient.
    let partial = partial_devices_on_path(&project, &trace);
    if !partial.is_empty() {
        if args.format == DataFormat::Text {
            let list = partial
                .iter()
                .map(|(d, n)| format!("« {d} » ({n} directive(s) non comprise(s))"))
                .collect::<Vec<_>>()
                .join(", ");
            println!(
                "\nAttention : verdict NON FERME — le chemin traverse un modèle partiel : {list}.\n\
                 Lancez `calque model check` pour le détail (code de sortie {EXIT_NON_FIRM})."
            );
        }
        return Ok(ExitCode::from(EXIT_NON_FIRM));
    }

    Ok(match view.verdict {
        VerdictView::Allowed => ExitCode::SUCCESS,
        // Refusé / pas de route / boucle : documenté dans l'aide.
        _ => ExitCode::from(1),
    })
}

// ---------------------------------------------------------------------------
// calque reach (mode symbolique, §5.3)
// ---------------------------------------------------------------------------

/// Résout la partie adresse d'une spec de `reach` en préfixes concrets,
/// avec un libellé humain. Une zone est résolue comme dans `calque test` :
/// les sous-réseaux des interfaces membres (ici en entier — le mode
/// symbolique couvre tout le sous-réseau, pas un hôte représentatif).
fn resolve_reach_prefixes(
    network: &Network,
    spec: &ReachSpec,
) -> miette::Result<(PrefixSet, String)> {
    match spec {
        ReachSpec::Addr { net, .. } => {
            let label = if net.prefix_len() == net.max_prefix_len() {
                net.addr().to_string()
            } else {
                net.to_string()
            };
            Ok((PrefixSet::from_net(*net), label))
        }
        ReachSpec::Zone { name, .. } => {
            let zone = ZoneId::new(name.as_str());
            let mut hits: Vec<&calque_model::Device> = network
                .devices
                .values()
                .filter(|d| d.zones.contains_key(&zone))
                .collect();
            let device = match hits.len() {
                0 => {
                    return Err(miette!(
                        help = "cibles acceptées : une adresse IP, un préfixe CIDR, \
                                IP:PORT/PROTO, CIDR:PORT/PROTO, ou un nom de zone du modèle",
                        "« {name} » ne correspond ni à une adresse, ni à un préfixe, \
                         ni à une zone du modèle"
                    ))
                }
                1 => hits.pop().expect("hits.len() == 1"),
                _ => {
                    let list = hits
                        .iter()
                        .map(|d| format!("« {} »", d.id))
                        .collect::<Vec<_>>()
                        .join(", ");
                    return Err(miette!(
                        "la zone « {name} » existe sur plusieurs équipements ({list}) : ambigu"
                    ));
                }
            };
            let members = device.zones.get(&zone).expect("zone présente");
            let nets: Vec<ipnet::IpNet> = members
                .iter()
                .filter_map(|m| device.interfaces.get(m))
                .flat_map(|i| i.addrs.iter().map(|a| a.trunc()))
                .collect();
            if nets.is_empty() {
                return Err(miette!(
                    "la zone « {name} » (équipement « {} ») n'a aucun sous-réseau exploitable",
                    device.id
                ));
            }
            let prefixes = PrefixSet::from_net(nets[0]);
            let prefixes = nets[1..]
                .iter()
                .fold(prefixes, |acc, n| acc.union(&PrefixSet::from_net(*n)));
            let subnets = prefixes
                .prefixes()
                .iter()
                .map(|p| p.to_string())
                .collect::<Vec<_>>()
                .join(", ");
            Ok((prefixes, format!("la zone « {name} » ({subnets})")))
        }
    }
}

/// Construit le `HeaderSet` de la question : les préfixes sur la dimension
/// destination (`--to`) ou source (`--from`) ; le port, s'il est donné,
/// contraint toujours le port de destination et son protocole.
fn reach_headerset(
    prefixes: &PrefixSet,
    port: Option<(u16, Proto)>,
    constrain_dst: bool,
) -> HeaderSet {
    let mut cube = Cube::full();
    if constrain_dst {
        cube.dst = prefixes.clone();
    } else {
        cube.src = prefixes.clone();
    }
    if let Some((port, proto)) = port {
        cube.proto = ProtoSet::single(proto.number());
        cube.dport = PortRanges::single(port);
    }
    HeaderSet::from_cube(cube)
}

/// Les équipements touchés par le rapport (points d'entrée et décisions)
/// dont l'import est partiel : le rapport n'est pas ferme (§6.3).
fn partial_devices_in_reach(project: &Project, report: &ReachReport) -> Vec<(DeviceId, usize)> {
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    let devices = report.flows.iter().flat_map(|f| {
        std::iter::once(&f.entry.device).chain(f.decisions.iter().map(|d| &d.device))
    });
    for device in devices {
        if !seen.insert(device.clone()) {
            continue;
        }
        if let Fidelity::Partial { unsupported } = project.fidelity_of(device) {
            out.push((device.clone(), unsupported.len()));
        }
    }
    out
}

fn reach(root: &Path, args: ReachArgs) -> miette::Result<ExitCode> {
    let (raw, is_to) = match (&args.to, &args.from) {
        (Some(t), None) => (t.as_str(), true),
        (None, Some(f)) => (f.as_str(), false),
        // clap garantit l'exclusivité et la présence de l'un des deux.
        _ => return Err(miette!("précisez soit --to CIBLE, soit --from SOURCE")),
    };
    let spec = parse_reach_spec_or_help(raw)?;
    let project = project::load(root)?;

    let (prefixes, mut label) = resolve_reach_prefixes(&project.network, &spec)?;
    let port = match &spec {
        ReachSpec::Addr { port, .. } | ReachSpec::Zone { port, .. } => *port,
    };
    if let Some((port, proto)) = port {
        label.push_str(&format!(":{port}/{proto}"));
    }
    let set = reach_headerset(&prefixes, port, is_to);

    // Même préparation du modèle que `path`, `test` et `plan`.
    let prepared = backend::prepare_for_engine(&project.network);
    let report = if is_to {
        calque_engine::reach_to(&prepared, &set)
    } else {
        calque_engine::reach_from(&prepared, &set)
    };

    let question = if is_to {
        format!("Tout ce qui peut atteindre {label}")
    } else {
        format!("Tout ce que {label} peut atteindre")
    };
    let view = backend::reach_to_view(&report, question);
    match args.format {
        DataFormat::Text => print!("{}", calque_report::render_reach_text(&view)),
        DataFormat::Json => println!("{}", calque_report::render_reach_json(&view)),
    }

    // §6.3 : parts non décidables, ou modèle partiel sur un équipement
    // touché → rapport NON FERME, code de sortie dédié.
    let has_undecidable = report
        .diagnostics
        .iter()
        .any(|d| d.severity == Severity::Error);
    let partial = partial_devices_in_reach(&project, &report);
    if has_undecidable || !partial.is_empty() {
        if args.format == DataFormat::Text {
            if !partial.is_empty() {
                let list = partial
                    .iter()
                    .map(|(d, n)| format!("« {d} » ({n} directive(s) non comprise(s))"))
                    .collect::<Vec<_>>()
                    .join(", ");
                println!(
                    "\nAttention : le rapport traverse un modèle partiel : {list}.\n\
                     Lancez `calque model check` pour le détail."
                );
            }
            println!("\nRapport NON FERME (code de sortie {EXIT_NON_FIRM}).");
        }
        return Ok(ExitCode::from(EXIT_NON_FIRM));
    }
    Ok(ExitCode::SUCCESS)
}

/// `parse_reach_spec` avec l'aide contextuelle de miette.
fn parse_reach_spec_or_help(raw: &str) -> miette::Result<ReachSpec> {
    crate::cli::parse_reach_spec(raw).map_err(|e| {
        miette!(
            help = "exemples : calque reach --to 10.0.20.5:445/tcp ; \
                    calque reach --to 10.0.20.0/24 ; \
                    calque reach --from vlan-invite",
            "{e}"
        )
    })
}

// ---------------------------------------------------------------------------
// calque model dead-rules (S6)
// ---------------------------------------------------------------------------

fn model_dead_rules(root: &Path, format: DataFormat) -> miette::Result<ExitCode> {
    let project = project::load(root)?;
    // L'analyse porte sur les politiques telles qu'importées : la
    // préparation pour le moteur (déplacement de politiques dans la
    // séquence) ne change ni les règles ni leur ordre.
    let view = backend::dead_rules_view(&project.network)?;
    match format {
        DataFormat::Text => print!("{}", calque_report::render_dead_rules_text(&view)),
        DataFormat::Json => println!("{}", calque_report::render_dead_rules_json(&view)),
    }
    // Informatif : code de sortie 0, même avec des règles mortes (seule
    // une erreur d'évaluation — déjà rendue plus haut — fait échouer).
    Ok(ExitCode::SUCCESS)
}

// ---------------------------------------------------------------------------
// calque test
// ---------------------------------------------------------------------------

fn test(root: &Path, args: TestArgs) -> miette::Result<ExitCode> {
    let project = project::load(root)?;
    let flows = load_flows(&args.flows)?;

    // L'évaluation vit dans calque-policy (`evaluate_flows`) : même
    // préparation du modèle que `path` et `plan`, faite une fois pour
    // toute la suite.
    let prepared = backend::prepare_for_engine(&project.network);
    // `--allow-partial` : la carte de fidélité vidée désactive le refus
    // de verdict ferme (§6.3) — assumé et rappelé sur stderr.
    let fidelity = if args.allow_partial {
        let partiels = project
            .device_fidelity
            .iter()
            .filter(|(_, f)| !f.is_complete())
            .count();
        if partiels > 0 {
            eprintln!(
                "Attention : --allow-partial — {partiels} équipement(s) à fidélité \
                 PARTIELLE ; les verdicts s'appuient sur la partie modélisée \
                 (lancez `calque model check` pour ce qui ne l'est pas)."
            );
        }
        std::collections::BTreeMap::new()
    } else {
        project.device_fidelity.clone()
    };
    let results = calque_policy::evaluate_flows(&prepared, &flows.flows, &fidelity);

    match args.format {
        OutputFormat::Text => print!("{}", calque_report::render_flow_results_text(&results)),
        OutputFormat::Junit => {
            print!(
                "{}",
                calque_report::render_flow_results_junit("calque", &results)
            );
        }
        OutputFormat::Json => {
            println!("{}", calque_report::render_flow_results_json(&results));
        }
    }

    let failures = results.iter().filter(|r| r.status.is_failure()).count();
    // Code de sortie non nul : c'est ce qui permet de brancher
    // `calque test` dans une chaîne d'intégration continue (§10.1).
    Ok(if failures > 0 {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    })
}

pub(crate) fn load_flows(path: &Path) -> miette::Result<FlowsFile> {
    // Borne de taille AVANT la désérialisation YAML (audit R1 — bombes
    // YAML) : la justification est documentée sur `MAX_YAML_BYTES`.
    let raw = backend::read_bounded(path, backend::MAX_YAML_BYTES, "un fichier de flux")?;
    let flows: FlowsFile = serde_yaml::from_str(&raw).map_err(|e| {
        miette!(
            help = "format attendu (§10.1) : flows: [ {{ name, from, to, port: 445/tcp | any, expect: allow | deny }} ]",
            "{} est invalide : {e}",
            path.display()
        )
    })?;
    if flows.flows.is_empty() {
        return Err(miette!("{} ne déclare aucun flux", path.display()));
    }
    Ok(flows)
}

/// La justification du verdict : la dernière décision portée par une règle.
fn deciding_rule(trace: &calque_report::TraceView) -> Option<String> {
    trace
        .hops
        .iter()
        .rev()
        .flat_map(|h| h.decisions.iter().rev())
        .find(|d| d.rule.is_some() || d.source.is_some())
        .map(|d| {
            let mut s = format!("{} : {}", d.stage, d.outcome);
            if let Some(rule) = &d.rule {
                s.push_str(&format!(" (règle {rule}"));
                if let Some(span) = &d.source {
                    s.push_str(&format!(", {span}"));
                }
                s.push(')');
            } else if let Some(span) = &d.source {
                s.push_str(&format!(" ({span})"));
            }
            s
        })
}

// ---------------------------------------------------------------------------
// calque plan (§10.2)
// ---------------------------------------------------------------------------

fn plan(root: &Path, args: PlanArgs) -> miette::Result<ExitCode> {
    let project = project::load(root)?;

    // 1. Import de la candidate, avec les mêmes adaptateurs que `import`.
    let candidate = backend::import_config(&args.candidate, None)?;
    println!(
        "candidate : {} ({}) → équipement « {} »",
        args.candidate.display(),
        backend::vendor_label(candidate.vendor),
        candidate.device.id
    );
    if let Fidelity::Partial { unsupported } = &candidate.fidelity {
        println!(
            "Attention : la candidate est PARTIELLE ({} directive(s) non comprise(s)) — \
             les verdicts qui la traversent ne seront pas fermes (§6.3).",
            unsupported.len()
        );
    }

    // 2. Remplacement de l'équipement de même identifiant — ou de l'unique
    // équipement du modèle. Choix documenté : sur un modèle à un seul
    // équipement, la candidate le remplace même si son hostname diffère,
    // et elle est réinsérée SOUS L'IDENTIFIANT EXISTANT pour préserver les
    // liens et les flux qui le référencent.
    let mut after = project.network.clone();
    let target_id = if after.devices.contains_key(&candidate.device.id) {
        candidate.device.id.clone()
    } else if after.devices.len() == 1 {
        let id = after.devices.keys().next().expect("un équipement").clone();
        println!(
            "note : « {} » remplace « {id} », l'unique équipement du modèle",
            candidate.device.id
        );
        id
    } else {
        let list = after
            .devices
            .keys()
            .map(|d| format!("« {d} »"))
            .collect::<Vec<_>>()
            .join(", ");
        return Err(miette!(
            help = "le remplacement se fait par identifiant ; vérifiez le hostname de la candidate ou réimportez le modèle avec `calque import --as`",
            "la candidate « {} » ne correspond à aucun équipement du modèle ({list})",
            candidate.device.id
        ));
    };
    let mut device = candidate.device;
    device.id = target_id.clone();
    after.devices.insert(target_id, device);

    // 3. Les flux déclarés, résolus comme pour `calque test` (sur le
    // modèle courant : ce sont ses zones qui font foi). Un flux non
    // résolu est signalé et écarté — jamais deviné.
    let mut resolved: Vec<calque_diff::ResolvedFlow> = Vec::new();
    if args.flows.exists() {
        let flows = load_flows(&args.flows)?;
        for flow in &flows.flows {
            match flow_packet(&project.network, flow) {
                Ok((packet, _)) => resolved.push(calque_diff::ResolvedFlow {
                    name: flow.name.clone(),
                    packet,
                    expect_allow: Some(matches!(flow.expect, Expectation::Allow)),
                }),
                Err(reason) => println!(
                    "avertissement : flux « {} » écarté — extrémité non résolue : {reason}",
                    flow.name
                ),
            }
        }
    } else {
        println!(
            "(pas de fichier {} : seules les ouvertures non déclarées seront recherchées)",
            args.flows.display()
        );
    }

    // 4. Comparaison de comportement sur les modèles préparés pour le
    // moteur (même préparation que `path` et `test`).
    let report = calque_diff::plan(
        &backend::prepare_for_engine(&project.network),
        &backend::prepare_for_engine(&after),
        &resolved,
    );

    // 5. Rendu §10.2 via calque-report.
    print!("{}", calque_report::render_plan_text(&plan_view(&report)));

    // ROMPU ou ouverture non déclarée → code de sortie non nul, comme
    // `calque test` : la prévisualisation échoue si le changement casse.
    Ok(if report.broken.is_empty() && report.new_flows.is_empty() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    })
}

/// Libellé d'un paquet concret : `10.0.10.5 → 10.0.20.5:445/tcp`.
fn packet_label(p: &ConcretePacket) -> String {
    let proto = match p.proto {
        6 => "tcp".to_owned(),
        17 => "udp".to_owned(),
        n => format!("proto {n}"),
    };
    format!("{} → {}:{}/{proto}", p.src, p.dst, p.dport)
}

/// Adapte le rapport de `calque-diff` vers la vue rendue par
/// `calque-report`.
fn plan_view(report: &calque_diff::PlanReport) -> calque_report::PlanView {
    let delta = |d: &calque_diff::FlowDelta| calque_report::PlanEntry {
        name: d.flow.clone(),
        flow: packet_label(&d.packet),
        // « avant : … ; après : … » → une ligne par côté, comme §10.2.
        detail: Some(d.explanation.replace(" ; ", "\n")),
    };
    calque_report::PlanView {
        broken: report.broken.iter().map(delta).collect(),
        fixed: report.fixed.iter().map(delta).collect(),
        changed: report.changed.iter().map(delta).collect(),
        undecided: report
            .undecided
            .iter()
            .map(|u| calque_report::PlanEntry {
                name: u.flow.clone(),
                flow: packet_label(&u.packet),
                detail: (!u.diagnostics.is_empty()).then(|| u.diagnostics.join("\n")),
            })
            .collect(),
        new_flows: report
            .new_flows
            .iter()
            .map(|n| {
                let mut detail = "n'était couvert par aucun flux déclaré (détection par sondes : \
                     l'absence d'autres lignes NOUVEAU ne prouve rien)"
                    .to_owned();
                if let Some(rule) = &n.allowed_by {
                    detail.push_str(&format!("\ndésormais autorisé par la règle {rule}"));
                    if let Some(span) = &n.source {
                        detail.push_str(&format!(" ({span})"));
                    }
                }
                calque_report::PlanEntry {
                    name: format!("{} → {}:{} devient joignable", n.from, n.to, n.port),
                    flow: format!("paquet témoin : {}", packet_label(&n.packet)),
                    detail: Some(detail),
                }
            })
            .collect(),
        unchanged: report.unchanged.clone(),
    }
}

// ---------------------------------------------------------------------------
// calque scrub (§10, §11.4)
// ---------------------------------------------------------------------------

/// Le rappel §11.4, imprimé sur stderr à chaque scrub (stderr pour ne pas
/// polluer une sortie redirigée : `calque scrub fw.conf > fw-anon.conf`).
const SCRUB_REMINDER: &str = "Rappel (§11.4) : relisez le résultat avant toute diffusion ; \
     l'anonymisation est structurelle, pas un chiffrement.";

/// La destination d'un fichier anonymisé : le même nom dans `--out-dir`,
/// sinon `<nom>.anon.<ext>` (ou `<nom>.anon` sans extension) à côté de
/// l'original.
fn scrub_out_path(file: &Path, out_dir: Option<&Path>) -> miette::Result<PathBuf> {
    let name = file
        .file_name()
        .ok_or_else(|| miette!("« {} » n'a pas de nom de fichier", file.display()))?;
    if let Some(dir) = out_dir {
        return Ok(dir.join(name));
    }
    let mut anon = file.file_stem().unwrap_or(name).to_os_string();
    anon.push(".anon");
    if let Some(ext) = file.extension() {
        anon.push(".");
        anon.push(ext);
    }
    Ok(file.with_file_name(anon))
}

/// Refuse une destination qui écraserait un fichier existant sans
/// `--force` — et refuse TOUJOURS d'écraser un fichier d'entrée de
/// l'appel : même avec `--force`, détruire l'original serait absurde.
fn scrub_check_dest(dest: &Path, inputs: &[PathBuf], force: bool) -> miette::Result<()> {
    if !dest.exists() {
        return Ok(());
    }
    let dest_canon = std::fs::canonicalize(dest).ok();
    let ecrase_une_entree = dest_canon.is_some()
        && inputs
            .iter()
            .any(|f| std::fs::canonicalize(f).ok() == dest_canon);
    if ecrase_une_entree {
        return Err(miette!(
            help = "choisissez un autre répertoire de sortie (--out-dir), ou laissez \
                    `calque scrub` nommer les sorties <nom>.anon.<ext>",
            "la sortie {} écraserait un fichier d'entrée de cet appel — refusé, même avec --force",
            dest.display()
        ));
    }
    if !force {
        return Err(miette!(
            help = "utilisez --force pour écraser, ou --out-dir pour écrire ailleurs",
            "{} existe déjà : rien n'a été écrit",
            dest.display()
        ));
    }
    Ok(())
}

/// `calque scrub <FICHIER>...` — anonymise un ou plusieurs fichiers avec
/// le MÊME `Scrubber` : la table de correspondance est partagée, donc un
/// nom ou une adresse présents dans plusieurs fichiers reçoivent partout
/// le même remplacement (§11.4). Indépendant du projet `.calque/`.
fn scrub(args: ScrubArgs) -> miette::Result<()> {
    let vers_stdout = args.files.len() == 1 && args.out_dir.is_none();

    // 1. Les destinations, vérifiées AVANT toute lecture et toute
    // écriture : on refuse d'écraser (sauf --force), et on n'écrit rien
    // du tout si une destination est refusée.
    let dests: Option<Vec<PathBuf>> = if vers_stdout {
        None
    } else {
        let mut dests = Vec::with_capacity(args.files.len());
        for file in &args.files {
            let dest = scrub_out_path(file, args.out_dir.as_deref())?;
            scrub_check_dest(&dest, &args.files, args.force)?;
            dests.push(dest);
        }
        Some(dests)
    };
    if let Some(map) = &args.map {
        scrub_check_dest(map, &args.files, args.force)?;
    }

    // 2. Anonymisation, avec un unique Scrubber pour tout l'appel. Tout
    // est lu et transformé avant la première écriture : une erreur de
    // lecture (fichier introuvable, non-UTF8, trop gros) ne laisse aucune
    // sortie partielle.
    let mut scrubber = calque_scrub::Scrubber::new();
    let mut sorties: Vec<String> = Vec::with_capacity(args.files.len());
    for file in &args.files {
        let brut = backend::read_bounded(file, backend::MAX_CONFIG_BYTES, "une configuration")?;
        let (texte, rapport) = scrubber.scrub_avec_rapport(&brut);
        if !rapport.format_reconnu {
            // En gras, sur stderr : la passe de collecte des noms n'a pas
            // reconnu le format — seuls secrets et adresses sont couverts.
            eprintln!(
                "\x1b[1mATTENTION : format non reconnu ({}) — anonymisation probablement \
                 incomplète (noms et identifiants non détectés). Ne diffusez pas ce résultat \
                 sans relecture approfondie.\x1b[0m",
                file.display()
            );
        }
        sorties.push(texte);
    }

    // 3. Écriture.
    match &dests {
        None => {
            // Un seul fichier, pas de --out-dir : sortie standard, pour
            // la redirection du §10 (`calque scrub fw-01.conf > …`).
            print!("{}", sorties[0]);
        }
        Some(dests) => {
            if let Some(dir) = &args.out_dir {
                std::fs::create_dir_all(dir)
                    .into_diagnostic()
                    .wrap_err_with(|| format!("création de {} impossible", dir.display()))?;
            }
            for ((file, dest), texte) in args.files.iter().zip(dests).zip(&sorties) {
                std::fs::write(dest, texte)
                    .into_diagnostic()
                    .wrap_err_with(|| format!("écriture de {} impossible", dest.display()))?;
                println!("{} → {}", file.display(), dest.display());
            }
            println!("{} fichier(s) anonymisé(s).", args.files.len());
        }
    }

    // 4. La table de correspondance, uniquement sur demande (--map).
    if let Some(map) = &args.map {
        let mut contenu = String::from(
            "# Table de correspondance `calque scrub` — à conserver en lieu sûr, ne jamais publier.\n\
             # Elle permet de retrouver les originaux : la diffuser annule l'anonymisation.\n\
             # Une ligne par remplacement : original<TAB>remplacement. Les secrets n'y figurent jamais.\n",
        );
        for (original, remplacement) in scrubber.mapping() {
            contenu.push_str(original);
            contenu.push('\t');
            contenu.push_str(remplacement);
            contenu.push('\n');
        }
        std::fs::write(map, contenu)
            .into_diagnostic()
            .wrap_err_with(|| format!("écriture de {} impossible", map.display()))?;
        eprintln!(
            "Table de correspondance écrite dans {} — à conserver en lieu sûr, ne jamais publier.",
            map.display()
        );
    }

    eprintln!("{SCRUB_REMINDER}");
    Ok(())
}

// ---------------------------------------------------------------------------
// calque topology check (§7)
// ---------------------------------------------------------------------------

/// Le fichier `topology.yaml` : des liens déclarés par l'humain,
/// désérialisés ici (le cœur reste pur).
#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct TopoFile {
    links: Vec<TopoLink>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct TopoLink {
    a: TopoEnd,
    b: TopoEnd,
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct TopoEnd {
    device: String,
    iface: String,
}

/// Deux liens relient-ils la même paire d'extrémités (peu importe l'ordre
/// et l'origine) ?
pub(crate) fn same_pair(x: &Link, y: &Link) -> bool {
    (x.a == y.a && x.b == y.b) || (x.a == y.b && x.b == y.a)
}

fn topology_check(root: &Path, topology_file: &Path) -> miette::Result<ExitCode> {
    let project = project::load(root)?;
    let mut network = project.network.clone();

    // topology.yaml optionnel : les liens y sont fusionnés comme Declared.
    if topology_file.exists() {
        // Même garde que `load_flows` (audit R1) : borne de taille avant
        // toute désérialisation YAML.
        let raw = backend::read_bounded(
            topology_file,
            backend::MAX_YAML_BYTES,
            "un fichier de topologie",
        )?;
        let topo: TopoFile = serde_yaml::from_str(&raw).map_err(|e| {
            miette!(
                help = "format attendu : links: [ {{ a: {{ device, iface }}, b: {{ device, iface }} }} ]",
                "{} est invalide : {e}",
                topology_file.display()
            )
        })?;
        let mut added = 0usize;
        for l in topo.links {
            let link = Link {
                a: Endpoint {
                    device: DeviceId::new(l.a.device),
                    iface: IfaceId::new(l.a.iface),
                },
                b: Endpoint {
                    device: DeviceId::new(l.b.device),
                    iface: IfaceId::new(l.b.iface),
                },
                origin: LinkOrigin::Declared,
            };
            if !network.links.iter().any(|e| same_pair(e, &link)) {
                network.links.push(link);
                added += 1;
            }
        }
        println!(
            "{added} lien(s) déclaré(s) chargé(s) depuis {}.",
            topology_file.display()
        );
    }

    // Inférence par sous-réseau (§7, source n° 3) : uniquement les
    // segments francs, jamais une étoile devinée.
    let inferred = calque_engine::infer_links_from_subnets(&network);
    if inferred.is_empty() {
        println!("Aucun lien inféré par sous-réseau.");
    } else {
        println!("{} lien(s) inféré(s) par sous-réseau :", inferred.len());
        for l in &inferred {
            println!(
                "  {}/{} ↔ {}/{}",
                l.a.device, l.a.iface, l.b.device, l.b.iface
            );
        }
    }
    // Les liens inférés participent à la vérification : une interface
    // reliée par inférence n'est pas « isolée ».
    network.links.extend(inferred);

    let issues = calque_engine::check_topology(&network);
    println!("Topologie : {} lien(s) au total.", network.links.len());
    if issues.is_empty() {
        println!("Aucune incohérence détectée.");
    } else {
        println!("{} incohérence(s) :", issues.len());
        for issue in &issues {
            println!("  {issue}");
        }
    }
    // Code de sortie non nul sur une incohérence de sévérité erreur
    // (lien déclaré cassé…) ; les avertissements et infos n'échouent pas.
    let has_error = issues.iter().any(|i| i.severity == Severity::Error);
    Ok(if has_error {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    })
}
