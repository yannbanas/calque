//! L'exécution des commandes.
//!
//! Toutes les erreurs passent par `miette` : jamais de panique sur une
//! entrée externe. Les textes sont en français.

use std::path::{Path, PathBuf};

use calque_model::{ConcretePacket, Fidelity, Severity};
use calque_policy::{FlowSpec, FlowsFile, PortSpec};
use calque_report::{FlowResult, FlowStatus, VerdictView};
use miette::{miette, Context, IntoDiagnostic};

use crate::backend;
use crate::cli::{
    Cli, Command, ImportArgs, ModelCommand, OutputFormat, PathArgs, PlanArgs, TestArgs,
    TopologyCommand,
};
use crate::project::{self, Project};

pub fn run(cli: Cli) -> miette::Result<()> {
    let root = std::env::current_dir()
        .into_diagnostic()
        .wrap_err("répertoire courant illisible")?;
    match cli.command {
        Command::Import(args) => import(&root, args),
        Command::Model {
            command: ModelCommand::Check,
        } => model_check(&root),
        Command::Path(args) => path(&root, args),
        Command::Test(args) => test(&root, args),
        Command::Plan(args) => plan(args),
        Command::Topology {
            command: TopologyCommand::Check,
        } => topology_check(),
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

fn add_import(project: &mut Project, file: &Path, name: Option<&str>) -> miette::Result<()> {
    let outcome = backend::import_config(file, name)?;
    project
        .network
        .devices
        .insert(outcome.device.id.clone(), outcome.device);
    let previous = std::mem::replace(&mut project.fidelity, Fidelity::Complete);
    project.fidelity = previous.merge(outcome.fidelity);
    project.imported_files.push(file.display().to_string());
    Ok(())
}

// ---------------------------------------------------------------------------
// calque model check
// ---------------------------------------------------------------------------

fn model_check(root: &Path) -> miette::Result<()> {
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
        }
    }
    Ok(())
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
// calque path
// ---------------------------------------------------------------------------

fn path(root: &Path, args: PathArgs) -> miette::Result<()> {
    if args.arrow != "->" {
        return Err(miette!(
            help = "exemple : calque path 10.0.10.5 '->' 10.0.20.10:445/tcp",
            "syntaxe : calque path SOURCE '->' DESTINATION (reçu « {} » à la place de « -> »)",
            args.arrow
        ));
    }
    let (dst, dport, proto) = crate::cli::parse_dst_spec(&args.dst).map_err(|e| miette!("{e}"))?;
    let project = project::load(root)?;
    refuse_verdict_on_partial_model(&project)?;

    let packet = ConcretePacket {
        src: args.src,
        dst,
        proto: proto.number(),
        // Port source éphémère représentatif ; le mode symbolique couvrira
        // tout l'intervalle.
        sport: 49152,
        dport,
    };
    let trace = backend::trace_concrete(&project.network, &packet)?;

    if args.explain {
        print!("{}", calque_report::render_trace_text(&trace));
    } else {
        println!(
            "{} → {}:{}/{} : {}",
            packet.src, packet.dst, packet.dport, proto, trace.verdict
        );
        let devices: Vec<&str> = trace.hops.iter().map(|h| h.device.as_str()).collect();
        if !devices.is_empty() {
            println!("chemin : {}", devices.join(" → "));
        }
        println!("(--explain pour la trace complète, règle par règle)");
    }
    Ok(())
}

/// Ne jamais deviner (§6.3) : pas de verdict ferme sur un modèle partiel.
///
/// Version 1, prudente : on refuse dès que le modèle est partiel. Quand le
/// moteur saura dire quelles directives touchent le chemin analysé, ce
/// refus deviendra plus fin.
fn refuse_verdict_on_partial_model(project: &Project) -> miette::Result<()> {
    if let Fidelity::Partial { unsupported } = &project.fidelity {
        return Err(miette!(
            help = "lancez `calque model check` pour la liste des directives non comprises",
            "le modèle est partiel ({} directive(s) non comprise(s)) : un verdict ferme serait une supposition, et Calque ne devine jamais (§6.3)",
            unsupported.len()
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// calque test
// ---------------------------------------------------------------------------

fn test(root: &Path, args: TestArgs) -> miette::Result<()> {
    let project = project::load(root)?;
    let raw = std::fs::read_to_string(&args.flows)
        .into_diagnostic()
        .wrap_err_with(|| {
            format!(
                "lecture du fichier de flux {} impossible",
                args.flows.display()
            )
        })?;
    let flows: FlowsFile = serde_yaml::from_str(&raw).map_err(|e| {
        miette!(
            help = "format attendu (§10.1) : flows: [ {{ name, from, to, port: 445/tcp | any, expect: allow | deny }} ]",
            "{} est invalide : {e}",
            args.flows.display()
        )
    })?;
    if flows.flows.is_empty() {
        return Err(miette!("{} ne déclare aucun flux", args.flows.display()));
    }

    let mut results = Vec::with_capacity(flows.flows.len());
    for flow in &flows.flows {
        results.push(run_flow(&project, flow)?);
    }

    match args.format {
        OutputFormat::Text => print!("{}", calque_report::render_flow_results_text(&results)),
        OutputFormat::Junit => {
            print!(
                "{}",
                calque_report::render_flow_results_junit("calque", &results)
            );
        }
    }

    let failures = results.iter().filter(|r| r.status.is_failure()).count();
    if failures > 0 {
        // Code de sortie non nul : c'est ce qui permet de brancher
        // `calque test` dans une chaîne d'intégration continue (§10.1).
        Err(miette!(
            "{failures} flux ne se comporte(nt) pas comme déclaré"
        ))
    } else {
        Ok(())
    }
}

/// Exécute un flux déclaré contre le modèle. Rend `Err` seulement pour les
/// problèmes d'infrastructure (moteur absent) ; un flux qui ne se comporte
/// pas comme déclaré rend un `FlowResult` en échec.
fn run_flow(project: &Project, flow: &FlowSpec) -> miette::Result<FlowResult> {
    // Extrémités symboliques : la résolution (zones, groupes d'objets)
    // n'est pas encore branchée. Ne jamais deviner → le flux est compté
    // en échec, avec la raison.
    let (src, dst) = match (flow.from.sample_ip(), flow.to.sample_ip()) {
        (Some(src), Some(dst)) => (src, dst),
        _ => {
            let symbolic = [&flow.from, &flow.to]
                .into_iter()
                .filter(|e| e.is_symbolic())
                .map(|e| format!("« {e} »"))
                .collect::<Vec<_>>()
                .join(" et ");
            return Ok(FlowResult {
                name: flow.name.clone(),
                flow: flow.flow_label(),
                expected: flow.expect.to_string(),
                actual: None,
                status: FlowStatus::Broken,
                detail: Some(format!(
                    "extrémité symbolique {symbolic} non encore résolue : verdict impossible, flux compté en échec (ne jamais deviner, §6.3)"
                )),
            });
        }
    };

    let (proto, dport, port_note) = match flow.port {
        PortSpec::One { port, proto } => (proto.number(), port, None),
        // `port: any` sur un test concret : un paquet représentatif.
        // La couverture complète de l'intervalle arrive avec le mode
        // symbolique (S6).
        PortSpec::Any => (
            6,
            80,
            Some("port « any » testé avec un paquet représentatif 80/tcp (couverture complète au mode symbolique)".to_owned()),
        ),
    };

    let packet = ConcretePacket {
        src,
        dst,
        proto,
        sport: 49152,
        dport,
    };
    let trace = backend::trace_concrete(&project.network, &packet)?;

    let actual = match trace.verdict {
        VerdictView::Allowed => "allow",
        VerdictView::Denied | VerdictView::NoRoute | VerdictView::Loop => "deny",
        VerdictView::Unknown => "unknown",
    };
    let as_declared = actual == flow.expect.as_str();
    let status = if as_declared && !matches!(trace.verdict, VerdictView::Unknown) {
        FlowStatus::Ok
    } else {
        FlowStatus::Broken
    };

    let mut detail = deciding_rule(&trace);
    if let Some(note) = port_note {
        detail = Some(match detail {
            Some(d) => format!("{d}\n          {note}"),
            None => note,
        });
    }

    Ok(FlowResult {
        name: flow.name.clone(),
        flow: flow.flow_label(),
        expected: flow.expect.to_string(),
        actual: Some(actual.to_owned()),
        status,
        detail,
    })
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
            }
            s
        })
}

// ---------------------------------------------------------------------------
// calque plan / calque topology check — étapes ultérieures
// ---------------------------------------------------------------------------

fn plan(args: PlanArgs) -> miette::Result<()> {
    Err(miette!(
        help = "en attendant, `calque test` vérifie déjà le modèle courant contre flows.yaml",
        "« calque plan » arrive à l'étape S4 de la feuille de route : la configuration candidate « {} » sera importée en parallèle du modèle courant, chaque flux de flows.yaml sera rejoué des deux côtés, et les différences seront signalées ROMPU / CORRIGÉ / NOUVEAU — y compris les ouvertures d'accès que personne n'a demandées (§10.2)",
        args.candidate.display()
    ))
}

fn topology_check() -> miette::Result<()> {
    Err(miette!(
        help = "les liens peuvent déjà être déclarés à la main dans le modèle ; l'inférence par sous-réseau et topology.yaml arrivent avec la topologie (§7)",
        "« calque topology check » n'est pas encore implémentée : elle signalera les liens ambigus ou manquants à partir de l'inférence par sous-réseau, corrigée par un fichier topology.yaml"
    ))
}
