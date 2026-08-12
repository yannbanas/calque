//! L'exécution des commandes.
//!
//! Toutes les erreurs passent par `miette` : jamais de panique sur une
//! entrée externe. Les textes sont en français.
//!
//! Codes de sortie : `run` rend un `ExitCode` pour distinguer un verdict
//! (refusé, non ferme, flux en échec…) d'une erreur d'exécution. Le détail
//! par commande est documenté dans l'aide (`cli.rs`).

use std::collections::BTreeSet;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use calque_engine::Trace;
use calque_model::{
    ConcretePacket, DeviceId, Endpoint, Fidelity, IfaceId, Link, LinkOrigin, Network, Severity,
    ZoneId,
};
use calque_policy::{EndpointSpec, Expectation, FlowSpec, FlowsFile, PortSpec};
use calque_report::{FlowResult, FlowStatus, VerdictView};
use miette::{miette, Context, IntoDiagnostic};

use crate::backend;
use crate::cli::{
    Cli, Command, ImportArgs, ModelCommand, OutputFormat, PathArgs, PlanArgs, TestArgs,
    TopologyCommand,
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
        Command::Path(args) => path(&root, args),
        Command::Test(args) => test(&root, args),
        Command::Plan(args) => plan(&root, args),
        Command::Topology {
            command: TopologyCommand::Check { topology },
        } => topology_check(&root, &topology),
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
    project.device_fidelity.insert(id, outcome.fidelity);
    project.recompute_fidelity();
    let label = file.display().to_string();
    if !project.imported_files.contains(&label) {
        project.imported_files.push(label);
    }
    Ok(())
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
/// un verdict qui les traverse n'est pas ferme (§6.3).
fn partial_devices_on_path(project: &Project, trace: &Trace) -> Vec<(DeviceId, usize)> {
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for hop in &trace.hops {
        if !seen.insert(hop.device.clone()) {
            continue;
        }
        if let Fidelity::Partial { unsupported } = project.fidelity_of(&hop.device) {
            out.push((hop.device.clone(), unsupported.len()));
        }
    }
    out
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

    if args.explain {
        print!("{}", calque_report::render_trace_text(&view));
        if !trace.diagnostics.is_empty() {
            println!();
            print_trace_diagnostics(&trace);
        }
    } else {
        println!(
            "{} → {}:{}/{} : {}",
            packet.src, packet.dst, packet.dport, proto, view.verdict
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

    // Verdict indéterminé : le moteur n'a pas pu conclure sans deviner.
    if matches!(view.verdict, VerdictView::Unknown) {
        if !args.explain {
            print_trace_diagnostics(&trace);
        }
        println!("\nVerdict NON FERME (code de sortie {EXIT_NON_FIRM}).");
        return Ok(ExitCode::from(EXIT_NON_FIRM));
    }

    // §6.3 : un équipement traversé a un import partiel → pas de verdict
    // ferme, même si le moteur a conclu sur ce que le modèle contient.
    let partial = partial_devices_on_path(&project, &trace);
    if !partial.is_empty() {
        let list = partial
            .iter()
            .map(|(d, n)| format!("« {d} » ({n} directive(s) non comprise(s))"))
            .collect::<Vec<_>>()
            .join(", ");
        println!(
            "\nAttention : verdict NON FERME — le chemin traverse un modèle partiel : {list}.\n\
             Lancez `calque model check` pour le détail (code de sortie {EXIT_NON_FIRM})."
        );
        return Ok(ExitCode::from(EXIT_NON_FIRM));
    }

    Ok(match view.verdict {
        VerdictView::Allowed => ExitCode::SUCCESS,
        // Refusé / pas de route / boucle : documenté dans l'aide.
        _ => ExitCode::from(1),
    })
}

// ---------------------------------------------------------------------------
// calque test
// ---------------------------------------------------------------------------

fn test(root: &Path, args: TestArgs) -> miette::Result<ExitCode> {
    let project = project::load(root)?;
    let flows = load_flows(&args.flows)?;

    let mut results = Vec::with_capacity(flows.flows.len());
    for flow in &flows.flows {
        results.push(run_flow(&project, flow));
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
    // Code de sortie non nul : c'est ce qui permet de brancher
    // `calque test` dans une chaîne d'intégration continue (§10.1).
    Ok(if failures > 0 {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    })
}

fn load_flows(path: &Path) -> miette::Result<FlowsFile> {
    let raw = std::fs::read_to_string(path)
        .into_diagnostic()
        .wrap_err_with(|| format!("lecture du fichier de flux {} impossible", path.display()))?;
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

/// Résout une extrémité de flux en adresse concrète représentative :
/// IP telle quelle ; préfixe CIDR → première adresse hôte ; nom symbolique
/// → zone du modèle (première adresse d'hôte d'un sous-réseau d'une
/// interface membre, hors adresse de l'interface elle-même). Échec → raison
/// honnête, jamais une supposition.
fn resolve_endpoint(network: &Network, e: &EndpointSpec) -> Result<IpAddr, String> {
    match e {
        EndpointSpec::Ip(ip) => Ok(*ip),
        EndpointSpec::Net(net) => net
            .hosts()
            .next()
            .ok_or_else(|| format!("le préfixe {net} ne contient aucune adresse hôte")),
        EndpointSpec::Symbolic(name) => resolve_zone_sample(network, name),
    }
}

/// Résout un nom symbolique comme zone du modèle et rend une adresse
/// d'hôte représentative d'un sous-réseau d'une interface membre.
fn resolve_zone_sample(network: &Network, name: &str) -> Result<IpAddr, String> {
    let zone = ZoneId::new(name);
    let mut hits: Vec<(&calque_model::Device, &Vec<calque_model::IfaceId>)> = network
        .devices
        .values()
        .filter_map(|d| d.zones.get(&zone).map(|members| (d, members)))
        .collect();
    let (device, members) = match hits.len() {
        0 => return Err(format!("« {name} » ne correspond à aucune zone du modèle")),
        1 => hits.pop().expect("hits.len() == 1"),
        _ => {
            let list = hits
                .iter()
                .map(|(d, _)| format!("« {} »", d.id))
                .collect::<Vec<_>>()
                .join(", ");
            return Err(format!(
                "la zone « {name} » existe sur plusieurs équipements ({list}) : ambigu"
            ));
        }
    };
    for member in members {
        let Some(iface) = device.interfaces.get(member) else {
            continue;
        };
        for addr in &iface.addrs {
            // La première adresse d'hôte du sous-réseau qui n'est pas
            // l'adresse de l'interface : elle représente un hôte de la
            // zone, pas la passerelle.
            if let Some(host) = addr.hosts().find(|h| *h != addr.addr()) {
                return Ok(host);
            }
        }
    }
    Err(format!(
        "la zone « {name} » (équipement « {} ») n'a aucun sous-réseau exploitable",
        device.id
    ))
}

/// Construit le paquet concret représentatif d'un flux déclaré : les
/// extrémités sont résolues (voir [`resolve_endpoint`]) et `port: any`
/// devient un paquet représentatif 80/tcp (avec une note ; la couverture
/// complète de l'intervalle arrive avec le mode symbolique, S6).
fn flow_packet(
    network: &Network,
    flow: &FlowSpec,
) -> Result<(ConcretePacket, Option<String>), String> {
    let src = resolve_endpoint(network, &flow.from)?;
    let dst = resolve_endpoint(network, &flow.to)?;
    let (proto, dport, port_note) = match flow.port {
        PortSpec::One { port, proto } => (proto.number(), port, None),
        PortSpec::Any => (
            6,
            80,
            Some(
                "port « any » testé avec un paquet représentatif 80/tcp \
                 (couverture complète au mode symbolique)"
                    .to_owned(),
            ),
        ),
    };
    Ok((
        ConcretePacket {
            src,
            dst,
            proto,
            sport: backend::EPHEMERAL_SPORT,
            dport,
        },
        port_note,
    ))
}

/// Exécute un flux déclaré contre le modèle. Un flux qui ne se comporte
/// pas comme déclaré — ou qu'on ne peut pas évaluer sans deviner — rend
/// un `FlowResult` en échec, jamais une erreur fatale.
fn run_flow(project: &Project, flow: &FlowSpec) -> FlowResult {
    let broken = |actual: Option<String>, detail: String| FlowResult {
        name: flow.name.clone(),
        flow: flow.flow_label(),
        expected: flow.expect.to_string(),
        actual,
        status: FlowStatus::Broken,
        detail: Some(detail),
    };

    // Résolution des extrémités (documentée dans l'aide de `calque test`).
    let (packet, port_note) = match flow_packet(&project.network, flow) {
        Ok(x) => x,
        Err(reason) => {
            return broken(
                None,
                format!("extrémité non résolue : {reason} — flux compté en échec (§6.3)"),
            )
        }
    };
    let trace = backend::trace_concrete(&project.network, &packet);
    let view = backend::trace_to_view(&trace);

    // §6.3 : chemin traversant un import partiel → pas de verdict ferme,
    // le flux est compté en échec avec la raison.
    let partial = partial_devices_on_path(project, &trace);
    if !partial.is_empty() {
        let list = partial
            .iter()
            .map(|(d, _)| format!("« {d} »"))
            .collect::<Vec<_>>()
            .join(", ");
        return broken(
            None,
            format!(
                "verdict non ferme : le chemin traverse un modèle partiel ({list}) — \
                 lancez `calque model check` (§6.3)"
            ),
        );
    }

    let actual = match view.verdict {
        VerdictView::Allowed => "allow",
        VerdictView::Denied | VerdictView::NoRoute | VerdictView::Loop => "deny",
        VerdictView::Unknown => "unknown",
    };
    let as_declared = actual == flow.expect.as_str();
    let status = if as_declared && !matches!(view.verdict, VerdictView::Unknown) {
        FlowStatus::Ok
    } else {
        FlowStatus::Broken
    };

    let mut detail = deciding_rule(&view);
    if matches!(view.verdict, VerdictView::Unknown) {
        let reasons = trace
            .diagnostics
            .iter()
            .map(|d| d.message.clone())
            .collect::<Vec<_>>()
            .join(" ; ");
        detail = Some(match detail {
            Some(d) => format!("{d}\n          {reasons}"),
            None => reasons,
        });
    }
    if let Some(note) = port_note {
        detail = Some(match detail {
            Some(d) => format!("{d}\n          {note}"),
            None => note,
        });
    }

    FlowResult {
        name: flow.name.clone(),
        flow: flow.flow_label(),
        expected: flow.expect.to_string(),
        actual: Some(actual.to_owned()),
        status,
        detail,
    }
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
fn same_pair(x: &Link, y: &Link) -> bool {
    (x.a == y.a && x.b == y.b) || (x.a == y.b && x.b == y.a)
}

fn topology_check(root: &Path, topology_file: &Path) -> miette::Result<ExitCode> {
    let project = project::load(root)?;
    let mut network = project.network.clone();

    // topology.yaml optionnel : les liens y sont fusionnés comme Declared.
    if topology_file.exists() {
        let raw = std::fs::read_to_string(topology_file)
            .into_diagnostic()
            .wrap_err_with(|| format!("lecture de {} impossible", topology_file.display()))?;
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
