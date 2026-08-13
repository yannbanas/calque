//! Tests d'intégration du parsing clap (§10).

use calque_cli::cli::{Cli, Command, DataFormat, ModelCommand, OutputFormat, TopologyCommand};
use clap::Parser;

#[test]
fn import_fichier_avec_nom() {
    let cli = Cli::try_parse_from(["calque", "import", "fw-01.conf", "--as", "fw-01"]).unwrap();
    match cli.command {
        Command::Import(args) => {
            assert_eq!(args.file.as_deref().unwrap().to_str(), Some("fw-01.conf"));
            assert_eq!(args.name.as_deref(), Some("fw-01"));
            assert!(args.dir.is_none());
        }
        other => panic!("commande inattendue : {other:?}"),
    }
}

#[test]
fn import_repertoire() {
    let cli = Cli::try_parse_from(["calque", "import", "--dir", "./configs/"]).unwrap();
    match cli.command {
        Command::Import(args) => {
            assert!(args.file.is_none());
            assert_eq!(args.dir.as_deref().unwrap().to_str(), Some("./configs/"));
        }
        other => panic!("commande inattendue : {other:?}"),
    }
}

#[test]
fn import_sans_fichier_ni_repertoire_echoue() {
    assert!(Cli::try_parse_from(["calque", "import"]).is_err());
    // --dir et un fichier positionnel sont exclusifs.
    assert!(Cli::try_parse_from(["calque", "import", "fw.conf", "--dir", "d"]).is_err());
}

#[test]
fn model_check() {
    let cli = Cli::try_parse_from(["calque", "model", "check"]).unwrap();
    assert!(matches!(
        cli.command,
        Command::Model {
            command: ModelCommand::Check
        }
    ));
}

#[test]
fn path_avec_explain() {
    let cli = Cli::try_parse_from([
        "calque",
        "path",
        "10.0.10.5",
        "->",
        "10.0.20.10:445/tcp",
        "--explain",
    ])
    .unwrap();
    match cli.command {
        Command::Path(args) => {
            assert_eq!(args.src, "10.0.10.5".parse::<std::net::IpAddr>().unwrap());
            assert_eq!(args.arrow, "->");
            assert_eq!(args.dst, "10.0.20.10:445/tcp");
            assert!(args.explain);
            assert_eq!(args.format, DataFormat::Text);
        }
        other => panic!("commande inattendue : {other:?}"),
    }
}

#[test]
fn path_format_json() {
    let cli = Cli::try_parse_from([
        "calque",
        "path",
        "10.0.10.5",
        "->",
        "10.0.20.10:445/tcp",
        "--format",
        "json",
    ])
    .unwrap();
    match cli.command {
        Command::Path(args) => assert_eq!(args.format, DataFormat::Json),
        other => panic!("commande inattendue : {other:?}"),
    }
}

#[test]
fn test_par_defaut_et_junit() {
    let cli = Cli::try_parse_from(["calque", "test"]).unwrap();
    match cli.command {
        Command::Test(args) => {
            assert_eq!(args.flows.to_str(), Some("flows.yaml"));
            assert_eq!(args.format, OutputFormat::Text);
        }
        other => panic!("commande inattendue : {other:?}"),
    }

    let cli = Cli::try_parse_from(["calque", "test", "--format", "junit"]).unwrap();
    match cli.command {
        Command::Test(args) => assert_eq!(args.format, OutputFormat::Junit),
        other => panic!("commande inattendue : {other:?}"),
    }

    let cli = Cli::try_parse_from(["calque", "test", "--format", "json"]).unwrap();
    match cli.command {
        Command::Test(args) => assert_eq!(args.format, OutputFormat::Json),
        other => panic!("commande inattendue : {other:?}"),
    }
}

#[test]
fn plan_exige_candidate() {
    assert!(Cli::try_parse_from(["calque", "plan"]).is_err());
    let cli = Cli::try_parse_from(["calque", "plan", "--candidate", "fw-01-nouveau.conf"]).unwrap();
    match cli.command {
        Command::Plan(args) => {
            assert_eq!(args.candidate.to_str(), Some("fw-01-nouveau.conf"));
        }
        other => panic!("commande inattendue : {other:?}"),
    }
}

#[test]
fn scrub_fichiers_et_options() {
    // Au moins un fichier est requis.
    assert!(Cli::try_parse_from(["calque", "scrub"]).is_err());

    let cli = Cli::try_parse_from([
        "calque",
        "scrub",
        "fw-01.conf",
        "fw-02.conf",
        "--out-dir",
        "anon/",
        "--map",
        "table.tsv",
        "--force",
    ])
    .unwrap();
    match cli.command {
        Command::Scrub(args) => {
            assert_eq!(args.files.len(), 2);
            assert_eq!(args.files[0].to_str(), Some("fw-01.conf"));
            assert_eq!(args.out_dir.as_deref().unwrap().to_str(), Some("anon/"));
            assert_eq!(args.map.as_deref().unwrap().to_str(), Some("table.tsv"));
            assert!(args.force);
        }
        other => panic!("commande inattendue : {other:?}"),
    }

    // Les valeurs par défaut : ni --out-dir, ni --map, ni --force.
    let cli = Cli::try_parse_from(["calque", "scrub", "fw-01.conf"]).unwrap();
    match cli.command {
        Command::Scrub(args) => {
            assert_eq!(args.files.len(), 1);
            assert!(args.out_dir.is_none());
            assert!(args.map.is_none());
            assert!(!args.force);
        }
        other => panic!("commande inattendue : {other:?}"),
    }
}

#[test]
fn topology_check() {
    let cli = Cli::try_parse_from(["calque", "topology", "check"]).unwrap();
    match cli.command {
        Command::Topology {
            command: TopologyCommand::Check { topology },
        } => assert_eq!(topology.to_str(), Some("topology.yaml")),
        other => panic!("commande inattendue : {other:?}"),
    }
}
