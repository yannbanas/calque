//! Le binaire `calque`. Toute la logique vit dans la bibliothèque
//! (`calque_cli`), pour rester testable.

use std::process::ExitCode;

use clap::Parser;

fn main() -> miette::Result<ExitCode> {
    let cli = calque_cli::cli::Cli::parse();
    calque_cli::commands::run(cli)
}
