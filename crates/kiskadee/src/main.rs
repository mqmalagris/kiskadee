use std::process::ExitCode;

use clap::{Parser, Subcommand};

mod ledger;

/// Terminal email for you and your AI agents.
#[derive(Parser)]
#[command(name = "kiskadee", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Show what agents and you did: every Verb call, in order.
    Ledger(ledger::Args),
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Some(Command::Ledger(args)) => ledger::run(args),
        None => Ok(ExitCode::SUCCESS),
    };
    result.unwrap_or_else(|error| {
        eprintln!("kiskadee: {error}");
        ExitCode::FAILURE
    })
}
