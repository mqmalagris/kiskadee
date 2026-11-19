use std::process::ExitCode;

use clap::{Parser, Subcommand};

mod ledger;
mod run;

/// Terminal email for you and your AI agents.
#[derive(Parser)]
#[command(name = "kiskadee", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Run the Broker in the foreground. Clients start one on demand, so
    /// you rarely need this.
    Broker(run::BrokerArgs),
    /// Check the Broker answers, starting it if needed.
    Ping,
    /// Show what agents and you did: every Verb call, in order.
    Ledger(ledger::Args),
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Some(Command::Broker(args)) => run::broker(args),
        Some(Command::Ping) => run::ping(),
        Some(Command::Ledger(args)) => ledger::run(args),
        None => Ok(ExitCode::SUCCESS),
    };
    result.unwrap_or_else(|error| {
        eprintln!("kiskadee: {error}");
        ExitCode::FAILURE
    })
}
