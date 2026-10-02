use clap::Parser;

/// Terminal email for you and your AI agents.
#[derive(Parser)]
#[command(name = "kiskadee", version, about)]
struct Cli {}

fn main() {
    Cli::parse();
}
