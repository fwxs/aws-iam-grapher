mod cli;
mod exit_code;
mod output;

use clap::Parser as _;
use output::OutputFormat;
use std::process::ExitCode;

#[tokio::main]
async fn main() -> ExitCode {
    let parsed_cli = cli::Cli::parse();
    let json = parsed_cli.output == OutputFormat::Json;

    match run(parsed_cli).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => exit_code::handle_error(err, json),
    }
}

async fn run(parsed_cli: cli::Cli) -> anyhow::Result<()> {
    // RUST_LOG, when set, takes full control (e.g. `RUST_LOG=iam_collector=debug`) — our
    // defaults below only apply when the user hasn't opted into their own filter, otherwise a
    // same-target default directive would always win ties against the user's own.
    let filter = if std::env::var("RUST_LOG").is_ok() {
        tracing_subscriber::EnvFilter::from_default_env()
    } else {
        tracing_subscriber::EnvFilter::new("")
            .add_directive("aws_iam_grapher=info".parse()?)
            .add_directive("iam_collector=info".parse()?)
            .add_directive("iam_graph=info".parse()?)
    };

    tracing_subscriber::fmt().with_env_filter(filter).init();

    cli::run(parsed_cli).await
}
