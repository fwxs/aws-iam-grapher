use std::io::Read;
use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "aws-iam-expansion")]
#[command(about = "Expand AWS IAM action wildcards using awsiamactions.io")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// List all IAM actions for a service, optionally filtered by prefix
    ExpandActions {
        /// AWS service name (e.g. s3, iam, ec2)
        service: String,
        /// Filter by action name prefix (e.g. Get)
        #[arg(long, short)]
        prefix: Option<String>,
    },
    /// Expand wildcards in a JSON IAM policy document
    ExpandPolicy {
        /// Path to the policy JSON file (reads from stdin when omitted)
        #[arg(long, short)]
        input: Option<PathBuf>,
    },
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::ExpandActions { service, prefix } => {
            let mut cache = match iam_expander::ActionCache::load().await {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("error: {e}");
                    std::process::exit(1);
                }
            };
            match iam_expander::expand_actions_with_cache(&service, prefix.as_deref(), &mut cache)
                .await
            {
                Ok(actions) => {
                    for action in actions {
                        println!("{action}");
                    }
                }
                Err(e) => {
                    eprintln!("error: {e}");
                    if let Err(flush_err) = cache.flush().await {
                        eprintln!("error flushing cache: {flush_err}");
                    }
                    std::process::exit(1);
                }
            }
            if let Err(e) = cache.flush().await {
                eprintln!("error: {e}");
                std::process::exit(1);
            }
        }
        Commands::ExpandPolicy { input } => {
            let json = match input {
                Some(path) => match std::fs::read_to_string(&path) {
                    Ok(s) => s,
                    Err(e) => {
                        eprintln!("error reading {}: {e}", path.display());
                        std::process::exit(1);
                    }
                },
                None => {
                    let mut buf = String::new();
                    if let Err(e) = std::io::stdin().read_to_string(&mut buf) {
                        eprintln!("error reading stdin: {e}");
                        std::process::exit(1);
                    }
                    buf
                }
            };

            let mut cache = match iam_expander::ActionCache::load().await {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("error: {e}");
                    std::process::exit(1);
                }
            };
            match iam_expander::expand_policy_document_with_cache(&json, &mut cache).await {
                Ok(expanded) => println!("{expanded}"),
                Err(e) => {
                    eprintln!("error: {e}");
                    if let Err(flush_err) = cache.flush().await {
                        eprintln!("error flushing cache: {flush_err}");
                    }
                    std::process::exit(1);
                }
            }
            if let Err(e) = cache.flush().await {
                eprintln!("error: {e}");
                std::process::exit(1);
            }
        }
    }
}
