pub mod collect;
pub mod query;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "aws-iam-grapher",
    about = "Collect and analyse AWS IAM permissions as a graph",
    version
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Collect IAM data and persist it in Neo4j.
    Collect(collect::CollectArgs),
    /// Run analysis queries against persisted IAM snapshots.
    Query(query::QueryArgs),
}

pub async fn run() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Collect(args) => collect::run(args).await,
        Commands::Query(args) => query::run(args).await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use collect::CollectMode;

    #[test]
    fn collect_default_mode_is_hybrid() {
        let cli = Cli::try_parse_from(["aws-iam-grapher", "collect", "--neo4j-pass", "test"])
            .expect("parse must succeed");
        let Commands::Collect(args) = cli.command else {
            panic!("expected Collect subcommand");
        };
        assert_eq!(args.mode, CollectMode::Hybrid);
    }

    #[test]
    fn collect_offline_parses_with_input_file() {
        let cli = Cli::try_parse_from([
            "aws-iam-grapher",
            "collect",
            "--mode",
            "offline",
            "--input-file",
            "/tmp/auth.json",
            "--neo4j-pass",
            "test",
        ])
        .expect("parse must succeed");
        let Commands::Collect(args) = cli.command else {
            panic!("expected Collect subcommand");
        };
        assert_eq!(args.mode, CollectMode::Offline);
        assert!(args.input_file.is_some());
    }

    #[test]
    fn collect_offline_without_input_file_fails_validation() {
        let args = collect::CollectArgs {
            mode: CollectMode::Offline,
            input_file: None,
            profiles_file: None,
            neo4j_uri: "bolt://localhost:7687".to_string(),
            neo4j_user: "neo4j".to_string(),
            neo4j_pass: "neo4j".to_string(),
            account_alias: None,
            batch_size: 500,
            dry_run: false,
            output: crate::output::OutputFormat::Table,
        };
        assert!(collect::validate(&args).is_err());
    }

    #[test]
    fn collect_dry_run_flag_parses() {
        let cli = Cli::try_parse_from([
            "aws-iam-grapher",
            "collect",
            "--dry-run",
            "--neo4j-pass",
            "test",
        ])
        .expect("parse must succeed");
        let Commands::Collect(args) = cli.command else {
            panic!("expected Collect subcommand");
        };
        assert!(args.dry_run);
    }
}
