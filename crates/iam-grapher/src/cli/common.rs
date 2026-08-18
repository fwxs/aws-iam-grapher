use clap::Args;
use std::path::PathBuf;

/// Neo4j connection args shared by `collect` and `query`. `global = true` lets these
/// parse either before or after the subcommand name.
#[derive(Args)]
pub struct ConnectionArgs {
    /// Neo4j bolt URI.
    #[arg(long, global = true, default_value = "bolt://localhost:7687")]
    pub neo4j_uri: String,

    /// Neo4j username.
    #[arg(long, global = true, default_value = "neo4j")]
    pub neo4j_user: String,

    /// Path to a file containing the Neo4j password (e.g. a Docker/Kubernetes secret
    /// mount). Takes precedence over NEO4J_PASSWORD. A trailing newline is trimmed.
    #[arg(long, global = true)]
    pub neo4j_pass_file: Option<PathBuf>,
}

/// Output-file arg shared by `collect` and `query`. `--output` itself is already global
/// on the top-level `Cli` (`cli/mod.rs`).
#[derive(Args)]
pub struct OutputArgs {
    /// Write the result to this file, in whatever format --output selects.
    #[arg(long, global = true)]
    pub output_file: Option<PathBuf>,
}
