use clap::ValueEnum;

pub mod graphviz;
pub mod json;

/// Output format selector for all subcommands.
#[derive(ValueEnum, Clone, PartialEq, Eq, Debug)]
pub enum OutputFormat {
    Json,
    /// Graphviz DOT text. Only supported by queries with graph-shaped results
    /// (`who-can`, `privilege-escalation`, `org-escalation`); other subcommands
    /// reject it with an error.
    Graphviz,
}
