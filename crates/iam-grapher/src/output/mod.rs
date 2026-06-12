use clap::ValueEnum;

pub mod json;
pub mod table;

/// Output format selector for all subcommands.
#[derive(ValueEnum, Clone, PartialEq, Eq, Debug)]
pub enum OutputFormat {
    Table,
    Json,
}
