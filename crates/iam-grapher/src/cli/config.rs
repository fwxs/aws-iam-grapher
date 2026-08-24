use crate::exit_code::CliValidationError;
use crate::output::OutputFormat;
use clap::{Args, Subcommand};
use iam_graph::RiskyActionGroups;
use serde::Serialize;
use std::path::{Path, PathBuf};

/// Validate or inspect risky-actions config.
#[derive(Args)]
pub struct ConfigArgs {
    #[command(subcommand)]
    pub verb: ConfigVerb,
}

#[derive(Subcommand)]
pub enum ConfigVerb {
    /// Validate a risky-actions config file, or the resolved default if no path is given.
    Check {
        /// Path to validate. Omit to validate the resolved default
        /// (~/.aws-iam-grapher/config/risky-actions.yaml).
        path: Option<PathBuf>,
    },
}

#[derive(Serialize)]
struct CheckResult {
    path: String,
    valid: bool,
    groups: Option<usize>,
    distinct_actions: Option<usize>,
    errors: Vec<String>,
}

pub async fn run(args: ConfigArgs, output: OutputFormat) -> anyhow::Result<()> {
    match args.verb {
        ConfigVerb::Check { path } => check(path.as_deref(), output),
    }
}

fn check(explicit: Option<&Path>, output: OutputFormat) -> anyhow::Result<()> {
    let home = std::env::var_os("HOME").map(PathBuf::from);
    let path = RiskyActionGroups::resolve_path(explicit, home.as_deref())?;

    if output != OutputFormat::Json {
        println!("checking {}", path.display());
    }

    let text =
        std::fs::read_to_string(&path).map_err(|source| iam_graph::RiskyActionsError::Read {
            path: path.display().to_string(),
            source,
        })?;

    match RiskyActionGroups::from_yaml(&text) {
        Ok(groups) => {
            let action_count = groups.all_actions().len();
            let group_count = groups.groups().len();
            if output == OutputFormat::Json {
                crate::output::json::print_json(&CheckResult {
                    path: path.display().to_string(),
                    valid: true,
                    groups: Some(group_count),
                    distinct_actions: Some(action_count),
                    errors: Vec::new(),
                })?;
            } else {
                println!("ok — {group_count} groups, {action_count} distinct actions");
            }
            Ok(())
        }
        Err(errors) => {
            let messages: Vec<String> = errors.iter().map(ToString::to_string).collect();
            let count = messages.len();
            if output == OutputFormat::Json {
                crate::output::json::print_json(&CheckResult {
                    path: path.display().to_string(),
                    valid: false,
                    groups: None,
                    distinct_actions: None,
                    errors: messages,
                })?;
            } else {
                for message in &messages {
                    println!("  error: {message}");
                }
                println!("{count} problem(s) found");
            }
            Err(CliValidationError::ConfigCheckFailed { count }.into())
        }
    }
}
