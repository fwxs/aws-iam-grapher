use crate::exit_code::CliValidationError;
use clap::{Args, Subcommand};
use iam_graph::RiskyActionGroups;
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

pub async fn run(args: ConfigArgs) -> anyhow::Result<()> {
    match args.verb {
        ConfigVerb::Check { path } => check(path.as_deref()),
    }
}

fn check(explicit: Option<&Path>) -> anyhow::Result<()> {
    let path: PathBuf = match explicit {
        Some(p) => p.to_path_buf(),
        None => {
            let home = std::env::var_os("HOME")
                .map(PathBuf::from)
                .ok_or(iam_graph::RiskyActionsError::NoHome)?;
            home.join(".aws-iam-grapher/config/risky-actions.yaml")
        }
    };

    println!("checking {}", path.display());

    if !path.is_file() {
        return Err(iam_graph::RiskyActionsError::NotFound {
            path: path.display().to_string(),
        }
        .into());
    }

    let text =
        std::fs::read_to_string(&path).map_err(|source| iam_graph::RiskyActionsError::Read {
            path: path.display().to_string(),
            source,
        })?;

    match RiskyActionGroups::from_yaml(&text) {
        Ok(groups) => {
            let action_count = groups.all_actions().len();
            println!(
                "ok — {} groups, {} distinct actions",
                groups.groups().len(),
                action_count
            );
            Ok(())
        }
        Err(errors) => {
            for error in &errors {
                println!("  error: {error}");
            }
            let count = errors.len();
            println!("{count} problem(s) found");
            Err(CliValidationError::ConfigCheckFailed { count }.into())
        }
    }
}
