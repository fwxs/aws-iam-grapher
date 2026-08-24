pub mod collect;
pub mod collect_org;
pub mod common;
pub mod config;
pub mod docs;
pub mod query;

use crate::output::OutputFormat;
use clap::{Args, Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "aws-iam-grapher",
    about = "Collect and analyse AWS IAM permissions as a graph",
    version
)]
pub struct Cli {
    /// Output format. Global so the error path (exit-code JSON envelope on stderr) and
    /// every subcommand's success-path output agree on the same format.
    #[arg(long, value_enum, global = true, default_value = "table")]
    pub output: OutputFormat,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Collect IAM data and persist it in Neo4j.
    Collect(Box<CollectTopArgs>),
    /// Run analysis queries against persisted IAM snapshots.
    Query(Box<query::QueryArgs>),
    /// Print bundled docs (caveats, limitations) from the installed docs directory.
    Docs(docs::DocsArgs),
    /// Validate or inspect risky-actions config.
    Config(config::ConfigArgs),
}

/// `collect` with no verb runs single-account collection (today's behavior, unchanged);
/// `collect org` runs an AWS-Organizations-wide collection across every member account.
#[derive(Args)]
pub struct CollectTopArgs {
    #[command(flatten)]
    pub account: collect::CollectArgs,

    #[command(subcommand)]
    pub verb: Option<CollectVerb>,
}

#[derive(Subcommand)]
pub enum CollectVerb {
    /// Enumerate an AWS Organization and collect every member account.
    Org(collect_org::OrgArgs),
}

pub async fn run(cli: Cli) -> anyhow::Result<()> {
    let output = cli.output;
    match cli.command {
        Commands::Collect(top) => match top.verb {
            Some(CollectVerb::Org(args)) => collect_org::run(args, output).await,
            None => collect::run(top.account, output).await,
        },
        Commands::Query(args) => query::run(*args, output).await,
        Commands::Docs(args) => docs::run(args, output).await,
        Commands::Config(args) => config::run(args).await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use collect::CollectMode;

    #[test]
    fn collect_default_mode_is_hybrid() {
        let cli = Cli::try_parse_from(["aws-iam-grapher", "collect"]).expect("parse must succeed");
        let Commands::Collect(top) = cli.command else {
            panic!("expected Collect subcommand");
        };
        assert_eq!(top.account.mode, CollectMode::Hybrid);
    }

    #[test]
    fn collect_neo4j_pass_file_parses() {
        let cli = Cli::try_parse_from([
            "aws-iam-grapher",
            "collect",
            "--neo4j-pass-file",
            "/run/secrets/neo4j_pass",
        ])
        .expect("parse must succeed");
        let Commands::Collect(top) = cli.command else {
            panic!("expected Collect subcommand");
        };
        assert_eq!(
            top.account.shared.connection.neo4j_pass_file,
            Some(std::path::PathBuf::from("/run/secrets/neo4j_pass"))
        );
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
        ])
        .expect("parse must succeed");
        let Commands::Collect(top) = cli.command else {
            panic!("expected Collect subcommand");
        };
        assert_eq!(top.account.mode, CollectMode::Offline);
        assert!(top.account.input_file.is_some());
    }

    #[test]
    fn collect_offline_without_input_file_fails_validation() {
        let args = collect::CollectArgs {
            mode: CollectMode::Offline,
            input_file: None,
            profiles_file: None,
            shared: collect::SharedCollectArgs {
                connection: common::ConnectionArgs {
                    neo4j_uri: "bolt://localhost:7687".to_string(),
                    neo4j_user: "neo4j".to_string(),
                    neo4j_pass_file: None,
                },
                batch_size: 500,
                dry_run: false,
                output: common::OutputArgs { output_file: None },
            },
            account_id: None,
            account_alias: None,
            regions: Vec::new(),
            profile: None,
        };
        assert!(collect::validate(&args).is_err());
    }

    #[test]
    fn collect_profile_parses() {
        let cli = Cli::try_parse_from(["aws-iam-grapher", "collect", "--profile", "work"])
            .expect("parse must succeed");
        let Commands::Collect(top) = cli.command else {
            panic!("expected Collect subcommand");
        };
        assert_eq!(top.account.profile, Some("work".to_string()));
    }

    #[test]
    fn collect_dry_run_flag_parses() {
        let cli = Cli::try_parse_from(["aws-iam-grapher", "collect", "--dry-run"])
            .expect("parse must succeed");
        let Commands::Collect(top) = cli.command else {
            panic!("expected Collect subcommand");
        };
        assert!(top.account.shared.dry_run);
    }

    #[test]
    fn collect_output_file_flag_parses() {
        let cli = Cli::try_parse_from([
            "aws-iam-grapher",
            "collect",
            "--output-file",
            "/tmp/out.json",
        ])
        .expect("parse must succeed");
        let Commands::Collect(top) = cli.command else {
            panic!("expected Collect subcommand");
        };
        assert_eq!(
            top.account.shared.output.output_file,
            Some(std::path::PathBuf::from("/tmp/out.json"))
        );
    }

    #[test]
    fn collect_regions_flag_defaults_to_empty() {
        let cli = Cli::try_parse_from(["aws-iam-grapher", "collect"]).expect("parse must succeed");
        let Commands::Collect(top) = cli.command else {
            panic!("expected Collect subcommand");
        };
        assert!(top.account.regions.is_empty());
    }

    #[test]
    fn collect_regions_flag_parses_repeated_values() {
        let cli = Cli::try_parse_from([
            "aws-iam-grapher",
            "collect",
            "--region",
            "us-west-2",
            "--region",
            "eu-central-1",
        ])
        .expect("parse must succeed");
        let Commands::Collect(top) = cli.command else {
            panic!("expected Collect subcommand");
        };
        assert_eq!(top.account.regions, vec!["us-west-2", "eu-central-1"]);
    }

    #[test]
    fn collect_org_parses_with_required_args() {
        let cli = Cli::try_parse_from([
            "aws-iam-grapher",
            "collect",
            "org",
            "--management-profile",
            "mgmt",
            "--assume-role-name",
            "OrgAccess",
            "--exclude-ou-id",
            "ou-1111",
            "--exclude-ou-id",
            "ou-2222",
        ])
        .expect("parse must succeed");
        let Commands::Collect(top) = cli.command else {
            panic!("expected Collect subcommand");
        };
        let Some(CollectVerb::Org(org_args)) = top.verb else {
            panic!("expected Org verb");
        };
        assert_eq!(org_args.management_profile, "mgmt");
        assert_eq!(org_args.assume_role_name, "OrgAccess");
        assert_eq!(org_args.exclude_ou_ids, vec!["ou-1111", "ou-2222"]);
        assert_eq!(org_args.jump_from_profile, None);
    }

    #[test]
    fn collect_org_parses_exclude_ou_name() {
        let cli = Cli::try_parse_from([
            "aws-iam-grapher",
            "collect",
            "org",
            "--management-profile",
            "mgmt",
            "--assume-role-name",
            "OrgAccess",
            "--exclude-ou-name",
            "Sandbox",
            "--exclude-ou-name",
            "Legacy",
        ])
        .expect("parse must succeed");
        let Commands::Collect(top) = cli.command else {
            panic!("expected Collect subcommand");
        };
        let Some(CollectVerb::Org(org_args)) = top.verb else {
            panic!("expected Org verb");
        };
        assert_eq!(org_args.exclude_ou_names, vec!["Sandbox", "Legacy"]);
        assert!(org_args.exclude_ou_ids.is_empty());
    }

    #[test]
    fn collect_org_parses_include_ou_name() {
        let cli = Cli::try_parse_from([
            "aws-iam-grapher",
            "collect",
            "org",
            "--management-profile",
            "mgmt",
            "--assume-role-name",
            "OrgAccess",
            "--include-ou-name",
            "Prod",
            "--include-ou-name",
            "Shared",
        ])
        .expect("parse must succeed");
        let Commands::Collect(top) = cli.command else {
            panic!("expected Collect subcommand");
        };
        let Some(CollectVerb::Org(org_args)) = top.verb else {
            panic!("expected Org verb");
        };
        assert_eq!(org_args.include_ou_names, vec!["Prod", "Shared"]);
        assert!(org_args.exclude_ou_names.is_empty());
    }

    #[test]
    fn collect_org_parses_jump_from_profile() {
        let cli = Cli::try_parse_from([
            "aws-iam-grapher",
            "collect",
            "org",
            "--management-profile",
            "mgmt",
            "--jump-from-profile",
            "default",
            "--assume-role-name",
            "OrgAccess",
        ])
        .expect("parse must succeed");
        let Commands::Collect(top) = cli.command else {
            panic!("expected Collect subcommand");
        };
        let Some(CollectVerb::Org(org_args)) = top.verb else {
            panic!("expected Org verb");
        };
        assert_eq!(org_args.jump_from_profile, Some("default".to_string()));
    }

    #[test]
    fn collect_org_parses_region_flag() {
        let cli = Cli::try_parse_from([
            "aws-iam-grapher",
            "collect",
            "org",
            "--management-profile",
            "mgmt",
            "--assume-role-name",
            "OrgAccess",
            "--region",
            "us-west-2",
        ])
        .expect("parse must succeed");
        let Commands::Collect(top) = cli.command else {
            panic!("expected Collect subcommand");
        };
        let Some(CollectVerb::Org(org_args)) = top.verb else {
            panic!("expected Org verb");
        };
        assert_eq!(org_args.regions, vec!["us-west-2"]);
    }

    #[test]
    fn collect_org_rejects_missing_management_profile() {
        let result = Cli::try_parse_from([
            "aws-iam-grapher",
            "collect",
            "org",
            "--assume-role-name",
            "OrgAccess",
        ]);
        assert!(result.is_err());
    }

    #[test]
    fn collect_org_rejects_missing_assume_role_name() {
        let result = Cli::try_parse_from([
            "aws-iam-grapher",
            "collect",
            "org",
            "--management-profile",
            "mgmt",
        ]);
        assert!(result.is_err());
    }

    #[test]
    fn query_output_file_flag_parses() {
        let cli = Cli::try_parse_from([
            "aws-iam-grapher",
            "query",
            "--output-file",
            "/tmp/out.json",
            "list-snapshots",
        ])
        .expect("parse must succeed");
        assert!(matches!(cli.command, Commands::Query(_)));
    }

    #[test]
    fn query_neo4j_pass_file_flag_parses() {
        let cli = Cli::try_parse_from([
            "aws-iam-grapher",
            "query",
            "--neo4j-pass-file",
            "/run/secrets/neo4j_pass",
            "list-snapshots",
        ])
        .expect("parse must succeed");
        assert!(matches!(cli.command, Commands::Query(_)));
    }

    #[test]
    fn query_output_file_after_subcommand_parses() {
        let cli = Cli::try_parse_from([
            "aws-iam-grapher",
            "query",
            "list-snapshots",
            "--output-file",
            "/tmp/out.json",
        ])
        .expect("--output-file is global, must parse after the subcommand");
        assert!(matches!(cli.command, Commands::Query(_)));
    }

    #[test]
    fn query_neo4j_uri_after_subcommand_parses() {
        let cli = Cli::try_parse_from([
            "aws-iam-grapher",
            "query",
            "list-snapshots",
            "--neo4j-uri",
            "bolt://example:7687",
        ])
        .expect("--neo4j-uri is global, must parse after the subcommand");
        assert!(matches!(cli.command, Commands::Query(_)));
    }

    #[test]
    fn docs_queries_parses_with_no_name() {
        let cli = Cli::try_parse_from(["aws-iam-grapher", "docs", "queries"])
            .expect("parse must succeed");
        let Commands::Docs(args) = cli.command else {
            panic!("expected Docs subcommand");
        };
        let Some(docs::DocsVerb::Queries(queries_args)) = args.verb else {
            panic!("expected Queries verb");
        };
        assert_eq!(queries_args.name, None);
    }

    #[test]
    fn docs_queries_parses_with_name() {
        let cli = Cli::try_parse_from(["aws-iam-grapher", "docs", "queries", "who-can"])
            .expect("parse must succeed");
        let Commands::Docs(args) = cli.command else {
            panic!("expected Docs subcommand");
        };
        let Some(docs::DocsVerb::Queries(queries_args)) = args.verb else {
            panic!("expected Queries verb");
        };
        assert_eq!(queries_args.name, Some("who-can".to_string()));
    }

    #[test]
    fn config_check_parses_with_no_path() {
        let cli = Cli::try_parse_from(["aws-iam-grapher", "config", "check"])
            .expect("parse must succeed");
        let Commands::Config(args) = cli.command else {
            panic!("expected Config subcommand");
        };
        let config::ConfigVerb::Check { path } = args.verb;
        assert_eq!(path, None);
    }

    #[test]
    fn config_check_parses_with_path() {
        let cli = Cli::try_parse_from(["aws-iam-grapher", "config", "check", "./my.yaml"])
            .expect("parse must succeed");
        let Commands::Config(args) = cli.command else {
            panic!("expected Config subcommand");
        };
        let config::ConfigVerb::Check { path } = args.verb;
        assert_eq!(path, Some(std::path::PathBuf::from("./my.yaml")));
    }

    #[test]
    fn query_rejects_batch_size() {
        let result = Cli::try_parse_from([
            "aws-iam-grapher",
            "query",
            "--batch-size",
            "10",
            "list-snapshots",
        ]);
        assert!(result.is_err());
    }
}
