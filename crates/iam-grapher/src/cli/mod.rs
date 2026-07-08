pub mod collect;
pub mod collect_org;
pub mod query;

use clap::{Args, Parser, Subcommand};

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
    Collect(Box<CollectTopArgs>),
    /// Run analysis queries against persisted IAM snapshots.
    Query(Box<query::QueryArgs>),
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

pub async fn run() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Collect(top) => match top.verb {
            Some(CollectVerb::Org(args)) => collect_org::run(args).await,
            None => collect::run(top.account).await,
        },
        Commands::Query(args) => query::run(*args).await,
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
        let Commands::Collect(top) = cli.command else {
            panic!("expected Collect subcommand");
        };
        assert_eq!(top.account.mode, CollectMode::Hybrid);
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
                neo4j_uri: "bolt://localhost:7687".to_string(),
                neo4j_user: "neo4j".to_string(),
                neo4j_pass: Some("neo4j".to_string()),
                batch_size: 500,
                dry_run: false,
                output: crate::output::OutputFormat::Table,
                output_file: None,
            },
            account_id: None,
            account_alias: None,
            regions: Vec::new(),
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
            "--neo4j-pass",
            "test",
        ])
        .expect("parse must succeed");
        let Commands::Collect(top) = cli.command else {
            panic!("expected Collect subcommand");
        };
        assert_eq!(
            top.account.shared.output_file,
            Some(std::path::PathBuf::from("/tmp/out.json"))
        );
    }

    #[test]
    fn collect_regions_flag_defaults_to_empty() {
        let cli = Cli::try_parse_from(["aws-iam-grapher", "collect", "--neo4j-pass", "test"])
            .expect("parse must succeed");
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
            "--neo4j-pass",
            "test",
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
            "--neo4j-pass",
            "test",
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
            "--neo4j-pass",
            "test",
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
            "--neo4j-pass",
            "test",
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
            "--neo4j-pass",
            "test",
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
            "--neo4j-pass",
            "test",
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
            "--neo4j-pass",
            "test",
        ]);
        assert!(result.is_err());
    }

    #[test]
    fn query_output_file_flag_parses() {
        let cli = Cli::try_parse_from([
            "aws-iam-grapher",
            "query",
            "--neo4j-pass",
            "test",
            "--output-file",
            "/tmp/out.json",
            "list-snapshots",
        ])
        .expect("parse must succeed");
        assert!(matches!(cli.command, Commands::Query(_)));
    }
}
