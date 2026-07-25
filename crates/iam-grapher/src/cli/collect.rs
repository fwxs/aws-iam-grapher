use crate::output::OutputFormat;
use anyhow::Context as _;
use clap::{Args, ValueEnum};
use iam_collector::{
    CollectedData, CollectorError, CollectorWarning, HybridCollector, IamDataSource, LiveCollector,
    OfflineCollectorBuilder,
};
use iam_graph::{GraphClient, GraphIngester, IngestConfig, IngestStats};
use std::path::PathBuf;
use tracing::info;
use uuid::Uuid;

#[derive(ValueEnum, Clone, PartialEq, Eq, Debug)]
pub enum CollectMode {
    Live,
    Offline,
    Hybrid,
}

/// Neo4j connection + output args shared by every `collect` subcommand.
#[derive(Args)]
pub struct SharedCollectArgs {
    /// Neo4j bolt URI.
    #[arg(long, default_value = "bolt://localhost:7687")]
    pub neo4j_uri: String,

    /// Neo4j username.
    #[arg(long, default_value = "neo4j")]
    pub neo4j_user: String,

    /// Neo4j password. Required via flag or NEO4J_PASSWORD env var, but not enforced by
    /// clap directly since this struct is also flattened into the `collect org` parent
    /// command where it is unused — see `resolve_neo4j_pass`.
    #[arg(long, env = "NEO4J_PASSWORD")]
    pub neo4j_pass: Option<String>,

    /// Batch size for Neo4j writes.
    #[arg(long, default_value = "500")]
    pub batch_size: usize,

    /// Show what would happen without writing to Neo4j.
    #[arg(long)]
    pub dry_run: bool,

    /// Output format.
    #[arg(long, value_enum, default_value = "table")]
    pub output: OutputFormat,

    /// Write JSON summary to this file. Overrides --output to JSON for the file;
    /// the human-readable summary still prints to stdout.
    #[arg(long)]
    pub output_file: Option<PathBuf>,
}

#[derive(Args)]
pub struct CollectArgs {
    /// Collection mode.
    #[arg(long, value_enum, default_value = "hybrid")]
    pub mode: CollectMode,

    /// JSON from `aws iam get-account-authorization-details` (required for offline).
    #[arg(long)]
    pub input_file: Option<PathBuf>,

    /// JSON from `aws iam list-instance-profiles` (optional for offline).
    #[arg(long)]
    pub profiles_file: Option<PathBuf>,

    #[command(flatten)]
    pub shared: SharedCollectArgs,

    /// AWS account ID (12-digit number). If omitted, derived automatically from entity ARNs
    /// in the collected data. Required when no entities are present (e.g. empty account).
    #[arg(long)]
    pub account_id: Option<String>,

    /// Human-readable alias for this account.
    #[arg(long)]
    pub account_alias: Option<String>,

    /// AWS region(s) to use for API calls. Repeatable; the first entry wins and overrides
    /// whatever region the profile/environment resolves. Ignored in offline mode. If omitted,
    /// falls back to the profile/environment's configured region, then us-east-1.
    #[arg(long = "region")]
    pub regions: Vec<String>,

    /// Named local AWS profile to use for credentials. Honored by `live` and `hybrid` modes;
    /// ignored in `offline` mode, same as `--region`. Precedence: this flag, if given, wins
    /// outright; otherwise `AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY` in the environment are
    /// used if both are set; otherwise the standard AWS credential chain (`AWS_PROFILE` / the
    /// `[default]` profile / a container or IMDS role) applies unchanged.
    #[arg(long)]
    pub profile: Option<String>,
}

/// Validate argument combinations before making any network calls.
pub fn validate(args: &CollectArgs) -> anyhow::Result<()> {
    if args.mode == CollectMode::Offline && args.input_file.is_none() {
        anyhow::bail!(
            "offline mode requires --input-file.\n\n\
             Generate the file with:\n\n    \
             aws iam get-account-authorization-details --output json > account-auth-details.json"
        );
    }
    if args.profile.as_deref() == Some("") {
        anyhow::bail!("--profile must not be empty");
    }
    Ok(())
}

/// Resolve the Neo4j password, erroring with a friendly message if it's missing.
/// Not enforced by clap directly because `SharedCollectArgs` is also flattened into the
/// `collect org` parent command, where this particular instance of it goes unused.
pub fn resolve_neo4j_pass(shared: &SharedCollectArgs) -> anyhow::Result<String> {
    shared
        .neo4j_pass
        .clone()
        .context("Neo4j password required: pass --neo4j-pass or set the NEO4J_PASSWORD env var")
}

pub async fn run(args: CollectArgs) -> anyhow::Result<()> {
    validate(&args)?;

    let data = match collect_data(&args).await {
        Ok(d) => d,
        Err(CollectorError::ManualInterventionRequired { instructions, .. }) => {
            eprintln!("{instructions}");
            std::process::exit(1);
        }
        Err(e) => return Err(e).context("collection failed"),
    };

    print_warnings(&data);

    if args.shared.dry_run {
        print_dry_run_summary(&data, &args);
        return Ok(());
    }

    let snapshot_id = Uuid::new_v4().to_string();
    let neo4j_pass = resolve_neo4j_pass(&args.shared)?;
    let client = GraphClient::connect(&args.shared.neo4j_uri, &args.shared.neo4j_user, &neo4j_pass)
        .await
        .with_context(|| format!("failed to connect to Neo4j at {}", args.shared.neo4j_uri))?;
    client
        .initialize_schema()
        .await
        .context("failed to initialize Neo4j schema")?;

    // Precedence: explicit --account-id flag → derived from entity ARNs → error.
    // Never fall back to "unknown" — every snapshot must be filed under a real account ID
    // because all analysis queries filter on account_id for tenant isolation.
    let account_id = args
        .account_id
        .clone()
        .or_else(|| data.account_id.clone())
        .with_context(|| {
            "could not determine AWS account ID: no entities were collected and \
             --account-id was not provided.\n\n\
             Pass the account ID explicitly:\n\n    \
             aws-iam-grapher collect --account-id 123456789012 ..."
        })?;

    let config = IngestConfig {
        snapshot_id: snapshot_id.clone(),
        account_id,
        account_alias: args.account_alias.clone(),
        batch_size: args.shared.batch_size,
        dry_run: false,
        org_collection_run_id: None,
    };

    let mode_label = mode_label(&args.mode);
    let start = std::time::Instant::now();
    let ingester = GraphIngester::new(client, config);
    let stats = ingester
        .ingest(&data)
        .await
        .context("ingestion into Neo4j failed")?;

    let duration_secs = start.elapsed().as_secs_f64();

    print_collect_summary(
        &snapshot_id,
        mode_label,
        &data,
        &stats,
        duration_secs,
        &args.shared.output,
        args.shared.output_file.as_deref(),
    )?;
    Ok(())
}

async fn collect_data(args: &CollectArgs) -> Result<CollectedData, CollectorError> {
    match args.mode {
        CollectMode::Live => {
            info!("building live collector");
            let collector = LiveCollector::from_env(&args.regions, args.profile.as_deref()).await?;
            collector.collect().await
        }
        CollectMode::Hybrid => {
            info!("building hybrid collector");
            let collector =
                HybridCollector::from_env(&args.regions, args.profile.as_deref()).await?;
            collector.collect().await
        }
        CollectMode::Offline => {
            info!("building offline collector");
            let input_path = args.input_file.as_ref().expect("validated above");
            let auth_json = std::fs::read_to_string(input_path)
                .with_context(|| format!("failed to read {}", input_path.display()))
                .map_err(|e| CollectorError::AwsSdk(e.to_string()))?;

            let mut builder = OfflineCollectorBuilder::new().auth_details_json(&auth_json);

            if let Some(profiles_path) = &args.profiles_file {
                let profiles_json = std::fs::read_to_string(profiles_path)
                    .with_context(|| format!("failed to read {}", profiles_path.display()))
                    .map_err(|e| CollectorError::AwsSdk(e.to_string()))?;
                builder = builder.instance_profiles_json(&profiles_json);
            }

            let collector = builder.build()?;
            collector.collect().await
        }
    }
}

fn print_warnings(data: &CollectedData) {
    for warning in &data.warnings {
        let msg: &str = match warning {
            CollectorWarning::InstanceProfilesMissing => {
                "ListInstanceProfiles not accessible — instance profiles will not be ingested.\n  \
                 To include them, run:\n    \
                 aws iam list-instance-profiles --output json > profiles.json\n  \
                 then re-run with: --profiles-file profiles.json"
            }
            CollectorWarning::InlinePoliciesNotResolved => {
                "Some inline policy documents could not be resolved."
            }
            CollectorWarning::WildcardsNotExpanded => {
                "Wildcard actions in some policies could not be expanded."
            }
            CollectorWarning::MfaDevicesMissing => {
                "Some users' MFA devices could not be listed (ListMFADevices denied)."
            }
            CollectorWarning::LoginProfileMissing => {
                "Some users' console login status could not be determined (GetLoginProfile denied)."
            }
            CollectorWarning::AccessKeyActivityMissing => {
                "Some users' access key activity could not be determined."
            }
            CollectorWarning::UserSecurityAttributesNotCollected => {
                "Offline collection does not populate MFA, console login, or last-activity \
                 attributes for users."
            }
            CollectorWarning::PartialData(msg) => msg,
        };
        eprintln!("[!] {msg}");
    }
}

fn entity_counts(data: &CollectedData) -> [(&'static str, usize); 5] {
    [
        ("Policies", data.policies.len()),
        ("Roles", data.roles.len()),
        ("Users", data.users.len()),
        ("Groups", data.groups.len()),
        ("Instance Profiles", data.instance_profiles.len()),
    ]
}

fn print_dry_run_summary(data: &CollectedData, args: &CollectArgs) {
    println!("Dry run — no data written to Neo4j.\n");
    println!("Would collect in mode: {}", mode_label(&args.mode));
    for (label, count) in entity_counts(data) {
        println!("  {label:<20} {count}");
    }
}

fn print_collect_summary(
    snapshot_id: &str,
    mode_label: &str,
    data: &CollectedData,
    stats: &IngestStats,
    duration_secs: f64,
    format: &OutputFormat,
    output_file: Option<&std::path::Path>,
) -> anyhow::Result<()> {
    let total_nodes = stats.accounts_merged
        + stats.snapshots_created
        + stats.policies_merged
        + stats.roles_merged
        + stats.users_merged
        + stats.groups_merged
        + stats.instance_profiles_merged
        + stats.permissions_merged;

    let summary = serde_json::json!({
        "snapshot_id": snapshot_id,
        "mode": mode_label,
        "collected": {
            "policies": data.policies.len(),
            "roles": data.roles.len(),
            "users": data.users.len(),
            "groups": data.groups.len(),
            "instance_profiles": data.instance_profiles.len(),
        },
        "ingested": {
            "nodes_created": total_nodes,
            "relationships_created": stats.relationships_created,
            "duration_secs": duration_secs,
        }
    });

    if let Some(path) = output_file {
        crate::output::json::write_json(&summary, path)?;
    } else if *format == OutputFormat::Json {
        let json = serde_json::to_string_pretty(&summary)
            .context("failed to serialize collect summary")?;
        println!("{json}");
        return Ok(());
    }

    println!("Snapshot ID: {snapshot_id}");
    println!("Collection completed in mode: {mode_label}");
    for (label, count) in entity_counts(data) {
        println!("  {label:<20} {count}");
    }
    println!();
    println!("Ingestion into Neo4j:");
    println!("  Nodes created:         {total_nodes}");
    println!("  Relationships created: {}", stats.relationships_created);
    println!("  Duration:              {duration_secs:.1}s");
    Ok(())
}

fn mode_label(mode: &CollectMode) -> &'static str {
    match mode {
        CollectMode::Live => "live",
        CollectMode::Offline => "offline",
        CollectMode::Hybrid => "hybrid",
    }
}
