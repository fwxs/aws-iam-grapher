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

    /// Neo4j bolt URI.
    #[arg(long, default_value = "bolt://localhost:7687")]
    pub neo4j_uri: String,

    /// Neo4j username.
    #[arg(long, default_value = "neo4j")]
    pub neo4j_user: String,

    /// Neo4j password.
    #[arg(long, env = "NEO4J_PASSWORD")]
    pub neo4j_pass: String,

    /// Human-readable alias for this account.
    #[arg(long)]
    pub account_alias: Option<String>,

    /// Batch size for Neo4j writes.
    #[arg(long, default_value = "500")]
    pub batch_size: usize,

    /// Show what would happen without writing to Neo4j.
    #[arg(long)]
    pub dry_run: bool,

    /// Output format.
    #[arg(long, value_enum, default_value = "table")]
    pub output: OutputFormat,
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
    Ok(())
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

    if args.dry_run {
        print_dry_run_summary(&data, &args);
        return Ok(());
    }

    let snapshot_id = Uuid::new_v4().to_string();
    let client = GraphClient::connect(&args.neo4j_uri, &args.neo4j_user, &args.neo4j_pass)
        .await
        .with_context(|| format!("failed to connect to Neo4j at {}", args.neo4j_uri))?;
    client
        .initialize_schema()
        .await
        .context("failed to initialize Neo4j schema")?;

    let config = IngestConfig {
        snapshot_id: snapshot_id.clone(),
        account_id: data
            .account_id
            .clone()
            .unwrap_or_else(|| "unknown".to_string()),
        account_alias: args.account_alias.clone(),
        batch_size: args.batch_size,
        dry_run: false,
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
        &args.output,
    )?;
    Ok(())
}

async fn collect_data(args: &CollectArgs) -> Result<CollectedData, CollectorError> {
    match args.mode {
        CollectMode::Live => {
            info!("building live collector");
            let collector = LiveCollector::from_env().await?;
            collector.collect().await
        }
        CollectMode::Hybrid => {
            info!("building hybrid collector");
            let collector = HybridCollector::from_env().await?;
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
) -> anyhow::Result<()> {
    let total_nodes = stats.accounts_merged
        + stats.snapshots_created
        + stats.policies_merged
        + stats.roles_merged
        + stats.users_merged
        + stats.groups_merged
        + stats.instance_profiles_merged
        + stats.permissions_merged;

    if *format == OutputFormat::Json {
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
