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

    /// Path to a file containing the Neo4j password (e.g. a Docker/Kubernetes secret
    /// mount). Takes precedence over NEO4J_PASSWORD. A trailing newline is trimmed.
    #[arg(long)]
    pub neo4j_pass_file: Option<PathBuf>,

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
    #[arg(long, value_parser = clap::builder::NonEmptyStringValueParser::new())]
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
    Ok(())
}

/// Resolve the Neo4j password: `--neo4j-pass-file` (if given) → `NEO4J_PASSWORD` env var
/// → error. The single source of truth for `collect`, `collect org`, and `query` — the
/// password is never accepted as a bare CLI value, since that would leak it into `ps`
/// output, shell history, and Claude Code transcripts. A file path is safe in argv
/// because it isn't the secret itself. File-read failures report the path, never the
/// file's contents.
pub fn resolve_neo4j_pass(pass_file: Option<&std::path::Path>) -> anyhow::Result<String> {
    if let Some(path) = pass_file {
        let contents = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read Neo4j password file {}", path.display()))?;
        let trimmed = contents.trim_end_matches(['\n', '\r']);
        if trimmed.trim().is_empty() {
            anyhow::bail!(
                "Neo4j password file {} is empty or whitespace-only",
                path.display()
            );
        }
        return Ok(trimmed.to_string());
    }

    std::env::var("NEO4J_PASSWORD").context(
        "Neo4j password required: pass --neo4j-pass-file <path> or set the \
         NEO4J_PASSWORD environment variable",
    )
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
    let neo4j_pass = resolve_neo4j_pass(args.shared.neo4j_pass_file.as_deref())?;
    let client = GraphClient::connect(&args.shared.neo4j_uri, &args.shared.neo4j_user, &neo4j_pass)
        .await
        .with_context(|| {
            format!(
                "failed to connect to Neo4j at {}",
                iam_graph::redact_uri(&args.shared.neo4j_uri)
            )
        })?;
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

#[cfg(test)]
mod tests {
    use super::*;

    /// `NEO4J_PASSWORD` is process-global; serialize every test here that touches it so
    /// they don't race under `cargo test`'s default parallel threads.
    static NEO4J_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn write_pass_file(contents: &str) -> tempfile::NamedTempFile {
        use std::io::Write as _;
        let mut file = tempfile::NamedTempFile::new().expect("create temp file");
        file.write_all(contents.as_bytes())
            .expect("write temp file");
        file
    }

    #[test]
    fn resolve_neo4j_pass_file_wins_over_env_var() {
        let _guard = NEO4J_ENV_LOCK.lock().expect("lock poisoned");
        std::env::set_var("NEO4J_PASSWORD", "env-pass");
        let file = write_pass_file("file-pass\n");

        let result = resolve_neo4j_pass(Some(file.path()));

        std::env::remove_var("NEO4J_PASSWORD");
        assert_eq!(result.expect("resolve must succeed"), "file-pass");
    }

    #[test]
    fn resolve_neo4j_pass_trims_trailing_newline() {
        let file = write_pass_file("secret\n");

        let result = resolve_neo4j_pass(Some(file.path()));

        assert_eq!(result.expect("resolve must succeed"), "secret");
    }

    #[test]
    fn resolve_neo4j_pass_empty_file_is_distinct_error() {
        let file = write_pass_file("   \n");

        let result = resolve_neo4j_pass(Some(file.path()));

        let err = result.expect_err("empty file must error");
        assert!(err.to_string().contains("empty or whitespace-only"));
    }

    #[test]
    fn resolve_neo4j_pass_missing_file_names_path() {
        let path = std::path::Path::new("/nonexistent/neo4j-pass-file-for-test");

        let result = resolve_neo4j_pass(Some(path));

        let err = result.expect_err("missing file must error");
        assert!(err.to_string().contains(path.to_str().unwrap()));
    }

    #[test]
    fn resolve_neo4j_pass_falls_back_to_env_var() {
        let _guard = NEO4J_ENV_LOCK.lock().expect("lock poisoned");
        std::env::set_var("NEO4J_PASSWORD", "env-only-pass");

        let result = resolve_neo4j_pass(None);

        std::env::remove_var("NEO4J_PASSWORD");
        assert_eq!(result.expect("resolve must succeed"), "env-only-pass");
    }

    #[test]
    fn resolve_neo4j_pass_errors_when_nothing_set() {
        let _guard = NEO4J_ENV_LOCK.lock().expect("lock poisoned");
        std::env::remove_var("NEO4J_PASSWORD");

        let result = resolve_neo4j_pass(None);

        assert!(result.is_err());
    }
}
