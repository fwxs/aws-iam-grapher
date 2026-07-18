use crate::cli::collect::SharedCollectArgs;
use anyhow::Context as _;
use clap::Args;
use iam_collector::{CollectorWarning, OrgCollector};
use iam_graph::{stitch_cross_account, GraphClient, GraphIngester, IngestConfig};
use uuid::Uuid;

#[derive(Args)]
pub struct OrgArgs {
    /// Named AWS profile for the organization's management account. Used only for
    /// Organizations discovery (enumerating OUs and accounts) — never for role assumption.
    #[arg(long)]
    pub management_profile: String,

    /// Named AWS profile to assume the per-account jump role from. Role assumption always
    /// originates from this profile, regardless of --management-profile, so a
    /// --management-profile that itself resolves to an assumed role (e.g. SSO, or a profile
    /// with role_arn/source_profile chaining) never double-hops the AssumeRole call. Defaults
    /// to the standard AWS credential chain (AWS_PROFILE / the "default" profile) if omitted.
    #[arg(long)]
    pub jump_from_profile: Option<String>,

    /// IAM role name to assume in every member account.
    #[arg(long)]
    pub assume_role_name: String,

    /// Organizational Unit id to exclude (and its descendants). Repeatable.
    #[arg(long = "exclude-ou-id")]
    pub exclude_ou_ids: Vec<String>,

    /// Organizational Unit display name to exclude (and its descendants). Repeatable.
    #[arg(long = "exclude-ou-name")]
    pub exclude_ou_names: Vec<String>,

    /// Collect accounts under this OU (by id or display name, matched against both — and its
    /// descendants) via a named local AWS profile directly, bypassing assume-role for that
    /// subtree entirely. Repeatable; form is `<ou_id_or_name>=<aws_profile>`. Nested overrides
    /// take precedence over an ancestor's. Every account collected this way still joins the
    /// same org collection run id.
    #[arg(long = "ou-profile-override")]
    pub ou_profile_overrides: Vec<String>,

    /// AWS region(s) to use for org discovery and jump-role assumption. Repeatable; the first
    /// entry wins and overrides whatever region --management-profile / --jump-from-profile
    /// resolve. If omitted, falls back to the resolved profile region, then us-east-1.
    #[arg(long = "region")]
    pub regions: Vec<String>,

    #[command(flatten)]
    pub shared: SharedCollectArgs,
}

pub async fn run(args: OrgArgs) -> anyhow::Result<()> {
    let ou_profile_overrides = parse_ou_profile_overrides(&args.ou_profile_overrides)?;

    let collector = OrgCollector::from_profile(
        args.management_profile.clone(),
        args.jump_from_profile.clone(),
        &args.regions,
        args.assume_role_name.clone(),
        args.exclude_ou_ids.clone(),
        args.exclude_ou_names.clone(),
        ou_profile_overrides,
    )
    .await
    .context("failed to build org collector")?;

    let result = collector
        .collect()
        .await
        .context("org-wide collection failed")?;

    for warning in &result.warnings {
        let msg = match warning {
            CollectorWarning::InstanceProfilesMissing => {
                "ListInstanceProfiles not accessible for an account".to_string()
            }
            CollectorWarning::InlinePoliciesNotResolved => {
                "some inline policy documents could not be resolved".to_string()
            }
            CollectorWarning::WildcardsNotExpanded => {
                "wildcard actions in some policies could not be expanded".to_string()
            }
            CollectorWarning::MfaDevicesMissing => {
                "some users' MFA devices could not be listed".to_string()
            }
            CollectorWarning::LoginProfileMissing => {
                "some users' console login status could not be determined".to_string()
            }
            CollectorWarning::AccessKeyActivityMissing => {
                "some users' access key activity could not be determined".to_string()
            }
            CollectorWarning::UserSecurityAttributesNotCollected => {
                "offline collection does not populate user MFA/login/activity attributes"
                    .to_string()
            }
            CollectorWarning::PartialData(msg) => msg.clone(),
        };
        eprintln!("[!] {msg}");
    }

    if args.shared.dry_run {
        println!("Dry run — no data written to Neo4j.\n");
        println!("Org collection run id: {}", result.run_id);
        println!("Accounts collected: {}", result.accounts.len());
        return Ok(());
    }

    let neo4j_pass = crate::cli::collect::resolve_neo4j_pass(&args.shared)?;
    let client = GraphClient::connect(&args.shared.neo4j_uri, &args.shared.neo4j_user, &neo4j_pass)
        .await
        .with_context(|| format!("failed to connect to Neo4j at {}", args.shared.neo4j_uri))?;
    client
        .initialize_schema()
        .await
        .context("failed to initialize Neo4j schema")?;

    println!("Org collection run id: {}", result.run_id);

    let mut client = client;
    for data in &result.accounts {
        let account_id = data.account_id.clone().with_context(|| {
            "an org member account produced no entities to derive an account ID from \
             — this should not happen for accounts returned by AWS Organizations"
        })?;
        let snapshot_id = Uuid::new_v4().to_string();
        let config = IngestConfig {
            snapshot_id: snapshot_id.clone(),
            account_id: account_id.clone(),
            account_alias: None,
            batch_size: args.shared.batch_size,
            dry_run: false,
            org_collection_run_id: Some(result.run_id.clone()),
        };
        let ingester = GraphIngester::new(client, config);
        let stats = ingester
            .ingest(data)
            .await
            .with_context(|| format!("ingestion failed for account {account_id}"))?;
        client = ingester.into_client();

        println!(
            "  account {account_id}: snapshot {snapshot_id} — {} relationships created",
            stats.relationships_created
        );
    }

    let edge_count = stitch_cross_account(client.inner(), &result.run_id)
        .await
        .context("cross-account stitch failed")?;
    println!("  cross-account edges stitched: {edge_count}");

    println!(
        "Org collection complete: {} accounts ingested, {} warnings",
        result.accounts.len(),
        result.warnings.len()
    );
    Ok(())
}

/// Parses repeatable `--ou-profile-override <ou_id_or_name>=<aws_profile>` entries into
/// `(ou_id_or_name, aws_profile)` pairs. OU-existence and profile-existence validation happen
/// later, inside `OrgCollector::collect()`, once the org tree has actually been enumerated —
/// this only validates the flag's `key=value` shape.
fn parse_ou_profile_overrides(entries: &[String]) -> anyhow::Result<Vec<(String, String)>> {
    entries
        .iter()
        .map(|entry| {
            let (ou, profile) = entry.split_once('=').ok_or_else(|| {
                anyhow::anyhow!("--ou-profile-override must be in `ou=profile` form, got `{entry}`")
            })?;
            Ok((ou.to_string(), profile.to_string()))
        })
        .collect()
}
