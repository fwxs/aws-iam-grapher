use crate::cli::collect::SharedCollectArgs;
use anyhow::Context as _;
use clap::Args;
use iam_collector::{CollectorWarning, OrgCollector};
use iam_graph::{stitch_cross_account, GraphClient, GraphIngester, IngestConfig};
use uuid::Uuid;

#[derive(Args)]
pub struct OrgArgs {
    /// Named AWS profile for the organization's management account.
    #[arg(long)]
    pub management_profile: String,

    /// IAM role name to assume in every member account.
    #[arg(long)]
    pub assume_role_name: String,

    /// Organizational Unit id to exclude (and its descendants). Repeatable.
    #[arg(long = "exclude-ou")]
    pub exclude_ous: Vec<String>,

    #[command(flatten)]
    pub shared: SharedCollectArgs,
}

pub async fn run(args: OrgArgs) -> anyhow::Result<()> {
    let collector = OrgCollector::from_profile(
        args.management_profile.clone(),
        args.assume_role_name.clone(),
        args.exclude_ous.clone(),
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
