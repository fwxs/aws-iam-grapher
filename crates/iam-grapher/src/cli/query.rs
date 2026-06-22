use crate::output::{json, table, OutputFormat};
use anyhow::Context as _;
use clap::{Args, Subcommand};
use iam_graph::{
    delete_snapshot, diff_permissions, entity_permissions, instance_profiles_with_action,
    list_snapshots, privilege_escalation_paths, who_can, GraphClient, PermissionRow, QueryContext,
    DEFAULT_MAX_HOPS,
};

#[derive(Args)]
pub struct QueryArgs {
    /// Neo4j bolt URI.
    #[arg(long, default_value = "bolt://localhost:7687")]
    neo4j_uri: String,

    /// Neo4j username.
    #[arg(long, default_value = "neo4j")]
    neo4j_user: String,

    /// Neo4j password.
    #[arg(long, env = "NEO4J_PASSWORD")]
    neo4j_pass: String,

    /// AWS account ID to query (required for most subcommands).
    #[arg(long)]
    account_id: Option<String>,

    /// Snapshot ID to query (default: most recent for the account).
    #[arg(long)]
    snapshot_id: Option<String>,

    /// Output format.
    #[arg(long, value_enum, default_value = "table")]
    output: OutputFormat,

    #[command(subcommand)]
    command: QueryCommand,
}

#[derive(Subcommand)]
enum QueryCommand {
    /// Entities that can perform the given IAM action.
    WhoCan {
        action: String,
        /// Intersect wildcard (Action: "*") grants against this resource ARN, excluding
        /// grants whose resource scope doesn't cover it.
        #[arg(long)]
        resource: Option<String>,
    },
    /// All permissions for a specific entity ARN.
    EntityPerms { arn: String },
    /// Instance profiles whose roles grant the given IAM action.
    InstanceProfilesWith { action: String },
    /// Entities with privilege-escalation permissions, directly or via a transitive
    /// sts:AssumeRole chain.
    PrivilegeEscalation {
        /// Max sts:AssumeRole hops to traverse when looking for transitive escalation
        /// paths. Capped at 10 to bound traversal cost on dense CAN_ASSUME_ROLE graphs.
        #[arg(long, default_value_t = DEFAULT_MAX_HOPS)]
        max_hops: u32,
    },
    /// List available snapshots for the account.
    ListSnapshots,
    /// Compare permissions between two snapshots.
    Diff {
        snapshot_a: String,
        snapshot_b: String,
    },
    /// Delete a snapshot and all its nodes from the graph.
    DeleteSnapshot { snapshot_id: String },
}

pub async fn run(args: QueryArgs) -> anyhow::Result<()> {
    let client = GraphClient::connect(&args.neo4j_uri, &args.neo4j_user, &args.neo4j_pass)
        .await
        .with_context(|| format!("failed to connect to Neo4j at {}", args.neo4j_uri))?;

    match args.command {
        QueryCommand::ListSnapshots => {
            let account_id = require_account_id(args.account_id.as_deref())?;
            let snapshots = list_snapshots(client.inner(), account_id)
                .await
                .context("list-snapshots query failed")?;

            if args.output == OutputFormat::Json {
                return json::print_json(&snapshots);
            }

            let rows: Vec<Vec<String>> = snapshots
                .iter()
                .map(|s| {
                    vec![
                        s.id.clone(),
                        s.account_id.clone(),
                        s.collected_at.clone(),
                        if s.is_partial { "partial" } else { "full" }.to_string(),
                    ]
                })
                .collect();
            print!(
                "{}",
                table::format_table(&["SNAPSHOT ID", "ACCOUNT", "COLLECTED AT", "STATUS"], &rows)
            );
        }

        QueryCommand::DeleteSnapshot { snapshot_id } => {
            let deleted = delete_snapshot(client.inner(), &snapshot_id)
                .await
                .context("delete-snapshot failed")?;
            println!("Deleted {deleted} nodes for snapshot {snapshot_id}");
        }

        QueryCommand::Diff {
            ref snapshot_a,
            ref snapshot_b,
        } => {
            let account_id = require_account_id(args.account_id.as_deref())?;
            let diff = diff_permissions(client.inner(), account_id, snapshot_a, snapshot_b)
                .await
                .context("diff query failed")?;

            if args.output == OutputFormat::Json {
                return json::print_json(&diff);
            }

            println!("Permission diff between {snapshot_a} and {snapshot_b}\n");

            if diff.added.is_empty() && diff.removed.is_empty() {
                println!("No permission differences found.");
                return Ok(());
            }

            if !diff.added.is_empty() {
                println!("NEW PERMISSIONS (in {snapshot_b}, not in {snapshot_a}):");
                for p in &diff.added {
                    println!("  [+] {:<6} {:<40} {}", p.effect, p.action, p.resource);
                }
                println!();
            }

            if !diff.removed.is_empty() {
                println!("REMOVED PERMISSIONS (in {snapshot_a}, not in {snapshot_b}):");
                for p in &diff.removed {
                    println!("  [-] {:<6} {:<40} {}", p.effect, p.action, p.resource);
                }
            }
        }

        ref cmd => {
            let account_id = require_account_id(args.account_id.as_deref())?;
            let snapshot_id =
                resolve_snapshot_id(args.snapshot_id.as_deref(), &client, account_id).await?;
            let ctx = QueryContext::new(snapshot_id.clone(), account_id);

            // Warn if the queried snapshot is marked partial so analysts know results may
            // be incomplete before reading them.
            if let Ok(snaps) = list_snapshots(client.inner(), account_id).await {
                if let Some(snap) = snaps.iter().find(|s| s.id == snapshot_id) {
                    if snap.is_partial {
                        let detail = if snap.partial_reasons.is_empty() {
                            String::new()
                        } else {
                            format!(" ({})", snap.partial_reasons.join(", "))
                        };
                        eprintln!(
                            "[!] snapshot is PARTIAL{} — results may understate access",
                            detail
                        );
                    }
                }
            }

            match cmd {
                QueryCommand::WhoCan { action, resource } => {
                    let results = who_can(client.inner(), &ctx, action, resource.as_deref())
                        .await
                        .context("who-can query failed")?;

                    if args.output == OutputFormat::Json {
                        return json::print_json(&results);
                    }

                    println!(
                        "Entities with permission {} (snapshot: {})\n",
                        action,
                        short_id(&snapshot_id)
                    );

                    if results.is_empty() {
                        println!("No entities found with that permission.");
                        return Ok(());
                    }

                    let rows: Vec<Vec<String>> = results
                        .iter()
                        .map(|e| {
                            let type_label = if e.is_full_admin {
                                format!("{} [full-admin]", e.entity_type)
                            } else {
                                e.entity_type.clone()
                            };
                            vec![type_label, e.arn.clone(), e.resource.clone()]
                        })
                        .collect();
                    print!(
                        "{}",
                        table::format_table(&["TYPE", "ARN", "RESOURCE"], &rows)
                    );
                }

                QueryCommand::EntityPerms { arn } => {
                    let uid = format!("{}|{}", snapshot_id, arn);
                    let perms = entity_permissions(client.inner(), &ctx, &uid)
                        .await
                        .context("entity-perms query failed")?;

                    if args.output == OutputFormat::Json {
                        return json::print_json(&perms);
                    }

                    println!("Permissions for {arn}\n");

                    if perms.is_empty() {
                        println!("No permissions found.");
                        return Ok(());
                    }

                    let rows: Vec<Vec<String>> = perms
                        .iter()
                        .map(|p: &PermissionRow| {
                            vec![p.effect.clone(), p.action.clone(), p.resource.clone()]
                        })
                        .collect();
                    print!(
                        "{}",
                        table::format_table(&["EFFECT", "ACTION", "RESOURCE"], &rows)
                    );
                }

                QueryCommand::InstanceProfilesWith { action } => {
                    let results = instance_profiles_with_action(client.inner(), &ctx, action)
                        .await
                        .context("instance-profiles-with query failed")?;

                    if args.output == OutputFormat::Json {
                        return json::print_json(&results);
                    }

                    println!(
                        "Instance profiles granting {} (snapshot: {})\n",
                        action,
                        short_id(&snapshot_id)
                    );

                    if results.is_empty() {
                        println!("No instance profiles found with that permission.");
                        return Ok(());
                    }

                    let rows: Vec<Vec<String>> = results
                        .iter()
                        .map(|e| vec![e.name.clone(), e.arn.clone()])
                        .collect();
                    print!("{}", table::format_table(&["NAME", "ARN"], &rows));
                }

                QueryCommand::PrivilegeEscalation { max_hops } => {
                    let max_hops = *max_hops;
                    let paths = privilege_escalation_paths(client.inner(), &ctx, max_hops)
                        .await
                        .context("privilege-escalation query failed")?;

                    if args.output == OutputFormat::Json {
                        return json::print_json(&paths);
                    }

                    println!(
                        "Privilege escalation paths (snapshot: {}, max-hops: {})\n",
                        short_id(&snapshot_id),
                        max_hops
                    );

                    if paths.is_empty() {
                        println!("No privilege escalation paths found.");
                        return Ok(());
                    }

                    let rows: Vec<Vec<String>> = paths
                        .iter()
                        .map(|p| {
                            let path_str = p
                                .path
                                .iter()
                                .map(|h| h.arn.as_str())
                                .collect::<Vec<_>>()
                                .join(" -> ");
                            vec![
                                p.arn.clone(),
                                path_str,
                                p.risky_actions.join(", "),
                                if p.conditional { "yes" } else { "no" }.to_string(),
                            ]
                        })
                        .collect();
                    print!(
                        "{}",
                        table::format_table(
                            &["ENTITY", "PATH", "RISKY ACTIONS", "CONDITIONAL"],
                            &rows
                        )
                    );
                }

                _ => unreachable!(),
            }
        }
    }

    Ok(())
}

fn require_account_id(account_id: Option<&str>) -> anyhow::Result<&str> {
    account_id.ok_or_else(|| anyhow::anyhow!("--account-id is required for this subcommand"))
}

async fn resolve_snapshot_id(
    snapshot_id: Option<&str>,
    client: &GraphClient,
    account_id: &str,
) -> anyhow::Result<String> {
    if let Some(id) = snapshot_id {
        return Ok(id.to_owned());
    }

    let snapshots = list_snapshots(client.inner(), account_id)
        .await
        .context("failed to list snapshots while resolving latest")?;

    snapshots.into_iter().next().map(|s| s.id).ok_or_else(|| {
        anyhow::anyhow!(
            "no snapshots found for account {account_id}.\n\
                 Run first: aws-iam-grapher collect --account-alias my-account"
        )
    })
}

fn short_id(id: &str) -> &str {
    &id[..8.min(id.len())]
}
