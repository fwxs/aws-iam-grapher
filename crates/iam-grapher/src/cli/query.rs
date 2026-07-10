use crate::output::{json, table, OutputFormat};
use anyhow::Context as _;
use clap::{Args, Subcommand};
use iam_graph::{
    delete_snapshot, diff_permissions, entity_permissions, instance_profiles_with_action,
    latest_org_run_id, list_account_ids, list_accounts, list_snapshots, org_escalation_paths,
    privilege_escalation_paths, snapshot_account_id, who_can, EntityRef, EscalationPath,
    GraphClient, OrgQueryContext, PermissionRow, QueryContext, DEFAULT_MAX_HOPS,
};
use iam_models::condition::ConditionContext;
use serde::Serialize;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

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

    /// AWS account ID to query. If omitted, the query runs once per account that has a
    /// snapshot in the graph, each scoped to its own (account_id, snapshot_id).
    #[arg(long)]
    account_id: Option<String>,

    /// Snapshot ID to query (default: most recent for the account). Cannot be combined
    /// with multi-account mode (--account-id omitted and more than one account found).
    #[arg(long)]
    snapshot_id: Option<String>,

    /// Output format.
    #[arg(long, value_enum, default_value = "table")]
    output: OutputFormat,

    /// Write JSON result to this file. Overrides --output to JSON for the file;
    /// the human-readable table/summary still prints to stdout.
    #[arg(long)]
    output_file: Option<PathBuf>,

    #[command(subcommand)]
    command: QueryCommand,
}

/// Emit JSON to `output_file` and/or stdout per `output`/`output_file` settings.
/// Returns `true` if the human-readable view should still be printed to stdout.
fn emit_json<T: Serialize>(
    value: &T,
    output: &OutputFormat,
    output_file: Option<&Path>,
) -> anyhow::Result<bool> {
    if let Some(path) = output_file {
        json::write_json(value, path)?;
        return Ok(true);
    }
    if *output == OutputFormat::Json {
        json::print_json(value)?;
        return Ok(false);
    }
    Ok(true)
}

/// One account's results within a multi-account (`--account-id` omitted) fan-out.
#[derive(Serialize)]
struct AccountGroup<T: Serialize> {
    account_id: String,
    snapshot_id: String,
    results: T,
}

fn print_account_header(account_id: &str, snapshot_id: &str) {
    println!(
        "=== Account: {} (snapshot: {}) ===",
        account_id,
        short_id(snapshot_id)
    );
}

fn who_can_rows(results: &[EntityRef]) -> Vec<Vec<String>> {
    results
        .iter()
        .map(|e| {
            let mut type_label = e.entity_type.clone();
            if e.is_full_admin {
                type_label.push_str(" [full-admin]");
            }
            if e.is_bounded {
                type_label.push_str(" [bounded]");
            }
            if e.conditional {
                type_label.push_str(&format!(
                    " [conditional: {}]",
                    e.unevaluated_condition_keys.join(", ")
                ));
            }
            vec![type_label, e.arn.clone(), e.resource.clone()]
        })
        .collect()
}

fn entity_perm_rows(perms: &[PermissionRow]) -> Vec<Vec<String>> {
    perms
        .iter()
        .map(|p| {
            let status = if p.effective {
                "effective"
            } else {
                "capped-by-boundary"
            };
            vec![
                p.effect.clone(),
                p.action.clone(),
                p.resource.clone(),
                status.to_string(),
            ]
        })
        .collect()
}

fn instance_profile_rows(results: &[EntityRef]) -> Vec<Vec<String>> {
    results
        .iter()
        .map(|e| vec![e.name.clone(), e.arn.clone()])
        .collect()
}

fn escalation_rows(paths: &[EscalationPath]) -> Vec<Vec<String>> {
    paths
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
        .collect()
}

/// Resolve the accounts a fan-out (`ref cmd` with no `--account-id`) should target:
/// every distinct account_id with at least one snapshot in the graph.
async fn resolve_all_account_ids(client: &GraphClient) -> anyhow::Result<Vec<String>> {
    let accounts = list_account_ids(client.inner())
        .await
        .context("failed to list accounts")?;
    if accounts.is_empty() {
        anyhow::bail!(
            "no snapshots found in the graph.\n\
             Run first: aws-iam-grapher collect --account-alias my-account"
        );
    }
    Ok(accounts)
}

/// Print a partial-snapshot warning if the given snapshot is marked partial.
async fn warn_if_partial(client: &GraphClient, account_id: &str, snapshot_id: &str) {
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
        /// Evaluate `aws:RequestedRegion` conditions against this region.
        #[arg(long)]
        region: Option<String>,
        /// Evaluate `aws:MultiFactorAuthPresent` conditions against this value.
        #[arg(long)]
        mfa: Option<bool>,
        /// Evaluate `aws:PrincipalTag/<key>` conditions against `key=value` (repeatable).
        #[arg(long = "principal-tag")]
        principal_tags: Vec<String>,
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
    /// List every account in the graph, with its OU id/name if collected via `collect org`.
    /// Cross-account by design — never requires `--account-id`.
    ListAccounts,
    /// Compare permissions between two snapshots.
    Diff {
        snapshot_a: String,
        snapshot_b: String,
    },
    /// Delete a snapshot and all its nodes from the graph.
    DeleteSnapshot { snapshot_id: String },
    /// Cross-account privilege-escalation paths across an org collection run.
    OrgEscalation {
        /// Max sts:AssumeRole hops to traverse.
        #[arg(long, default_value_t = DEFAULT_MAX_HOPS)]
        max_hops: u32,
        /// Org collection run id (default: most recent org run).
        #[arg(long)]
        org_run_id: Option<String>,
    },
}

pub async fn run(args: QueryArgs) -> anyhow::Result<()> {
    let client = GraphClient::connect(&args.neo4j_uri, &args.neo4j_user, &args.neo4j_pass)
        .await
        .with_context(|| format!("failed to connect to Neo4j at {}", args.neo4j_uri))?;

    match args.command {
        QueryCommand::ListSnapshots => {
            let snapshots = match args.account_id.as_deref() {
                Some(account_id) => list_snapshots(client.inner(), account_id)
                    .await
                    .context("list-snapshots query failed")?,
                None => {
                    let accounts = resolve_all_account_ids(&client).await?;
                    let mut all = Vec::new();
                    for account_id in &accounts {
                        all.extend(
                            list_snapshots(client.inner(), account_id)
                                .await
                                .context("list-snapshots query failed")?,
                        );
                    }
                    all
                }
            };

            if !emit_json(&snapshots, &args.output, args.output_file.as_deref())? {
                return Ok(());
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

        QueryCommand::ListAccounts => {
            let accounts = list_accounts(client.inner())
                .await
                .context("list-accounts query failed")?;

            if !emit_json(&accounts, &args.output, args.output_file.as_deref())? {
                return Ok(());
            }

            let rows: Vec<Vec<String>> = accounts
                .iter()
                .map(|a| {
                    vec![
                        a.id.clone(),
                        a.alias.clone().unwrap_or_default(),
                        a.ou_id.clone().unwrap_or_default(),
                        a.ou_name.clone().unwrap_or_default(),
                    ]
                })
                .collect();
            print!(
                "{}",
                table::format_table(&["ACCOUNT ID", "ALIAS", "OU ID", "OU NAME"], &rows)
            );
        }

        QueryCommand::DeleteSnapshot { snapshot_id } => {
            let deleted = delete_snapshot(client.inner(), &snapshot_id)
                .await
                .context("delete-snapshot failed")?;
            println!("Deleted {deleted} nodes for snapshot {snapshot_id}");
        }

        QueryCommand::OrgEscalation {
            max_hops,
            org_run_id,
        } => {
            let run_id = match org_run_id {
                Some(id) => id,
                None => latest_org_run_id(client.inner())
                    .await
                    .context("failed to look up latest org run")?
                    .ok_or_else(|| {
                        anyhow::anyhow!(
                            "no org collection runs found.\n\
                             Run first: aws-iam-grapher collect org ..."
                        )
                    })?,
            };
            let ctx = OrgQueryContext::new(&run_id);
            let paths = org_escalation_paths(client.inner(), &ctx, max_hops)
                .await
                .context("org-escalation query failed")?;

            if !emit_json(&paths, &args.output, args.output_file.as_deref())? {
                return Ok(());
            }

            println!(
                "Cross-account escalation paths (org-run: {}, max-hops: {})\n",
                short_id(&run_id),
                max_hops
            );

            if paths.is_empty() {
                println!("No cross-account escalation paths found.");
                return Ok(());
            }

            let rows: Vec<Vec<String>> = paths
                .iter()
                .map(|ep| {
                    let path_str = ep
                        .path
                        .iter()
                        .map(|h| format!("{}@{}", h.arn, short_id(&h.account_id)))
                        .collect::<Vec<_>>()
                        .join(" -> ");
                    vec![
                        ep.arn.clone(),
                        ep.account_id.clone(),
                        path_str,
                        ep.risky_actions.join(", "),
                        if ep.conditional { "yes" } else { "no" }.to_string(),
                    ]
                })
                .collect();
            print!(
                "{}",
                table::format_table(
                    &["ENTITY", "ACCOUNT", "PATH", "RISKY ACTIONS", "CONDITIONAL"],
                    &rows
                )
            );
        }

        QueryCommand::Diff {
            ref snapshot_a,
            ref snapshot_b,
        } => {
            let resolved_account_id;
            let account_id = match args.account_id.as_deref() {
                Some(id) => id,
                None => {
                    resolved_account_id = resolve_diff_account_id(&client, snapshot_a, snapshot_b)
                        .await
                        .context("failed to resolve account for diff")?;
                    &resolved_account_id
                }
            };
            let diff = diff_permissions(client.inner(), account_id, snapshot_a, snapshot_b)
                .await
                .context("diff query failed")?;

            if !emit_json(&diff, &args.output, args.output_file.as_deref())? {
                return Ok(());
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

        ref cmd => match args.account_id.as_deref() {
            Some(account_id) => {
                let snapshot_id =
                    resolve_snapshot_id(args.snapshot_id.as_deref(), &client, account_id).await?;
                let ctx = QueryContext::new(snapshot_id.clone(), account_id);
                warn_if_partial(&client, account_id, &snapshot_id).await;

                match cmd {
                    QueryCommand::WhoCan {
                        action,
                        resource,
                        region,
                        mfa,
                        principal_tags,
                    } => {
                        let condition_ctx = parse_condition_context(region, *mfa, principal_tags)?;
                        let results = who_can(
                            client.inner(),
                            &ctx,
                            action,
                            resource.as_deref(),
                            &condition_ctx,
                        )
                        .await
                        .context("who-can query failed")?;

                        if !emit_json(&results, &args.output, args.output_file.as_deref())? {
                            return Ok(());
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

                        print!(
                            "{}",
                            table::format_table(
                                &["TYPE", "ARN", "RESOURCE"],
                                &who_can_rows(&results)
                            )
                        );
                    }

                    QueryCommand::EntityPerms { arn } => {
                        let uid = format!("{}|{}", snapshot_id, arn);
                        let perms = entity_permissions(client.inner(), &ctx, &uid)
                            .await
                            .context("entity-perms query failed")?;

                        if !emit_json(&perms, &args.output, args.output_file.as_deref())? {
                            return Ok(());
                        }

                        println!("Permissions for {arn}\n");

                        if perms.is_empty() {
                            println!("No permissions found.");
                            return Ok(());
                        }

                        print!(
                            "{}",
                            table::format_table(
                                &["EFFECT", "ACTION", "RESOURCE", "STATUS"],
                                &entity_perm_rows(&perms)
                            )
                        );
                    }

                    QueryCommand::InstanceProfilesWith { action } => {
                        let results = instance_profiles_with_action(client.inner(), &ctx, action)
                            .await
                            .context("instance-profiles-with query failed")?;

                        if !emit_json(&results, &args.output, args.output_file.as_deref())? {
                            return Ok(());
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

                        print!(
                            "{}",
                            table::format_table(&["NAME", "ARN"], &instance_profile_rows(&results))
                        );
                    }

                    QueryCommand::PrivilegeEscalation { max_hops } => {
                        let max_hops = *max_hops;
                        let paths = privilege_escalation_paths(client.inner(), &ctx, max_hops)
                            .await
                            .context("privilege-escalation query failed")?;

                        if !emit_json(&paths, &args.output, args.output_file.as_deref())? {
                            return Ok(());
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

                        print!(
                            "{}",
                            table::format_table(
                                &["ENTITY", "PATH", "RISKY ACTIONS", "CONDITIONAL"],
                                &escalation_rows(&paths)
                            )
                        );
                    }

                    _ => unreachable!(),
                }
            }

            None => {
                let accounts = resolve_all_account_ids(&client).await?;
                if accounts.len() > 1 && args.snapshot_id.is_some() {
                    anyhow::bail!(
                        "--snapshot-id cannot be combined with multi-account mode \
                         (no --account-id, {} accounts found); pass --account-id to \
                         target a single account",
                        accounts.len()
                    );
                }

                match cmd {
                    QueryCommand::WhoCan {
                        action,
                        resource,
                        region,
                        mfa,
                        principal_tags,
                    } => {
                        let condition_ctx = parse_condition_context(region, *mfa, principal_tags)?;
                        let mut groups = Vec::with_capacity(accounts.len());
                        for account_id in &accounts {
                            let snapshot_id = resolve_snapshot_id(
                                args.snapshot_id.as_deref(),
                                &client,
                                account_id,
                            )
                            .await?;
                            warn_if_partial(&client, account_id, &snapshot_id).await;
                            let ctx = QueryContext::new(snapshot_id.clone(), account_id.clone());
                            let results = who_can(
                                client.inner(),
                                &ctx,
                                action,
                                resource.as_deref(),
                                &condition_ctx,
                            )
                            .await
                            .context("who-can query failed")?;
                            groups.push(AccountGroup {
                                account_id: account_id.clone(),
                                snapshot_id,
                                results,
                            });
                        }

                        if !emit_json(&groups, &args.output, args.output_file.as_deref())? {
                            return Ok(());
                        }

                        println!(
                            "Entities with permission {} (across {} account(s))\n",
                            action,
                            groups.len()
                        );
                        for g in &groups {
                            print_account_header(&g.account_id, &g.snapshot_id);
                            if g.results.is_empty() {
                                println!("No entities found with that permission.\n");
                                continue;
                            }
                            println!(
                                "{}",
                                table::format_table(
                                    &["TYPE", "ARN", "RESOURCE"],
                                    &who_can_rows(&g.results)
                                )
                            );
                        }
                    }

                    QueryCommand::EntityPerms { arn } => {
                        let mut groups = Vec::with_capacity(accounts.len());
                        for account_id in &accounts {
                            let snapshot_id = resolve_snapshot_id(
                                args.snapshot_id.as_deref(),
                                &client,
                                account_id,
                            )
                            .await?;
                            warn_if_partial(&client, account_id, &snapshot_id).await;
                            let ctx = QueryContext::new(snapshot_id.clone(), account_id.clone());
                            let uid = format!("{}|{}", snapshot_id, arn);
                            let perms = entity_permissions(client.inner(), &ctx, &uid)
                                .await
                                .context("entity-perms query failed")?;
                            groups.push(AccountGroup {
                                account_id: account_id.clone(),
                                snapshot_id,
                                results: perms,
                            });
                        }

                        if !emit_json(&groups, &args.output, args.output_file.as_deref())? {
                            return Ok(());
                        }

                        println!(
                            "Permissions for {} (across {} account(s))\n",
                            arn,
                            groups.len()
                        );
                        for g in &groups {
                            print_account_header(&g.account_id, &g.snapshot_id);
                            if g.results.is_empty() {
                                println!("No permissions found.\n");
                                continue;
                            }
                            println!(
                                "{}",
                                table::format_table(
                                    &["EFFECT", "ACTION", "RESOURCE", "STATUS"],
                                    &entity_perm_rows(&g.results)
                                )
                            );
                        }
                    }

                    QueryCommand::InstanceProfilesWith { action } => {
                        let mut groups = Vec::with_capacity(accounts.len());
                        for account_id in &accounts {
                            let snapshot_id = resolve_snapshot_id(
                                args.snapshot_id.as_deref(),
                                &client,
                                account_id,
                            )
                            .await?;
                            warn_if_partial(&client, account_id, &snapshot_id).await;
                            let ctx = QueryContext::new(snapshot_id.clone(), account_id.clone());
                            let results =
                                instance_profiles_with_action(client.inner(), &ctx, action)
                                    .await
                                    .context("instance-profiles-with query failed")?;
                            groups.push(AccountGroup {
                                account_id: account_id.clone(),
                                snapshot_id,
                                results,
                            });
                        }

                        if !emit_json(&groups, &args.output, args.output_file.as_deref())? {
                            return Ok(());
                        }

                        println!(
                            "Instance profiles granting {} (across {} account(s))\n",
                            action,
                            groups.len()
                        );
                        for g in &groups {
                            print_account_header(&g.account_id, &g.snapshot_id);
                            if g.results.is_empty() {
                                println!("No instance profiles found with that permission.\n");
                                continue;
                            }
                            println!(
                                "{}",
                                table::format_table(
                                    &["NAME", "ARN"],
                                    &instance_profile_rows(&g.results)
                                )
                            );
                        }
                    }

                    QueryCommand::PrivilegeEscalation { max_hops } => {
                        let max_hops = *max_hops;
                        let mut groups = Vec::with_capacity(accounts.len());
                        for account_id in &accounts {
                            let snapshot_id = resolve_snapshot_id(
                                args.snapshot_id.as_deref(),
                                &client,
                                account_id,
                            )
                            .await?;
                            warn_if_partial(&client, account_id, &snapshot_id).await;
                            let ctx = QueryContext::new(snapshot_id.clone(), account_id.clone());
                            let paths = privilege_escalation_paths(client.inner(), &ctx, max_hops)
                                .await
                                .context("privilege-escalation query failed")?;
                            groups.push(AccountGroup {
                                account_id: account_id.clone(),
                                snapshot_id,
                                results: paths,
                            });
                        }

                        if !emit_json(&groups, &args.output, args.output_file.as_deref())? {
                            return Ok(());
                        }

                        println!(
                            "Privilege escalation paths (max-hops: {}, across {} account(s))\n",
                            max_hops,
                            groups.len()
                        );
                        for g in &groups {
                            print_account_header(&g.account_id, &g.snapshot_id);
                            if g.results.is_empty() {
                                println!("No privilege escalation paths found.\n");
                                continue;
                            }
                            println!(
                                "{}",
                                table::format_table(
                                    &["ENTITY", "PATH", "RISKY ACTIONS", "CONDITIONAL"],
                                    &escalation_rows(&g.results)
                                )
                            );
                        }
                    }

                    _ => unreachable!(),
                }
            }
        },
    }

    Ok(())
}

/// Build a [`ConditionContext`] from `--region`/`--mfa`/`--principal-tag` flags.
fn parse_condition_context(
    region: &Option<String>,
    mfa: Option<bool>,
    principal_tags: &[String],
) -> anyhow::Result<ConditionContext> {
    let mut tags = HashMap::new();
    for entry in principal_tags {
        let (key, value) = entry.split_once('=').ok_or_else(|| {
            anyhow::anyhow!("--principal-tag must be in `key=value` form, got `{entry}`")
        })?;
        tags.insert(key.to_string(), value.to_string());
    }
    Ok(ConditionContext {
        region: region.clone(),
        mfa,
        principal_tags: tags,
    })
}

/// Derive the account a `diff` should run in from its two explicit snapshot ids, for use
/// when `--account-id` is omitted. Errors if either snapshot doesn't exist, or if they
/// belong to different accounts (diff only compares snapshots within one account).
async fn resolve_diff_account_id(
    client: &GraphClient,
    snapshot_a: &str,
    snapshot_b: &str,
) -> anyhow::Result<String> {
    let account_a = snapshot_account_id(client.inner(), snapshot_a)
        .await?
        .ok_or_else(|| anyhow::anyhow!("snapshot {snapshot_a} not found"))?;
    let account_b = snapshot_account_id(client.inner(), snapshot_b)
        .await?
        .ok_or_else(|| anyhow::anyhow!("snapshot {snapshot_b} not found"))?;

    if account_a != account_b {
        anyhow::bail!(
            "snapshot {snapshot_a} belongs to account {account_a} but snapshot {snapshot_b} \
             belongs to account {account_b}; diff requires both snapshots in the same account"
        );
    }
    Ok(account_a)
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
