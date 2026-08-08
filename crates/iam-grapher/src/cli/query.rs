use crate::output::{graphviz, json, table, table::RenderSpec, OutputFormat};
use anyhow::Context as _;
use clap::{Args, Subcommand};
use iam_graph::{
    delete_snapshot, diff_permissions, entity_permissions, instance_profiles_with_action,
    list_account_ids, list_accounts, list_snapshots, org_escalation_paths,
    privilege_escalation_paths, resolve_org_context, resolve_scopes, snapshot_account_id, who_can,
    EntityRef, EscalationPath, GraphClient, GraphError, PermissionRow, QueryContext, ResolvedScope,
    ScopeSelector, SnapshotRecord, DEFAULT_MAX_HOPS,
};
use iam_models::condition::ConditionContext;
use serde::Serialize;
use std::collections::HashMap;
use std::future::Future;
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

fn who_can_rows(results: &[EntityRef]) -> RenderSpec {
    let rows = results
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
        .collect();
    RenderSpec {
        headers: &["TYPE", "ARN", "RESOURCE"],
        rows,
    }
}

fn entity_perm_rows(perms: &[PermissionRow]) -> RenderSpec {
    let rows = perms
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
        .collect();
    RenderSpec {
        headers: &["EFFECT", "ACTION", "RESOURCE", "STATUS"],
        rows,
    }
}

fn instance_profile_rows(results: &[EntityRef]) -> RenderSpec {
    let rows = results
        .iter()
        .map(|e| vec![e.name.clone(), e.arn.clone()])
        .collect();
    RenderSpec {
        headers: &["NAME", "ARN"],
        rows,
    }
}

fn escalation_rows(paths: &[EscalationPath]) -> RenderSpec {
    let rows = paths
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
    RenderSpec {
        headers: &["ENTITY", "PATH", "RISKY ACTIONS", "CONDITIONAL"],
        rows,
    }
}

/// Resolve the accounts a fan-out (`ref cmd` with no `--account-id`) should target:
/// every distinct account_id with at least one snapshot in the graph.
async fn resolve_all_account_ids(client: &GraphClient) -> anyhow::Result<Vec<String>> {
    let accounts = list_account_ids(client.inner())
        .await
        .context("failed to list accounts")?;
    if accounts.is_empty() {
        return Err(GraphError::no_snapshots().into());
    }
    Ok(accounts)
}

/// Resolve the scope(s) a `WhoCan`/`EntityPerms`/`InstanceProfilesWith`/`PrivilegeEscalation`
/// invocation should run over, from `--account-id`/`--snapshot-id`. The returned `Vec` has
/// exactly one scope whenever `account_id` is `Some`; the caller (not scope count) decides
/// single-vs-fan-out rendering — see `run_scoped`.
async fn resolve_command_scopes(
    client: &GraphClient,
    account_id: Option<&str>,
    snapshot_id: Option<&str>,
) -> anyhow::Result<Vec<ResolvedScope>> {
    let selector = match account_id {
        Some(account_id) => match snapshot_id.map(str::to_owned) {
            Some(snapshot_id) => ScopeSelector::snapshot(snapshot_id, Some(account_id.to_owned())),
            None => ScopeSelector::account(account_id),
        },
        None => match snapshot_id.map(str::to_owned) {
            Some(snapshot_id) => {
                let accounts = resolve_all_account_ids(client).await?;
                if accounts.len() > 1 {
                    anyhow::bail!(
                        "--snapshot-id cannot be combined with multi-account mode \
                         (no --account-id, {} accounts found); pass --account-id to \
                         target a single account",
                        accounts.len()
                    );
                }
                ScopeSelector::snapshot(snapshot_id, None)
            }
            None => ScopeSelector::all_accounts(),
        },
    };
    let scopes = resolve_scopes(client.inner(), selector).await?;
    Ok(scopes)
}

/// Print a partial-snapshot warning if the given (already-resolved) snapshot is marked
/// partial. Takes the record straight from `ResolvedScope` — no DB access here, since
/// `resolve_scopes` already fetched `is_partial`/`partial_reasons` while resolving the scope.
fn print_partial_warning(snapshot: &SnapshotRecord) {
    if snapshot.is_partial {
        let detail = if snapshot.partial_reasons.is_empty() {
            String::new()
        } else {
            format!(" ({})", snapshot.partial_reasons.join(", "))
        };
        eprintln!(
            "[!] snapshot is PARTIAL{} — results may understate access",
            detail
        );
    }
}

/// Whether a scoped query ran against one account (carrying its snapshot id, for the
/// single-account heading) or fanned out across several (carrying the account count).
enum ScopeCount<'a> {
    Single(&'a str),
    Multi(usize),
}

/// Output routing plus single-vs-fan-out mode for a `run_scoped` call, bundled so the
/// driver stays under clippy's argument-count lint.
struct ScopedOutput<'a> {
    format: &'a OutputFormat,
    file: Option<&'a Path>,
    /// `--account-id`/explicit-single-snapshot mode (`true`), not `scopes.len() == 1` —
    /// the `--account-id`-omitted path always wraps in `AccountGroup` and prints an
    /// account header, even for a one-account graph. Mirrors base behavior.
    single: bool,
}

/// Renders a query result as Graphviz DOT text, given (result, suggested graph name).
type ToDot<'a, T> = &'a dyn Fn(&T, &str) -> String;

/// Run a query over one or more resolved scopes and render the result uniformly.
///
/// `to_dot`, when present, renders a scope's result as Graphviz DOT text. Pass `None`
/// for queries with no graph-shaped result — `--output graphviz` is rejected up front
/// in `run()` for those, so this is never called with `out.format == Graphviz` and
/// `to_dot: None` at once.
#[allow(clippy::too_many_arguments)]
async fn run_scoped<T, F, Fut>(
    out: ScopedOutput<'_>,
    scopes: Vec<ResolvedScope>,
    query: F,
    render: impl Fn(&T) -> RenderSpec,
    to_dot: Option<ToDot<'_, T>>,
    heading: impl Fn(ScopeCount) -> String,
    empty_msg: &str,
) -> anyhow::Result<()>
where
    T: Serialize,
    F: Fn(QueryContext) -> Fut,
    Fut: Future<Output = anyhow::Result<T>>,
{
    if *out.format == OutputFormat::Graphviz {
        let to_dot = to_dot
            .ok_or_else(|| anyhow::anyhow!("--output graphviz is not supported for this query"))?;
        return run_scoped_graphviz(out, scopes, query, to_dot).await;
    }

    if out.single {
        let [ResolvedScope { context, snapshot }] = <[ResolvedScope; 1]>::try_from(scopes)
            .map_err(|scopes| {
                anyhow::anyhow!(
                    "single-account mode resolved {} scopes, expected exactly 1",
                    scopes.len()
                )
            })?;
        print_partial_warning(&snapshot);
        let result = query(context.clone()).await?;

        if !emit_json(&result, out.format, out.file)? {
            return Ok(());
        }

        println!("{}\n", heading(ScopeCount::Single(&context.snapshot_id)));

        let spec = render(&result);
        if spec.rows.is_empty() {
            println!("{empty_msg}");
            return Ok(());
        }
        print!("{}", table::format_table(spec.headers, &spec.rows));
        return Ok(());
    }

    let mut groups = Vec::with_capacity(scopes.len());
    for scope in &scopes {
        print_partial_warning(&scope.snapshot);
        let results = query(scope.context.clone()).await?;
        groups.push(AccountGroup {
            account_id: scope.context.account_id.clone(),
            snapshot_id: scope.context.snapshot_id.clone(),
            results,
        });
    }

    if !emit_json(&groups, out.format, out.file)? {
        return Ok(());
    }

    println!("{}\n", heading(ScopeCount::Multi(groups.len())));
    for g in &groups {
        print_account_header(&g.account_id, &g.snapshot_id);
        let spec = render(&g.results);
        if spec.rows.is_empty() {
            println!("{empty_msg}\n");
            continue;
        }
        println!("{}", table::format_table(spec.headers, &spec.rows));
    }
    Ok(())
}

/// Graphviz counterpart to the tail of `run_scoped`: single-account mode emits one
/// digraph; multi-account mode concatenates one digraph per account (each with a
/// distinct graph name embedding the account id) into a single `.dot` file/stream —
/// valid Graphviz input, since the DOT grammar allows a file to contain a list of graphs.
async fn run_scoped_graphviz<T, F, Fut>(
    out: ScopedOutput<'_>,
    scopes: Vec<ResolvedScope>,
    query: F,
    to_dot: ToDot<'_, T>,
) -> anyhow::Result<()>
where
    F: Fn(QueryContext) -> Fut,
    Fut: Future<Output = anyhow::Result<T>>,
{
    let mut dot = String::new();

    if out.single {
        let [ResolvedScope { context, snapshot }] = <[ResolvedScope; 1]>::try_from(scopes)
            .map_err(|scopes| {
                anyhow::anyhow!(
                    "single-account mode resolved {} scopes, expected exactly 1",
                    scopes.len()
                )
            })?;
        print_partial_warning(&snapshot);
        let result = query(context).await?;
        dot.push_str(&to_dot(&result, "query_result"));
    } else {
        for scope in &scopes {
            print_partial_warning(&scope.snapshot);
            let result = query(scope.context.clone()).await?;
            let graph_name = format!("account_{}", scope.context.account_id);
            dot.push_str(&to_dot(&result, &graph_name));
        }
    }

    match out.file {
        Some(path) => {
            std::fs::write(path, &dot).with_context(|| {
                format!("failed to write graphviz output to {}", path.display())
            })?;
        }
        None => print!("{dot}"),
    }
    Ok(())
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
    if args.output == OutputFormat::Graphviz
        && !matches!(
            args.command,
            QueryCommand::WhoCan { .. }
                | QueryCommand::PrivilegeEscalation { .. }
                | QueryCommand::OrgEscalation { .. }
        )
    {
        anyhow::bail!(
            "--output graphviz is not supported for this query; supported queries: \
             who-can, privilege-escalation, org-escalation"
        );
    }

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
            let ctx = resolve_org_context(client.inner(), org_run_id).await?;
            let run_id = ctx.org_run_id.clone();
            let paths = org_escalation_paths(client.inner(), &ctx, max_hops)
                .await
                .context("org-escalation query failed")?;

            if args.output == OutputFormat::Graphviz {
                let dot = graphviz::org_escalation_paths_to_dot("org_escalation", &paths);
                match args.output_file.as_deref() {
                    Some(path) => std::fs::write(path, &dot).with_context(|| {
                        format!("failed to write graphviz output to {}", path.display())
                    })?,
                    None => print!("{dot}"),
                }
                return Ok(());
            }

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

        QueryCommand::WhoCan {
            action,
            resource,
            region,
            mfa,
            principal_tags,
        } => {
            let condition_ctx = parse_condition_context(&region, mfa, &principal_tags)?;
            let scopes = resolve_command_scopes(
                &client,
                args.account_id.as_deref(),
                args.snapshot_id.as_deref(),
            )
            .await?;
            run_scoped(
                ScopedOutput {
                    format: &args.output,
                    file: args.output_file.as_deref(),
                    single: args.account_id.is_some(),
                },
                scopes,
                |ctx| {
                    let condition_ctx = condition_ctx.clone();
                    let resource = resource.clone();
                    let action = action.clone();
                    let client = &client;
                    async move {
                        who_can(
                            client.inner(),
                            &ctx,
                            &action,
                            resource.as_deref(),
                            &condition_ctx,
                        )
                        .await
                        .context("who-can query failed")
                    }
                },
                |results: &Vec<EntityRef>| who_can_rows(results),
                Some(&|results: &Vec<EntityRef>, graph_name: &str| {
                    graphviz::who_can_to_dot(graph_name, &action, results)
                }),
                |sc| match sc {
                    ScopeCount::Single(snapshot_id) => format!(
                        "Entities with permission {} (snapshot: {})",
                        action,
                        short_id(snapshot_id)
                    ),
                    ScopeCount::Multi(n) => {
                        format!("Entities with permission {action} (across {n} account(s))")
                    }
                },
                "No entities found with that permission.",
            )
            .await?;
        }

        QueryCommand::EntityPerms { arn } => {
            let scopes = resolve_command_scopes(
                &client,
                args.account_id.as_deref(),
                args.snapshot_id.as_deref(),
            )
            .await?;
            run_scoped(
                ScopedOutput {
                    format: &args.output,
                    file: args.output_file.as_deref(),
                    single: args.account_id.is_some(),
                },
                scopes,
                |ctx| {
                    let arn = arn.clone();
                    let client = &client;
                    async move {
                        let uid = format!("{}|{}", ctx.snapshot_id, arn);
                        entity_permissions(client.inner(), &ctx, &uid)
                            .await
                            .context("entity-perms query failed")
                    }
                },
                |perms: &Vec<PermissionRow>| entity_perm_rows(perms),
                None,
                |sc| match sc {
                    ScopeCount::Single(_) => format!("Permissions for {arn}"),
                    ScopeCount::Multi(n) => {
                        format!("Permissions for {arn} (across {n} account(s))")
                    }
                },
                "No permissions found.",
            )
            .await?;
        }

        QueryCommand::InstanceProfilesWith { action } => {
            let scopes = resolve_command_scopes(
                &client,
                args.account_id.as_deref(),
                args.snapshot_id.as_deref(),
            )
            .await?;
            run_scoped(
                ScopedOutput {
                    format: &args.output,
                    file: args.output_file.as_deref(),
                    single: args.account_id.is_some(),
                },
                scopes,
                |ctx| {
                    let action = action.clone();
                    let client = &client;
                    async move {
                        instance_profiles_with_action(client.inner(), &ctx, &action)
                            .await
                            .context("instance-profiles-with query failed")
                    }
                },
                |results: &Vec<EntityRef>| instance_profile_rows(results),
                None,
                |sc| match sc {
                    ScopeCount::Single(snapshot_id) => format!(
                        "Instance profiles granting {} (snapshot: {})",
                        action,
                        short_id(snapshot_id)
                    ),
                    ScopeCount::Multi(n) => {
                        format!("Instance profiles granting {action} (across {n} account(s))")
                    }
                },
                "No instance profiles found with that permission.",
            )
            .await?;
        }

        QueryCommand::PrivilegeEscalation { max_hops } => {
            let scopes = resolve_command_scopes(
                &client,
                args.account_id.as_deref(),
                args.snapshot_id.as_deref(),
            )
            .await?;
            run_scoped(
                ScopedOutput {
                    format: &args.output,
                    file: args.output_file.as_deref(),
                    single: args.account_id.is_some(),
                },
                scopes,
                |ctx| {
                    let client = &client;
                    async move {
                        privilege_escalation_paths(client.inner(), &ctx, max_hops)
                            .await
                            .context("privilege-escalation query failed")
                    }
                },
                |paths: &Vec<EscalationPath>| escalation_rows(paths),
                Some(&|paths: &Vec<EscalationPath>, graph_name: &str| {
                    graphviz::escalation_paths_to_dot(graph_name, paths)
                }),
                |sc| match sc {
                    ScopeCount::Single(snapshot_id) => format!(
                        "Privilege escalation paths (snapshot: {}, max-hops: {})",
                        short_id(snapshot_id),
                        max_hops
                    ),
                    ScopeCount::Multi(n) => format!(
                        "Privilege escalation paths (max-hops: {max_hops}, across {n} account(s))"
                    ),
                },
                "No privilege escalation paths found.",
            )
            .await?;
        }
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
        .ok_or_else(|| GraphError::snapshot_not_found(snapshot_a))?;
    let account_b = snapshot_account_id(client.inner(), snapshot_b)
        .await?
        .ok_or_else(|| GraphError::snapshot_not_found(snapshot_b))?;

    if account_a != account_b {
        anyhow::bail!(
            "snapshot {snapshot_a} belongs to account {account_a} but snapshot {snapshot_b} \
             belongs to account {account_b}; diff requires both snapshots in the same account"
        );
    }
    Ok(account_a)
}

fn short_id(id: &str) -> &str {
    &id[..8.min(id.len())]
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    fn scope(account_id: &str, snapshot_id: &str) -> ResolvedScope {
        ResolvedScope {
            context: QueryContext::new(snapshot_id, account_id),
            snapshot: SnapshotRecord {
                id: snapshot_id.to_string(),
                account_id: account_id.to_string(),
                collected_at: String::new(),
                is_partial: false,
                partial_reasons: Vec::new(),
                org_collection_run_id: None,
            },
        }
    }

    // Signature must be `&String`, not `&str`: it's used as `render: impl Fn(&T)` with
    // `T = String` (the query closures below return `anyhow::Result<String>`).
    #[allow(clippy::ptr_arg)]
    fn render_str(s: &String) -> RenderSpec {
        RenderSpec {
            headers: &["X"],
            rows: vec![vec![s.clone()]],
        }
    }

    #[tokio::test]
    async fn run_scoped_multi_mode_wraps_result_even_for_one_scope() {
        let scopes = vec![scope("111111111111", "snap-a")];
        let calls = RefCell::new(Vec::new());
        let out = ScopedOutput {
            format: &OutputFormat::Table,
            file: None,
            single: false,
        };

        run_scoped(
            out,
            scopes,
            |ctx: QueryContext| async move { Ok(ctx.account_id) },
            render_str,
            None,
            |sc| {
                calls.borrow_mut().push(match sc {
                    ScopeCount::Single(_) => "single".to_string(),
                    ScopeCount::Multi(n) => format!("multi:{n}"),
                });
                String::new()
            },
            "empty",
        )
        .await
        .unwrap();

        // --account-id omitted always fans out through AccountGroup, even when only
        // one account resolved — matches base behavior; must not key off scopes.len().
        assert_eq!(calls.into_inner(), ["multi:1"]);
    }

    #[tokio::test]
    async fn run_scoped_single_mode_unwraps_the_lone_scope() {
        let scopes = vec![scope("111111111111", "snap-a")];
        let calls = RefCell::new(Vec::new());
        let out = ScopedOutput {
            format: &OutputFormat::Table,
            file: None,
            single: true,
        };

        run_scoped(
            out,
            scopes,
            |ctx: QueryContext| async move { Ok(ctx.account_id) },
            render_str,
            None,
            |sc| {
                calls.borrow_mut().push(match sc {
                    ScopeCount::Single(id) => format!("single:{id}"),
                    ScopeCount::Multi(n) => format!("multi:{n}"),
                });
                String::new()
            },
            "empty",
        )
        .await
        .unwrap();

        assert_eq!(calls.into_inner(), ["single:snap-a"]);
    }

    #[tokio::test]
    async fn run_scoped_single_mode_errors_on_unexpected_scope_count() {
        let scopes = vec![scope("111111111111", "a"), scope("222222222222", "b")];
        let out = ScopedOutput {
            format: &OutputFormat::Table,
            file: None,
            single: true,
        };

        let result = run_scoped(
            out,
            scopes,
            |ctx: QueryContext| async move { Ok(ctx.account_id) },
            render_str,
            None,
            |_sc| String::new(),
            "empty",
        )
        .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn run_scoped_graphviz_single_mode_renders_to_dot_output() {
        let scopes = vec![scope("111111111111", "snap-a")];
        let out = ScopedOutput {
            format: &OutputFormat::Graphviz,
            file: None,
            single: true,
        };

        let result = run_scoped(
            out,
            scopes,
            |ctx: QueryContext| async move { Ok(ctx.account_id) },
            render_str,
            Some(&|s: &String, graph_name: &str| format!("digraph {graph_name} {{ {s} }}")),
            |_sc| String::new(),
            "empty",
        )
        .await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn run_scoped_graphviz_without_to_dot_errors() {
        let scopes = vec![scope("111111111111", "snap-a")];
        let out = ScopedOutput {
            format: &OutputFormat::Graphviz,
            file: None,
            single: true,
        };

        let result = run_scoped(
            out,
            scopes,
            |ctx: QueryContext| async move { Ok(ctx.account_id) },
            render_str,
            None,
            |_sc| String::new(),
            "empty",
        )
        .await;

        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("not supported for this query"));
    }
}
