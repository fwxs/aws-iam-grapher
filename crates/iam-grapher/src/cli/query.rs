use crate::exit_code::CliValidationError;
use crate::output::{graphviz, json, table, table::RenderSpec, OutputFormat};
use anyhow::Context as _;
use clap::{Args, Subcommand};
use iam_collector::account_id_from_arn;
use iam_graph::{
    delete_snapshot, diff_permissions, entity_permissions, instance_profiles_with_action,
    list_account_ids, list_accounts, list_snapshots, org_escalation_paths,
    privilege_escalation_paths, resolve_org_context, resolve_scopes, snapshot_record,
    snapshots_for_org_run, who_can, Caveat, EntityRef, EscalationPath, GraphClient, GraphError,
    PermissionRow, QueryContext, ResolvedScope, ScopeSelector, SnapshotRecord, DEFAULT_MAX_HOPS,
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

    /// Path to a file containing the Neo4j password (e.g. a Docker/Kubernetes secret
    /// mount). Takes precedence over NEO4J_PASSWORD. A trailing newline is trimmed.
    #[arg(long)]
    neo4j_pass_file: Option<PathBuf>,

    /// AWS account ID to query. If omitted, the query runs once per account that has a
    /// snapshot in the graph, each scoped to its own (account_id, snapshot_id).
    #[arg(long)]
    account_id: Option<String>,

    /// Snapshot ID to query (default: most recent for the account). Cannot be combined
    /// with multi-account mode (--account-id omitted and more than one account found).
    #[arg(long)]
    snapshot_id: Option<String>,

    /// Write the result to this file, in whatever format --output selects (json or
    /// graphviz; table has no file-writable form, so this has no effect with the default
    /// --output table). For --output json, stdout is suppressed once the file is written.
    #[arg(long)]
    output_file: Option<PathBuf>,

    #[command(subcommand)]
    command: QueryCommand,
}

/// Envelope for every JSON query response: results plus the approximations (see
/// `docs/limitations.md`) that apply to this query and the snapshot(s) it ran against.
/// Always present, even when `caveats` is empty, so JSON consumers have a stable schema.
#[derive(Serialize)]
struct QueryResponse<'a, T: Serialize> {
    results: &'a T,
    caveats: Vec<Caveat>,
}

/// Emit JSON (wrapped in [`QueryResponse`]) to `output_file` (if given) and/or stdout per
/// `output`. Returns `true` if the human-readable view should still be printed to stdout.
///
/// | output | output_file | file | stdout |
/// |--------|-------------|------|--------|
/// | table  | absent      | —    | table  |
/// | json   | absent      | —    | json   |
/// | table  | present     | json | table  |
/// | json   | present     | json | (none) |
fn emit_json<T: Serialize>(
    value: &T,
    caveats: Vec<Caveat>,
    output: &OutputFormat,
    output_file: Option<&Path>,
) -> anyhow::Result<bool> {
    let response = QueryResponse {
        results: value,
        caveats,
    };
    if let Some(path) = output_file {
        json::write_json(&response, path)?;
    }
    if *output == OutputFormat::Json {
        if output_file.is_none() {
            json::print_json(&response)?;
        }
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

/// Approximations derived from the snapshot(s) a query actually ran against: at most one
/// `partial-snapshot` caveat (reasons unioned and deduped across all given snapshots, so a
/// multi-account fan-out reports one caveat, not one per account) plus `expansion-degraded`
/// when any of those reasons is specifically the wildcard-expansion fallback.
fn snapshot_caveats(snapshots: &[&SnapshotRecord]) -> Vec<Caveat> {
    let mut reasons = Vec::new();
    let mut is_partial = false;
    let mut expansion_degraded = false;
    for snapshot in snapshots {
        if snapshot.is_partial {
            is_partial = true;
        }
        for reason in &snapshot.partial_reasons {
            if reason == iam_graph::queries::caveats::WILDCARDS_NOT_EXPANDED_REASON {
                expansion_degraded = true;
            }
            if !reasons.contains(reason) {
                reasons.push(reason.clone());
            }
        }
    }

    let mut caveats = Vec::new();
    if is_partial {
        caveats.push(Caveat::partial_snapshot(&reasons));
    }
    if expansion_degraded {
        caveats.push(Caveat::expansion_degraded());
    }
    caveats
}

/// Static caveats for `who_can` (`crates/iam-graph/src/queries/analysis.rs`), the only query
/// that performs both glob-based Deny subtraction (via `iam_expander::glob_match`) and
/// `NotAction` exclusion evaluation — see "Deny scope is approximate" and "`NotAction` —
/// implemented as allow-all-except" in `docs/limitations.md`. Do not reuse this for a query
/// that doesn't call `who_can`/`privilege_escalation_paths`-style Deny/NotAction logic; check
/// the query's own Cypher and Rust before attaching either caveat.
fn who_can_static_caveats() -> Vec<Caveat> {
    vec![Caveat::approximate_deny(), Caveat::notaction_not_expanded()]
}

/// Static caveats for `privilege_escalation_paths`/`org_escalation_paths`
/// (`crates/iam-graph/src/queries/escalation.rs`, `org_escalation.rs`), which track
/// `allowed_actions`/`deny_actions` and subtract Deny via the same glob matcher as `who_can`,
/// but never evaluate `NotAction` — so only `approximate-deny` applies here.
fn escalation_static_caveats() -> Vec<Caveat> {
    vec![Caveat::approximate_deny()]
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
                    return Err(CliValidationError::SnapshotIdMultiAccountConflict {
                        accounts: accounts.len(),
                    }
                    .into());
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
    /// Approximations that apply to this query kind regardless of which snapshot(s) it runs
    /// against (e.g. `approximate-deny` for `who-can`). Unioned with the snapshot-derived
    /// caveats (`partial-snapshot`, `expansion-degraded`) before `emit_json`.
    caveats: Vec<Caveat>,
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

        let mut caveats = out.caveats;
        caveats.extend(snapshot_caveats(&[&snapshot]));
        if !emit_json(&result, caveats, out.format, out.file)? {
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
    let mut all_snapshots = Vec::with_capacity(scopes.len());
    for scope in &scopes {
        print_partial_warning(&scope.snapshot);
        let results = query(scope.context.clone()).await?;
        groups.push(AccountGroup {
            account_id: scope.context.account_id.clone(),
            snapshot_id: scope.context.snapshot_id.clone(),
            results,
        });
        all_snapshots.push(&scope.snapshot);
    }

    let mut caveats = out.caveats;
    caveats.extend(snapshot_caveats(&all_snapshots));
    if !emit_json(&groups, caveats, out.format, out.file)? {
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

    write_dot_output(&dot, out.file)
}

/// Write rendered DOT text to `file`, or stdout when `file` is `None`.
fn write_dot_output(dot: &str, file: Option<&Path>) -> anyhow::Result<()> {
    match file {
        Some(path) => {
            std::fs::write(path, dot).with_context(|| {
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
    /// All permissions for a specific entity ARN. The account is inferred from the ARN's
    /// own account segment, not from `--account-id` — an ARN can only belong to one
    /// account, so this command never fans out across accounts. An explicit
    /// `--account-id` that disagrees with the ARN's account is an error.
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

pub async fn run(args: QueryArgs, output: OutputFormat) -> anyhow::Result<()> {
    if output == OutputFormat::Graphviz
        && !matches!(
            args.command,
            QueryCommand::WhoCan { .. }
                | QueryCommand::PrivilegeEscalation { .. }
                | QueryCommand::OrgEscalation { .. }
        )
    {
        return Err(CliValidationError::GraphvizUnsupported.into());
    }

    let neo4j_pass = crate::cli::collect::resolve_neo4j_pass(args.neo4j_pass_file.as_deref())?;
    let client = GraphClient::connect(&args.neo4j_uri, &args.neo4j_user, &neo4j_pass)
        .await
        .with_context(|| {
            format!(
                "failed to connect to Neo4j at {}",
                iam_graph::redact_uri(&args.neo4j_uri)
            )
        })?;

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

            // A snapshot listing isn't an access query — it's metadata, and each row
            // already self-reports `is_partial`/`partial_reasons`. No caveats apply.
            if !emit_json(&snapshots, Vec::new(), &output, args.output_file.as_deref())? {
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

            // Cross-account discovery, not an access query. Always empty (acceptance
            // criterion: `list-accounts --output json` returns `caveats: []`).
            if !emit_json(&accounts, Vec::new(), &output, args.output_file.as_deref())? {
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

            if output == OutputFormat::Graphviz {
                let dot = graphviz::org_escalation_paths_to_dot("org_escalation", &paths);
                write_dot_output(&dot, args.output_file.as_deref())?;
                return Ok(());
            }

            // Snapshot-derived caveats need one extra graph query across the whole org run.
            // Only pay for it when the result will actually carry caveats: `--output table`
            // with no `--output-file` never serializes JSON at all.
            let mut caveats = escalation_static_caveats();
            if output == OutputFormat::Json || args.output_file.is_some() {
                let snapshots = snapshots_for_org_run(client.inner(), &run_id)
                    .await
                    .context("failed to resolve org-run snapshots for caveats")?;
                caveats.extend(snapshot_caveats(&snapshots.iter().collect::<Vec<_>>()));
            }
            if !emit_json(&paths, caveats, &output, args.output_file.as_deref())? {
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
            // Fetch both full records once — needed for `partial-snapshot`/`expansion-degraded`
            // caveats regardless, and reused below to derive `account_id` when `--account-id`
            // is omitted instead of issuing a second pair of lookups for that alone. Fetched
            // concurrently: the two snapshot ids are independent read-only lookups.
            let (record_a, record_b) = tokio::try_join!(
                snapshot_record(client.inner(), snapshot_a),
                snapshot_record(client.inner(), snapshot_b),
            )?;
            let record_a = record_a.ok_or_else(|| GraphError::snapshot_not_found(snapshot_a))?;
            let record_b = record_b.ok_or_else(|| GraphError::snapshot_not_found(snapshot_b))?;

            let resolved_account_id;
            let account_id = match args.account_id.as_deref() {
                Some(id) => id,
                None => {
                    resolved_account_id =
                        diff_account_id_from_records(snapshot_a, &record_a, snapshot_b, &record_b)?;
                    &resolved_account_id
                }
            };
            let diff = diff_permissions(client.inner(), account_id, snapshot_a, snapshot_b)
                .await
                .context("diff query failed")?;

            // diff_permissions()/diff_added.cypher/diff_removed.cypher do a raw structural
            // existence-diff of stored (action, resource, effect) triples — no Deny
            // reconciliation, no glob matching, no NotAction logic. Neither approximation
            // caveat applies; only snapshot-derived caveats can.
            let caveats = snapshot_caveats(&[&record_a, &record_b]);
            if !emit_json(&diff, caveats, &output, args.output_file.as_deref())? {
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
                    format: &output,
                    file: args.output_file.as_deref(),
                    single: args.account_id.is_some(),
                    caveats: who_can_static_caveats(),
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
            let arn_account = entity_perms_account(&arn, args.account_id.as_deref())?;

            let selector = match args.snapshot_id.as_deref() {
                Some(snapshot_id) => ScopeSelector::snapshot(snapshot_id, Some(arn_account)),
                None => ScopeSelector::account(arn_account),
            };
            let scopes = resolve_scopes(client.inner(), selector).await?;

            run_scoped(
                ScopedOutput {
                    format: &output,
                    file: args.output_file.as_deref(),
                    // Always single: an ARN names exactly one account, so entity-perms
                    // never fans out (see docs/limitations.md and issue #151).
                    single: true,
                    // entity_permissions() does no Deny subtraction and no NotAction
                    // handling — it returns every stored Allow/Deny row unfiltered, with
                    // `effective` computed only from permission-boundary capping. Neither
                    // caveat applies; see crates/iam-graph/src/queries/analysis.rs.
                    caveats: Vec::new(),
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
                |_sc| format!("Permissions for {arn}"),
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
                    format: &output,
                    file: args.output_file.as_deref(),
                    single: args.account_id.is_some(),
                    // instance_profiles_with_action.cypher matches only exact
                    // `effect: 'Allow', action: $action` — no Deny exclusion, no
                    // wildcard/NotAction arm. Neither caveat applies; see
                    // crates/iam-graph/queries/instance_profiles_with_action.cypher.
                    caveats: Vec::new(),
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
                    format: &output,
                    file: args.output_file.as_deref(),
                    single: args.account_id.is_some(),
                    caveats: escalation_static_caveats(),
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
fn diff_account_id_from_records(
    snapshot_a: &str,
    record_a: &SnapshotRecord,
    snapshot_b: &str,
    record_b: &SnapshotRecord,
) -> anyhow::Result<String> {
    if record_a.account_id != record_b.account_id {
        anyhow::bail!(
            "snapshot {snapshot_a} belongs to account {} but snapshot {snapshot_b} belongs to \
             account {}; diff requires both snapshots in the same account",
            record_a.account_id,
            record_b.account_id,
        );
    }
    Ok(record_a.account_id.clone())
}

/// Derive the single account `entity-perms` should query from its ARN argument, validating
/// it against an optional explicit `--account-id`. An ARN names exactly one account, so
/// `entity-perms` never fans out across accounts (issue #151) — this replaces the
/// `resolve_command_scopes` fan-out path used by the other scoped query commands.
fn entity_perms_account(
    arn: &str,
    flag_account: Option<&str>,
) -> Result<String, CliValidationError> {
    let arn_account = account_id_from_arn(arn)
        .filter(|account| account != "aws")
        .ok_or_else(|| CliValidationError::EntityPermsArnUnparseable {
            arn: arn.to_string(),
        })?;

    if let Some(flag_account) = flag_account {
        if flag_account != arn_account {
            return Err(CliValidationError::EntityPermsAccountConflict {
                flag_account: flag_account.to_string(),
                arn_account,
                arn: arn.to_string(),
            });
        }
    }

    Ok(arn_account)
}

fn short_id(id: &str) -> &str {
    &id[..8.min(id.len())]
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    #[test]
    fn entity_perms_account_derives_from_arn_when_flag_omitted() {
        let result = entity_perms_account("arn:aws:iam::123456789012:user/alice", None);

        assert_eq!(result.unwrap(), "123456789012");
    }

    #[test]
    fn entity_perms_account_matching_flag_succeeds() {
        let result =
            entity_perms_account("arn:aws:iam::123456789012:user/alice", Some("123456789012"));

        assert_eq!(result.unwrap(), "123456789012");
    }

    #[test]
    fn entity_perms_account_conflicting_flag_errors() {
        let result =
            entity_perms_account("arn:aws:iam::123456789012:user/alice", Some("999999999999"));

        assert!(matches!(
            result,
            Err(CliValidationError::EntityPermsAccountConflict {
                flag_account,
                arn_account,
                ..
            }) if flag_account == "999999999999" && arn_account == "123456789012"
        ));
    }

    #[test]
    fn entity_perms_account_unparseable_arn_errors() {
        let result = entity_perms_account("not-an-arn", None);

        assert!(matches!(
            result,
            Err(CliValidationError::EntityPermsArnUnparseable { arn }) if arn == "not-an-arn"
        ));
    }

    #[test]
    fn entity_perms_account_aws_managed_policy_arn_errors() {
        let result = entity_perms_account("arn:aws:iam::aws:policy/ReadOnlyAccess", None);

        assert!(matches!(
            result,
            Err(CliValidationError::EntityPermsArnUnparseable { arn })
                if arn == "arn:aws:iam::aws:policy/ReadOnlyAccess"
        ));
    }

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

    #[derive(Serialize)]
    struct SampleValue {
        n: u32,
    }

    #[test]
    fn emit_json_table_no_file_prints_table_no_file_written() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("out.json");

        let print_table = emit_json(
            &SampleValue { n: 1 },
            Vec::new(),
            &OutputFormat::Table,
            None,
        )
        .unwrap();

        assert!(print_table);
        assert!(!path.exists());
    }

    #[test]
    fn emit_json_json_no_file_suppresses_table_no_file_written() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("out.json");

        let print_table =
            emit_json(&SampleValue { n: 1 }, Vec::new(), &OutputFormat::Json, None).unwrap();

        assert!(!print_table);
        assert!(!path.exists());
    }

    #[test]
    fn emit_json_table_with_file_writes_file_and_prints_table() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("out.json");

        let print_table = emit_json(
            &SampleValue { n: 1 },
            Vec::new(),
            &OutputFormat::Table,
            Some(&path),
        )
        .unwrap();

        assert!(print_table);
        assert!(path.exists());
    }

    #[test]
    fn emit_json_json_with_file_writes_file_and_suppresses_table() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("out.json");

        let print_table = emit_json(
            &SampleValue { n: 1 },
            Vec::new(),
            &OutputFormat::Json,
            Some(&path),
        )
        .unwrap();

        assert!(!print_table);
        assert!(path.exists());
        let contents = std::fs::read_to_string(&path).unwrap();
        assert!(contents.contains("\"n\": 1"));
    }

    #[tokio::test]
    async fn run_scoped_multi_mode_wraps_result_even_for_one_scope() {
        let scopes = vec![scope("111111111111", "snap-a")];
        let calls = RefCell::new(Vec::new());
        let out = ScopedOutput {
            format: &OutputFormat::Table,
            file: None,
            single: false,
            caveats: Vec::new(),
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
            caveats: Vec::new(),
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
            caveats: Vec::new(),
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
            caveats: Vec::new(),
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
            caveats: Vec::new(),
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

    fn snapshot(is_partial: bool, reasons: &[&str]) -> SnapshotRecord {
        SnapshotRecord {
            id: "snap-a".to_string(),
            account_id: "111111111111".to_string(),
            collected_at: String::new(),
            is_partial,
            partial_reasons: reasons.iter().map(|r| r.to_string()).collect(),
            org_collection_run_id: None,
        }
    }

    #[test]
    fn emit_json_wraps_value_in_results_with_caveats_array() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("out.json");

        emit_json(&"hello", Vec::new(), &OutputFormat::Table, Some(&path)).unwrap();

        let contents = std::fs::read_to_string(&path).unwrap();
        assert!(contents.contains("\"results\""));
        assert!(contents.contains("\"caveats\""));
    }

    #[test]
    fn emit_json_emits_empty_caveats_array_when_none_apply() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("out.json");

        emit_json(&"hello", Vec::new(), &OutputFormat::Table, Some(&path)).unwrap();

        let contents = std::fs::read_to_string(&path).unwrap();
        assert!(contents.contains("\"caveats\": []"));
    }

    #[test]
    fn snapshot_caveats_partial_snapshot_includes_reasons() {
        let snap = snapshot(true, &["instance profiles missing"]);

        let caveats = snapshot_caveats(&[&snap]);

        assert_eq!(caveats.len(), 1);
        assert_eq!(caveats[0].code, iam_graph::CaveatCode::PartialSnapshot);
        assert!(caveats[0].message.contains("instance profiles missing"));
    }

    #[test]
    fn snapshot_caveats_complete_snapshot_is_empty() {
        let snap = snapshot(false, &[]);

        let caveats = snapshot_caveats(&[&snap]);

        assert!(caveats.is_empty());
    }

    #[test]
    fn snapshot_caveats_wildcard_reason_adds_expansion_degraded() {
        let snap = snapshot(
            true,
            &[iam_graph::queries::caveats::WILDCARDS_NOT_EXPANDED_REASON],
        );

        let caveats = snapshot_caveats(&[&snap]);

        let codes: Vec<_> = caveats.iter().map(|c| c.code).collect();
        assert!(codes.contains(&iam_graph::CaveatCode::PartialSnapshot));
        assert!(codes.contains(&iam_graph::CaveatCode::ExpansionDegraded));
    }

    #[test]
    fn snapshot_caveats_dedups_partial_across_multiple_scopes() {
        let snap_a = snapshot(true, &["instance profiles missing"]);
        let snap_b = snapshot(true, &["instance profiles missing"]);

        let caveats = snapshot_caveats(&[&snap_a, &snap_b]);

        let partial_count = caveats
            .iter()
            .filter(|c| c.code == iam_graph::CaveatCode::PartialSnapshot)
            .count();
        assert_eq!(partial_count, 1);
    }

    #[test]
    fn who_can_static_caveats_includes_deny_and_notaction() {
        let codes: Vec<_> = who_can_static_caveats()
            .into_iter()
            .map(|c| c.code)
            .collect();

        assert_eq!(
            codes,
            [
                iam_graph::CaveatCode::ApproximateDeny,
                iam_graph::CaveatCode::NotactionNotExpanded,
            ]
        );
    }

    #[test]
    fn escalation_static_caveats_includes_only_deny() {
        let codes: Vec<_> = escalation_static_caveats()
            .into_iter()
            .map(|c| c.code)
            .collect();

        assert_eq!(codes, [iam_graph::CaveatCode::ApproximateDeny]);
    }

    #[test]
    fn diff_account_id_from_records_matches_when_accounts_agree() {
        let record = snapshot(false, &[]);

        let account_id =
            diff_account_id_from_records("snap-a", &record, "snap-b", &record).unwrap();

        assert_eq!(account_id, "111111111111");
    }

    #[test]
    fn diff_account_id_from_records_errors_on_account_mismatch() {
        let mut record_b = snapshot(false, &[]);
        record_b.account_id = "222222222222".to_string();

        let result =
            diff_account_id_from_records("snap-a", &snapshot(false, &[]), "snap-b", &record_b);

        assert!(result.is_err());
    }
}
