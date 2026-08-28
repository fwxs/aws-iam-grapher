use crate::cli::common::{ConnectionArgs, OutputArgs};
use crate::exit_code::CliValidationError;
use crate::output::{graphviz, json, OutputFormat};
use anyhow::Context as _;
use clap::{Args, Subcommand, ValueEnum};
use iam_collector::account_id_from_arn;
use iam_graph::{
    associated_entities, delete_snapshot, diff_permissions, entity_permissions,
    instance_profiles_with_action, list_account_ids, list_accounts, list_snapshots,
    org_escalation_paths, privilege_escalation_paths, resolve_org_context, resolve_scopes,
    snapshot_record, snapshots_for_org_run, who_can, Caveat, EntityRef, EscalationPath,
    GraphClient, GraphError, OrgEscalationPath, QueryContext, ResolvedScope, RiskyActionGroups,
    ScopeSelector, SnapshotRecord, DEFAULT_MAX_HOPS,
};
use iam_models::condition::ConditionContext;
use serde::Serialize;
use std::collections::HashMap;
use std::future::Future;
use std::path::{Path, PathBuf};

#[derive(Args)]
pub struct QueryArgs {
    #[command(flatten)]
    connection: ConnectionArgs,

    /// AWS account ID to query. If omitted, the query runs once per account that has a
    /// snapshot in the graph, each scoped to its own (account_id, snapshot_id).
    #[arg(long)]
    account_id: Option<String>,

    /// Snapshot ID to query (default: most recent for the account). Cannot be combined
    /// with multi-account mode (--account-id omitted and more than one account found).
    #[arg(long)]
    snapshot_id: Option<String>,

    #[command(flatten)]
    output: OutputArgs,

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

/// Emit JSON (wrapped in [`QueryResponse`]) to `output_file` (if given), or stdout otherwise.
fn emit_json<T: Serialize>(
    value: &T,
    caveats: Vec<Caveat>,
    output_file: Option<&Path>,
) -> anyhow::Result<()> {
    let response = QueryResponse {
        results: value,
        caveats,
    };
    match output_file {
        Some(path) => json::write_json(&response, path),
        None => json::print_json(&response),
    }
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

/// Run a query over one or more resolved scopes and emit the result as JSON.
///
/// `to_dot`, when present, renders a scope's result as Graphviz DOT text. Pass `None`
/// for queries with no graph-shaped result — `--output graphviz` is rejected up front
/// in `run()` for those, so this is never called with `out.format == Graphviz` and
/// `to_dot: None` at once.
async fn run_scoped<T, F, Fut>(
    out: ScopedOutput<'_>,
    scopes: Vec<ResolvedScope>,
    query: F,
    to_dot: Option<ToDot<'_, T>>,
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
        let result = query(context).await?;

        let mut caveats = out.caveats;
        caveats.extend(snapshot_caveats(&[&snapshot]));
        emit_json(&result, caveats, out.file)?;
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
    emit_json(&groups, caveats, out.file)?;
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
    /// Entities structurally linked to a Policy/Role/Group ARN: attached/inline policy
    /// holders, role assumers, containing instance profiles, or group members, depending on
    /// the target's type. The account is inferred from the ARN's own account segment, same
    /// as `entity-perms` — this command never fans out across accounts either.
    AssociatedEntities { arn: String },
    /// Instance profiles whose roles grant the given IAM action.
    InstanceProfilesWith { action: String },
    /// Entities with privilege-escalation permissions, directly or via a transitive
    /// sts:AssumeRole chain.
    PrivilegeEscalation {
        #[command(flatten)]
        hops: MaxHopsArg,
        #[command(flatten)]
        risky_actions: RiskyActionsArg,
        #[command(flatten)]
        entity_type: EntityTypeArg,
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
        #[command(flatten)]
        hops: MaxHopsArg,
        #[command(flatten)]
        risky_actions: RiskyActionsArg,
        /// Org collection run id (default: most recent org run).
        #[arg(long)]
        org_run_id: Option<String>,
        #[command(flatten)]
        entity_type: EntityTypeArg,
    },
}

/// Max sts:AssumeRole hops to traverse when looking for transitive escalation paths.
/// Capped at 10 to bound traversal cost on dense CAN_ASSUME_ROLE graphs. Shared by
/// `PrivilegeEscalation` and `OrgEscalation`.
#[derive(Args)]
pub struct MaxHopsArg {
    #[arg(long, default_value_t = DEFAULT_MAX_HOPS)]
    max_hops: u32,
}

/// Path to the risky-actions config, or fall back to the installed default. Shared by
/// `PrivilegeEscalation` and `OrgEscalation`.
#[derive(Args)]
pub struct RiskyActionsArg {
    /// Path to a risky-actions YAML config. If omitted, falls back to
    /// ~/.aws-iam-grapher/config/risky-actions.yaml (fatal if neither is found).
    #[arg(long)]
    risky_actions: Option<PathBuf>,
}

/// Which escalating-entity types to keep in an escalation result. Shared by
/// `PrivilegeEscalation` and `OrgEscalation`.
#[derive(Args)]
pub struct EntityTypeArg {
    /// Restrict results to this entity type. `user` also keeps a Group path that has at
    /// least one holder — a user reachable only via that group's membership is exactly
    /// the case this filter is for.
    #[arg(long = "entity-type", value_enum, default_value_t = EntityTypeFilter::All)]
    entity_type: EntityTypeFilter,
}

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum EntityTypeFilter {
    User,
    Role,
    Group,
    All,
}

/// Filter escalation results in Rust, after the query returns — never in Cypher. The
/// UNION/dedupe/Deny-subtraction logic in `privilege_escalation_paths.cypher` is
/// intricate and correct; a post-filter here cannot break it.
fn filter_by_entity_type<T>(
    paths: Vec<T>,
    filter: EntityTypeFilter,
    entity_type: impl Fn(&T) -> &str,
    holder_count: impl Fn(&T) -> usize,
) -> Vec<T> {
    match filter {
        EntityTypeFilter::All => paths,
        EntityTypeFilter::User => paths
            .into_iter()
            .filter(|p| entity_type(p) == "User" || holder_count(p) > 0)
            .collect(),
        EntityTypeFilter::Role => paths
            .into_iter()
            .filter(|p| entity_type(p) == "Role")
            .collect(),
        EntityTypeFilter::Group => paths
            .into_iter()
            .filter(|p| entity_type(p) == "Group")
            .collect(),
    }
}

/// Resolve the risky-actions config per the two-step rule: `explicit` (fatal if missing)
/// else `~/.aws-iam-grapher/config/risky-actions.yaml` (fatal if missing or `$HOME`
/// unset). Shared by `PrivilegeEscalation` and `OrgEscalation` — the only two commands
/// that consume a risky-actions config. `config check` resolves its own path separately
/// since it needs the multi-error `from_yaml` path, not this single-error one.
fn resolve_risky_actions(explicit: Option<&Path>) -> anyhow::Result<RiskyActionGroups> {
    let home = std::env::var_os("HOME").map(std::path::PathBuf::from);
    RiskyActionGroups::resolve(explicit, home.as_deref()).map_err(anyhow::Error::from)
}

impl QueryCommand {
    /// Whether this query kind has a graph-shaped result renderable as Graphviz DOT.
    /// Exhaustive match (no `_` arm) so a new variant fails to compile until this is
    /// answered explicitly, instead of failing at runtime.
    fn supports_graphviz(&self) -> bool {
        match self {
            QueryCommand::WhoCan { .. }
            | QueryCommand::PrivilegeEscalation { .. }
            | QueryCommand::OrgEscalation { .. } => true,
            QueryCommand::EntityPerms { .. }
            | QueryCommand::AssociatedEntities { .. }
            | QueryCommand::InstanceProfilesWith { .. }
            | QueryCommand::ListSnapshots
            | QueryCommand::ListAccounts
            | QueryCommand::Diff { .. }
            | QueryCommand::DeleteSnapshot { .. } => false,
        }
    }
}

pub async fn run(args: QueryArgs, output: OutputFormat) -> anyhow::Result<()> {
    if output == OutputFormat::Graphviz && !args.command.supports_graphviz() {
        return Err(CliValidationError::GraphvizUnsupported.into());
    }

    let neo4j_pass =
        crate::cli::collect::resolve_neo4j_pass(args.connection.neo4j_pass_file.as_deref())?;
    let client = GraphClient::connect(
        &args.connection.neo4j_uri,
        &args.connection.neo4j_user,
        &neo4j_pass,
    )
    .await
    .with_context(|| {
        format!(
            "failed to connect to Neo4j at {}",
            iam_graph::redact_uri(&args.connection.neo4j_uri)
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
            emit_json(&snapshots, Vec::new(), args.output.output_file.as_deref())?;
        }

        QueryCommand::ListAccounts => {
            let accounts = list_accounts(client.inner())
                .await
                .context("list-accounts query failed")?;

            // Cross-account discovery, not an access query. Always empty (acceptance
            // criterion: `list-accounts --output json` returns `caveats: []`).
            emit_json(&accounts, Vec::new(), args.output.output_file.as_deref())?;
        }

        QueryCommand::DeleteSnapshot { snapshot_id } => {
            let deleted = delete_snapshot(client.inner(), &snapshot_id)
                .await
                .context("delete-snapshot failed")?;
            println!("Deleted {deleted} nodes for snapshot {snapshot_id}");
        }

        QueryCommand::OrgEscalation {
            hops: MaxHopsArg { max_hops },
            risky_actions,
            org_run_id,
            entity_type: EntityTypeArg { entity_type },
        } => {
            let groups = resolve_risky_actions(risky_actions.risky_actions.as_deref())?;
            let ctx = resolve_org_context(client.inner(), org_run_id).await?;
            let run_id = ctx.org_run_id.clone();
            let paths = org_escalation_paths(client.inner(), &ctx, max_hops, &groups)
                .await
                .context("org-escalation query failed")?;
            let paths = filter_by_entity_type(
                paths,
                entity_type,
                |p: &OrgEscalationPath| p.entity_type.as_str(),
                |p: &OrgEscalationPath| p.holders.len(),
            );

            if output == OutputFormat::Graphviz {
                let dot = graphviz::org_escalation_paths_to_dot("org_escalation", &paths);
                write_dot_output(&dot, args.output.output_file.as_deref())?;
                return Ok(());
            }

            // Snapshot-derived caveats need one extra graph query across the whole org run.
            let mut caveats = escalation_static_caveats();
            let snapshots = snapshots_for_org_run(client.inner(), &run_id)
                .await
                .context("failed to resolve org-run snapshots for caveats")?;
            caveats.extend(snapshot_caveats(&snapshots.iter().collect::<Vec<_>>()));
            emit_json(&paths, caveats, args.output.output_file.as_deref())?;
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
            emit_json(&diff, caveats, args.output.output_file.as_deref())?;
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
                    file: args.output.output_file.as_deref(),
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
                Some(&|results: &Vec<EntityRef>, graph_name: &str| {
                    graphviz::who_can_to_dot(graph_name, &action, results)
                }),
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
                    file: args.output.output_file.as_deref(),
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
                        entity_permissions(client.inner(), &ctx, &arn)
                            .await
                            .context("entity-perms query failed")
                    }
                },
                None,
            )
            .await?;
        }

        QueryCommand::AssociatedEntities { arn } => {
            let arn_account = entity_perms_account(&arn, args.account_id.as_deref())?;

            let selector = match args.snapshot_id.as_deref() {
                Some(snapshot_id) => ScopeSelector::snapshot(snapshot_id, Some(arn_account)),
                None => ScopeSelector::account(arn_account),
            };
            let scopes = resolve_scopes(client.inner(), selector).await?;

            run_scoped(
                ScopedOutput {
                    format: &output,
                    file: args.output.output_file.as_deref(),
                    // Always single: an ARN names exactly one account, so
                    // associated-entities never fans out, same as entity-perms (see
                    // docs/limitations.md and issue #151).
                    single: true,
                    // associated_entities() is a pure structural relationship traversal —
                    // no Deny subtraction, no NotAction, no permission-level GRANTS logic —
                    // so neither caveat applies; see
                    // crates/iam-graph/src/queries/analysis.rs.
                    caveats: Vec::new(),
                },
                scopes,
                |ctx| {
                    let arn = arn.clone();
                    let client = &client;
                    async move {
                        associated_entities(client.inner(), &ctx, &arn)
                            .await
                            .context("associated-entities query failed")
                    }
                },
                None,
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
                    file: args.output.output_file.as_deref(),
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
                None,
            )
            .await?;
        }

        QueryCommand::PrivilegeEscalation {
            hops: MaxHopsArg { max_hops },
            risky_actions,
            entity_type: EntityTypeArg { entity_type },
        } => {
            let groups = resolve_risky_actions(risky_actions.risky_actions.as_deref())?;
            let scopes = resolve_command_scopes(
                &client,
                args.account_id.as_deref(),
                args.snapshot_id.as_deref(),
            )
            .await?;
            run_scoped(
                ScopedOutput {
                    format: &output,
                    file: args.output.output_file.as_deref(),
                    single: args.account_id.is_some(),
                    caveats: escalation_static_caveats(),
                },
                scopes,
                |ctx| {
                    let client = &client;
                    let groups = &groups;
                    async move {
                        let paths =
                            privilege_escalation_paths(client.inner(), &ctx, max_hops, groups)
                                .await
                                .context("privilege-escalation query failed")?;
                        Ok(filter_by_entity_type(
                            paths,
                            entity_type,
                            |p: &EscalationPath| p.entity_type.as_str(),
                            |p: &EscalationPath| p.holders.len(),
                        ))
                    }
                },
                Some(&|paths: &Vec<EscalationPath>, graph_name: &str| {
                    graphviz::escalation_paths_to_dot(graph_name, paths)
                }),
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

#[cfg(test)]
mod tests {
    use super::*;
    use iam_graph::{Holder, UserAttributes};

    fn escalation_path(entity_type: &str, holders: Vec<Holder>) -> EscalationPath {
        EscalationPath {
            arn: format!("arn:aws:iam::111111111111:{entity_type}/x"),
            name: "x".to_string(),
            entity_type: entity_type.to_string(),
            risky_actions: vec!["iam:PutUserPolicy".to_string()],
            matched_paths: vec!["put-user-policy".to_string()],
            path: vec![],
            conditional: false,
            holders,
            instance_profiles: vec![],
            trust_principals: vec![],
            user_attributes: None,
            associations: vec![],
        }
    }

    fn holder(arn: &str) -> Holder {
        Holder {
            arn: arn.to_string(),
            name: "holder".to_string(),
            entity_type: "User".to_string(),
            attributes: UserAttributes {
                user_id: "AIDAHOLDER".to_string(),
                has_mfa: false,
                mfa_method: None,
                console_login_enabled: false,
                password_last_used: None,
                last_activity_date: None,
                create_date: "2025-01-01T00:00:00+00:00".to_string(),
                access_key_count: 0,
                active_access_key_count: 0,
                oldest_active_key_date: None,
                access_key_ids: vec![],
            },
        }
    }

    #[test]
    fn filter_by_entity_type_user_keeps_user_entities_and_groups_with_holders() {
        let paths = vec![
            escalation_path("User", vec![]),
            escalation_path("Role", vec![]),
            escalation_path("Group", vec![]),
            escalation_path(
                "Group",
                vec![holder("arn:aws:iam::111111111111:user/member")],
            ),
        ];

        let filtered = filter_by_entity_type(
            paths,
            EntityTypeFilter::User,
            |p: &EscalationPath| p.entity_type.as_str(),
            |p: &EscalationPath| p.holders.len(),
        );

        assert_eq!(filtered.len(), 2);
        assert!(filtered.iter().any(|p| p.entity_type == "User"));
        assert!(filtered
            .iter()
            .any(|p| p.entity_type == "Group" && !p.holders.is_empty()));
        assert!(!filtered
            .iter()
            .any(|p| p.entity_type == "Group" && p.holders.is_empty()));
        assert!(!filtered.iter().any(|p| p.entity_type == "Role"));
    }

    #[test]
    fn filter_by_entity_type_all_keeps_everything() {
        let paths = vec![
            escalation_path("User", vec![]),
            escalation_path("Role", vec![]),
        ];

        let filtered = filter_by_entity_type(
            paths,
            EntityTypeFilter::All,
            |p: &EscalationPath| p.entity_type.as_str(),
            |p: &EscalationPath| p.holders.len(),
        );

        assert_eq!(filtered.len(), 2);
    }

    #[test]
    fn supports_graphviz_true_for_graph_shaped_queries() {
        assert!(QueryCommand::WhoCan {
            action: "s3:GetObject".to_string(),
            resource: None,
            region: None,
            mfa: None,
            principal_tags: Vec::new(),
        }
        .supports_graphviz());
        assert!(QueryCommand::PrivilegeEscalation {
            hops: MaxHopsArg { max_hops: 5 },
            risky_actions: RiskyActionsArg {
                risky_actions: None
            },
            entity_type: EntityTypeArg {
                entity_type: EntityTypeFilter::All
            },
        }
        .supports_graphviz());
        assert!(QueryCommand::OrgEscalation {
            hops: MaxHopsArg { max_hops: 5 },
            risky_actions: RiskyActionsArg {
                risky_actions: None
            },
            org_run_id: None,
            entity_type: EntityTypeArg {
                entity_type: EntityTypeFilter::All
            },
        }
        .supports_graphviz());
    }

    #[test]
    fn supports_graphviz_false_for_non_graph_queries() {
        assert!(!QueryCommand::ListSnapshots.supports_graphviz());
        assert!(!QueryCommand::ListAccounts.supports_graphviz());
        assert!(!QueryCommand::EntityPerms {
            arn: "arn:aws:iam::111111111111:user/alice".to_string(),
        }
        .supports_graphviz());
        assert!(!QueryCommand::AssociatedEntities {
            arn: "arn:aws:iam::111111111111:policy/example".to_string(),
        }
        .supports_graphviz());
    }

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

    #[derive(Serialize)]
    struct SampleValue {
        n: u32,
    }

    #[test]
    fn emit_json_no_file_writes_nothing_to_disk() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("out.json");

        emit_json(&SampleValue { n: 1 }, Vec::new(), None).unwrap();

        assert!(!path.exists());
    }

    #[test]
    fn emit_json_with_file_writes_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("out.json");

        emit_json(&SampleValue { n: 1 }, Vec::new(), Some(&path)).unwrap();

        assert!(path.exists());
        let contents = std::fs::read_to_string(&path).unwrap();
        assert!(contents.contains("\"n\": 1"));
    }

    #[tokio::test]
    async fn run_scoped_multi_mode_wraps_result_even_for_one_scope() {
        let scopes = vec![scope("111111111111", "snap-a")];
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("out.json");
        let out = ScopedOutput {
            format: &OutputFormat::Json,
            file: Some(&path),
            single: false,
            caveats: Vec::new(),
        };

        run_scoped(
            out,
            scopes,
            |ctx: QueryContext| async move { Ok(ctx.account_id) },
            None,
        )
        .await
        .unwrap();

        // --account-id omitted always fans out through AccountGroup, even when only
        // one account resolved — matches base behavior; must not key off scopes.len().
        let contents = std::fs::read_to_string(&path).unwrap();
        assert!(contents.contains("\"account_id\""));
    }

    #[tokio::test]
    async fn run_scoped_single_mode_unwraps_the_lone_scope() {
        let scopes = vec![scope("111111111111", "snap-a")];
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("out.json");
        let out = ScopedOutput {
            format: &OutputFormat::Json,
            file: Some(&path),
            single: true,
            caveats: Vec::new(),
        };

        run_scoped(
            out,
            scopes,
            |ctx: QueryContext| async move { Ok(ctx.account_id) },
            None,
        )
        .await
        .unwrap();

        let contents = std::fs::read_to_string(&path).unwrap();
        assert!(contents.contains("111111111111"));
        assert!(!contents.contains("\"account_id\""));
    }

    #[tokio::test]
    async fn run_scoped_single_mode_errors_on_unexpected_scope_count() {
        let scopes = vec![scope("111111111111", "a"), scope("222222222222", "b")];
        let out = ScopedOutput {
            format: &OutputFormat::Json,
            file: None,
            single: true,
            caveats: Vec::new(),
        };

        let result = run_scoped(
            out,
            scopes,
            |ctx: QueryContext| async move { Ok(ctx.account_id) },
            None,
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
            Some(&|s: &String, graph_name: &str| format!("digraph {graph_name} {{ {s} }}")),
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
            None,
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

        emit_json(&"hello", Vec::new(), Some(&path)).unwrap();

        let contents = std::fs::read_to_string(&path).unwrap();
        assert!(contents.contains("\"results\""));
        assert!(contents.contains("\"caveats\""));
    }

    #[test]
    fn emit_json_emits_empty_caveats_array_when_none_apply() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("out.json");

        emit_json(&"hello", Vec::new(), Some(&path)).unwrap();

        let contents = std::fs::read_to_string(&path).unwrap();
        assert!(contents.contains("\"caveats\": []"));
    }

    fn entity_ref_fixture() -> EntityRef {
        EntityRef {
            arn: "arn:aws:iam::123456789012:role/Example".to_string(),
            name: "Example".to_string(),
            entity_type: "Role".to_string(),
            is_full_admin: false,
            resource: "arn:aws:s3:::example-bucket/*".to_string(),
            is_bounded: false,
            conditional: false,
            unevaluated_condition_keys: Vec::new(),
        }
    }

    /// Pins the `{"results": ..., "caveats": [...]}` envelope shape for a single-account
    /// response. A failing snapshot here is a consumer-visible contract change — update the
    /// skill (#145) in the same PR. See `CLAUDE.md`.
    #[test]
    fn query_response_json_shape() {
        let value = vec![entity_ref_fixture()];
        let response = QueryResponse {
            results: &value,
            caveats: vec![Caveat::approximate_deny()],
        };

        insta::assert_json_snapshot!(response);
    }

    /// Pins the multi-account fan-out envelope shape (`--account-id` omitted).
    #[test]
    fn account_group_json_shape() {
        let group = AccountGroup {
            account_id: "123456789012".to_string(),
            snapshot_id: "snap-a".to_string(),
            results: vec![entity_ref_fixture()],
        };

        insta::assert_json_snapshot!(group);
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
