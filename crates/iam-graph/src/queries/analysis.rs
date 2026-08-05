use crate::errors::GraphError;
use crate::queries::col;
use crate::queries::context::QueryContext;
use iam_models::condition::{self, ConditionContext, ConditionOutcome};
use neo4rs::Graph;

/// Reference to an IAM entity returned by analysis queries.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct EntityRef {
    pub arn: String,
    pub name: String,
    pub entity_type: String,
    /// True when the entity holds an unqualified `Action: "*"` Allow — i.e. full-admin access.
    /// Such entities match *every* specific-action query even without an explicit permission node.
    pub is_full_admin: bool,
    /// The `Resource` of the grant that matched this entity.
    pub resource: String,
    /// True when the entity has a Permission Boundary attached, regardless of whether the
    /// boundary capped the matched action.
    pub is_bounded: bool,
    /// True when at least one surviving grant for this entity carries a `Condition` key
    /// outside the evaluated subset (see `iam_models::condition`) — access is gated, not
    /// unconditional, even though it's returned here. See `docs/limitations.md`.
    pub conditional: bool,
    /// Condition keys that could not be evaluated for this entity's grant(s).
    pub unevaluated_condition_keys: Vec<String>,
}

/// A single permission row with named fields.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct PermissionRow {
    pub action: String,
    pub effect: String,
    pub resource: String,
    /// False when this Allow is capped by the entity's Permission Boundary (the boundary does
    /// not also Allow this action). Always true for Deny rows and for unbounded entities.
    pub effective: bool,
}

/// An instance profile that has privilege-escalation permissions.
#[derive(Debug, Clone, serde::Serialize)]
pub struct RiskyInstanceProfile {
    pub arn: String,
    pub name: String,
    pub entity_type: String,
    pub risky_actions: Vec<String>,
}

const WHO_CAN_QUERY: &str = include_str!("../../queries/who_can.cypher");
const CANDIDATE_DENY_ACTIONS_QUERY: &str =
    include_str!("../../queries/candidate_deny_actions.cypher");
const CANDIDATE_BOUNDARY_ACTIONS_QUERY: &str =
    include_str!("../../queries/candidate_boundary_actions.cypher");
const ENTITY_BOUNDARY_ACTIONS_QUERY: &str =
    include_str!("../../queries/entity_boundary_actions.cypher");

/// Fetch every distinct Deny action string in this snapshot/account scope, excluding
/// Deny-NotAction sentinel nodes. Callers match the queried action against this list with
/// `iam_expander::glob_match` to compute the concrete Deny set that covers it.
async fn candidate_deny_actions(
    graph: &Graph,
    ctx: &QueryContext,
) -> Result<Vec<String>, GraphError> {
    let mut stream = graph
        .execute(
            neo4rs::query(CANDIDATE_DENY_ACTIONS_QUERY)
                .param("snapshot_id", ctx.snapshot_id.as_str())
                .param("account_id", ctx.account_id.as_str()),
        )
        .await?;

    let mut actions = Vec::new();
    while let Some(row) = stream.next().await? {
        let action: String = col(&row, "action")?;
        actions.push(action);
    }
    Ok(actions)
}

/// Fetch every distinct Allow action string granted by any Permission Boundary in this
/// snapshot/account scope, excluding allow-all-except sentinel nodes. Callers match the queried
/// action against this list with `iam_expander::glob_match` to compute the concrete set of
/// boundary-allowed actions that cover it.
async fn candidate_boundary_actions(
    graph: &Graph,
    ctx: &QueryContext,
) -> Result<Vec<String>, GraphError> {
    let mut stream = graph
        .execute(
            neo4rs::query(CANDIDATE_BOUNDARY_ACTIONS_QUERY)
                .param("snapshot_id", ctx.snapshot_id.as_str())
                .param("account_id", ctx.account_id.as_str()),
        )
        .await?;

    let mut actions = Vec::new();
    while let Some(row) = stream.next().await? {
        let action: String = col(&row, "action")?;
        actions.push(action);
    }
    Ok(actions)
}

/// Return all entities that have permission to perform `action` in this snapshot.
///
/// `resource`, when supplied, intersects the queried resource against the `Resource` of
/// wildcard (`Action: "*"` full-admin / NotAction allow-all-except) grants using IAM
/// resource-glob semantics (`iam_expander::glob_match`), excluding wildcard grants whose
/// resource scope doesn't cover the queried resource. Exact-action grants (arms 1/2) are
/// never filtered by `resource` — their `resource` is only surfaced in the output. See
/// limitations.md.
pub async fn who_can(
    graph: &Graph,
    ctx: &QueryContext,
    action: &str,
    resource: Option<&str>,
    condition_ctx: &ConditionContext,
) -> Result<Vec<EntityRef>, GraphError> {
    let candidates = candidate_deny_actions(graph, ctx).await?;
    let deny_actions: Vec<String> = candidates
        .into_iter()
        .filter(|candidate| iam_expander::glob_match(candidate, action))
        .collect();

    let boundary_candidates = candidate_boundary_actions(graph, ctx).await?;
    let boundary_allow_actions: Vec<String> = boundary_candidates
        .into_iter()
        .filter(|candidate| iam_expander::glob_match(candidate, action))
        .collect();

    let mut stream = graph
        .execute(
            neo4rs::query(WHO_CAN_QUERY)
                .param("action", action)
                .param("snapshot_id", ctx.snapshot_id.as_str())
                .param("account_id", ctx.account_id.as_str())
                .param("deny_actions", deny_actions)
                .param("boundary_allow_actions", boundary_allow_actions),
        )
        .await?;

    let mut raw: Vec<EntityRef> = Vec::new();
    while let Some(row) = stream.next().await? {
        let arn: String = col(&row, "arn")?;
        let name: String = col(&row, "name")?;
        let entity_type: String = col(&row, "entity_type")?;
        let is_full_admin: bool = col(&row, "is_full_admin")?;
        let perm_resource: String = col(&row, "resource")?;
        let grant_kind: String = col(&row, "grant_kind")?;
        let is_bounded: bool = col(&row, "is_bounded")?;
        let condition_json: Option<String> = col(&row, "condition")?;

        // Only wildcard (action='*') grants are resource-scoped intersection candidates;
        // exact-action grants always pass through.
        if let Some(queried_resource) = resource {
            if grant_kind == "wildcard"
                && !iam_expander::glob_match(&perm_resource, queried_resource)
            {
                continue;
            }
        }

        let (conditional, unevaluated_condition_keys) =
            match evaluate_grant_condition(condition_json.as_deref(), condition_ctx) {
                Some(outcome) => outcome,
                None => continue,
            };

        raw.push(EntityRef {
            arn,
            name,
            entity_type,
            is_full_admin,
            resource: perm_resource,
            is_bounded,
            conditional,
            unevaluated_condition_keys,
        });
    }

    // Deduplicate by ARN (UNION arms can return the same entity via different paths).
    // If an entity appears as both specific-action and full-admin, keep is_full_admin: true.
    // ponytail: an entity is conditional only if every surviving grant for it is conditional
    // (AND across duplicates, union of keys) — a second, unconditional grant to the same
    // action makes the entity's access unconditional overall. Refine only if a real case
    // needs per-grant tracking instead of this per-entity approximation.
    let mut by_arn: std::collections::HashMap<String, EntityRef> = std::collections::HashMap::new();
    for entity in raw {
        by_arn
            .entry(entity.arn.clone())
            .and_modify(|entry| {
                if entity.is_full_admin {
                    entry.is_full_admin = true;
                }
                entry.conditional = entry.conditional && entity.conditional;
                for key in &entity.unevaluated_condition_keys {
                    if !entry.unevaluated_condition_keys.contains(key) {
                        entry.unevaluated_condition_keys.push(key.clone());
                    }
                }
            })
            .or_insert(entity);
    }
    let mut results: Vec<EntityRef> = by_arn.into_values().collect();
    results.sort_by(|a, b| a.arn.cmp(&b.arn));
    Ok(results)
}

/// Evaluate a grant's stored `Condition` JSON against query context.
///
/// Returns `None` when the grant is excluded (a supported condition key evaluated false —
/// e.g. `--mfa false` against an `aws:MultiFactorAuthPresent: true` grant), otherwise
/// `Some((conditional, unevaluated_keys))`.
fn evaluate_grant_condition(
    condition_json: Option<&str>,
    ctx: &ConditionContext,
) -> Option<(bool, Vec<String>)> {
    let Some(condition_json) = condition_json else {
        return Some((false, Vec::new()));
    };
    let parsed: iam_models::Condition = match serde_json::from_str(condition_json) {
        Ok(c) => c,
        // Unparseable stored condition — treat as unevaluated rather than dropping the grant.
        Err(_) => return Some((true, vec!["<unparseable>".to_string()])),
    };
    match condition::evaluate(&parsed, ctx) {
        ConditionOutcome::Unconditional => Some((false, Vec::new())),
        ConditionOutcome::Excluded => None,
        ConditionOutcome::Conditional { unevaluated_keys } => Some((true, unevaluated_keys)),
    }
}

const ENTITY_PERMISSIONS_QUERY: &str = include_str!("../../queries/entity_permissions.cypher");

/// A boundary Allow entry: an exact/wildcard action, or a full-admin / allow-all-except
/// sentinel (`action == "*"`) with an optional `excluded_actions` set.
struct BoundaryEntry {
    action: String,
    excluded_actions: Option<Vec<String>>,
}

/// True if `action` is covered by any boundary Allow entry — exact/wildcard match, a true
/// full-admin boundary (`action == "*"`, no exclusions), or an allow-all-except boundary
/// (`action == "*"` with exclusions, action not excluded).
fn boundary_allows(entries: &[BoundaryEntry], action: &str) -> bool {
    entries.iter().any(|entry| {
        if entry.action == "*" {
            match &entry.excluded_actions {
                None => true,
                Some(excluded) => !excluded.iter().any(|excluded| excluded == action),
            }
        } else {
            iam_expander::glob_match(&entry.action, action)
        }
    })
}

/// Return all permissions for a specific entity UID. Allow rows carry `effective: false` when
/// capped by the entity's Permission Boundary (see limitations.md).
pub async fn entity_permissions(
    graph: &Graph,
    ctx: &QueryContext,
    entity_uid: &str,
) -> Result<Vec<PermissionRow>, GraphError> {
    let mut boundary_stream = graph
        .execute(
            neo4rs::query(ENTITY_BOUNDARY_ACTIONS_QUERY)
                .param("uid", entity_uid)
                .param("snapshot_id", ctx.snapshot_id.as_str()),
        )
        .await?;

    let mut boundary_entries = Vec::new();
    while let Some(row) = boundary_stream.next().await? {
        let action: String = col(&row, "action")?;
        let excluded_actions: Option<Vec<String>> = col(&row, "excluded_actions")?;
        boundary_entries.push(BoundaryEntry {
            action,
            excluded_actions,
        });
    }
    let is_bounded = !boundary_entries.is_empty();

    let mut stream = graph
        .execute(
            neo4rs::query(ENTITY_PERMISSIONS_QUERY)
                .param("uid", entity_uid)
                .param("snapshot_id", ctx.snapshot_id.as_str()),
        )
        .await?;

    let mut results = Vec::new();
    while let Some(row) = stream.next().await? {
        let action: String = col(&row, "action")?;
        let effect: String = col(&row, "effect")?;
        let resource: String = col(&row, "resource")?;
        let effective =
            effect != "Allow" || !is_bounded || boundary_allows(&boundary_entries, &action);
        results.push(PermissionRow {
            action,
            effect,
            resource,
            effective,
        });
    }
    Ok(results)
}

const INSTANCE_PROFILES_WITH_ACTION_QUERY: &str =
    include_str!("../../queries/instance_profiles_with_action.cypher");

/// Return instance profiles whose associated roles grant the given action.
pub async fn instance_profiles_with_action(
    graph: &Graph,
    ctx: &QueryContext,
    action: &str,
) -> Result<Vec<EntityRef>, GraphError> {
    collect_instance_profile_refs(
        graph,
        neo4rs::query(INSTANCE_PROFILES_WITH_ACTION_QUERY)
            .param("action", action)
            .param("snapshot_id", ctx.snapshot_id.as_str())
            .param("account_id", ctx.account_id.as_str()),
    )
    .await
}

const RISKY_INSTANCE_PROFILES_QUERY: &str =
    include_str!("../../queries/risky_instance_profiles.cypher");

/// Return instance profiles whose roles have privilege-escalation permissions,
/// including the specific risky actions found.
pub async fn risky_instance_profiles(
    graph: &Graph,
    ctx: &QueryContext,
) -> Result<Vec<RiskyInstanceProfile>, GraphError> {
    let mut stream = graph
        .execute(
            neo4rs::query(RISKY_INSTANCE_PROFILES_QUERY)
                .param("account_id", ctx.account_id.as_str())
                .param("snapshot_id", ctx.snapshot_id.as_str()),
        )
        .await?;

    let mut results = Vec::new();
    while let Some(row) = stream.next().await? {
        let arn: String = col(&row, "arn")?;
        let name: String = col(&row, "name")?;
        let risky_actions: Vec<String> = col(&row, "risky_actions")?;
        results.push(RiskyInstanceProfile {
            arn,
            name,
            entity_type: "InstanceProfile".to_string(),
            risky_actions,
        });
    }
    Ok(results)
}

async fn collect_instance_profile_refs(
    graph: &Graph,
    query: neo4rs::Query,
) -> Result<Vec<EntityRef>, GraphError> {
    let mut stream = graph.execute(query).await?;
    let mut results = Vec::new();
    while let Some(row) = stream.next().await? {
        let arn: String = col(&row, "arn")?;
        let name: String = col(&row, "name")?;
        results.push(EntityRef {
            arn,
            name,
            entity_type: "InstanceProfile".to_string(),
            is_full_admin: false,
            resource: String::new(),
            is_bounded: false,
            conditional: false,
            unevaluated_condition_keys: Vec::new(),
        });
    }
    Ok(results)
}
