use crate::errors::GraphError;
use crate::queries::context::QueryContext;
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
}

/// A single permission row with named fields.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct PermissionRow {
    pub action: String,
    pub effect: String,
    pub resource: String,
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
        let action: String = row
            .get("action")
            .map_err(|e| GraphError::UnexpectedResult(e.to_string()))?;
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
) -> Result<Vec<EntityRef>, GraphError> {
    let candidates = candidate_deny_actions(graph, ctx).await?;
    let deny_actions: Vec<String> = candidates
        .into_iter()
        .filter(|candidate| iam_expander::glob_match(candidate, action))
        .collect();

    let mut stream = graph
        .execute(
            neo4rs::query(WHO_CAN_QUERY)
                .param("action", action)
                .param("snapshot_id", ctx.snapshot_id.as_str())
                .param("account_id", ctx.account_id.as_str())
                .param("deny_actions", deny_actions),
        )
        .await?;

    let mut raw: Vec<EntityRef> = Vec::new();
    while let Some(row) = stream.next().await? {
        let arn: String = row
            .get("arn")
            .map_err(|e| GraphError::UnexpectedResult(e.to_string()))?;
        let name: String = row
            .get("name")
            .map_err(|e| GraphError::UnexpectedResult(e.to_string()))?;
        let entity_type: String = row
            .get("entity_type")
            .map_err(|e| GraphError::UnexpectedResult(e.to_string()))?;
        let is_full_admin: bool = row
            .get("is_full_admin")
            .map_err(|e| GraphError::UnexpectedResult(e.to_string()))?;
        let perm_resource: String = row
            .get("resource")
            .map_err(|e| GraphError::UnexpectedResult(e.to_string()))?;
        let grant_kind: String = row
            .get("grant_kind")
            .map_err(|e| GraphError::UnexpectedResult(e.to_string()))?;

        // Only wildcard (action='*') grants are resource-scoped intersection candidates;
        // exact-action grants always pass through.
        if let Some(queried_resource) = resource {
            if grant_kind == "wildcard"
                && !iam_expander::glob_match(&perm_resource, queried_resource)
            {
                continue;
            }
        }

        raw.push(EntityRef {
            arn,
            name,
            entity_type,
            is_full_admin,
            resource: perm_resource,
        });
    }

    // Deduplicate by ARN (UNION arms can return the same entity via different paths).
    // If an entity appears as both specific-action and full-admin, keep is_full_admin: true.
    let mut by_arn: std::collections::HashMap<String, EntityRef> = std::collections::HashMap::new();
    for entity in raw {
        let entry = by_arn
            .entry(entity.arn.clone())
            .or_insert_with(|| entity.clone());
        if entity.is_full_admin {
            entry.is_full_admin = true;
        }
    }
    let mut results: Vec<EntityRef> = by_arn.into_values().collect();
    results.sort_by(|a, b| a.arn.cmp(&b.arn));
    Ok(results)
}

const ENTITY_PERMISSIONS_QUERY: &str = include_str!("../../queries/entity_permissions.cypher");

/// Return all permissions for a specific entity UID.
pub async fn entity_permissions(
    graph: &Graph,
    ctx: &QueryContext,
    entity_uid: &str,
) -> Result<Vec<PermissionRow>, GraphError> {
    let mut stream = graph
        .execute(
            neo4rs::query(ENTITY_PERMISSIONS_QUERY)
                .param("uid", entity_uid)
                .param("snapshot_id", ctx.snapshot_id.as_str()),
        )
        .await?;

    let mut results = Vec::new();
    while let Some(row) = stream.next().await? {
        let action: String = row
            .get("action")
            .map_err(|e| GraphError::UnexpectedResult(e.to_string()))?;
        let effect: String = row
            .get("effect")
            .map_err(|e| GraphError::UnexpectedResult(e.to_string()))?;
        let resource: String = row
            .get("resource")
            .map_err(|e| GraphError::UnexpectedResult(e.to_string()))?;
        results.push(PermissionRow {
            action,
            effect,
            resource,
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
        let arn: String = row
            .get("arn")
            .map_err(|e| GraphError::UnexpectedResult(e.to_string()))?;
        let name: String = row
            .get("name")
            .map_err(|e| GraphError::UnexpectedResult(e.to_string()))?;
        let risky_actions: Vec<String> = row
            .get("risky_actions")
            .map_err(|e| GraphError::UnexpectedResult(e.to_string()))?;
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
        let arn: String = row
            .get("arn")
            .map_err(|e| GraphError::UnexpectedResult(e.to_string()))?;
        let name: String = row
            .get("name")
            .map_err(|e| GraphError::UnexpectedResult(e.to_string()))?;
        results.push(EntityRef {
            arn,
            name,
            entity_type: "InstanceProfile".to_string(),
            is_full_admin: false,
            resource: String::new(),
        });
    }
    Ok(results)
}
