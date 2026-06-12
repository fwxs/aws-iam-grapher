use crate::errors::GraphError;
use crate::queries::context::QueryContext;
use neo4rs::Graph;

/// Reference to an IAM entity returned by analysis queries.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct EntityRef {
    pub arn: String,
    pub name: String,
    pub entity_type: String,
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

const WHO_CAN_QUERY: &str = "
    MATCH (e)-[:HAS_ATTACHED_POLICY|HAS_INLINE_POLICY*1..2]->(pol)
          -[:GRANTS]->(perm:Permission {
              action: $action,
              effect: 'Allow',
              snapshot_id: $snapshot_id
          })
    WHERE e.account_id = $account_id
    RETURN e.arn AS arn, e.name AS name, labels(e)[0] AS entity_type
    UNION
    MATCH (u:User)-[:MEMBER_OF]->(g:Group)
          -[:HAS_ATTACHED_POLICY|HAS_INLINE_POLICY*1..2]->(pol)
          -[:GRANTS]->(perm:Permission {
              action: $action,
              effect: 'Allow',
              snapshot_id: $snapshot_id
          })
    WHERE u.account_id = $account_id
    RETURN u.arn AS arn, u.name AS name, labels(u)[0] AS entity_type
";

/// Return all entities that have permission to perform `action` in this snapshot.
pub async fn who_can(
    graph: &Graph,
    ctx: &QueryContext,
    action: &str,
) -> Result<Vec<EntityRef>, GraphError> {
    let mut stream = graph
        .execute(
            neo4rs::query(WHO_CAN_QUERY)
                .param("action", action)
                .param("snapshot_id", ctx.snapshot_id.as_str())
                .param("account_id", ctx.account_id.as_str()),
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
        let entity_type: String = row
            .get("entity_type")
            .map_err(|e| GraphError::UnexpectedResult(e.to_string()))?;
        results.push(EntityRef {
            arn,
            name,
            entity_type,
        });
    }
    Ok(results)
}

const ENTITY_PERMISSIONS_QUERY: &str = "
    MATCH (e {uid: $uid})-[:HAS_ATTACHED_POLICY|HAS_INLINE_POLICY*1..2]->(pol)
          -[:GRANTS]->(perm:Permission {snapshot_id: $snapshot_id})
    RETURN perm.action AS action, perm.effect AS effect, perm.resource AS resource
";

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

const INSTANCE_PROFILES_WITH_ACTION_QUERY: &str = "
    MATCH (ip:InstanceProfile {account_id: $account_id, snapshot_id: $snapshot_id})
          -[:CONTAINS_ROLE]->(r:Role)
          -[:HAS_ATTACHED_POLICY|HAS_INLINE_POLICY*1..2]->(pol)
          -[:GRANTS]->(perm:Permission {
              action: $action,
              effect: 'Allow',
              snapshot_id: $snapshot_id
          })
    RETURN DISTINCT ip.arn AS arn, ip.name AS name
";

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

const RISKY_INSTANCE_PROFILES_QUERY: &str = "
    MATCH (ip:InstanceProfile {account_id: $account_id, snapshot_id: $snapshot_id})
          -[:CONTAINS_ROLE]->(r:Role)
          -[:HAS_ATTACHED_POLICY|HAS_INLINE_POLICY*1..2]->(pol)
          -[:GRANTS]->(perm:Permission {effect: 'Allow', snapshot_id: $snapshot_id})
    WHERE perm.action IN [
        'iam:CreatePolicyVersion', 'iam:SetDefaultPolicyVersion',
        'iam:AttachRolePolicy', 'iam:AttachUserPolicy',
        'iam:PassRole', 'iam:PutRolePolicy', 'iam:PutUserPolicy',
        'iam:CreateAccessKey', 'iam:CreateLoginProfile'
    ]
    RETURN ip.arn AS arn, ip.name AS name, collect(perm.action) AS risky_actions
";

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
        });
    }
    Ok(results)
}
