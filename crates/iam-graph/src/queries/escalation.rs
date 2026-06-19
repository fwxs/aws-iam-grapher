use crate::errors::GraphError;
use crate::queries::context::QueryContext;
use neo4rs::Graph;

/// An entity that has known privilege-escalation permissions.
#[derive(Debug, Clone, serde::Serialize)]
pub struct EscalationPath {
    pub arn: String,
    pub name: String,
    pub entity_type: String,
    pub risky_actions: Vec<String>,
}

const ESCALATION_QUERY: &str = include_str!("../../queries/privilege_escalation_paths.cypher");

/// Return all entities with at least one privilege-escalation permission.
pub async fn privilege_escalation_paths(
    graph: &Graph,
    ctx: &QueryContext,
) -> Result<Vec<EscalationPath>, GraphError> {
    let mut stream = graph
        .execute(
            neo4rs::query(ESCALATION_QUERY)
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
        let entity_type: String = row
            .get("entity_type")
            .map_err(|e| GraphError::UnexpectedResult(e.to_string()))?;
        let allowed_actions: Vec<String> = row
            .get("allowed_actions")
            .map_err(|e| GraphError::UnexpectedResult(e.to_string()))?;
        let deny_actions: Vec<String> = row
            .get("deny_actions")
            .map_err(|e| GraphError::UnexpectedResult(e.to_string()))?;

        // Wildcard- and group-Deny-aware suppression: drop any allowed action covered by
        // a Deny (exact, wildcard, or full-admin) on the entity's own or a member group's policies.
        let risky_actions: Vec<String> = allowed_actions
            .into_iter()
            .filter(|action| {
                !deny_actions
                    .iter()
                    .any(|deny| iam_expander::glob_match(deny, action))
            })
            .collect();

        if risky_actions.is_empty() {
            continue;
        }

        results.push(EscalationPath {
            arn,
            name,
            entity_type,
            risky_actions,
        });
    }
    Ok(results)
}
