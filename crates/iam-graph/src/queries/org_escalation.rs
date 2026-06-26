use crate::errors::GraphError;
use crate::queries::context::OrgQueryContext;
use neo4rs::Graph;
use std::collections::HashMap;

pub use crate::queries::escalation::{DEFAULT_MAX_HOPS, MAX_HOPS_CAP};

/// One hop in a cross-account escalation path — includes `account_id` for account labeling.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct OrgHop {
    pub arn: String,
    pub entity_type: String,
    pub account_id: String,
}

/// An entity that can reach risky IAM permissions via a transitive `sts:AssumeRole` chain
/// that crosses at least one account boundary within an org collection run.
#[derive(Debug, Clone, serde::Serialize)]
pub struct OrgEscalationPath {
    pub arn: String,
    pub name: String,
    pub entity_type: String,
    pub account_id: String,
    pub risky_actions: Vec<String>,
    /// Ordered chain from `arn` to the entity holding `risky_actions`, with per-hop account ids.
    pub path: Vec<OrgHop>,
    /// `true` if any `CAN_ASSUME_ROLE` hop carries an unevaluated runtime trust condition.
    pub conditional: bool,
}

const ORG_ESCALATION_QUERY: &str = include_str!("../../queries/org_escalation_paths.cypher");

/// Return all cross-account escalation paths within the given org collection run.
///
/// `max_hops` is clamped to `[1, MAX_HOPS_CAP]` and interpolated as a literal integer into
/// the Cypher text (variable-length relationship bounds cannot be parameterized in Cypher).
/// Results are deduped by start entity ARN, keeping the shortest path per entity.
pub async fn org_escalation_paths(
    graph: &Graph,
    ctx: &OrgQueryContext,
    max_hops: u32,
) -> Result<Vec<OrgEscalationPath>, GraphError> {
    let max_hops = max_hops.clamp(1, MAX_HOPS_CAP);
    let cypher = ORG_ESCALATION_QUERY.replace("{max_hops}", &max_hops.to_string());

    let mut stream = graph
        .execute(neo4rs::query(&cypher).param("org_run_id", ctx.org_run_id.as_str()))
        .await?;

    struct Candidate {
        name: String,
        entity_type: String,
        account_id: String,
        allowed_actions: Vec<String>,
        deny_actions: Vec<String>,
        path: Vec<OrgHop>,
        conditional: bool,
    }

    let mut by_arn: HashMap<String, Candidate> = HashMap::new();

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
        let account_id: String = row
            .get("account_id")
            .map_err(|e| GraphError::UnexpectedResult(e.to_string()))?;
        let allowed_actions: Vec<String> = row
            .get("allowed_actions")
            .map_err(|e| GraphError::UnexpectedResult(e.to_string()))?;
        let deny_actions: Vec<String> = row
            .get("deny_actions")
            .map_err(|e| GraphError::UnexpectedResult(e.to_string()))?;
        let path: Vec<OrgHop> = row
            .get("path")
            .map_err(|e| GraphError::UnexpectedResult(e.to_string()))?;
        let conditional: bool = row
            .get("conditional")
            .map_err(|e| GraphError::UnexpectedResult(e.to_string()))?;

        match by_arn.get(&arn) {
            Some(existing) if existing.path.len() <= path.len() => {}
            _ => {
                by_arn.insert(
                    arn,
                    Candidate {
                        name,
                        entity_type,
                        account_id,
                        allowed_actions,
                        deny_actions,
                        path,
                        conditional,
                    },
                );
            }
        }
    }

    let mut results = Vec::new();
    for (arn, candidate) in by_arn {
        let risky_actions: Vec<String> = candidate
            .allowed_actions
            .into_iter()
            .filter(|action| {
                !candidate
                    .deny_actions
                    .iter()
                    .any(|deny| iam_expander::glob_match(deny, action))
            })
            .collect();

        if risky_actions.is_empty() {
            continue;
        }

        results.push(OrgEscalationPath {
            arn,
            name: candidate.name,
            entity_type: candidate.entity_type,
            account_id: candidate.account_id,
            risky_actions,
            path: candidate.path,
            conditional: candidate.conditional,
        });
    }
    Ok(results)
}
