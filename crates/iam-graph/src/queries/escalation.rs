use crate::errors::GraphError;
use crate::queries::col;
use crate::queries::context::QueryContext;
use neo4rs::Graph;
use std::collections::HashMap;

/// Default `CAN_ASSUME_ROLE` traversal depth when the caller doesn't specify one.
pub const DEFAULT_MAX_HOPS: u32 = 3;

/// Upper bound on traversal depth to keep variable-length path matching bounded on
/// dense `CAN_ASSUME_ROLE` graphs.
pub const MAX_HOPS_CAP: u32 = 10;

/// One hop in an escalation path — the ARN and entity-type label of a node on the chain.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Hop {
    pub arn: String,
    pub entity_type: String,
}

/// An entity that has known privilege-escalation permissions, directly or via a
/// transitive `sts:AssumeRole` chain.
#[derive(Debug, Clone, serde::Serialize)]
pub struct EscalationPath {
    pub arn: String,
    pub name: String,
    pub entity_type: String,
    pub risky_actions: Vec<String>,
    /// Ordered chain from `arn` to the entity that holds `risky_actions`.
    /// A single-element path means the entity holds the risky permissions directly.
    pub path: Vec<Hop>,
    /// `true` if any `CAN_ASSUME_ROLE` hop on `path` carries an unevaluated
    /// runtime trust condition — the path may not hold at runtime.
    pub conditional: bool,
}

const ESCALATION_QUERY: &str = include_str!("../../queries/privilege_escalation_paths.cypher");

/// Return all entities with at least one privilege-escalation permission, reachable
/// directly or transitively via up to `max_hops` `sts:AssumeRole` hops.
///
/// `max_hops` is clamped to `[1, MAX_HOPS_CAP]` and interpolated as a literal integer
/// into the Cypher text, since variable-length relationship bounds can't be parameterized.
pub async fn privilege_escalation_paths(
    graph: &Graph,
    ctx: &QueryContext,
    max_hops: u32,
) -> Result<Vec<EscalationPath>, GraphError> {
    let max_hops = max_hops.clamp(1, MAX_HOPS_CAP);
    let cypher = ESCALATION_QUERY.replace("{max_hops}", &max_hops.to_string());

    let mut stream = graph
        .execute(
            neo4rs::query(&cypher)
                .param("account_id", ctx.account_id.as_str())
                .param("snapshot_id", ctx.snapshot_id.as_str()),
        )
        .await?;

    struct Candidate {
        name: String,
        entity_type: String,
        allowed_actions: Vec<String>,
        deny_actions: Vec<String>,
        path: Vec<Hop>,
        conditional: bool,
    }

    // Dedupe by arn across the direct and transitive UNION arms, keeping the shortest
    // path (a direct/self path always wins over a longer transitive one to the same entity).
    let mut by_arn: HashMap<String, Candidate> = HashMap::new();

    while let Some(row) = stream.next().await? {
        let arn: String = col(&row, "arn")?;
        let name: String = col(&row, "name")?;
        let entity_type: String = col(&row, "entity_type")?;
        let allowed_actions: Vec<String> = col(&row, "allowed_actions")?;
        let deny_actions: Vec<String> = col(&row, "deny_actions")?;
        let path: Vec<Hop> = col(&row, "path")?;
        let conditional: bool = col(&row, "conditional")?;

        match by_arn.get(&arn) {
            Some(existing) if existing.path.len() <= path.len() => {}
            _ => {
                by_arn.insert(
                    arn,
                    Candidate {
                        name,
                        entity_type,
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
        // Wildcard- and group-Deny-aware suppression: drop any allowed action covered by
        // a Deny (exact, wildcard, or full-admin) on the terminal entity's own or a member
        // group's policies.
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

        results.push(EscalationPath {
            arn,
            name: candidate.name,
            entity_type: candidate.entity_type,
            risky_actions,
            path: candidate.path,
            conditional: candidate.conditional,
        });
    }
    Ok(results)
}
