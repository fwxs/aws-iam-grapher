use crate::errors::GraphError;
use crate::queries::context::{OrgQueryContext, QueryContext};
use crate::queries::snapshots::{
    latest_org_run_id, list_account_ids, list_snapshots, snapshot_account_id,
};
use neo4rs::Graph;

/// How the caller wants a query scoped.
pub enum ScopeSelector {
    /// Explicit snapshot. The owning account is derived from the graph; if
    /// `expected_account` is `Some` and differs from the derived owner, resolution
    /// fails with `GraphError::AccountMismatch`.
    Snapshot {
        snapshot_id: String,
        expected_account: Option<String>,
    },
    /// Latest snapshot of one account.
    Account { account_id: String },
    /// Latest snapshot of every account that has one (fan-out).
    AllAccounts,
}

/// Resolve a selector into one or more concrete [`QueryContext`]s.
pub async fn resolve_contexts(
    graph: &Graph,
    selector: ScopeSelector,
) -> Result<Vec<QueryContext>, GraphError> {
    match selector {
        ScopeSelector::Snapshot {
            snapshot_id,
            expected_account,
        } => {
            let actual = snapshot_account_id(graph, &snapshot_id)
                .await?
                .ok_or_else(|| GraphError::SnapshotNotFound(snapshot_id.clone()))?;

            if let Some(expected) = expected_account {
                if expected != actual {
                    return Err(GraphError::AccountMismatch {
                        snapshot_id,
                        expected,
                        actual,
                    });
                }
            }

            Ok(vec![QueryContext::new(snapshot_id, actual)])
        }

        ScopeSelector::Account { account_id } => {
            let latest = list_snapshots(graph, &account_id)
                .await?
                .into_iter()
                .next()
                .ok_or_else(|| GraphError::NoSnapshotsForAccount(account_id.clone()))?;

            Ok(vec![QueryContext::new(latest.id, account_id)])
        }

        ScopeSelector::AllAccounts => {
            let accounts = list_account_ids(graph).await?;
            if accounts.is_empty() {
                return Err(GraphError::NoSnapshots);
            }

            let mut contexts = Vec::with_capacity(accounts.len());
            for account_id in accounts {
                let latest = list_snapshots(graph, &account_id)
                    .await?
                    .into_iter()
                    .next()
                    .ok_or_else(|| GraphError::NoSnapshotsForAccount(account_id.clone()))?;
                contexts.push(QueryContext::new(latest.id, account_id));
            }
            Ok(contexts)
        }
    }
}

/// Resolve the org scope: explicit `org_run_id` or the most recent org run.
pub async fn resolve_org_context(
    graph: &Graph,
    org_run_id: Option<String>,
) -> Result<OrgQueryContext, GraphError> {
    let run_id = match org_run_id {
        Some(id) => id,
        None => latest_org_run_id(graph)
            .await?
            .ok_or(GraphError::NoOrgRuns)?,
    };
    Ok(OrgQueryContext::new(run_id))
}
