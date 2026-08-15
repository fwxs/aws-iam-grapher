use crate::errors::GraphError;
use crate::queries::context::{OrgQueryContext, QueryContext};
use crate::queries::snapshots::{
    latest_org_run_id, list_account_ids, list_snapshots, snapshot_record, SnapshotRecord,
};
use neo4rs::Graph;

/// How the caller wants a query scoped.
#[non_exhaustive]
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

impl ScopeSelector {
    /// An explicit snapshot scope. See [`ScopeSelector::Snapshot`].
    pub fn snapshot(snapshot_id: impl Into<String>, expected_account: Option<String>) -> Self {
        Self::Snapshot {
            snapshot_id: snapshot_id.into(),
            expected_account,
        }
    }

    /// The latest snapshot of one account. See [`ScopeSelector::Account`].
    pub fn account(account_id: impl Into<String>) -> Self {
        Self::Account {
            account_id: account_id.into(),
        }
    }

    /// The latest snapshot of every account. See [`ScopeSelector::AllAccounts`].
    pub fn all_accounts() -> Self {
        Self::AllAccounts
    }
}

/// A resolved query scope: the `QueryContext` to filter on, plus the full snapshot record
/// it was pinned to (carries `is_partial`/`partial_reasons` so callers never need a second
/// `list_snapshots` round trip just to render a partial-snapshot warning).
#[derive(Debug, Clone)]
pub struct ResolvedScope {
    pub context: QueryContext,
    pub snapshot: SnapshotRecord,
}

/// Resolve a selector into one or more concrete [`ResolvedScope`]s.
pub async fn resolve_scopes(
    graph: &Graph,
    selector: ScopeSelector,
) -> Result<Vec<ResolvedScope>, GraphError> {
    match selector {
        ScopeSelector::Snapshot {
            snapshot_id,
            expected_account,
        } => {
            let snapshot = snapshot_record(graph, &snapshot_id)
                .await?
                .ok_or_else(|| GraphError::SnapshotNotFound(snapshot_id.clone()))?;

            if let Some(expected) = expected_account {
                if expected != snapshot.account_id {
                    return Err(GraphError::AccountMismatch {
                        snapshot_id,
                        expected,
                        actual: snapshot.account_id,
                    });
                }
            }

            let context = QueryContext::new(snapshot.id.clone(), snapshot.account_id.clone());
            Ok(vec![ResolvedScope { context, snapshot }])
        }

        ScopeSelector::Account { account_id } => {
            let snapshot = list_snapshots(graph, &account_id)
                .await?
                .into_iter()
                .next()
                .ok_or_else(|| GraphError::NoSnapshotsForAccount(account_id.clone()))?;

            let context = QueryContext::new(snapshot.id.clone(), account_id);
            Ok(vec![ResolvedScope { context, snapshot }])
        }

        ScopeSelector::AllAccounts => {
            let accounts = list_account_ids(graph).await?;
            if accounts.is_empty() {
                return Err(GraphError::NoSnapshots);
            }

            let mut scopes = Vec::with_capacity(accounts.len());
            for account_id in accounts {
                // list_account_ids only returns accounts with >=1 snapshot, so this
                // is unreachable today; kept as a defensive guard against that
                // invariant changing rather than an unwrap.
                let snapshot = list_snapshots(graph, &account_id)
                    .await?
                    .into_iter()
                    .next()
                    .ok_or_else(|| GraphError::NoSnapshotsForAccount(account_id.clone()))?;
                let context = QueryContext::new(snapshot.id.clone(), account_id);
                scopes.push(ResolvedScope { context, snapshot });
            }
            Ok(scopes)
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
