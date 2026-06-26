/// Mandatory filter context for all analysis queries.
/// Prevents cross-account and cross-snapshot data leakage.
#[derive(Debug, Clone)]
pub struct QueryContext {
    /// UUID of the specific snapshot to query.
    pub snapshot_id: String,
    /// AWS account ID this snapshot belongs to.
    pub account_id: String,
}

impl QueryContext {
    /// Create a new context.
    pub fn new(snapshot_id: impl Into<String>, account_id: impl Into<String>) -> Self {
        Self {
            snapshot_id: snapshot_id.into(),
            account_id: account_id.into(),
        }
    }
}

/// Query context for org-wide queries that span multiple account snapshots.
///
/// Uses `org_collection_run_id` as the isolation boundary instead of `(account_id,
/// snapshot_id)`. All snapshots in one org run share the same `org_run_id`, making
/// cross-account traversal possible without cross-tenant leakage.
#[derive(Debug, Clone)]
pub struct OrgQueryContext {
    /// Org collection run id shared by all per-account snapshots in one `collect org` run.
    pub org_run_id: String,
}

impl OrgQueryContext {
    /// Create a new org-scoped query context.
    pub fn new(org_run_id: impl Into<String>) -> Self {
        Self {
            org_run_id: org_run_id.into(),
        }
    }
}
