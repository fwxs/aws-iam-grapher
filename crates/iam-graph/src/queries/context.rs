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
