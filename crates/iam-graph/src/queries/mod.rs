pub mod accounts;
pub mod analysis;
pub mod context;
pub mod escalation;
pub mod org_escalation;
pub mod scope;
pub mod snapshots;
pub mod stitch;

use crate::errors::GraphError;

/// Extract a required column from a `Row`, folding a missing/mistyped column into
/// [`GraphError::UnexpectedResult`] with the column name attached — `neo4rs`'s own
/// deserialization error (e.g. "The property does not exist") doesn't name the column.
pub(crate) fn col<'r, T>(row: &'r neo4rs::Row, name: &'static str) -> Result<T, GraphError>
where
    T: serde::Deserialize<'r>,
{
    row.get(name)
        .map_err(|e| GraphError::UnexpectedResult(format!("column `{name}`: {e}")))
}

/// Extract a column that is legitimately absent for some rows, falling back to
/// `T::default()`. Only call this where the caller has documented *why* absence is a valid
/// data-model state (see call sites) — everywhere else, use [`col`] so malformed rows fail
/// loudly instead of silently becoming empty values.
pub(crate) fn col_or_default<'r, T>(row: &'r neo4rs::Row, name: &'static str) -> T
where
    T: serde::Deserialize<'r> + Default,
{
    row.get(name).unwrap_or_default()
}

pub use accounts::{list_accounts, AccountRecord};
pub use analysis::{
    entity_permissions, instance_profiles_with_action, risky_instance_profiles, who_can, EntityRef,
    PermissionRow, RiskyInstanceProfile,
};
pub use context::{OrgQueryContext, QueryContext};
pub use escalation::{
    privilege_escalation_paths, EscalationPath, Hop, DEFAULT_MAX_HOPS, MAX_HOPS_CAP,
};
pub use org_escalation::{org_escalation_paths, OrgEscalationPath, OrgHop};
pub use scope::{resolve_org_context, resolve_scopes, ResolvedScope, ScopeSelector};
pub use snapshots::{
    delete_snapshot, diff_permissions, latest_org_run_id, list_account_ids, list_snapshots,
    snapshot_account_id, snapshot_record, PermissionDiff, PermissionRecord, SnapshotRecord,
};
pub use stitch::stitch_cross_account;
