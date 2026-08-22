pub mod accounts;
pub mod analysis;
pub mod caveats;
pub mod context;
pub mod escalation;
pub mod escalation_enrichment;
pub mod org_escalation;
pub mod scope;
pub mod snapshots;
pub mod stitch;

use crate::errors::GraphError;

/// Default `CAN_ASSUME_ROLE` traversal depth when the caller doesn't specify one.
pub const DEFAULT_MAX_HOPS: u32 = 3;

/// Upper bound on traversal depth to keep variable-length path matching bounded on
/// dense `CAN_ASSUME_ROLE` graphs.
pub const MAX_HOPS_CAP: u32 = 10;

/// The ONLY sanctioned string interpolation into Cypher in this crate.
/// Variable-length relationship bounds cannot be parameterized; `hops` is
/// clamped to an integer here, making injection impossible by type.
/// Do not add other interpolation helpers — use query parameters instead.
pub(crate) fn render_hop_bound(template: &'static str, hops: u32) -> String {
    let hops = hops.clamp(1, MAX_HOPS_CAP);
    debug_assert!(
        template.contains("{max_hops}"),
        "template missing {{max_hops}} placeholder"
    );
    template.replace("{max_hops}", &hops.to_string())
}

/// Extract a required column from a `Row`, folding a missing/mistyped column into
/// [`GraphError::RowDecode`] with the column name attached — `neo4rs`'s own
/// deserialization error (e.g. "The property does not exist") doesn't name the column.
pub(crate) fn col<'r, T>(row: &'r neo4rs::Row, name: &'static str) -> Result<T, GraphError>
where
    T: serde::Deserialize<'r>,
{
    row.get(name).map_err(|e| GraphError::RowDecode {
        column: name,
        source: e,
    })
}

pub use accounts::{list_accounts, AccountRecord};
pub use analysis::{
    associated_entities, entity_permissions, instance_profiles_with_action, who_can,
    AssociatedEntity, EntityRef, PermissionRow,
};
pub use caveats::{Caveat, CaveatCode};
pub use context::{OrgQueryContext, QueryContext};
pub use escalation::{privilege_escalation_paths, EscalationPath, Hop};
pub use escalation_enrichment::{Holder, InstanceProfileRef, TrustPrincipal};
pub use org_escalation::{org_escalation_paths, OrgEscalationPath, OrgHop};
pub use scope::{resolve_org_context, resolve_scopes, ResolvedScope, ScopeSelector};
pub use snapshots::{
    delete_snapshot, diff_permissions, latest_org_run_id, list_account_ids, list_snapshots,
    snapshot_record, snapshots_for_org_run, PermissionDiff, PermissionRecord, SnapshotRecord,
};
pub use stitch::stitch_cross_account;

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_TEMPLATE: &str = "MATCH ()-[:R*1..{max_hops}]->() RETURN 1";

    #[test]
    fn render_hop_bound_zero_clamps_to_one() {
        let cypher = render_hop_bound(TEST_TEMPLATE, 0);

        assert_eq!(cypher, "MATCH ()-[:R*1..1]->() RETURN 1");
    }

    #[test]
    fn render_hop_bound_max_u32_clamps_to_cap() {
        let cypher = render_hop_bound(TEST_TEMPLATE, u32::MAX);

        assert_eq!(
            cypher,
            format!("MATCH ()-[:R*1..{MAX_HOPS_CAP}]->() RETURN 1")
        );
    }

    #[test]
    fn render_hop_bound_matches_manual_clamp_and_replace() {
        let hops = 5;
        let expected =
            TEST_TEMPLATE.replace("{max_hops}", &hops.clamp(1, MAX_HOPS_CAP).to_string());

        let cypher = render_hop_bound(TEST_TEMPLATE, hops);

        assert_eq!(cypher, expected);
    }

    #[test]
    #[should_panic(expected = "template missing")]
    fn render_hop_bound_missing_placeholder_panics_in_debug() {
        render_hop_bound("MATCH () RETURN 1", 3);
    }
}
