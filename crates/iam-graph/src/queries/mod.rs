pub mod analysis;
pub mod context;
pub mod escalation;
pub mod snapshots;

pub use analysis::{
    entity_permissions, instance_profiles_with_action, risky_instance_profiles, who_can, EntityRef,
    PermissionRow, RiskyInstanceProfile,
};
pub use context::QueryContext;
pub use escalation::{
    privilege_escalation_paths, EscalationPath, Hop, DEFAULT_MAX_HOPS, MAX_HOPS_CAP,
};
pub use snapshots::{
    delete_snapshot, diff_permissions, list_snapshots, PermissionDiff, PermissionRecord,
    SnapshotRecord,
};
