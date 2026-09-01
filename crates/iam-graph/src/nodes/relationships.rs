use crate::nodes::permission::condition_json;
use crate::nodes::uid::{canonical_condition, entity_uid, excluded_actions_key, inline_policy_uid};
use crate::nodes::Row;
use iam_models::Condition;
use neo4rs::{query, Query};

/// UNWIND-batched: INCLUDES relationship from Snapshot to any entity node, per row.
pub const SNAPSHOT_INCLUDES: &str = "
    UNWIND $rows AS row
    MATCH (s:Snapshot {id: row.snapshot_id})
    MATCH (n {uid: row.uid})
    MERGE (s)-[:INCLUDES]->(n)
";

/// UNWIND-batched: HAS_ATTACHED_POLICY from entity to managed policy, per row.
pub const HAS_ATTACHED_POLICY: &str = "
    UNWIND $rows AS row
    MATCH (e {uid: row.entity_uid})
    MATCH (p:Policy {uid: row.policy_uid})
    MERGE (e)-[:HAS_ATTACHED_POLICY]->(p)
";

/// UNWIND-batched: HAS_INLINE_POLICY from entity to inline policy, per row.
pub const HAS_INLINE_POLICY: &str = "
    UNWIND $rows AS row
    MATCH (e {uid: row.entity_uid})
    MATCH (ip:InlinePolicy {uid: row.inline_uid})
    MERGE (e)-[:HAS_INLINE_POLICY]->(ip)
";

/// UNWIND-batched: MEMBER_OF from user to group, per row.
pub const MEMBER_OF: &str = "
    UNWIND $rows AS row
    MATCH (u:User {uid: row.user_uid})
    MATCH (g:Group {uid: row.group_uid})
    MERGE (u)-[:MEMBER_OF]->(g)
";

/// UNWIND-batched: GRANTS from managed policy to permission, per row.
///
/// `effect`/`resource`/`snapshot_id`/`condition_key`/`excluded_key` form the MERGE identity
/// (so distinct conditions and distinct NotAction exclusion sets never collide onto the same
/// edge); `condition`/`excluded_actions`/`account_id` are payload, set afterward.
pub const POLICY_GRANTS: &str = "
    UNWIND $rows AS row
    MATCH (p:Policy {uid: row.policy_uid})
    MATCH (perm:Permission {action: row.action})
    MERGE (p)-[g:GRANTS {
        effect: row.effect,
        resource: row.resource,
        snapshot_id: row.snapshot_id,
        condition_key: row.condition_key,
        excluded_key: row.excluded_key
    }]->(perm)
    SET g.condition = row.condition,
        g.excluded_actions = row.excluded_actions,
        g.account_id = row.account_id
";

/// UNWIND-batched: GRANTS from inline policy to permission, per row. Same MERGE-identity
/// shape as `POLICY_GRANTS`.
pub const INLINE_GRANTS: &str = "
    UNWIND $rows AS row
    MATCH (ip:InlinePolicy {uid: row.inline_uid})
    MATCH (perm:Permission {action: row.action})
    MERGE (ip)-[g:GRANTS {
        effect: row.effect,
        resource: row.resource,
        snapshot_id: row.snapshot_id,
        condition_key: row.condition_key,
        excluded_key: row.excluded_key
    }]->(perm)
    SET g.condition = row.condition,
        g.excluded_actions = row.excluded_actions,
        g.account_id = row.account_id
";

/// UNWIND-batched: CAN_ASSUME from a principal to a role (trust policy), per row.
pub const CAN_ASSUME: &str = "
    UNWIND $rows AS row
    MERGE (pr:Principal {id: row.principal_id, type: row.principal_type})
    WITH pr, row
    MATCH (r:Role {uid: row.role_uid})
    MERGE (pr)-[:CAN_ASSUME {conditional: row.conditional}]->(r)
";

/// UNWIND-batched: CAN_ASSUME_ROLE from an in-snapshot Role/User entity to the Role
/// it can assume, per row.
pub const CAN_ASSUME_ROLE: &str = "
    UNWIND $rows AS row
    MATCH (assumer {arn: row.principal_id, snapshot_id: row.snapshot_id})
    WHERE assumer:Role OR assumer:User
    MATCH (r:Role {uid: row.role_uid})
    MERGE (assumer)-[:CAN_ASSUME_ROLE {conditional: row.conditional}]->(r)
";

/// UNWIND-batched: CONTAINS_ROLE from InstanceProfile to Role, per row.
pub const CONTAINS_ROLE: &str = "
    UNWIND $rows AS row
    MATCH (ip:InstanceProfile {uid: row.profile_uid})
    MATCH (r:Role {uid: row.role_uid})
    MERGE (ip)-[:CONTAINS_ROLE]->(r)
";

/// UNWIND-batched: BOUNDED_BY from entity to permissions-boundary policy, per row.
pub const BOUNDED_BY: &str = "
    UNWIND $rows AS row
    MATCH (e {uid: row.entity_uid})
    MATCH (p:Policy {uid: row.policy_uid})
    MERGE (e)-[:BOUNDED_BY]->(p)
";

const STITCH_CROSS_ACCOUNT: &str = include_str!("../../queries/stitch_cross_account.cypher");

/// Build a row for the `SNAPSHOT_INCLUDES` UNWIND statement.
pub fn snapshot_includes_row(snapshot_id: &str, entity_uid: &str) -> Row {
    Row::from([
        ("snapshot_id".to_string(), snapshot_id.into()),
        ("uid".to_string(), entity_uid.into()),
    ])
}

/// Build a row for the `HAS_ATTACHED_POLICY` UNWIND statement.
pub fn has_attached_policy_row(snapshot_id: &str, entity_arn: &str, policy_arn: &str) -> Row {
    Row::from([
        (
            "entity_uid".to_string(),
            entity_uid(snapshot_id, entity_arn).into(),
        ),
        (
            "policy_uid".to_string(),
            entity_uid(snapshot_id, policy_arn).into(),
        ),
    ])
}

/// Build a row for the `HAS_INLINE_POLICY` UNWIND statement.
pub fn has_inline_policy_row(snapshot_id: &str, entity_arn: &str, inline_name: &str) -> Row {
    Row::from([
        (
            "entity_uid".to_string(),
            entity_uid(snapshot_id, entity_arn).into(),
        ),
        (
            "inline_uid".to_string(),
            inline_policy_uid(snapshot_id, entity_arn, inline_name).into(),
        ),
    ])
}

/// Build a row for the `MEMBER_OF` UNWIND statement.
pub fn member_of_row(snapshot_id: &str, user_arn: &str, group_arn: &str) -> Row {
    Row::from([
        (
            "user_uid".to_string(),
            entity_uid(snapshot_id, user_arn).into(),
        ),
        (
            "group_uid".to_string(),
            entity_uid(snapshot_id, group_arn).into(),
        ),
    ])
}

/// Build a row for the `POLICY_GRANTS` UNWIND statement.
///
/// `excluded` is empty for a normal `Action` grant, or the sorted `NotAction` list for an
/// allow/deny-all-except grant (in which case `action` is always `"*"`).
#[allow(clippy::too_many_arguments)]
pub fn policy_grants_row(
    snapshot_id: &str,
    account_id: &str,
    policy_arn: &str,
    effect: &str,
    action: &str,
    resource: &str,
    excluded: &[String],
    condition: Option<&Condition>,
) -> Row {
    Row::from([
        (
            "policy_uid".to_string(),
            entity_uid(snapshot_id, policy_arn).into(),
        ),
        ("action".to_string(), action.into()),
        ("effect".to_string(), effect.into()),
        ("resource".to_string(), resource.into()),
        ("snapshot_id".to_string(), snapshot_id.into()),
        ("account_id".to_string(), account_id.into()),
        (
            "condition_key".to_string(),
            canonical_condition(condition).into(),
        ),
        (
            "excluded_key".to_string(),
            excluded_actions_key(excluded).into(),
        ),
        (
            "excluded_actions".to_string(),
            if excluded.is_empty() {
                None
            } else {
                Some(excluded.to_vec())
            }
            .into(),
        ),
        ("condition".to_string(), condition_json(condition).into()),
    ])
}

/// Build a row for the `INLINE_GRANTS` UNWIND statement. See `policy_grants_row` for the
/// `excluded` convention.
#[allow(clippy::too_many_arguments)]
pub fn inline_grants_row(
    snapshot_id: &str,
    account_id: &str,
    owner_arn: &str,
    inline_name: &str,
    effect: &str,
    action: &str,
    resource: &str,
    excluded: &[String],
    condition: Option<&Condition>,
) -> Row {
    Row::from([
        (
            "inline_uid".to_string(),
            inline_policy_uid(snapshot_id, owner_arn, inline_name).into(),
        ),
        ("action".to_string(), action.into()),
        ("effect".to_string(), effect.into()),
        ("resource".to_string(), resource.into()),
        ("snapshot_id".to_string(), snapshot_id.into()),
        ("account_id".to_string(), account_id.into()),
        (
            "condition_key".to_string(),
            canonical_condition(condition).into(),
        ),
        (
            "excluded_key".to_string(),
            excluded_actions_key(excluded).into(),
        ),
        (
            "excluded_actions".to_string(),
            if excluded.is_empty() {
                None
            } else {
                Some(excluded.to_vec())
            }
            .into(),
        ),
        ("condition".to_string(), condition_json(condition).into()),
    ])
}

/// Build a row for the `CAN_ASSUME` UNWIND statement (trust policy).
///
/// `principal_kind` should come from the trust policy block key (`AWS`, `Service`,
/// `Federated`, `CanonicalUser`) rather than being re-inferred from the id string.
/// `conditional` is `true` when the edge's validity depends on a runtime value the
/// ingester can't evaluate from collected data (e.g. `sts:ExternalId`, MFA, or an
/// unresolved `NotPrincipal` exclusion) — see `ingester::classify_trust_condition`.
/// Deterministic conditions (e.g. a `PrincipalAccount` check consistent with the
/// listed principal) are folded into `false`; contradictory ones suppress the edge
/// entirely before this function is even called.
pub fn can_assume_row(
    snapshot_id: &str,
    principal_kind: &str,
    principal_id: &str,
    role_arn: &str,
    conditional: bool,
) -> Row {
    Row::from([
        ("principal_id".to_string(), principal_id.into()),
        ("principal_type".to_string(), principal_kind.into()),
        (
            "role_uid".to_string(),
            entity_uid(snapshot_id, role_arn).into(),
        ),
        ("conditional".to_string(), conditional.into()),
    ])
}

/// Build a row for the `CAN_ASSUME_ROLE` UNWIND statement.
///
/// Direct entity-to-entity bridge over `CAN_ASSUME` (which targets an ARN-keyed
/// `Principal` node, not the entity node itself), materialized only when the trust
/// policy principal resolves to a Role or User ARN present in this snapshot. This is
/// what makes `CAN_ASSUME_ROLE*1..N` variable-length traversal possible for
/// transitive `sts:AssumeRole` privilege-escalation analysis.
pub fn can_assume_role_row(
    snapshot_id: &str,
    principal_arn: &str,
    role_arn: &str,
    conditional: bool,
) -> Row {
    Row::from([
        ("principal_id".to_string(), principal_arn.into()),
        ("snapshot_id".to_string(), snapshot_id.into()),
        (
            "role_uid".to_string(),
            entity_uid(snapshot_id, role_arn).into(),
        ),
        ("conditional".to_string(), conditional.into()),
    ])
}

/// Build a row for the `CONTAINS_ROLE` UNWIND statement.
pub fn contains_role_row(snapshot_id: &str, profile_arn: &str, role_arn: &str) -> Row {
    Row::from([
        (
            "profile_uid".to_string(),
            entity_uid(snapshot_id, profile_arn).into(),
        ),
        (
            "role_uid".to_string(),
            entity_uid(snapshot_id, role_arn).into(),
        ),
    ])
}

/// Build a row for the `BOUNDED_BY` UNWIND statement.
pub fn bounded_by_row(snapshot_id: &str, entity_arn: &str, boundary_arn: &str) -> Row {
    Row::from([
        (
            "entity_uid".to_string(),
            entity_uid(snapshot_id, entity_arn).into(),
        ),
        (
            "policy_uid".to_string(),
            entity_uid(snapshot_id, boundary_arn).into(),
        ),
    ])
}

/// Build the cross-account stitch query for one org collection run.
///
/// Materializes `CAN_ASSUME_ROLE {cross_account: true}` edges between entities in different
/// account snapshots that share the same `org_collection_run_id`, validated against both the
/// trust policy (via existing `CAN_ASSUME` → `Principal` nodes) and the assumer's own
/// `sts:AssumeRole` grants. Idempotent — safe to re-run via `MERGE`.
pub fn stitch_cross_account_query(org_run_id: &str) -> Query {
    query(STITCH_CROSS_ACCOUNT).param("org_run_id", org_run_id)
}
