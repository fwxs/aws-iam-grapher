use crate::nodes::uid::{entity_uid, excluded_permission_uid, inline_policy_uid, permission_uid};
use neo4rs::{query, Query};

const SNAPSHOT_INCLUDES: &str = "
    MATCH (s:Snapshot {id: $snapshot_id})
    MATCH (n {uid: $uid})
    MERGE (s)-[:INCLUDES]->(n)
";

const HAS_ATTACHED_POLICY: &str = "
    MATCH (e {uid: $entity_uid})
    MATCH (p:Policy {uid: $policy_uid})
    MERGE (e)-[:HAS_ATTACHED_POLICY]->(p)
";

const HAS_INLINE_POLICY: &str = "
    MATCH (e {uid: $entity_uid})
    MATCH (ip:InlinePolicy {uid: $inline_uid})
    MERGE (e)-[:HAS_INLINE_POLICY]->(ip)
";

const MEMBER_OF: &str = "
    MATCH (u:User {uid: $user_uid})
    MATCH (g:Group {uid: $group_uid})
    MERGE (u)-[:MEMBER_OF]->(g)
";

const POLICY_GRANTS: &str = "
    MATCH (p:Policy {uid: $policy_uid})
    MATCH (perm:Permission {uid: $perm_uid})
    MERGE (p)-[:GRANTS]->(perm)
";

const INLINE_GRANTS: &str = "
    MATCH (ip:InlinePolicy {uid: $inline_uid})
    MATCH (perm:Permission {uid: $perm_uid})
    MERGE (ip)-[:GRANTS]->(perm)
";

const CAN_ASSUME: &str = "
    MERGE (pr:Principal {id: $principal_id, type: $principal_type})
    WITH pr
    MATCH (r:Role {uid: $role_uid})
    MERGE (pr)-[:CAN_ASSUME {conditional: $conditional}]->(r)
";

const CAN_ASSUME_ROLE: &str = "
    MATCH (assumer {arn: $principal_id, snapshot_id: $snapshot_id})
    WHERE assumer:Role OR assumer:User
    MATCH (r:Role {uid: $role_uid})
    MERGE (assumer)-[:CAN_ASSUME_ROLE {conditional: $conditional}]->(r)
";

const CONTAINS_ROLE: &str = "
    MATCH (ip:InstanceProfile {uid: $profile_uid})
    MATCH (r:Role {uid: $role_uid})
    MERGE (ip)-[:CONTAINS_ROLE]->(r)
";

const BOUNDED_BY: &str = "
    MATCH (e {uid: $entity_uid})
    MATCH (p:Policy {uid: $policy_uid})
    MERGE (e)-[:BOUNDED_BY]->(p)
";

const STITCH_CROSS_ACCOUNT: &str = include_str!("../../queries/stitch_cross_account.cypher");

/// INCLUDES relationship from Snapshot to any entity node.
pub fn snapshot_includes_query(snapshot_id: &str, entity_uid: &str) -> Query {
    query(SNAPSHOT_INCLUDES)
        .param("snapshot_id", snapshot_id)
        .param("uid", entity_uid)
}

/// HAS_ATTACHED_POLICY from entity to managed policy.
pub fn has_attached_policy_query(snapshot_id: &str, entity_arn: &str, policy_arn: &str) -> Query {
    query(HAS_ATTACHED_POLICY)
        .param("entity_uid", entity_uid(snapshot_id, entity_arn))
        .param("policy_uid", entity_uid(snapshot_id, policy_arn))
}

/// HAS_INLINE_POLICY from entity to inline policy.
pub fn has_inline_policy_query(snapshot_id: &str, entity_arn: &str, inline_name: &str) -> Query {
    query(HAS_INLINE_POLICY)
        .param("entity_uid", entity_uid(snapshot_id, entity_arn))
        .param(
            "inline_uid",
            inline_policy_uid(snapshot_id, entity_arn, inline_name),
        )
}

/// MEMBER_OF from user to group.
pub fn member_of_query(snapshot_id: &str, user_arn: &str, group_arn: &str) -> Query {
    query(MEMBER_OF)
        .param("user_uid", entity_uid(snapshot_id, user_arn))
        .param("group_uid", entity_uid(snapshot_id, group_arn))
}

/// GRANTS from managed policy to permission.
pub fn policy_grants_query(
    snapshot_id: &str,
    policy_arn: &str,
    effect: &str,
    action: &str,
    resource: &str,
) -> Query {
    query(POLICY_GRANTS)
        .param("policy_uid", entity_uid(snapshot_id, policy_arn))
        .param(
            "perm_uid",
            permission_uid(snapshot_id, effect, action, resource),
        )
}

/// GRANTS from inline policy to permission.
pub fn inline_grants_query(
    snapshot_id: &str,
    owner_arn: &str,
    inline_name: &str,
    effect: &str,
    action: &str,
    resource: &str,
) -> Query {
    query(INLINE_GRANTS)
        .param(
            "inline_uid",
            inline_policy_uid(snapshot_id, owner_arn, inline_name),
        )
        .param(
            "perm_uid",
            permission_uid(snapshot_id, effect, action, resource),
        )
}

/// GRANTS from managed policy to an allow-all-except Permission node.
pub fn policy_grants_excluded_query(
    snapshot_id: &str,
    policy_arn: &str,
    effect: &str,
    resource: &str,
    excluded: &[String],
) -> Query {
    query(POLICY_GRANTS)
        .param("policy_uid", entity_uid(snapshot_id, policy_arn))
        .param(
            "perm_uid",
            excluded_permission_uid(snapshot_id, effect, resource, excluded),
        )
}

/// GRANTS from inline policy to an allow-all-except Permission node.
pub fn inline_grants_excluded_query(
    snapshot_id: &str,
    owner_arn: &str,
    inline_name: &str,
    effect: &str,
    resource: &str,
    excluded: &[String],
) -> Query {
    query(INLINE_GRANTS)
        .param(
            "inline_uid",
            inline_policy_uid(snapshot_id, owner_arn, inline_name),
        )
        .param(
            "perm_uid",
            excluded_permission_uid(snapshot_id, effect, resource, excluded),
        )
}

/// CAN_ASSUME from a principal to a role (trust policy).
///
/// `principal_kind` should come from the trust policy block key (`AWS`, `Service`,
/// `Federated`, `CanonicalUser`) rather than being re-inferred from the id string.
/// `conditional` is `true` when the edge's validity depends on a runtime value the
/// ingester can't evaluate from collected data (e.g. `sts:ExternalId`, MFA, or an
/// unresolved `NotPrincipal` exclusion) — see `ingester::classify_trust_condition`.
/// Deterministic conditions (e.g. a `PrincipalAccount` check consistent with the
/// listed principal) are folded into `false`; contradictory ones suppress the edge
/// entirely before this function is even called.
pub fn can_assume_query(
    snapshot_id: &str,
    principal_kind: &str,
    principal_id: &str,
    role_arn: &str,
    conditional: bool,
) -> Query {
    query(CAN_ASSUME)
        .param("principal_id", principal_id)
        .param("principal_type", principal_kind)
        .param("role_uid", entity_uid(snapshot_id, role_arn))
        .param("conditional", conditional)
}

/// CAN_ASSUME_ROLE from an in-snapshot Role/User entity to the Role it can assume.
///
/// Direct entity-to-entity bridge over `CAN_ASSUME` (which targets an ARN-keyed
/// `Principal` node, not the entity node itself), materialized only when the trust
/// policy principal resolves to a Role or User ARN present in this snapshot. This is
/// what makes `CAN_ASSUME_ROLE*1..N` variable-length traversal possible for
/// transitive `sts:AssumeRole` privilege-escalation analysis.
pub fn can_assume_role_query(
    snapshot_id: &str,
    principal_arn: &str,
    role_arn: &str,
    conditional: bool,
) -> Query {
    query(CAN_ASSUME_ROLE)
        .param("principal_id", principal_arn)
        .param("snapshot_id", snapshot_id)
        .param("role_uid", entity_uid(snapshot_id, role_arn))
        .param("conditional", conditional)
}

/// CONTAINS_ROLE from InstanceProfile to Role.
pub fn contains_role_query(snapshot_id: &str, profile_arn: &str, role_arn: &str) -> Query {
    query(CONTAINS_ROLE)
        .param("profile_uid", entity_uid(snapshot_id, profile_arn))
        .param("role_uid", entity_uid(snapshot_id, role_arn))
}

/// BOUNDED_BY from entity to permissions-boundary policy.
pub fn bounded_by_query(snapshot_id: &str, entity_arn: &str, boundary_arn: &str) -> Query {
    query(BOUNDED_BY)
        .param("entity_uid", entity_uid(snapshot_id, entity_arn))
        .param("policy_uid", entity_uid(snapshot_id, boundary_arn))
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
