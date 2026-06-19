// name: privilege_escalation_paths
// description: Entities with at least one of the 9 risky IAM actions via attached/inline
//   policy. Returns the entity's full allowed_actions set (intersected with the risky list)
//   and the Deny action strings that may cover them — own policies plus every group the
//   entity is MEMBER_OF (group-inherited Deny). Per-action, wildcard-aware Deny suppression
//   (e.g. a Deny on `iam:Put*` covering `iam:PutRolePolicy`) is applied in Rust via
//   iam_expander::glob_match against deny_actions, since Cypher has no glob matching.
//   Deny-NotAction sentinel nodes (action='*' with excluded_actions) are excluded from
//   deny_actions and not evaluated — see limitations.md.
// param $account_id: account scope for tenant isolation
// param $snapshot_id: snapshot scope

MATCH (e {account_id: $account_id, snapshot_id: $snapshot_id})
      -[:HAS_ATTACHED_POLICY|HAS_INLINE_POLICY*1..2]->(pol)
      -[:GRANTS]->(perm:Permission {effect: 'Allow', snapshot_id: $snapshot_id})
WHERE perm.action IN [
    'iam:CreatePolicyVersion',
    'iam:SetDefaultPolicyVersion',
    'iam:AttachRolePolicy',
    'iam:AttachUserPolicy',
    'iam:PassRole',
    'iam:PutRolePolicy',
    'iam:PutUserPolicy',
    'iam:CreateAccessKey',
    'iam:CreateLoginProfile'
]
WITH e, collect(DISTINCT perm.action) AS allowed_actions
OPTIONAL MATCH (e)-[:HAS_ATTACHED_POLICY|HAS_INLINE_POLICY*1..2]->(dpol)
               -[:GRANTS]->(deny:Permission {effect: 'Deny', snapshot_id: $snapshot_id})
WHERE deny.excluded_actions IS NULL
WITH e, allowed_actions, collect(DISTINCT deny.action) AS own_deny_actions
OPTIONAL MATCH (e)-[:MEMBER_OF]->(:Group)
               -[:HAS_ATTACHED_POLICY|HAS_INLINE_POLICY*1..2]->(gdpol)
               -[:GRANTS]->(gdeny:Permission {effect: 'Deny', snapshot_id: $snapshot_id})
WHERE gdeny.excluded_actions IS NULL
WITH e, allowed_actions, own_deny_actions, collect(DISTINCT gdeny.action) AS group_deny_actions
RETURN e.arn AS arn, e.name AS name, labels(e)[0] AS entity_type,
       allowed_actions, own_deny_actions + group_deny_actions AS deny_actions
