// name: privilege_escalation_paths
// description: Entities with at least one of the 9 risky IAM actions via attached/inline policy, excluding entities denied by an Action:'*' Deny.
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
  AND NOT EXISTS {
      MATCH (e)-[:HAS_ATTACHED_POLICY|HAS_INLINE_POLICY*1..2]->(dpol)
            -[:GRANTS]->(deny:Permission {
                action: '*',
                effect: 'Deny',
                snapshot_id: $snapshot_id
            })
  }
RETURN e.arn AS arn, e.name AS name, labels(e)[0] AS entity_type,
       collect(perm.action) AS risky_actions
