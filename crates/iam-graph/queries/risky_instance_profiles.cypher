// name: risky_instance_profiles
// description: Instance profiles whose roles hold at least one of the 9 known privilege-escalation actions.
// param $account_id: account scope for tenant isolation
// param $snapshot_id: snapshot scope

MATCH (ip:InstanceProfile {account_id: $account_id, snapshot_id: $snapshot_id})
      -[:CONTAINS_ROLE]->(r:Role)
      -[:HAS_ATTACHED_POLICY|HAS_INLINE_POLICY*1..2]->(pol)
      -[:GRANTS]->(perm:Permission {effect: 'Allow', snapshot_id: $snapshot_id})
WHERE perm.action IN [
    'iam:CreatePolicyVersion', 'iam:SetDefaultPolicyVersion',
    'iam:AttachRolePolicy', 'iam:AttachUserPolicy',
    'iam:PassRole', 'iam:PutRolePolicy', 'iam:PutUserPolicy',
    'iam:CreateAccessKey', 'iam:CreateLoginProfile'
]
RETURN ip.arn AS arn, ip.name AS name, collect(perm.action) AS risky_actions
