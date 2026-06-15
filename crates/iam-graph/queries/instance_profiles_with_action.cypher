// name: instance_profiles_with_action
// description: Instance profiles whose associated roles have an Allow permission for $action.
// param $account_id: account scope for tenant isolation
// param $snapshot_id: snapshot scope
// param $action: IAM action to test (e.g. "ec2:DescribeInstances")

MATCH (ip:InstanceProfile {account_id: $account_id, snapshot_id: $snapshot_id})
      -[:CONTAINS_ROLE]->(r:Role)
      -[:HAS_ATTACHED_POLICY|HAS_INLINE_POLICY*1..2]->(pol)
      -[:GRANTS]->(perm:Permission {
          action: $action,
          effect: 'Allow',
          snapshot_id: $snapshot_id
      })
RETURN DISTINCT ip.arn AS arn, ip.name AS name
