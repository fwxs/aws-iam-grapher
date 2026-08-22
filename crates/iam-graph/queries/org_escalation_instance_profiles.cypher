// name: org_escalation_instance_profiles
// description: Org-scoped variant of escalation_instance_profiles. Terminal ARNs may belong to
//   different account snapshots within one org collection run, so each row carries the
//   terminal's own snapshot_id ($pairs is a list of {arn, snapshot_id} maps) instead of a
//   single bound $snapshot_id parameter.
// param $pairs: list of {arn, snapshot_id} maps for terminal Role ARNs to resolve instance
//   profiles for

UNWIND $pairs AS pair
MATCH (r:Role {arn: pair.arn, snapshot_id: pair.snapshot_id})
MATCH (ip:InstanceProfile)-[:CONTAINS_ROLE]->(r)
RETURN pair.arn AS terminal_arn, ip.arn AS arn, ip.name AS name
