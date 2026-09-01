// name: delete_snapshot
// description: Detach-deletes all entity nodes that carry snapshot_id (Policy, InlinePolicy,
//   Role, User, Group, InstanceProfile, Snapshot, etc.). Permission is a global, action-keyed
//   vocabulary node (no snapshot_id) and is never matched here — DETACH DELETE on the deleted
//   Policy/InlinePolicy nodes removes their outgoing GRANTS edges, so this snapshot's grants
//   disappear correctly while shared Permission nodes survive, same as AwsService today. Does
//   not touch AwsAccount or AwsService nodes.
// param $snapshot_id: snapshot whose nodes to delete

MATCH (n {snapshot_id: $snapshot_id})
DETACH DELETE n
RETURN count(n) AS deleted
