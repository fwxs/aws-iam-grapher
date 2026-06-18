// name: delete_snapshot
// description: Detach-deletes all entity nodes that carry snapshot_id (Permission, Role, User, etc.). Does not touch AwsAccount or AwsService nodes.
// param $snapshot_id: snapshot whose nodes to delete

MATCH (n {snapshot_id: $snapshot_id})
DETACH DELETE n
RETURN count(n) AS deleted
