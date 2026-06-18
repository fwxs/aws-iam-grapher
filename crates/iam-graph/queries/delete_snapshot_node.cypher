// name: delete_snapshot_node
// description: Deletes the Snapshot node itself (identified by its id property, not snapshot_id). Run after delete_snapshot.cypher.
// param $snapshot_id: id of the Snapshot node to delete

MATCH (s:Snapshot {id: $snapshot_id})
DETACH DELETE s
RETURN count(s) AS deleted
