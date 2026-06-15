// name: entity_permissions
// description: All permissions (action, effect, resource) reachable from a specific entity via attached or inline policies in a snapshot.
// param $uid: entity uid ("snapshot_id|arn")
// param $snapshot_id: snapshot scope

MATCH (e {uid: $uid})-[:HAS_ATTACHED_POLICY|HAS_INLINE_POLICY*1..2]->(pol)
      -[:GRANTS]->(perm:Permission {snapshot_id: $snapshot_id})
RETURN perm.action AS action, perm.effect AS effect, perm.resource AS resource
