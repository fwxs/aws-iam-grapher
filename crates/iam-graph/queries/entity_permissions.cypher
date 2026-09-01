// name: entity_permissions
// description: All permissions (action, effect, resource) reachable from a specific entity via
//   attached or inline policies in a snapshot. The Rust caller separately fetches the entity's
//   Permission Boundary Allow set (entity_boundary_actions.cypher) and computes per-row
//   `effective` via iam_expander::glob_match (no glob logic in Cypher) — see
//   entity_permissions() in src/queries/analysis.rs. See limitations.md.
// param $uid: entity uid ("snapshot_id|arn")
// param $snapshot_id: snapshot scope

MATCH (e {uid: $uid})-[:HAS_ATTACHED_POLICY|HAS_INLINE_POLICY*1..2]->(pol)
      -[g:GRANTS {snapshot_id: $snapshot_id}]->(perm:Permission)
RETURN perm.action AS action, g.effect AS effect, g.resource AS resource
