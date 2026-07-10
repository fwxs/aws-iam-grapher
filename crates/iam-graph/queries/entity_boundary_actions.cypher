// name: entity_boundary_actions
// description: Returns every Allow permission (action, excluded_actions) granted by $uid's
//   Permission Boundary policy, if attached, in this snapshot. Used by entity_permissions() to
//   compute per-row `effective` via iam_expander::glob_match against each boundary action
//   (exact/wildcard), a full-admin boundary (action='*', excluded_actions IS NULL), or an
//   allow-all-except boundary (action='*', excluded_actions IS NOT NULL).
// param $uid: entity uid ("snapshot_id|arn")
// param $snapshot_id: snapshot scope

MATCH (e {uid: $uid})-[:BOUNDED_BY]->(:Policy)-[:GRANTS]->(perm:Permission {
    effect: 'Allow',
    snapshot_id: $snapshot_id
})
RETURN perm.action AS action, perm.excluded_actions AS excluded_actions
