// name: candidate_boundary_actions
// description: Returns every distinct Allow action string granted by a Permission Boundary
//   policy (reached via BOUNDED_BY) in this snapshot/account scope, excluding allow-all-except
//   sentinel nodes (action='*' with excluded_actions set — those are matched inline in Cypher
//   instead, see who_can.cypher / entity_permissions.cypher). The caller matches the queried
//   action against this list with IAM glob semantics (iam_expander::glob_match) to compute the
//   concrete set of boundary-allowed actions that cover it, then passes that set back as
//   $boundary_allow_actions. See limitations.md.
// param $snapshot_id: snapshot scope
// param $account_id: account scope for tenant isolation

MATCH (e)-[:BOUNDED_BY]->(:Policy)-[:GRANTS]->(perm:Permission {
    effect: 'Allow',
    snapshot_id: $snapshot_id
})
WHERE e.account_id = $account_id
  AND perm.excluded_actions IS NULL
RETURN DISTINCT perm.action AS action
