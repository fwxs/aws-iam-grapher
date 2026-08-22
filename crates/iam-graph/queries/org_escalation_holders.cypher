// name: org_escalation_holders
// description: Org-scoped variant of escalation_holders. Terminal ARNs may belong to different
//   account snapshots within one org collection run, so each row carries the terminal's own
//   snapshot_id ($pairs is a list of {arn, snapshot_id} maps) instead of a single bound
//   $snapshot_id parameter.
// param $pairs: list of {arn, snapshot_id} maps for terminal Group ARNs to resolve holders for

UNWIND $pairs AS pair
MATCH (g:Group {arn: pair.arn, snapshot_id: pair.snapshot_id})
MATCH (u:User)-[:MEMBER_OF]->(g)
RETURN pair.arn AS terminal_arn, u.arn AS arn, u.name AS name, labels(u)[0] AS entity_type
