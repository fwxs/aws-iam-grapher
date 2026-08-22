// name: escalation_holders
// description: For each terminal Group ARN in $arns, return its member Users via an inbound
//   MEMBER_OF edge (User)-[:MEMBER_OF]->(Group). Batched via UNWIND so all terminals from one
//   privilege_escalation_paths call are resolved in a single round trip.
// param $arns: terminal Group ARNs to resolve holders for
// param $account_id: account scope for tenant isolation
// param $snapshot_id: snapshot scope

UNWIND $arns AS terminal_arn
MATCH (g:Group {arn: terminal_arn, account_id: $account_id, snapshot_id: $snapshot_id})
MATCH (u:User)-[:MEMBER_OF]->(g)
RETURN terminal_arn, u.arn AS arn, u.name AS name, labels(u)[0] AS entity_type
