// name: escalation_trust_principals
// description: For each terminal Role ARN in $arns, return trust-policy Principals that can
//   assume it via CAN_ASSUME (Principal)-[:CAN_ASSUME]->(Role) — the full trust-policy
//   principal set (AWS/Service/Federated/CanonicalUser/wildcard), richer than the
//   CAN_ASSUME_ROLE bridge which only covers principals resolved to in-graph Role/User ARNs.
//   Batched via UNWIND so all terminals from one privilege_escalation_paths call are resolved
//   in a single round trip.
// param $arns: terminal Role ARNs to resolve trust principals for
// param $account_id: account scope for tenant isolation
// param $snapshot_id: snapshot scope

UNWIND $arns AS terminal_arn
MATCH (r:Role {arn: terminal_arn, account_id: $account_id, snapshot_id: $snapshot_id})
MATCH (pr:Principal)-[rel:CAN_ASSUME]->(r)
RETURN terminal_arn, pr.id AS id, pr.type AS principal_type, rel.conditional AS conditional
