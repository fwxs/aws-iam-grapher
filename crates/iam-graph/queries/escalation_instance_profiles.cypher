// name: escalation_instance_profiles
// description: For each terminal Role ARN in $arns, return InstanceProfiles that contain it via
//   an inbound CONTAINS_ROLE edge (InstanceProfile)-[:CONTAINS_ROLE]->(Role). Batched via UNWIND
//   so all terminals from one privilege_escalation_paths call are resolved in a single round trip.
// param $arns: terminal Role ARNs to resolve instance profiles for
// param $account_id: account scope for tenant isolation
// param $snapshot_id: snapshot scope

UNWIND $arns AS terminal_arn
MATCH (r:Role {arn: terminal_arn, account_id: $account_id, snapshot_id: $snapshot_id})
MATCH (ip:InstanceProfile)-[:CONTAINS_ROLE]->(r)
RETURN terminal_arn, ip.arn AS arn, ip.name AS name
