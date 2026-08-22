// name: org_escalation_trust_principals
// description: Org-scoped variant of escalation_trust_principals. Terminal ARNs may belong to
//   different account snapshots within one org collection run, so each row carries the
//   terminal's own snapshot_id ($pairs is a list of {arn, snapshot_id} maps) instead of a
//   single bound $snapshot_id parameter.
// param $pairs: list of {arn, snapshot_id} maps for terminal Role ARNs to resolve trust
//   principals for

UNWIND $pairs AS pair
MATCH (r:Role {arn: pair.arn, snapshot_id: pair.snapshot_id})
MATCH (pr:Principal)-[rel:CAN_ASSUME]->(r)
RETURN pair.arn AS terminal_arn, pr.id AS id, pr.type AS principal_type, rel.conditional AS conditional
