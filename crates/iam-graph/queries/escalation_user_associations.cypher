// name: escalation_user_associations
// description: For each escalating User ARN in $arns, return roles it can assume, its
//   attached/inline policies, and its group memberships. Batched via UNWIND so all entities
//   from one privilege_escalation_paths call are resolved in a single round trip.
//   CAN_ASSUME_ROLE arm is permission-verified: the trust-policy edge alone is not enough,
//   the user must also hold an Allow for sts:AssumeRole (or *) whose resource matches the
//   target role or covers '*', checked on the user's own policies and group-inherited ones
//   (same predicate as stitch_cross_account.cypher). conditional is true when the trust edge
//   is conditional OR only a resource='*' sts grant exists (no specific-ARN grant).
//   The other three arms are exact structural traversals; conditional is always false.
//   HAS_ATTACHED_POLICY_OR_INLINE uses coalesce(pol.arn, pol.uid) because InlinePolicy nodes
//   have no arn property (inline policies aren't ARN-addressable in AWS).
// param $arns: escalating User ARNs to resolve associations for
// param $account_id: account scope for tenant isolation
// param $snapshot_id: snapshot scope

UNWIND $arns AS entity_arn
MATCH (u:User {arn: entity_arn, account_id: $account_id, snapshot_id: $snapshot_id})
MATCH (u)-[car:CAN_ASSUME_ROLE]->(role:Role)
WHERE (
    EXISTS {
      MATCH (u)-[:HAS_ATTACHED_POLICY|HAS_INLINE_POLICY*1..2]->(pol)
            -[:GRANTS]->(sp:Permission {effect: 'Allow', snapshot_id: $snapshot_id})
      WHERE sp.action IN ['sts:AssumeRole', '*']
        AND (sp.resource = role.arn OR sp.resource = '*')
    }
    OR EXISTS {
      MATCH (u)-[:MEMBER_OF]->(:Group)
            -[:HAS_ATTACHED_POLICY|HAS_INLINE_POLICY*1..2]->(gpol)
            -[:GRANTS]->(gsp:Permission {effect: 'Allow', snapshot_id: $snapshot_id})
      WHERE gsp.action IN ['sts:AssumeRole', '*']
        AND (gsp.resource = role.arn OR gsp.resource = '*')
    }
  )
RETURN entity_arn, role.arn AS arn, role.name AS name, labels(role)[0] AS entity_type,
       'CAN_ASSUME_ROLE' AS relationship,
       (car.conditional
        OR (
          NOT EXISTS {
            MATCH (u)-[:HAS_ATTACHED_POLICY|HAS_INLINE_POLICY*1..2]->(pol2)
                  -[:GRANTS]->(sp2:Permission {effect: 'Allow', snapshot_id: $snapshot_id})
            WHERE sp2.action IN ['sts:AssumeRole', '*'] AND sp2.resource = role.arn
          }
          AND NOT EXISTS {
            MATCH (u)-[:MEMBER_OF]->(:Group)
                  -[:HAS_ATTACHED_POLICY|HAS_INLINE_POLICY*1..2]->(gpol2)
                  -[:GRANTS]->(gsp2:Permission {effect: 'Allow', snapshot_id: $snapshot_id})
            WHERE gsp2.action IN ['sts:AssumeRole', '*'] AND gsp2.resource = role.arn
          }
        )
       ) AS conditional

UNION

UNWIND $arns AS entity_arn
MATCH (u:User {arn: entity_arn, account_id: $account_id, snapshot_id: $snapshot_id})
MATCH (u)-[:HAS_ATTACHED_POLICY|HAS_INLINE_POLICY]->(pol)
RETURN entity_arn, coalesce(pol.arn, pol.uid) AS arn, pol.name AS name,
       labels(pol)[0] AS entity_type,
       'HAS_ATTACHED_POLICY_OR_INLINE' AS relationship, false AS conditional

UNION

UNWIND $arns AS entity_arn
MATCH (u:User {arn: entity_arn, account_id: $account_id, snapshot_id: $snapshot_id})
MATCH (u)-[:MEMBER_OF]->(g:Group)
RETURN entity_arn, g.arn AS arn, g.name AS name, labels(g)[0] AS entity_type,
       'MEMBER_OF' AS relationship, false AS conditional
