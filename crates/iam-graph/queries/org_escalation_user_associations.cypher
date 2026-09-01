// name: org_escalation_user_associations
// description: Org-scoped variant of escalation_user_associations. Escalating User ARNs may
//   belong to different account snapshots within one org collection run, so each row carries
//   its own snapshot_id ($pairs is a list of {arn, snapshot_id} maps) instead of a single
//   bound $snapshot_id parameter. No account_id filter — matched by (arn, snapshot_id) alone.
//   HAS_ATTACHED_POLICY_OR_INLINE uses coalesce(pol.arn, pol.uid) because InlinePolicy nodes
//   have no arn property (inline policies aren't ARN-addressable in AWS).
// param $pairs: list of {arn, snapshot_id} maps for escalating User ARNs

UNWIND $pairs AS pair
MATCH (u:User {arn: pair.arn, snapshot_id: pair.snapshot_id})
MATCH (u)-[car:CAN_ASSUME_ROLE]->(role:Role)
WHERE (
    EXISTS {
      MATCH (u)-[:HAS_ATTACHED_POLICY|HAS_INLINE_POLICY*1..2]->(pol)
            -[sg:GRANTS {effect: 'Allow', snapshot_id: pair.snapshot_id}]->(sp:Permission)
      WHERE sp.action IN ['sts:AssumeRole', '*']
        AND (sg.resource = role.arn OR sg.resource = '*')
    }
    OR EXISTS {
      MATCH (u)-[:MEMBER_OF]->(:Group)
            -[:HAS_ATTACHED_POLICY|HAS_INLINE_POLICY*1..2]->(gpol)
            -[gsg:GRANTS {effect: 'Allow', snapshot_id: pair.snapshot_id}]->(gsp:Permission)
      WHERE gsp.action IN ['sts:AssumeRole', '*']
        AND (gsg.resource = role.arn OR gsg.resource = '*')
    }
  )
RETURN pair.arn AS entity_arn, role.arn AS arn, role.name AS name, labels(role)[0] AS entity_type,
       'CAN_ASSUME_ROLE' AS relationship,
       (car.conditional
        OR (
          NOT EXISTS {
            MATCH (u)-[:HAS_ATTACHED_POLICY|HAS_INLINE_POLICY*1..2]->(pol2)
                  -[sg2:GRANTS {effect: 'Allow', snapshot_id: pair.snapshot_id}]->(sp2:Permission)
            WHERE sp2.action IN ['sts:AssumeRole', '*'] AND sg2.resource = role.arn
          }
          AND NOT EXISTS {
            MATCH (u)-[:MEMBER_OF]->(:Group)
                  -[:HAS_ATTACHED_POLICY|HAS_INLINE_POLICY*1..2]->(gpol2)
                  -[gsg2:GRANTS {effect: 'Allow', snapshot_id: pair.snapshot_id}]->(gsp2:Permission)
            WHERE gsp2.action IN ['sts:AssumeRole', '*'] AND gsg2.resource = role.arn
          }
        )
       ) AS conditional

UNION

UNWIND $pairs AS pair
MATCH (u:User {arn: pair.arn, snapshot_id: pair.snapshot_id})
MATCH (u)-[:HAS_ATTACHED_POLICY|HAS_INLINE_POLICY]->(pol)
RETURN pair.arn AS entity_arn, coalesce(pol.arn, pol.uid) AS arn, pol.name AS name,
       labels(pol)[0] AS entity_type,
       'HAS_ATTACHED_POLICY_OR_INLINE' AS relationship, false AS conditional

UNION

UNWIND $pairs AS pair
MATCH (u:User {arn: pair.arn, snapshot_id: pair.snapshot_id})
MATCH (u)-[:MEMBER_OF]->(g:Group)
RETURN pair.arn AS entity_arn, g.arn AS arn, g.name AS name, labels(g)[0] AS entity_type,
       'MEMBER_OF' AS relationship, false AS conditional
