// name: stitch_cross_account
// description: Materialize cross-account CAN_ASSUME_ROLE edges for one org collection run.
//   For every Principal{type:'IamEntity'} that has a CAN_ASSUME edge to a Role in this org
//   run, finds assumer entities in a different account within the same run that satisfy both:
//   1) Trust side: the principal ARN is either an account-root (:root suffix, matches by
//      account_id) or a specific entity ARN (exact arn match).
//   2) STS side: the assumer holds an Allow for sts:AssumeRole or * whose resource matches
//      the target role ARN exactly or covers * (checked on own and group-inherited policies).
//   Edges are created with cross_account=true. conditional is set to ca.conditional OR
//   the sts grant only covers resource='*' (no specific-ARN sts grant found).
//   MERGE is used so re-runs are safe.
// param $org_run_id: org collection run id shared across all per-account snapshots

MATCH (p:Principal {type: 'IamEntity'})-[ca:CAN_ASSUME]->(target:Role)
MATCH (target)<-[:INCLUDES]-(:Snapshot {org_collection_run_id: $org_run_id})
MATCH (:Snapshot {org_collection_run_id: $org_run_id})-[:INCLUDES]->(assumer)
WHERE (assumer:Role OR assumer:User)
  AND assumer.account_id <> target.account_id
  AND (
    (p.id ENDS WITH ':root'
      AND split(split(p.id, '::')[1], ':')[0] = assumer.account_id)
    OR assumer.arn = p.id
  )
  AND (
    EXISTS {
      MATCH (assumer)-[:HAS_ATTACHED_POLICY|HAS_INLINE_POLICY*1..2]->(pol)
            -[:GRANTS]->(sp:Permission {effect: 'Allow', snapshot_id: assumer.snapshot_id})
      WHERE sp.action IN ['sts:AssumeRole', '*']
        AND (sp.resource = target.arn OR sp.resource = '*')
    }
    OR EXISTS {
      MATCH (assumer)-[:MEMBER_OF]->(:Group)
            -[:HAS_ATTACHED_POLICY|HAS_INLINE_POLICY*1..2]->(gpol)
            -[:GRANTS]->(gsp:Permission {effect: 'Allow', snapshot_id: assumer.snapshot_id})
      WHERE gsp.action IN ['sts:AssumeRole', '*']
        AND (gsp.resource = target.arn OR gsp.resource = '*')
    }
  )
WITH assumer, target, ca,
     (ca.conditional
      OR (
        NOT EXISTS {
          MATCH (assumer)-[:HAS_ATTACHED_POLICY|HAS_INLINE_POLICY*1..2]->(pol2)
                -[:GRANTS]->(sp2:Permission {effect: 'Allow', snapshot_id: assumer.snapshot_id})
          WHERE sp2.action IN ['sts:AssumeRole', '*'] AND sp2.resource = target.arn
        }
        AND NOT EXISTS {
          MATCH (assumer)-[:MEMBER_OF]->(:Group)
                -[:HAS_ATTACHED_POLICY|HAS_INLINE_POLICY*1..2]->(gpol2)
                -[:GRANTS]->(gsp2:Permission {effect: 'Allow', snapshot_id: assumer.snapshot_id})
          WHERE gsp2.action IN ['sts:AssumeRole', '*'] AND gsp2.resource = target.arn
        }
      )
     ) AS edge_conditional
MERGE (assumer)-[r:CAN_ASSUME_ROLE]->(target)
ON CREATE SET r.conditional = edge_conditional, r.cross_account = true
ON MATCH SET r.conditional = r.conditional OR edge_conditional, r.cross_account = true
RETURN count(r) AS edges_created
