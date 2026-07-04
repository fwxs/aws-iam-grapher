// name: who_can
// description: Returns all entities with an Allow permission for $action in this snapshot.
//   Three UNION arms: (1) direct entity→policy grant, (2) user via group membership,
//   (3) entity with action='*' Allow — covers true full-admin (excluded_actions IS NULL) and
//   allow-all-except (NotAction) nodes. Arm 3 filters out entities where $action is in
//   excluded_actions, honoring NotAction exclusions exactly. is_full_admin is true only for
//   true full-admin grants (excluded_actions IS NULL); NotAction grants set it false.
//   Each arm excludes entities with a Deny that covers $action — exact match, wildcard match
//   (e.g. `s3:Delete*`), a true full-admin Deny (action='*' AND excluded_actions IS NULL), or a
//   deny-all-except (Deny NotAction) node (action='*' AND excluded_actions IS NOT NULL AND
//   $action NOT IN excluded_actions) — i.e. Deny NotAction denies every action except the ones
//   listed. $deny_actions is the concrete set of exact/wildcard/full-admin Deny action strings
//   already matched against $action via iam_expander::glob_match (see
//   candidate_deny_actions.cypher); deny-all-except matching is plain set membership and is done
//   inline in Cypher instead, since it needs $action directly. A user's effective Deny set is
//   the union of its own policies and every group it is MEMBER_OF; Deny from either side
//   suppresses the user.
//   Permission Boundary evaluation: an entity with a BOUNDED_BY edge is only returned if its
//   boundary policy also Allows $action — exact/wildcard-matched (via $boundary_allow_actions,
//   computed in Rust the same way as $deny_actions), a true full-admin boundary
//   (action='*' AND excluded_actions IS NULL, caps nothing), or an allow-all-except boundary
//   (action='*' AND excluded_actions IS NOT NULL AND $action NOT IN excluded_actions). Entities
//   with no BOUNDED_BY edge are unaffected. is_bounded reports whether a boundary is attached,
//   regardless of whether it capped anything.
//   Every arm also returns perm.resource and a grant_kind ('exact' for arms 1/2, 'wildcard' for
//   arm 3) so the Rust caller can intersect arm-3's resource against an optional queried
//   resource via iam_expander::glob_match (no glob logic in Cypher) — see who_can() in
//   src/queries/analysis.rs. See limitations.md.
// param $action: IAM action to test (e.g. "s3:GetObject")
// param $snapshot_id: snapshot scope
// param $account_id: account scope for tenant isolation
// param $deny_actions: concrete Deny action strings (exact/wildcard-matched/full-admin) that cover $action
// param $boundary_allow_actions: concrete boundary Allow action strings (exact/wildcard-matched) that cover $action
// Each arm also returns perm.condition (raw JSON string, or null) so the Rust caller can
// evaluate the fixed condition subset (iam_models::condition::evaluate) against optional
// query context and flag/exclude gated grants — see who_can() in src/queries/analysis.rs.

MATCH (e)-[:HAS_ATTACHED_POLICY|HAS_INLINE_POLICY*1..2]->(pol)
      -[:GRANTS]->(perm:Permission {
          action: $action,
          effect: 'Allow',
          snapshot_id: $snapshot_id
      })
WHERE e.account_id = $account_id
  AND NOT EXISTS {
      MATCH (e)-[:HAS_ATTACHED_POLICY|HAS_INLINE_POLICY*1..2]->(dpol)
            -[:GRANTS]->(deny:Permission {
                effect: 'Deny',
                snapshot_id: $snapshot_id
            })
      WHERE deny.action IN $deny_actions
         OR (deny.action = '*' AND deny.excluded_actions IS NOT NULL
             AND NOT $action IN deny.excluded_actions)
  }
  AND NOT EXISTS {
      MATCH (e)-[:MEMBER_OF]->(:Group)-[:HAS_ATTACHED_POLICY|HAS_INLINE_POLICY*1..2]->(dpol)
            -[:GRANTS]->(deny:Permission {
                effect: 'Deny',
                snapshot_id: $snapshot_id
            })
      WHERE deny.action IN $deny_actions
         OR (deny.action = '*' AND deny.excluded_actions IS NOT NULL
             AND NOT $action IN deny.excluded_actions)
  }
  AND (
      NOT EXISTS { MATCH (e)-[:BOUNDED_BY]->(:Policy) }
      OR EXISTS {
          MATCH (e)-[:BOUNDED_BY]->(:Policy)-[:GRANTS]->(b:Permission {
              effect: 'Allow',
              snapshot_id: $snapshot_id
          })
          WHERE b.action IN $boundary_allow_actions
             OR (b.action = '*' AND b.excluded_actions IS NULL)
             OR (b.action = '*' AND b.excluded_actions IS NOT NULL
                 AND NOT $action IN b.excluded_actions)
      }
  )
RETURN e.arn AS arn, e.name AS name, labels(e)[0] AS entity_type, false AS is_full_admin,
       perm.resource AS resource, 'exact' AS grant_kind,
       EXISTS { MATCH (e)-[:BOUNDED_BY]->(:Policy) } AS is_bounded,
       perm.condition AS condition
UNION
MATCH (u:User)-[:MEMBER_OF]->(g:Group)
      -[:HAS_ATTACHED_POLICY|HAS_INLINE_POLICY*1..2]->(pol)
      -[:GRANTS]->(perm:Permission {
          action: $action,
          effect: 'Allow',
          snapshot_id: $snapshot_id
      })
WHERE u.account_id = $account_id
  AND NOT EXISTS {
      MATCH (u)-[:HAS_ATTACHED_POLICY|HAS_INLINE_POLICY*1..2]->(dpol)
            -[:GRANTS]->(deny:Permission {
                effect: 'Deny',
                snapshot_id: $snapshot_id
            })
      WHERE deny.action IN $deny_actions
         OR (deny.action = '*' AND deny.excluded_actions IS NOT NULL
             AND NOT $action IN deny.excluded_actions)
  }
  AND NOT EXISTS {
      MATCH (u)-[:MEMBER_OF]->(:Group)-[:HAS_ATTACHED_POLICY|HAS_INLINE_POLICY*1..2]->(dpol)
            -[:GRANTS]->(deny:Permission {
                effect: 'Deny',
                snapshot_id: $snapshot_id
            })
      WHERE deny.action IN $deny_actions
         OR (deny.action = '*' AND deny.excluded_actions IS NOT NULL
             AND NOT $action IN deny.excluded_actions)
  }
  AND (
      NOT EXISTS { MATCH (u)-[:BOUNDED_BY]->(:Policy) }
      OR EXISTS {
          MATCH (u)-[:BOUNDED_BY]->(:Policy)-[:GRANTS]->(b:Permission {
              effect: 'Allow',
              snapshot_id: $snapshot_id
          })
          WHERE b.action IN $boundary_allow_actions
             OR (b.action = '*' AND b.excluded_actions IS NULL)
             OR (b.action = '*' AND b.excluded_actions IS NOT NULL
                 AND NOT $action IN b.excluded_actions)
      }
  )
RETURN u.arn AS arn, u.name AS name, labels(u)[0] AS entity_type, false AS is_full_admin,
       perm.resource AS resource, 'exact' AS grant_kind,
       EXISTS { MATCH (u)-[:BOUNDED_BY]->(:Policy) } AS is_bounded,
       perm.condition AS condition
UNION
MATCH (e)-[:HAS_ATTACHED_POLICY|HAS_INLINE_POLICY*1..2]->(pol)
      -[:GRANTS]->(perm:Permission {
          action: '*',
          effect: 'Allow',
          snapshot_id: $snapshot_id
      })
WHERE e.account_id = $account_id
  AND NOT $action IN coalesce(perm.excluded_actions, [])
  AND NOT EXISTS {
      MATCH (e)-[:HAS_ATTACHED_POLICY|HAS_INLINE_POLICY*1..2]->(dpol)
            -[:GRANTS]->(deny:Permission {
                effect: 'Deny',
                snapshot_id: $snapshot_id
            })
      WHERE deny.action IN $deny_actions
         OR (deny.action = '*' AND deny.excluded_actions IS NOT NULL
             AND NOT $action IN deny.excluded_actions)
  }
  AND NOT EXISTS {
      MATCH (e)-[:MEMBER_OF]->(:Group)-[:HAS_ATTACHED_POLICY|HAS_INLINE_POLICY*1..2]->(dpol)
            -[:GRANTS]->(deny:Permission {
                effect: 'Deny',
                snapshot_id: $snapshot_id
            })
      WHERE deny.action IN $deny_actions
         OR (deny.action = '*' AND deny.excluded_actions IS NOT NULL
             AND NOT $action IN deny.excluded_actions)
  }
  AND (
      NOT EXISTS { MATCH (e)-[:BOUNDED_BY]->(:Policy) }
      OR EXISTS {
          MATCH (e)-[:BOUNDED_BY]->(:Policy)-[:GRANTS]->(b:Permission {
              effect: 'Allow',
              snapshot_id: $snapshot_id
          })
          WHERE b.action IN $boundary_allow_actions
             OR (b.action = '*' AND b.excluded_actions IS NULL)
             OR (b.action = '*' AND b.excluded_actions IS NOT NULL
                 AND NOT $action IN b.excluded_actions)
      }
  )
RETURN e.arn AS arn, e.name AS name, labels(e)[0] AS entity_type,
       perm.excluded_actions IS NULL AS is_full_admin,
       perm.resource AS resource, 'wildcard' AS grant_kind,
       EXISTS { MATCH (e)-[:BOUNDED_BY]->(:Policy) } AS is_bounded,
       perm.condition AS condition
