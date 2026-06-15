// name: who_can
// description: Returns all entities with an Allow permission for $action in this snapshot.
//   Three UNION arms: (1) direct entity→policy grant, (2) user via group membership,
//   (3) entity with action='*' Allow — covers true full-admin (excluded_actions IS NULL) and
//   allow-all-except (NotAction) nodes. Arm 3 filters out entities where $action is in
//   excluded_actions, honoring NotAction exclusions exactly. is_full_admin is true only for
//   true full-admin grants (excluded_actions IS NULL); NotAction grants set it false.
//   Each arm excludes entities with an explicit Deny on $action or a true full-admin Deny
//   (action='*' AND excluded_actions IS NULL). Deny-NotAction nodes (action='*' Deny with
//   excluded_actions) are stored but not evaluated. See limitations.md.
// param $action: IAM action to test (e.g. "s3:GetObject")
// param $snapshot_id: snapshot scope
// param $account_id: account scope for tenant isolation

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
      WHERE deny.action = $action
         OR (deny.action = '*' AND deny.excluded_actions IS NULL)
  }
RETURN e.arn AS arn, e.name AS name, labels(e)[0] AS entity_type, false AS is_full_admin
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
      WHERE deny.action = $action
         OR (deny.action = '*' AND deny.excluded_actions IS NULL)
  }
RETURN u.arn AS arn, u.name AS name, labels(u)[0] AS entity_type, false AS is_full_admin
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
      WHERE deny.action = $action
         OR (deny.action = '*' AND deny.excluded_actions IS NULL)
  }
RETURN e.arn AS arn, e.name AS name, labels(e)[0] AS entity_type,
       perm.excluded_actions IS NULL AS is_full_admin
