// name: who_can
// description: Returns all entities with an Allow permission for $action in this snapshot.
//   Three UNION arms: (1) direct entity→policy grant, (2) user via group membership,
//   (3) entity with Action:'*' — covers both true full-admin (no excluded_actions) and
//   allow-all-except (NotAction) nodes. Arm 3 filters out entities where $action is in
//   the Permission's excluded_actions list, so NotAction exclusions are honored exactly.
//   Each arm also excludes entities that have an explicit Deny on $action or '*' in their
//   own policies. Deny scope is approximate: only exact-action and Action:'*' Denies are
//   checked; wildcard Denies (e.g. s3:Delete*) and group-inherited Denies for a user's
//   own policies are not evaluated (see limitations.md).
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
      WHERE deny.action IN [$action, '*']
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
      WHERE deny.action IN [$action, '*']
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
      WHERE deny.action IN [$action, '*']
  }
RETURN e.arn AS arn, e.name AS name, labels(e)[0] AS entity_type, true AS is_full_admin
