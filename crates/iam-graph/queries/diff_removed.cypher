// name: diff_removed
// description: Permissions present in snapshot A but absent from snapshot B (removed).
//   Permission is a global, action-keyed node — the (action, resource, effect) tuple
//   comparison runs over GRANTS edges scoped by snapshot_id/account_id, not node properties.
// param $snapshot_a: baseline snapshot id
// param $snapshot_b: comparison snapshot id
// param $account_id: account scope for tenant isolation

MATCH (:Policy|InlinePolicy)-[g:GRANTS {snapshot_id: $snapshot_a, account_id: $account_id}]
        ->(perm:Permission)
WHERE NOT EXISTS {
    MATCH (:Policy|InlinePolicy)-[gb:GRANTS {
        snapshot_id: $snapshot_b,
        account_id: $account_id,
        effect: g.effect,
        resource: g.resource
    }]->(:Permission {action: perm.action})
}
RETURN DISTINCT perm.action AS action, g.resource AS resource, g.effect AS effect
ORDER BY perm.action
