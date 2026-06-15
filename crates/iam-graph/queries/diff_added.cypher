// name: diff_added
// description: Permissions present in snapshot B but absent from snapshot A (newly added).
// param $snapshot_a: baseline snapshot id
// param $snapshot_b: comparison snapshot id
// param $account_id: account scope for tenant isolation

MATCH (perm:Permission {snapshot_id: $snapshot_b, account_id: $account_id})
WHERE NOT EXISTS {
    MATCH (:Permission {
        action: perm.action,
        resource: perm.resource,
        effect: perm.effect,
        snapshot_id: $snapshot_a,
        account_id: $account_id
    })
}
RETURN perm.action AS action, perm.resource AS resource, perm.effect AS effect
ORDER BY perm.action
