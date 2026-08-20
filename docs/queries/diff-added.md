# diff_added

## Purpose

Permissions present in snapshot B but absent from snapshot A (newly added).

## Parameters

- `$snapshot_a` — baseline snapshot id
- `$snapshot_b` — comparison snapshot id
- `$account_id` — account scope for tenant isolation

## Cypher

```cypher
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
```

## Rust binding

`crates/iam-graph/src/queries/snapshots.rs` — `DIFF_ADDED_QUERY`, used inside
`diff_permissions(graph: &Graph, account_id: &str, snapshot_a: &str, snapshot_b: &str) -> Result<PermissionDiff, GraphError>`.

## Returns

Rows of `{ action, resource, effect }`, collected into `PermissionDiff.added: Vec<PermissionRecord>`.

## Notes

Has a sibling query, `diff_removed.cypher`, which is the mirror image (permissions in A but
absent from B) and feeds `PermissionDiff.removed`. Both are run by the same
`diff_permissions()` call.
