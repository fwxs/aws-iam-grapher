# diff_added

## Purpose

Permissions present in snapshot B but absent from snapshot A (newly added).

## Parameters

- `$snapshot_a` — baseline snapshot id
- `$snapshot_b` — comparison snapshot id
- `$account_id` — account scope for tenant isolation

## Cypher

```cypher
MATCH (:Policy|InlinePolicy)-[g:GRANTS {snapshot_id: $snapshot_b, account_id: $account_id}]
        ->(perm:Permission)
WHERE NOT EXISTS {
    MATCH (:Policy|InlinePolicy)-[ga:GRANTS {
        snapshot_id: $snapshot_a,
        account_id: $account_id,
        effect: g.effect,
        resource: g.resource
    }]->(:Permission {action: perm.action})
}
RETURN DISTINCT perm.action AS action, g.resource AS resource, g.effect AS effect
ORDER BY perm.action
```

## Rust binding

`crates/iam-graph/src/queries/snapshots.rs` — `DIFF_ADDED_QUERY`, used inside
`diff_permissions(graph: &Graph, account_id: &str, snapshot_a: &str, snapshot_b: &str) -> Result<PermissionDiff, GraphError>`.

## Returns

Rows of `{ action, resource, effect }`, collected into `PermissionDiff.added: Vec<PermissionRecord>`.

## Notes

`Permission` is a global, action-keyed node with no `snapshot_id`/`account_id` of its own — this
query starts at the scoped `Policy`/`InlinePolicy` set and reaches `Permission` via its `GRANTS`
edge, then re-checks the same `(action, resource, effect)` triple against snapshot A's `GRANTS`
edges to decide if the grant is genuinely new (rather than starting at the `Permission` node
directly, which would compare against the whole graph, not just this account's data).

Has a sibling query, `diff_removed.cypher`, which is the mirror image (permissions in A but
absent from B) and feeds `PermissionDiff.removed`. Both are run by the same
`diff_permissions()` call.
