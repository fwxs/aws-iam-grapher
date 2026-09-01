# entity_boundary_actions

## Purpose

Every Allow permission (`action`, `excluded_actions`) granted by `$uid`'s Permission
Boundary policy, if attached, in this snapshot.

## Parameters

- `$uid` — entity uid (`"snapshot_id|arn"`)
- `$snapshot_id` — snapshot scope

## Cypher

```cypher
MATCH (e {uid: $uid})-[:BOUNDED_BY]->(:Policy)-[g:GRANTS {
    effect: 'Allow',
    snapshot_id: $snapshot_id
}]->(perm:Permission)
RETURN perm.action AS action, g.excluded_actions AS excluded_actions
```

## Rust binding

`crates/iam-graph/src/queries/analysis.rs` — `ENTITY_BOUNDARY_ACTIONS_QUERY`, used inline
inside [`entity_permissions`](entity-permissions.md) (not a standalone public function).

## Returns

`Vec<BoundaryEntry>` where `BoundaryEntry { action, excluded_actions: Option<Vec<String>> }`.

## Notes

`Permission` is a global, action-keyed node; `effect` and `excluded_actions` live on the `GRANTS`
relationship. Used by `entity_permissions()` to compute each permission row's `effective` flag via
`iam_expander::glob_match` against each boundary action — matching exact/wildcard actions, a
full-admin boundary (`action = '*'`, `GRANTS.excluded_actions IS NULL`), or an allow-all-except
boundary (`action = '*'`, `GRANTS.excluded_actions IS NOT NULL`).
