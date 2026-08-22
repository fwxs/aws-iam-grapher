# entity_permissions

## Purpose

All permissions (action, effect, resource) reachable from a specific entity via attached or
inline policies in a snapshot.

## Parameters

- `$uid` — entity uid (`"snapshot_id|arn"`)
- `$snapshot_id` — snapshot scope

## Cypher

```cypher
MATCH (e {uid: $uid})-[:HAS_ATTACHED_POLICY|HAS_INLINE_POLICY*1..2]->(pol)
      -[:GRANTS]->(perm:Permission {snapshot_id: $snapshot_id})
RETURN perm.action AS action, perm.effect AS effect, perm.resource AS resource
```

## Rust binding

`crates/iam-graph/src/queries/analysis.rs` — `ENTITY_PERMISSIONS_QUERY`, used in
`entity_permissions(graph: &Graph, ctx: &QueryContext, entity_arn: &str) -> Result<Vec<PermissionRow>, GraphError>`.

## Returns

`Vec<PermissionRow>` where `PermissionRow { action, effect, resource, effective }`.

## Notes

The query itself does not compute `effective` — the Rust caller separately fetches the
entity's Permission Boundary Allow set via [`entity_boundary_actions`](entity-boundary-actions.md)
and computes `effective` per row using `iam_expander::glob_match` (no glob logic lives in
Cypher). `entity_permissions()` also checks entity existence first, returning
`GraphError::EntityNotFound` if the uid doesn't resolve. See `docs/limitations.md`.
