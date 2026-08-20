# candidate_boundary_actions

## Purpose

Every distinct Allow action string granted by a Permission Boundary policy (reached via
`BOUNDED_BY`) in this snapshot/account scope, excluding allow-all-except sentinel nodes
(`action = '*'` with `excluded_actions` set — those are matched inline in Cypher instead,
see [`who_can`](who-can.md) / [`entity_permissions`](entity-permissions.md)).

## Parameters

- `$snapshot_id` — snapshot scope
- `$account_id` — account scope for tenant isolation

## Cypher

```cypher
MATCH (e)-[:BOUNDED_BY]->(:Policy)-[:GRANTS]->(perm:Permission {
    effect: 'Allow',
    snapshot_id: $snapshot_id
})
WHERE e.account_id = $account_id
  AND perm.excluded_actions IS NULL
RETURN DISTINCT perm.action AS action
```

## Rust binding

`crates/iam-graph/src/queries/analysis.rs` — `CANDIDATE_BOUNDARY_ACTIONS_QUERY`, used by the
private helper `candidate_boundary_actions(graph: &Graph, ctx: &QueryContext) -> Result<Vec<String>, GraphError>`,
called from [`who_can`](who-can.md).

## Returns

`Vec<String>` of candidate boundary-Allow action strings.

## Notes

The caller matches the queried action against this list via `iam_expander::glob_match` to
compute the concrete set of boundary-allowed actions that cover it, then passes that set back
as `$boundary_allow_actions`. See `docs/limitations.md`.
