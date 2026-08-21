# candidate_deny_actions

## Purpose

Every distinct Deny action string present in this snapshot/account scope, excluding
Deny-NotAction sentinel nodes (`action = '*'` with `excluded_actions` set — those are not
evaluated here, see `docs/limitations.md`).

## Parameters

- `$snapshot_id` — snapshot scope
- `$account_id` — account scope for tenant isolation

## Cypher

```cypher
MATCH (deny:Permission {
    effect: 'Deny',
    snapshot_id: $snapshot_id,
    account_id: $account_id
})
WHERE deny.excluded_actions IS NULL
RETURN DISTINCT deny.action AS action
```

## Rust binding

`crates/iam-graph/src/queries/analysis.rs` — `CANDIDATE_DENY_ACTIONS_QUERY`, used by the
private helper `candidate_deny_actions(graph: &Graph, ctx: &QueryContext) -> Result<Vec<String>, GraphError>`,
called from [`who_can`](who-can.md).

## Returns

`Vec<String>` of candidate Deny action strings.

## Notes

The caller matches the queried action against this list with IAM glob semantics
(`iam_expander::glob_match`) to compute the concrete set of Deny actions that cover it, then
passes that set back into `who_can.cypher` / `privilege_escalation_paths.cypher` as
`$deny_actions`. Cypher itself does no glob matching.
