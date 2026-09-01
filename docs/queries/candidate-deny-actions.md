# candidate_deny_actions

## Purpose

Every distinct Deny action string present in this snapshot/account scope, excluding
Deny-NotAction grants (`action = '*'` with the `GRANTS` edge's `excluded_actions` set — those are
not evaluated here, see `docs/limitations.md`).

## Parameters

- `$snapshot_id` — snapshot scope
- `$account_id` — account scope for tenant isolation

## Cypher

```cypher
MATCH (:Policy|InlinePolicy)-[g:GRANTS {
    effect: 'Deny',
    snapshot_id: $snapshot_id,
    account_id: $account_id
}]->(deny:Permission)
WHERE g.excluded_actions IS NULL
RETURN DISTINCT deny.action AS action
```

## Rust binding

`crates/iam-graph/src/queries/analysis.rs` — `CANDIDATE_DENY_ACTIONS_QUERY`, used by the
private helper `candidate_deny_actions(graph: &Graph, ctx: &QueryContext) -> Result<Vec<String>, GraphError>`,
called from [`who_can`](who-can.md).

## Returns

`Vec<String>` of candidate Deny action strings.

## Notes

`Permission` is a global, action-keyed node with no `snapshot_id`/`account_id` of its own — this
query starts at the scoped `Policy`/`InlinePolicy` set and reaches `Permission` via its `GRANTS`
edge, which is where `effect`, `excluded_actions`, `snapshot_id`, and `account_id` actually live.
Starting at the `Permission` node directly (as this query used to) would return Deny actions from
every account in the graph, not just this one — see `docs/limitations.md`.

The caller matches the queried action against this list with IAM glob semantics
(`iam_expander::glob_match`) to compute the concrete set of Deny actions that cover it, then
passes that set back into `who_can.cypher` / `privilege_escalation_paths.cypher` as
`$deny_actions`. Cypher itself does no glob matching.
