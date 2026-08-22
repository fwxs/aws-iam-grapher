# list_account_ids

## Purpose

Distinct `account_id`s that have at least one snapshot in the graph, ordered for
deterministic multi-account fan-out (the `query` subcommand's default behavior when
`--account-id` is omitted).

## Parameters

None.

## Cypher

```cypher
MATCH (s:Snapshot)
RETURN DISTINCT s.account_id AS account_id
ORDER BY account_id
```

## Rust binding

`crates/iam-graph/src/queries/snapshots.rs` — `LIST_ACCOUNT_IDS_QUERY`, used in
`list_account_ids(graph: &Graph) -> Result<Vec<String>, GraphError>`.

## Returns

Plain `Vec<String>` of account ids.
