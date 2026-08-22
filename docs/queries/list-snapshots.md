# list_snapshots

## Purpose

All snapshots for an account, ordered newest first. Includes partial-collection metadata.

## Parameters

- `$account_id` — account to list snapshots for

## Cypher

```cypher
MATCH (s:Snapshot {account_id: $account_id})
RETURN s.id AS id, s.account_id AS account_id,
       s.collected_at AS collected_at, s.is_partial AS is_partial,
       coalesce(s.partial_reasons, []) AS partial_reasons,
       coalesce(s.org_collection_run_id, "") AS org_collection_run_id
ORDER BY s.collected_at DESC
```

## Rust binding

`crates/iam-graph/src/queries/snapshots.rs` — `LIST_SNAPSHOTS_QUERY`, used in
`list_snapshots(graph: &Graph, account_id: &str) -> Result<Vec<SnapshotRecord>, GraphError>`.

## Returns

`Vec<SnapshotRecord>`, same shape as [`snapshots_for_org_run`](snapshots-for-org-run.md).
`org_collection_run_id` is empty-string coalesced in Cypher, then mapped to `None` in Rust.
