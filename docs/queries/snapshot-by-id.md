# snapshot_by_id

## Purpose

Look up the full snapshot record (`account_id`, `collected_at`, partiality) for an explicit
snapshot id in one round trip, so scope resolution never needs a second `list_snapshots` call
just to read `is_partial`/`partial_reasons`.

## Parameters

- `$snapshot_id` — snapshot to look up

## Cypher

```cypher
MATCH (s:Snapshot {id: $snapshot_id})
RETURN s.id AS id, s.account_id AS account_id,
       s.collected_at AS collected_at, s.is_partial AS is_partial,
       coalesce(s.partial_reasons, []) AS partial_reasons,
       coalesce(s.org_collection_run_id, "") AS org_collection_run_id
```

## Rust binding

`crates/iam-graph/src/queries/snapshots.rs` — `SNAPSHOT_BY_ID_QUERY`, used in
`snapshot_record(graph: &Graph, snapshot_id: &str) -> Result<Option<SnapshotRecord>, GraphError>`.

## Returns

`Option<SnapshotRecord>` — `None` if no snapshot with that id exists, else `Some(SnapshotRecord)`
(same shape as [`list_snapshots`](list-snapshots.md)).
