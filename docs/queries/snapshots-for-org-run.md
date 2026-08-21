# snapshots_for_org_run

## Purpose

All snapshots belonging to one org collection run, across accounts. Includes
partial-collection metadata.

## Parameters

- `$org_run_id` — `org_collection_run_id` shared by every snapshot in one `collect org` run

## Cypher

```cypher
MATCH (s:Snapshot {org_collection_run_id: $org_run_id})
RETURN s.id AS id, s.account_id AS account_id,
       s.collected_at AS collected_at, s.is_partial AS is_partial,
       coalesce(s.partial_reasons, []) AS partial_reasons,
       coalesce(s.org_collection_run_id, "") AS org_collection_run_id
ORDER BY s.collected_at DESC
```

## Rust binding

`crates/iam-graph/src/queries/snapshots.rs` — `SNAPSHOTS_FOR_ORG_RUN_QUERY`, used in
`snapshots_for_org_run(graph: &Graph, org_run_id: &str) -> Result<Vec<SnapshotRecord>, GraphError>`.

## Returns

`Vec<SnapshotRecord>` where `SnapshotRecord { id, account_id, collected_at, is_partial, partial_reasons, org_collection_run_id: Option<String> }`.
