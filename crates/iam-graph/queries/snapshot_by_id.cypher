// name: snapshot_by_id
// description: Look up the full snapshot record (account_id, collected_at, partiality) for an
//   explicit snapshot id in one round trip, so scope resolution never needs a second
//   list_snapshots call to read is_partial/partial_reasons.
// param $snapshot_id: snapshot to look up

MATCH (s:Snapshot {id: $snapshot_id})
RETURN s.id AS id, s.account_id AS account_id,
       s.collected_at AS collected_at, s.is_partial AS is_partial,
       coalesce(s.partial_reasons, []) AS partial_reasons,
       coalesce(s.org_collection_run_id, "") AS org_collection_run_id
