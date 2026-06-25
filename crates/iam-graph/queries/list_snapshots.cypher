// name: list_snapshots
// description: All snapshots for an account, ordered newest first. Includes partial-collection metadata.
// param $account_id: account to list snapshots for

MATCH (s:Snapshot {account_id: $account_id})
RETURN s.id AS id, s.account_id AS account_id,
       s.collected_at AS collected_at, s.is_partial AS is_partial,
       coalesce(s.partial_reasons, []) AS partial_reasons,
       coalesce(s.org_collection_run_id, "") AS org_collection_run_id
ORDER BY s.collected_at DESC
