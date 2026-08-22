// name: snapshots_for_org_run
// description: All snapshots belonging to one org collection run, across accounts. Includes partial-collection metadata.
// param $org_run_id: org_collection_run_id shared by every snapshot in one `collect org` run

MATCH (s:Snapshot {org_collection_run_id: $org_run_id})
RETURN s.id AS id, s.account_id AS account_id,
       s.collected_at AS collected_at, s.is_partial AS is_partial,
       coalesce(s.partial_reasons, []) AS partial_reasons,
       coalesce(s.org_collection_run_id, "") AS org_collection_run_id
ORDER BY s.collected_at DESC
