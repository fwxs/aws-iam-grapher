// name: list_accounts
// description: Every distinct AwsAccount node in the graph, with its alias and — for
//   accounts ingested via `collect org` — the immediate OU id/name they belong to. This is
//   inherently cross-account (it's how a user discovers which accounts exist to query), so
//   unlike other queries it does not require an account_id/snapshot_id scope.

MATCH (a:AwsAccount)
RETURN a.id AS id,
       coalesce(a.alias, "") AS alias,
       coalesce(a.ou_id, "") AS ou_id,
       coalesce(a.ou_name, "") AS ou_name
ORDER BY a.id
