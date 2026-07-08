// name: list_account_ids
// description: Distinct account_ids that have at least one snapshot in the graph, ordered
//   for deterministic multi-account fan-out (query subcommand default when --account-id
//   is omitted).

MATCH (s:Snapshot)
RETURN DISTINCT s.account_id AS account_id
ORDER BY account_id
