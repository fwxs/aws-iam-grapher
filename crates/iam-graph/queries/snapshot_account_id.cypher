// name: snapshot_account_id
// description: Look up the account_id a given snapshot belongs to, so callers can derive
//   a QueryContext from an explicit snapshot id without requiring --account-id.
// param $snapshot_id: snapshot to look up

MATCH (s:Snapshot {id: $snapshot_id})
RETURN s.account_id AS account_id
