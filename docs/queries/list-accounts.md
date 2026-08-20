# list_accounts

## Purpose

Every distinct `AwsAccount` node in the graph, with its alias and — for accounts ingested via
`collect org` — the immediate OU id/name they belong to.

## Parameters

None. This query is inherently cross-account (it's how a user discovers which accounts exist
to query), so unlike other queries it does not require an `account_id`/`snapshot_id` scope.

## Cypher

```cypher
MATCH (a:AwsAccount)
RETURN a.id AS id,
       coalesce(a.alias, "") AS alias,
       coalesce(a.ou_id, "") AS ou_id,
       coalesce(a.ou_name, "") AS ou_name
ORDER BY a.id
```

## Rust binding

`crates/iam-graph/src/queries/accounts.rs` — `LIST_ACCOUNTS_QUERY`, used in
`list_accounts(graph: &Graph) -> Result<Vec<AccountRecord>, GraphError>` — no `QueryContext`
by design.

## Returns

`Vec<AccountRecord>` where `AccountRecord { id, alias: Option<String>, ou_id: Option<String>, ou_name: Option<String> }`.
Empty-string coalesced columns are converted to `None` in Rust.
