use neo4rs::{query, Query};

const MERGE_ACCOUNT: &str = "
    MERGE (a:AwsAccount {id: $id})
    ON CREATE SET a.alias = $alias
    ON MATCH SET a.alias = CASE WHEN $alias IS NOT NULL THEN $alias ELSE a.alias END
";

const MERGE_SNAPSHOT: &str = "
    MERGE (s:Snapshot {id: $id})
    SET s.account_id = $account_id,
        s.collected_at = $collected_at,
        s.is_partial = $is_partial
";

const SNAPSHOT_OF_ACCOUNT: &str = "
    MATCH (s:Snapshot {id: $snapshot_id})
    MATCH (a:AwsAccount {id: $account_id})
    MERGE (s)-[:OF_ACCOUNT]->(a)
";

/// Build a query to MERGE an AwsAccount node.
pub fn merge_account_query(account_id: &str, alias: Option<&str>) -> Query {
    query(MERGE_ACCOUNT)
        .param("id", account_id)
        .param("alias", alias.unwrap_or(""))
}

/// Build a query to MERGE a Snapshot node.
pub fn merge_snapshot_query(
    snapshot_id: &str,
    account_id: &str,
    collected_at: &str,
    is_partial: bool,
) -> Query {
    query(MERGE_SNAPSHOT)
        .param("id", snapshot_id)
        .param("account_id", account_id)
        .param("collected_at", collected_at)
        .param("is_partial", is_partial)
}

/// Build a query to create the Snapshot → AwsAccount relationship.
pub fn snapshot_of_account_query(snapshot_id: &str, account_id: &str) -> Query {
    query(SNAPSHOT_OF_ACCOUNT)
        .param("snapshot_id", snapshot_id)
        .param("account_id", account_id)
}
