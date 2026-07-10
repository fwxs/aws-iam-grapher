use neo4rs::{query, Query};

const MERGE_ACCOUNT: &str = "
    MERGE (a:AwsAccount {id: $id})
    ON CREATE SET a.alias = $alias, a.ou_id = $ou_id, a.ou_name = $ou_name
    ON MATCH SET a.alias = CASE WHEN $alias IS NOT NULL THEN $alias ELSE a.alias END,
        a.ou_id = CASE WHEN $ou_id IS NOT NULL THEN $ou_id ELSE a.ou_id END,
        a.ou_name = CASE WHEN $ou_name IS NOT NULL THEN $ou_name ELSE a.ou_name END
";

const MERGE_SNAPSHOT: &str = "
    MERGE (s:Snapshot {id: $id})
    SET s.account_id = $account_id,
        s.collected_at = $collected_at,
        s.is_partial = $is_partial,
        s.partial_reasons = $partial_reasons,
        s.org_collection_run_id = $org_collection_run_id
";

const SNAPSHOT_OF_ACCOUNT: &str = "
    MATCH (s:Snapshot {id: $snapshot_id})
    MATCH (a:AwsAccount {id: $account_id})
    MERGE (s)-[:OF_ACCOUNT]->(a)
";

/// Build a query to MERGE an AwsAccount node.
///
/// `ou_id`/`ou_name` are the account's immediate parent Organizational Unit, populated only
/// for accounts ingested via `collect org`; both are empty strings for standalone
/// (live/offline/hybrid) collection or an account directly under the org root.
pub fn merge_account_query(
    account_id: &str,
    alias: Option<&str>,
    ou_id: Option<&str>,
    ou_name: Option<&str>,
) -> Query {
    query(MERGE_ACCOUNT)
        .param("id", account_id)
        .param("alias", alias.unwrap_or(""))
        .param("ou_id", ou_id.unwrap_or(""))
        .param("ou_name", ou_name.unwrap_or(""))
}

/// Build a query to MERGE a Snapshot node.
pub fn merge_snapshot_query(
    snapshot_id: &str,
    account_id: &str,
    collected_at: &str,
    is_partial: bool,
    partial_reasons: Vec<String>,
    org_collection_run_id: Option<&str>,
) -> Query {
    query(MERGE_SNAPSHOT)
        .param("id", snapshot_id)
        .param("account_id", account_id)
        .param("collected_at", collected_at)
        .param("is_partial", is_partial)
        .param("partial_reasons", partial_reasons)
        .param("org_collection_run_id", org_collection_run_id.unwrap_or(""))
}

/// Build a query to create the Snapshot → AwsAccount relationship.
pub fn snapshot_of_account_query(snapshot_id: &str, account_id: &str) -> Query {
    query(SNAPSHOT_OF_ACCOUNT)
        .param("snapshot_id", snapshot_id)
        .param("account_id", account_id)
}
