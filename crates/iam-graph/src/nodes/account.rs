use crate::nodes::Row;

/// UNWIND-batched: MERGE an AwsAccount node per row.
pub const MERGE_ACCOUNT: &str = "
    UNWIND $rows AS row
    MERGE (a:AwsAccount {id: row.id})
    ON CREATE SET a.alias = row.alias, a.ou_id = row.ou_id, a.ou_name = row.ou_name
    ON MATCH SET a.alias = CASE WHEN row.alias IS NOT NULL THEN row.alias ELSE a.alias END,
        a.ou_id = CASE WHEN row.ou_id IS NOT NULL THEN row.ou_id ELSE a.ou_id END,
        a.ou_name = CASE WHEN row.ou_name IS NOT NULL THEN row.ou_name ELSE a.ou_name END
";

/// UNWIND-batched: MERGE a Snapshot node per row.
pub const MERGE_SNAPSHOT: &str = "
    UNWIND $rows AS row
    MERGE (s:Snapshot {id: row.id})
    SET s.account_id = row.account_id,
        s.collected_at = row.collected_at,
        s.is_partial = row.is_partial,
        s.partial_reasons = row.partial_reasons,
        s.org_collection_run_id = row.org_collection_run_id
";

/// UNWIND-batched: create the Snapshot → AwsAccount relationship per row.
pub const SNAPSHOT_OF_ACCOUNT: &str = "
    UNWIND $rows AS row
    MATCH (s:Snapshot {id: row.snapshot_id})
    MATCH (a:AwsAccount {id: row.account_id})
    MERGE (s)-[:OF_ACCOUNT]->(a)
";

/// Build a row for the `MERGE_ACCOUNT` UNWIND statement.
///
/// `ou_id`/`ou_name` are the account's immediate parent Organizational Unit, populated only
/// for accounts ingested via `collect org`; both are empty strings for standalone
/// (live/offline/hybrid) collection or an account directly under the org root.
pub fn account_row(
    account_id: &str,
    alias: Option<&str>,
    ou_id: Option<&str>,
    ou_name: Option<&str>,
) -> Row {
    Row::from([
        ("id".to_string(), account_id.into()),
        ("alias".to_string(), alias.unwrap_or("").into()),
        ("ou_id".to_string(), ou_id.unwrap_or("").into()),
        ("ou_name".to_string(), ou_name.unwrap_or("").into()),
    ])
}

/// Build a row for the `MERGE_SNAPSHOT` UNWIND statement.
pub fn snapshot_row(
    snapshot_id: &str,
    account_id: &str,
    collected_at: &str,
    is_partial: bool,
    partial_reasons: Vec<String>,
    org_collection_run_id: Option<&str>,
) -> Row {
    Row::from([
        ("id".to_string(), snapshot_id.into()),
        ("account_id".to_string(), account_id.into()),
        ("collected_at".to_string(), collected_at.into()),
        ("is_partial".to_string(), is_partial.into()),
        ("partial_reasons".to_string(), partial_reasons.into()),
        (
            "org_collection_run_id".to_string(),
            org_collection_run_id.unwrap_or("").into(),
        ),
    ])
}

/// Build a row for the `SNAPSHOT_OF_ACCOUNT` UNWIND statement.
pub fn snapshot_of_account_row(snapshot_id: &str, account_id: &str) -> Row {
    Row::from([
        ("snapshot_id".to_string(), snapshot_id.into()),
        ("account_id".to_string(), account_id.into()),
    ])
}
