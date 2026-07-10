use crate::errors::GraphError;
use neo4rs::Graph;

/// One `AwsAccount` node in the graph: its id, optional alias, and — for accounts ingested
/// via `collect org` — the immediate parent Organizational Unit it belongs to.
#[derive(Debug, Clone, serde::Serialize)]
pub struct AccountRecord {
    pub id: String,
    pub alias: Option<String>,
    pub ou_id: Option<String>,
    pub ou_name: Option<String>,
}

const LIST_ACCOUNTS_QUERY: &str = include_str!("../../queries/list_accounts.cypher");

/// Return every distinct account in the graph, ordered by account id.
///
/// Cross-account by design: unlike other queries in this module, this does not take a
/// `QueryContext` — it's how a user discovers which accounts exist to query in the first
/// place.
pub async fn list_accounts(graph: &Graph) -> Result<Vec<AccountRecord>, GraphError> {
    let mut stream = graph.execute(neo4rs::query(LIST_ACCOUNTS_QUERY)).await?;

    let mut results = Vec::new();
    while let Some(row) = stream.next().await? {
        let id: String = row
            .get("id")
            .map_err(|e| GraphError::UnexpectedResult(e.to_string()))?;
        let alias: String = row.get("alias").unwrap_or_default();
        let ou_id: String = row.get("ou_id").unwrap_or_default();
        let ou_name: String = row.get("ou_name").unwrap_or_default();
        results.push(AccountRecord {
            id,
            alias: non_empty(alias),
            ou_id: non_empty(ou_id),
            ou_name: non_empty(ou_name),
        });
    }
    Ok(results)
}

fn non_empty(s: String) -> Option<String> {
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}
