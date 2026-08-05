use crate::errors::GraphError;
use crate::queries::{col, col_or_default};
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
        let id: String = col(&row, "id")?;
        // alias/ou_id/ou_name are optional-by-data-model: an account has no alias unless one
        // was set, and only accounts ingested via `collect org` carry an OU. The Cypher
        // (list_accounts.cypher) already `coalesce`s each to "", so an absent value here means
        // "not set" rather than a malformed row.
        let alias: String = col_or_default(&row, "alias");
        let ou_id: String = col_or_default(&row, "ou_id");
        let ou_name: String = col_or_default(&row, "ou_name");
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
