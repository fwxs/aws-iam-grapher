use crate::errors::GraphError;
use crate::nodes::relationships::stitch_cross_account_query;
use crate::queries::col;
use neo4rs::Graph;

/// Materialize cross-account `CAN_ASSUME_ROLE` edges for one org collection run.
///
/// Returns the number of edges created or updated. The underlying query is idempotent
/// (`MERGE`), so calling this multiple times for the same `org_run_id` is safe.
pub async fn stitch_cross_account(graph: &Graph, org_run_id: &str) -> Result<u64, GraphError> {
    let mut stream = graph
        .execute(stitch_cross_account_query(org_run_id))
        .await?;

    if let Some(row) = stream.next().await? {
        let count: i64 = col(&row, "edges_created")?;
        Ok(count as u64)
    } else {
        Ok(0)
    }
}
