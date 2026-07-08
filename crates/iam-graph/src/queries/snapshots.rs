use crate::errors::GraphError;
use neo4rs::Graph;

/// A snapshot record stored in the graph.
#[derive(Debug, Clone, serde::Serialize)]
pub struct SnapshotRecord {
    pub id: String,
    pub account_id: String,
    pub collected_at: String,
    pub is_partial: bool,
    pub partial_reasons: Vec<String>,
    pub org_collection_run_id: Option<String>,
}

const LIST_SNAPSHOTS_QUERY: &str = include_str!("../../queries/list_snapshots.cypher");

/// Return all snapshots for the given account, newest first.
pub async fn list_snapshots(
    graph: &Graph,
    account_id: &str,
) -> Result<Vec<SnapshotRecord>, GraphError> {
    let mut stream = graph
        .execute(neo4rs::query(LIST_SNAPSHOTS_QUERY).param("account_id", account_id))
        .await?;

    let mut results = Vec::new();
    while let Some(row) = stream.next().await? {
        let id: String = row
            .get("id")
            .map_err(|e| GraphError::UnexpectedResult(e.to_string()))?;
        let account_id: String = row
            .get("account_id")
            .map_err(|e| GraphError::UnexpectedResult(e.to_string()))?;
        let collected_at: String = row
            .get("collected_at")
            .map_err(|e| GraphError::UnexpectedResult(e.to_string()))?;
        let is_partial: bool = row
            .get("is_partial")
            .map_err(|e| GraphError::UnexpectedResult(e.to_string()))?;
        let partial_reasons: Vec<String> = row.get("partial_reasons").unwrap_or_default();
        let org_collection_run_id: Option<String> = row
            .get::<String>("org_collection_run_id")
            .ok()
            .filter(|s| !s.is_empty());
        results.push(SnapshotRecord {
            id,
            account_id,
            collected_at,
            is_partial,
            partial_reasons,
            org_collection_run_id,
        });
    }
    Ok(results)
}

const LIST_ACCOUNT_IDS_QUERY: &str = include_str!("../../queries/list_account_ids.cypher");

/// Return every distinct account_id that has at least one snapshot in the graph.
/// Used by the `query` CLI to fan out per-account when `--account-id` is omitted.
pub async fn list_account_ids(graph: &Graph) -> Result<Vec<String>, GraphError> {
    let mut stream = graph.execute(neo4rs::query(LIST_ACCOUNT_IDS_QUERY)).await?;

    let mut results = Vec::new();
    while let Some(row) = stream.next().await? {
        let account_id: String = row
            .get("account_id")
            .map_err(|e| GraphError::UnexpectedResult(e.to_string()))?;
        results.push(account_id);
    }
    Ok(results)
}

const SNAPSHOT_ACCOUNT_ID_QUERY: &str = include_str!("../../queries/snapshot_account_id.cypher");

/// Look up the account_id a snapshot belongs to, or `None` if the snapshot doesn't exist.
pub async fn snapshot_account_id(
    graph: &Graph,
    snapshot_id: &str,
) -> Result<Option<String>, GraphError> {
    let mut stream = graph
        .execute(neo4rs::query(SNAPSHOT_ACCOUNT_ID_QUERY).param("snapshot_id", snapshot_id))
        .await?;

    if let Some(row) = stream.next().await? {
        let account_id: String = row
            .get("account_id")
            .map_err(|e| GraphError::UnexpectedResult(e.to_string()))?;
        Ok(Some(account_id))
    } else {
        Ok(None)
    }
}

const LATEST_ORG_RUN_QUERY: &str = "
    MATCH (s:Snapshot)
    WHERE s.org_collection_run_id IS NOT NULL AND s.org_collection_run_id <> ''
    RETURN s.org_collection_run_id AS org_run_id
    ORDER BY s.collected_at DESC
    LIMIT 1
";

/// Return the most recent org collection run id, or `None` if no org runs exist.
pub async fn latest_org_run_id(graph: &Graph) -> Result<Option<String>, GraphError> {
    let mut stream = graph.execute(neo4rs::query(LATEST_ORG_RUN_QUERY)).await?;

    if let Some(row) = stream.next().await? {
        let id: String = row
            .get("org_run_id")
            .map_err(|e| GraphError::UnexpectedResult(e.to_string()))?;
        Ok(Some(id))
    } else {
        Ok(None)
    }
}

const DELETE_SNAPSHOT_QUERY: &str = include_str!("../../queries/delete_snapshot.cypher");

const DELETE_SNAPSHOT_NODE_QUERY: &str = include_str!("../../queries/delete_snapshot_node.cypher");

/// Delete all nodes belonging to `snapshot_id` (except AwsAccount and AwsService).
/// Returns the number of nodes deleted.
pub async fn delete_snapshot(graph: &Graph, snapshot_id: &str) -> Result<u64, GraphError> {
    // Delete entity nodes (those with snapshot_id property)
    let mut stream = graph
        .execute(neo4rs::query(DELETE_SNAPSHOT_QUERY).param("snapshot_id", snapshot_id))
        .await?;

    let deleted = if let Some(row) = stream.next().await? {
        let count: i64 = row
            .get("deleted")
            .map_err(|e| GraphError::UnexpectedResult(e.to_string()))?;
        count as u64
    } else {
        0
    };

    // Also delete the Snapshot node itself (has `id` not `snapshot_id`)
    graph
        .run(neo4rs::query(DELETE_SNAPSHOT_NODE_QUERY).param("snapshot_id", snapshot_id))
        .await?;

    Ok(deleted)
}

/// Permissions that differ between two snapshots of the same account.
#[derive(Debug, Clone, serde::Serialize)]
pub struct PermissionDiff {
    pub added: Vec<PermissionRecord>,
    pub removed: Vec<PermissionRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct PermissionRecord {
    pub action: String,
    pub resource: String,
    pub effect: String,
}

const DIFF_ADDED_QUERY: &str = include_str!("../../queries/diff_added.cypher");

const DIFF_REMOVED_QUERY: &str = include_str!("../../queries/diff_removed.cypher");

/// Compute added/removed permissions between two snapshots of the same account.
pub async fn diff_permissions(
    graph: &Graph,
    account_id: &str,
    snapshot_a: &str,
    snapshot_b: &str,
) -> Result<PermissionDiff, GraphError> {
    let (added, removed) = tokio::try_join!(
        fetch_permission_records(graph, DIFF_ADDED_QUERY, account_id, snapshot_a, snapshot_b),
        fetch_permission_records(
            graph,
            DIFF_REMOVED_QUERY,
            account_id,
            snapshot_a,
            snapshot_b
        ),
    )?;
    Ok(PermissionDiff { added, removed })
}

async fn fetch_permission_records(
    graph: &Graph,
    cypher: &str,
    account_id: &str,
    snapshot_a: &str,
    snapshot_b: &str,
) -> Result<Vec<PermissionRecord>, GraphError> {
    let mut stream = graph
        .execute(
            neo4rs::query(cypher)
                .param("account_id", account_id)
                .param("snapshot_a", snapshot_a)
                .param("snapshot_b", snapshot_b),
        )
        .await?;

    let mut results = Vec::new();
    while let Some(row) = stream.next().await? {
        let action: String = row
            .get("action")
            .map_err(|e| GraphError::UnexpectedResult(e.to_string()))?;
        let resource: String = row
            .get("resource")
            .map_err(|e| GraphError::UnexpectedResult(e.to_string()))?;
        let effect: String = row
            .get("effect")
            .map_err(|e| GraphError::UnexpectedResult(e.to_string()))?;
        results.push(PermissionRecord {
            action,
            resource,
            effect,
        });
    }
    Ok(results)
}
