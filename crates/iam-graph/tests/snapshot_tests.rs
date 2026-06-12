mod helpers;

use iam_graph::{delete_snapshot, list_snapshots, GraphIngester};

#[tokio::test]
#[ignore = "requires Docker"]
async fn delete_snapshot_removes_only_target_snapshot() {
    let (client, _container) = helpers::start_neo4j().await;
    let account_id = "555566667777";

    // Ingest two snapshots
    let config_a = helpers::test_config(account_id);
    let snap_a = config_a.snapshot_id.clone();
    let ingester_a = GraphIngester::new(client, config_a);
    ingester_a
        .ingest(&helpers::empty_data(account_id))
        .await
        .expect("ingest A must succeed");

    let graph_client = ingester_a.into_client();
    let config_b = helpers::test_config(account_id);
    let snap_b = config_b.snapshot_id.clone();
    let ingester_b = GraphIngester::new(graph_client, config_b);
    ingester_b
        .ingest(&helpers::empty_data(account_id))
        .await
        .expect("ingest B must succeed");

    let graph = ingester_b.client().inner();

    // Confirm both snapshots exist
    let snapshots = list_snapshots(graph, account_id)
        .await
        .expect("list must succeed");
    assert_eq!(
        snapshots.len(),
        2,
        "both snapshots must exist before delete"
    );

    // Delete snapshot A
    delete_snapshot(graph, &snap_a)
        .await
        .expect("delete must succeed");

    // Snapshot B must survive; snapshot A must be gone
    let after = list_snapshots(graph, account_id)
        .await
        .expect("list must succeed");
    assert_eq!(after.len(), 1, "only one snapshot must remain");
    assert_eq!(after[0].id, snap_b, "surviving snapshot must be B");
}

#[tokio::test]
#[ignore = "requires Docker"]
async fn delete_snapshot_preserves_aws_service_nodes() {
    let (client, _container) = helpers::start_neo4j().await;
    let account_id = "666677778888";

    let config = helpers::test_config(account_id);
    let snap_id = config.snapshot_id.clone();
    let ingester = GraphIngester::new(client, config);
    let (data, _) = helpers::data_with_policy(account_id);
    ingester.ingest(&data).await.expect("ingest must succeed");

    let graph = ingester.client().inner();

    // Record AwsService node count before delete
    let rows_before = ingester
        .client()
        .fetch_all(neo4rs::query("MATCH (s:AwsService) RETURN count(s) AS cnt"))
        .await
        .unwrap();
    let cnt_before: i64 = rows_before[0].get("cnt").unwrap();

    delete_snapshot(graph, &snap_id)
        .await
        .expect("delete must succeed");

    // AwsService nodes must be untouched
    let rows_after = ingester
        .client()
        .fetch_all(neo4rs::query("MATCH (s:AwsService) RETURN count(s) AS cnt"))
        .await
        .unwrap();
    let cnt_after: i64 = rows_after[0].get("cnt").unwrap();

    assert_eq!(
        cnt_before, cnt_after,
        "AwsService nodes must not be deleted with snapshot"
    );
}
