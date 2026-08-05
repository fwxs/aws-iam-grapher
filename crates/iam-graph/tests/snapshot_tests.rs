mod helpers;

use iam_graph::{
    delete_snapshot, list_account_ids, list_snapshots, snapshot_account_id, GraphError,
    GraphIngester,
};

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires Docker"]
async fn delete_snapshot_removes_only_target_snapshot() {
    let client = helpers::shared_client().await;
    let account_id = "555566667777";

    // Ingest two snapshots
    let config_a = helpers::test_config(account_id);
    let snap_a = config_a.snapshot_id.clone();
    let ingester_a = GraphIngester::new(client, config_a);
    ingester_a
        .ingest(&helpers::empty_data(account_id))
        .await
        .expect("ingest A must succeed");

    let client_b = helpers::shared_client().await;
    let config_b = helpers::test_config(account_id);
    let snap_b = config_b.snapshot_id.clone();
    let ingester_b = GraphIngester::new(client_b, config_b);
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

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires Docker"]
async fn delete_snapshot_preserves_aws_service_nodes() {
    let client = helpers::shared_client().await;
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
        .expect("count query must succeed");
    let cnt_before: i64 = rows_before[0].get("cnt").expect("cnt field must exist");

    delete_snapshot(graph, &snap_id)
        .await
        .expect("delete must succeed");

    // AwsService nodes must be untouched
    let rows_after = ingester
        .client()
        .fetch_all(neo4rs::query("MATCH (s:AwsService) RETURN count(s) AS cnt"))
        .await
        .expect("count query must succeed");
    let cnt_after: i64 = rows_after[0].get("cnt").expect("cnt field must exist");

    assert_eq!(
        cnt_before, cnt_after,
        "AwsService nodes must not be deleted with snapshot"
    );
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires Docker"]
async fn ingest_with_warning_marks_snapshot_partial() {
    let client = helpers::shared_client().await;
    let account_id = "900000000003";
    let config = helpers::test_config(account_id);
    let snapshot_id = config.snapshot_id.clone();

    let ingester = GraphIngester::new(client, config);
    let data = helpers::data_with_missing_profiles_warning(account_id);
    ingester.ingest(&data).await.expect("ingest must succeed");

    let snapshots = list_snapshots(ingester.client().inner(), account_id)
        .await
        .expect("list must succeed");

    let snap = snapshots
        .iter()
        .find(|s| s.id == snapshot_id)
        .expect("snapshot must exist");

    assert!(snap.is_partial, "snapshot must be marked partial");
    assert!(
        snap.partial_reasons
            .contains(&"instance profiles missing".to_string()),
        "partial_reasons must include the missing profiles reason"
    );
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires Docker"]
async fn ingest_with_wildcards_not_expanded_warning_marks_snapshot_partial() {
    let client = helpers::shared_client().await;
    let account_id = "900000000005";
    let config = helpers::test_config(account_id);
    let snapshot_id = config.snapshot_id.clone();

    let ingester = GraphIngester::new(client, config);
    let data = helpers::data_with_wildcards_not_expanded_warning(account_id);
    ingester.ingest(&data).await.expect("ingest must succeed");

    let snapshots = list_snapshots(ingester.client().inner(), account_id)
        .await
        .expect("list must succeed");

    let snap = snapshots
        .iter()
        .find(|s| s.id == snapshot_id)
        .expect("snapshot must exist");

    assert!(
        snap.is_partial,
        "snapshot must be marked partial when wildcards were not expanded"
    );
    assert!(
        snap.partial_reasons
            .contains(&"some wildcards not expanded".to_string()),
        "partial_reasons must include the wildcards reason"
    );
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires Docker"]
async fn list_account_ids_returns_every_distinct_account_with_a_snapshot() {
    let client = helpers::shared_client().await;
    let account_a = "910000000001";
    let account_b = "910000000002";

    let ingester_a = GraphIngester::new(client, helpers::test_config(account_a));
    ingester_a
        .ingest(&helpers::empty_data(account_a))
        .await
        .expect("ingest A must succeed");

    let client_b = helpers::shared_client().await;
    let ingester_b = GraphIngester::new(client_b, helpers::test_config(account_b));
    ingester_b
        .ingest(&helpers::empty_data(account_b))
        .await
        .expect("ingest B must succeed");

    let accounts = list_account_ids(ingester_b.client().inner())
        .await
        .expect("list_account_ids must succeed");

    assert!(
        accounts.contains(&account_a.to_string()),
        "account A must be present"
    );
    assert!(
        accounts.contains(&account_b.to_string()),
        "account B must be present"
    );
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires Docker"]
async fn snapshot_account_id_resolves_owning_account() {
    let client = helpers::shared_client().await;
    let account_id = "910000000003";
    let config = helpers::test_config(account_id);
    let snapshot_id = config.snapshot_id.clone();

    let ingester = GraphIngester::new(client, config);
    ingester
        .ingest(&helpers::empty_data(account_id))
        .await
        .expect("ingest must succeed");

    let resolved = snapshot_account_id(ingester.client().inner(), &snapshot_id)
        .await
        .expect("snapshot_account_id must succeed");

    assert_eq!(resolved, Some(account_id.to_string()));
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires Docker"]
async fn snapshot_account_id_returns_none_for_unknown_snapshot() {
    let client = helpers::shared_client().await;

    let resolved = snapshot_account_id(client.inner(), "not-a-real-snapshot-id")
        .await
        .expect("snapshot_account_id must succeed");

    assert_eq!(resolved, None);
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires Docker"]
async fn list_snapshots_reports_column_name_on_malformed_row() {
    let client = helpers::shared_client().await;
    let account_id = "910000000004";
    let config = helpers::test_config(account_id);
    let snapshot_id = config.snapshot_id.clone();

    let ingester = GraphIngester::new(client, config);
    ingester
        .ingest(&helpers::empty_data(account_id))
        .await
        .expect("ingest must succeed");

    let graph = ingester.client().inner();

    // Corrupt the type of `is_partial` on the Snapshot node — the row-extraction helper
    // (`col` in queries/mod.rs) must surface the column name in the resulting error.
    graph
        .run(
            neo4rs::query("MATCH (s:Snapshot {id: $id}) SET s.is_partial = 'not-a-bool'")
                .param("id", snapshot_id.as_str()),
        )
        .await
        .expect("corrupting query must succeed");

    let err = list_snapshots(graph, account_id)
        .await
        .expect_err("malformed is_partial column must fail");

    // Restore the node before asserting: this container is shared by every test in this
    // binary (see helpers::shared_client), so a left-behind malformed property would break
    // any later test that lists snapshots across accounts. Do this before the assertions
    // below so cleanup still runs if they panic.
    graph
        .run(
            neo4rs::query("MATCH (s:Snapshot {id: $id}) SET s.is_partial = false")
                .param("id", snapshot_id.as_str()),
        )
        .await
        .expect("restoring query must succeed");

    match err {
        GraphError::UnexpectedResult(message) => {
            assert!(
                message.contains("is_partial"),
                "error must name the malformed column, got: {message}"
            );
        }
        other => panic!("expected UnexpectedResult, got: {other:?}"),
    }
}
