mod helpers;

use iam_graph::{resolve_contexts, resolve_org_context, GraphError, GraphIngester, ScopeSelector};

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires Docker"]
async fn account_selector_picks_newest_snapshot() {
    let client = helpers::shared_client().await;
    let account_id = "920000000001";

    let mut data_older = helpers::empty_data(account_id);
    data_older.collection_timestamp = chrono::Utc::now() - chrono::Duration::hours(1);
    let config_older = helpers::test_config(account_id);
    let snap_older = config_older.snapshot_id.clone();
    let ingester_older = GraphIngester::new(client, config_older);
    ingester_older
        .ingest(&data_older)
        .await
        .expect("ingest older must succeed");

    let client_newer = helpers::shared_client().await;
    let data_newer = helpers::empty_data(account_id);
    let config_newer = helpers::test_config(account_id);
    let snap_newer = config_newer.snapshot_id.clone();
    let ingester_newer = GraphIngester::new(client_newer, config_newer);
    ingester_newer
        .ingest(&data_newer)
        .await
        .expect("ingest newer must succeed");

    let contexts = resolve_contexts(
        ingester_newer.client().inner(),
        ScopeSelector::Account {
            account_id: account_id.to_string(),
        },
    )
    .await
    .expect("resolve_contexts must succeed");

    assert_eq!(contexts.len(), 1);
    assert_eq!(contexts[0].snapshot_id, snap_newer);
    assert_ne!(contexts[0].snapshot_id, snap_older);
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires Docker"]
async fn all_accounts_selector_returns_one_context_per_account_pinned_to_latest() {
    let client = helpers::shared_client().await;
    let account_a = "920000000002";
    let account_b = "920000000003";

    let config_a = helpers::test_config(account_a);
    let snap_a = config_a.snapshot_id.clone();
    let ingester_a = GraphIngester::new(client, config_a);
    ingester_a
        .ingest(&helpers::empty_data(account_a))
        .await
        .expect("ingest A must succeed");

    let client_b = helpers::shared_client().await;
    let config_b = helpers::test_config(account_b);
    let snap_b = config_b.snapshot_id.clone();
    let ingester_b = GraphIngester::new(client_b, config_b);
    ingester_b
        .ingest(&helpers::empty_data(account_b))
        .await
        .expect("ingest B must succeed");

    let contexts = resolve_contexts(ingester_b.client().inner(), ScopeSelector::AllAccounts)
        .await
        .expect("resolve_contexts must succeed");

    let ctx_a = contexts
        .iter()
        .find(|c| c.account_id == account_a)
        .expect("account A must be present");
    assert_eq!(ctx_a.snapshot_id, snap_a);

    let ctx_b = contexts
        .iter()
        .find(|c| c.account_id == account_b)
        .expect("account B must be present");
    assert_eq!(ctx_b.snapshot_id, snap_b);
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires Docker"]
async fn snapshot_selector_derives_account_and_accepts_matching_expected_account() {
    let client = helpers::shared_client().await;
    let account_id = "920000000004";
    let config = helpers::test_config(account_id);
    let snapshot_id = config.snapshot_id.clone();
    let ingester = GraphIngester::new(client, config);
    ingester
        .ingest(&helpers::empty_data(account_id))
        .await
        .expect("ingest must succeed");

    let contexts = resolve_contexts(
        ingester.client().inner(),
        ScopeSelector::Snapshot {
            snapshot_id: snapshot_id.clone(),
            expected_account: Some(account_id.to_string()),
        },
    )
    .await
    .expect("resolve_contexts must succeed");

    assert_eq!(contexts.len(), 1);
    assert_eq!(contexts[0].snapshot_id, snapshot_id);
    assert_eq!(contexts[0].account_id, account_id);
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires Docker"]
async fn snapshot_selector_errors_on_account_mismatch() {
    let client = helpers::shared_client().await;
    let account_id = "920000000005";
    let config = helpers::test_config(account_id);
    let snapshot_id = config.snapshot_id.clone();
    let ingester = GraphIngester::new(client, config);
    ingester
        .ingest(&helpers::empty_data(account_id))
        .await
        .expect("ingest must succeed");

    let result = resolve_contexts(
        ingester.client().inner(),
        ScopeSelector::Snapshot {
            snapshot_id: snapshot_id.clone(),
            expected_account: Some("999999999999".to_string()),
        },
    )
    .await;

    match result {
        Err(GraphError::AccountMismatch {
            snapshot_id: sid,
            expected,
            actual,
        }) => {
            assert_eq!(sid, snapshot_id);
            assert_eq!(expected, "999999999999");
            assert_eq!(actual, account_id);
        }
        other => panic!("expected AccountMismatch, got {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires Docker"]
async fn snapshot_selector_errors_on_unknown_snapshot() {
    let client = helpers::shared_client().await;

    let result = resolve_contexts(
        client.inner(),
        ScopeSelector::Snapshot {
            snapshot_id: "not-a-real-snapshot-id".to_string(),
            expected_account: None,
        },
    )
    .await;

    match result {
        Err(GraphError::SnapshotNotFound(id)) => assert_eq!(id, "not-a-real-snapshot-id"),
        other => panic!("expected SnapshotNotFound, got {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires Docker"]
async fn account_selector_errors_when_account_has_no_snapshots() {
    let client = helpers::shared_client().await;

    let result = resolve_contexts(
        client.inner(),
        ScopeSelector::Account {
            account_id: "no-such-account".to_string(),
        },
    )
    .await;

    match result {
        Err(GraphError::NoSnapshotsForAccount(id)) => assert_eq!(id, "no-such-account"),
        other => panic!("expected NoSnapshotsForAccount, got {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires Docker"]
async fn resolve_org_context_uses_explicit_run_id() {
    let client = helpers::shared_client().await;

    let ctx = resolve_org_context(client.inner(), Some("explicit-org-run".to_string()))
        .await
        .expect("resolve_org_context must succeed");

    assert_eq!(ctx.org_run_id, "explicit-org-run");
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires Docker"]
async fn resolve_org_context_falls_back_to_latest_org_run() {
    let client = helpers::shared_client().await;
    let account_id = "920000000006";
    let org_run_id = "org-run-920000000006";

    let config = iam_graph::IngestConfig {
        org_collection_run_id: Some(org_run_id.to_string()),
        ..helpers::test_config(account_id)
    };
    let ingester = GraphIngester::new(client, config);
    ingester
        .ingest(&helpers::empty_data(account_id))
        .await
        .expect("ingest must succeed");

    let ctx = resolve_org_context(ingester.client().inner(), None)
        .await
        .expect("resolve_org_context must succeed");

    assert_eq!(ctx.org_run_id, org_run_id);
}
