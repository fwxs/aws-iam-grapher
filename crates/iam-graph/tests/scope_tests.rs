mod helpers;

use iam_graph::{
    resolve_org_context, resolve_scopes, who_can, GraphError, GraphIngester, QueryContext,
    ScopeSelector,
};
use iam_models::condition::ConditionContext;

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

    let scopes = resolve_scopes(
        ingester_newer.client().inner(),
        ScopeSelector::account(account_id),
    )
    .await
    .expect("resolve_scopes must succeed");

    assert_eq!(scopes.len(), 1);
    assert_eq!(scopes[0].context.snapshot_id, snap_newer);
    assert_ne!(scopes[0].context.snapshot_id, snap_older);
    assert_eq!(scopes[0].snapshot.id, snap_newer);
    assert_eq!(scopes[0].snapshot.account_id, account_id);
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

    let scopes = resolve_scopes(ingester_b.client().inner(), ScopeSelector::all_accounts())
        .await
        .expect("resolve_scopes must succeed");

    let scope_a = scopes
        .iter()
        .find(|s| s.context.account_id == account_a)
        .expect("account A must be present");
    assert_eq!(scope_a.context.snapshot_id, snap_a);
    assert_eq!(scope_a.snapshot.id, snap_a);

    let scope_b = scopes
        .iter()
        .find(|s| s.context.account_id == account_b)
        .expect("account B must be present");
    assert_eq!(scope_b.context.snapshot_id, snap_b);
    assert_eq!(scope_b.snapshot.id, snap_b);
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

    let scopes = resolve_scopes(
        ingester.client().inner(),
        ScopeSelector::snapshot(snapshot_id.clone(), Some(account_id.to_string())),
    )
    .await
    .expect("resolve_scopes must succeed");

    assert_eq!(scopes.len(), 1);
    assert_eq!(scopes[0].context.snapshot_id, snapshot_id);
    assert_eq!(scopes[0].context.account_id, account_id);
    assert_eq!(scopes[0].snapshot.id, snapshot_id);
    assert_eq!(scopes[0].snapshot.account_id, account_id);
    assert!(!scopes[0].snapshot.is_partial);
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires Docker"]
async fn snapshot_selector_returns_partial_metadata_in_the_same_call() {
    let client = helpers::shared_client().await;
    let account_id = "920000000007";
    let config = helpers::test_config(account_id);
    let snapshot_id = config.snapshot_id.clone();
    let ingester = GraphIngester::new(client, config);
    ingester
        .ingest(&helpers::data_with_missing_profiles_warning(account_id))
        .await
        .expect("ingest must succeed");

    // Regression guard for issue #78: resolving an explicit --snapshot-id must return
    // is_partial/partial_reasons directly from the single resolution query, so the CLI
    // never needs a second list_snapshots round trip to render the partial warning.
    let scopes = resolve_scopes(
        ingester.client().inner(),
        ScopeSelector::snapshot(snapshot_id.clone(), None),
    )
    .await
    .expect("resolve_scopes must succeed");

    assert_eq!(scopes.len(), 1);
    assert!(scopes[0].snapshot.is_partial);
    assert_eq!(
        scopes[0].snapshot.partial_reasons,
        vec!["instance profiles missing".to_string()]
    );
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

    let result = resolve_scopes(
        ingester.client().inner(),
        ScopeSelector::snapshot(snapshot_id.clone(), Some("999999999999".to_string())),
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

    let result = resolve_scopes(
        client.inner(),
        ScopeSelector::snapshot("not-a-real-snapshot-id", None),
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

    let result = resolve_scopes(client.inner(), ScopeSelector::account("no-such-account")).await;

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

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires Docker"]
async fn candidate_deny_actions_does_not_leak_across_accounts() {
    // Permission is now a global, action-keyed node with no account_id — Deny scoping lives
    // entirely on the GRANTS edge. This proves candidate_deny_actions (exercised inside
    // who_can) still isolates per account: account A's Deny on an action must not suppress
    // an unrelated account B's Allow for the very same action.
    let client = helpers::shared_client().await;
    let account_a = "920000000007";
    let account_b = "920000000008";
    let action = "s3:DeleteObject";

    let config_a = helpers::test_config(account_a);
    let ingester_a = GraphIngester::new(client, config_a);
    ingester_a
        .ingest(&helpers::data_with_allow_and_deny(account_a, action))
        .await
        .expect("ingest A must succeed");

    let client_b = helpers::shared_client().await;
    let config_b = helpers::test_config(account_b);
    let snapshot_b = config_b.snapshot_id.clone();
    let ingester_b = GraphIngester::new(client_b, config_b);
    ingester_b
        .ingest(&helpers::data_with_role_action(account_b, action, true))
        .await
        .expect("ingest B must succeed");

    let ctx_b = QueryContext::new(&snapshot_b, account_b);
    let entities = who_can(
        ingester_b.client().inner(),
        &ctx_b,
        action,
        None,
        &ConditionContext::default(),
    )
    .await
    .expect("who_can must succeed");

    assert!(
        entities.iter().any(|e| e.name == "ActionRole"),
        "account B's Allow must not be suppressed by account A's unrelated Deny — \
         candidate_deny_actions must not leak across accounts now that Permission carries no \
         account_id"
    );
}
