mod helpers;

use iam_graph::{privilege_escalation_paths, who_can, GraphIngester, QueryContext};

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires Docker"]
async fn who_can_returns_correct_entities() {
    let client = helpers::shared_client().await;
    let config = helpers::test_config("222233334444");
    let snapshot_id = config.snapshot_id.clone();
    let account_id = config.account_id.clone();

    let ingester = GraphIngester::new(client, config);
    let data = helpers::data_with_role_action("222233334444", "s3:GetObject", true);
    ingester.ingest(&data).await.expect("ingest must succeed");

    let ctx = QueryContext::new(&snapshot_id, &account_id);
    let entities = who_can(ingester.client().inner(), &ctx, "s3:GetObject")
        .await
        .expect("who_can must succeed");

    assert!(
        !entities.is_empty(),
        "At least one entity must have s3:GetObject"
    );
    assert!(
        entities.iter().any(|e| e.name == "ActionRole"),
        "ActionRole must appear in results"
    );
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires Docker"]
async fn who_can_does_not_leak_across_accounts() {
    let client = helpers::shared_client().await;

    // Ingest account A
    let config_a = helpers::test_config("ACCOUNT_A");
    let snap_a = config_a.snapshot_id.clone();
    let ingester_a = GraphIngester::new(client, config_a);
    let data_a = helpers::data_with_role_action("ACCOUNT_A", "s3:GetObject", true);
    ingester_a
        .ingest(&data_a)
        .await
        .expect("ingest A must succeed");

    // Second client to same shared container for account B
    let client_b = helpers::shared_client().await;
    let config_b = helpers::test_config("ACCOUNT_B");
    let ingester_b = GraphIngester::new(client_b, config_b);
    let data_b = helpers::data_with_role_action("ACCOUNT_B", "s3:GetObject", true);
    ingester_b
        .ingest(&data_b)
        .await
        .expect("ingest B must succeed");

    // Query account A — must not see account B's entities
    let ctx_a = QueryContext::new(&snap_a, "ACCOUNT_A");
    let entities = who_can(ingester_b.client().inner(), &ctx_a, "s3:GetObject")
        .await
        .expect("who_can must succeed");
    for entity in &entities {
        assert!(
            !entity.arn.contains("ACCOUNT_B"),
            "Account B entity leaked into A query"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires Docker"]
async fn privilege_escalation_finds_iam_passrole() {
    let client = helpers::shared_client().await;
    let config = helpers::test_config("333344445555");
    let snapshot_id = config.snapshot_id.clone();
    let account_id = config.account_id.clone();

    let ingester = GraphIngester::new(client, config);
    let data = helpers::data_with_role_action("333344445555", "iam:PassRole", true);
    ingester.ingest(&data).await.expect("ingest must succeed");

    let ctx = QueryContext::new(&snapshot_id, &account_id);
    let paths = privilege_escalation_paths(ingester.client().inner(), &ctx)
        .await
        .expect("escalation query must succeed");

    assert!(
        !paths.is_empty(),
        "iam:PassRole must appear as escalation path"
    );
    assert!(
        paths
            .iter()
            .any(|p| p.risky_actions.contains(&"iam:PassRole".to_string())),
        "iam:PassRole must be in risky_actions"
    );
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires Docker"]
async fn diff_permissions_detects_new_permissions() {
    use iam_graph::diff_permissions;

    let client = helpers::shared_client().await;
    let account_id = "444455556666";

    // Snapshot A — no s3:DeleteObject
    let config_a = helpers::test_config(account_id);
    let snap_a = config_a.snapshot_id.clone();
    let ingester_a = GraphIngester::new(client, config_a);
    let data_a = helpers::data_with_role_action(account_id, "s3:GetObject", true);
    ingester_a
        .ingest(&data_a)
        .await
        .expect("ingest A must succeed");

    // Snapshot B — adds s3:DeleteObject
    let client_b = helpers::shared_client().await;
    let config_b = helpers::test_config(account_id);
    let snap_b = config_b.snapshot_id.clone();
    let ingester_b = GraphIngester::new(client_b, config_b);
    let data_b = helpers::data_with_role_action(account_id, "s3:DeleteObject", true);
    ingester_b
        .ingest(&data_b)
        .await
        .expect("ingest B must succeed");

    let diff = diff_permissions(ingester_b.client().inner(), account_id, &snap_a, &snap_b)
        .await
        .expect("diff must succeed");

    assert!(
        diff.added.iter().any(|p| p.action == "s3:DeleteObject"),
        "s3:DeleteObject must appear as added permission"
    );
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires Docker"]
async fn who_can_sees_group_and_inline_user_paths() {
    let client = helpers::shared_client().await;
    let account_id = "555566667777";
    let config = helpers::test_config(account_id);
    let snapshot_id = config.snapshot_id.clone();

    let ingester = GraphIngester::new(client, config);
    let data = helpers::data_with_user_group_and_inline(account_id);
    ingester.ingest(&data).await.expect("ingest must succeed");

    let ctx = QueryContext::new(&snapshot_id, account_id);
    let entities = who_can(ingester.client().inner(), &ctx, "s3:DeleteObject")
        .await
        .expect("who_can must succeed");

    assert!(
        entities.iter().any(|e| e.name == "dave"),
        "inline-on-user grant is missing (GRANTS edge not written for user inline policies)"
    );
    assert!(
        entities.iter().any(|e| e.name == "carol"),
        "group-derived grant is missing (MEMBER_OF not ingested or not traversed)"
    );
    assert!(
        entities.iter().any(|e| e.name == "Auditors"),
        "group itself is missing from who_can results"
    );
}
