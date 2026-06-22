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
    let entities = who_can(ingester.client().inner(), &ctx, "s3:GetObject", None)
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
    let entities = who_can(ingester_b.client().inner(), &ctx_a, "s3:GetObject", None)
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
    let paths =
        privilege_escalation_paths(ingester.client().inner(), &ctx, iam_graph::DEFAULT_MAX_HOPS)
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
async fn privilege_escalation_finds_deep_transitive_chain() {
    let client = helpers::shared_client().await;
    let account_id = "333344445556";
    let config = helpers::test_config(account_id);
    let snapshot_id = config.snapshot_id.clone();

    let ingester = GraphIngester::new(client, config);
    let data = helpers::data_with_assume_role_chain(account_id);
    ingester.ingest(&data).await.expect("ingest must succeed");

    let ctx = QueryContext::new(&snapshot_id, account_id);
    let paths = privilege_escalation_paths(ingester.client().inner(), &ctx, 3)
        .await
        .expect("escalation query must succeed");

    let chain_x = paths
        .iter()
        .find(|p| p.name == "ChainX")
        .expect("ChainX must be reported as an escalation path via its assume-role chain");

    assert!(
        chain_x.risky_actions.contains(&"iam:PassRole".to_string()),
        "risky action from the chain terminal (ChainC) must be attributed to ChainX"
    );

    let path_arns: Vec<&str> = chain_x.path.iter().map(|h| h.arn.as_str()).collect();
    assert_eq!(
        path_arns,
        vec![
            format!("arn:aws:iam::{}:role/ChainX", account_id),
            format!("arn:aws:iam::{}:role/ChainA", account_id),
            format!("arn:aws:iam::{}:role/ChainB", account_id),
            format!("arn:aws:iam::{}:role/ChainC", account_id),
        ],
        "full 4-node chain X -> A -> B -> C must be reported in order"
    );
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires Docker"]
async fn privilege_escalation_cyclic_assume_role_terminates_without_duplicates() {
    let client = helpers::shared_client().await;
    let account_id = "333344445557";
    let config = helpers::test_config(account_id);
    let snapshot_id = config.snapshot_id.clone();

    let ingester = GraphIngester::new(client, config);
    let data = helpers::data_with_assume_role_cycle(account_id);
    ingester.ingest(&data).await.expect("ingest must succeed");

    let ctx = QueryContext::new(&snapshot_id, account_id);
    let paths = privilege_escalation_paths(ingester.client().inner(), &ctx, 5)
        .await
        .expect("escalation query must terminate on a cyclic CAN_ASSUME_ROLE graph");

    assert_eq!(
        paths.iter().filter(|p| p.name == "CycleA").count(),
        1,
        "CycleA must be reported exactly once, not duplicated by the A->B->A cycle path"
    );
    assert_eq!(
        paths.iter().filter(|p| p.name == "CycleB").count(),
        1,
        "CycleB must be reported exactly once via the transitive B->A path"
    );

    let cycle_a = paths.iter().find(|p| p.name == "CycleA").unwrap();
    assert_eq!(
        cycle_a.path.len(),
        1,
        "CycleA's own direct risky permission must win over the longer A->B->A path"
    );

    let cycle_b = paths.iter().find(|p| p.name == "CycleB").unwrap();
    assert_eq!(
        cycle_b
            .path
            .iter()
            .map(|h| h.arn.as_str())
            .collect::<Vec<_>>(),
        vec![
            format!("arn:aws:iam::{}:role/CycleB", account_id),
            format!("arn:aws:iam::{}:role/CycleA", account_id),
        ],
        "CycleB escalates by assuming CycleA"
    );
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires Docker"]
async fn privilege_escalation_flags_path_gated_by_runtime_trust_condition() {
    let client = helpers::shared_client().await;
    let account_id = "333344445558";
    let config = helpers::test_config(account_id);
    let snapshot_id = config.snapshot_id.clone();

    let ingester = GraphIngester::new(client, config);
    let data = helpers::data_with_conditional_assume_role(account_id);
    ingester.ingest(&data).await.expect("ingest must succeed");

    let ctx = QueryContext::new(&snapshot_id, account_id);
    let paths = privilege_escalation_paths(ingester.client().inner(), &ctx, 3)
        .await
        .expect("escalation query must succeed");

    let chain_x = paths
        .iter()
        .find(|p| p.name == "CondChainX")
        .expect("CondChainX must be reported via its conditional assume-role chain");

    assert!(
        chain_x.risky_actions.contains(&"iam:PassRole".to_string()),
        "risky action from the chain terminal must be attributed to CondChainX"
    );
    assert!(
        chain_x.conditional,
        "path gated by an unevaluated runtime trust condition must be flagged conditional"
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
    let entities = who_can(ingester.client().inner(), &ctx, "s3:DeleteObject", None)
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

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires Docker"]
async fn who_can_deny_overrides_allow() {
    let client = helpers::shared_client().await;
    let account_id = "900000000001";
    let config = helpers::test_config(account_id);
    let snapshot_id = config.snapshot_id.clone();

    let ingester = GraphIngester::new(client, config);
    let data = helpers::data_with_allow_and_deny(account_id, "s3:DeleteObject");
    ingester.ingest(&data).await.expect("ingest must succeed");

    let ctx = QueryContext::new(&snapshot_id, account_id);
    let entities = who_can(ingester.client().inner(), &ctx, "s3:DeleteObject", None)
        .await
        .expect("who_can must succeed");

    assert!(
        !entities.iter().any(|e| e.name == "DenyTestRole"),
        "DenyTestRole must not appear — explicit Deny overrides Allow"
    );
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires Docker"]
async fn who_can_full_admin_wildcard_matches_any_action() {
    let client = helpers::shared_client().await;
    let account_id = "900000000002";
    let config = helpers::test_config(account_id);
    let snapshot_id = config.snapshot_id.clone();

    let ingester = GraphIngester::new(client, config);
    let data = helpers::data_with_full_admin_role(account_id);
    ingester.ingest(&data).await.expect("ingest must succeed");

    let ctx = QueryContext::new(&snapshot_id, account_id);
    let entities = who_can(ingester.client().inner(), &ctx, "s3:DeleteObject", None)
        .await
        .expect("who_can must succeed");

    let admin_entity = entities.iter().find(|e| e.name == "FullAdminRole");
    assert!(
        admin_entity.is_some(),
        "FullAdminRole with Action:* must appear in who_can for any specific action"
    );
    assert!(
        admin_entity.unwrap().is_full_admin,
        "FullAdminRole must be flagged as full-admin"
    );
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires Docker"]
async fn who_can_resource_scoped_admin_excluded_when_resource_not_covered() {
    let client = helpers::shared_client().await;
    let account_id = "900000000007";
    let config = helpers::test_config(account_id);
    let snapshot_id = config.snapshot_id.clone();

    let ingester = GraphIngester::new(client, config);
    let bucket_resource = "arn:aws:s3:::my-bucket";
    let data = helpers::data_with_resource_scoped_full_admin_role(account_id, bucket_resource);
    ingester.ingest(&data).await.expect("ingest must succeed");

    let ctx = QueryContext::new(&snapshot_id, account_id);
    let entities = who_can(
        ingester.client().inner(),
        &ctx,
        "s3:DeleteObject",
        Some("arn:aws:s3:::my-bucket/object"),
    )
    .await
    .expect("who_can must succeed");

    assert!(
        !entities.iter().any(|e| e.name == "ScopedAdminRole"),
        "ScopedAdminRole's Action:* grant is bucket-scoped, not object-scoped — \
         must be excluded when --resource is an object under the bucket"
    );
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires Docker"]
async fn who_can_resource_scoped_admin_included_when_resource_covered() {
    let client = helpers::shared_client().await;
    let account_id = "900000000008";
    let config = helpers::test_config(account_id);
    let snapshot_id = config.snapshot_id.clone();

    let ingester = GraphIngester::new(client, config);
    let bucket_resource = "arn:aws:s3:::my-bucket";
    let data = helpers::data_with_resource_scoped_full_admin_role(account_id, bucket_resource);
    ingester.ingest(&data).await.expect("ingest must succeed");

    let ctx = QueryContext::new(&snapshot_id, account_id);
    let entities = who_can(
        ingester.client().inner(),
        &ctx,
        "s3:ListBucket",
        Some(bucket_resource),
    )
    .await
    .expect("who_can must succeed");

    let admin_entity = entities.iter().find(|e| e.name == "ScopedAdminRole");
    assert!(
        admin_entity.is_some(),
        "ScopedAdminRole must be included — the queried resource matches the grant's resource scope"
    );
    assert_eq!(
        admin_entity.unwrap().resource,
        bucket_resource,
        "matched resource must be surfaced on the EntityRef"
    );
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires Docker"]
async fn who_can_wildcard_deny_overrides_exact_allow() {
    let client = helpers::shared_client().await;
    let account_id = "900000000005";
    let config = helpers::test_config(account_id);
    let snapshot_id = config.snapshot_id.clone();

    let ingester = GraphIngester::new(client, config);
    let data =
        helpers::data_with_allow_and_wildcard_deny(account_id, "s3:DeleteObject", "s3:Delete*");
    ingester.ingest(&data).await.expect("ingest must succeed");

    let ctx = QueryContext::new(&snapshot_id, account_id);
    let entities = who_can(ingester.client().inner(), &ctx, "s3:DeleteObject", None)
        .await
        .expect("who_can must succeed");

    assert!(
        !entities.iter().any(|e| e.name == "WildcardDenyTestRole"),
        "WildcardDenyTestRole must not appear — Deny s3:Delete* covers Allow s3:DeleteObject"
    );
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires Docker"]
async fn who_can_group_inherited_deny_overrides_own_allow() {
    let client = helpers::shared_client().await;
    let account_id = "900000000006";
    let config = helpers::test_config(account_id);
    let snapshot_id = config.snapshot_id.clone();

    let ingester = GraphIngester::new(client, config);
    let data = helpers::data_with_user_allow_and_group_deny(account_id, "iam:PassRole");
    ingester.ingest(&data).await.expect("ingest must succeed");

    let ctx = QueryContext::new(&snapshot_id, account_id);
    let entities = who_can(ingester.client().inner(), &ctx, "iam:PassRole", None)
        .await
        .expect("who_can must succeed");

    assert!(
        !entities.iter().any(|e| e.name == "GroupDeniedUser"),
        "GroupDeniedUser must not appear — group-inherited Deny overrides the user's own Allow"
    );

    let paths =
        privilege_escalation_paths(ingester.client().inner(), &ctx, iam_graph::DEFAULT_MAX_HOPS)
            .await
            .expect("escalation query must succeed");

    assert!(
        !paths.iter().any(|p| p.name == "GroupDeniedUser"),
        "GroupDeniedUser must not appear in privilege-escalation — group Deny suppresses iam:PassRole"
    );
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires Docker"]
async fn who_can_not_action_includes_non_excluded_excludes_excluded() {
    let client = helpers::shared_client().await;
    let account_id = "900000000004";
    // Excluded action is s3:DeleteObject; any non-S3 action must be granted.
    let excluded_action = "s3:DeleteObject";

    let config = helpers::test_config(account_id);
    let snapshot_id = config.snapshot_id.clone();
    let ingester = GraphIngester::new(client, config);
    let data = helpers::data_with_allow_not_action(account_id, excluded_action);
    ingester.ingest(&data).await.expect("ingest must succeed");

    let ctx = QueryContext::new(&snapshot_id, account_id);

    // Act — non-excluded action: entity must appear, must not be flagged full-admin
    let included = who_can(
        ingester.client().inner(),
        &ctx,
        "ec2:DescribeInstances",
        None,
    )
    .await
    .expect("who_can must succeed");
    let not_action_entity = included
        .iter()
        .find(|e| e.name == "NotActionRole")
        .expect("NotActionRole must appear in who_can for ec2:DescribeInstances (not excluded)");
    assert!(
        !not_action_entity.is_full_admin,
        "NotAction (allow-all-except) entity must NOT be flagged full-admin"
    );

    // Act — excluded action: entity must NOT appear
    let excluded = who_can(ingester.client().inner(), &ctx, excluded_action, None)
        .await
        .expect("who_can must succeed");
    assert!(
        !excluded.iter().any(|e| e.name == "NotActionRole"),
        "NotActionRole must NOT appear in who_can for {} (excluded by NotAction)",
        excluded_action
    );
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires Docker"]
async fn who_can_deny_not_action_denies_all_except_excluded() {
    let client = helpers::shared_client().await;
    let account_id = "900000000009";
    // Deny NotAction excludes s3:GetObject — every other action must be denied
    // despite the full-admin Allow *.
    let excluded_action = "s3:GetObject";

    let config = helpers::test_config(account_id);
    let snapshot_id = config.snapshot_id.clone();
    let ingester = GraphIngester::new(client, config);
    let data = helpers::data_with_full_admin_allow_and_deny_not_action(account_id, excluded_action);
    ingester.ingest(&data).await.expect("ingest must succeed");

    let ctx = QueryContext::new(&snapshot_id, account_id);

    // Act — a non-excluded action must be denied (Deny NotAction covers everything but
    // s3:GetObject), even though the entity also holds Allow *.
    let denied = who_can(ingester.client().inner(), &ctx, "s3:DeleteObject", None)
        .await
        .expect("who_can must succeed");
    assert!(
        !denied.iter().any(|e| e.name == "DenyNotActionRole"),
        "DenyNotActionRole must NOT appear in who_can for s3:DeleteObject — \
         Deny NotAction:[\"s3:GetObject\"] denies every action except s3:GetObject"
    );

    // Act — the excluded action itself must remain allowed.
    let allowed = who_can(ingester.client().inner(), &ctx, excluded_action, None)
        .await
        .expect("who_can must succeed");
    assert!(
        allowed.iter().any(|e| e.name == "DenyNotActionRole"),
        "DenyNotActionRole must appear in who_can for {} — excluded from the deny-all-except Deny",
        excluded_action
    );
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires Docker"]
async fn privilege_escalation_paths_suppresses_action_covered_by_deny_not_action() {
    let client = helpers::shared_client().await;
    let account_id = "900000000010";

    let config = helpers::test_config(account_id);
    let snapshot_id = config.snapshot_id.clone();
    let ingester = GraphIngester::new(client, config);
    // Deny NotAction excludes s3:GetObject, so iam:PassRole (not excluded) must be suppressed.
    let data = helpers::data_with_pass_role_and_deny_not_action(account_id, "s3:GetObject");
    ingester.ingest(&data).await.expect("ingest must succeed");

    let ctx = QueryContext::new(&snapshot_id, account_id);
    let paths =
        privilege_escalation_paths(ingester.client().inner(), &ctx, iam_graph::DEFAULT_MAX_HOPS)
            .await
            .expect("escalation query must succeed");

    assert!(
        !paths
            .iter()
            .any(|p| p.name == "EscalationDenyNotActionRole"),
        "EscalationDenyNotActionRole must NOT appear — Deny NotAction:[\"s3:GetObject\"] \
         denies iam:PassRole (not in the excluded set)"
    );
}
