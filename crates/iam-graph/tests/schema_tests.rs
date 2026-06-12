mod helpers;

/// Verify that all expected constraints exist after initialize_schema().
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires Docker"]
async fn constraints_are_created_on_initialize_schema() {
    let client = helpers::shared_client().await;

    let rows = client
        .fetch_all(neo4rs::query("SHOW CONSTRAINTS"))
        .await
        .expect("SHOW CONSTRAINTS must execute");

    let names: Vec<String> = rows
        .iter()
        .filter_map(|r| r.get::<String>("name").ok())
        .collect();

    assert!(
        names.iter().any(|n| n.contains("snapshot")),
        "snapshot constraint missing. found: {:?}",
        names
    );
    assert!(
        names.iter().any(|n| n.contains("account")),
        "account constraint missing"
    );
    assert!(
        names.iter().any(|n| n.contains("policy")),
        "policy constraint missing"
    );
    assert!(
        names.iter().any(|n| n.contains("role")),
        "role constraint missing"
    );
    assert!(
        names.iter().any(|n| n.contains("user")),
        "user constraint missing"
    );
    assert!(
        names.iter().any(|n| n.contains("permission")),
        "permission constraint missing"
    );
}

/// Calling initialize_schema() twice must not fail.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires Docker"]
async fn schema_initialization_is_idempotent() {
    let client = helpers::shared_client().await;
    // shared_client() already called initialize_schema(); call again — must not error.
    client
        .initialize_schema()
        .await
        .expect("second initialize_schema must succeed");
}
