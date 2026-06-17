mod helpers;

use iam_graph::{GraphIngester, IngestConfig};
use iam_models::{Effect, IamRole, PolicyDocument, PolicyStatement};
use uuid::Uuid;

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires Docker"]
async fn ingest_creates_account_and_snapshot_nodes() {
    let client = helpers::shared_client().await;
    let config = helpers::test_config("111122223333");
    let snapshot_id = config.snapshot_id.clone();
    let account_id = config.account_id.clone();

    let ingester = GraphIngester::new(client, config);
    ingester
        .ingest(&helpers::empty_data("111122223333"))
        .await
        .expect("ingest must succeed");

    let rows = ingester
        .client()
        .fetch_all(
            neo4rs::query("MATCH (a:AwsAccount {id: $id}) RETURN a.id AS id")
                .param("id", account_id.as_str()),
        )
        .await
        .expect("account query must succeed");
    assert!(!rows.is_empty(), "AwsAccount must exist");
    let id: String = rows[0].get("id").expect("id field must exist");
    assert_eq!(id, account_id);

    let rows = ingester
        .client()
        .fetch_all(
            neo4rs::query("MATCH (s:Snapshot {id: $id}) RETURN s.id AS id")
                .param("id", snapshot_id.as_str()),
        )
        .await
        .expect("snapshot query must succeed");
    assert!(!rows.is_empty(), "Snapshot must exist");
    let snap: String = rows[0].get("id").expect("id field must exist");
    assert_eq!(snap, snapshot_id);
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires Docker"]
async fn ingest_creates_policy_nodes_with_correct_uid() {
    let client = helpers::shared_client().await;
    let config = helpers::test_config("111122223333");
    let snapshot_id = config.snapshot_id.clone();

    let ingester = GraphIngester::new(client, config);
    let (data, policy_arn) = helpers::data_with_policy("111122223333");
    ingester.ingest(&data).await.expect("ingest must succeed");

    let expected_uid = format!("{}|{}", snapshot_id, policy_arn);
    let rows = ingester
        .client()
        .fetch_all(
            neo4rs::query(
                "MATCH (p:Policy {uid: $uid}) RETURN p.uid AS uid, p.is_aws_managed AS aws",
            )
            .param("uid", expected_uid.as_str()),
        )
        .await
        .expect("policy query must succeed");
    assert!(!rows.is_empty(), "Policy must exist");
    let uid: String = rows[0].get("uid").expect("uid field must exist");
    let is_aws: bool = rows[0].get("aws").expect("aws field must exist");
    assert_eq!(uid, expected_uid);
    assert!(!is_aws);
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires Docker"]
async fn ingest_creates_permission_nodes_without_wildcards() {
    let client = helpers::shared_client().await;
    let config = helpers::test_config("111122223333");
    let snapshot_id = config.snapshot_id.clone();

    let ingester = GraphIngester::new(client, config);
    let (data, _) = helpers::data_with_policy("111122223333");
    ingester.ingest(&data).await.expect("ingest must succeed");

    let rows = ingester
        .client()
        .fetch_all(
            neo4rs::query(
                "MATCH (perm:Permission {snapshot_id: $snap})
                 WHERE perm.action CONTAINS '*'
                 RETURN count(perm) AS cnt",
            )
            .param("snap", snapshot_id.as_str()),
        )
        .await
        .expect("wildcard query must succeed");
    let cnt: i64 = rows[0].get("cnt").expect("cnt field must exist");
    assert_eq!(cnt, 0, "No permission node should have wildcard in action");
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires Docker"]
async fn ingest_creates_role_to_policy_relationship() {
    let client = helpers::shared_client().await;
    let config = helpers::test_config("111122223333");
    let snapshot_id = config.snapshot_id.clone();

    let ingester = GraphIngester::new(client, config);
    let data = helpers::data_with_role_and_policy("111122223333");
    ingester.ingest(&data).await.expect("ingest must succeed");

    let rows = ingester
        .client()
        .fetch_all(
            neo4rs::query(
                "MATCH (r:Role {snapshot_id: $snap})-[:HAS_ATTACHED_POLICY]->(p:Policy)
                 RETURN count(r) AS cnt",
            )
            .param("snap", snapshot_id.as_str()),
        )
        .await
        .expect("relationship query must succeed");
    let cnt: i64 = rows[0].get("cnt").expect("cnt field must exist");
    assert!(cnt > 0, "HAS_ATTACHED_POLICY relationship must exist");
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires Docker"]
async fn ingest_creates_instance_profile_to_role_relationship() {
    let client = helpers::shared_client().await;
    let config = helpers::test_config("111122223333");
    let snapshot_id = config.snapshot_id.clone();

    let ingester = GraphIngester::new(client, config);
    let data = helpers::data_with_instance_profile("111122223333");
    ingester.ingest(&data).await.expect("ingest must succeed");

    let rows = ingester
        .client()
        .fetch_all(
            neo4rs::query(
                "MATCH (ip:InstanceProfile {snapshot_id: $snap})-[:CONTAINS_ROLE]->(r:Role)
                 RETURN count(ip) AS cnt",
            )
            .param("snap", snapshot_id.as_str()),
        )
        .await
        .expect("relationship query must succeed");
    let cnt: i64 = rows[0].get("cnt").expect("cnt field must exist");
    assert!(cnt > 0, "CONTAINS_ROLE relationship must exist");
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires Docker"]
async fn ingest_handles_empty_collected_data() {
    let client = helpers::shared_client().await;
    let config = helpers::test_config("111122223333");
    let ingester = GraphIngester::new(client, config);
    ingester
        .ingest(&helpers::empty_data("111122223333"))
        .await
        .expect("empty ingest must not fail");
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires Docker"]
async fn ingest_respects_batch_size() {
    use chrono::Utc;
    use iam_models::IamPolicy;
    use std::collections::HashMap;

    let client = helpers::shared_client().await;
    let config = IngestConfig {
        batch_size: 500,
        snapshot_id: Uuid::new_v4().to_string(),
        account_id: "111122223333".to_string(),
        account_alias: None,
        dry_run: false,
    };
    let snapshot_id = config.snapshot_id.clone();

    let policies: Vec<_> = (0..1500)
        .map(|i| IamPolicy {
            arn: format!("arn:aws:iam::111122223333:policy/Pol{}", i),
            policy_id: format!("ANPA{:016}", i),
            policy_name: format!("Pol{}", i),
            path: "/".to_string(),
            create_date: Utc::now(),
            update_date: Utc::now(),
            attachment_count: 0,
            is_attachable: true,
            default_version_id: "v1".to_string(),
            description: None,
            is_aws_managed: false,
            document: None,
            tags: HashMap::new(),
        })
        .collect();

    let data = iam_collector::CollectedData {
        source: iam_collector::CollectorMode::Offline,
        account_id: Some("111122223333".to_string()),
        collection_timestamp: Utc::now(),
        policies,
        ..Default::default()
    };

    let ingester = GraphIngester::new(client, config);
    ingester
        .ingest(&data)
        .await
        .expect("1500-policy ingest must succeed");

    let rows = ingester
        .client()
        .fetch_all(
            neo4rs::query("MATCH (p:Policy {snapshot_id: $snap}) RETURN count(p) AS cnt")
                .param("snap", snapshot_id.as_str()),
        )
        .await
        .expect("count query must succeed");
    let cnt: i64 = rows[0].get("cnt").expect("cnt field must exist");
    assert_eq!(cnt, 1500, "All 1500 policies must be present");
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires Docker"]
async fn ingest_trust_policy_with_condition_marks_can_assume_conditional() {
    use chrono::Utc;
    use iam_collector::{CollectedData, CollectorMode};
    use std::collections::HashMap;

    let client = helpers::shared_client().await;
    let config = helpers::test_config("444455556666");
    let snap_id = config.snapshot_id.clone();

    let role_arn = "arn:aws:iam::444455556666:role/CondRole";
    let assume_doc = PolicyDocument {
        version: Some("2012-10-17".to_string()),
        statement: vec![PolicyStatement {
            sid: None,
            effect: Effect::Allow,
            action: vec!["sts:AssumeRole".to_string()],
            not_action: vec![],
            resource: vec![],
            not_resource: vec![],
            principal: Some(serde_json::json!({"AWS": "arn:aws:iam::444455556666:root"})),
            not_principal: None,
            condition: Some(std::collections::HashMap::from([(
                "StringEquals".to_string(),
                std::collections::HashMap::from([(
                    "sts:ExternalId".to_string(),
                    vec!["secret".to_string()],
                )]),
            )])),
        }],
    };
    let role = IamRole {
        arn: role_arn.to_string(),
        role_id: "AROATEST_COND".to_string(),
        role_name: "CondRole".to_string(),
        path: "/".to_string(),
        create_date: Utc::now(),
        assume_role_policy_document: Some(assume_doc),
        attached_managed_policies: vec![],
        inline_policies: vec![],
        permissions_boundary: None,
        role_last_used: None,
        description: None,
        max_session_duration: None,
        is_aws_managed: false,
        tags: HashMap::new(),
    };

    let data = CollectedData {
        source: CollectorMode::Offline,
        account_id: Some("444455556666".to_string()),
        collection_timestamp: Utc::now(),
        roles: vec![role],
        ..Default::default()
    };

    let ingester = GraphIngester::new(client, config);
    ingester.ingest(&data).await.expect("ingest must succeed");

    let rows = ingester
        .client()
        .fetch_all(
            neo4rs::query(
                "MATCH (pr:Principal)-[ca:CAN_ASSUME]->(r:Role {uid: $uid})
                 RETURN ca.conditional AS conditional",
            )
            .param("uid", format!("{}|{}", snap_id, role_arn).as_str()),
        )
        .await
        .expect("CAN_ASSUME query must succeed");

    assert!(!rows.is_empty(), "CAN_ASSUME relationship must exist");
    let conditional: bool = rows[0]
        .get("conditional")
        .expect("conditional property must be present");
    assert!(
        conditional,
        "CAN_ASSUME edge must be marked conditional when trust policy has Condition block"
    );
}
