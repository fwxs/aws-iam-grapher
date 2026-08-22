mod helpers;

use chrono::Utc;
use iam_collector::{CollectedData, CollectorMode};
use iam_graph::{
    org_escalation_paths, stitch_cross_account, GraphIngester, IngestConfig, OrgQueryContext,
};
use iam_models::{Effect, IamInlinePolicy, IamRole, PolicyDocument, PolicyStatement};
use std::collections::HashMap;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Local fixture helpers
// ---------------------------------------------------------------------------

fn inline_policy(name: &str, action: &str, resource: &str, effect: Effect) -> IamInlinePolicy {
    IamInlinePolicy {
        policy_name: name.to_string(),
        policy_document: PolicyDocument {
            version: Some("2012-10-17".to_string()),
            statement: vec![PolicyStatement {
                sid: None,
                effect,
                action: vec![action.to_string()],
                not_action: vec![],
                resource: vec![resource.to_string()],
                not_resource: vec![],
                principal: None,
                not_principal: None,
                condition: None,
            }],
        },
    }
}

fn role_with_trust_and_policies(
    account_id: &str,
    role_name: &str,
    assumer_arn: &str,
    inline_policies: Vec<IamInlinePolicy>,
    conditional: bool,
) -> IamRole {
    use iam_models::{ConditionValues, PolicyDocument as Pd, PolicyStatement as Ps};

    let condition = if conditional {
        Some(HashMap::from([(
            "StringEquals".to_string(),
            HashMap::from([(
                "sts:ExternalId".to_string(),
                ConditionValues(vec!["secret".to_string()]),
            )]),
        )]))
    } else {
        None
    };

    let assume_doc = Pd {
        version: Some("2012-10-17".to_string()),
        statement: vec![Ps {
            sid: None,
            effect: Effect::Allow,
            action: vec!["sts:AssumeRole".to_string()],
            not_action: vec![],
            resource: vec![],
            not_resource: vec![],
            principal: Some(serde_json::json!({"AWS": assumer_arn})),
            not_principal: None,
            condition,
        }],
    };

    IamRole {
        arn: format!("arn:aws:iam::{}:role/{}", account_id, role_name),
        role_id: format!("AROA{}{}", account_id, role_name.to_uppercase()),
        role_name: role_name.to_string(),
        path: "/".to_string(),
        create_date: Utc::now(),
        assume_role_policy_document: Some(assume_doc),
        attached_managed_policies: vec![],
        inline_policies,
        permissions_boundary: None,
        role_last_used: None,
        description: None,
        max_session_duration: None,
        is_aws_managed: false,
        tags: HashMap::new(),
    }
}

fn data_for_account(account_id: &str, roles: Vec<IamRole>) -> CollectedData {
    CollectedData {
        source: CollectorMode::Offline,
        account_id: Some(account_id.to_string()),
        collection_timestamp: Utc::now(),
        roles,
        ..Default::default()
    }
}

async fn ingest_account(
    client: iam_graph::GraphClient,
    data: &CollectedData,
    account_id: &str,
    org_run_id: &str,
) -> (iam_graph::GraphClient, String) {
    let snapshot_id = Uuid::new_v4().to_string();
    let config = IngestConfig {
        snapshot_id: snapshot_id.clone(),
        account_id: account_id.to_string(),
        account_alias: None,
        batch_size: 500,
        dry_run: false,
        org_collection_run_id: Some(org_run_id.to_string()),
    };
    let ingester = GraphIngester::new(client, config);
    ingester.ingest(data).await.expect("ingestion must succeed");
    let client = ingester.into_client();
    (client, snapshot_id)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// A-role (account-A) can assume B-role (account-B). B-role trusts A's account root.
/// A-role holds sts:AssumeRole on B-role's ARN. B-role holds iam:PassRole (risky action).
/// After stitch, org_escalation_paths must return a 2-hop path A-role→B-role.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires Docker"]
async fn two_account_a_to_b_cross_account_escalation() {
    let client = helpers::shared_client().await;
    let org_run_id = Uuid::new_v4().to_string();

    let account_a = "111111111111";
    let account_b = "222222222222";
    let role_a_arn = format!("arn:aws:iam::{}:role/AssumerRole", account_a);
    let role_b_arn = format!("arn:aws:iam::{}:role/TargetRole", account_b);

    // Account A: role that holds sts:AssumeRole on B's role
    let role_a = IamRole {
        arn: role_a_arn.clone(),
        role_id: format!("AROA{}ASSUMER", account_a),
        role_name: "AssumerRole".to_string(),
        path: "/".to_string(),
        create_date: Utc::now(),
        assume_role_policy_document: None,
        attached_managed_policies: vec![],
        inline_policies: vec![inline_policy(
            "StsPolicy",
            "sts:AssumeRole",
            &role_b_arn,
            Effect::Allow,
        )],
        permissions_boundary: None,
        role_last_used: None,
        description: None,
        max_session_duration: None,
        is_aws_managed: false,
        tags: HashMap::new(),
    };

    // Account B: role trusts account-A root, holds iam:PassRole
    let role_b = role_with_trust_and_policies(
        account_b,
        "TargetRole",
        &format!("arn:aws:iam::{}:root", account_a),
        vec![inline_policy(
            "RiskyPolicy",
            "iam:PassRole",
            "*",
            Effect::Allow,
        )],
        false,
    );

    let data_a = data_for_account(account_a, vec![role_a]);
    let data_b = data_for_account(account_b, vec![role_b]);

    let (client, _) = ingest_account(client, &data_a, account_a, &org_run_id).await;
    let (client, _) = ingest_account(client, &data_b, account_b, &org_run_id).await;

    let edges = stitch_cross_account(client.inner(), &org_run_id)
        .await
        .expect("stitch must succeed");
    assert!(
        edges >= 1,
        "expected at least one cross-account edge, got {edges}"
    );

    let ctx = OrgQueryContext::new(&org_run_id);
    let paths = org_escalation_paths(client.inner(), &ctx, 3)
        .await
        .expect("org_escalation_paths must succeed");

    let path = paths
        .iter()
        .find(|ep| ep.arn == role_a_arn)
        .expect("A's role must appear in escalation paths");

    assert!(
        path.risky_actions.contains(&"iam:PassRole".to_string()),
        "iam:PassRole must be in risky actions"
    );
    assert_eq!(path.account_id, account_a);
    assert!(
        path.path.iter().any(|h| h.account_id == account_b),
        "path must include a hop in account B"
    );
    assert!(
        !path.conditional,
        "unconditional trust must not be flagged conditional"
    );

    // The terminal (TargetRole, account B) trusts account A's root — trust_principals
    // enrichment must resolve against TargetRole's own snapshot_id (account B), not the
    // OrgQueryContext or account A's snapshot, confirming the per-hop snapshot_id self-join
    // works across account boundaries (issue #188).
    assert!(
        path.trust_principals
            .iter()
            .any(|tp| tp.id == format!("arn:aws:iam::{}:root", account_a)),
        "trust_principals on the terminal (TargetRole) must include account A's root: {:?}",
        path.trust_principals
    );
    assert!(
        path.holders.is_empty(),
        "holders must be empty for a Role terminal"
    );
}

/// Three-account A→B→C chain. A-role assumes B-role, B-role assumes C-role.
/// C-role holds iam:CreateAccessKey (risky). After stitch with max_hops=3,
/// org_escalation_paths must return a path from A's role through B to C.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires Docker"]
async fn three_account_a_to_b_to_c_chain() {
    let client = helpers::shared_client().await;
    let org_run_id = Uuid::new_v4().to_string();

    let account_a = "333333333333";
    let account_b = "444444444444";
    let account_c = "555555555555";
    let role_a_arn = format!("arn:aws:iam::{}:role/ChainRoleA", account_a);
    let role_b_arn = format!("arn:aws:iam::{}:role/ChainRoleB", account_b);
    let role_c_arn = format!("arn:aws:iam::{}:role/ChainRoleC", account_c);

    // A: holds sts:AssumeRole on B
    let role_a = IamRole {
        arn: role_a_arn.clone(),
        role_id: format!("AROA{}CHAINA", account_a),
        role_name: "ChainRoleA".to_string(),
        path: "/".to_string(),
        create_date: Utc::now(),
        assume_role_policy_document: None,
        attached_managed_policies: vec![],
        inline_policies: vec![inline_policy(
            "StsB",
            "sts:AssumeRole",
            &role_b_arn,
            Effect::Allow,
        )],
        permissions_boundary: None,
        role_last_used: None,
        description: None,
        max_session_duration: None,
        is_aws_managed: false,
        tags: HashMap::new(),
    };

    // B: trusts A root, holds sts:AssumeRole on C
    let role_b = role_with_trust_and_policies(
        account_b,
        "ChainRoleB",
        &format!("arn:aws:iam::{}:root", account_a),
        vec![inline_policy(
            "StsC",
            "sts:AssumeRole",
            &role_c_arn,
            Effect::Allow,
        )],
        false,
    );

    // C: trusts B root, holds iam:CreateAccessKey (risky)
    let role_c = role_with_trust_and_policies(
        account_c,
        "ChainRoleC",
        &format!("arn:aws:iam::{}:root", account_b),
        vec![inline_policy(
            "RiskyC",
            "iam:CreateAccessKey",
            "*",
            Effect::Allow,
        )],
        false,
    );

    let data_a = data_for_account(account_a, vec![role_a]);
    let data_b = data_for_account(account_b, vec![role_b]);
    let data_c = data_for_account(account_c, vec![role_c]);

    let (client, _) = ingest_account(client, &data_a, account_a, &org_run_id).await;
    let (client, _) = ingest_account(client, &data_b, account_b, &org_run_id).await;
    let (client, _) = ingest_account(client, &data_c, account_c, &org_run_id).await;

    stitch_cross_account(client.inner(), &org_run_id)
        .await
        .expect("stitch must succeed");

    let ctx = OrgQueryContext::new(&org_run_id);
    let paths = org_escalation_paths(client.inner(), &ctx, 3)
        .await
        .expect("org_escalation_paths must succeed");

    // B-role should reach C via one cross-account hop (B→C edge from stitch)
    let b_path = paths
        .iter()
        .find(|ep| ep.arn == role_b_arn)
        .expect("B's role must appear (can reach C's risky action)");
    assert!(b_path
        .risky_actions
        .contains(&"iam:CreateAccessKey".to_string()));

    // A-role should reach C via two cross-account hops if max_hops >= 2
    let a_path = paths.iter().find(|ep| ep.arn == role_a_arn);
    assert!(
        a_path.is_some(),
        "A's role must appear with max_hops=3; escalation chain A→B→C should be visible"
    );
}

/// Trust condition on B's role (sts:ExternalId) must propagate conditional=true
/// to the CAN_ASSUME_ROLE edge and the resulting escalation path.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires Docker"]
async fn conditional_trust_flags_path_conditional() {
    let client = helpers::shared_client().await;
    let org_run_id = Uuid::new_v4().to_string();

    let account_a = "666666666666";
    let account_b = "777777777777";
    let role_a_arn = format!("arn:aws:iam::{}:role/CondAssumer", account_a);
    let role_b_arn = format!("arn:aws:iam::{}:role/CondTarget", account_b);

    let role_a = IamRole {
        arn: role_a_arn.clone(),
        role_id: format!("AROA{}CONDASSUMER", account_a),
        role_name: "CondAssumer".to_string(),
        path: "/".to_string(),
        create_date: Utc::now(),
        assume_role_policy_document: None,
        attached_managed_policies: vec![],
        inline_policies: vec![inline_policy(
            "StsPolicy",
            "sts:AssumeRole",
            &role_b_arn,
            Effect::Allow,
        )],
        permissions_boundary: None,
        role_last_used: None,
        description: None,
        max_session_duration: None,
        is_aws_managed: false,
        tags: HashMap::new(),
    };

    // B's trust policy has a runtime condition (sts:ExternalId)
    let role_b = role_with_trust_and_policies(
        account_b,
        "CondTarget",
        &format!("arn:aws:iam::{}:root", account_a),
        vec![inline_policy(
            "RiskyPolicy",
            "iam:PassRole",
            "*",
            Effect::Allow,
        )],
        true, // conditional
    );

    let (client, _) = ingest_account(
        client,
        &data_for_account(account_a, vec![role_a]),
        account_a,
        &org_run_id,
    )
    .await;
    let (client, _) = ingest_account(
        client,
        &data_for_account(account_b, vec![role_b]),
        account_b,
        &org_run_id,
    )
    .await;

    stitch_cross_account(client.inner(), &org_run_id)
        .await
        .expect("stitch must succeed");

    let ctx = OrgQueryContext::new(&org_run_id);
    let paths = org_escalation_paths(client.inner(), &ctx, 3)
        .await
        .expect("org_escalation_paths must succeed");

    let path = paths
        .iter()
        .find(|ep| ep.arn == role_a_arn)
        .expect("A's role must appear");
    assert!(
        path.conditional,
        "path through conditional trust must be flagged conditional"
    );
}

/// Both-sides model: A trusts B's role but A's role has NO sts:AssumeRole grant.
/// Stitch should create NO cross-account edge; org_escalation_paths returns nothing for A.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires Docker"]
async fn no_sts_grant_means_no_cross_account_edge() {
    let client = helpers::shared_client().await;
    let org_run_id = Uuid::new_v4().to_string();

    let account_a = "888888888888";
    let account_b = "999999999999";
    let role_a_arn = format!("arn:aws:iam::{}:role/NoStsRole", account_a);

    // A: NO sts:AssumeRole grant (only has s3:GetObject)
    let role_a = IamRole {
        arn: role_a_arn.clone(),
        role_id: format!("AROA{}NOASSUME", account_a),
        role_name: "NoStsRole".to_string(),
        path: "/".to_string(),
        create_date: Utc::now(),
        assume_role_policy_document: None,
        attached_managed_policies: vec![],
        inline_policies: vec![inline_policy(
            "S3Policy",
            "s3:GetObject",
            "*",
            Effect::Allow,
        )],
        permissions_boundary: None,
        role_last_used: None,
        description: None,
        max_session_duration: None,
        is_aws_managed: false,
        tags: HashMap::new(),
    };

    // B: trusts A root, holds iam:PassRole — but A can't assume without sts grant
    let role_b = role_with_trust_and_policies(
        account_b,
        "TrustingTarget",
        &format!("arn:aws:iam::{}:root", account_a),
        vec![inline_policy(
            "RiskyPolicy",
            "iam:PassRole",
            "*",
            Effect::Allow,
        )],
        false,
    );

    let (client, _) = ingest_account(
        client,
        &data_for_account(account_a, vec![role_a]),
        account_a,
        &org_run_id,
    )
    .await;
    let (client, _) = ingest_account(
        client,
        &data_for_account(account_b, vec![role_b]),
        account_b,
        &org_run_id,
    )
    .await;

    let edges = stitch_cross_account(client.inner(), &org_run_id)
        .await
        .expect("stitch must succeed");
    assert_eq!(
        edges, 0,
        "no cross-account edge should be created without sts:AssumeRole grant"
    );

    let ctx = OrgQueryContext::new(&org_run_id);
    let paths = org_escalation_paths(client.inner(), &ctx, 3)
        .await
        .expect("org_escalation_paths must succeed");

    let found = paths.iter().any(|ep| ep.arn == role_a_arn);
    assert!(
        !found,
        "A's role must not appear in org escalation paths (no sts grant)"
    );
}
