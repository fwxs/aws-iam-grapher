// Each test file includes this module separately, so not every helper is used in every file.
#![allow(dead_code)]

use chrono::Utc;
use iam_collector::{CollectedData, CollectorMode};
use iam_graph::{GraphClient, IngestConfig};
use testcontainers_modules::{
    neo4j::{Neo4j, Neo4jImage},
    testcontainers::{runners::AsyncRunner, ContainerAsync},
};
use uuid::Uuid;

/// Start a Neo4j Community container and return a connected GraphClient.
/// The container is kept alive as long as the returned handle is in scope.
pub async fn start_neo4j() -> (GraphClient, ContainerAsync<Neo4jImage>) {
    let container = Neo4j::default().start().await.expect("Neo4j must start");
    let host = container.get_host().await.expect("host must be available");
    let port = container
        .image()
        .bolt_port_ipv4()
        .expect("bolt port must be available");
    let uri = format!("bolt://{}:{}", host, port);
    let user = container.image().user().expect("default user is set");
    let pass = container
        .image()
        .password()
        .expect("default password is set");

    let client = GraphClient::connect(&uri, user, pass)
        .await
        .expect("GraphClient must connect");
    client
        .initialize_schema()
        .await
        .expect("schema init must succeed");

    (client, container)
}

/// Create an IngestConfig with a fresh snapshot ID for the given account.
pub fn test_config(account_id: &str) -> IngestConfig {
    IngestConfig {
        batch_size: 500,
        snapshot_id: Uuid::new_v4().to_string(),
        account_id: account_id.to_string(),
        account_alias: Some("test-account".to_string()),
        dry_run: false,
    }
}

/// Minimal CollectedData with no entities.
pub fn empty_data(account_id: &str) -> CollectedData {
    CollectedData {
        source: CollectorMode::Offline,
        account_id: Some(account_id.to_string()),
        collection_timestamp: Utc::now(),
        ..Default::default()
    }
}

/// Build CollectedData with a single managed policy that has an explicit document.
pub fn data_with_policy(account_id: &str) -> (CollectedData, String) {
    use iam_models::{Effect, IamPolicy, PolicyDocument, PolicyStatement};
    use std::collections::HashMap;

    let policy_arn = format!("arn:aws:iam::{}:policy/TestPolicy", account_id);
    let doc = PolicyDocument {
        version: Some("2012-10-17".to_string()),
        statement: vec![PolicyStatement {
            sid: Some("AllowS3".to_string()),
            effect: Effect::Allow,
            action: vec!["s3:GetObject".to_string()],
            not_action: vec![],
            resource: vec!["*".to_string()],
            not_resource: vec![],
            principal: None,
            condition: None,
        }],
    };
    let policy = IamPolicy {
        arn: policy_arn.clone(),
        policy_id: "ANPATEST".to_string(),
        policy_name: "TestPolicy".to_string(),
        path: "/".to_string(),
        create_date: Utc::now(),
        update_date: Utc::now(),
        attachment_count: 0,
        is_attachable: true,
        default_version_id: "v1".to_string(),
        description: None,
        is_aws_managed: false,
        document: Some(doc),
        tags: HashMap::new(),
    };
    let data = CollectedData {
        source: CollectorMode::Offline,
        account_id: Some(account_id.to_string()),
        collection_timestamp: Utc::now(),
        policies: vec![policy],
        ..Default::default()
    };
    (data, policy_arn)
}

/// Build CollectedData with a role attached to a policy.
pub fn data_with_role_and_policy(account_id: &str) -> CollectedData {
    use iam_models::{Effect, IamPolicy, IamRole, PolicyDocument, PolicyRef, PolicyStatement};
    use std::collections::HashMap;

    let policy_arn = format!("arn:aws:iam::{}:policy/RolePolicy", account_id);
    let role_arn = format!("arn:aws:iam::{}:role/TestRole", account_id);

    let doc = PolicyDocument {
        version: Some("2012-10-17".to_string()),
        statement: vec![PolicyStatement {
            sid: None,
            effect: Effect::Allow,
            action: vec!["ec2:DescribeInstances".to_string()],
            not_action: vec![],
            resource: vec!["*".to_string()],
            not_resource: vec![],
            principal: None,
            condition: None,
        }],
    };
    let policy = IamPolicy {
        arn: policy_arn.clone(),
        policy_id: "ANPAROLE".to_string(),
        policy_name: "RolePolicy".to_string(),
        path: "/".to_string(),
        create_date: Utc::now(),
        update_date: Utc::now(),
        attachment_count: 1,
        is_attachable: true,
        default_version_id: "v1".to_string(),
        description: None,
        is_aws_managed: false,
        document: Some(doc),
        tags: HashMap::new(),
    };
    let role = IamRole {
        arn: role_arn.clone(),
        role_id: "AROATEST".to_string(),
        role_name: "TestRole".to_string(),
        path: "/".to_string(),
        create_date: Utc::now(),
        assume_role_policy_document: None,
        attached_managed_policies: vec![PolicyRef {
            policy_arn: policy_arn.clone(),
            policy_name: "RolePolicy".to_string(),
        }],
        inline_policies: vec![],
        permissions_boundary: None,
        role_last_used: None,
        description: None,
        max_session_duration: None,
        is_aws_managed: false,
        tags: HashMap::new(),
    };
    CollectedData {
        source: CollectorMode::Offline,
        account_id: Some(account_id.to_string()),
        collection_timestamp: Utc::now(),
        policies: vec![policy],
        roles: vec![role],
        ..Default::default()
    }
}

/// Build CollectedData with an instance profile containing a role.
pub fn data_with_instance_profile(account_id: &str) -> CollectedData {
    use iam_models::{IamInstanceProfile, IamRole};
    use std::collections::HashMap;

    let role_arn = format!("arn:aws:iam::{}:role/ProfileRole", account_id);
    let profile_arn = format!("arn:aws:iam::{}:instance-profile/TestProfile", account_id);

    let role = IamRole {
        arn: role_arn.clone(),
        role_id: "AROAIP".to_string(),
        role_name: "ProfileRole".to_string(),
        path: "/".to_string(),
        create_date: Utc::now(),
        assume_role_policy_document: None,
        attached_managed_policies: vec![],
        inline_policies: vec![],
        permissions_boundary: None,
        role_last_used: None,
        description: None,
        max_session_duration: None,
        is_aws_managed: false,
        tags: HashMap::new(),
    };
    let profile = IamInstanceProfile {
        arn: profile_arn.clone(),
        instance_profile_id: "AIPTEST".to_string(),
        instance_profile_name: "TestProfile".to_string(),
        path: "/".to_string(),
        create_date: Utc::now(),
        roles: vec![role.clone()],
        is_aws_managed: false,
    };
    CollectedData {
        source: CollectorMode::Offline,
        account_id: Some(account_id.to_string()),
        collection_timestamp: Utc::now(),
        roles: vec![role],
        instance_profiles: vec![profile],
        ..Default::default()
    }
}

/// Build CollectedData with a role that has the given action in an inline policy.
pub fn data_with_role_action(account_id: &str, action: &str, effect_allow: bool) -> CollectedData {
    use iam_models::{Effect, IamInlinePolicy, IamRole, PolicyDocument, PolicyStatement};
    use std::collections::HashMap;

    let role_arn = format!("arn:aws:iam::{}:role/ActionRole", account_id);
    let eff = if effect_allow {
        Effect::Allow
    } else {
        Effect::Deny
    };
    let inline = IamInlinePolicy {
        policy_name: "InlineActionPolicy".to_string(),
        policy_document: PolicyDocument {
            version: Some("2012-10-17".to_string()),
            statement: vec![PolicyStatement {
                sid: None,
                effect: eff,
                action: vec![action.to_string()],
                not_action: vec![],
                resource: vec!["*".to_string()],
                not_resource: vec![],
                principal: None,
                condition: None,
            }],
        },
    };
    let role = IamRole {
        arn: role_arn.clone(),
        role_id: "AROAACTION".to_string(),
        role_name: "ActionRole".to_string(),
        path: "/".to_string(),
        create_date: Utc::now(),
        assume_role_policy_document: None,
        attached_managed_policies: vec![],
        inline_policies: vec![inline],
        permissions_boundary: None,
        role_last_used: None,
        description: None,
        max_session_duration: None,
        is_aws_managed: false,
        tags: HashMap::new(),
    };
    CollectedData {
        source: CollectorMode::Offline,
        account_id: Some(account_id.to_string()),
        collection_timestamp: Utc::now(),
        roles: vec![role],
        ..Default::default()
    }
}
