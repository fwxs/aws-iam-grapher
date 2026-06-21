// Each test file includes this module separately, so not every helper is used in every file.
#![allow(dead_code)]

use chrono::Utc;
use iam_collector::{CollectedData, CollectorMode};
use iam_graph::{GraphClient, IngestConfig};
use std::sync::OnceLock;
use std::time::Duration;
use testcontainers_modules::{
    neo4j::{Neo4j, Neo4jImage},
    testcontainers::{core::WaitFor, runners::AsyncRunner, ContainerAsync, ImageExt as _},
};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Shared container (one per test binary)
// ---------------------------------------------------------------------------

struct ContainerInfo {
    uri: String,
    user: String,
    pass: String,
}

static NEO4J_CONTAINER: OnceLock<ContainerInfo> = OnceLock::new();

fn init_container() -> &'static ContainerInfo {
    NEO4J_CONTAINER.get_or_init(|| {
        // block_in_place lets us call block_on from inside a multi-thread tokio runtime.
        // All Docker-gated tests must use #[tokio::test(flavor = "multi_thread")].
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                let container: ContainerAsync<Neo4jImage> = Neo4j::default()
                    .with_ready_conditions(vec![
                        WaitFor::message_on_either_std("Bolt enabled on"),
                        WaitFor::message_on_either_std("Started."),
                    ])
                    .with_startup_timeout(Duration::from_secs(180))
                    .start()
                    .await
                    .expect("Neo4j must start");

                let host = container.get_host().await.expect("host must be available");
                let port = container
                    .image()
                    .bolt_port_ipv4()
                    .expect("bolt port must be available");
                let uri = format!("bolt://{}:{}", host, port);
                let user = container
                    .image()
                    .user()
                    .expect("default user is set")
                    .to_string();
                let pass = container
                    .image()
                    .password()
                    .expect("default password is set")
                    .to_string();

                // Leak the container so it is never dropped during the test run.
                // The Docker daemon manages the container lifecycle; cleanup happens
                // via ryuk (if enabled) or `docker container prune` after the process exits.
                Box::leak(Box::new(container));

                // Initialize schema once here so concurrent shared_client() calls
                // don't race on CREATE INDEX — Neo4j throws EquivalentSchemaRuleAlreadyExists
                // even with IF NOT EXISTS when multiple connections hit it simultaneously.
                let bootstrap = GraphClient::connect(&uri, &user, &pass)
                    .await
                    .expect("GraphClient must connect for schema init");
                bootstrap
                    .initialize_schema()
                    .await
                    .expect("schema init must succeed");

                ContainerInfo { uri, user, pass }
            })
        })
    })
}

/// Return a GraphClient connected to the shared Neo4j container for this test binary.
///
/// The container is started once on the first call and reused for all subsequent calls.
/// Schema is initialized exactly once inside `init_container()`.
///
/// Requires `#[tokio::test(flavor = "multi_thread")]` on the calling test.
pub async fn shared_client() -> GraphClient {
    let info = init_container();
    GraphClient::connect(&info.uri, &info.user, &info.pass)
        .await
        .expect("GraphClient must connect to shared Neo4j container")
}

// ---------------------------------------------------------------------------
// IngestConfig factory
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Data fixtures
// ---------------------------------------------------------------------------

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
            not_principal: None,
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
            not_principal: None,
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

/// Build CollectedData with a group+user (group-derived) and a second user with an inline policy.
///
/// Grant paths for `s3:DeleteObject`:
/// - Group `Auditors` → attached managed policy `GroupPolicy` → Allow s3:DeleteObject
/// - User `carol` → member of `Auditors` (group-derived)
/// - User `dave` → inline policy `DaveInline` → Allow s3:DeleteObject (no group)
pub fn data_with_user_group_and_inline(account_id: &str) -> CollectedData {
    use iam_models::{
        Effect, IamGroup, IamInlinePolicy, IamPolicy, IamUser, PolicyDocument, PolicyRef,
        PolicyStatement,
    };
    use std::collections::HashMap;

    let policy_arn = format!("arn:aws:iam::{}:policy/GroupPolicy", account_id);
    let group_arn = format!("arn:aws:iam::{}:group/Auditors", account_id);
    let carol_arn = format!("arn:aws:iam::{}:user/carol", account_id);
    let dave_arn = format!("arn:aws:iam::{}:user/dave", account_id);

    let allow_s3_delete = PolicyDocument {
        version: Some("2012-10-17".to_string()),
        statement: vec![PolicyStatement {
            sid: None,
            effect: Effect::Allow,
            action: vec!["s3:DeleteObject".to_string()],
            not_action: vec![],
            resource: vec!["*".to_string()],
            not_resource: vec![],
            principal: None,
            not_principal: None,
            condition: None,
        }],
    };

    let managed_policy = IamPolicy {
        arn: policy_arn.clone(),
        policy_id: "ANPAGROUPTEST".to_string(),
        policy_name: "GroupPolicy".to_string(),
        path: "/".to_string(),
        create_date: Utc::now(),
        update_date: Utc::now(),
        attachment_count: 1,
        is_attachable: true,
        default_version_id: "v1".to_string(),
        description: None,
        is_aws_managed: false,
        document: Some(allow_s3_delete.clone()),
        tags: HashMap::new(),
    };

    let group = IamGroup {
        arn: group_arn.clone(),
        group_id: "AGPAAUDITORS".to_string(),
        group_name: "Auditors".to_string(),
        path: "/".to_string(),
        create_date: Utc::now(),
        attached_managed_policies: vec![PolicyRef {
            policy_arn: policy_arn.clone(),
            policy_name: "GroupPolicy".to_string(),
        }],
        inline_policies: vec![],
    };

    let carol = IamUser {
        arn: carol_arn.clone(),
        user_id: "AIDACAROL".to_string(),
        user_name: "carol".to_string(),
        path: "/".to_string(),
        create_date: Utc::now(),
        attached_managed_policies: vec![],
        inline_policies: vec![],
        group_list: vec!["Auditors".to_string()],
        permissions_boundary: None,
        password_last_used: None,
        access_keys: vec![],
        is_aws_managed: false,
        tags: HashMap::new(),
    };

    let dave_inline = IamInlinePolicy {
        policy_name: "DaveInline".to_string(),
        policy_document: allow_s3_delete,
    };

    let dave = IamUser {
        arn: dave_arn.clone(),
        user_id: "AIDADAVE".to_string(),
        user_name: "dave".to_string(),
        path: "/".to_string(),
        create_date: Utc::now(),
        attached_managed_policies: vec![],
        inline_policies: vec![dave_inline],
        group_list: vec![],
        permissions_boundary: None,
        password_last_used: None,
        access_keys: vec![],
        is_aws_managed: false,
        tags: HashMap::new(),
    };

    CollectedData {
        source: CollectorMode::Offline,
        account_id: Some(account_id.to_string()),
        collection_timestamp: Utc::now(),
        policies: vec![managed_policy],
        groups: vec![group],
        users: vec![carol, dave],
        ..Default::default()
    }
}

/// Build CollectedData with a role that has both Allow AND Deny for the same action.
/// Used to verify explicit Deny overrides Allow in `who_can` queries.
pub fn data_with_allow_and_deny(account_id: &str, action: &str) -> CollectedData {
    use iam_models::{Effect, IamInlinePolicy, IamRole, PolicyDocument, PolicyStatement};
    use std::collections::HashMap;

    let role_arn = format!("arn:aws:iam::{}:role/DenyTestRole", account_id);
    let make_stmt = |effect: Effect| PolicyStatement {
        sid: None,
        effect,
        action: vec![action.to_string()],
        not_action: vec![],
        resource: vec!["*".to_string()],
        not_resource: vec![],
        principal: None,
        not_principal: None,
        condition: None,
    };
    let inline = IamInlinePolicy {
        policy_name: "AllowAndDenyPolicy".to_string(),
        policy_document: PolicyDocument {
            version: Some("2012-10-17".to_string()),
            statement: vec![make_stmt(Effect::Allow), make_stmt(Effect::Deny)],
        },
    };
    let role = IamRole {
        arn: role_arn.clone(),
        role_id: "AROATEST_DENY".to_string(),
        role_name: "DenyTestRole".to_string(),
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

/// Build CollectedData with a role that holds `Action: "*"` Allow (full-admin).
pub fn data_with_full_admin_role(account_id: &str) -> CollectedData {
    use iam_models::{Effect, IamInlinePolicy, IamRole, PolicyDocument, PolicyStatement};
    use std::collections::HashMap;

    let role_arn = format!("arn:aws:iam::{}:role/FullAdminRole", account_id);
    let inline = IamInlinePolicy {
        policy_name: "FullAdminPolicy".to_string(),
        policy_document: PolicyDocument {
            version: Some("2012-10-17".to_string()),
            statement: vec![PolicyStatement {
                sid: None,
                effect: Effect::Allow,
                action: vec!["*".to_string()],
                not_action: vec![],
                resource: vec!["*".to_string()],
                not_resource: vec![],
                principal: None,
                not_principal: None,
                condition: None,
            }],
        },
    };
    let role = IamRole {
        arn: role_arn.clone(),
        role_id: "AROATEST_ADMIN".to_string(),
        role_name: "FullAdminRole".to_string(),
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

/// Build CollectedData with a role holding `Action: "*"` scoped to a single `resource` (e.g. a
/// specific bucket ARN), rather than the unrestricted `"*"` resource used by
/// `data_with_full_admin_role`. Used to test `who_can`'s `--resource` intersection (M-A2).
pub fn data_with_resource_scoped_full_admin_role(
    account_id: &str,
    resource: &str,
) -> CollectedData {
    use iam_models::{Effect, IamInlinePolicy, IamRole, PolicyDocument, PolicyStatement};
    use std::collections::HashMap;

    let role_arn = format!("arn:aws:iam::{}:role/ScopedAdminRole", account_id);
    let inline = IamInlinePolicy {
        policy_name: "ScopedAdminPolicy".to_string(),
        policy_document: PolicyDocument {
            version: Some("2012-10-17".to_string()),
            statement: vec![PolicyStatement {
                sid: None,
                effect: Effect::Allow,
                action: vec!["*".to_string()],
                not_action: vec![],
                resource: vec![resource.to_string()],
                not_resource: vec![],
                principal: None,
                not_principal: None,
                condition: None,
            }],
        },
    };
    let role = IamRole {
        arn: role_arn.clone(),
        role_id: "AROATEST_SCOPED_ADMIN".to_string(),
        role_name: "ScopedAdminRole".to_string(),
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

/// Build CollectedData carrying a InstanceProfilesMissing warning.
pub fn data_with_missing_profiles_warning(account_id: &str) -> CollectedData {
    use iam_collector::CollectorWarning;

    CollectedData {
        source: CollectorMode::Offline,
        account_id: Some(account_id.to_string()),
        collection_timestamp: Utc::now(),
        warnings: vec![CollectorWarning::InstanceProfilesMissing],
        ..Default::default()
    }
}

/// Build CollectedData carrying a WildcardsNotExpanded warning (simulates awsiamactions.io failure).
pub fn data_with_wildcards_not_expanded_warning(account_id: &str) -> CollectedData {
    use iam_collector::CollectorWarning;

    CollectedData {
        source: CollectorMode::Offline,
        account_id: Some(account_id.to_string()),
        collection_timestamp: Utc::now(),
        warnings: vec![CollectorWarning::WildcardsNotExpanded],
        ..Default::default()
    }
}

/// Build CollectedData with a role whose inline policy has `Allow NotAction: [excluded_action]`.
///
/// The excluded list is passed pre-expanded (no wildcards) — callers specify exact action strings.
/// The role ARN is `arn:aws:iam::<account_id>:role/NotActionRole`.
pub fn data_with_allow_not_action(account_id: &str, excluded_action: &str) -> CollectedData {
    use iam_models::{Effect, IamInlinePolicy, IamRole, PolicyDocument, PolicyStatement};
    use std::collections::HashMap;

    let role_arn = format!("arn:aws:iam::{}:role/NotActionRole", account_id);
    let inline = IamInlinePolicy {
        policy_name: "NotActionPolicy".to_string(),
        policy_document: PolicyDocument {
            version: Some("2012-10-17".to_string()),
            statement: vec![PolicyStatement {
                sid: None,
                effect: Effect::Allow,
                action: vec![],
                not_action: vec![excluded_action.to_string()],
                resource: vec!["*".to_string()],
                not_resource: vec![],
                principal: None,
                not_principal: None,
                condition: None,
            }],
        },
    };
    let role = IamRole {
        arn: role_arn.clone(),
        role_id: "AROATEST_NOTACTION".to_string(),
        role_name: "NotActionRole".to_string(),
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

/// Build CollectedData with a role that has `Allow $action` AND `Deny $deny_action_pattern`
/// (e.g. `s3:Delete*`) in an inline policy. Used to verify wildcard Deny suppresses Allow.
pub fn data_with_allow_and_wildcard_deny(
    account_id: &str,
    action: &str,
    deny_action_pattern: &str,
) -> CollectedData {
    use iam_models::{Effect, IamInlinePolicy, IamRole, PolicyDocument, PolicyStatement};
    use std::collections::HashMap;

    let role_arn = format!("arn:aws:iam::{}:role/WildcardDenyTestRole", account_id);
    let make_stmt = |effect: Effect, action: &str| PolicyStatement {
        sid: None,
        effect,
        action: vec![action.to_string()],
        not_action: vec![],
        resource: vec!["*".to_string()],
        not_resource: vec![],
        principal: None,
        not_principal: None,
        condition: None,
    };
    let inline = IamInlinePolicy {
        policy_name: "AllowAndWildcardDenyPolicy".to_string(),
        policy_document: PolicyDocument {
            version: Some("2012-10-17".to_string()),
            statement: vec![
                make_stmt(Effect::Allow, action),
                make_stmt(Effect::Deny, deny_action_pattern),
            ],
        },
    };
    let role = IamRole {
        arn: role_arn.clone(),
        role_id: "AROATEST_WILDCARD_DENY".to_string(),
        role_name: "WildcardDenyTestRole".to_string(),
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

/// Build CollectedData with a user Allowed `action` on its own inline policy, and a group
/// (that the user is a member of) Denying the same action via the group's inline policy.
/// Used to verify group-inherited Deny suppresses a user's own Allow.
pub fn data_with_user_allow_and_group_deny(account_id: &str, action: &str) -> CollectedData {
    use iam_models::{Effect, IamGroup, IamInlinePolicy, IamUser, PolicyDocument, PolicyStatement};
    use std::collections::HashMap;

    let user_arn = format!("arn:aws:iam::{}:user/GroupDeniedUser", account_id);
    let group_arn = format!("arn:aws:iam::{}:group/DenyingGroup", account_id);

    let make_stmt = |effect: Effect| PolicyStatement {
        sid: None,
        effect,
        action: vec![action.to_string()],
        not_action: vec![],
        resource: vec!["*".to_string()],
        not_resource: vec![],
        principal: None,
        not_principal: None,
        condition: None,
    };

    let group = IamGroup {
        arn: group_arn.clone(),
        group_id: "AGPADENYGROUP".to_string(),
        group_name: "DenyingGroup".to_string(),
        path: "/".to_string(),
        create_date: Utc::now(),
        attached_managed_policies: vec![],
        inline_policies: vec![IamInlinePolicy {
            policy_name: "GroupDenyPolicy".to_string(),
            policy_document: PolicyDocument {
                version: Some("2012-10-17".to_string()),
                statement: vec![make_stmt(Effect::Deny)],
            },
        }],
    };

    let user = IamUser {
        arn: user_arn.clone(),
        user_id: "AIDAGROUPDENIED".to_string(),
        user_name: "GroupDeniedUser".to_string(),
        path: "/".to_string(),
        create_date: Utc::now(),
        attached_managed_policies: vec![],
        inline_policies: vec![IamInlinePolicy {
            policy_name: "UserAllowPolicy".to_string(),
            policy_document: PolicyDocument {
                version: Some("2012-10-17".to_string()),
                statement: vec![make_stmt(Effect::Allow)],
            },
        }],
        group_list: vec!["DenyingGroup".to_string()],
        permissions_boundary: None,
        password_last_used: None,
        access_keys: vec![],
        is_aws_managed: false,
        tags: HashMap::new(),
    };

    CollectedData {
        source: CollectorMode::Offline,
        account_id: Some(account_id.to_string()),
        collection_timestamp: Utc::now(),
        groups: vec![group],
        users: vec![user],
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
                not_principal: None,
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
