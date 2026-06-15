use crate::errors::{CollectorError, CollectorWarning};
use crate::expand::expand_collected_data;
use crate::traits::{CollectedData, CollectorMode, IamDataSource};
use crate::util::account_id_from_arns;
use aws_sdk_iam::error::SdkError;
use chrono::{DateTime, Utc};
use iam_models::{
    IamGroup, IamInlinePolicy, IamInstanceProfile, IamPolicy, IamRole, IamUser,
    PermissionsBoundary, PolicyDocument, PolicyRef, RoleLastUsed,
};
use std::collections::HashMap;
use tracing::{debug, info, warn};

/// Collects IAM data from the live AWS API.
pub struct LiveCollector {
    iam_client: aws_sdk_iam::Client,
}

impl LiveCollector {
    /// Create a collector from an already-constructed IAM client (for testing).
    pub fn new(client: aws_sdk_iam::Client) -> Self {
        Self { iam_client: client }
    }

    /// Create a collector loading credentials from the environment.
    pub async fn from_env() -> Result<Self, CollectorError> {
        let config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
        Ok(Self::new(aws_sdk_iam::Client::new(&config)))
    }
}

#[async_trait::async_trait]
impl IamDataSource for LiveCollector {
    fn mode(&self) -> CollectorMode {
        CollectorMode::Live
    }

    async fn collect(&self) -> Result<CollectedData, CollectorError> {
        info!("starting live IAM collection");
        let mut warnings = Vec::new();

        let mut users: Vec<IamUser> = Vec::new();
        let mut roles: Vec<IamRole> = Vec::new();
        let mut groups: Vec<IamGroup> = Vec::new();
        let mut policies: Vec<IamPolicy> = Vec::new();

        let mut paginator = self
            .iam_client
            .get_account_authorization_details()
            .into_paginator()
            .send();

        let mut page_count = 0u32;
        while let Some(page) = paginator.next().await {
            let page = page.map_err(map_sdk_error)?;
            page_count += 1;
            debug!(
                page = page_count,
                "processing GetAccountAuthorizationDetails page"
            );

            for u in page.user_detail_list() {
                users.push(sdk_user_to_model(u));
            }
            for r in page.role_detail_list() {
                roles.push(sdk_role_to_model(r));
            }
            for g in page.group_detail_list() {
                groups.push(sdk_group_to_model(g));
            }
            for p in page.policies() {
                policies.push(sdk_managed_policy_to_model(p));
            }
        }

        debug!(
            users = users.len(),
            roles = roles.len(),
            groups = groups.len(),
            policies = policies.len(),
            "collected entities"
        );

        // Paginate ListInstanceProfiles (non-fatal on 403)
        let mut instance_profiles: Vec<IamInstanceProfile> = Vec::new();
        let mut ip_paginator = self
            .iam_client
            .list_instance_profiles()
            .into_paginator()
            .send();

        loop {
            match ip_paginator.next().await {
                None => break,
                Some(Err(e)) => {
                    let mapped = map_sdk_error(e);
                    if matches!(mapped, CollectorError::InsufficientPermissions(_)) {
                        warn!("insufficient permissions for ListInstanceProfiles — skipping");
                        warnings.push(CollectorWarning::InstanceProfilesMissing);
                        break;
                    }
                    return Err(mapped);
                }
                Some(Ok(page)) => {
                    for ip in page.instance_profiles() {
                        instance_profiles.push(sdk_instance_profile_to_model(ip));
                    }
                }
            }
        }

        info!(
            instance_profiles = instance_profiles.len(),
            "live collection complete"
        );

        // Prefer customer entity ARNs (users, roles, groups) over managed-policy ARNs,
        // which use the literal "aws" as their account segment.
        let account_id = account_id_from_arns(
            users
                .iter()
                .map(|u| u.arn.as_str())
                .chain(roles.iter().map(|r| r.arn.as_str()))
                .chain(groups.iter().map(|g| g.arn.as_str()))
                .chain(instance_profiles.iter().map(|ip| ip.arn.as_str()))
                .chain(policies.iter().map(|p| p.arn.as_str())),
        );

        let mut data = CollectedData {
            source: CollectorMode::Live,
            account_id,
            policies,
            roles,
            users,
            groups,
            instance_profiles,
            collection_timestamp: Utc::now(),
            warnings,
        };

        expand_collected_data(&mut data).await;

        Ok(data)
    }
}

// ---------------------------------------------------------------------------
// SDK type → iam-models type conversions
// ---------------------------------------------------------------------------

/// Convert an AWS smithy DateTime to chrono UTC. Calling `.secs()` and
/// `.subsec_nanos()` works without naming `aws_smithy_types::DateTime`
/// directly in our Cargo.toml because the type comes from the SDK.
macro_rules! sdk_dt {
    ($opt:expr) => {
        $opt.and_then(|d| DateTime::from_timestamp(d.secs(), d.subsec_nanos()))
            .unwrap_or_else(Utc::now)
    };
}

fn parse_policy_doc(s: Option<&str>) -> Option<PolicyDocument> {
    let s = s?;
    serde_json::from_str(s)
        .or_else(|_| serde_json::from_str(&percent_decode(s)))
        .ok()
}

fn percent_decode(s: &str) -> String {
    let mut result = Vec::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Some(byte) = std::str::from_utf8(&bytes[i + 1..i + 3])
                .ok()
                .and_then(|h| u8::from_str_radix(h, 16).ok())
            {
                result.push(byte);
                i += 3;
                continue;
            }
        } else if bytes[i] == b'+' {
            result.push(b' ');
            i += 1;
            continue;
        }
        result.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&result).into_owned()
}

fn sdk_policy_ref(p: &aws_sdk_iam::types::AttachedPolicy) -> PolicyRef {
    PolicyRef {
        policy_arn: p.policy_arn().unwrap_or_default().to_string(),
        policy_name: p.policy_name().unwrap_or_default().to_string(),
    }
}

fn sdk_boundary(
    b: Option<&aws_sdk_iam::types::AttachedPermissionsBoundary>,
) -> Option<PermissionsBoundary> {
    b.map(|b| PermissionsBoundary {
        permissions_boundary_type: b
            .permissions_boundary_type()
            .map(|t| t.as_str().to_string())
            .unwrap_or_default(),
        permissions_boundary_arn: b.permissions_boundary_arn().unwrap_or_default().to_string(),
    })
}

fn sdk_inline(p: &aws_sdk_iam::types::PolicyDetail) -> Option<IamInlinePolicy> {
    let name = p.policy_name()?.to_string();
    let doc = parse_policy_doc(p.policy_document())?;
    Some(IamInlinePolicy {
        policy_name: name,
        policy_document: doc,
    })
}

fn sdk_tags(tags: &[aws_sdk_iam::types::Tag]) -> HashMap<String, String> {
    tags.iter()
        .map(|t| (t.key().to_string(), t.value().to_string()))
        .collect()
}

fn sdk_user_to_model(u: &aws_sdk_iam::types::UserDetail) -> IamUser {
    IamUser {
        arn: u.arn().unwrap_or_default().to_string(),
        user_id: u.user_id().unwrap_or_default().to_string(),
        user_name: u.user_name().unwrap_or_default().to_string(),
        path: u.path().unwrap_or("/").to_string(),
        create_date: sdk_dt!(u.create_date()),
        attached_managed_policies: u
            .attached_managed_policies()
            .iter()
            .map(sdk_policy_ref)
            .collect(),
        inline_policies: u.user_policy_list().iter().filter_map(sdk_inline).collect(),
        group_list: u.group_list().to_vec(),
        permissions_boundary: sdk_boundary(u.permissions_boundary()),
        password_last_used: None,
        access_keys: Vec::new(),
        is_aws_managed: false,
        tags: sdk_tags(u.tags()),
    }
}

fn sdk_group_to_model(g: &aws_sdk_iam::types::GroupDetail) -> IamGroup {
    IamGroup {
        arn: g.arn().unwrap_or_default().to_string(),
        group_id: g.group_id().unwrap_or_default().to_string(),
        group_name: g.group_name().unwrap_or_default().to_string(),
        path: g.path().unwrap_or("/").to_string(),
        create_date: sdk_dt!(g.create_date()),
        attached_managed_policies: g
            .attached_managed_policies()
            .iter()
            .map(sdk_policy_ref)
            .collect(),
        inline_policies: g
            .group_policy_list()
            .iter()
            .filter_map(sdk_inline)
            .collect(),
    }
}

fn sdk_role_to_model(r: &aws_sdk_iam::types::RoleDetail) -> IamRole {
    let is_aws_managed = r.path().unwrap_or("/").starts_with("/aws-service-role/");
    let role_last_used = r.role_last_used().map(|rlu| RoleLastUsed {
        last_used_date: rlu
            .last_used_date()
            .and_then(|d| DateTime::from_timestamp(d.secs(), d.subsec_nanos())),
        region: rlu.region().map(|s| s.to_string()),
    });
    IamRole {
        arn: r.arn().unwrap_or_default().to_string(),
        role_id: r.role_id().unwrap_or_default().to_string(),
        role_name: r.role_name().unwrap_or_default().to_string(),
        path: r.path().unwrap_or("/").to_string(),
        create_date: sdk_dt!(r.create_date()),
        assume_role_policy_document: parse_policy_doc(r.assume_role_policy_document()),
        attached_managed_policies: r
            .attached_managed_policies()
            .iter()
            .map(sdk_policy_ref)
            .collect(),
        inline_policies: r.role_policy_list().iter().filter_map(sdk_inline).collect(),
        permissions_boundary: sdk_boundary(r.permissions_boundary()),
        role_last_used,
        description: None,
        max_session_duration: None,
        is_aws_managed,
        tags: sdk_tags(r.tags()),
    }
}

fn sdk_managed_policy_to_model(p: &aws_sdk_iam::types::ManagedPolicyDetail) -> IamPolicy {
    let arn = p.arn().unwrap_or_default().to_string();
    let is_aws_managed = arn.contains(":aws:policy/");
    let document = p
        .policy_version_list()
        .iter()
        .find(|v| v.is_default_version())
        .and_then(|v| parse_policy_doc(v.document()));
    IamPolicy {
        arn,
        policy_id: p.policy_id().unwrap_or_default().to_string(),
        policy_name: p.policy_name().unwrap_or_default().to_string(),
        path: p.path().unwrap_or("/").to_string(),
        create_date: sdk_dt!(p.create_date()),
        update_date: sdk_dt!(p.update_date()),
        attachment_count: p.attachment_count().unwrap_or(0),
        is_attachable: p.is_attachable(),
        default_version_id: p.default_version_id().unwrap_or("v1").to_string(),
        description: p.description().map(|s| s.to_string()),
        is_aws_managed,
        document,
        tags: HashMap::new(),
    }
}

fn sdk_role_from_role_type(r: &aws_sdk_iam::types::Role) -> IamRole {
    let is_aws_managed = r.path().starts_with("/aws-service-role/");
    let role_last_used = r.role_last_used().map(|rlu| RoleLastUsed {
        last_used_date: rlu
            .last_used_date()
            .and_then(|d| DateTime::from_timestamp(d.secs(), d.subsec_nanos())),
        region: rlu.region().map(|s| s.to_string()),
    });
    IamRole {
        arn: r.arn().to_string(),
        role_id: r.role_id().to_string(),
        role_name: r.role_name().to_string(),
        path: r.path().to_string(),
        create_date: DateTime::from_timestamp(
            r.create_date().secs(),
            r.create_date().subsec_nanos(),
        )
        .unwrap_or_else(Utc::now),
        assume_role_policy_document: parse_policy_doc(r.assume_role_policy_document()),
        attached_managed_policies: Vec::new(),
        inline_policies: Vec::new(),
        permissions_boundary: None,
        role_last_used,
        description: r.description().map(|s| s.to_string()),
        max_session_duration: r.max_session_duration(),
        is_aws_managed,
        tags: sdk_tags(r.tags()),
    }
}

fn sdk_instance_profile_to_model(ip: &aws_sdk_iam::types::InstanceProfile) -> IamInstanceProfile {
    let is_aws_managed = ip.path().starts_with("/aws-service-role/");
    let roles = ip.roles().iter().map(sdk_role_from_role_type).collect();
    IamInstanceProfile {
        arn: ip.arn().to_string(),
        instance_profile_id: ip.instance_profile_id().to_string(),
        instance_profile_name: ip.instance_profile_name().to_string(),
        path: ip.path().to_string(),
        create_date: DateTime::from_timestamp(
            ip.create_date().secs(),
            ip.create_date().subsec_nanos(),
        )
        .unwrap_or_else(Utc::now),
        roles,
        is_aws_managed,
    }
}

// ---------------------------------------------------------------------------
// Error mapping — inspect error string for HTTP status codes
// ---------------------------------------------------------------------------

fn map_sdk_error<E: std::fmt::Debug, R: std::fmt::Debug>(err: SdkError<E, R>) -> CollectorError {
    let msg = format!("{err:?}");
    // Check for HTTP 403 / permission denied indicators
    if msg.contains("403") || msg.contains("AccessDenied") || msg.contains("Forbidden") {
        return CollectorError::InsufficientPermissions(msg);
    }
    CollectorError::AwsSdk(msg)
}
