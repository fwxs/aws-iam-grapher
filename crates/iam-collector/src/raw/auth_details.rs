use chrono::{DateTime, Utc};
use iam_models::{
    IamGroup, IamInlinePolicy, IamPolicy, IamRole, IamUser, PermissionsBoundary, PolicyDocument,
    PolicyRef, RoleLastUsed,
};
use serde::Deserialize;
use std::collections::HashMap;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct AccountAuthorizationDetails {
    #[serde(default)]
    pub user_detail_list: Vec<RawUserDetail>,
    #[serde(default)]
    pub group_detail_list: Vec<RawGroupDetail>,
    #[serde(default)]
    pub role_detail_list: Vec<RawRoleDetail>,
    #[serde(default)]
    pub policies: Vec<RawManagedPolicy>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct RawUserDetail {
    pub arn: String,
    pub user_id: String,
    pub user_name: String,
    pub path: String,
    pub create_date: DateTime<Utc>,
    #[serde(default)]
    pub attached_managed_policies: Vec<PolicyRef>,
    #[serde(default)]
    pub user_policy_list: Vec<RawInlinePolicy>,
    #[serde(default)]
    pub group_list: Vec<String>,
    pub permissions_boundary: Option<PermissionsBoundary>,
    pub password_last_used: Option<DateTime<Utc>>,
    #[serde(default)]
    pub tags: Vec<RawTag>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct RawGroupDetail {
    pub arn: String,
    pub group_id: String,
    pub group_name: String,
    pub path: String,
    pub create_date: DateTime<Utc>,
    #[serde(default)]
    pub attached_managed_policies: Vec<PolicyRef>,
    #[serde(default)]
    pub group_policy_list: Vec<RawInlinePolicy>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct RawRoleDetail {
    pub arn: String,
    pub role_id: String,
    pub role_name: String,
    pub path: String,
    pub create_date: DateTime<Utc>,
    pub assume_role_policy_document: Option<PolicyDocument>,
    #[serde(default)]
    pub attached_managed_policies: Vec<PolicyRef>,
    #[serde(default)]
    pub role_policy_list: Vec<RawInlinePolicy>,
    pub permissions_boundary: Option<PermissionsBoundary>,
    pub role_last_used: Option<RawRoleLastUsed>,
    pub description: Option<String>,
    #[serde(default)]
    pub tags: Vec<RawTag>,
    pub max_session_duration: Option<i32>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct RawRoleLastUsed {
    pub last_used_date: Option<DateTime<Utc>>,
    pub region: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct RawManagedPolicy {
    pub arn: String,
    pub policy_id: String,
    pub policy_name: String,
    pub path: String,
    pub create_date: DateTime<Utc>,
    pub update_date: DateTime<Utc>,
    pub attachment_count: i32,
    pub is_attachable: bool,
    pub default_version_id: String,
    pub description: Option<String>,
    #[serde(default)]
    pub policy_version_list: Vec<RawPolicyVersion>,
    #[serde(default)]
    pub tags: Vec<RawTag>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct RawPolicyVersion {
    pub document: Option<PolicyDocument>,
    pub is_default_version: bool,
    #[allow(dead_code)]
    pub version_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct RawInlinePolicy {
    pub policy_name: String,
    pub policy_document: PolicyDocument,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct RawTag {
    pub key: String,
    pub value: String,
}

// ---------------------------------------------------------------------------
// From impls — convert Raw types to iam-models public types
// ---------------------------------------------------------------------------

impl From<RawInlinePolicy> for IamInlinePolicy {
    fn from(raw: RawInlinePolicy) -> Self {
        Self {
            policy_name: raw.policy_name,
            policy_document: raw.policy_document,
        }
    }
}

impl From<RawUserDetail> for IamUser {
    fn from(raw: RawUserDetail) -> Self {
        let tags = raw.tags.into_iter().map(|t| (t.key, t.value)).collect();
        Self {
            arn: raw.arn,
            user_id: raw.user_id,
            user_name: raw.user_name,
            path: raw.path,
            create_date: raw.create_date,
            attached_managed_policies: raw.attached_managed_policies,
            inline_policies: raw
                .user_policy_list
                .into_iter()
                .map(IamInlinePolicy::from)
                .collect(),
            group_list: raw.group_list,
            permissions_boundary: raw.permissions_boundary,
            password_last_used: raw.password_last_used,
            access_keys: Vec::new(),
            is_aws_managed: false,
            tags,
        }
    }
}

impl From<RawGroupDetail> for IamGroup {
    fn from(raw: RawGroupDetail) -> Self {
        Self {
            arn: raw.arn,
            group_id: raw.group_id,
            group_name: raw.group_name,
            path: raw.path,
            create_date: raw.create_date,
            attached_managed_policies: raw.attached_managed_policies,
            inline_policies: raw
                .group_policy_list
                .into_iter()
                .map(IamInlinePolicy::from)
                .collect(),
        }
    }
}

impl From<RawRoleDetail> for IamRole {
    fn from(raw: RawRoleDetail) -> Self {
        let is_aws_managed = raw.path.starts_with("/aws-service-role/");
        let tags = raw.tags.into_iter().map(|t| (t.key, t.value)).collect();
        let role_last_used = raw.role_last_used.map(|r| RoleLastUsed {
            last_used_date: r.last_used_date,
            region: r.region,
        });
        Self {
            arn: raw.arn,
            role_id: raw.role_id,
            role_name: raw.role_name,
            path: raw.path,
            create_date: raw.create_date,
            assume_role_policy_document: raw.assume_role_policy_document,
            attached_managed_policies: raw.attached_managed_policies,
            inline_policies: raw
                .role_policy_list
                .into_iter()
                .map(IamInlinePolicy::from)
                .collect(),
            permissions_boundary: raw.permissions_boundary,
            role_last_used,
            description: raw.description,
            max_session_duration: raw.max_session_duration,
            is_aws_managed,
            tags,
        }
    }
}

impl From<RawManagedPolicy> for IamPolicy {
    fn from(raw: RawManagedPolicy) -> Self {
        let is_aws_managed = raw.arn.contains(":aws:policy/");
        let tags: HashMap<String, String> =
            raw.tags.into_iter().map(|t| (t.key, t.value)).collect();
        let document = raw
            .policy_version_list
            .into_iter()
            .find(|v| v.is_default_version)
            .and_then(|v| v.document);
        Self {
            arn: raw.arn,
            policy_id: raw.policy_id,
            policy_name: raw.policy_name,
            path: raw.path,
            create_date: raw.create_date,
            update_date: raw.update_date,
            attachment_count: raw.attachment_count,
            is_attachable: raw.is_attachable,
            default_version_id: raw.default_version_id,
            description: raw.description,
            is_aws_managed,
            document,
            tags,
        }
    }
}
