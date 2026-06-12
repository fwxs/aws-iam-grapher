use crate::common::{PermissionsBoundary, PolicyRef};
use crate::policy::{IamInlinePolicy, PolicyDocument, RawInlinePolicy};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Raw types
// ---------------------------------------------------------------------------

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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default)]
    pub tags: Vec<RawTag>,
    #[serde(skip_serializing_if = "Option::is_none")]
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
pub(crate) struct RawTag {
    pub key: String,
    pub value: String,
}

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// When and where this role was last used.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoleLastUsed {
    /// Timestamp of last use.
    pub last_used_date: Option<DateTime<Utc>>,
    /// AWS region where the role was last used.
    pub region: Option<String>,
}

/// An IAM role.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct IamRole {
    /// Full ARN of the role.
    pub arn: String,
    /// Unique identifier (AROA…).
    pub role_id: String,
    /// Human-readable name.
    pub role_name: String,
    /// Path in the IAM namespace.
    pub path: String,
    /// When the role was created.
    pub create_date: DateTime<Utc>,
    /// The trust policy (who can assume this role).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub assume_role_policy_document: Option<PolicyDocument>,
    /// Managed policies attached to the role.
    #[serde(default)]
    pub attached_managed_policies: Vec<PolicyRef>,
    /// Inline policies embedded in the role.
    #[serde(default)]
    pub inline_policies: Vec<IamInlinePolicy>,
    /// Permissions boundary, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub permissions_boundary: Option<PermissionsBoundary>,
    /// When/where the role was last used.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role_last_used: Option<RoleLastUsed>,
    /// Optional description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Maximum session duration in seconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_session_duration: Option<i32>,
    /// Derived: `true` when path starts with `/aws-service-role/`.
    #[serde(skip)]
    pub is_aws_managed: bool,
    /// Tags attached to the role.
    #[serde(default)]
    pub tags: HashMap<String, String>,
}

impl IamRole {
    /// Construct from a raw API response, deriving computed fields.
    pub(crate) fn from_api(raw: RawRoleDetail) -> Self {
        let is_aws_managed = raw.path.starts_with("/aws-service-role/");
        let tags = raw.tags.into_iter().map(|t| (t.key, t.value)).collect();
        let inline_policies = raw
            .role_policy_list
            .into_iter()
            .map(IamInlinePolicy::from)
            .collect();
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
            inline_policies,
            permissions_boundary: raw.permissions_boundary,
            role_last_used,
            description: raw.description,
            max_session_duration: raw.max_session_duration,
            is_aws_managed,
            tags,
        }
    }

    /// Deserialize from AWS IAM `get-account-authorization-details` JSON.
    pub fn from_json(s: &str) -> Result<Self, serde_json::Error> {
        let raw: RawRoleDetail = serde_json::from_str(s)?;
        Ok(Self::from_api(raw))
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {

    #[test]
    fn is_aws_managed_true_for_service_role_path() {
        assert!("/aws-service-role/elasticloadbalancing.amazonaws.com/"
            .starts_with("/aws-service-role/"));
    }

    #[test]
    fn is_aws_managed_false_for_customer_path() {
        assert!(!"/".starts_with("/aws-service-role/"));
        assert!(!"/engineering/".starts_with("/aws-service-role/"));
    }
}
