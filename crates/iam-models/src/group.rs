use crate::common::PolicyRef;
use crate::policy::IamInlinePolicy;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Raw types
// ---------------------------------------------------------------------------

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
    pub group_policy_list: Vec<crate::policy::RawInlinePolicy>,
}

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// An IAM group.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct IamGroup {
    /// Full ARN of the group.
    pub arn: String,
    /// Unique identifier (AGPA…).
    pub group_id: String,
    /// Human-readable name.
    pub group_name: String,
    /// Path in the IAM namespace.
    pub path: String,
    /// When the group was created.
    pub create_date: DateTime<Utc>,
    /// Managed policies attached to the group.
    #[serde(default)]
    pub attached_managed_policies: Vec<PolicyRef>,
    /// Inline policies embedded in the group.
    #[serde(default)]
    pub inline_policies: Vec<IamInlinePolicy>,
}

impl IamGroup {
    pub(crate) fn from_api(raw: RawGroupDetail) -> Self {
        let inline_policies = raw
            .group_policy_list
            .into_iter()
            .map(IamInlinePolicy::from)
            .collect();
        Self {
            arn: raw.arn,
            group_id: raw.group_id,
            group_name: raw.group_name,
            path: raw.path,
            create_date: raw.create_date,
            attached_managed_policies: raw.attached_managed_policies,
            inline_policies,
        }
    }

    /// Deserialize from AWS API JSON.
    pub fn from_json(s: &str) -> Result<Self, serde_json::Error> {
        let raw: RawGroupDetail = serde_json::from_str(s)?;
        Ok(Self::from_api(raw))
    }
}
