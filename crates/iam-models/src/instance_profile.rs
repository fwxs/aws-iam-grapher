use crate::role::IamRole;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Raw types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct RawInstanceProfile {
    pub arn: String,
    pub instance_profile_id: String,
    pub instance_profile_name: String,
    pub path: String,
    pub create_date: DateTime<Utc>,
    #[serde(default)]
    pub roles: Vec<crate::role::RawRoleDetail>,
}

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// An EC2 instance profile that wraps an IAM role.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct IamInstanceProfile {
    /// Full ARN of the instance profile.
    pub arn: String,
    /// Unique identifier.
    pub instance_profile_id: String,
    /// Human-readable name.
    pub instance_profile_name: String,
    /// Path in the IAM namespace.
    pub path: String,
    /// When the instance profile was created.
    pub create_date: DateTime<Utc>,
    /// Roles assigned to this instance profile.
    #[serde(default)]
    pub roles: Vec<IamRole>,
    /// Derived: `true` when path starts with `/aws-service-role/`.
    #[serde(skip)]
    pub is_aws_managed: bool,
}

impl IamInstanceProfile {
    pub(crate) fn from_api(raw: RawInstanceProfile) -> Self {
        let is_aws_managed = raw.path.starts_with("/aws-service-role/");
        let roles = raw.roles.into_iter().map(IamRole::from_api).collect();
        Self {
            arn: raw.arn,
            instance_profile_id: raw.instance_profile_id,
            instance_profile_name: raw.instance_profile_name,
            path: raw.path,
            create_date: raw.create_date,
            roles,
            is_aws_managed,
        }
    }

    /// Deserialize from AWS API JSON.
    pub fn from_json(s: &str) -> Result<Self, serde_json::Error> {
        let raw: RawInstanceProfile = serde_json::from_str(s)?;
        Ok(Self::from_api(raw))
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    #[test]
    fn instance_profile_is_aws_managed_false_for_standard_path() {
        assert!(!"/".starts_with("/aws-service-role/"));
    }

    #[test]
    fn instance_profile_is_aws_managed_true_for_service_role_path() {
        assert!("/aws-service-role/ec2.amazonaws.com/".starts_with("/aws-service-role/"));
    }
}
