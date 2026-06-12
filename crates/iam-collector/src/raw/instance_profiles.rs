use crate::raw::auth_details::RawRoleDetail;
use chrono::{DateTime, Utc};
use iam_models::IamInstanceProfile;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct ListInstanceProfilesResponse {
    #[serde(default)]
    pub instance_profiles: Vec<RawInstanceProfile>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct RawInstanceProfile {
    pub arn: String,
    pub instance_profile_id: String,
    pub instance_profile_name: String,
    pub path: String,
    pub create_date: DateTime<Utc>,
    #[serde(default)]
    pub roles: Vec<RawRoleDetail>,
}

impl From<RawInstanceProfile> for IamInstanceProfile {
    fn from(raw: RawInstanceProfile) -> Self {
        let is_aws_managed = raw.path.starts_with("/aws-service-role/");
        let roles = raw
            .roles
            .into_iter()
            .map(iam_models::IamRole::from)
            .collect();
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
}
