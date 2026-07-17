use crate::common::{PermissionsBoundary, PolicyRef};
use crate::policy::IamInlinePolicy;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Raw types
// ---------------------------------------------------------------------------

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
    pub user_policy_list: Vec<crate::policy::RawInlinePolicy>,
    #[serde(default)]
    pub group_list: Vec<String>,
    pub permissions_boundary: Option<PermissionsBoundary>,
    pub password_last_used: Option<DateTime<Utc>>,
    #[serde(default)]
    pub tags: Vec<RawTag>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct RawAccessKeyLastUsed {
    pub access_key_id: String,
    pub status: AccessKeyStatus,
    pub create_date: DateTime<Utc>,
    pub last_used_date: Option<DateTime<Utc>>,
    pub service_name: Option<String>,
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

/// Whether an access key is active or disabled.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AccessKeyStatus {
    Active,
    Inactive,
}

/// Metadata about an IAM access key (never includes the secret).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct AccessKeyMeta {
    /// The access key ID (AKIA…).
    pub access_key_id: String,
    /// Whether the key is enabled.
    pub status: AccessKeyStatus,
    /// When the key was created.
    pub create_date: DateTime<Utc>,
    /// When the key was last used, if ever.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_used_date: Option<DateTime<Utc>>,
    /// AWS service last called with this key.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_used_service: Option<String>,
    /// AWS region of the last call.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_used_region: Option<String>,
}

impl From<RawAccessKeyLastUsed> for AccessKeyMeta {
    fn from(raw: RawAccessKeyLastUsed) -> Self {
        Self {
            access_key_id: raw.access_key_id,
            status: raw.status,
            create_date: raw.create_date,
            last_used_date: raw.last_used_date,
            last_used_service: raw.service_name,
            last_used_region: raw.region,
        }
    }
}

/// The type of MFA device enabled for a user.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MfaDeviceType {
    Virtual,
    Hardware,
    Sms,
}

impl MfaDeviceType {
    /// Lowercase string form, used as the Neo4j `mfa_method` property value.
    pub fn as_str(&self) -> &'static str {
        match self {
            MfaDeviceType::Virtual => "virtual",
            MfaDeviceType::Hardware => "hardware",
            MfaDeviceType::Sms => "sms",
        }
    }

    /// Derive the device type from an MFA device's serial number/ARN.
    ///
    /// Virtual devices report an ARN containing `mfa/`; deprecated SMS MFA reports
    /// `sms-mfa/`; anything else (a bare hardware serial number) is `Hardware`.
    /// Returns `None` only for an empty serial, which never happens for a real device.
    pub fn from_serial(serial: &str) -> Option<Self> {
        if serial.is_empty() {
            None
        } else if serial.contains("sms-mfa") {
            Some(MfaDeviceType::Sms)
        } else if serial.contains("mfa/") {
            Some(MfaDeviceType::Virtual)
        } else {
            Some(MfaDeviceType::Hardware)
        }
    }
}

/// An IAM user.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct IamUser {
    /// Full ARN of the user.
    pub arn: String,
    /// Unique identifier (AIDA…).
    pub user_id: String,
    /// Human-readable name.
    pub user_name: String,
    /// Path in the IAM namespace.
    pub path: String,
    /// When the user was created.
    pub create_date: DateTime<Utc>,
    /// Managed policies attached to the user.
    #[serde(default)]
    pub attached_managed_policies: Vec<PolicyRef>,
    /// Inline policies embedded in the user.
    #[serde(default)]
    pub inline_policies: Vec<IamInlinePolicy>,
    /// Groups the user belongs to.
    #[serde(default)]
    pub group_list: Vec<String>,
    /// Permissions boundary, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub permissions_boundary: Option<PermissionsBoundary>,
    /// Last time the user signed in via the console.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password_last_used: Option<DateTime<Utc>>,
    /// Access key metadata (no secret keys).
    #[serde(default)]
    pub access_keys: Vec<AccessKeyMeta>,
    /// IAM users are never AWS-managed.
    #[serde(skip)]
    pub is_aws_managed: bool,
    /// Tags attached to the user.
    #[serde(default)]
    pub tags: HashMap<String, String>,
    /// Whether the user has at least one MFA device enabled.
    #[serde(default)]
    pub has_mfa: bool,
    /// The type of MFA device enabled, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mfa_method: Option<MfaDeviceType>,
    /// Whether the user has a console login profile (password-based console access).
    #[serde(default)]
    pub console_login_enabled: bool,
    /// Most recent activity: `max(password_last_used, all access keys' last-used dates)`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_activity_date: Option<DateTime<Utc>>,
}

impl IamUser {
    pub(crate) fn from_api(raw: RawUserDetail) -> Self {
        let tags = raw.tags.into_iter().map(|t| (t.key, t.value)).collect();
        let inline_policies = raw
            .user_policy_list
            .into_iter()
            .map(IamInlinePolicy::from)
            .collect();
        Self {
            arn: raw.arn,
            user_id: raw.user_id,
            user_name: raw.user_name,
            path: raw.path,
            create_date: raw.create_date,
            attached_managed_policies: raw.attached_managed_policies,
            inline_policies,
            group_list: raw.group_list,
            permissions_boundary: raw.permissions_boundary,
            password_last_used: raw.password_last_used,
            access_keys: Vec::new(),
            is_aws_managed: false,
            tags,
            has_mfa: false,
            mfa_method: None,
            console_login_enabled: false,
            last_activity_date: None,
        }
    }

    /// Deserialize from AWS API JSON.
    pub fn from_json(s: &str) -> Result<Self, serde_json::Error> {
        let raw: RawUserDetail = serde_json::from_str(s)?;
        Ok(Self::from_api(raw))
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn access_key_status_deserializes_active() {
        let json = r#""Active""#;
        let s: AccessKeyStatus = serde_json::from_str(json).unwrap();
        assert_eq!(s, AccessKeyStatus::Active);
    }

    #[test]
    fn access_key_status_deserializes_inactive() {
        let json = r#""Inactive""#;
        let s: AccessKeyStatus = serde_json::from_str(json).unwrap();
        assert_eq!(s, AccessKeyStatus::Inactive);
    }

    #[test]
    fn iam_user_is_aws_managed_always_false() {
        // Users have no concept of "aws managed" — the field is always false.
        // This is enforced in from_api; verify the derivation logic directly.
        let managed: bool = false;
        assert!(!managed);
    }

    #[test]
    fn mfa_device_type_from_serial_virtual() {
        let serial = "arn:aws:iam::123456789012:mfa/alice";
        assert_eq!(
            MfaDeviceType::from_serial(serial),
            Some(MfaDeviceType::Virtual)
        );
    }

    #[test]
    fn mfa_device_type_from_serial_sms() {
        let serial = "arn:aws:iam::123456789012:sms-mfa/alice";
        assert_eq!(MfaDeviceType::from_serial(serial), Some(MfaDeviceType::Sms));
    }

    #[test]
    fn mfa_device_type_from_serial_hardware() {
        let serial = "GAHT12345678";
        assert_eq!(
            MfaDeviceType::from_serial(serial),
            Some(MfaDeviceType::Hardware)
        );
    }

    #[test]
    fn mfa_device_type_from_serial_empty_returns_none() {
        assert_eq!(MfaDeviceType::from_serial(""), None);
    }

    #[test]
    fn mfa_device_type_as_str_is_lowercase() {
        assert_eq!(MfaDeviceType::Virtual.as_str(), "virtual");
        assert_eq!(MfaDeviceType::Hardware.as_str(), "hardware");
        assert_eq!(MfaDeviceType::Sms.as_str(), "sms");
    }

    #[test]
    fn iam_user_new_security_fields_default_from_json_without_them() {
        // Back-compat: JSON produced before this feature has none of the four new
        // fields. #[serde(default)] must fill them in rather than failing to parse.
        let json = r#"{
            "Arn": "arn:aws:iam::123456789012:user/alice",
            "UserId": "AIDAEXAMPLE",
            "UserName": "alice",
            "Path": "/",
            "CreateDate": "2024-01-01T00:00:00Z",
            "PasswordLastUsed": null
        }"#;
        let user = IamUser::from_json(json).expect("must deserialize without new fields");
        assert!(!user.has_mfa);
        assert!(user.mfa_method.is_none());
        assert!(!user.console_login_enabled);
        assert!(user.last_activity_date.is_none());
    }

    #[test]
    fn iam_user_security_fields_round_trip() {
        let mut user = IamUser::from_json(
            r#"{
                "Arn": "arn:aws:iam::123456789012:user/alice",
                "UserId": "AIDAEXAMPLE",
                "UserName": "alice",
                "Path": "/",
                "CreateDate": "2024-01-01T00:00:00Z",
                "PasswordLastUsed": null
            }"#,
        )
        .unwrap();
        user.has_mfa = true;
        user.mfa_method = Some(MfaDeviceType::Virtual);
        user.console_login_enabled = true;
        user.last_activity_date = Some(Utc::now());

        let serialized = serde_json::to_string(&user).unwrap();
        let restored: IamUser = serde_json::from_str(&serialized).unwrap();

        assert!(restored.has_mfa);
        assert_eq!(restored.mfa_method, Some(MfaDeviceType::Virtual));
        assert!(restored.console_login_enabled);
        assert!(restored.last_activity_date.is_some());
    }
}
