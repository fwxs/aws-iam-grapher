use crate::common::{Condition, Effect};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer, Serialize};
use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Raw types — reflect AWS API JSON exactly, not part of public API
// ---------------------------------------------------------------------------

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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default)]
    pub tags: Vec<RawTag>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct RawTag {
    pub key: String,
    pub value: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct RawInlinePolicy {
    pub policy_name: String,
    pub policy_document: PolicyDocument,
}

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// AWS managed or customer-managed IAM policy (has its own ARN).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct IamPolicy {
    /// Full ARN of the policy.
    pub arn: String,
    /// Unique identifier (ANPA…).
    pub policy_id: String,
    /// Human-readable name.
    pub policy_name: String,
    /// Path in the IAM namespace.
    pub path: String,
    /// When the policy was created.
    pub create_date: DateTime<Utc>,
    /// When the policy was last updated.
    pub update_date: DateTime<Utc>,
    /// Number of principals this policy is attached to.
    pub attachment_count: i32,
    /// Whether the policy can be attached to principals.
    pub is_attachable: bool,
    /// Default version ID (e.g. `v1`).
    pub default_version_id: String,
    /// Optional description set by creator.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Derived: `true` when ARN contains `::aws:policy/`.
    #[serde(skip)]
    pub is_aws_managed: bool,
    /// Embedded policy document (populated when fetching full policy detail).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub document: Option<PolicyDocument>,
    /// Tags attached to the policy.
    #[serde(default)]
    pub tags: HashMap<String, String>,
}

impl IamPolicy {
    /// Construct from a raw API response, deriving computed fields.
    pub(crate) fn from_api(raw: RawManagedPolicy) -> Self {
        let is_aws_managed = raw.arn.contains(":aws:policy/");
        let tags = raw.tags.into_iter().map(|t| (t.key, t.value)).collect();
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
            document: None,
            tags,
        }
    }

    /// Deserialize from AWS API JSON, deriving computed fields.
    ///
    /// Deserialize from AWS API JSON, deriving computed fields.
    pub fn from_json(s: &str) -> Result<Self, serde_json::Error> {
        let raw: RawManagedPolicy = serde_json::from_str(s)?;
        Ok(Self::from_api(raw))
    }
}

/// Inline policy embedded directly in a role/user/group (no ARN).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct IamInlinePolicy {
    /// Name of the inline policy.
    pub policy_name: String,
    /// The policy document.
    pub policy_document: PolicyDocument,
}

impl From<RawInlinePolicy> for IamInlinePolicy {
    fn from(raw: RawInlinePolicy) -> Self {
        Self {
            policy_name: raw.policy_name,
            policy_document: raw.policy_document,
        }
    }
}

/// IAM policy document containing one or more statements.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct PolicyDocument {
    /// Policy language version (typically `"2012-10-17"`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// List of policy statements.
    pub statement: Vec<PolicyStatement>,
}

/// A single statement within a policy document.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct PolicyStatement {
    /// Optional identifier for the statement.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sid: Option<String>,
    /// Allow or Deny.
    pub effect: Effect,
    /// Actions this statement applies to (normalized from string-or-array).
    #[serde(default, deserialize_with = "deserialize_string_or_vec_opt")]
    pub action: Vec<String>,
    /// Actions this statement explicitly excludes.
    #[serde(default, deserialize_with = "deserialize_string_or_vec_opt")]
    pub not_action: Vec<String>,
    /// Resources this statement applies to.
    #[serde(default, deserialize_with = "deserialize_string_or_vec_opt")]
    pub resource: Vec<String>,
    /// Resources this statement explicitly excludes.
    #[serde(default, deserialize_with = "deserialize_string_or_vec_opt")]
    pub not_resource: Vec<String>,
    /// Optional principal block.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub principal: Option<serde_json::Value>,
    /// Optional NotPrincipal block.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_principal: Option<serde_json::Value>,
    /// Optional condition block.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub condition: Option<Condition>,
}

/// Convenience alias matching the milestone spec field name.
impl PolicyStatement {
    /// All explicit actions (same as `action` field).
    pub fn actions(&self) -> &[String] {
        &self.action
    }
    /// All explicit not-actions (same as `not_action` field).
    pub fn not_actions(&self) -> &[String] {
        &self.not_action
    }
}

// ---------------------------------------------------------------------------
// Custom deserializer: accepts a JSON string or array and returns Vec<String>.
// Missing field → empty Vec.
// ---------------------------------------------------------------------------

fn deserialize_string_or_vec_opt<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::{SeqAccess, Visitor};
    use std::fmt;

    struct StringOrVec;

    impl<'de> Visitor<'de> for StringOrVec {
        type Value = Vec<String>;

        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("string or array of strings")
        }

        fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Self::Value, E> {
            Ok(vec![v.to_owned()])
        }

        fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
            let mut out = Vec::new();
            while let Some(item) = seq.next_element::<String>()? {
                out.push(item);
            }
            Ok(out)
        }
    }

    deserializer.deserialize_any(StringOrVec)
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_statement_normalizes_single_action_string_to_vec() {
        let json = r#"{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}"#;
        let stmt: PolicyStatement = serde_json::from_str(json).unwrap();
        assert_eq!(stmt.action, vec!["s3:GetObject"]);
    }

    #[test]
    fn policy_statement_accepts_action_array() {
        let json = r#"{"Effect":"Allow","Action":["s3:GetObject","s3:PutObject"],"Resource":"*"}"#;
        let stmt: PolicyStatement = serde_json::from_str(json).unwrap();
        assert_eq!(stmt.action.len(), 2);
    }

    #[test]
    fn policy_statement_handles_notaction() {
        let json = r#"{"Effect":"Deny","NotAction":"sts:AssumeRole","Resource":"*"}"#;
        let stmt: PolicyStatement = serde_json::from_str(json).unwrap();
        assert!(stmt.action.is_empty());
        assert_eq!(stmt.not_action, vec!["sts:AssumeRole"]);
    }

    #[test]
    fn policy_statement_missing_optional_fields_deserializes_ok() {
        let json = r#"{"Effect":"Allow","Action":"*","Resource":"*"}"#;
        let stmt: PolicyStatement = serde_json::from_str(json).unwrap();
        assert!(stmt.sid.is_none());
        assert!(stmt.condition.is_none());
        assert!(stmt.principal.is_none());
        assert!(stmt.not_action.is_empty());
        assert!(stmt.not_resource.is_empty());
    }

    #[test]
    fn iam_policy_derives_is_aws_managed_from_arn() {
        let aws_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess";
        let customer_arn = "arn:aws:iam::123456789012:policy/MyPolicy";
        assert!(aws_arn.contains(":aws:policy/"));
        assert!(!customer_arn.contains(":aws:policy/"));
    }
}
