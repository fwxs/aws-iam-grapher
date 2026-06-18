use serde::{Deserialize, Deserializer, Serialize};
use std::collections::HashMap;
use std::fmt;

/// Allow or Deny effect for a policy statement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Effect {
    Allow,
    Deny,
}

/// Condition block in a policy statement.
/// Outer key: condition operator (e.g. `StringEquals`).
/// Inner key: condition key; value: list of values.
pub type Condition = HashMap<String, HashMap<String, ConditionValues>>;

/// Values for a single condition key. AWS accepts either a bare string
/// (e.g. `"aws:PrincipalTag/role": "AdminAccess"`) or an array of strings
/// for the same position, so this deserializes either shape into a `Vec<String>`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct ConditionValues(pub Vec<String>);

impl<'de> Deserialize<'de> for ConditionValues {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::{SeqAccess, Visitor};

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

        deserializer
            .deserialize_any(StringOrVec)
            .map(ConditionValues)
    }
}

/// Reference to an attached managed policy (ARN + name).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct PolicyRef {
    /// ARN of the attached policy.
    pub policy_arn: String,
    /// Display name of the attached policy.
    pub policy_name: String,
}

/// Permissions boundary applied to a principal.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct PermissionsBoundary {
    /// Type of boundary: `PermissionsBoundaryPolicy`.
    pub permissions_boundary_type: String,
    /// ARN of the policy used as the boundary.
    pub permissions_boundary_arn: String,
}
