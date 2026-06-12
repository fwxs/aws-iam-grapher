use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Allow or Deny effect for a policy statement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Effect {
    Allow,
    Deny,
}

/// Condition block in a policy statement.
/// Outer key: condition operator (e.g. `StringEquals`).
/// Inner key: condition key; value: list of values.
pub type Condition = HashMap<String, HashMap<String, Vec<String>>>;

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
