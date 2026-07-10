use crate::nodes::uid::{excluded_permission_uid, permission_uid};
use iam_models::Condition;
use neo4rs::{query, Query};

const MERGE_AWS_SERVICE: &str = "
    MERGE (svc:AwsService {prefix: $prefix})
    ON CREATE SET svc.name = $name
";

const MERGE_PERMISSION: &str = "
    MERGE (perm:Permission {uid: $uid})
    SET perm.action = $action,
        perm.resource = $resource,
        perm.effect = $effect,
        perm.account_id = $account_id,
        perm.snapshot_id = $snapshot_id,
        perm.condition = $condition
";

const PERMISSION_ON_SERVICE: &str = "
    MATCH (perm:Permission {uid: $uid})
    MATCH (svc:AwsService {prefix: $prefix})
    MERGE (perm)-[:ON_SERVICE]->(svc)
";

const MERGE_EXCLUDED_PERMISSION: &str = "
    MERGE (perm:Permission {uid: $uid})
    SET perm.action = '*',
        perm.resource = $resource,
        perm.effect = $effect,
        perm.account_id = $account_id,
        perm.snapshot_id = $snapshot_id,
        perm.excluded_actions = $excluded_actions,
        perm.condition = $condition
";

/// Build a query to MERGE an AwsService node.
pub fn merge_aws_service_query(prefix: &str) -> Query {
    let name = service_name_from_prefix(prefix);
    query(MERGE_AWS_SERVICE)
        .param("prefix", prefix)
        .param("name", name)
}

/// Build a query to MERGE a Permission node.
///
/// `condition` (if present and non-empty) is stored as a JSON string on `perm.condition`
/// so query-time evaluators (see `iam_models::condition`) can read it back and flag
/// gated grants instead of treating them as unconditional.
pub fn merge_permission_query(
    snapshot_id: &str,
    account_id: &str,
    effect: &str,
    action: &str,
    resource: &str,
    condition: Option<&Condition>,
) -> Query {
    let uid = permission_uid(snapshot_id, effect, action, resource, condition);
    query(MERGE_PERMISSION)
        .param("uid", uid)
        .param("action", action)
        .param("resource", resource)
        .param("effect", effect)
        .param("account_id", account_id)
        .param("snapshot_id", snapshot_id)
        .param("condition", condition_json(condition))
}

/// Build a query to MERGE an allow-all-except Permission node (from a `NotAction` statement).
///
/// The node stores `action = '*'` with an `excluded_actions` list. `who_can` matches it for
/// any queried action that is NOT in `excluded_actions`. No `ON_SERVICE` edge — the `*`
/// action belongs to no single service prefix.
pub fn merge_excluded_permission_query(
    snapshot_id: &str,
    account_id: &str,
    effect: &str,
    resource: &str,
    excluded: &[String],
    condition: Option<&Condition>,
) -> Query {
    let uid = excluded_permission_uid(snapshot_id, effect, resource, excluded, condition);
    query(MERGE_EXCLUDED_PERMISSION)
        .param("uid", uid)
        .param("resource", resource)
        .param("effect", effect)
        .param("account_id", account_id)
        .param("snapshot_id", snapshot_id)
        .param("excluded_actions", excluded.to_vec())
        .param("condition", condition_json(condition))
}

/// Build a query to link a Permission to its AwsService.
pub fn permission_on_service_query(
    snapshot_id: &str,
    effect: &str,
    action: &str,
    resource: &str,
    prefix: &str,
    condition: Option<&Condition>,
) -> Query {
    let uid = permission_uid(snapshot_id, effect, action, resource, condition);
    query(PERMISSION_ON_SERVICE)
        .param("uid", uid)
        .param("prefix", prefix)
}

/// Serialize a `Condition` block to a JSON string for storage, or `None` if absent/empty.
fn condition_json(condition: Option<&Condition>) -> Option<String> {
    condition
        .filter(|c| !c.is_empty())
        .map(|c| serde_json::to_string(c).expect("Condition serializes to JSON"))
}

/// Extract the service prefix from an IAM action (e.g. `s3:GetObject` → `s3`).
pub fn service_prefix(action: &str) -> &str {
    action.split(':').next().unwrap_or(action)
}

fn service_name_from_prefix(prefix: &str) -> String {
    // Best-effort human-readable name from well-known prefixes.
    match prefix {
        "s3" => "Amazon S3".to_string(),
        "iam" => "AWS IAM".to_string(),
        "ec2" => "Amazon EC2".to_string(),
        "sts" => "AWS STS".to_string(),
        "lambda" => "AWS Lambda".to_string(),
        "glue" => "AWS Glue".to_string(),
        "rds" => "Amazon RDS".to_string(),
        "dynamodb" => "Amazon DynamoDB".to_string(),
        other => other.to_string(),
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_prefix_extracts_prefix() {
        assert_eq!(service_prefix("s3:GetObject"), "s3");
        assert_eq!(service_prefix("iam:PassRole"), "iam");
        assert_eq!(service_prefix("ec2:DescribeInstances"), "ec2");
    }

    #[test]
    fn service_prefix_handles_no_colon() {
        assert_eq!(service_prefix("*"), "*");
        assert_eq!(service_prefix("s3"), "s3");
    }
}
