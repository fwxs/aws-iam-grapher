use crate::nodes::uid::{excluded_permission_uid, permission_uid};
use crate::nodes::Row;
use iam_models::Condition;
use neo4rs::{query, Query};

const MERGE_AWS_SERVICE: &str = "
    MERGE (svc:AwsService {prefix: $prefix})
    ON CREATE SET svc.name = $name
";

/// UNWIND-batched: MERGE a Permission node per row.
pub const MERGE_PERMISSION: &str = "
    UNWIND $rows AS row
    MERGE (perm:Permission {uid: row.uid})
    SET perm.action = row.action,
        perm.resource = row.resource,
        perm.effect = row.effect,
        perm.account_id = row.account_id,
        perm.snapshot_id = row.snapshot_id,
        perm.condition = row.condition
";

/// UNWIND-batched: link a Permission to its AwsService per row.
pub const PERMISSION_ON_SERVICE: &str = "
    UNWIND $rows AS row
    MATCH (perm:Permission {uid: row.uid})
    MATCH (svc:AwsService {prefix: row.prefix})
    MERGE (perm)-[:ON_SERVICE]->(svc)
";

/// UNWIND-batched: MERGE an allow-all-except Permission node per row.
pub const MERGE_EXCLUDED_PERMISSION: &str = "
    UNWIND $rows AS row
    MERGE (perm:Permission {uid: row.uid})
    SET perm.action = '*',
        perm.resource = row.resource,
        perm.effect = row.effect,
        perm.account_id = row.account_id,
        perm.snapshot_id = row.snapshot_id,
        perm.excluded_actions = row.excluded_actions,
        perm.condition = row.condition
";

/// Build a query to MERGE an AwsService node.
pub fn merge_aws_service_query(prefix: &str) -> Query {
    let name = service_name_from_prefix(prefix);
    query(MERGE_AWS_SERVICE)
        .param("prefix", prefix)
        .param("name", name)
}

/// Build a row for the `MERGE_PERMISSION` UNWIND statement.
///
/// `condition` (if present and non-empty) is stored as a JSON string on `perm.condition`
/// so query-time evaluators (see `iam_models::condition`) can read it back and flag
/// gated grants instead of treating them as unconditional.
pub fn permission_row(
    snapshot_id: &str,
    account_id: &str,
    effect: &str,
    action: &str,
    resource: &str,
    condition: Option<&Condition>,
) -> Row {
    let uid = permission_uid(snapshot_id, effect, action, resource, condition);
    Row::from([
        ("uid".to_string(), uid.into()),
        ("action".to_string(), action.into()),
        ("resource".to_string(), resource.into()),
        ("effect".to_string(), effect.into()),
        ("account_id".to_string(), account_id.into()),
        ("snapshot_id".to_string(), snapshot_id.into()),
        ("condition".to_string(), condition_json(condition).into()),
    ])
}

/// Build a row for the `MERGE_EXCLUDED_PERMISSION` UNWIND statement (from a
/// `NotAction` statement).
///
/// The node stores `action = '*'` with an `excluded_actions` list. `who_can` matches it for
/// any queried action that is NOT in `excluded_actions`. No `ON_SERVICE` edge — the `*`
/// action belongs to no single service prefix.
pub fn excluded_permission_row(
    snapshot_id: &str,
    account_id: &str,
    effect: &str,
    resource: &str,
    excluded: &[String],
    condition: Option<&Condition>,
) -> Row {
    let uid = excluded_permission_uid(snapshot_id, effect, resource, excluded, condition);
    Row::from([
        ("uid".to_string(), uid.into()),
        ("resource".to_string(), resource.into()),
        ("effect".to_string(), effect.into()),
        ("account_id".to_string(), account_id.into()),
        ("snapshot_id".to_string(), snapshot_id.into()),
        ("excluded_actions".to_string(), excluded.to_vec().into()),
        ("condition".to_string(), condition_json(condition).into()),
    ])
}

/// Build a row for the `PERMISSION_ON_SERVICE` UNWIND statement.
pub fn permission_on_service_row(
    snapshot_id: &str,
    effect: &str,
    action: &str,
    resource: &str,
    prefix: &str,
    condition: Option<&Condition>,
) -> Row {
    let uid = permission_uid(snapshot_id, effect, action, resource, condition);
    Row::from([
        ("uid".to_string(), uid.into()),
        ("prefix".to_string(), prefix.into()),
    ])
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
