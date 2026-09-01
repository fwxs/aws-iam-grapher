use crate::nodes::Row;
use iam_models::Condition;

/// UNWIND-batched: MERGE an AwsService node per row.
pub const MERGE_AWS_SERVICE: &str = "
    UNWIND $rows AS row
    MERGE (svc:AwsService {prefix: row.prefix})
    ON CREATE SET svc.name = row.name
";

/// UNWIND-batched: MERGE a Permission node per row. Global, action-keyed vocabulary node —
/// no snapshot_id/account_id/effect/resource/condition; those live on the `GRANTS` edge.
pub const MERGE_PERMISSION: &str = "
    UNWIND $rows AS row
    MERGE (perm:Permission {action: row.action})
";

/// UNWIND-batched: link a Permission to its AwsService per row. One-time-per-action —
/// no longer recomputed per snapshot/statement.
pub const PERMISSION_ON_SERVICE: &str = "
    UNWIND $rows AS row
    MATCH (perm:Permission {action: row.action})
    MATCH (svc:AwsService {prefix: row.prefix})
    MERGE (perm)-[:ON_SERVICE]->(svc)
";

/// Build a row for the `MERGE_AWS_SERVICE` UNWIND statement.
pub fn aws_service_row(prefix: &str) -> Row {
    let name = service_name_from_prefix(prefix);
    Row::from([
        ("prefix".to_string(), prefix.into()),
        ("name".to_string(), name.into()),
    ])
}

/// Build a row for the `MERGE_PERMISSION` UNWIND statement.
pub fn permission_row(action: &str) -> Row {
    Row::from([("action".to_string(), action.into())])
}

/// Build a row for the `PERMISSION_ON_SERVICE` UNWIND statement.
pub fn permission_on_service_row(action: &str, prefix: &str) -> Row {
    Row::from([
        ("action".to_string(), action.into()),
        ("prefix".to_string(), prefix.into()),
    ])
}

/// Serialize a `Condition` block to a JSON string for storage, or `None` if absent/empty.
///
/// Used by `relationships.rs`'s `GRANTS`-edge row builders now that `condition` lives on
/// the edge rather than the `Permission` node.
pub(crate) fn condition_json(condition: Option<&Condition>) -> Option<String> {
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
