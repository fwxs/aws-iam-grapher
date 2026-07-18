use crate::nodes::uid::entity_uid;
use crate::nodes::Row;
use iam_models::IamRole;

/// UNWIND-batched: MERGE a Role node per row.
pub const MERGE_ROLE: &str = "
    UNWIND $rows AS row
    MERGE (r:Role {uid: row.uid})
    SET r.arn = row.arn,
        r.role_id = row.role_id,
        r.name = row.name,
        r.path = row.path,
        r.is_aws_managed = row.is_aws_managed,
        r.description = row.description,
        r.create_date = row.create_date,
        r.last_used_date = row.last_used_date,
        r.last_used_region = row.last_used_region,
        r.account_id = row.account_id,
        r.snapshot_id = row.snapshot_id
";

/// Build a row for the `MERGE_ROLE` UNWIND statement.
pub fn role_row(snapshot_id: &str, account_id: &str, role: &IamRole) -> Row {
    let uid = entity_uid(snapshot_id, &role.arn);
    let last_used_date = role
        .role_last_used
        .as_ref()
        .and_then(|r| r.last_used_date)
        .map(|d| d.to_rfc3339())
        .unwrap_or_default();
    let last_used_region = role
        .role_last_used
        .as_ref()
        .and_then(|r| r.region.clone())
        .unwrap_or_default();
    Row::from([
        ("uid".to_string(), uid.into()),
        ("arn".to_string(), role.arn.clone().into()),
        ("role_id".to_string(), role.role_id.clone().into()),
        ("name".to_string(), role.role_name.clone().into()),
        ("path".to_string(), role.path.clone().into()),
        ("is_aws_managed".to_string(), role.is_aws_managed.into()),
        (
            "description".to_string(),
            role.description.clone().unwrap_or_default().into(),
        ),
        (
            "create_date".to_string(),
            role.create_date.to_rfc3339().into(),
        ),
        ("last_used_date".to_string(), last_used_date.into()),
        ("last_used_region".to_string(), last_used_region.into()),
        ("account_id".to_string(), account_id.into()),
        ("snapshot_id".to_string(), snapshot_id.into()),
    ])
}
