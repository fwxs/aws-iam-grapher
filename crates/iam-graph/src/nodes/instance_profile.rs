use crate::nodes::uid::entity_uid;
use crate::nodes::Row;
use iam_models::IamInstanceProfile;

/// UNWIND-batched: MERGE an InstanceProfile node per row.
pub const MERGE_INSTANCE_PROFILE: &str = "
    UNWIND $rows AS row
    MERGE (ip:InstanceProfile {uid: row.uid})
    SET ip.arn = row.arn,
        ip.instance_profile_id = row.instance_profile_id,
        ip.name = row.name,
        ip.path = row.path,
        ip.is_aws_managed = row.is_aws_managed,
        ip.create_date = row.create_date,
        ip.account_id = row.account_id,
        ip.snapshot_id = row.snapshot_id
";

/// Build a row for the `MERGE_INSTANCE_PROFILE` UNWIND statement.
pub fn instance_profile_row(
    snapshot_id: &str,
    account_id: &str,
    profile: &IamInstanceProfile,
) -> Row {
    let uid = entity_uid(snapshot_id, &profile.arn);
    Row::from([
        ("uid".to_string(), uid.into()),
        ("arn".to_string(), profile.arn.clone().into()),
        (
            "instance_profile_id".to_string(),
            profile.instance_profile_id.clone().into(),
        ),
        (
            "name".to_string(),
            profile.instance_profile_name.clone().into(),
        ),
        ("path".to_string(), profile.path.clone().into()),
        ("is_aws_managed".to_string(), profile.is_aws_managed.into()),
        (
            "create_date".to_string(),
            profile.create_date.to_rfc3339().into(),
        ),
        ("account_id".to_string(), account_id.into()),
        ("snapshot_id".to_string(), snapshot_id.into()),
    ])
}
