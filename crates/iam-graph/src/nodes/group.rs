use crate::nodes::uid::entity_uid;
use crate::nodes::Row;
use iam_models::IamGroup;

/// UNWIND-batched: MERGE a Group node per row.
pub const MERGE_GROUP: &str = "
    UNWIND $rows AS row
    MERGE (g:Group {uid: row.uid})
    SET g.arn = row.arn,
        g.group_id = row.group_id,
        g.name = row.name,
        g.path = row.path,
        g.create_date = row.create_date,
        g.account_id = row.account_id,
        g.snapshot_id = row.snapshot_id
";

/// Build a row for the `MERGE_GROUP` UNWIND statement.
pub fn group_row(snapshot_id: &str, account_id: &str, group: &IamGroup) -> Row {
    let uid = entity_uid(snapshot_id, &group.arn);
    Row::from([
        ("uid".to_string(), uid.into()),
        ("arn".to_string(), group.arn.clone().into()),
        ("group_id".to_string(), group.group_id.clone().into()),
        ("name".to_string(), group.group_name.clone().into()),
        ("path".to_string(), group.path.clone().into()),
        (
            "create_date".to_string(),
            group.create_date.to_rfc3339().into(),
        ),
        ("account_id".to_string(), account_id.into()),
        ("snapshot_id".to_string(), snapshot_id.into()),
    ])
}
