use crate::nodes::uid::entity_uid;
use iam_models::IamGroup;
use neo4rs::{query, Query};

const MERGE_GROUP: &str = "
    MERGE (g:Group {uid: $uid})
    SET g.arn = $arn,
        g.group_id = $group_id,
        g.name = $name,
        g.path = $path,
        g.create_date = $create_date,
        g.account_id = $account_id,
        g.snapshot_id = $snapshot_id
";

/// Build a query to MERGE a Group node.
pub fn merge_group_query(snapshot_id: &str, account_id: &str, group: &IamGroup) -> Query {
    let uid = entity_uid(snapshot_id, &group.arn);
    query(MERGE_GROUP)
        .param("uid", uid)
        .param("arn", group.arn.clone())
        .param("group_id", group.group_id.clone())
        .param("name", group.group_name.clone())
        .param("path", group.path.clone())
        .param("create_date", group.create_date.to_rfc3339())
        .param("account_id", account_id)
        .param("snapshot_id", snapshot_id)
}
