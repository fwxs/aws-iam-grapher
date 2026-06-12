use crate::nodes::uid::entity_uid;
use iam_models::IamRole;
use neo4rs::{query, Query};

const MERGE_ROLE: &str = "
    MERGE (r:Role {uid: $uid})
    SET r.arn = $arn,
        r.role_id = $role_id,
        r.name = $name,
        r.path = $path,
        r.is_aws_managed = $is_aws_managed,
        r.description = $description,
        r.create_date = $create_date,
        r.last_used_date = $last_used_date,
        r.last_used_region = $last_used_region,
        r.account_id = $account_id,
        r.snapshot_id = $snapshot_id
";

/// Build a query to MERGE a Role node.
pub fn merge_role_query(snapshot_id: &str, account_id: &str, role: &IamRole) -> Query {
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
    query(MERGE_ROLE)
        .param("uid", uid)
        .param("arn", role.arn.clone())
        .param("role_id", role.role_id.clone())
        .param("name", role.role_name.clone())
        .param("path", role.path.clone())
        .param("is_aws_managed", role.is_aws_managed)
        .param("description", role.description.clone().unwrap_or_default())
        .param("create_date", role.create_date.to_rfc3339())
        .param("last_used_date", last_used_date)
        .param("last_used_region", last_used_region)
        .param("account_id", account_id)
        .param("snapshot_id", snapshot_id)
}
