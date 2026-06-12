use crate::nodes::uid::entity_uid;
use iam_models::IamInstanceProfile;
use neo4rs::{query, Query};

const MERGE_INSTANCE_PROFILE: &str = "
    MERGE (ip:InstanceProfile {uid: $uid})
    SET ip.arn = $arn,
        ip.instance_profile_id = $instance_profile_id,
        ip.name = $name,
        ip.path = $path,
        ip.is_aws_managed = $is_aws_managed,
        ip.create_date = $create_date,
        ip.account_id = $account_id,
        ip.snapshot_id = $snapshot_id
";

/// Build a query to MERGE an InstanceProfile node.
pub fn merge_instance_profile_query(
    snapshot_id: &str,
    account_id: &str,
    profile: &IamInstanceProfile,
) -> Query {
    let uid = entity_uid(snapshot_id, &profile.arn);
    query(MERGE_INSTANCE_PROFILE)
        .param("uid", uid)
        .param("arn", profile.arn.clone())
        .param("instance_profile_id", profile.instance_profile_id.clone())
        .param("name", profile.instance_profile_name.clone())
        .param("path", profile.path.clone())
        .param("is_aws_managed", profile.is_aws_managed)
        .param("create_date", profile.create_date.to_rfc3339())
        .param("account_id", account_id)
        .param("snapshot_id", snapshot_id)
}
