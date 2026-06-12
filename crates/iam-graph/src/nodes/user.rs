use crate::nodes::uid::entity_uid;
use iam_models::IamUser;
use neo4rs::{query, Query};

const MERGE_USER: &str = "
    MERGE (u:User {uid: $uid})
    SET u.arn = $arn,
        u.user_id = $user_id,
        u.name = $name,
        u.path = $path,
        u.is_aws_managed = $is_aws_managed,
        u.create_date = $create_date,
        u.password_last_used = $password_last_used,
        u.has_mfa = $has_mfa,
        u.account_id = $account_id,
        u.snapshot_id = $snapshot_id
";

/// Build a query to MERGE a User node.
pub fn merge_user_query(snapshot_id: &str, account_id: &str, user: &IamUser) -> Query {
    let uid = entity_uid(snapshot_id, &user.arn);
    let password_last_used = user
        .password_last_used
        .map(|d| d.to_rfc3339())
        .unwrap_or_default();
    query(MERGE_USER)
        .param("uid", uid)
        .param("arn", user.arn.clone())
        .param("user_id", user.user_id.clone())
        .param("name", user.user_name.clone())
        .param("path", user.path.clone())
        .param("is_aws_managed", user.is_aws_managed)
        .param("create_date", user.create_date.to_rfc3339())
        .param("password_last_used", password_last_used)
        .param("has_mfa", false)
        .param("account_id", account_id)
        .param("snapshot_id", snapshot_id)
}
