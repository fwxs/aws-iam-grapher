use crate::nodes::uid::entity_uid;
use crate::nodes::Row;
use iam_models::IamUser;

/// UNWIND-batched: MERGE a User node per row.
pub const MERGE_USER: &str = "
    UNWIND $rows AS row
    MERGE (u:User {uid: row.uid})
    SET u.arn = row.arn,
        u.user_id = row.user_id,
        u.name = row.name,
        u.path = row.path,
        u.is_aws_managed = row.is_aws_managed,
        u.create_date = row.create_date,
        u.password_last_used = row.password_last_used,
        u.has_mfa = row.has_mfa,
        u.mfa_method = row.mfa_method,
        u.console_login_enabled = row.console_login_enabled,
        u.last_activity_date = row.last_activity_date,
        u.account_id = row.account_id,
        u.snapshot_id = row.snapshot_id
";

/// Build a row for the `MERGE_USER` UNWIND statement.
pub fn user_row(snapshot_id: &str, account_id: &str, user: &IamUser) -> Row {
    let uid = entity_uid(snapshot_id, &user.arn);
    let password_last_used = user
        .password_last_used
        .map(|d| d.to_rfc3339())
        .unwrap_or_default();
    let mfa_method = user
        .mfa_method
        .map(|m| m.as_str().to_string())
        .unwrap_or_default();
    let last_activity_date = user
        .last_activity_date
        .map(|d| d.to_rfc3339())
        .unwrap_or_default();
    Row::from([
        ("uid".to_string(), uid.into()),
        ("arn".to_string(), user.arn.clone().into()),
        ("user_id".to_string(), user.user_id.clone().into()),
        ("name".to_string(), user.user_name.clone().into()),
        ("path".to_string(), user.path.clone().into()),
        ("is_aws_managed".to_string(), user.is_aws_managed.into()),
        (
            "create_date".to_string(),
            user.create_date.to_rfc3339().into(),
        ),
        ("password_last_used".to_string(), password_last_used.into()),
        ("has_mfa".to_string(), user.has_mfa.into()),
        ("mfa_method".to_string(), mfa_method.into()),
        (
            "console_login_enabled".to_string(),
            user.console_login_enabled.into(),
        ),
        ("last_activity_date".to_string(), last_activity_date.into()),
        ("account_id".to_string(), account_id.into()),
        ("snapshot_id".to_string(), snapshot_id.into()),
    ])
}
