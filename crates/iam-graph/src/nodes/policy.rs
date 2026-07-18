use crate::nodes::uid::{entity_uid, inline_policy_uid};
use crate::nodes::Row;
use iam_models::{IamInlinePolicy, IamPolicy};

/// UNWIND-batched: MERGE a managed Policy node per row.
pub const MERGE_POLICY: &str = "
    UNWIND $rows AS row
    MERGE (p:Policy {uid: row.uid})
    SET p.arn = row.arn,
        p.policy_id = row.policy_id,
        p.name = row.name,
        p.path = row.path,
        p.is_aws_managed = row.is_aws_managed,
        p.is_attachable = row.is_attachable,
        p.attachment_count = row.attachment_count,
        p.create_date = row.create_date,
        p.update_date = row.update_date,
        p.account_id = row.account_id,
        p.snapshot_id = row.snapshot_id
";

/// UNWIND-batched: MERGE an InlinePolicy node per row.
pub const MERGE_INLINE_POLICY: &str = "
    UNWIND $rows AS row
    MERGE (ip:InlinePolicy {uid: row.uid})
    SET ip.name = row.name,
        ip.owner_arn = row.owner_arn,
        ip.account_id = row.account_id,
        ip.snapshot_id = row.snapshot_id
";

/// Build a row for the `MERGE_POLICY` UNWIND statement.
pub fn policy_row(snapshot_id: &str, account_id: &str, policy: &IamPolicy) -> Row {
    let uid = entity_uid(snapshot_id, &policy.arn);
    Row::from([
        ("uid".to_string(), uid.into()),
        ("arn".to_string(), policy.arn.clone().into()),
        ("policy_id".to_string(), policy.policy_id.clone().into()),
        ("name".to_string(), policy.policy_name.clone().into()),
        ("path".to_string(), policy.path.clone().into()),
        ("is_aws_managed".to_string(), policy.is_aws_managed.into()),
        ("is_attachable".to_string(), policy.is_attachable.into()),
        (
            "attachment_count".to_string(),
            (policy.attachment_count as i64).into(),
        ),
        (
            "create_date".to_string(),
            policy.create_date.to_rfc3339().into(),
        ),
        (
            "update_date".to_string(),
            policy.update_date.to_rfc3339().into(),
        ),
        ("account_id".to_string(), account_id.into()),
        ("snapshot_id".to_string(), snapshot_id.into()),
    ])
}

/// Build a row for the `MERGE_INLINE_POLICY` UNWIND statement.
pub fn inline_policy_row(
    snapshot_id: &str,
    account_id: &str,
    owner_arn: &str,
    inline: &IamInlinePolicy,
) -> Row {
    let uid = inline_policy_uid(snapshot_id, owner_arn, &inline.policy_name);
    Row::from([
        ("uid".to_string(), uid.into()),
        ("name".to_string(), inline.policy_name.clone().into()),
        ("owner_arn".to_string(), owner_arn.into()),
        ("account_id".to_string(), account_id.into()),
        ("snapshot_id".to_string(), snapshot_id.into()),
    ])
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merge_policy_query_uses_correct_uid() {
        use crate::nodes::uid::entity_uid;
        let uid = entity_uid("snap-001", "arn:aws:iam::123:policy/Test");
        assert_eq!(uid, "snap-001|arn:aws:iam::123:policy/Test");
    }

    #[test]
    fn entity_uid_is_deterministic() {
        assert_eq!(
            entity_uid("snap-001", "arn:aws:iam::123:policy/Test"),
            "snap-001|arn:aws:iam::123:policy/Test"
        );
    }

    #[test]
    fn inline_policy_uid_includes_owner_and_name() {
        let uid = inline_policy_uid("snap-001", "arn:aws:iam::123:role/Foo", "InlinePolicy");
        assert_eq!(uid, "snap-001|arn:aws:iam::123:role/Foo|InlinePolicy");
    }
}
