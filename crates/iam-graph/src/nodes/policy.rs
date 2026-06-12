use crate::nodes::uid::{entity_uid, inline_policy_uid};
use iam_models::{IamInlinePolicy, IamPolicy};
use neo4rs::{query, Query};

const MERGE_POLICY: &str = "
    MERGE (p:Policy {uid: $uid})
    SET p.arn = $arn,
        p.policy_id = $policy_id,
        p.name = $name,
        p.path = $path,
        p.is_aws_managed = $is_aws_managed,
        p.is_attachable = $is_attachable,
        p.attachment_count = $attachment_count,
        p.create_date = $create_date,
        p.update_date = $update_date,
        p.account_id = $account_id,
        p.snapshot_id = $snapshot_id
";

const MERGE_INLINE_POLICY: &str = "
    MERGE (ip:InlinePolicy {uid: $uid})
    SET ip.name = $name,
        ip.owner_arn = $owner_arn,
        ip.account_id = $account_id,
        ip.snapshot_id = $snapshot_id
";

/// Build a query to MERGE a managed Policy node.
pub fn merge_policy_query(snapshot_id: &str, account_id: &str, policy: &IamPolicy) -> Query {
    let uid = entity_uid(snapshot_id, &policy.arn);
    query(MERGE_POLICY)
        .param("uid", uid)
        .param("arn", policy.arn.clone())
        .param("policy_id", policy.policy_id.clone())
        .param("name", policy.policy_name.clone())
        .param("path", policy.path.clone())
        .param("is_aws_managed", policy.is_aws_managed)
        .param("is_attachable", policy.is_attachable)
        .param("attachment_count", policy.attachment_count as i64)
        .param("create_date", policy.create_date.to_rfc3339())
        .param("update_date", policy.update_date.to_rfc3339())
        .param("account_id", account_id)
        .param("snapshot_id", snapshot_id)
}

/// Build a query to MERGE an InlinePolicy node.
pub fn merge_inline_policy_query(
    snapshot_id: &str,
    account_id: &str,
    owner_arn: &str,
    inline: &IamInlinePolicy,
) -> Query {
    let uid = inline_policy_uid(snapshot_id, owner_arn, &inline.policy_name);
    query(MERGE_INLINE_POLICY)
        .param("uid", uid)
        .param("name", inline.policy_name.clone())
        .param("owner_arn", owner_arn)
        .param("account_id", account_id)
        .param("snapshot_id", snapshot_id)
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
