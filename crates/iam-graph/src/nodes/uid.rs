/// UID for entities with an ARN.
pub fn entity_uid(snapshot_id: &str, arn: &str) -> String {
    format!("{snapshot_id}|{arn}")
}

/// UID for inline policies (no ARN — keyed by owner ARN + name).
pub fn inline_policy_uid(snapshot_id: &str, owner_arn: &str, name: &str) -> String {
    format!("{snapshot_id}|{owner_arn}|{name}")
}

/// UID for Permission nodes.
pub fn permission_uid(snapshot_id: &str, effect: &str, action: &str, resource: &str) -> String {
    format!("{snapshot_id}|{effect}|{action}|{resource}")
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entity_uid_is_deterministic() {
        assert_eq!(
            entity_uid("snap-001", "arn:aws:iam::123:policy/Test"),
            "snap-001|arn:aws:iam::123:policy/Test"
        );
    }

    #[test]
    fn inline_policy_uid_encodes_owner_and_name() {
        assert_eq!(
            inline_policy_uid("snap-001", "arn:aws:iam::123:role/Foo", "Inline"),
            "snap-001|arn:aws:iam::123:role/Foo|Inline"
        );
    }

    #[test]
    fn permission_uid_encodes_all_parts() {
        assert_eq!(
            permission_uid("snap-001", "Allow", "s3:GetObject", "*"),
            "snap-001|Allow|s3:GetObject|*"
        );
    }
}
