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

/// UID for allow-all-except (NotAction) Permission nodes.
///
/// Encodes the sorted excluded-action list so two NotAction grants on the same
/// resource but with different excluded sets get distinct nodes, and so the UID
/// never collides with a true full-admin `action='*'` node.
pub fn excluded_permission_uid(
    snapshot_id: &str,
    effect: &str,
    resource: &str,
    excluded: &[String],
) -> String {
    let mut sorted = excluded.to_vec();
    sorted.sort();
    let joined = sorted.join(",");
    format!("{snapshot_id}|{effect}|*|{resource}|EXCEPT:{joined}")
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

    #[test]
    fn excluded_permission_uid_is_deterministic_and_sorts_excluded() {
        let a = excluded_permission_uid(
            "snap-001",
            "Allow",
            "*",
            &["s3:DeleteObject".to_string(), "s3:GetObject".to_string()],
        );
        let b = excluded_permission_uid(
            "snap-001",
            "Allow",
            "*",
            &["s3:GetObject".to_string(), "s3:DeleteObject".to_string()],
        );
        assert_eq!(a, b, "order of excluded list must not affect uid");
        assert!(a.contains("EXCEPT:"), "uid must encode exclusion marker");
    }

    #[test]
    fn excluded_permission_uid_differs_from_full_admin_uid() {
        let full_admin = permission_uid("snap-001", "Allow", "*", "*");
        let not_action =
            excluded_permission_uid("snap-001", "Allow", "*", &["s3:GetObject".to_string()]);
        assert_ne!(full_admin, not_action);
    }
}
