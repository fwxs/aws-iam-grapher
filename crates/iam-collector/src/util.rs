/// Extract the AWS account ID from an IAM ARN.
///
/// ARN format: `arn:partition:service:region:account-id:resource`
///
/// Returns `None` if the ARN is malformed or the account segment is empty.
/// For AWS-managed ARNs such as `arn:aws:iam::aws:policy/ReadOnlyAccess` the
/// account segment is the literal string `"aws"`, not a 12-digit number; callers
/// that need a real account ID should prefer ARNs for customer-owned entities
/// (users, roles, groups) over managed-policy ARNs.
///
/// # Examples
///
/// ```
/// use iam_collector::account_id_from_arn;
///
/// assert_eq!(
///     account_id_from_arn("arn:aws:iam::123456789012:user/alice"),
///     Some("123456789012".to_string()),
/// );
/// assert_eq!(
///     account_id_from_arn("arn:aws:iam::aws:policy/ReadOnlyAccess"),
///     Some("aws".to_string()),
/// );
/// assert_eq!(account_id_from_arn("not-an-arn"), None);
/// ```
pub fn account_id_from_arn(arn: &str) -> Option<String> {
    arn.split(':')
        .nth(4)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

/// Find the account ID from the first ARN in an iterator that yields a non-empty,
/// non-`"aws"` account segment. Returns `None` if no qualifying ARN is found.
pub fn account_id_from_arns<'a>(mut arns: impl Iterator<Item = &'a str>) -> Option<String> {
    arns.find_map(|arn| {
        let segment = account_id_from_arn(arn)?;
        if segment == "aws" {
            None
        } else {
            Some(segment)
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn account_id_from_arn_user_arn_returns_account_id() {
        let result = account_id_from_arn("arn:aws:iam::123456789012:user/alice");
        assert_eq!(result, Some("123456789012".to_string()));
    }

    #[test]
    fn account_id_from_arn_role_arn_returns_account_id() {
        let result = account_id_from_arn("arn:aws:iam::123456789012:role/MyRole");
        assert_eq!(result, Some("123456789012".to_string()));
    }

    #[test]
    fn account_id_from_arn_aws_managed_policy_returns_aws_literal() {
        // AWS-managed policy ARNs use the literal "aws" as account segment —
        // this is expected; callers should prefer customer entity ARNs as source.
        let result = account_id_from_arn("arn:aws:iam::aws:policy/ReadOnlyAccess");
        assert_eq!(result, Some("aws".to_string()));
    }

    #[test]
    fn account_id_from_arn_malformed_returns_none() {
        assert_eq!(account_id_from_arn("not-an-arn"), None);
        assert_eq!(account_id_from_arn(""), None);
        assert_eq!(account_id_from_arn("arn:aws:iam"), None);
    }

    #[test]
    fn account_id_from_arns_skips_aws_literal_picks_customer_id() {
        let arns = [
            "arn:aws:iam::aws:policy/ReadOnlyAccess",
            "arn:aws:iam::123456789012:user/alice",
        ];
        assert_eq!(
            account_id_from_arns(arns.iter().copied()),
            Some("123456789012".to_string()),
        );
    }

    #[test]
    fn account_id_from_arns_empty_iterator_returns_none() {
        assert_eq!(account_id_from_arns(std::iter::empty()), None);
    }
}
