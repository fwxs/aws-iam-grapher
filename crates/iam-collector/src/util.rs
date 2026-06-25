use crate::errors::CollectorError;
use aws_sdk_iam::error::SdkError;
use aws_smithy_types::error::metadata::ProvideErrorMetadata;

/// Maps an `SdkError` from any AWS SDK client to a `CollectorError`.
///
/// `SdkError<E, R>` is a type alias re-exported identically by every AWS SDK crate
/// (`aws_sdk_iam`, `aws_sdk_organizations`, `aws_sdk_sts`, ...) onto the same underlying
/// `aws_smithy_runtime_api::client::result::SdkError`, so this single generic function
/// classifies errors from all of them.
///
/// Checked against aws-sdk-iam 1.112.0 / aws-smithy-runtime-api 1.12.3:
/// AccessDenied arrives as an unhandled `ServiceError` whose `meta().code()` returns
/// `Some("AccessDenied")`. This is stable API; the Debug string is not.
pub(crate) fn map_sdk_error<E, R>(err: SdkError<E, R>) -> CollectorError
where
    E: std::fmt::Debug + ProvideErrorMetadata,
    R: std::fmt::Debug,
{
    // Primary: inspect the modeled error code via stable typed API.
    if let SdkError::ServiceError(ref svc_err) = err {
        let code = svc_err.err().meta().code();
        if matches!(code, Some("AccessDenied") | Some("Forbidden")) {
            return CollectorError::InsufficientPermissions(format!("{err:?}"));
        }
    }

    // Last-resort fallback: Debug string. The Debug representation of SdkError is not a
    // stable API and may change across SDK releases. Only reached when the service error
    // does not carry a typed code (e.g. network-level 403 with no body).
    let msg = format!("{err:?}");
    if msg.contains("403") || msg.contains("AccessDenied") || msg.contains("Forbidden") {
        return CollectorError::InsufficientPermissions(msg);
    }

    CollectorError::AwsSdk(msg)
}

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

    use aws_smithy_runtime_api::client::orchestrator::HttpResponse;
    use aws_smithy_runtime_api::http::StatusCode;
    use aws_smithy_types::body::SdkBody;
    use aws_smithy_types::error::metadata::ErrorMetadata;

    /// Minimal error type for unit-testing `map_sdk_error` in isolation.
    #[derive(Debug)]
    struct StubError {
        meta: ErrorMetadata,
    }

    impl ProvideErrorMetadata for StubError {
        fn meta(&self) -> &ErrorMetadata {
            &self.meta
        }
    }

    fn stub_http_response(status: u16) -> HttpResponse {
        HttpResponse::new(
            StatusCode::try_from(status).expect("valid status code"),
            SdkBody::empty(),
        )
    }

    fn stub_sdk_error(code: &str, http_status: u16) -> SdkError<StubError, HttpResponse> {
        let meta = ErrorMetadata::builder().code(code).build();
        let source = StubError { meta };
        SdkError::service_error(source, stub_http_response(http_status))
    }

    #[test]
    fn map_sdk_error_access_denied_code_returns_insufficient_permissions() {
        // Arrange
        let err = stub_sdk_error("AccessDenied", 403);

        // Act
        let result = map_sdk_error(err);

        // Assert
        assert!(
            matches!(result, CollectorError::InsufficientPermissions(_)),
            "expected InsufficientPermissions, got {result:?}"
        );
    }

    #[test]
    fn map_sdk_error_forbidden_code_returns_insufficient_permissions() {
        let err = stub_sdk_error("Forbidden", 403);
        let result = map_sdk_error(err);
        assert!(matches!(result, CollectorError::InsufficientPermissions(_)));
    }

    #[test]
    fn map_sdk_error_non_403_returns_aws_sdk_error() {
        let err = stub_sdk_error("NoSuchEntity", 404);
        let result = map_sdk_error(err);
        assert!(
            matches!(result, CollectorError::AwsSdk(_)),
            "expected AwsSdk, got {result:?}"
        );
    }

    #[test]
    fn map_sdk_error_service_failure_returns_aws_sdk_error() {
        let err = stub_sdk_error("ServiceFailure", 500);
        let result = map_sdk_error(err);
        assert!(matches!(result, CollectorError::AwsSdk(_)));
    }
}
