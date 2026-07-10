use aws_sdk_iam::config::Region;
use tracing::debug;

/// Hardcoded last-resort region when nothing else resolves one.
const DEFAULT_REGION: &str = "us-east-1";

/// Resolves the effective AWS region for a collector.
///
/// Precedence: the first entry of `explicit` (typically the CLI `--region` flag) wins if
/// present; otherwise `profile_region` (whatever the AWS profile/environment already
/// resolved); otherwise [`DEFAULT_REGION`]. Collection never proceeds with no region
/// configured at all — that fails every call with `ResolveEndpointError("Missing Region")`
/// before it ever reaches AWS.
pub fn resolve_region(explicit: &[String], profile_region: Option<&Region>) -> Region {
    if let Some(first) = explicit.first() {
        debug!(region = %first, source = "--region flag", "resolved AWS region");
        return Region::new(first.clone());
    }
    if let Some(region) = profile_region {
        debug!(region = %region, source = "profile/environment", "resolved AWS region");
        return region.clone();
    }
    debug!(
        region = DEFAULT_REGION,
        source = "default",
        "resolved AWS region"
    );
    Region::new(DEFAULT_REGION)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_region_wins_over_profile_region() {
        let region = resolve_region(&["us-west-2".to_string()], Some(&Region::new("eu-west-1")));
        assert_eq!(region, Region::new("us-west-2"));
    }

    #[test]
    fn explicit_region_uses_first_entry_when_multiple_given() {
        let region = resolve_region(&["us-west-2".to_string(), "eu-central-1".to_string()], None);
        assert_eq!(region, Region::new("us-west-2"));
    }

    #[test]
    fn falls_back_to_profile_region_when_no_explicit_regions() {
        let region = resolve_region(&[], Some(&Region::new("ap-southeast-2")));
        assert_eq!(region, Region::new("ap-southeast-2"));
    }

    #[test]
    fn falls_back_to_default_when_nothing_resolves() {
        let region = resolve_region(&[], None);
        assert_eq!(region, Region::new(DEFAULT_REGION));
    }
}
