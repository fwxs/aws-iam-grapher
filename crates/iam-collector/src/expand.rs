use crate::errors::CollectorWarning;
use crate::traits::CollectedData;
use iam_expander::ActionCache;
use iam_models::{IamInlinePolicy, PolicyDocument};
use tracing::warn;

/// Run wildcard expansion over all policy documents in `data`, in-place.
///
/// Loads [`ActionCache`] once, expands all documents, then flushes the cache
/// once at the end.  Previous behavior loaded the cache per-document, causing
/// O(N) disk reads on a 500-policy account.
///
/// Falls back to the original document on any expansion error so air-gapped
/// runs degrade gracefully.  If any expansion fails,
/// [`CollectorWarning::WildcardsNotExpanded`] is pushed so the snapshot is
/// recorded as partial.
pub(crate) async fn expand_collected_data(data: &mut CollectedData) {
    let mut cache = match ActionCache::load().await {
        Ok(c) => c,
        Err(e) => {
            warn!(err = %e, "action cache load failed; wildcards not expanded");
            data.warnings.push(CollectorWarning::WildcardsNotExpanded);
            return;
        }
    };

    let any_failed = expand_with_cache(data, &mut cache).await;

    if any_failed {
        data.warnings.push(CollectorWarning::WildcardsNotExpanded);
    }

    if let Err(e) = cache.flush().await {
        warn!(err = %e, "action cache flush failed; cache not persisted");
    }
}

/// Expands all documents in `data` using `cache`.  Returns `true` if any
/// document failed to expand.
async fn expand_with_cache(data: &mut CollectedData, cache: &mut ActionCache) -> bool {
    let mut any_failed = false;
    for policy in &mut data.policies {
        if let Some(doc) = policy.document.take() {
            let (expanded, ok) = try_expand(doc, cache).await;
            policy.document = Some(expanded);
            if !ok {
                any_failed = true;
            }
        }
    }
    for role in &mut data.roles {
        if expand_inline_policies(&mut role.inline_policies, cache).await {
            any_failed = true;
        }
    }
    for user in &mut data.users {
        if expand_inline_policies(&mut user.inline_policies, cache).await {
            any_failed = true;
        }
    }
    for group in &mut data.groups {
        if expand_inline_policies(&mut group.inline_policies, cache).await {
            any_failed = true;
        }
    }
    any_failed
}

/// Returns `true` if any inline policy in `inlines` failed to expand.
async fn expand_inline_policies(
    inlines: &mut Vec<IamInlinePolicy>,
    cache: &mut ActionCache,
) -> bool {
    let placeholder = PolicyDocument {
        version: None,
        statement: Vec::new(),
    };
    let mut any_failed = false;
    for inline in inlines {
        let doc = std::mem::replace(&mut inline.policy_document, placeholder.clone());
        let (expanded, ok) = try_expand(doc, cache).await;
        inline.policy_document = expanded;
        if !ok {
            any_failed = true;
        }
    }
    any_failed
}

/// Returns `(PolicyDocument, succeeded)`.
/// `succeeded` is `false` only when the expander returned an `ExpanderError`;
/// a serialize error is treated as a no-op (no wildcards to expand).
async fn try_expand(doc: PolicyDocument, cache: &mut ActionCache) -> (PolicyDocument, bool) {
    let json = match serde_json::to_string(&doc) {
        Ok(j) => j,
        Err(_) => return (doc, true),
    };
    match iam_expander::expand_policy_document_with_cache(&json, cache).await {
        Ok(expanded_json) => {
            let expanded = serde_json::from_str(&expanded_json).unwrap_or(doc);
            (expanded, true)
        }
        Err(e) => {
            warn!(err = %e, "wildcard expansion failed, keeping original");
            (doc, false)
        }
    }
}
