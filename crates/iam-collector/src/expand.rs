use crate::errors::CollectorWarning;
use crate::traits::CollectedData;
use iam_models::{IamInlinePolicy, PolicyDocument};
use tracing::warn;

/// Run wildcard expansion over all policy documents in `data`, in-place.
///
/// Applied identically in both live and offline collection so queries return the same
/// results regardless of how data was collected. Falls back to the original document on
/// any error so air-gapped runs degrade gracefully (awsiamactions.io may be unreachable).
/// If any expansion fails, `CollectorWarning::WildcardsNotExpanded` is added to `data.warnings`
/// so the resulting snapshot is recorded as partial.
pub(crate) async fn expand_collected_data(data: &mut CollectedData) {
    let mut any_failed = false;
    for policy in &mut data.policies {
        if let Some(doc) = policy.document.take() {
            let (expanded, ok) = try_expand(doc).await;
            policy.document = Some(expanded);
            if !ok {
                any_failed = true;
            }
        }
    }
    for role in &mut data.roles {
        if expand_inline_policies(&mut role.inline_policies).await {
            any_failed = true;
        }
    }
    for user in &mut data.users {
        if expand_inline_policies(&mut user.inline_policies).await {
            any_failed = true;
        }
    }
    for group in &mut data.groups {
        if expand_inline_policies(&mut group.inline_policies).await {
            any_failed = true;
        }
    }
    if any_failed {
        data.warnings.push(CollectorWarning::WildcardsNotExpanded);
    }
}

/// Returns `true` if any inline policy in `inlines` failed to expand.
async fn expand_inline_policies(inlines: &mut Vec<IamInlinePolicy>) -> bool {
    let placeholder = PolicyDocument {
        version: None,
        statement: Vec::new(),
    };
    let mut any_failed = false;
    for inline in inlines {
        let doc = std::mem::replace(&mut inline.policy_document, placeholder.clone());
        let (expanded, ok) = try_expand(doc).await;
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
async fn try_expand(doc: PolicyDocument) -> (PolicyDocument, bool) {
    let json = match serde_json::to_string(&doc) {
        Ok(j) => j,
        Err(_) => return (doc, true),
    };
    match iam_expander::expand_policy_document(&json).await {
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
