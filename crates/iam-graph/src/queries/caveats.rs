//! Machine-readable caveats attached to JSON query responses.
//!
//! `docs/limitations.md` documents permanent approximations in how effective IAM access is
//! computed. A human reading table output can hold those in mind; a model consuming bare JSON
//! cannot. [`Caveat`] carries the applicable subset of those limitations alongside query
//! results so callers — human or automated — don't state approximate results as fact.

/// Reason string recorded on a `Snapshot` node's `partial_reasons` when wildcard action
/// expansion fell back during collection (`iam_collector::CollectorWarning::WildcardsNotExpanded`).
/// Shared with `ingester.rs` and with callers deciding whether to emit `expansion-degraded`, so
/// a rename of the literal breaks both sides at compile time instead of drifting silently.
pub const WILDCARDS_NOT_EXPANDED_REASON: &str = "some wildcards not expanded";

/// Plain-prose pointer used for every `Caveat::doc_anchor`. Deliberately not a `docs/x.md#anchor`
/// path: that format implied local resolvability an installed binary doesn't have (no `docs/`
/// folder ships next to it). See `docs/caveats.md`.
const CAVEAT_DOC_POINTER: &str =
    "Caveat information is in docs/caveats.md file inside aws-iam-grapher repository";

/// Closed set of known result approximations. Deliberately not `#[non_exhaustive]`: consumers
/// branch on this set, so a new approximation must be a visible addition here, not silently
/// absorbed by a wildcard match.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CaveatCode {
    ApproximateDeny,
    NotactionNotExpanded,
    PartialSnapshot,
    ExpansionDegraded,
}

/// One applicable approximation attached to a JSON query response.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Caveat {
    pub code: CaveatCode,
    pub message: String,
    pub doc_anchor: String,
}

impl Caveat {
    /// Deny subtraction compares wildcard Deny actions against wildcard Allow grants as literal
    /// glob patterns, not set containment; a wildcard grant narrowed by a wildcard Deny may be
    /// reported as permitted. Group results are not suppressed by Denies on member users.
    pub fn approximate_deny() -> Self {
        Self {
            code: CaveatCode::ApproximateDeny,
            message: "Deny subtraction compares wildcard Deny actions against wildcard Allow \
                grants as literal glob patterns, not set containment; a wildcard grant narrowed \
                by a wildcard Deny may be reported as permitted. Group results are not \
                suppressed by Denies on member users."
                .to_string(),
            doc_anchor: CAVEAT_DOC_POINTER.to_string(),
        }
    }

    /// `NotAction` grants are evaluated by exclusion, but their resource scope is not
    /// intersected with `--resource` and conditions on `NotAction` statements are not evaluated.
    pub fn notaction_not_expanded() -> Self {
        Self {
            code: CaveatCode::NotactionNotExpanded,
            message: "`NotAction` grants are evaluated by exclusion, but their resource scope \
                is not intersected with --resource and conditions on NotAction statements are \
                not evaluated; results may overstate access."
                .to_string(),
            doc_anchor: CAVEAT_DOC_POINTER.to_string(),
        }
    }

    /// The snapshot this query ran against is marked partial; `reasons` are the collection-time
    /// causes recorded on the snapshot.
    pub fn partial_snapshot(reasons: &[String]) -> Self {
        let joined = if reasons.is_empty() {
            "(none recorded)".to_string()
        } else {
            reasons.join(", ")
        };
        Self {
            code: CaveatCode::PartialSnapshot,
            message: format!(
                "Snapshot is marked partial; collection was incomplete, so results may \
                understate access. Reasons: {joined}"
            ),
            doc_anchor: CAVEAT_DOC_POINTER.to_string(),
        }
    }

    /// Wildcard action expansion degraded during collection (awsiamactions.io unreachable);
    /// some wildcard actions were stored unexpanded and may not match a concrete-action query.
    pub fn expansion_degraded() -> Self {
        Self {
            code: CaveatCode::ExpansionDegraded,
            message: "Wildcard action expansion degraded during collection (awsiamactions.io \
                unreachable); some wildcard actions were stored unexpanded and may not match \
                this query."
                .to_string(),
            doc_anchor: CAVEAT_DOC_POINTER.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn caveat_code_serializes_to_kebab_case_wire_strings() {
        let cases = [
            (CaveatCode::ApproximateDeny, "\"approximate-deny\""),
            (
                CaveatCode::NotactionNotExpanded,
                "\"notaction-not-expanded\"",
            ),
            (CaveatCode::PartialSnapshot, "\"partial-snapshot\""),
            (CaveatCode::ExpansionDegraded, "\"expansion-degraded\""),
        ];

        for (code, expected) in cases {
            let json = serde_json::to_string(&code).unwrap();

            assert_eq!(json, expected);
        }
    }

    #[test]
    fn partial_snapshot_message_includes_reasons() {
        let reasons = vec!["instance profiles missing".to_string()];

        let caveat = Caveat::partial_snapshot(&reasons);

        assert!(caveat.message.contains("instance profiles missing"));
    }

    #[test]
    fn partial_snapshot_with_no_reasons_still_builds_message() {
        let caveat = Caveat::partial_snapshot(&[]);

        assert!(caveat.message.contains("(none recorded)"));
    }

    #[test]
    fn every_caveat_doc_anchor_points_at_caveats_md_and_it_covers_every_caveat() {
        let caveats_doc = include_str!("../../../../docs/caveats.md");

        let caveats = [
            Caveat::approximate_deny(),
            Caveat::notaction_not_expanded(),
            Caveat::partial_snapshot(&[]),
            Caveat::expansion_degraded(),
        ];

        let expected_headings = [
            "Deny scope is approximate",
            "NotAction",
            "Partial snapshots",
            "Wildcard expansion degradation",
        ];

        for caveat in caveats {
            assert_eq!(caveat.doc_anchor, CAVEAT_DOC_POINTER);
        }

        for heading in expected_headings {
            assert!(
                caveats_doc.contains(heading),
                "docs/caveats.md is missing expected section `{heading}`; doc drifted from CaveatCode variants"
            );
        }
    }
}
