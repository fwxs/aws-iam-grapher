use crate::errors::GraphError;
use crate::queries::col;
use crate::queries::context::OrgQueryContext;
use crate::queries::escalation_enrichment::{
    fetch_org_holders, fetch_org_instance_profiles, fetch_org_trust_principals, Holder,
    InstanceProfileRef, OrgTerminal, TrustPrincipal,
};
use crate::queries::render_hop_bound;
use crate::queries::risky_actions::RiskyActionGroups;
use neo4rs::Graph;
use std::collections::{HashMap, HashSet};

/// One hop in a cross-account escalation path — includes `account_id` for account labeling.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct OrgHop {
    pub arn: String,
    pub entity_type: String,
    pub account_id: String,
    /// Snapshot this hop's node belongs to — org paths cross snapshots, so each hop must
    /// carry its own rather than relying on one bound snapshot for the whole path.
    pub snapshot_id: String,
}

/// An entity that can reach risky IAM permissions via a transitive `sts:AssumeRole` chain
/// that crosses at least one account boundary within an org collection run.
#[derive(Debug, Clone, serde::Serialize)]
pub struct OrgEscalationPath {
    pub arn: String,
    pub name: String,
    pub entity_type: String,
    pub account_id: String,
    pub risky_actions: Vec<String>,
    /// Names of the risky-action groups this entity's post-Deny `risky_actions` fully
    /// satisfies (see `RiskyActionGroups::finalize_actions`).
    pub matched_paths: Vec<String>,
    /// Ordered chain from `arn` to the entity holding `risky_actions`, with per-hop account ids.
    pub path: Vec<OrgHop>,
    /// `true` if any `CAN_ASSUME_ROLE` hop carries an unevaluated runtime trust condition.
    pub conditional: bool,
    /// Users who inherit `risky_actions` via `MEMBER_OF`, populated only when
    /// `entity_type == "Group"`.
    pub holders: Vec<Holder>,
    /// InstanceProfiles that wrap this entity via `CONTAINS_ROLE`, populated only when
    /// `entity_type == "Role"`.
    pub instance_profiles: Vec<InstanceProfileRef>,
    /// Trust-policy principals that can assume this entity via `CAN_ASSUME`, populated only
    /// when `entity_type == "Role"`.
    pub trust_principals: Vec<TrustPrincipal>,
}

const ORG_ESCALATION_QUERY: &str = include_str!("../../queries/org_escalation_paths.cypher");

/// Return all cross-account escalation paths within the given org collection run.
///
/// `max_hops` is clamped to `[1, MAX_HOPS_CAP]` and interpolated as a literal integer into
/// the Cypher text (variable-length relationship bounds cannot be parameterized in Cypher).
/// Results are deduped by start entity ARN, keeping the shortest path per entity.
pub async fn org_escalation_paths(
    graph: &Graph,
    ctx: &OrgQueryContext,
    max_hops: u32,
    groups: &RiskyActionGroups,
) -> Result<Vec<OrgEscalationPath>, GraphError> {
    let cypher = render_hop_bound(ORG_ESCALATION_QUERY, max_hops);

    let mut stream = graph
        .execute(
            neo4rs::query(&cypher)
                .param("org_run_id", ctx.org_run_id.as_str())
                .param("risky_actions", groups.all_actions()),
        )
        .await?;

    struct Candidate {
        name: String,
        entity_type: String,
        account_id: String,
        allowed_actions: Vec<String>,
        deny_actions: Vec<String>,
        path: Vec<OrgHop>,
        conditional: bool,
    }

    let mut by_arn: HashMap<String, Candidate> = HashMap::new();

    while let Some(row) = stream.next().await? {
        let arn: String = col(&row, "arn")?;
        let name: String = col(&row, "name")?;
        let entity_type: String = col(&row, "entity_type")?;
        let account_id: String = col(&row, "account_id")?;
        let allowed_actions: Vec<String> = col(&row, "allowed_actions")?;
        let deny_actions: Vec<String> = col(&row, "deny_actions")?;
        let path: Vec<OrgHop> = col(&row, "path")?;
        let conditional: bool = col(&row, "conditional")?;

        match by_arn.get(&arn) {
            Some(existing) if existing.path.len() <= path.len() => {}
            _ => {
                by_arn.insert(
                    arn,
                    Candidate {
                        name,
                        entity_type,
                        account_id,
                        allowed_actions,
                        deny_actions,
                        path,
                        conditional,
                    },
                );
            }
        }
    }

    let mut kept: Vec<(String, Candidate, Vec<String>, Vec<String>)> = Vec::new();
    for (arn, candidate) in by_arn {
        let risky_actions: Vec<String> = candidate
            .allowed_actions
            .iter()
            .filter(|action| {
                !candidate
                    .deny_actions
                    .iter()
                    .any(|deny| iam_expander::glob_match(deny, action))
            })
            .cloned()
            .collect();

        // Group AND-matching MUST run on the post-Deny risky_actions computed above,
        // never on candidate.allowed_actions directly — evaluating groups before Deny
        // subtraction would let a group falsely "match" on an action an explicit Deny
        // actually suppresses, a false positive on a security query.
        let Some((risky_actions, matched_paths)) = groups.finalize_actions(&risky_actions) else {
            continue;
        };

        kept.push((arn, candidate, risky_actions, matched_paths));
    }

    // Enrichment is keyed on the terminal entity (the actual permission holder, the last
    // hop of `path`), not `arn` — for transitive chains `arn` is the assumer that can
    // *reach* the risky action, while `path.last()` is the entity that holds it directly.
    // Org terminals may span different account snapshots, so each carries its own
    // `snapshot_id` from the hop rather than a single bound `QueryContext`. Multiple distinct
    // start entities can share the same terminal via different chains, so dedupe via HashSet
    // before UNWINDing — otherwise the enrichment query re-executes its MATCH once per
    // duplicate and every path sharing that terminal reports doubled results.
    let terminal_hops: Vec<&OrgHop> = kept
        .iter()
        .filter_map(|(_, c, _, _)| c.path.last())
        .collect();
    let group_terminals: Vec<OrgTerminal> = terminal_hops
        .iter()
        .filter(|h| h.entity_type == "Group")
        .map(|h| OrgTerminal {
            arn: h.arn.clone(),
            snapshot_id: h.snapshot_id.clone(),
        })
        .collect::<HashSet<_>>()
        .into_iter()
        .collect();
    let role_terminals: Vec<OrgTerminal> = terminal_hops
        .iter()
        .filter(|h| h.entity_type == "Role")
        .map(|h| OrgTerminal {
            arn: h.arn.clone(),
            snapshot_id: h.snapshot_id.clone(),
        })
        .collect::<HashSet<_>>()
        .into_iter()
        .collect();

    let (holders_by_terminal, profiles_by_terminal, trust_by_terminal) = tokio::try_join!(
        fetch_org_holders(graph, &group_terminals),
        fetch_org_instance_profiles(graph, &role_terminals),
        fetch_org_trust_principals(graph, &role_terminals),
    )?;

    let results = kept
        .into_iter()
        .map(|(arn, candidate, risky_actions, matched_paths)| {
            let terminal_arn = candidate
                .path
                .last()
                .map(|h| h.arn.as_str())
                .unwrap_or(arn.as_str());
            let holders = holders_by_terminal
                .get(terminal_arn)
                .cloned()
                .unwrap_or_default();
            let instance_profiles = profiles_by_terminal
                .get(terminal_arn)
                .cloned()
                .unwrap_or_default();
            let trust_principals = trust_by_terminal
                .get(terminal_arn)
                .cloned()
                .unwrap_or_default();
            OrgEscalationPath {
                arn,
                name: candidate.name,
                entity_type: candidate.entity_type,
                account_id: candidate.account_id,
                risky_actions,
                matched_paths,
                path: candidate.path,
                conditional: candidate.conditional,
                holders,
                instance_profiles,
                trust_principals,
            }
        })
        .collect();
    Ok(results)
}
