use crate::errors::GraphError;
use crate::queries::col;
use crate::queries::context::OrgQueryContext;
use crate::queries::escalation_enrichment::{
    collect_enrichment_keys, fetch_org_holders, fetch_org_instance_profiles,
    fetch_org_trust_principals, fetch_org_user_attributes, finalize_kept, EnrichmentKeys, Holder,
    InstanceProfileRef, OrgTerminal, TrustPrincipal, UserAttributes,
};
use crate::queries::render_hop_bound;
use crate::queries::risky_actions::RiskyActionGroups;
use neo4rs::Graph;
use std::collections::HashMap;

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
    /// Security posture of `arn` itself, populated only when `entity_type == "User"`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_attributes: Option<UserAttributes>,
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

    let kept = finalize_kept(
        by_arn,
        groups,
        |c: &Candidate| c.allowed_actions.as_slice(),
        |c: &Candidate| c.deny_actions.as_slice(),
    );

    // Org terminals may span different account snapshots, so `OrgTerminal` carries its own
    // `snapshot_id` from the hop rather than a single bound `QueryContext`; the escalating
    // entity's own `snapshot_id` for `user_arns` comes from `path.first()` — the first node
    // of `path` is always `start` (see org_escalation_paths.cypher) — since `Candidate`
    // doesn't separately track it.
    let EnrichmentKeys {
        group_terminals,
        role_terminals,
        user_arns,
    } = collect_enrichment_keys(
        &kept,
        |c: &Candidate| c.path.as_slice(),
        |c: &Candidate| c.entity_type.as_str(),
        |h: &OrgHop| OrgTerminal {
            arn: h.arn.clone(),
            snapshot_id: h.snapshot_id.clone(),
        },
        |h: &OrgHop| h.entity_type.as_str(),
        |arn: &str, c: &Candidate| {
            c.path.first().map(|start_hop| OrgTerminal {
                arn: arn.to_string(),
                snapshot_id: start_hop.snapshot_id.clone(),
            })
        },
    );

    let (holders_by_terminal, profiles_by_terminal, trust_by_terminal, user_attrs_by_arn) = tokio::try_join!(
        fetch_org_holders(graph, &group_terminals),
        fetch_org_instance_profiles(graph, &role_terminals),
        fetch_org_trust_principals(graph, &role_terminals),
        fetch_org_user_attributes(graph, &user_arns),
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
            let user_attributes = user_attrs_by_arn.get(&arn).cloned();
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
                user_attributes,
            }
        })
        .collect();
    Ok(results)
}
