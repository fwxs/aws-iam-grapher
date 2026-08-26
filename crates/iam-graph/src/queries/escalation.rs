use crate::errors::GraphError;
use crate::queries::col;
use crate::queries::context::QueryContext;
use crate::queries::escalation_enrichment::{
    collect_enrichment_keys, fetch_holders, fetch_instance_profiles, fetch_trust_principals,
    fetch_user_attributes, EnrichmentKeys, Holder, InstanceProfileRef, TrustPrincipal,
    UserAttributes,
};
use crate::queries::render_hop_bound;
use crate::queries::risky_actions::RiskyActionGroups;
use neo4rs::Graph;
use std::collections::HashMap;

/// One hop in an escalation path — the ARN and entity-type label of a node on the chain.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Hop {
    pub arn: String,
    pub entity_type: String,
}

/// An entity that has known privilege-escalation permissions, directly or via a
/// transitive `sts:AssumeRole` chain.
#[derive(Debug, Clone, serde::Serialize)]
pub struct EscalationPath {
    pub arn: String,
    pub name: String,
    pub entity_type: String,
    pub risky_actions: Vec<String>,
    /// Names of the risky-action groups this entity's post-Deny `risky_actions` fully
    /// satisfies (see `RiskyActionGroups::finalize_actions`).
    pub matched_paths: Vec<String>,
    /// Ordered chain from `arn` to the entity that holds `risky_actions`.
    /// A single-element path means the entity holds the risky permissions directly.
    pub path: Vec<Hop>,
    /// `true` if any `CAN_ASSUME_ROLE` hop on `path` carries an unevaluated
    /// runtime trust condition — the path may not hold at runtime.
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

const ESCALATION_QUERY: &str = include_str!("../../queries/privilege_escalation_paths.cypher");

/// Return all entities with at least one privilege-escalation permission, reachable
/// directly or transitively via up to `max_hops` `sts:AssumeRole` hops.
///
/// `max_hops` is clamped to `[1, MAX_HOPS_CAP]` and interpolated as a literal integer
/// into the Cypher text, since variable-length relationship bounds can't be parameterized.
pub async fn privilege_escalation_paths(
    graph: &Graph,
    ctx: &QueryContext,
    max_hops: u32,
    groups: &RiskyActionGroups,
) -> Result<Vec<EscalationPath>, GraphError> {
    let cypher = render_hop_bound(ESCALATION_QUERY, max_hops);

    let mut stream = graph
        .execute(
            neo4rs::query(&cypher)
                .param("account_id", ctx.account_id.as_str())
                .param("snapshot_id", ctx.snapshot_id.as_str())
                .param("risky_actions", groups.all_actions()),
        )
        .await?;

    struct Candidate {
        name: String,
        entity_type: String,
        allowed_actions: Vec<String>,
        deny_actions: Vec<String>,
        path: Vec<Hop>,
        conditional: bool,
    }

    // Dedupe by arn across the direct and transitive UNION arms, keeping the shortest
    // path (a direct/self path always wins over a longer transitive one to the same entity).
    let mut by_arn: HashMap<String, Candidate> = HashMap::new();

    while let Some(row) = stream.next().await? {
        let arn: String = col(&row, "arn")?;
        let name: String = col(&row, "name")?;
        let entity_type: String = col(&row, "entity_type")?;
        let allowed_actions: Vec<String> = col(&row, "allowed_actions")?;
        let deny_actions: Vec<String> = col(&row, "deny_actions")?;
        let path: Vec<Hop> = col(&row, "path")?;
        let conditional: bool = col(&row, "conditional")?;

        match by_arn.get(&arn) {
            Some(existing) if existing.path.len() <= path.len() => {}
            _ => {
                by_arn.insert(
                    arn,
                    Candidate {
                        name,
                        entity_type,
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
        // Wildcard- and group-Deny-aware suppression: drop any allowed action covered by
        // a Deny (exact, wildcard, or full-admin) on the terminal entity's own or a member
        // group's policies.
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

    let EnrichmentKeys {
        group_terminals,
        role_terminals,
        user_arns,
    } = collect_enrichment_keys(
        &kept,
        |c: &Candidate| c.path.as_slice(),
        |c: &Candidate| c.entity_type.as_str(),
        |h: &Hop| h.arn.clone(),
        |h: &Hop| h.entity_type.as_str(),
        |arn: &str, _c: &Candidate| Some(arn.to_string()),
    );

    let (holders_by_terminal, profiles_by_terminal, trust_by_terminal, user_attrs_by_arn) = tokio::try_join!(
        fetch_holders(graph, ctx, &group_terminals),
        fetch_instance_profiles(graph, ctx, &role_terminals),
        fetch_trust_principals(graph, ctx, &role_terminals),
        fetch_user_attributes(graph, ctx, &user_arns),
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
            EscalationPath {
                arn,
                name: candidate.name,
                entity_type: candidate.entity_type,
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
