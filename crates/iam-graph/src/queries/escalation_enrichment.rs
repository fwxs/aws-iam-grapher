use crate::errors::GraphError;
use crate::nodes::Row;
use crate::queries::col;
use crate::queries::context::QueryContext;
use crate::queries::risky_actions::RiskyActionGroups;
use neo4rs::Graph;
use std::collections::{HashMap, HashSet};

/// Security posture of a `User` appearing in an escalation result — either the escalating
/// entity itself, or a `Holder` who inherits risky permissions via `MEMBER_OF`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct UserAttributes {
    pub user_id: String,
    pub has_mfa: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mfa_method: Option<String>,
    pub console_login_enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password_last_used: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_activity_date: Option<String>,
    pub create_date: String,
    pub access_key_count: u32,
    pub active_access_key_count: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oldest_active_key_date: Option<String>,
    pub access_key_ids: Vec<String>,
}

/// A `User` that inherits a terminal `Group`'s risky permissions via `MEMBER_OF`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Holder {
    pub arn: String,
    pub name: String,
    pub entity_type: String,
    pub attributes: UserAttributes,
}

/// An `InstanceProfile` that wraps a terminal `Role` via `CONTAINS_ROLE`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct InstanceProfileRef {
    pub arn: String,
    pub name: String,
}

/// A trust-policy principal that can assume a terminal `Role` via `CAN_ASSUME`.
///
/// `principal_type` is the trust policy block key (`AWS`, `Service`, `Federated`,
/// `CanonicalUser`) — see `principal_kind` on `relationships::can_assume_row`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct TrustPrincipal {
    pub id: String,
    pub principal_type: String,
    pub conditional: bool,
}

const HOLDERS_QUERY: &str = include_str!("../../queries/escalation_holders.cypher");
const INSTANCE_PROFILES_QUERY: &str =
    include_str!("../../queries/escalation_instance_profiles.cypher");
const TRUST_PRINCIPALS_QUERY: &str =
    include_str!("../../queries/escalation_trust_principals.cypher");
const USER_ATTRIBUTES_QUERY: &str = include_str!("../../queries/escalation_user_attributes.cypher");

const ORG_HOLDERS_QUERY: &str = include_str!("../../queries/org_escalation_holders.cypher");
const ORG_INSTANCE_PROFILES_QUERY: &str =
    include_str!("../../queries/org_escalation_instance_profiles.cypher");
const ORG_TRUST_PRINCIPALS_QUERY: &str =
    include_str!("../../queries/org_escalation_trust_principals.cypher");
const ORG_USER_ATTRIBUTES_QUERY: &str =
    include_str!("../../queries/org_escalation_user_attributes.cypher");

/// Run `query`, decoding each row via `row_mapper` into a `(terminal_arn, value)` pair and
/// accumulating values per terminal ARN. Shared by every `fetch_*`/`fetch_org_*` function
/// below — they differ only in the query/params and the row shape being decoded.
async fn fetch_rows<T>(
    graph: &Graph,
    query: neo4rs::Query,
    row_mapper: impl Fn(&neo4rs::Row) -> Result<(String, T), GraphError>,
) -> Result<HashMap<String, Vec<T>>, GraphError> {
    let mut stream = graph.execute(query).await?;

    let mut by_terminal: HashMap<String, Vec<T>> = HashMap::new();
    while let Some(row) = stream.next().await? {
        let (terminal_arn, value) = row_mapper(&row)?;
        by_terminal.entry(terminal_arn).or_default().push(value);
    }
    Ok(by_terminal)
}

/// Like [`fetch_rows`], but for a query that returns at most one row per key (e.g. one
/// `UserAttributes` per ARN) rather than a 1-to-many relationship — `insert` instead of
/// `push`, so a later row for the same key overwrites rather than accumulates.
async fn fetch_row<T>(
    graph: &Graph,
    query: neo4rs::Query,
    row_mapper: impl Fn(&neo4rs::Row) -> Result<(String, T), GraphError>,
) -> Result<HashMap<String, T>, GraphError> {
    let mut stream = graph.execute(query).await?;

    let mut by_key: HashMap<String, T> = HashMap::new();
    while let Some(row) = stream.next().await? {
        let (key, value) = row_mapper(&row)?;
        by_key.insert(key, value);
    }
    Ok(by_key)
}

/// Node properties are written as `""` rather than absent when a `DateTime`/enum field is
/// `None` (see `nodes/user.rs::user_row`) — decode that convention back to `None` here
/// rather than repeating the check at every call site.
fn non_empty(s: String) -> Option<String> {
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

fn decode_user_attributes(row: &neo4rs::Row) -> Result<UserAttributes, GraphError> {
    let user_id: String = col(row, "user_id")?;
    let has_mfa: bool = col(row, "has_mfa")?;
    let mfa_method: String = col(row, "mfa_method")?;
    let console_login_enabled: bool = col(row, "console_login_enabled")?;
    let password_last_used: String = col(row, "password_last_used")?;
    let last_activity_date: String = col(row, "last_activity_date")?;
    let create_date: String = col(row, "create_date")?;
    let access_key_count: i64 = col(row, "access_key_count")?;
    let active_access_key_count: i64 = col(row, "active_access_key_count")?;
    let oldest_active_key_date: String = col(row, "oldest_active_key_date")?;
    let access_key_ids: Vec<String> = col(row, "access_key_ids")?;
    Ok(UserAttributes {
        user_id,
        has_mfa,
        mfa_method: non_empty(mfa_method),
        console_login_enabled,
        password_last_used: non_empty(password_last_used),
        last_activity_date: non_empty(last_activity_date),
        create_date,
        access_key_count: access_key_count as u32,
        active_access_key_count: active_access_key_count as u32,
        oldest_active_key_date: non_empty(oldest_active_key_date),
        access_key_ids,
    })
}

fn decode_holder(row: &neo4rs::Row) -> Result<(String, Holder), GraphError> {
    let terminal_arn: String = col(row, "terminal_arn")?;
    let arn: String = col(row, "arn")?;
    let name: String = col(row, "name")?;
    let entity_type: String = col(row, "entity_type")?;
    let attributes = decode_user_attributes(row)?;
    Ok((
        terminal_arn,
        Holder {
            arn,
            name,
            entity_type,
            attributes,
        },
    ))
}

fn decode_entity_user_attributes(
    row: &neo4rs::Row,
) -> Result<(String, UserAttributes), GraphError> {
    let entity_arn: String = col(row, "entity_arn")?;
    let attributes = decode_user_attributes(row)?;
    Ok((entity_arn, attributes))
}

fn decode_instance_profile_ref(
    row: &neo4rs::Row,
) -> Result<(String, InstanceProfileRef), GraphError> {
    let terminal_arn: String = col(row, "terminal_arn")?;
    let arn: String = col(row, "arn")?;
    let name: String = col(row, "name")?;
    Ok((terminal_arn, InstanceProfileRef { arn, name }))
}

fn decode_trust_principal(row: &neo4rs::Row) -> Result<(String, TrustPrincipal), GraphError> {
    let terminal_arn: String = col(row, "terminal_arn")?;
    let id: String = col(row, "id")?;
    let principal_type: String = col(row, "principal_type")?;
    let conditional: bool = col(row, "conditional")?;
    Ok((
        terminal_arn,
        TrustPrincipal {
            id,
            principal_type,
            conditional,
        },
    ))
}

/// Fetch `Holder`s (Group member Users) for a batch of terminal Group ARNs.
///
/// Returns an empty map without a round trip when `arns` is empty.
pub(crate) async fn fetch_holders(
    graph: &Graph,
    ctx: &QueryContext,
    arns: &[String],
) -> Result<HashMap<String, Vec<Holder>>, GraphError> {
    if arns.is_empty() {
        return Ok(HashMap::new());
    }
    let query = neo4rs::query(HOLDERS_QUERY)
        .param("arns", arns.to_vec())
        .param("account_id", ctx.account_id.as_str())
        .param("snapshot_id", ctx.snapshot_id.as_str());
    fetch_rows(graph, query, decode_holder).await
}

/// Fetch `InstanceProfileRef`s for a batch of terminal Role ARNs.
///
/// Returns an empty map without a round trip when `arns` is empty.
pub(crate) async fn fetch_instance_profiles(
    graph: &Graph,
    ctx: &QueryContext,
    arns: &[String],
) -> Result<HashMap<String, Vec<InstanceProfileRef>>, GraphError> {
    if arns.is_empty() {
        return Ok(HashMap::new());
    }
    let query = neo4rs::query(INSTANCE_PROFILES_QUERY)
        .param("arns", arns.to_vec())
        .param("account_id", ctx.account_id.as_str())
        .param("snapshot_id", ctx.snapshot_id.as_str());
    fetch_rows(graph, query, decode_instance_profile_ref).await
}

/// Fetch `TrustPrincipal`s for a batch of terminal Role ARNs.
///
/// Returns an empty map without a round trip when `arns` is empty.
pub(crate) async fn fetch_trust_principals(
    graph: &Graph,
    ctx: &QueryContext,
    arns: &[String],
) -> Result<HashMap<String, Vec<TrustPrincipal>>, GraphError> {
    if arns.is_empty() {
        return Ok(HashMap::new());
    }
    let query = neo4rs::query(TRUST_PRINCIPALS_QUERY)
        .param("arns", arns.to_vec())
        .param("account_id", ctx.account_id.as_str())
        .param("snapshot_id", ctx.snapshot_id.as_str());
    fetch_rows(graph, query, decode_trust_principal).await
}

/// Fetch `UserAttributes` for a batch of escalating-entity ARNs that are Users.
///
/// Returns an empty map without a round trip when `arns` is empty. An ARN that isn't a
/// User in this scope simply produces no row and is absent from the result map.
pub(crate) async fn fetch_user_attributes(
    graph: &Graph,
    ctx: &QueryContext,
    arns: &[String],
) -> Result<HashMap<String, UserAttributes>, GraphError> {
    if arns.is_empty() {
        return Ok(HashMap::new());
    }
    let query = neo4rs::query(USER_ATTRIBUTES_QUERY)
        .param("arns", arns.to_vec())
        .param("account_id", ctx.account_id.as_str())
        .param("snapshot_id", ctx.snapshot_id.as_str());
    fetch_row(graph, query, decode_entity_user_attributes).await
}

/// `(arn, snapshot_id)` pair identifying one org-escalation terminal — org terminals may
/// belong to different account snapshots within the same org collection run, so each pair
/// carries its own `snapshot_id` rather than relying on one bound `QueryContext`.
#[derive(Clone, PartialEq, Eq, Hash)]
pub(crate) struct OrgTerminal {
    pub arn: String,
    pub snapshot_id: String,
}

/// Deduped terminal/entity keys to enrich for one `privilege_escalation_paths`/
/// `org_escalation_paths` call — `K` is `String` for the single-account query, `OrgTerminal`
/// for the org-wide one (which needs each terminal's own `snapshot_id` alongside its arn).
pub(crate) struct EnrichmentKeys<K> {
    pub group_terminals: Vec<K>,
    pub role_terminals: Vec<K>,
    pub user_arns: Vec<K>,
}

/// Extract and dedupe the three enrichment key sets from a candidate list, shared by
/// `privilege_escalation_paths` and `org_escalation_paths` so the dedup rule can't drift
/// between them.
///
/// Enrichment is keyed on the terminal entity (the actual permission holder, the last hop
/// of a path) for `group_terminals`/`role_terminals` — for transitive chains the candidate's
/// own key is the assumer that can *reach* the risky action, while the terminal is the entity
/// that holds it directly. `user_arns` is the opposite: keyed on the escalating entity's own
/// key, since the User whose security posture matters is the one who'd actually be attacked,
/// at the start of the chain, not whichever entity happens to hold the permission at the end.
///
/// Multiple distinct candidates can share the same terminal via different chains, so every
/// set is deduped via `HashSet` before the caller UNWINDs it — otherwise the enrichment query
/// re-executes its `MATCH` once per duplicate and every path sharing that terminal reports
/// doubled results.
pub(crate) fn collect_enrichment_keys<C, K, H>(
    candidates: &[(String, C, Vec<String>, Vec<String>)],
    path_of: impl Fn(&C) -> &[H],
    entity_type_of: impl Fn(&C) -> &str,
    terminal_key: impl Fn(&H) -> K,
    hop_entity_type: impl Fn(&H) -> &str,
    user_key: impl Fn(&str, &C) -> Option<K>,
) -> EnrichmentKeys<K>
where
    K: Eq + std::hash::Hash + Clone,
{
    let terminal_hops: Vec<&H> = candidates
        .iter()
        .filter_map(|(_, c, _, _)| path_of(c).last())
        .collect();

    let group_terminals: Vec<K> = terminal_hops
        .iter()
        .filter(|h| hop_entity_type(h) == "Group")
        .map(|h| terminal_key(h))
        .collect::<HashSet<_>>()
        .into_iter()
        .collect();
    let role_terminals: Vec<K> = terminal_hops
        .iter()
        .filter(|h| hop_entity_type(h) == "Role")
        .map(|h| terminal_key(h))
        .collect::<HashSet<_>>()
        .into_iter()
        .collect();
    let user_arns: Vec<K> = candidates
        .iter()
        .filter(|(_, c, _, _)| entity_type_of(c) == "User")
        .filter_map(|(arn, c, _, _)| user_key(arn, c))
        .collect::<HashSet<_>>()
        .into_iter()
        .collect();

    EnrichmentKeys {
        group_terminals,
        role_terminals,
        user_arns,
    }
}

/// Wildcard- and group-Deny-aware suppression, followed by risky-action-group AND-matching,
/// shared by `privilege_escalation_paths` and `org_escalation_paths` so the two evaluation
/// orders can't drift apart.
///
/// Drops any allowed action covered by a Deny (exact, wildcard, or full-admin) on the
/// terminal entity's own or a member group's policies, then runs `groups.finalize_actions`
/// on the survivors. Group AND-matching MUST run on the post-Deny actions, never on the raw
/// allowed actions — evaluating groups before Deny subtraction would let a group falsely
/// "match" on an action an explicit Deny actually suppresses, a false positive on a security
/// query. Candidates whose post-Deny actions don't fully satisfy any risky-action group are
/// dropped.
pub(crate) fn finalize_kept<C>(
    by_arn: HashMap<String, C>,
    groups: &RiskyActionGroups,
    allowed_actions: impl Fn(&C) -> &[String],
    deny_actions: impl Fn(&C) -> &[String],
) -> Vec<(String, C, Vec<String>, Vec<String>)> {
    let mut kept = Vec::new();
    for (arn, candidate) in by_arn {
        let risky_actions: Vec<String> = allowed_actions(&candidate)
            .iter()
            .filter(|action| {
                !deny_actions(&candidate)
                    .iter()
                    .any(|deny| iam_expander::glob_match(deny, action))
            })
            .cloned()
            .collect();

        let Some((risky_actions, matched_paths)) = groups.finalize_actions(&risky_actions) else {
            continue;
        };

        kept.push((arn, candidate, risky_actions, matched_paths));
    }
    kept
}

fn org_pairs(terminals: &[OrgTerminal]) -> Vec<Row> {
    terminals
        .iter()
        .map(|t| {
            Row::from([
                ("arn".to_string(), t.arn.as_str().into()),
                ("snapshot_id".to_string(), t.snapshot_id.as_str().into()),
            ])
        })
        .collect()
}

/// Org-scoped variant of [`fetch_holders`] — see [`OrgTerminal`].
pub(crate) async fn fetch_org_holders(
    graph: &Graph,
    terminals: &[OrgTerminal],
) -> Result<HashMap<String, Vec<Holder>>, GraphError> {
    if terminals.is_empty() {
        return Ok(HashMap::new());
    }
    let query = neo4rs::query(ORG_HOLDERS_QUERY).param("pairs", org_pairs(terminals));
    fetch_rows(graph, query, decode_holder).await
}

/// Org-scoped variant of [`fetch_instance_profiles`] — see [`OrgTerminal`].
pub(crate) async fn fetch_org_instance_profiles(
    graph: &Graph,
    terminals: &[OrgTerminal],
) -> Result<HashMap<String, Vec<InstanceProfileRef>>, GraphError> {
    if terminals.is_empty() {
        return Ok(HashMap::new());
    }
    let query = neo4rs::query(ORG_INSTANCE_PROFILES_QUERY).param("pairs", org_pairs(terminals));
    fetch_rows(graph, query, decode_instance_profile_ref).await
}

/// Org-scoped variant of [`fetch_trust_principals`] — see [`OrgTerminal`].
pub(crate) async fn fetch_org_trust_principals(
    graph: &Graph,
    terminals: &[OrgTerminal],
) -> Result<HashMap<String, Vec<TrustPrincipal>>, GraphError> {
    if terminals.is_empty() {
        return Ok(HashMap::new());
    }
    let query = neo4rs::query(ORG_TRUST_PRINCIPALS_QUERY).param("pairs", org_pairs(terminals));
    fetch_rows(graph, query, decode_trust_principal).await
}

/// Org-scoped variant of [`fetch_user_attributes`] — see [`OrgTerminal`].
pub(crate) async fn fetch_org_user_attributes(
    graph: &Graph,
    terminals: &[OrgTerminal],
) -> Result<HashMap<String, UserAttributes>, GraphError> {
    if terminals.is_empty() {
        return Ok(HashMap::new());
    }
    let query = neo4rs::query(ORG_USER_ATTRIBUTES_QUERY).param("pairs", org_pairs(terminals));
    fetch_row(graph, query, decode_entity_user_attributes).await
}
