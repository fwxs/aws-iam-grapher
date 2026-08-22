use crate::errors::GraphError;
use crate::nodes::Row;
use crate::queries::col;
use crate::queries::context::QueryContext;
use neo4rs::Graph;
use std::collections::HashMap;

/// A `User` that inherits a terminal `Group`'s risky permissions via `MEMBER_OF`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Holder {
    pub arn: String,
    pub name: String,
    pub entity_type: String,
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

const ORG_HOLDERS_QUERY: &str = include_str!("../../queries/org_escalation_holders.cypher");
const ORG_INSTANCE_PROFILES_QUERY: &str =
    include_str!("../../queries/org_escalation_instance_profiles.cypher");
const ORG_TRUST_PRINCIPALS_QUERY: &str =
    include_str!("../../queries/org_escalation_trust_principals.cypher");

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

fn decode_holder(row: &neo4rs::Row) -> Result<(String, Holder), GraphError> {
    let terminal_arn: String = col(row, "terminal_arn")?;
    let arn: String = col(row, "arn")?;
    let name: String = col(row, "name")?;
    let entity_type: String = col(row, "entity_type")?;
    Ok((
        terminal_arn,
        Holder {
            arn,
            name,
            entity_type,
        },
    ))
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

/// `(arn, snapshot_id)` pair identifying one org-escalation terminal — org terminals may
/// belong to different account snapshots within the same org collection run, so each pair
/// carries its own `snapshot_id` rather than relying on one bound `QueryContext`.
#[derive(Clone, PartialEq, Eq, Hash)]
pub(crate) struct OrgTerminal {
    pub arn: String,
    pub snapshot_id: String,
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
