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

    let mut stream = graph
        .execute(
            neo4rs::query(HOLDERS_QUERY)
                .param("arns", arns.to_vec())
                .param("account_id", ctx.account_id.as_str())
                .param("snapshot_id", ctx.snapshot_id.as_str()),
        )
        .await?;

    let mut by_terminal: HashMap<String, Vec<Holder>> = HashMap::new();
    while let Some(row) = stream.next().await? {
        let terminal_arn: String = col(&row, "terminal_arn")?;
        let arn: String = col(&row, "arn")?;
        let name: String = col(&row, "name")?;
        let entity_type: String = col(&row, "entity_type")?;
        by_terminal.entry(terminal_arn).or_default().push(Holder {
            arn,
            name,
            entity_type,
        });
    }
    Ok(by_terminal)
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

    let mut stream = graph
        .execute(
            neo4rs::query(INSTANCE_PROFILES_QUERY)
                .param("arns", arns.to_vec())
                .param("account_id", ctx.account_id.as_str())
                .param("snapshot_id", ctx.snapshot_id.as_str()),
        )
        .await?;

    let mut by_terminal: HashMap<String, Vec<InstanceProfileRef>> = HashMap::new();
    while let Some(row) = stream.next().await? {
        let terminal_arn: String = col(&row, "terminal_arn")?;
        let arn: String = col(&row, "arn")?;
        let name: String = col(&row, "name")?;
        by_terminal
            .entry(terminal_arn)
            .or_default()
            .push(InstanceProfileRef { arn, name });
    }
    Ok(by_terminal)
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

    let mut stream = graph
        .execute(
            neo4rs::query(TRUST_PRINCIPALS_QUERY)
                .param("arns", arns.to_vec())
                .param("account_id", ctx.account_id.as_str())
                .param("snapshot_id", ctx.snapshot_id.as_str()),
        )
        .await?;

    let mut by_terminal: HashMap<String, Vec<TrustPrincipal>> = HashMap::new();
    while let Some(row) = stream.next().await? {
        let terminal_arn: String = col(&row, "terminal_arn")?;
        let id: String = col(&row, "id")?;
        let principal_type: String = col(&row, "principal_type")?;
        let conditional: bool = col(&row, "conditional")?;
        by_terminal
            .entry(terminal_arn)
            .or_default()
            .push(TrustPrincipal {
                id,
                principal_type,
                conditional,
            });
    }
    Ok(by_terminal)
}

/// `(arn, snapshot_id)` pair identifying one org-escalation terminal — org terminals may
/// belong to different account snapshots within the same org collection run, so each pair
/// carries its own `snapshot_id` rather than relying on one bound `QueryContext`.
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

    let mut stream = graph
        .execute(neo4rs::query(ORG_HOLDERS_QUERY).param("pairs", org_pairs(terminals)))
        .await?;

    let mut by_terminal: HashMap<String, Vec<Holder>> = HashMap::new();
    while let Some(row) = stream.next().await? {
        let terminal_arn: String = col(&row, "terminal_arn")?;
        let arn: String = col(&row, "arn")?;
        let name: String = col(&row, "name")?;
        let entity_type: String = col(&row, "entity_type")?;
        by_terminal.entry(terminal_arn).or_default().push(Holder {
            arn,
            name,
            entity_type,
        });
    }
    Ok(by_terminal)
}

/// Org-scoped variant of [`fetch_instance_profiles`] — see [`OrgTerminal`].
pub(crate) async fn fetch_org_instance_profiles(
    graph: &Graph,
    terminals: &[OrgTerminal],
) -> Result<HashMap<String, Vec<InstanceProfileRef>>, GraphError> {
    if terminals.is_empty() {
        return Ok(HashMap::new());
    }

    let mut stream = graph
        .execute(neo4rs::query(ORG_INSTANCE_PROFILES_QUERY).param("pairs", org_pairs(terminals)))
        .await?;

    let mut by_terminal: HashMap<String, Vec<InstanceProfileRef>> = HashMap::new();
    while let Some(row) = stream.next().await? {
        let terminal_arn: String = col(&row, "terminal_arn")?;
        let arn: String = col(&row, "arn")?;
        let name: String = col(&row, "name")?;
        by_terminal
            .entry(terminal_arn)
            .or_default()
            .push(InstanceProfileRef { arn, name });
    }
    Ok(by_terminal)
}

/// Org-scoped variant of [`fetch_trust_principals`] — see [`OrgTerminal`].
pub(crate) async fn fetch_org_trust_principals(
    graph: &Graph,
    terminals: &[OrgTerminal],
) -> Result<HashMap<String, Vec<TrustPrincipal>>, GraphError> {
    if terminals.is_empty() {
        return Ok(HashMap::new());
    }

    let mut stream = graph
        .execute(neo4rs::query(ORG_TRUST_PRINCIPALS_QUERY).param("pairs", org_pairs(terminals)))
        .await?;

    let mut by_terminal: HashMap<String, Vec<TrustPrincipal>> = HashMap::new();
    while let Some(row) = stream.next().await? {
        let terminal_arn: String = col(&row, "terminal_arn")?;
        let id: String = col(&row, "id")?;
        let principal_type: String = col(&row, "principal_type")?;
        let conditional: bool = col(&row, "conditional")?;
        by_terminal
            .entry(terminal_arn)
            .or_default()
            .push(TrustPrincipal {
                id,
                principal_type,
                conditional,
            });
    }
    Ok(by_terminal)
}
