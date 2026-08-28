//! Graphviz DOT rendering for graph-shaped query results (escalation paths, who-can).
//!
//! Only a subset of query results are graph-shaped enough to be worth rendering as DOT;
//! see `cli/query.rs` for which subcommands wire this in.

use iam_graph::{EntityRef, EscalationPath, OrgEscalationPath, UserAttributes};
use std::collections::BTreeMap;
use std::fmt::Write as _;

const RISK_FILL: &str = "#f8d7da";
const CONDITIONAL_FILL: &str = "#fff3cd";
const DEFAULT_FILL: &str = "#e8e8e8";
const CONDITIONAL_EDGE_COLOR: &str = "#d9822b";
/// Fill for a risky terminal User with no MFA — a strictly worse posture than an
/// ordinary risky terminal, so it gets a distinct, more alarming color rather than
/// sharing `RISK_FILL`.
const RISK_NO_MFA_FILL: &str = "#dc3545";

/// Escape a string for safe use inside a double-quoted DOT identifier or label.
fn escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

/// Wrap `s` as a quoted DOT identifier/label, escaping embedded quotes/backslashes.
fn quoted(s: &str) -> String {
    format!("\"{}\"", escape(s))
}

/// Last path segment of an ARN (the resource part after the final `/`), used as a
/// short node label so graphs stay readable instead of showing the full ARN.
fn short_name(arn: &str) -> &str {
    arn.rsplit('/').next().unwrap_or(arn)
}

struct EscalationNode<'a> {
    entity_type: &'a str,
    /// `Some` for org-wide paths, labeled `[account_id]`; `None` for single-account paths.
    account_id: Option<&'a str>,
    risky_actions: Option<String>,
    /// Enrichment count summary (holders/instance_profiles/trust_principals) — a property of
    /// the terminal entity itself, not of any one path, so it's set once rather than merged
    /// like `risky_actions`.
    enrichment: Option<String>,
    /// Security posture of this node when it's a User — the escalating entity's own
    /// `user_attributes`, or a Group terminal's holder attributes. `None` for non-User nodes.
    user_posture: Option<&'a UserAttributes>,
}

/// Shared renderer behind [`escalation_paths_to_dot`] and [`org_escalation_paths_to_dot`]:
/// one node per entity ARN appearing on any path, edges following each path's
/// `CAN_ASSUME_ROLE` chain, and the risk-holding terminal node of each path highlighted
/// with its risky actions (merged if the same ARN is terminal on more than one path).
/// Conditional paths (unresolved runtime trust conditions) render with dashed, colored edges.
fn render_escalation_dot(
    graph_name: &str,
    nodes: BTreeMap<&str, EscalationNode>,
    edges: &[(&str, &str, bool)],
) -> String {
    let mut out = String::new();
    writeln!(out, "digraph {} {{", quoted(graph_name)).unwrap();
    writeln!(out, "  rankdir=LR;").unwrap();
    writeln!(
        out,
        "  node [shape=box, style=filled, fontname=\"Helvetica\", fillcolor={}];",
        quoted(DEFAULT_FILL)
    )
    .unwrap();

    for (arn, node) in &nodes {
        let mut label = format!(
            "{}\\n({})",
            escape(short_name(arn)),
            escape(node.entity_type)
        );
        if let Some(account_id) = node.account_id {
            write!(label, "\\n[{}]", escape(account_id)).unwrap();
        }
        let mut attrs = format!("label={}", quoted(&label));
        if let Some(actions) = &node.risky_actions {
            let mut tooltip = actions.clone();
            if let Some(enrichment) = &node.enrichment {
                write!(tooltip, "\\n{enrichment}").unwrap();
            }
            let fillcolor = match node.user_posture {
                Some(posture) if !posture.has_mfa => {
                    write!(tooltip, "\\n{}", user_posture_summary(posture)).unwrap();
                    RISK_NO_MFA_FILL
                }
                Some(posture) => {
                    write!(tooltip, "\\n{}", user_posture_summary(posture)).unwrap();
                    RISK_FILL
                }
                None => RISK_FILL,
            };
            write!(
                attrs,
                ", fillcolor={}, tooltip={}",
                quoted(fillcolor),
                quoted(&tooltip)
            )
            .unwrap();
        }
        writeln!(out, "  {} [{}];", quoted(arn), attrs).unwrap();
    }

    write_edges(&mut out, edges);
    writeln!(out, "}}").unwrap();
    out
}

/// Merge `actions` into a node's risky-action tooltip, combining rather than overwriting
/// when the same ARN is the terminal node of more than one path.
fn merge_risky_actions(existing: Option<String>, actions: String) -> Option<String> {
    match existing {
        Some(existing) if existing != actions => Some(format!("{existing}, {actions}")),
        Some(existing) => Some(existing),
        None => Some(actions),
    }
}

/// Format the enrichment count summary appended to a terminal node's tooltip — counts only
/// (holders/instance_profiles/trust_principals), full detail is available via `--output json`.
fn enrichment_summary(
    holders: usize,
    instance_profiles: usize,
    trust_principals: usize,
    associations: usize,
) -> String {
    format!(
        "holders: {holders}, instance_profiles: {instance_profiles}, trust_principals: {trust_principals}, associations: {associations}"
    )
}

/// Format a User's security posture for a node tooltip — full detail is available via
/// `--output json`, this is a glance-level summary.
fn user_posture_summary(attrs: &UserAttributes) -> String {
    let mfa = if attrs.has_mfa { "yes" } else { "no" };
    let console = if attrs.console_login_enabled {
        "yes"
    } else {
        "no"
    };
    let mut summary = format!(
        "mfa: {mfa}, console: {console}, active keys: {}",
        attrs.active_access_key_count
    );
    if let Some(oldest) = &attrs.oldest_active_key_date {
        write!(summary, " (oldest {oldest})").unwrap();
    }
    summary
}

/// Render privilege-escalation paths as a DOT digraph. See [`render_escalation_dot`].
pub fn escalation_paths_to_dot(graph_name: &str, paths: &[EscalationPath]) -> String {
    let mut nodes: BTreeMap<&str, EscalationNode> = BTreeMap::new();
    let mut edges: Vec<(&str, &str, bool)> = Vec::new();

    for p in paths {
        let terminal_arn = p.path.last().map(|h| h.arn.as_str()).unwrap_or(&p.arn);
        for hop in &p.path {
            let node = nodes.entry(&hop.arn).or_insert_with(|| EscalationNode {
                entity_type: &hop.entity_type,
                account_id: None,
                risky_actions: None,
                enrichment: None,
                user_posture: None,
            });
            if hop.arn == terminal_arn {
                node.risky_actions =
                    merge_risky_actions(node.risky_actions.take(), p.risky_actions.join(", "));
                node.enrichment.get_or_insert_with(|| {
                    enrichment_summary(
                        p.holders.len(),
                        p.instance_profiles.len(),
                        p.trust_principals.len(),
                        p.associations.len(),
                    )
                });
                if hop.arn == p.arn {
                    node.user_posture = p.user_attributes.as_ref();
                }
            }
        }
        for window in p.path.windows(2) {
            edges.push((&window[0].arn, &window[1].arn, p.conditional));
        }
    }

    render_escalation_dot(graph_name, nodes, &edges)
}

/// Render cross-account escalation paths as a DOT digraph, same shape as
/// [`escalation_paths_to_dot`] but with each node labeled with its account id.
/// See [`render_escalation_dot`].
pub fn org_escalation_paths_to_dot(graph_name: &str, paths: &[OrgEscalationPath]) -> String {
    let mut nodes: BTreeMap<&str, EscalationNode> = BTreeMap::new();
    let mut edges: Vec<(&str, &str, bool)> = Vec::new();

    for p in paths {
        let terminal_arn = p.path.last().map(|h| h.arn.as_str()).unwrap_or(&p.arn);
        for hop in &p.path {
            let node = nodes.entry(&hop.arn).or_insert_with(|| EscalationNode {
                entity_type: &hop.entity_type,
                account_id: Some(&hop.account_id),
                risky_actions: None,
                enrichment: None,
                user_posture: None,
            });
            if hop.arn == terminal_arn {
                node.risky_actions =
                    merge_risky_actions(node.risky_actions.take(), p.risky_actions.join(", "));
                node.enrichment.get_or_insert_with(|| {
                    enrichment_summary(
                        p.holders.len(),
                        p.instance_profiles.len(),
                        p.trust_principals.len(),
                        p.associations.len(),
                    )
                });
                if hop.arn == p.arn {
                    node.user_posture = p.user_attributes.as_ref();
                }
            }
        }
        for window in p.path.windows(2) {
            edges.push((&window[0].arn, &window[1].arn, p.conditional));
        }
    }

    render_escalation_dot(graph_name, nodes, &edges)
}

/// Render `who-can` results as a DOT digraph: one central node for the queried action,
/// with an edge from every matching entity to it. Entities are colored by risk —
/// full-admin grants in red, conditional grants in amber, everything else neutral.
pub fn who_can_to_dot(graph_name: &str, action: &str, entities: &[EntityRef]) -> String {
    let mut out = String::new();
    writeln!(out, "digraph {} {{", quoted(graph_name)).unwrap();
    writeln!(out, "  rankdir=LR;").unwrap();
    writeln!(
        out,
        "  node [shape=box, style=filled, fontname=\"Helvetica\"];"
    )
    .unwrap();
    writeln!(
        out,
        "  __action__ [shape=diamond, fillcolor=\"#cfe8ff\", label={}];",
        quoted(action)
    )
    .unwrap();

    for e in entities {
        let fillcolor = if e.is_full_admin {
            RISK_FILL
        } else if e.conditional {
            CONDITIONAL_FILL
        } else {
            DEFAULT_FILL
        };
        let mut label = format!("{}\\n({})", escape(&e.name), escape(&e.entity_type));
        if e.is_full_admin {
            label.push_str("\\n[full-admin]");
        }
        if e.is_bounded {
            label.push_str("\\n[bounded]");
        }
        writeln!(
            out,
            "  {} [label={}, fillcolor={}];",
            quoted(&e.arn),
            quoted(&label),
            quoted(fillcolor)
        )
        .unwrap();

        let style = if e.conditional {
            format!(", style=dashed, color={}", quoted(CONDITIONAL_EDGE_COLOR))
        } else {
            String::new()
        };
        writeln!(
            out,
            "  {} -> __action__ [label={}{}];",
            quoted(&e.arn),
            quoted(&e.resource),
            style
        )
        .unwrap();
    }

    writeln!(out, "}}").unwrap();
    out
}

fn write_edges(out: &mut String, edges: &[(&str, &str, bool)]) {
    for (from, to, conditional) in edges {
        let style = if *conditional {
            format!(", style=dashed, color={}", quoted(CONDITIONAL_EDGE_COLOR))
        } else {
            String::new()
        };
        writeln!(
            out,
            "  {} -> {} [label=\"CAN_ASSUME\"{}];",
            quoted(from),
            quoted(to),
            style
        )
        .unwrap();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iam_graph::Hop;

    fn hop(arn: &str, entity_type: &str) -> Hop {
        Hop {
            arn: arn.to_string(),
            entity_type: entity_type.to_string(),
        }
    }

    #[test]
    fn escalation_paths_to_dot_empty_produces_empty_graph() {
        let dot = escalation_paths_to_dot("privilege_escalation", &[]);
        assert_eq!(dot, "digraph \"privilege_escalation\" {\n  rankdir=LR;\n  node [shape=box, style=filled, fontname=\"Helvetica\", fillcolor=\"#e8e8e8\"];\n}\n");
    }

    #[test]
    fn escalation_paths_to_dot_single_hop_has_node_but_no_edge() {
        let paths = vec![EscalationPath {
            arn: "arn:aws:iam::111111111111:user/alice".to_string(),
            name: "alice".to_string(),
            entity_type: "User".to_string(),
            risky_actions: vec!["iam:PutUserPolicy".to_string()],
            matched_paths: vec!["put-user-policy".to_string()],
            path: vec![hop("arn:aws:iam::111111111111:user/alice", "User")],
            conditional: false,
            holders: vec![],
            instance_profiles: vec![],
            trust_principals: vec![],
            user_attributes: None,
            associations: vec![],
        }];

        let dot = escalation_paths_to_dot("privilege_escalation", &paths);

        assert!(dot.contains("\"arn:aws:iam::111111111111:user/alice\""));
        assert!(dot.contains("iam:PutUserPolicy"));
        assert!(!dot.contains("->"));
    }

    #[test]
    fn escalation_paths_to_dot_multi_hop_chain_has_edges() {
        let paths = vec![EscalationPath {
            arn: "arn:aws:iam::111111111111:role/A".to_string(),
            name: "A".to_string(),
            entity_type: "Role".to_string(),
            risky_actions: vec!["iam:CreateAccessKey".to_string()],
            matched_paths: vec!["create-access-key".to_string()],
            path: vec![
                hop("arn:aws:iam::111111111111:role/A", "Role"),
                hop("arn:aws:iam::111111111111:role/B", "Role"),
                hop("arn:aws:iam::111111111111:role/C", "Role"),
            ],
            conditional: true,
            holders: vec![],
            instance_profiles: vec![],
            trust_principals: vec![],
            user_attributes: None,
            associations: vec![],
        }];

        let dot = escalation_paths_to_dot("privilege_escalation", &paths);

        assert_eq!(dot.matches("->").count(), 2);
        assert!(dot.contains("style=dashed"));
        // Only the terminal node (C) carries the risky-action tooltip.
        assert_eq!(dot.matches("iam:CreateAccessKey").count(), 1);
        assert!(dot.contains("role/C"));
    }

    #[test]
    fn escalation_paths_to_dot_merges_risky_actions_on_shared_terminal_node() {
        let paths = vec![
            EscalationPath {
                arn: "arn:aws:iam::111111111111:role/A".to_string(),
                name: "A".to_string(),
                entity_type: "Role".to_string(),
                risky_actions: vec!["iam:PutUserPolicy".to_string()],
                matched_paths: vec!["put-user-policy".to_string()],
                path: vec![
                    hop("arn:aws:iam::111111111111:role/A", "Role"),
                    hop("arn:aws:iam::111111111111:role/C", "Role"),
                ],
                conditional: false,
                holders: vec![],
                instance_profiles: vec![],
                trust_principals: vec![],
                user_attributes: None,
                associations: vec![],
            },
            EscalationPath {
                arn: "arn:aws:iam::111111111111:role/B".to_string(),
                name: "B".to_string(),
                entity_type: "Role".to_string(),
                risky_actions: vec!["iam:CreateAccessKey".to_string()],
                matched_paths: vec!["create-access-key".to_string()],
                path: vec![
                    hop("arn:aws:iam::111111111111:role/B", "Role"),
                    hop("arn:aws:iam::111111111111:role/C", "Role"),
                ],
                conditional: false,
                holders: vec![],
                instance_profiles: vec![],
                trust_principals: vec![],
                user_attributes: None,
                associations: vec![],
            },
        ];

        let dot = escalation_paths_to_dot("privilege_escalation", &paths);

        assert!(dot.contains("iam:PutUserPolicy, iam:CreateAccessKey"));
    }

    #[test]
    fn who_can_to_dot_empty_still_renders_action_node() {
        let dot = who_can_to_dot("who_can", "s3:GetObject", &[]);
        assert!(dot.contains("__action__"));
        assert!(dot.contains("s3:GetObject"));
        assert!(!dot.contains("->"));
    }

    #[test]
    fn who_can_to_dot_flags_full_admin_and_conditional_entities() {
        let entities = vec![
            EntityRef {
                arn: "arn:aws:iam::111111111111:role/Admin".to_string(),
                name: "Admin".to_string(),
                entity_type: "Role".to_string(),
                is_full_admin: true,
                resource: "*".to_string(),
                is_bounded: false,
                conditional: false,
                unevaluated_condition_keys: vec![],
            },
            EntityRef {
                arn: "arn:aws:iam::111111111111:role/Conditional".to_string(),
                name: "Conditional".to_string(),
                entity_type: "Role".to_string(),
                is_full_admin: false,
                resource: "arn:aws:s3:::bucket/*".to_string(),
                is_bounded: false,
                conditional: true,
                unevaluated_condition_keys: vec!["aws:SourceIp".to_string()],
            },
        ];

        let dot = who_can_to_dot("who_can", "s3:GetObject", &entities);

        assert!(dot.contains("[full-admin]"));
        assert!(dot.contains(RISK_FILL));
        assert!(dot.contains(CONDITIONAL_FILL));
        assert_eq!(dot.matches("->").count(), 2);
    }

    #[test]
    fn arn_with_quotes_and_backslashes_is_escaped() {
        let entities = vec![EntityRef {
            arn: "arn:aws:iam::111111111111:role/weird\"name\\here".to_string(),
            name: "weird\"name\\here".to_string(),
            entity_type: "Role".to_string(),
            is_full_admin: false,
            resource: "*".to_string(),
            is_bounded: false,
            conditional: false,
            unevaluated_condition_keys: vec![],
        }];

        let dot = who_can_to_dot("who_can", "s3:GetObject", &entities);

        assert!(dot.contains("weird\\\"name\\\\here"));
    }

    #[test]
    fn org_escalation_paths_to_dot_labels_account_id() {
        let paths = vec![OrgEscalationPath {
            arn: "arn:aws:iam::111111111111:role/A".to_string(),
            name: "A".to_string(),
            entity_type: "Role".to_string(),
            account_id: "111111111111".to_string(),
            risky_actions: vec!["iam:PassRole".to_string()],
            matched_paths: vec!["pass-role".to_string()],
            path: vec![
                iam_graph::OrgHop {
                    arn: "arn:aws:iam::111111111111:role/A".to_string(),
                    entity_type: "Role".to_string(),
                    account_id: "111111111111".to_string(),
                    snapshot_id: "snap-1".to_string(),
                },
                iam_graph::OrgHop {
                    arn: "arn:aws:iam::222222222222:role/B".to_string(),
                    entity_type: "Role".to_string(),
                    account_id: "222222222222".to_string(),
                    snapshot_id: "snap-2".to_string(),
                },
            ],
            conditional: false,
            holders: vec![],
            instance_profiles: vec![],
            trust_principals: vec![],
            user_attributes: None,
            associations: vec![],
        }];

        let dot = org_escalation_paths_to_dot("org_escalation", &paths);

        assert!(dot.contains("[111111111111]"));
        assert!(dot.contains("[222222222222]"));
        assert_eq!(dot.matches("->").count(), 1);
    }
}
