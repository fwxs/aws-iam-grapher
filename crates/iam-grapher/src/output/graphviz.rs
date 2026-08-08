//! Graphviz DOT rendering for graph-shaped query results (escalation paths, who-can).
//!
//! Only a subset of query results are graph-shaped enough to be worth rendering as DOT;
//! see `cli/query.rs` for which subcommands wire this in.

use iam_graph::{EntityRef, EscalationPath, OrgEscalationPath};
use std::collections::BTreeMap;
use std::fmt::Write as _;

const RISK_FILL: &str = "#f8d7da";
const CONDITIONAL_FILL: &str = "#fff3cd";
const DEFAULT_FILL: &str = "#e8e8e8";
const CONDITIONAL_EDGE_COLOR: &str = "#d9822b";

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

/// Render privilege-escalation paths as a DOT digraph: one node per entity that
/// appears on any path, edges following each path's `CAN_ASSUME_ROLE` chain, and the
/// risk-holding terminal node of each path highlighted with its risky actions.
/// Conditional paths (unresolved runtime trust conditions) render with dashed, colored edges.
pub fn escalation_paths_to_dot(graph_name: &str, paths: &[EscalationPath]) -> String {
    struct Node {
        entity_type: String,
        risky_actions: Option<String>,
    }

    let mut nodes: BTreeMap<&str, Node> = BTreeMap::new();
    let mut edges: Vec<(&str, &str, bool)> = Vec::new();

    for p in paths {
        let terminal_arn = p.path.last().map(|h| h.arn.as_str()).unwrap_or(&p.arn);
        for hop in &p.path {
            let node = nodes.entry(&hop.arn).or_insert_with(|| Node {
                entity_type: hop.entity_type.clone(),
                risky_actions: None,
            });
            if hop.arn == terminal_arn {
                node.risky_actions = Some(p.risky_actions.join(", "));
            }
        }
        for window in p.path.windows(2) {
            edges.push((&window[0].arn, &window[1].arn, p.conditional));
        }
    }

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
        let label = format!(
            "{}\\n({})",
            escape(short_name(arn)),
            escape(&node.entity_type)
        );
        let mut attrs = format!("label={}", quoted(&label));
        if let Some(actions) = &node.risky_actions {
            write!(
                attrs,
                ", fillcolor={}, tooltip={}",
                quoted(RISK_FILL),
                quoted(actions)
            )
            .unwrap();
        }
        writeln!(out, "  {} [{}];", quoted(arn), attrs).unwrap();
    }

    write_edges(&mut out, &edges);
    writeln!(out, "}}").unwrap();
    out
}

/// Render cross-account escalation paths as a DOT digraph, same shape as
/// [`escalation_paths_to_dot`] but with each node labeled with its account id.
pub fn org_escalation_paths_to_dot(graph_name: &str, paths: &[OrgEscalationPath]) -> String {
    struct Node {
        entity_type: String,
        account_id: String,
        risky_actions: Option<String>,
    }

    let mut nodes: BTreeMap<&str, Node> = BTreeMap::new();
    let mut edges: Vec<(&str, &str, bool)> = Vec::new();

    for p in paths {
        let terminal_arn = p.path.last().map(|h| h.arn.as_str()).unwrap_or(&p.arn);
        for hop in &p.path {
            let node = nodes.entry(&hop.arn).or_insert_with(|| Node {
                entity_type: hop.entity_type.clone(),
                account_id: hop.account_id.clone(),
                risky_actions: None,
            });
            if hop.arn == terminal_arn {
                node.risky_actions = Some(p.risky_actions.join(", "));
            }
        }
        for window in p.path.windows(2) {
            edges.push((&window[0].arn, &window[1].arn, p.conditional));
        }
    }

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
        let label = format!(
            "{}\\n({})\\n[{}]",
            escape(short_name(arn)),
            escape(&node.entity_type),
            escape(&node.account_id)
        );
        let mut attrs = format!("label={}", quoted(&label));
        if let Some(actions) = &node.risky_actions {
            write!(
                attrs,
                ", fillcolor={}, tooltip={}",
                quoted(RISK_FILL),
                quoted(actions)
            )
            .unwrap();
        }
        writeln!(out, "  {} [{}];", quoted(arn), attrs).unwrap();
    }

    write_edges(&mut out, &edges);
    writeln!(out, "}}").unwrap();
    out
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
            path: vec![hop("arn:aws:iam::111111111111:user/alice", "User")],
            conditional: false,
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
            path: vec![
                hop("arn:aws:iam::111111111111:role/A", "Role"),
                hop("arn:aws:iam::111111111111:role/B", "Role"),
                hop("arn:aws:iam::111111111111:role/C", "Role"),
            ],
            conditional: true,
        }];

        let dot = escalation_paths_to_dot("privilege_escalation", &paths);

        assert_eq!(dot.matches("->").count(), 2);
        assert!(dot.contains("style=dashed"));
        // Only the terminal node (C) carries the risky-action tooltip.
        assert_eq!(dot.matches("iam:CreateAccessKey").count(), 1);
        assert!(dot.contains("role/C"));
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
            path: vec![
                iam_graph::OrgHop {
                    arn: "arn:aws:iam::111111111111:role/A".to_string(),
                    entity_type: "Role".to_string(),
                    account_id: "111111111111".to_string(),
                },
                iam_graph::OrgHop {
                    arn: "arn:aws:iam::222222222222:role/B".to_string(),
                    entity_type: "Role".to_string(),
                    account_id: "222222222222".to_string(),
                },
            ],
            conditional: false,
        }];

        let dot = org_escalation_paths_to_dot("org_escalation", &paths);

        assert!(dot.contains("[111111111111]"));
        assert!(dot.contains("[222222222222]"));
        assert_eq!(dot.matches("->").count(), 1);
    }
}
