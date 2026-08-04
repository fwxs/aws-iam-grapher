/// Headers + rows for a table, decoupled from any specific query result type.
pub struct RenderSpec {
    pub headers: &'static [&'static str],
    pub rows: Vec<Vec<String>>,
}

/// Format rows as a left-aligned table with a header separator line.
/// `headers` — column names; `rows` — each row is a slice of cells matching headers length.
pub fn format_table(headers: &[&str], rows: &[Vec<String>]) -> String {
    use std::fmt::Write as _;

    // Compute column widths as max of header width and widest cell
    let mut widths: Vec<usize> = headers.iter().map(|h| h.len()).collect();
    for row in rows {
        for (i, cell) in row.iter().enumerate() {
            if i < widths.len() {
                widths[i] = widths[i].max(cell.len());
            }
        }
    }

    let mut out = String::new();

    // Header
    for (i, h) in headers.iter().enumerate() {
        if i > 0 {
            out.push_str("  ");
        }
        write!(out, "{:<width$}", h, width = widths[i]).unwrap();
    }
    out.push('\n');

    // Separator
    for (i, w) in widths.iter().enumerate() {
        if i > 0 {
            out.push_str("  ");
        }
        for _ in 0..*w {
            out.push('\u{2500}');
        }
    }
    out.push('\n');

    // Data rows
    for row in rows {
        for (i, cell) in row.iter().enumerate() {
            if i > 0 {
                out.push_str("  ");
            }
            let w = widths.get(i).copied().unwrap_or(0);
            write!(out, "{:<width$}", cell, width = w).unwrap();
        }
        out.push('\n');
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_table_aligns_columns_to_widest_cell() {
        let headers = &["TYPE", "ARN"];
        let rows = vec![
            vec![
                "Role".to_string(),
                "arn:aws:iam::123:role/Short".to_string(),
            ],
            vec![
                "User".to_string(),
                "arn:aws:iam::123:user/AVeryLongUserName".to_string(),
            ],
        ];
        let output = format_table(headers, &rows);

        assert!(output.contains("TYPE"));
        assert!(output.contains("ARN"));
        assert!(output.contains("Role"));
        assert!(output.contains("arn:aws:iam::123:role/Short"));
    }

    #[test]
    fn format_table_empty_rows_shows_only_header() {
        let output = format_table(&["COL"], &[]);
        assert!(output.contains("COL"));
        // separator line present
        assert!(output.contains('\u{2500}'));
        // no data lines after separator
        let lines: Vec<&str> = output.trim_end().lines().collect();
        assert_eq!(lines.len(), 2); // header + separator
    }
}
