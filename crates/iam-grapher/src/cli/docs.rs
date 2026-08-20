use anyhow::{bail, Context};
use clap::Args;
use std::path::{Path, PathBuf};

/// Prints bundled docs (`caveats`, `limitations`, ...) from the installed docs directory.
#[derive(Args)]
pub struct DocsArgs {
    /// Doc name to print (filename minus `.md`). Omit to list available docs.
    pub name: Option<String>,
}

pub async fn run(args: DocsArgs) -> anyhow::Result<()> {
    let dir = resolve_docs_dir();
    match args.name {
        None => {
            let names = list_docs(&dir)
                .with_context(|| format!("failed to list docs in {}", dir.display()))?;
            for name in names {
                println!("{name}");
            }
        }
        Some(name) => {
            let contents = read_doc(&dir, &name)?;
            println!("{contents}");
        }
    }
    Ok(())
}

fn resolve_docs_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("AWS_IAM_GRAPHER_DOCS_DIR") {
        return PathBuf::from(dir);
    }
    if let Some(home) = dirs_home() {
        let installed = home.join(".aws-iam-grapher").join("docs");
        if installed.is_dir() {
            return installed;
        }
    }
    // Fallback for `cargo run` from a repo checkout, where no install has happened yet.
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../docs")
}

fn dirs_home() -> Option<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from)
}

fn list_docs(dir: &Path) -> anyhow::Result<Vec<String>> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .with_context(|| format!("cannot read docs directory {}", dir.display()))?
        .filter_map(|entry| entry.ok())
        .filter_map(|entry| {
            let path = entry.path();
            if path.extension().and_then(|extension| extension.to_str()) == Some("md") {
                path.file_stem()
                    .and_then(|stem| stem.to_str())
                    .map(str::to_string)
            } else {
                None
            }
        })
        .collect();
    names.sort();
    Ok(names)
}

fn read_doc(dir: &Path, name: &str) -> anyhow::Result<String> {
    if name.is_empty()
        || !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        bail!("invalid doc name '{name}': only letters, digits, '-' and '_' are allowed");
    }

    let path = dir.join(format!("{name}.md"));
    let canonical_dir = std::fs::canonicalize(dir)
        .with_context(|| format!("cannot read docs directory {}", dir.display()))?;
    let canonical_path = std::fs::canonicalize(&path)
        .map_err(|_| anyhow::anyhow!(unknown_doc_message(dir, name)))?;
    if !canonical_path.starts_with(&canonical_dir) {
        bail!("invalid doc name '{name}'");
    }

    std::fs::read_to_string(&canonical_path)
        .with_context(|| format!("failed to read {}", canonical_path.display()))
}

fn unknown_doc_message(dir: &Path, name: &str) -> String {
    let available = list_docs(dir)
        .map(|names| names.join(", "))
        .unwrap_or_default();
    format!("unknown doc '{name}'. Available docs: {available}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_fixture_docs(dir: &Path) {
        std::fs::write(dir.join("caveats.md"), "# Caveats\n").unwrap();
        std::fs::write(dir.join("limitations.md"), "# Limitations\n").unwrap();
        std::fs::write(dir.join("not-a-doc.txt"), "ignored").unwrap();
    }

    #[test]
    fn list_docs_returns_sorted_md_stems_only() {
        let temp = tempfile::tempdir().unwrap();
        write_fixture_docs(temp.path());

        let names = list_docs(temp.path()).unwrap();

        assert_eq!(names, vec!["caveats", "limitations"]);
    }

    #[test]
    fn read_doc_returns_contents_for_known_name() {
        let temp = tempfile::tempdir().unwrap();
        write_fixture_docs(temp.path());

        let contents = read_doc(temp.path(), "caveats").unwrap();

        assert_eq!(contents, "# Caveats\n");
    }

    #[test]
    fn read_doc_unknown_name_lists_available_docs_in_error() {
        let temp = tempfile::tempdir().unwrap();
        write_fixture_docs(temp.path());

        let error = read_doc(temp.path(), "nonexistent").unwrap_err();

        let message = error.to_string();
        assert!(message.contains("unknown doc 'nonexistent'"));
        assert!(message.contains("caveats"));
        assert!(message.contains("limitations"));
    }

    #[test]
    fn read_doc_rejects_path_traversal() {
        let temp = tempfile::tempdir().unwrap();
        write_fixture_docs(temp.path());

        let error = read_doc(temp.path(), "../../../etc/passwd");

        assert!(error.is_err());
    }

    #[test]
    fn read_doc_rejects_non_allowlisted_characters() {
        let temp = tempfile::tempdir().unwrap();
        write_fixture_docs(temp.path());

        let error = read_doc(temp.path(), "caveats/../limitations");

        assert!(error.is_err());
    }
}
