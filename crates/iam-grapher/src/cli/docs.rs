use crate::exit_code::CliValidationError;
use crate::output::OutputFormat;
use anyhow::Context;
use clap::Args;
use serde::Serialize;
use std::path::{Path, PathBuf};

/// Prints bundled docs (`caveats`, `limitations`, ...) from the installed docs directory.
#[derive(Args)]
pub struct DocsArgs {
    /// Doc name to print (filename minus `.md`). Omit to list available docs.
    pub name: Option<String>,
}

#[derive(Serialize)]
struct DocsList {
    docs: Vec<String>,
}

#[derive(Serialize)]
struct DocContent {
    name: String,
    content: String,
}

pub async fn run(args: DocsArgs, output: OutputFormat) -> anyhow::Result<()> {
    let dir = resolve_docs_dir();
    match args.name {
        None => {
            let names = list_docs(&dir)
                .with_context(|| format!("failed to list docs in {}", dir.display()))?;
            if output == OutputFormat::Json {
                crate::output::json::print_json(&DocsList { docs: names })?;
            } else {
                for name in names {
                    println!("{name}");
                }
            }
        }
        Some(name) => {
            let contents = read_doc(&dir, &name)?;
            if output == OutputFormat::Json {
                crate::output::json::print_json(&DocContent {
                    name,
                    content: contents,
                })?;
            } else {
                println!("{contents}");
            }
        }
    }
    Ok(())
}

fn resolve_docs_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("AWS_IAM_GRAPHER_DOCS_DIR") {
        return PathBuf::from(dir);
    }
    let installed = dirs_home().map(|home| home.join(".aws-iam-grapher").join("docs"));
    if let Some(installed) = &installed {
        if installed.is_dir() {
            return installed.clone();
        }
    }
    // Fallback for `cargo run` from a repo checkout, where no install has happened yet.
    // Only used if it actually exists — on a machine where the binary was built elsewhere
    // (e.g. `cargo install`), this compiled-in build path won't exist, so fall through to
    // the installed-docs path instead and let the caller report a clear "not found" error
    // against the location a user would actually expect.
    let repo_checkout = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../docs");
    if repo_checkout.is_dir() {
        return repo_checkout;
    }
    installed.unwrap_or(repo_checkout)
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
        return Err(CliValidationError::DocsInvalidName {
            name: name.to_string(),
        }
        .into());
    }

    let path = dir.join(format!("{name}.md"));
    let canonical_dir = std::fs::canonicalize(dir)
        .with_context(|| format!("cannot read docs directory {}", dir.display()))?;
    let canonical_path = match std::fs::canonicalize(&path) {
        Ok(canonical_path) => canonical_path,
        Err(_) => {
            return Err(CliValidationError::DocsUnknownName {
                name: name.to_string(),
                available: available_docs(dir)?,
            }
            .into());
        }
    };
    if !canonical_path.starts_with(&canonical_dir) {
        return Err(CliValidationError::DocsInvalidName {
            name: name.to_string(),
        }
        .into());
    }

    std::fs::read_to_string(&canonical_path)
        .with_context(|| format!("failed to read {}", canonical_path.display()))
}

fn available_docs(dir: &Path) -> anyhow::Result<String> {
    list_docs(dir).map(|names| names.join(", "))
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
