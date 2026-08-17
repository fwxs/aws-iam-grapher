use anyhow::Context as _;
use serde::Serialize;
use std::path::Path;

/// Serialize `value` to pretty-printed JSON and print to stdout.
pub fn print_json<T: serde::Serialize>(value: &T) -> anyhow::Result<()> {
    let s = serde_json::to_string_pretty(value)?;
    println!("{s}");
    Ok(())
}

#[derive(Serialize)]
struct ErrorEnvelope<'a> {
    error: ErrorBody<'a>,
}

#[derive(Serialize)]
struct ErrorBody<'a> {
    code: &'a str,
    message: String,
}

/// Print a `{"error": {"code": ..., "message": ...}}` envelope to stderr. `message` should
/// be the outermost error text only (never a full causal chain) — see
/// `exit_code::handle_error`. Falls back to a hand-written literal if serialization itself
/// fails (`code`/`message` are plain strings, so this should never happen in practice).
pub fn eprint_json_error(code: &str, message: &str) {
    let envelope = ErrorEnvelope {
        error: ErrorBody {
            code,
            message: message.to_string(),
        },
    };
    match serde_json::to_string_pretty(&envelope) {
        Ok(s) => eprintln!("{s}"),
        Err(_) => {
            eprintln!(
                r#"{{"error":{{"code":"unexpected","message":"failed to serialize error"}}}}"#
            );
        }
    }
}

/// Serialize `value` to pretty-printed JSON and write it to `path`.
pub fn write_json<T: serde::Serialize>(value: &T, path: &Path) -> anyhow::Result<()> {
    let s = serde_json::to_string_pretty(value)?;
    std::fs::write(path, s)
        .with_context(|| format!("failed to write JSON to {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    struct Sample {
        name: String,
        count: u32,
    }

    #[test]
    fn write_json_produces_roundtrippable_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("out.json");
        let value = Sample {
            name: "test".to_string(),
            count: 3,
        };

        write_json(&value, &path).unwrap();

        let contents = std::fs::read_to_string(&path).unwrap();
        let roundtripped: Sample = serde_json::from_str(&contents).unwrap();
        assert_eq!(roundtripped, value);
    }
}
