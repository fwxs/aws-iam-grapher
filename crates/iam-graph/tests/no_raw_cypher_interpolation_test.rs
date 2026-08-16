use std::fs;
use std::path::Path;

/// Guards issue #84: `render_hop_bound` in `queries/mod.rs` must be the only place in
/// this crate that interpolates a `{max_hops}` placeholder into a Cypher template.
/// A second `.replace("{max_hops}"` site elsewhere would bypass the clamp/assert that
/// make the interpolation auditable.
#[test]
fn max_hops_interpolation_is_confined_to_render_hop_bound() {
    let needle = ".replace(\"{max_hops}\"";
    let src_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut hits = Vec::new();

    visit_rs_files(&src_dir, &mut |path, contents| {
        for (line_no, line) in contents.lines().enumerate() {
            if line.contains(needle) {
                hits.push(format!("{}:{}", path.display(), line_no + 1));
            }
        }
    });

    assert!(
        !hits.is_empty(),
        "expected at least one `{{max_hops}}` interpolation site (inside \
         render_hop_bound in queries/mod.rs), found none"
    );
    assert!(
        hits.iter().all(|hit| hit.contains("queries/mod.rs")),
        "every `{{max_hops}}` interpolation site must live in queries/mod.rs \
         (the sanctioned render_hop_bound helper or its own tests), found: {hits:?}"
    );
}

fn visit_rs_files(dir: &Path, on_file: &mut impl FnMut(&Path, &str)) {
    let entries = fs::read_dir(dir).unwrap_or_else(|e| panic!("read_dir {dir:?}: {e}"));
    for entry in entries {
        let entry = entry.expect("dir entry");
        let path = entry.path();
        if path.is_dir() {
            visit_rs_files(&path, on_file);
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
            let contents =
                fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path:?}: {e}"));
            on_file(&path, &contents);
        }
    }
}
