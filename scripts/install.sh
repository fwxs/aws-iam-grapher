#!/usr/bin/env bash
# Builds a release binary and installs it, plus the repo's docs/ and
# scripts/{neo4j-backup,neo4j-restore}.sh, under ~/.aws-iam-grapher/.
#
# Usage (local checkout): scripts/install.sh
# Usage (curl-pipeable):  curl -fsSL <raw-install.sh-url> | bash
#
# When run outside a local checkout (e.g. piped through `bash`), clones the
# repo into a temp dir under /tmp and builds from there; the clone is removed
# on exit regardless of success or failure.
set -euo pipefail

repo_url="https://github.com/fwxs/aws-iam-grapher.git"
repo_ref="main"
install_dir="$HOME/.aws-iam-grapher"
bin_dir="$install_dir/bin"
docs_dir="$install_dir/docs"
scripts_dir="$install_dir/scripts"
config_dir="$install_dir/config"

repo_root=""
tmp_clone=""
cleanup() {
  if [[ -n "$tmp_clone" && -d "$tmp_clone" ]]; then
    rm -rf "$tmp_clone"
  fi
}
trap cleanup EXIT

# BASH_SOURCE[0] is unset/"bash" when the script is read from a pipe (curl | bash).
if [[ -n "${BASH_SOURCE[0]:-}" && -f "${BASH_SOURCE[0]}" ]]; then
  repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fi

if [[ -z "$repo_root" ]]; then
  tmp_clone="$(mktemp -d)"
  echo "Cloning $repo_url ($repo_ref) into $tmp_clone..."
  git clone --depth 1 --branch "$repo_ref" "$repo_url" "$tmp_clone"
  repo_root="$tmp_clone"
fi

mkdir -p "$bin_dir" "$docs_dir/queries" "$scripts_dir" "$config_dir"

echo "Copying docs to $docs_dir..."
cp "$repo_root"/docs/*.md "$docs_dir/"
cp "$repo_root"/docs/queries/*.md "$docs_dir/queries/"

echo "Copying neo4j backup/restore scripts to $scripts_dir..."
cp "$repo_root/scripts/neo4j-backup.sh" "$repo_root/scripts/neo4j-restore.sh" "$scripts_dir/"
chmod +x "$scripts_dir/neo4j-backup.sh" "$scripts_dir/neo4j-restore.sh"

if [[ ! -f "$config_dir/risky-actions.yaml" ]]; then
  echo "Installing default risky-actions config to $config_dir..."
  cp "$repo_root/config/risky-actions.yaml" "$config_dir/risky-actions.yaml"
else
  echo "risky-actions.yaml already exists at $config_dir, not overwriting."
  echo "  Repo's shipped copy for comparison: $repo_root/config/risky-actions.yaml"
fi

echo "Building release binary..."
(cd "$repo_root" && cargo build --release)

echo "Installing binary to $bin_dir..."
mv "$repo_root/target/release/aws-iam-grapher" "$bin_dir/aws-iam-grapher"

echo
echo "Installed: $bin_dir/aws-iam-grapher"
echo "Docs bundled at: $docs_dir"
echo "Neo4j backup/restore scripts at: $scripts_dir"
echo "Risky-actions config at: $config_dir/risky-actions.yaml"
echo

case "$(uname -s)" in
  Linux*|Darwin*)
    case "$(basename "${SHELL:-}")" in
      zsh) rc_file="~/.zshrc" ;;
      *) rc_file="~/.bashrc" ;;
    esac
    echo "Add $bin_dir to your PATH by appending this line to $rc_file:"
    echo
    echo "  export PATH=\"\$HOME/.aws-iam-grapher/bin:\$PATH\""
    echo
    echo "Then reload with: source $rc_file"
    ;;
  MINGW*|MSYS*|CYGWIN*)
    echo "Detected Windows (Git Bash/MSYS). Add $bin_dir to your PATH with one of:"
    echo
    echo "  setx PATH \"%PATH%;%USERPROFILE%\\.aws-iam-grapher\\bin\""
    echo
    echo "or via System Properties > Environment Variables > Path > New, and add:"
    echo "  %USERPROFILE%\\.aws-iam-grapher\\bin"
    ;;
  *)
    echo "Add $bin_dir to your PATH using your OS's standard mechanism."
    ;;
esac
