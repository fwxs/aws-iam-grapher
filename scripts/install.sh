#!/usr/bin/env bash
# Builds a release binary and installs it, plus the repo's docs/, under ~/.aws-iam-grapher/.
#
# Usage: scripts/install.sh
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
install_dir="$HOME/.aws-iam-grapher"
bin_dir="$install_dir/bin"
docs_dir="$install_dir/docs"

mkdir -p "$bin_dir" "$docs_dir/queries"

echo "Copying docs to $docs_dir..."
cp "$repo_root"/docs/*.md "$docs_dir/"
cp "$repo_root"/docs/queries/*.md "$docs_dir/queries/"

echo "Building release binary..."
(cd "$repo_root" && cargo build --release)

echo "Installing binary to $bin_dir..."
mv "$repo_root/target/release/aws-iam-grapher" "$bin_dir/aws-iam-grapher"

echo
echo "Installed: $bin_dir/aws-iam-grapher"
echo "Docs bundled at: $docs_dir"
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
