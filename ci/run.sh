#!/usr/bin/env bash
# Everything CI runs, locally. Use it before a commit.
set -euo pipefail
cd "$(dirname "$0")/.."

echo "== formatting =="
cargo fmt --all -- --check

echo "== clippy (warnings are errors) =="
cargo clippy --all-targets -- -D warnings

echo "== tests =="
cargo test --all-targets

echo "== tests with the serial feature (COM adapter) =="
cargo test --all-targets --features serial

if command -v lean >/dev/null 2>&1; then
  echo "== lean =="
  lean lean/Redoubt.lean
  echo "lean: exit 0"
else
  echo "== lean: not installed, skipped =="
fi
