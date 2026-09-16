#!/bin/sh
# Checks for the mac-gate crate, in order: language of code, formatter,
# linter, compiler, tests. The crate has no features and builds only for the
# macOS host it runs on, so there are no narrow or cross builds. Does not
# modify the tree.
set -eu
cd "$(dirname "$0")"

# Code, comments and manifests are English; prose in README.md and docs/ is not
# checked here.
if git grep -I -n -P '[\x{0400}-\x{04FF}]' -- \
    src Cargo.toml clippy.toml rust-toolchain.toml check.sh awg3-server.sh .gitignore .github; then
    echo "non-English text in code or manifests" >&2
    exit 1
fi

cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo check --workspace --all-targets --all-features
cargo test --workspace --all-features
echo "checks passed"
