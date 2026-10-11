#!/usr/bin/env bash
# tests/gates/run.sh: the one entry point for the local verification gates of
# aien-protocols. Every step runs the SAME command as the hosted job it mirrors
# (.github/workflows/ci.yml, job "Workspace Verification & Invariant Audit").
# Manifests under tests/gates/ name this script plus one step word, so no
# manifest ever needs shell expansion (ADR 0028 P6). Observations are printed
# as "AIEN-OBS <name> <json>" lines (ADR 0028 Decision 5).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
step="${1:?usage: tests/gates/run.sh <step>}"
obs() { printf 'AIEN-OBS %s %s\n' "$1" "$2"; }

case "$step" in
  crumb-verify)
    # Hosted: no crumb job in this repo today; the trusted worker and the thin
    # gate both run `crumb verify .` (ADR 0033 Decision 11). The binary comes
    # from PATH here; the worker supplies the build pinned by the lane.
    "${CRUMB:-crumb}" verify .
    ;;
  fmt)
    cargo fmt --all -- --check
    ;;
  check)
    cargo check --workspace --all-targets
    ;;
  clippy)
    cargo clippy --workspace --all-targets -- -D warnings
    ;;
  test)
    cargo test --workspace --verbose
    ;;
  zero-disk-secrets)
    echo "Auditing repository for prohibited plaintext secret files..."
    if find . -maxdepth 4 -name ".env*" -not -path "*/.git/*" -not -path "*/target/*" | grep -q .; then
      echo "::error::Prohibited plaintext .env file found. Use an approved AIEN SecretProvider."
      obs env_files_found true
      exit 1
    fi
    obs env_files_found false
    echo "Zero plaintext .env files verified."
    ;;
  anti-slop)
    echo "Auditing repository for em dashes, en dashes, and formulaic tropes..."
    BAD_CHARS=$(grep -rnE --exclude-dir=target --exclude-dir=.git --exclude="*.rs" --exclude="*.json" --exclude="*.safetensors" "—|–" crates/ docs/ README.md ANTI_ENCLOSURE.md || true)
    if [ -n "$BAD_CHARS" ]; then
      echo "::error::Em dashes or en dashes detected:"
      echo "$BAD_CHARS"
      obs dash_hits "$(printf '%s\n' "$BAD_CHARS" | grep -c . )"
      exit 1
    fi
    obs dash_hits 0
    echo "Sovereign voice compliance verified."
    ;;
  *)
    echo "run.sh: unknown step '$step'" >&2
    exit 2
    ;;
esac
