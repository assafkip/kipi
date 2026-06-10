#!/usr/bin/env bash
# Deterministic secrets + export-boundary audit (issue oss-secrets-audit,
# PRD oss-release-readiness). Exit 0 = clean; exit 1 = violations, each named.
#
# What it enforces over `git ls-files` (the tracked tree — never reads .env
# contents; the security rule stands):
#   1. No tracked .env* file except .env.example
#   2. No tracked SQLite database (by extension AND by magic bytes)
#   3. No tracked file carrying a live-looking credential (sk-ant-, AWS AKIA,
#      ghp_/github_pat_, private key blocks) — placeholder values allowed
#   4. .env.example carries no real-looking key material
# Plus the EXPORT-BOUNDARY REPORT (informational unless --strict-export):
#   founder-OS directories + ignored/untracked sensitive files a naive
#   copy-export (cp -r, not git archive) would leak into a public release.
set -uo pipefail

cd "$(git rev-parse --show-toplevel)"
FAIL=0
say()  { printf '%s\n' "$*"; }
bad()  { printf 'VIOLATION: %s\n' "$*"; FAIL=1; }

say "== kipi OSS secrets audit =="

# --- 1. tracked .env* -------------------------------------------------------
while IFS= read -r f; do
  [ "$f" = ".env.example" ] && continue
  bad "tracked env file: $f"
done < <(git ls-files | grep -E '(^|/)\.env(\.|$)' || true)

# --- 2. tracked databases (extension + sqlite magic) ------------------------
while IFS= read -r f; do
  bad "tracked database file: $f"
done < <(git ls-files | grep -E '\.(db|sqlite3?|db-wal|db-shm)$' || true)

while IFS= read -r f; do
  [ -f "$f" ] || continue
  if head -c 16 "$f" 2>/dev/null | grep -q "SQLite format 3"; then
    case "$f" in *.db|*.sqlite|*.sqlite3) ;; *) bad "sqlite content under non-db extension: $f" ;; esac
  fi
done < <(git ls-files || true)

# --- 3. live-looking credentials in tracked files ---------------------------
# Patterns chosen for near-zero false positives; docs may show placeholders
# like sk-ant-... / sk-ant-xxxx (allowlisted by the trailing-char check).
CRED_PATTERNS=(
  'sk-ant-[A-Za-z0-9_-]{20,}'
  'AKIA[0-9A-Z]{16}'
  'ghp_[A-Za-z0-9]{30,}'
  'github_pat_[A-Za-z0-9_]{30,}'
  '-----BEGIN ((RSA|EC|OPENSSH|DSA|ENCRYPTED) )?PRIVATE KEY-----'
)
for pat in "${CRED_PATTERNS[@]}"; do
  while IFS= read -r hit; do
    f="${hit%%:*}"
    bad "credential-pattern '$pat' in tracked file: $f"
  done < <(git grep -I -E -l -e "$pat" 2>/dev/null || true)
done

# --- 4. .env.example carries placeholders only ------------------------------
if git ls-files --error-unmatch .env.example >/dev/null 2>&1; then
  # Catch quoted values, export prefixes, and trailing comments too — not just
  # bare end-of-line values.
  if git show ":.env.example" | grep -E "=[\"']?[A-Za-z0-9_/+-]{32,}" >/dev/null 2>&1; then
    bad ".env.example contains a real-looking (32+ char) value — use placeholders"
  fi
fi

# --- export-boundary report --------------------------------------------------
say ""
say "== export boundary (founder-OS content a naive copy-export would leak) =="
for d in q-system .claude .prd-os plugins memory my-project .agents; do
  if [ -e "$d" ]; then
    say "  NON-EXPORT dir present: $d/"
  fi
done
# Ignored/untracked sensitive files in the worktree (cp -r would take them;
# git archive would not — publish via git, never via cp). git status collapses
# ignored DIRECTORIES to one entry, hiding descendants like data/prod.db — so
# directory entries are expanded with a bounded find before filtering.
while IFS= read -r f; do
  say "  untracked/ignored sensitive file in worktree: $f"
done < <(git status --ignored --porcelain 2>/dev/null \
         | awk '$1 == "!!" || $1 == "??" {print $2}' \
         | while IFS= read -r entry; do
             case "$entry" in
               (*/) find "$entry" -maxdepth 3 -type f 2>/dev/null | head -200 ;;
               (*)  printf '%s\n' "$entry" ;;
             esac
           done \
         | grep -E '(^|/)\.env|\.(db|sqlite3?|db-wal|db-shm|pem|key)$|inbox/|vault/|assets/' \
         | head -40 || true)
say "  (publish via 'git archive' / a clean clone — NEVER a worktree copy)"

say ""
if [ "$FAIL" -eq 0 ]; then
  say "AUDIT CLEAN"
else
  say "AUDIT FAILED — fix the violations above before any publish step"
fi
exit "$FAIL"
