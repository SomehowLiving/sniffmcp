#!/usr/bin/env bash
# Self-healing daily crawl. Run it often (cron: every 30 min and @reboot). It crawls only when the
# last successful crawl is older than SNIFFMCP_CRAWL_EVERY_H hours (default 20), so a laptop that
# slept or was off at the usual time catches up as soon as it's back, instead of losing the day.
#
# Optional: SNIFFMCP_BACKUP_DIR=/path  -> consistent copy of crawl.db after each run, last 7 kept.
set -uo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
HOME_DIR="${SNIFFMCP_HOME:-$HOME/.sniffmcp}"
STAMP="$HOME_DIR/last-crawl-ok"
LOG="$HOME_DIR/crawl.log"
EVERY_H="${SNIFFMCP_CRAWL_EVERY_H:-20}"
mkdir -p "$HOME_DIR"

# A crawl started by hand counts as running ("ru[n]" keeps pgrep from matching itself).
if pgrep -f "sniffmcp crawl ru[n]" >/dev/null; then exit 0; fi

if [ -f "$STAMP" ] && [ $(( $(date +%s) - $(stat -c %Y "$STAMP") )) -lt $(( EVERY_H * 3600 )) ]; then
  exit 0
fi

exec 9>"$HOME_DIR/crawl.lock"
flock -n 9 || exit 0    # another wrapper is already crawling

cd "$REPO" || exit 1
echo "=== $(date -u +%FT%TZ) crawl start" >> "$LOG"
if .venv/bin/sniffmcp crawl run --output "reports/crawl-$(date +%F).md" >> "$LOG" 2>&1; then
  touch "$STAMP"
  echo "=== $(date -u +%FT%TZ) crawl ok" >> "$LOG"
  if [ -n "${SNIFFMCP_BACKUP_DIR:-}" ]; then
    mkdir -p "$SNIFFMCP_BACKUP_DIR"
    .venv/bin/python - "$HOME_DIR/crawl.db" "$SNIFFMCP_BACKUP_DIR/crawl-$(date +%F).db" <<'PY' >> "$LOG" 2>&1
import sqlite3, sys
src, dst = sys.argv[1], sys.argv[2]
with sqlite3.connect(src) as a, sqlite3.connect(dst) as b:
    a.backup(b)          # consistent online copy, safe while nothing else writes
print(f"backup ok: {dst}")
PY
    ls -1t "$SNIFFMCP_BACKUP_DIR"/crawl-*.db 2>/dev/null | tail -n +8 | xargs -r rm -f
  fi
else
  echo "=== $(date -u +%FT%TZ) crawl FAILED (will retry next tick)" >> "$LOG"
fi
