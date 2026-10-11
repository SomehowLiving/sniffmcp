#!/usr/bin/env bash
# Self-healing daily crawl. Run it often (cron every 30 min + @reboot, and/or Windows Task Scheduler
# on WSL). It crawls only when the last successful crawl is older than SNIFFMCP_CRAWL_EVERY_H hours
# (default 20), so a laptop that slept or was off at the usual time catches up instead of losing
# the day. Never runs twice at once. Alerts (Windows toast on WSL) when a run fails or when no crawl
# has succeeded for SNIFFMCP_STALE_H hours (default 36).
#
# Optional: SNIFFMCP_BACKUP_DIR=/path  -> consistent copy of crawl.db after each run, last 7 kept.
set -uo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
HOME_DIR="${SNIFFMCP_HOME:-$HOME/.sniffmcp}"
STAMP="$HOME_DIR/last-crawl-ok"
ALERTED="$HOME_DIR/last-stale-alert"
LOG="$HOME_DIR/crawl.log"
EVERY_H="${SNIFFMCP_CRAWL_EVERY_H:-20}"
STALE_H="${SNIFFMCP_STALE_H:-36}"
NOTIFY="$REPO/scripts/notify-windows.sh"
mkdir -p "$HOME_DIR"

age_h() { [ -f "$1" ] && echo $(( ($(date +%s) - $(stat -c %Y "$1")) / 3600 )) || echo 99999; }

# keep the log bounded: rotate at 20 MB, keep one old copy
if [ -f "$LOG" ] && [ "$(stat -c %s "$LOG")" -gt 20000000 ]; then mv -f "$LOG" "$LOG.1"; fi

# Stale alert, at most every 12h, even while nothing can run (e.g. repeated failures)
if [ "$(age_h "$STAMP")" -ge "$STALE_H" ] && [ "$(age_h "$ALERTED")" -ge 12 ] && [ -f "$STAMP" ]; then
  "$NOTIFY" "SniffMCP crawl is stale" "No successful crawl for $(age_h "$STAMP")h. Run: sniffmcp crawl status"
  touch "$ALERTED"
fi

# A crawl started by hand counts as running ("ru[n]" keeps pgrep from matching itself).
if pgrep -f "sniffmcp crawl ru[n]" >/dev/null; then exit 0; fi
[ "$(age_h "$STAMP")" -lt "$EVERY_H" ] && exit 0

exec 9>"$HOME_DIR/crawl.lock"
flock -n 9 || exit 0    # another wrapper is already crawling

cd "$REPO" || exit 1
echo "=== $(date -u +%FT%TZ) crawl start" >> "$LOG"
if .venv/bin/sniffmcp crawl run --output "reports/crawl-$(date +%F).md" >> "$LOG" 2>&1; then
  touch "$STAMP"
  rm -f "$ALERTED"
  echo "=== $(date -u +%FT%TZ) crawl ok" >> "$LOG"
  if [ -n "${SNIFFMCP_BACKUP_DIR:-}" ]; then
    mkdir -p "$SNIFFMCP_BACKUP_DIR"
    if .venv/bin/python - "$HOME_DIR/crawl.db" "$SNIFFMCP_BACKUP_DIR/crawl-$(date +%F).db" <<'PY' >> "$LOG" 2>&1
import sqlite3, sys
src, dst = sys.argv[1], sys.argv[2]
with sqlite3.connect(src) as a, sqlite3.connect(dst) as b:
    a.backup(b)          # consistent online copy
print(f"backup ok: {dst}")
PY
    then
      ls -1t "$SNIFFMCP_BACKUP_DIR"/crawl-*.db 2>/dev/null | tail -n +8 | xargs -r rm -f
    else
      "$NOTIFY" "SniffMCP backup failed" "crawl.db could not be copied to $SNIFFMCP_BACKUP_DIR"
    fi
  fi
else
  echo "=== $(date -u +%FT%TZ) crawl FAILED (will retry next tick)" >> "$LOG"
  "$NOTIFY" "SniffMCP crawl failed" "A core stage failed; it will retry within 30 min. Details: sniffmcp crawl status"
fi
