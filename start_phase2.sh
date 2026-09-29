#!/usr/bin/env bash
# Agent Sentinel — Phase 2 launcher
# Starts the API server + a real cloud agent (Anthropic or Azure).
#
# Usage:
#   bash start_phase2.sh --azure --dry-run           # no credentials needed, try it NOW
#   bash start_phase2.sh --azure --dry-run --attack  # inject violations
#   bash start_phase2.sh --azure                     # real Azure OpenAI calls
#   bash start_phase2.sh --azure --attack --loop 5   # real calls + violations
#   bash start_phase2.sh --anthropic --attack        # Anthropic API + violations
set -euo pipefail

cd "$(dirname "$(readlink -f "$0")")"

# ── Defaults ──────────────────────────────────────────────────────────────────
PROVIDER="azure"
ATTACK=""
DRY_RUN=""
LOOP="3"

for arg in "$@"; do
  case "$arg" in
    --anthropic) PROVIDER="anthropic" ;;
    --azure)     PROVIDER="azure"     ;;
    --attack)    ATTACK="--attack"    ;;
    --dry-run)   DRY_RUN="--dry-run"  ;;
    --loop=*)    LOOP="${arg#*=}"     ;;
  esac
done

# ── Colours ───────────────────────────────────────────────────────────────────
RED='\033[91m'; GRN='\033[92m'; YLW='\033[93m'
CYN='\033[96m'; BLD='\033[1m';  RST='\033[0m'

log()  { echo -e "  ${CYN}▸${RST} $*"; }
ok()   { echo -e "  ${GRN}✓${RST} $*"; }
warn() { echo -e "  ${YLW}⚠${RST} $*"; }
err()  { echo -e "  ${RED}✗${RST} $*"; exit 1; }

echo ""
echo -e "${BLD}${CYN}══════════════════════════════════════════════════════${RST}"
echo -e "${BLD}${CYN}  🛡️  Agent Sentinel — Phase 2 (${PROVIDER^^}) Launcher${RST}"
echo -e "${BLD}${CYN}══════════════════════════════════════════════════════${RST}"
echo ""

# ── Activate venv ─────────────────────────────────────────────────────────────
[ -f .venv/bin/activate ] || err "Run:  python3.12 -m venv .venv && source .venv/bin/activate && pip install -e '.[dev,${PROVIDER}]'"
source .venv/bin/activate
ok "venv activated ($(python --version))"

# Refresh package metadata so extras (azure, anthropic) are recognised
pip install -q -e "." --no-deps 2>/dev/null || true

# ── Auto-install SDK if missing ───────────────────────────────────────────────
if [ "$PROVIDER" = "anthropic" ]; then
  python -c "import anthropic" 2>/dev/null || { log "Installing anthropic SDK…"; pip install -q anthropic; }
  [ -n "$DRY_RUN" ] || { [ -n "${ANTHROPIC_API_KEY:-}" ] || err "Export ANTHROPIC_API_KEY or add to examples/phase2/.env"; }
else
  python -c "import openai" 2>/dev/null    || { log "Installing openai SDK…";    pip install -q openai; }
  [ -n "$DRY_RUN" ] || {
    [ -n "${AZURE_OPENAI_ENDPOINT:-}" ] || err "Export AZURE_OPENAI_ENDPOINT + KEY + DEPLOYMENT"
    [ -n "${AZURE_OPENAI_KEY:-}"      ] || err "Export AZURE_OPENAI_KEY"
  }
fi
ok "SDK ready${DRY_RUN:+ (dry-run — no credentials needed)}"

# ── Kill any existing server ──────────────────────────────────────────────────
if lsof -ti:8000 >/dev/null 2>&1; then
  warn "Port 8000 in use — stopping previous instance…"
  lsof -ti:8000 | xargs kill -9 2>/dev/null || true
  sleep 0.8
fi

# ── Start API server ──────────────────────────────────────────────────────────
log "Starting Sentinel API server…"
SENTINEL_POLICY=policies/fintech.yaml \
SENTINEL_DB=/tmp/sentinel-p2.duckdb \
  sentinel serve > /tmp/sentinel-p2-server.log 2>&1 &
SERVER_PID=$!

echo -n "  ${CYN}◌${RST} Waiting for API"
for i in $(seq 1 30); do
  curl -sf http://localhost:8000/healthz >/dev/null 2>&1 && { echo -e "  ${GRN}✓${RST} API ready"; break; }
  echo -n "."; sleep 0.4
  [ $i -eq 30 ] && err "Server did not start. Check /tmp/sentinel-p2-server.log"
done

# ── Open browser ──────────────────────────────────────────────────────────────
URL="http://localhost:8000"
[ -f /mnt/c/Windows/explorer.exe ] && /mnt/c/Windows/explorer.exe "$URL" 2>/dev/null || true

echo ""
echo -e "${BLD}${CYN}══════════════════════════════════════════════════════${RST}"
echo -e "  ${BLD}Dashboard:${RST}  ${GRN}${URL}${RST}  (live SSE stream)"
echo -e "  ${BLD}Provider:${RST}   ${PROVIDER}${DRY_RUN:+ (dry-run)}   attacks=${ATTACK:-none}   loops=${LOOP}"
echo -e "${BLD}${CYN}══════════════════════════════════════════════════════${RST}"
echo ""

cleanup() {
  echo ""; log "Stopping server (PID $SERVER_PID)…"; kill "$SERVER_PID" 2>/dev/null || true; ok "Done."; exit 0
}
trap cleanup INT TERM

# ── Run real agent (foreground so you see the output) ─────────────────────────
python "examples/phase2/${PROVIDER}_agent.py" $DRY_RUN $ATTACK --loop "$LOOP"

cleanup
