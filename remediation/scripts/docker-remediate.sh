# File: remediation/scripts/docker-remediate.sh

#!/usr/bin/env bash
set -euo pipefail

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; CYAN='\033[0;36m'; NC='\033[0m'
log()  { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
err()  { echo -e "${RED}[-]${NC} $1"; exit 1; }
info() { echo -e "${CYAN}[*]${NC} $1"; }

AUDIT_LOG="remediation/tracking/docker-remediation-$(date +%Y%m%d-%H%M%S).log"
mkdir -p remediation/tracking

log_action() { echo "[$(date -u +"%Y-%m-%dT%H:%M:%SZ")] $1" | tee -a "$AUDIT_LOG"; }

CONTAINER=""
CVE=""

usage() {
    echo "Usage: $0 --container <name_or_id> --cve <CVE-ID>"
    echo ""
    echo "  --container   Docker container name or ID"
    echo "  --cve         CVE ID being remediated (for logging)"
    exit 1
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --container) CONTAINER="$2"; shift 2 ;;
        --cve)       CVE="$2";       shift 2 ;;
        -h|--help)   usage ;;
        *) err "Unknown: $1" ;;
    esac
done

[[ -z "$CONTAINER" ]] && err "--container is required"

# ── Inspect container ─────────────────────────────────────────────────────────
info "Inspecting container: $CONTAINER"

INSPECT=$(docker inspect "$CONTAINER" 2>/dev/null) || err "Container '$CONTAINER' not found."

IMAGE=$(echo "$INSPECT" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d[0]['Config']['Image'])")
CONTAINER_ID=$(echo "$INSPECT" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d[0]['Id'][:12])")
RESTART_POLICY=$(echo "$INSPECT" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d[0]['HostConfig']['RestartPolicy']['Name'])" 2>/dev/null || echo "unless-stopped")
PORT_BINDINGS=$(echo "$INSPECT" | python3 -c "
import json,sys
d = json.load(sys.stdin)[0]['HostConfig']['PortBindings'] or {}
parts = []
for cp, hps in d.items():
    for hp in (hps or []):
        parts.append(f\"-p {hp.get('HostPort','0')}:{cp}\")
print(' '.join(parts))
" 2>/dev/null || echo "")
NETWORKS=$(echo "$INSPECT" | python3 -c "
import json,sys
d = json.load(sys.stdin)[0]['NetworkSettings']['Networks']
print(' '.join([f'--network {n}' for n in d.keys()]))
" 2>/dev/null || echo "")

log_action "BEGIN docker remediation: CONTAINER=$CONTAINER IMAGE=$IMAGE CVE=${CVE:-N/A}"
info "  Container ID : $CONTAINER_ID"
info "  Image        : $IMAGE"
info "  Ports        : ${PORT_BINDINGS:-none}"
info "  Networks     : ${NETWORKS:-default}"

# ── Save previous image tag ───────────────────────────────────────────────────
PREV_IMAGE_ID=$(docker images --no-trunc -q "$IMAGE" 2>/dev/null | head -1 || echo "")
log_action "Previous image ID: $PREV_IMAGE_ID"

# ── Pull latest image ─────────────────────────────────────────────────────────
info "Pulling latest image: $IMAGE"
if docker pull "$IMAGE" 2>&1 | tee -a "$AUDIT_LOG"; then
    NEW_IMAGE_ID=$(docker images --no-trunc -q "$IMAGE" 2>/dev/null | head -1 || echo "")
    log_action "New image ID: $NEW_IMAGE_ID"

    if [[ "$PREV_IMAGE_ID" == "$NEW_IMAGE_ID" ]]; then
        warn "Image is already at latest version — no update available."
        log_action "No image update — same digest."
    else
        log "Image updated: $PREV_IMAGE_ID → $NEW_IMAGE_ID"
    fi
else
    err "Failed to pull $IMAGE"
fi

# ── Stop and remove old container ─────────────────────────────────────────────
info "Stopping container: $CONTAINER"
docker stop "$CONTAINER" 2>&1 | tee -a "$AUDIT_LOG"
log_action "Stopped container: $CONTAINER"

info "Removing container: $CONTAINER"
docker rm "$CONTAINER" 2>&1 | tee -a "$AUDIT_LOG"
log_action "Removed container: $CONTAINER"

# ── Start new container ───────────────────────────────────────────────────────
info "Starting new container with same config..."
DOCKER_CMD="docker run -d --name $CONTAINER --restart $RESTART_POLICY $PORT_BINDINGS $NETWORKS $IMAGE"
log_action "Docker command: $DOCKER_CMD"

if eval "$DOCKER_CMD" 2>&1 | tee -a "$AUDIT_LOG"; then
    log "New container started: $CONTAINER"
else
    warn "Failed to start new container — attempting rollback..."
    if [[ -n "$PREV_IMAGE_ID" ]]; then
        ROLLBACK_CMD="docker run -d --name $CONTAINER --restart $RESTART_POLICY $PORT_BINDINGS $NETWORKS $PREV_IMAGE_ID"
        eval "$ROLLBACK_CMD" 2>&1 | tee -a "$AUDIT_LOG" || err "Rollback also failed. Manual intervention required."
        warn "Rolled back to previous image: $PREV_IMAGE_ID"
        log_action "ROLLBACK completed to $PREV_IMAGE_ID"
    fi
    exit 1
fi

# ── Health check ──────────────────────────────────────────────────────────────
info "Waiting for container health check..."
sleep 5
STATUS=$(docker inspect --format='{{.State.Status}}' "$CONTAINER" 2>/dev/null || echo "unknown")
log_action "Container status after start: $STATUS"

if [[ "$STATUS" == "running" ]]; then
    log "Container is running: $CONTAINER"
else
    warn "Container status: $STATUS — check logs: docker logs $CONTAINER"
fi

# ── Trivy re-scan ─────────────────────────────────────────────────────────────
info "Running Trivy re-scan to verify fix..."
RESCAN_OUT="scanners/scan-results/trivy-post-remediation-${CONTAINER}-$(date +%Y%m%d-%H%M%S).json"
if command -v trivy &>/dev/null; then
    trivy image --format json --output "$RESCAN_OUT" --severity CRITICAL,HIGH "$IMAGE" 2>&1 | tee -a "$AUDIT_LOG" || true
    log "Post-remediation scan saved: $RESCAN_OUT"
    log_action "Post-remediation scan: $RESCAN_OUT"
else
    warn "Trivy not found — skipping re-scan."
fi

log_action "END docker remediation: CONTAINER=$CONTAINER"
log "Audit log: $AUDIT_LOG"
log "Remediation complete. Review $RESCAN_OUT to confirm CVE is resolved."
