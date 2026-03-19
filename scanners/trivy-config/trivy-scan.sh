#!/usr/bin/env bash
set -euo pipefail

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; CYAN='\033[0;36m'; NC='\033[0m'
log()  { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
err()  { echo -e "${RED}[-]${NC} $1"; exit 1; }
info() { echo -e "${CYAN}[*]${NC} $1"; }

usage() {
    echo "Usage: $0 --type <image|fs|repo|k8s> --target <name> [--output <dir>]"
    echo ""
    echo "  --type    image  : scan a Docker image"
    echo "            fs     : scan a filesystem path"
    echo "            repo   : scan a git repository URL"
    echo "            k8s    : scan Kubernetes cluster"
    echo "  --target  Docker image name, path, repo URL, or k8s context"
    echo "  --output  Output directory (default: scanners/scan-results)"
    exit 1
}

TYPE=""
TARGET=""
OUTPUT_DIR="scanners/scan-results"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --type)   TYPE="$2";      shift 2 ;;
        --target) TARGET="$2";    shift 2 ;;
        --output) OUTPUT_DIR="$2";shift 2 ;;
        -h|--help) usage ;;
        *) err "Unknown argument: $1" ;;
    esac
done

[[ -z "$TYPE"   ]] && err "--type is required"
[[ -z "$TARGET" ]] && err "--target is required"

mkdir -p "$OUTPUT_DIR"

SAFE_TARGET=$(echo "$TARGET" | tr '/:' '-')
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
OUTPUT_FILE="${OUTPUT_DIR}/trivy-${TYPE}-${SAFE_TARGET}-${TIMESTAMP}.json"
SUMMARY_FILE="${OUTPUT_DIR}/trivy-${TYPE}-${SAFE_TARGET}-${TIMESTAMP}-summary.txt"

info "Scan type   : $TYPE"
info "Target      : $TARGET"
info "Output file : $OUTPUT_FILE"
echo ""

run_scan() {
    case "$TYPE" in
        image)
            log "Running image scan: $TARGET"
            trivy image \
                --format json \
                --output "$OUTPUT_FILE" \
                --severity CRITICAL,HIGH,MEDIUM,LOW \
                --no-progress \
                "$TARGET"
            ;;
        fs)
            log "Running filesystem scan: $TARGET"
            trivy fs \
                --format json \
                --output "$OUTPUT_FILE" \
                --severity CRITICAL,HIGH,MEDIUM,LOW \
                --no-progress \
                "$TARGET"
            ;;
        repo)
            log "Running repo scan: $TARGET"
            trivy repo \
                --format json \
                --output "$OUTPUT_FILE" \
                --severity CRITICAL,HIGH,MEDIUM,LOW \
                --no-progress \
                "$TARGET"
            ;;
        k8s)
            log "Running Kubernetes scan: $TARGET"
            trivy k8s \
                --format json \
                --output "$OUTPUT_FILE" \
                --severity CRITICAL,HIGH,MEDIUM,LOW \
                --no-progress \
                "$TARGET"
            ;;
        *)
            err "Invalid type: $TYPE. Use image|fs|repo|k8s"
            ;;
    esac
}

run_scan

if [[ ! -f "$OUTPUT_FILE" ]]; then
    err "Scan output not created: $OUTPUT_FILE"
fi

log "Scan complete. Generating summary..."

python3 - <<PYEOF
import json, sys
from pathlib import Path

data = json.loads(Path("${OUTPUT_FILE}").read_text())
counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}

results = data if isinstance(data, list) else data.get("Results", [])
for r in results:
    for v in r.get("Vulnerabilities") or []:
        sev = v.get("Severity", "UNKNOWN").upper()
        counts[sev] = counts.get(sev, 0) + 1

total = sum(counts.values())
summary = f"""
Trivy Scan Summary
==================
Type   : ${TYPE}
Target : ${TARGET}
Time   : $(date -u +"%Y-%m-%dT%H:%M:%SZ")

CRITICAL : {counts['CRITICAL']}
HIGH     : {counts['HIGH']}
MEDIUM   : {counts['MEDIUM']}
LOW      : {counts['LOW']}
UNKNOWN  : {counts['UNKNOWN']}
---------
TOTAL    : {total}

Output: ${OUTPUT_FILE}
"""
print(summary)
Path("${SUMMARY_FILE}").write_text(summary)
PYEOF

log "Summary saved: $SUMMARY_FILE"

log "Triggering Python pipeline..."
if [[ -f "scanners/trivy-config/trivy-scan.py" ]]; then
    python3 scanners/trivy-config/trivy-scan.py \
        --target "$TARGET" \
        --type   "$TYPE"   \
        --output "$OUTPUT_DIR" || warn "Pipeline trigger failed (non-fatal)"
fi

log "Done."
