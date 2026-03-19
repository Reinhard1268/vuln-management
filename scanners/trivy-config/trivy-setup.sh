#!/usr/bin/env bash
set -euo pipefail

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
log()  { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
err()  { echo -e "${RED}[-]${NC} $1"; exit 1; }

[[ $EUID -ne 0 ]] && err "Run as root: sudo bash trivy-setup.sh"

log "Installing Trivy..."
apt-get install -y wget apt-transport-https gnupg

wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key \
    | gpg --dearmor | tee /usr/share/keyrings/trivy.gpg > /dev/null

echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb generic main" \
    | tee /etc/apt/sources.list.d/trivy.list

apt-get update -qq
apt-get install -y trivy

log "Trivy version: $(trivy --version | head -1)"

log "Updating vulnerability database..."
trivy image --download-db-only

log "Creating output directory..."
mkdir -p scanners/scan-results

log "Creating wrapper scripts..."

cat > /usr/local/bin/trivy-scan-image << 'WRAPPER'
#!/usr/bin/env bash
IMAGE="${1:-}"
[[ -z "$IMAGE" ]] && echo "Usage: trivy-scan-image <image:tag>" && exit 1
OUT="scanners/scan-results/trivy-image-$(echo "$IMAGE" | tr '/:' '-')-$(date +%Y%m%d).json"
trivy image --format json --output "$OUT" --severity CRITICAL,HIGH,MEDIUM,LOW "$IMAGE"
echo "Saved: $OUT"
WRAPPER

cat > /usr/local/bin/trivy-scan-fs << 'WRAPPER'
#!/usr/bin/env bash
PATH_="${1:-.}"
OUT="scanners/scan-results/trivy-fs-$(date +%Y%m%d-%H%M).json"
trivy fs --format json --output "$OUT" --severity CRITICAL,HIGH,MEDIUM,LOW "$PATH_"
echo "Saved: $OUT"
WRAPPER

chmod +x /usr/local/bin/trivy-scan-image /usr/local/bin/trivy-scan-fs

log "===== Trivy Setup Complete ====="
echo -e "  Version:  ${GREEN}$(trivy --version | head -1)${NC}"
echo -e "  Wrappers: ${GREEN}/usr/local/bin/trivy-scan-image${NC}"
echo -e "            ${GREEN}/usr/local/bin/trivy-scan-fs${NC}"
warn "Run: trivy image --download-db-only   to keep DB fresh"
