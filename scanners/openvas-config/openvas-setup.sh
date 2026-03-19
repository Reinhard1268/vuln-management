#!/usr/bin/env bash
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
log()  { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
err()  { echo -e "${RED}[-]${NC} $1"; exit 1; }

[[ $EUID -ne 0 ]] && err "Run as root: sudo bash openvas-setup.sh"

ADMIN_PASS="Admin@OpenVAS2024!"
GVM_SOCKET="/run/gvmd/gvmd.sock"

log "Updating package lists..."
apt-get update -qq

log "Installing OpenVAS / GVM..."
apt-get install -y openvas gvm

log "Running gvm-setup (this takes 10-20 minutes)..."
gvm-setup 2>&1 | tee /tmp/gvm-setup.log

log "Setting admin password..."
gvmd --user=admin --new-password="${ADMIN_PASS}" || true

log "Checking GVM setup..."
gvm-check-setup 2>&1 | tee /tmp/gvm-check.log

log "Enabling GVM services on boot..."
systemctl enable gvmd ospd-openvas notus-scanner
systemctl start  gvmd ospd-openvas notus-scanner

log "Waiting for gvmd socket..."
for i in $(seq 1 30); do
    [[ -S "$GVM_SOCKET" ]] && break
    sleep 2
done
[[ -S "$GVM_SOCKET" ]] || err "gvmd socket not found after 60s"

log "Updating NVT feed..."
greenbone-nvt-sync || warn "NVT sync warning — may need manual retry"
greenbone-feed-sync --type GVMD_DATA  || true
greenbone-feed-sync --type SCAP       || true
greenbone-feed-sync --type CERT       || true

log "Creating scan targets..."

TARGET_LOCAL=$(gvm-cli --gmp-username admin --gmp-password "${ADMIN_PASS}" \
    socket --socketpath "$GVM_SOCKET" --xml \
    "<create_target><name>Localhost</name><hosts>127.0.0.1</hosts><port_list id=\"33d0cd82-57c6-11e1-8ed1-406186ea4fc5\"/></create_target>" \
    | grep -oP '(?<=id=")[^"]+' | head -1)

TARGET_DOCKER=$(gvm-cli --gmp-username admin --gmp-password "${ADMIN_PASS}" \
    socket --socketpath "$GVM_SOCKET" --xml \
    "<create_target><name>Docker Network</name><hosts>172.17.0.0/24</hosts><port_list id=\"33d0cd82-57c6-11e1-8ed1-406186ea4fc5\"/></create_target>" \
    | grep -oP '(?<=id=")[^"]+' | head -1)

TARGET_LAB=$(gvm-cli --gmp-username admin --gmp-password "${ADMIN_PASS}" \
    socket --socketpath "$GVM_SOCKET" --xml \
    "<create_target><name>Lab Network</name><hosts>192.168.1.0/24</hosts><port_list id=\"33d0cd82-57c6-11e1-8ed1-406186ea4fc5\"/></create_target>" \
    | grep -oP '(?<=id=")[^"]+' | head -1)

log "Creating scan configs..."

CONFIG_FULL=$(gvm-cli --gmp-username admin --gmp-password "${ADMIN_PASS}" \
    socket --socketpath "$GVM_SOCKET" --xml \
    "<create_config><copy>daba56c8-73ec-11df-a475-002264764cea</copy><name>Lab Full and Fast</name></create_config>" \
    | grep -oP '(?<=id=")[^"]+' | head -1)

CONFIG_WEB=$(gvm-cli --gmp-username admin --gmp-password "${ADMIN_PASS}" \
    socket --socketpath "$GVM_SOCKET" --xml \
    "<create_config><copy>085569ce-73ed-11df-83c3-002264764cea</copy><name>Lab Web Application</name></create_config>" \
    | grep -oP '(?<=id=")[^"]+' | head -1)

echo ""
log "===== OpenVAS Setup Complete ====="
echo -e "  URL:              ${GREEN}https://localhost:9392${NC}"
echo -e "  Username:         ${GREEN}admin${NC}"
echo -e "  Password:         ${GREEN}${ADMIN_PASS}${NC}"
echo ""
echo -e "  Target IDs:"
echo -e "    Localhost:      ${YELLOW}${TARGET_LOCAL}${NC}"
echo -e "    Docker network: ${YELLOW}${TARGET_DOCKER}${NC}"
echo -e "    Lab network:    ${YELLOW}${TARGET_LAB}${NC}"
echo ""
echo -e "  Scan Config IDs:"
echo -e "    Full and Fast:  ${YELLOW}${CONFIG_FULL}${NC}"
echo -e "    Web App:        ${YELLOW}${CONFIG_WEB}${NC}"
echo ""
warn "Save these IDs in your .env file!"
