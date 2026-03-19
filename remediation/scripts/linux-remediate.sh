# linux-remediate.sh
#!/usr/bin/env bash
set -euo pipefail

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; CYAN='\033[0;36m'; NC='\033[0m'
log()  { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
err()  { echo -e "${RED}[-]${NC} $1"; exit 1; }
info() { echo -e "${CYAN}[*]${NC} $1"; }

AUDIT_LOG="remediation/tracking/linux-remediation-$(date +%Y%m%d-%H%M%S).log"
mkdir -p remediation/tracking

log_action() { echo "[$(date -u +"%Y-%m-%dT%H:%M:%SZ")] $1" | tee -a "$AUDIT_LOG"; }

CVE=""
PACKAGE=""

usage() {
    echo "Usage: $0 --cve CVE-XXXX-XXXXX | --package <package_name>"
    echo ""
    echo "  --cve     CVE ID to remediate (looks up known fix)"
    echo "  --package Package name to upgrade"
    exit 1
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --cve)     CVE="$2";     shift 2 ;;
        --package) PACKAGE="$2"; shift 2 ;;
        -h|--help) usage ;;
        *) err "Unknown: $1" ;;
    esac
done

[[ -z "$CVE" && -z "$PACKAGE" ]] && usage

# Map known CVEs to packages
cve_to_package() {
    case "$1" in
        CVE-2021-44228) echo "liblog4j2-java" ;;
        CVE-2021-3156)  echo "sudo" ;;
        CVE-2022-0778)  echo "openssl" ;;
        CVE-2022-0847)  echo "linux-image-$(uname -r)" ;;
        CVE-2023-38408) echo "openssh-client openssh-server" ;;
        CVE-2023-4911)  echo "libc6 libc-bin" ;;
        CVE-2024-22365) echo "libpam-modules" ;;
        *)              echo "" ;;
    esac
}

if [[ -n "$CVE" ]]; then
    PACKAGE=$(cve_to_package "$CVE")
    if [[ -z "$PACKAGE" ]]; then
        warn "No automatic fix mapping for $CVE — use --package to specify the package name."
        exit 0
    fi
    info "CVE $CVE → package(s): $PACKAGE"
fi

log_action "BEGIN remediation: CVE=${CVE:-N/A} PACKAGE=${PACKAGE}"

# Backup configs
backup_configs() {
    local pkg="$1"
    local backup_dir="remediation/tracking/backups/$(date +%Y%m%d-%H%M%S)-${pkg}"
    mkdir -p "$backup_dir"
    dpkg -L "$pkg" 2>/dev/null | grep "^/etc" | while read -r f; do
        [[ -f "$f" ]] && cp --parents "$f" "$backup_dir" && log_action "Backed up: $f"
    done || true
    echo "$backup_dir"
}

rollback() {
    local pkg="$1"
    local backup_dir="$2"
    warn "Rolling back $pkg from $backup_dir..."
    if [[ -d "$backup_dir" ]]; then
        find "$backup_dir" -type f | while read -r f; do
            dest="${f#$backup_dir}"
            cp "$f" "$dest" && log_action "Restored: $dest"
        done
    fi
    log_action "Rollback complete for $pkg"
}

info "Updating package lists..."
apt-get update -qq
log_action "apt-get update completed"

for PKG in $PACKAGE; do
    info "Processing package: $PKG"

    if ! dpkg -l "$PKG" 2>/dev/null | grep -q "^ii"; then
        warn "Package $PKG not installed — skipping."
        log_action "SKIP $PKG — not installed"
        continue
    fi

    BEFORE=$(dpkg -l "$PKG" 2>/dev/null | awk '/^ii/ {print $3}')
    log_action "Version before: $PKG $BEFORE"

    info "Backing up configs for $PKG..."
    BACKUP_DIR=$(backup_configs "$PKG")

    if apt-get install -y --only-upgrade "$PKG" 2>&1 | tee -a "$AUDIT_LOG"; then
        AFTER=$(dpkg -l "$PKG" 2>/dev/null | awk '/^ii/ {print $3}')
        log_action "Version after:  $PKG $AFTER"

        if [[ "$BEFORE" == "$AFTER" ]]; then
            warn "$PKG is already at latest version: $AFTER"
        else
            log "Upgraded $PKG: $BEFORE → $AFTER"
        fi

        # Restart related services
        case "$PKG" in
            openssh*|openssl*)
                systemctl restart sshd 2>/dev/null && log_action "Restarted sshd" || true ;;
            nginx*)
                systemctl restart nginx 2>/dev/null && log_action "Restarted nginx" || true ;;
            apache2*)
                systemctl restart apache2 2>/dev/null && log_action "Restarted apache2" || true ;;
        esac
    else
        err_msg="apt-get upgrade failed for $PKG"
        log_action "ERROR: $err_msg"
        rollback "$PKG" "$BACKUP_DIR"
        warn "$err_msg — rolled back."
    fi
done

log_action "END remediation: CVE=${CVE:-N/A} PACKAGE=${PACKAGE}"
log "Audit log: $AUDIT_LOG"
log "Remediation complete. Run a new scan to verify the fix."
