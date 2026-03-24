#!/usr/bin/env bash
# =============================================================================
# StealthOS Relay Server — Installer for Linux & macOS
# =============================================================================
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/Olib-AI/StealthRelay/main/scripts/install.sh | bash
#
# Or download and inspect first:
#   curl -fsSL https://raw.githubusercontent.com/Olib-AI/StealthRelay/main/scripts/install.sh -o install.sh
#   chmod +x install.sh
#   ./install.sh
#
# Options:
#   --version VERSION    Install a specific version (default: latest)
#   --uninstall          Remove StealthRelay completely
#   --update             Update binary only, preserve keys and config
#   --no-service         Don't create or enable a system service
#   --no-browser         Don't auto-open browser after install
#   --help               Show this help message

set -euo pipefail

# ── Constants ─────────────────────────────────────────────────────────────────

REPO="Olib-AI/StealthRelay"
BINARY_NAME="stealth-relay"
SERVICE_NAME="stealth-relay"
LAUNCHD_LABEL="ai.olib.stealth-relay"

# ── Colors ────────────────────────────────────────────────────────────────────

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m' # No Color

info()    { echo -e "${BLUE}[info]${NC}  $*"; }
success() { echo -e "${GREEN}[ok]${NC}    $*"; }
warn()    { echo -e "${YELLOW}[warn]${NC}  $*"; }
error()   { echo -e "${RED}[error]${NC} $*" >&2; }
fatal()   { error "$@"; exit 1; }

# ── Argument parsing ──────────────────────────────────────────────────────────

VERSION="latest"
UNINSTALL=false
UPDATE=false
NO_SERVICE=false
NO_BROWSER=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --version)   VERSION="$2"; shift 2 ;;
        --uninstall) UNINSTALL=true; shift ;;
        --update)    UPDATE=true; shift ;;
        --no-service) NO_SERVICE=true; shift ;;
        --no-browser) NO_BROWSER=true; shift ;;
        --help|-h)
            echo "StealthOS Relay Installer"
            echo ""
            echo "Usage: install.sh [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --version VERSION    Install specific version (default: latest)"
            echo "  --uninstall          Remove StealthRelay completely"
            echo "  --update             Update binary, preserve keys and config"
            echo "  --no-service         Don't create/enable system service"
            echo "  --no-browser         Don't auto-open browser after install"
            echo "  --help               Show this help message"
            exit 0
            ;;
        *) fatal "Unknown option: $1. Use --help for usage." ;;
    esac
done

# ── Platform detection ────────────────────────────────────────────────────────

detect_platform() {
    local os arch

    case "$(uname -s)" in
        Linux)  os="linux" ;;
        Darwin) os="darwin" ;;
        *)      fatal "Unsupported OS: $(uname -s). Only Linux and macOS are supported." ;;
    esac

    case "$(uname -m)" in
        x86_64|amd64)       arch="amd64" ;;
        aarch64|arm64)      arch="arm64" ;;
        *)                  fatal "Unsupported architecture: $(uname -m). Only amd64 and arm64 are supported." ;;
    esac

    OS="$os"
    ARCH="$arch"
}

# ── Path configuration ────────────────────────────────────────────────────────

configure_paths() {
    if [ "$(id -u)" -eq 0 ]; then
        SUDO_CMD=""
        INSTALL_DIR="/usr/local/bin"
        DATA_DIR="/var/stealth-relay"
        CONFIG_DIR="/etc/stealth-relay"
        LOG_DIR="/var/log"
        USE_SUDO=false
    elif command -v sudo >/dev/null 2>&1; then
        SUDO_CMD="sudo"
        INSTALL_DIR="/usr/local/bin"
        DATA_DIR="/var/stealth-relay"
        CONFIG_DIR="/etc/stealth-relay"
        LOG_DIR="/var/log"
        USE_SUDO=true
    else
        SUDO_CMD=""
        INSTALL_DIR="${HOME}/.local/bin"
        DATA_DIR="${HOME}/.stealth-relay"
        CONFIG_DIR="${HOME}/.stealth-relay"
        LOG_DIR="${HOME}/.stealth-relay/logs"
        USE_SUDO=false
    fi

    BINARY_PATH="${INSTALL_DIR}/${BINARY_NAME}"
    CONFIG_PATH="${CONFIG_DIR}/config.toml"
    KEY_DIR="${DATA_DIR}/keys"
}

# ── Prerequisites ─────────────────────────────────────────────────────────────

check_prereqs() {
    if ! command -v curl >/dev/null 2>&1; then
        fatal "curl is required but not installed. Install it with your package manager."
    fi
}

# ── Version resolution ────────────────────────────────────────────────────────

resolve_version() {
    if [ "$VERSION" = "latest" ]; then
        info "Fetching latest release version..."
        VERSION=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
            | grep '"tag_name"' | head -1 | cut -d'"' -f4) \
            || fatal "Failed to fetch latest version. Check your internet connection."
        [ -n "$VERSION" ] || fatal "Could not determine latest version."
    fi
    success "Version: $VERSION"
}

# ── Download and verify ──────────────────────────────────────────────────────

download_binary() {
    local artifact="stealth-relay-${OS}-${ARCH}"
    local base_url="https://github.com/${REPO}/releases/download/${VERSION}"
    local tmp_dir
    tmp_dir=$(mktemp -d)

    info "Downloading ${artifact}..."
    curl -fSL "${base_url}/${artifact}" -o "${tmp_dir}/${artifact}" \
        || fatal "Failed to download binary. Check that version ${VERSION} exists."

    info "Downloading checksums..."
    curl -fSL "${base_url}/SHA256SUMS.txt" -o "${tmp_dir}/SHA256SUMS.txt" \
        || fatal "Failed to download checksums."

    info "Verifying SHA256 checksum..."
    local expected
    expected=$(grep "${artifact}" "${tmp_dir}/SHA256SUMS.txt" | awk '{print $1}')
    [ -n "$expected" ] || fatal "Binary ${artifact} not found in SHA256SUMS.txt"

    local actual
    if command -v sha256sum >/dev/null 2>&1; then
        actual=$(sha256sum "${tmp_dir}/${artifact}" | awk '{print $1}')
    elif command -v shasum >/dev/null 2>&1; then
        actual=$(shasum -a 256 "${tmp_dir}/${artifact}" | awk '{print $1}')
    else
        fatal "Neither sha256sum nor shasum found. Cannot verify checksum."
    fi

    if [ "$expected" != "$actual" ]; then
        fatal "Checksum mismatch!\n  Expected: ${expected}\n  Actual:   ${actual}"
    fi
    success "Checksum verified"

    DOWNLOAD_PATH="${tmp_dir}/${artifact}"
}

# ── Install binary ────────────────────────────────────────────────────────────

install_binary() {
    info "Installing binary to ${BINARY_PATH}..."
    $SUDO_CMD mkdir -p "$INSTALL_DIR"
    $SUDO_CMD install -m 755 "$DOWNLOAD_PATH" "$BINARY_PATH"
    success "Binary installed"

    local version_output
    version_output=$("$BINARY_PATH" version 2>&1 || true)
    info "Installed: ${version_output}"
}

# ── Create directories and config ─────────────────────────────────────────────

create_dirs_and_config() {
    info "Creating data directory ${KEY_DIR}..."
    $SUDO_CMD mkdir -p "$KEY_DIR"
    $SUDO_CMD chmod 700 "$KEY_DIR"

    if [ "$CONFIG_DIR" != "$DATA_DIR" ]; then
        $SUDO_CMD mkdir -p "$CONFIG_DIR"
    fi

    $SUDO_CMD mkdir -p "$LOG_DIR"

    # On macOS with LaunchAgent (non-root), the service runs as the current
    # user but directories were created with sudo. Fix ownership so the
    # binary can write keys and config.
    if [ "$OS" = "darwin" ] && [ "$USE_SUDO" = true ]; then
        $SUDO_CMD chown -R "$(whoami)" "$DATA_DIR"
        if [ "$CONFIG_DIR" != "$DATA_DIR" ]; then
            $SUDO_CMD chown -R "$(whoami)" "$CONFIG_DIR"
        fi
    fi

    if [ -f "$CONFIG_PATH" ]; then
        info "Config already exists at ${CONFIG_PATH}, keeping it"
        return
    fi

    info "Generating config at ${CONFIG_PATH}..."
    $SUDO_CMD tee "$CONFIG_PATH" > /dev/null << TOML
# StealthOS Relay Server — Configuration
# Generated by installer on $(date -u +"%Y-%m-%dT%H:%M:%SZ")

[server]
ws_bind = "0.0.0.0:9090"
# Bound to all interfaces so the setup page is accessible from your
# local network (e.g., from a laptop when the relay runs on a Pi).
metrics_bind = "0.0.0.0:9091"
max_connections = 500
max_message_size = 65536
idle_timeout = 600
handshake_timeout = 10

[pool]
max_pools = 100
max_pool_size = 16
pool_idle_timeout = 300

[crypto]
key_dir = "${KEY_DIR}"
auto_generate_keys = true

[logging]
level = "info"
format = "pretty"

[rate_limit]
connections_per_minute = 30
messages_per_second = 60
max_failed_auth = 5
block_duration_secs = 600
TOML

    $SUDO_CMD chmod 644 "$CONFIG_PATH"
    success "Config generated"
}

# ── Create system user (Linux only) ──────────────────────────────────────────

create_system_user() {
    if [ "$OS" != "linux" ] || [ "$USE_SUDO" = false ] && [ "$(id -u)" -ne 0 ]; then
        return
    fi

    if id "$SERVICE_NAME" &>/dev/null; then
        return
    fi

    info "Creating system user '${SERVICE_NAME}'..."
    $SUDO_CMD useradd --system --no-create-home --shell /usr/sbin/nologin "$SERVICE_NAME" 2>/dev/null || true
    $SUDO_CMD chown -R "${SERVICE_NAME}:${SERVICE_NAME}" "$DATA_DIR"
    success "System user created"
}

# ── systemd service (Linux) ──────────────────────────────────────────────────

install_systemd_service() {
    local unit_path="/etc/systemd/system/${SERVICE_NAME}.service"

    info "Creating systemd service..."
    $SUDO_CMD tee "$unit_path" > /dev/null << UNIT
[Unit]
Description=StealthOS Relay Server
Documentation=https://github.com/Olib-AI/StealthRelay
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${SERVICE_NAME}
Group=${SERVICE_NAME}
ExecStart=${BINARY_PATH} serve --config ${CONFIG_PATH}
Restart=on-failure
RestartSec=5
Environment=STEALTH_NO_BROWSER=1

# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=${DATA_DIR}
PrivateTmp=true
ProtectKernelTunables=true
ProtectControlGroups=true

[Install]
WantedBy=multi-user.target
UNIT

    $SUDO_CMD systemctl daemon-reload
    $SUDO_CMD systemctl enable "$SERVICE_NAME"
    success "systemd service created and enabled"
}

# ── launchd plist (macOS) ─────────────────────────────────────────────────────

install_launchd_service() {
    local plist_dir plist_path log_path

    if [ "$(id -u)" -eq 0 ]; then
        plist_dir="/Library/LaunchDaemons"
        log_path="/var/log/${SERVICE_NAME}.log"
    else
        plist_dir="${HOME}/Library/LaunchAgents"
        log_path="${HOME}/Library/Logs/${SERVICE_NAME}.log"
    fi

    plist_path="${plist_dir}/${LAUNCHD_LABEL}.plist"

    mkdir -p "$plist_dir"

    info "Creating launchd plist..."
    $SUDO_CMD tee "$plist_path" > /dev/null << PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>${LAUNCHD_LABEL}</string>
    <key>ProgramArguments</key>
    <array>
        <string>${BINARY_PATH}</string>
        <string>serve</string>
        <string>--config</string>
        <string>${CONFIG_PATH}</string>
    </array>
    <key>EnvironmentVariables</key>
    <dict>
        <key>STEALTH_NO_BROWSER</key>
        <string>1</string>
    </dict>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>${log_path}</string>
    <key>StandardErrorPath</key>
    <string>${log_path}</string>
</dict>
</plist>
PLIST

    success "launchd plist created"
}

# ── Service management ────────────────────────────────────────────────────────

start_service() {
    info "Starting ${SERVICE_NAME}..."

    if [ "$OS" = "linux" ]; then
        $SUDO_CMD systemctl start "$SERVICE_NAME"
    elif [ "$OS" = "darwin" ]; then
        if [ "$(id -u)" -eq 0 ]; then
            $SUDO_CMD launchctl load "/Library/LaunchDaemons/${LAUNCHD_LABEL}.plist"
        else
            launchctl load "${HOME}/Library/LaunchAgents/${LAUNCHD_LABEL}.plist"
        fi
    fi

    success "Service started"
}

stop_service() {
    if [ "$OS" = "linux" ]; then
        $SUDO_CMD systemctl stop "$SERVICE_NAME" 2>/dev/null || true
    elif [ "$OS" = "darwin" ]; then
        if [ "$(id -u)" -eq 0 ]; then
            $SUDO_CMD launchctl unload "/Library/LaunchDaemons/${LAUNCHD_LABEL}.plist" 2>/dev/null || true
        else
            launchctl unload "${HOME}/Library/LaunchAgents/${LAUNCHD_LABEL}.plist" 2>/dev/null || true
        fi
    fi
}

# ── Auto-update timer ─────────────────────────────────────────────────────────

install_update_timer() {
    if [ "$OS" = "linux" ]; then
        local timer_path="/etc/systemd/system/${SERVICE_NAME}-update.timer"
        local service_path="/etc/systemd/system/${SERVICE_NAME}-update.service"

        info "Creating weekly auto-update timer..."
        $SUDO_CMD tee "$service_path" > /dev/null << UNIT
[Unit]
Description=StealthOS Relay Auto-Update
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/bin/bash -c 'curl -fsSL https://raw.githubusercontent.com/Olib-AI/StealthRelay/main/scripts/install.sh | bash -s -- --update'
UNIT

        $SUDO_CMD tee "$timer_path" > /dev/null << UNIT
[Unit]
Description=Weekly StealthOS Relay update check

[Timer]
OnCalendar=weekly
RandomizedDelaySec=3600
Persistent=true

[Install]
WantedBy=timers.target
UNIT

        $SUDO_CMD systemctl daemon-reload
        $SUDO_CMD systemctl enable --now "${SERVICE_NAME}-update.timer"
        success "Weekly auto-update timer enabled"

    elif [ "$OS" = "darwin" ]; then
        local plist_dir plist_path
        if [ "$(id -u)" -eq 0 ]; then
            plist_dir="/Library/LaunchDaemons"
        else
            plist_dir="${HOME}/Library/LaunchAgents"
        fi
        plist_path="${plist_dir}/${LAUNCHD_LABEL}.update.plist"

        info "Creating weekly auto-update job..."
        $SUDO_CMD tee "$plist_path" > /dev/null << PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>${LAUNCHD_LABEL}.update</string>
    <key>ProgramArguments</key>
    <array>
        <string>/bin/bash</string>
        <string>-c</string>
        <string>curl -fsSL https://raw.githubusercontent.com/Olib-AI/StealthRelay/main/scripts/install.sh | bash -s -- --update</string>
    </array>
    <key>StartCalendarInterval</key>
    <dict>
        <key>Weekday</key>
        <integer>0</integer>
        <key>Hour</key>
        <integer>4</integer>
    </dict>
</dict>
</plist>
PLIST

        if [ "$(id -u)" -eq 0 ]; then
            $SUDO_CMD launchctl load "$plist_path"
        else
            launchctl load "$plist_path"
        fi
        success "Weekly auto-update job enabled (Sundays at 4 AM)"
    fi
}

# ── Wait for health ──────────────────────────────────────────────────────────

wait_for_health() {
    info "Waiting for server to start..."
    local attempts=0
    while [ $attempts -lt 30 ]; do
        if curl -sf "http://127.0.0.1:9091/health" >/dev/null 2>&1; then
            success "Server is running"
            return 0
        fi
        sleep 1
        attempts=$((attempts + 1))
    done
    warn "Server may not have started yet. Check logs for details."
    return 1
}

# ── Extract and display setup URL ─────────────────────────────────────────────

show_setup_url() {
    local setup_url=""

    if [ "$OS" = "linux" ]; then
        setup_url=$(journalctl -u "$SERVICE_NAME" --no-pager -n 30 2>/dev/null \
            | grep -oP 'http://[^ ]*setup\?token=[a-f0-9]+' | head -1) || true
    elif [ "$OS" = "darwin" ]; then
        local log_path
        if [ "$(id -u)" -eq 0 ]; then
            log_path="/var/log/${SERVICE_NAME}.log"
        else
            log_path="${HOME}/Library/Logs/${SERVICE_NAME}.log"
        fi
        if [ -f "$log_path" ]; then
            setup_url=$(grep -oE 'http://[^ ]*setup\?token=[a-f0-9]+' "$log_path" | head -1) || true
        fi
    fi

    echo ""
    echo -e "${BOLD}════════════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}  StealthOS Relay is running!${NC}"
    echo ""

    if [ -n "$setup_url" ]; then
        echo -e "  Open this URL to claim your server:"
        echo ""
        echo -e "  ${GREEN}${BOLD}${setup_url}${NC}"
        echo ""
        echo -e "  Or from another device on your network:"
        # Get local IP
        local local_ip
        if command -v hostname >/dev/null 2>&1; then
            local_ip=$(hostname -I 2>/dev/null | awk '{print $1}') || true
        fi
        if [ -z "${local_ip:-}" ] && command -v ifconfig >/dev/null 2>&1; then
            local_ip=$(ifconfig | grep 'inet ' | grep -v '127.0.0.1' | awk '{print $2}' | head -1) || true
        fi
        if [ -n "${local_ip:-}" ]; then
            local lan_url="${setup_url/0.0.0.0/${local_ip}}"
            lan_url="${lan_url/127.0.0.1/${local_ip}}"
            echo -e "  ${BLUE}${lan_url}${NC}"
            echo ""
        fi
    else
        echo -e "  Check the service logs for the setup URL:"
        if [ "$OS" = "linux" ]; then
            echo -e "  ${BLUE}sudo journalctl -u ${SERVICE_NAME} -n 30${NC}"
        else
            echo -e "  ${BLUE}cat ~/Library/Logs/${SERVICE_NAME}.log${NC}"
        fi
        echo ""
    fi

    echo -e "  WebSocket relay:  ws://0.0.0.0:9090"
    echo -e "  Health check:     http://127.0.0.1:9091/health"
    echo -e "${BOLD}════════════════════════════════════════════════════════════${NC}"
    echo ""

    # Auto-open browser
    if [ "$NO_BROWSER" = false ] && [ -n "$setup_url" ]; then
        if [ "$OS" = "darwin" ]; then
            open "$setup_url" 2>/dev/null || true
        elif [ "$OS" = "linux" ] && command -v xdg-open >/dev/null 2>&1; then
            xdg-open "$setup_url" 2>/dev/null || true
        fi
    fi
}

# ── Uninstall ─────────────────────────────────────────────────────────────────

do_uninstall() {
    echo -e "${BOLD}StealthOS Relay — Uninstall${NC}"
    echo ""

    stop_service

    # Remove service files and update timer
    if [ "$OS" = "linux" ]; then
        if [ -f "/etc/systemd/system/${SERVICE_NAME}-update.timer" ]; then
            $SUDO_CMD systemctl disable --now "${SERVICE_NAME}-update.timer" 2>/dev/null || true
            $SUDO_CMD rm -f "/etc/systemd/system/${SERVICE_NAME}-update.timer"
            $SUDO_CMD rm -f "/etc/systemd/system/${SERVICE_NAME}-update.service"
        fi
        if [ -f "/etc/systemd/system/${SERVICE_NAME}.service" ]; then
            info "Removing systemd service..."
            $SUDO_CMD systemctl disable "$SERVICE_NAME" 2>/dev/null || true
            $SUDO_CMD rm -f "/etc/systemd/system/${SERVICE_NAME}.service"
            $SUDO_CMD systemctl daemon-reload
            success "Service removed"
        fi
    elif [ "$OS" = "darwin" ]; then
        local plist
        for plist in "/Library/LaunchDaemons/${LAUNCHD_LABEL}.plist" \
                     "/Library/LaunchDaemons/${LAUNCHD_LABEL}.update.plist" \
                     "${HOME}/Library/LaunchAgents/${LAUNCHD_LABEL}.plist" \
                     "${HOME}/Library/LaunchAgents/${LAUNCHD_LABEL}.update.plist"; do
            if [ -f "$plist" ]; then
                info "Removing $(basename "$plist")..."
                $SUDO_CMD launchctl unload "$plist" 2>/dev/null || true
                $SUDO_CMD rm -f "$plist"
            fi
        done
        success "Service and update timer removed"
    fi

    # Remove binary
    if [ -f "$BINARY_PATH" ]; then
        info "Removing binary..."
        $SUDO_CMD rm -f "$BINARY_PATH"
        success "Binary removed"
    fi

    # Remove config
    if [ -f "$CONFIG_PATH" ]; then
        info "Removing config..."
        $SUDO_CMD rm -f "$CONFIG_PATH"
        [ -d "$CONFIG_DIR" ] && $SUDO_CMD rmdir "$CONFIG_DIR" 2>/dev/null || true
        success "Config removed"
    fi

    # Ask about keys
    if [ -d "$KEY_DIR" ]; then
        echo ""
        warn "Key directory found at ${KEY_DIR}"
        warn "This contains your server identity and claim binding."
        warn "If you delete it, you will need to re-claim the server."
        echo ""
        read -rp "Delete key directory? [y/N] " confirm
        if [[ "$confirm" =~ ^[Yy]$ ]]; then
            $SUDO_CMD rm -rf "$DATA_DIR"
            success "Data directory removed"
        else
            info "Key directory preserved at ${KEY_DIR}"
        fi
    fi

    # Remove system user (Linux)
    if [ "$OS" = "linux" ] && id "$SERVICE_NAME" &>/dev/null; then
        info "Removing system user..."
        $SUDO_CMD userdel "$SERVICE_NAME" 2>/dev/null || true
        success "System user removed"
    fi

    echo ""
    success "StealthOS Relay has been uninstalled."
}

# ── Update ────────────────────────────────────────────────────────────────────

do_update() {
    echo -e "${BOLD}StealthOS Relay — Update${NC}"
    echo ""

    if [ ! -f "$BINARY_PATH" ]; then
        fatal "StealthRelay is not installed at ${BINARY_PATH}. Run without --update to install."
    fi

    resolve_version
    download_binary

    stop_service

    install_binary

    if [ "$OS" = "linux" ] && [ -f "/etc/systemd/system/${SERVICE_NAME}.service" ]; then
        $SUDO_CMD systemctl start "$SERVICE_NAME"
    elif [ "$OS" = "darwin" ]; then
        start_service
    fi

    echo ""
    success "StealthOS Relay updated to ${VERSION}"
}

# ── Main install flow ─────────────────────────────────────────────────────────

do_install() {
    echo ""
    echo -e "${BOLD}StealthOS Relay — Installer${NC}"
    echo -e "Zero-knowledge WebSocket relay for StealthOS"
    echo ""

    if [ -f "$BINARY_PATH" ]; then
        warn "StealthRelay is already installed at ${BINARY_PATH}"
        warn "Use --update to update or --uninstall to remove first."
        exit 1
    fi

    resolve_version
    download_binary
    install_binary
    create_dirs_and_config

    if [ "$NO_SERVICE" = false ]; then
        if [ "$OS" = "linux" ]; then
            create_system_user
            install_systemd_service
        elif [ "$OS" = "darwin" ]; then
            install_launchd_service
        fi

        start_service
        install_update_timer

        if wait_for_health; then
            show_setup_url
        fi
    else
        echo ""
        success "Installation complete (no service created)."
        echo ""
        echo "  Start manually with:"
        echo "  ${BINARY_PATH} serve --config ${CONFIG_PATH}"
        echo ""
    fi
}

# ── Entry point ───────────────────────────────────────────────────────────────

detect_platform
check_prereqs
configure_paths

if [ "$UNINSTALL" = true ]; then
    do_uninstall
elif [ "$UPDATE" = true ]; then
    do_update
else
    do_install
fi
