#!/usr/bin/env bash
set -Eeuo pipefail

VERSION="1.0.0"
PORT="25"

PROGRAM_NAME="smtp25-guard"
INSTALL_PATH="/usr/local/sbin/${PROGRAM_NAME}"
SERVICE_NAME="${PROGRAM_NAME}.service"
TIMER_NAME="${PROGRAM_NAME}.timer"
SERVICE_PATH="/etc/systemd/system/${SERVICE_NAME}"
TIMER_PATH="/etc/systemd/system/${TIMER_NAME}"

NFT_FAMILY="inet"
NFT_TABLE="smtp25_guard"
DEFAULT_LOG_GLOB="/opt/remnanode/access.log*"
DEFAULT_WATCH_LOG="/opt/remnanode/access.log"

log() {
    printf '[%s] %s\n' "${PROGRAM_NAME}" "$*"
}

warn() {
    printf '[%s] WARNING: %s\n' "${PROGRAM_NAME}" "$*" >&2
}

die() {
    printf '[%s] ERROR: %s\n' "${PROGRAM_NAME}" "$*" >&2
    exit 1
}

require_root() {
    [[ ${EUID:-$(id -u)} -eq 0 ]] || die "Run this command as root (use sudo)."
}

have() {
    command -v "$1" >/dev/null 2>&1
}

chain_exists() {
    local bin="$1"
    local chain="$2"
    "$bin" -w 10 -S "$chain" >/dev/null 2>&1
}

tcp_rule() {
    printf '%s\0' \
        -p tcp --dport "$PORT" \
        -m comment --comment "$PROGRAM_NAME" \
        -j REJECT --reject-with tcp-reset
}

udp_rule() {
    printf '%s\0' \
        -p udp --dport "$PORT" \
        -m comment --comment "$PROGRAM_NAME" \
        -j DROP
}

add_rule() {
    local bin="$1"
    local chain="$2"
    local proto="$3"
    local -a rule=()

    chain_exists "$bin" "$chain" || return 0

    if [[ "$proto" == "tcp" ]]; then
        mapfile -d '' -t rule < <(tcp_rule)
    else
        mapfile -d '' -t rule < <(udp_rule)
    fi

    if "$bin" -w 10 -C "$chain" "${rule[@]}" >/dev/null 2>&1; then
        return 0
    fi

    "$bin" -w 10 -I "$chain" 1 "${rule[@]}"
    log "Added ${bin##*/} ${chain} ${proto}/${PORT} rule."
}

delete_rule() {
    local bin="$1"
    local chain="$2"
    local proto="$3"
    local -a rule=()

    chain_exists "$bin" "$chain" || return 0

    if [[ "$proto" == "tcp" ]]; then
        mapfile -d '' -t rule < <(tcp_rule)
    else
        mapfile -d '' -t rule < <(udp_rule)
    fi

    while "$bin" -w 10 -C "$chain" "${rule[@]}" >/dev/null 2>&1; do
        "$bin" -w 10 -D "$chain" "${rule[@]}"
    done
}

apply_xtables_family() {
    local bin="$1"
    local chain

    [[ -n "$bin" ]] || return 0

    for chain in INPUT OUTPUT FORWARD DOCKER-USER; do
        add_rule "$bin" "$chain" tcp
        add_rule "$bin" "$chain" udp
    done
}

remove_xtables_family() {
    local bin="$1"
    local chain

    [[ -n "$bin" ]] || return 0

    for chain in INPUT OUTPUT FORWARD DOCKER-USER; do
        delete_rule "$bin" "$chain" tcp
        delete_rule "$bin" "$chain" udp
    done
}

docker_uses_nftables() {
    if [[ -r /etc/docker/daemon.json ]] &&
       grep -Eiq '"firewall-backend"[[:space:]]*:[[:space:]]*"nftables"' /etc/docker/daemon.json; then
        return 0
    fi

    if have docker && docker info >/dev/null 2>&1; then
        if docker info 2>/dev/null | grep -Eiq 'firewall[[:space:]-]*backend.*nftables'; then
            return 0
        fi

        if ! have iptables || ! iptables -w 10 -S DOCKER-USER >/dev/null 2>&1; then
            return 0
        fi
    fi

    return 1
}

apply_nftables() {
    have nft || return 0

    # Docker's nftables backend has no DOCKER-USER chain. A separate table
    # with priority -10 runs before ordinary filter-priority chains.
    if ! docker_uses_nftables && have iptables; then
        return 0
    fi

    if nft list table "$NFT_FAMILY" "$NFT_TABLE" >/dev/null 2>&1; then
        return 0
    fi

    nft -f - <<EOF
table ${NFT_FAMILY} ${NFT_TABLE} {
    chain input {
        type filter hook input priority -10; policy accept;
        tcp dport ${PORT} counter reject with tcp reset
        udp dport ${PORT} counter drop
    }

    chain output {
        type filter hook output priority -10; policy accept;
        tcp dport ${PORT} counter reject with tcp reset
        udp dport ${PORT} counter drop
    }

    chain forward {
        type filter hook forward priority -10; policy accept;
        tcp dport ${PORT} counter reject with tcp reset
        udp dport ${PORT} counter drop
    }
}
EOF

    log "Created nftables table ${NFT_FAMILY} ${NFT_TABLE}."
}

remove_nftables() {
    if have nft && nft list table "$NFT_FAMILY" "$NFT_TABLE" >/dev/null 2>&1; then
        nft delete table "$NFT_FAMILY" "$NFT_TABLE"
        log "Removed nftables table ${NFT_FAMILY} ${NFT_TABLE}."
    fi
}

apply_rules() {
    require_root

    local ipt=""
    local ip6t=""

    have iptables && ipt="$(command -v iptables)"
    have ip6tables && ip6t="$(command -v ip6tables)"

    if [[ -z "$ipt" ]] && ! have nft; then
        die "Neither iptables nor nft is installed."
    fi

    apply_xtables_family "$ipt"
    apply_xtables_family "$ip6t"
    apply_nftables

    log "Port ${PORT} is blocked for inbound, outbound, and forwarded TCP/UDP traffic."
    log "Ports 465 and 587 are not changed."
}

remove_rules() {
    require_root

    local ipt=""
    local ip6t=""

    have iptables && ipt="$(command -v iptables)"
    have ip6tables && ip6t="$(command -v ip6tables)"

    remove_xtables_family "$ipt"
    remove_xtables_family "$ip6t"
    remove_nftables

    log "Removed rules managed by ${PROGRAM_NAME}."
}

print_chain_status() {
    local bin="$1"
    local chain="$2"

    chain_exists "$bin" "$chain" || return 0

    printf '\n=== %s %s ===\n' "${bin##*/}" "$chain"
    "$bin" -w 10 -vnL "$chain" --line-numbers 2>/dev/null |
        grep -E "dpt:${PORT}([^0-9]|$)" || printf 'No matching rules.\n'
}

status_rules() {
    local ipt=""
    local ip6t=""

    have iptables && ipt="$(command -v iptables)"
    have ip6tables && ip6t="$(command -v ip6tables)"

    if [[ -n "$ipt" ]]; then
        print_chain_status "$ipt" INPUT
        print_chain_status "$ipt" OUTPUT
        print_chain_status "$ipt" FORWARD
        print_chain_status "$ipt" DOCKER-USER
    fi

    if [[ -n "$ip6t" ]]; then
        print_chain_status "$ip6t" INPUT
        print_chain_status "$ip6t" OUTPUT
        print_chain_status "$ip6t" FORWARD
        print_chain_status "$ip6t" DOCKER-USER
    fi

    if have nft; then
        printf '\n=== nftables ===\n'
        if nft list table "$NFT_FAMILY" "$NFT_TABLE" 2>/dev/null; then
            :
        else
            printf 'No %s table.\n' "$NFT_TABLE"
        fi
    fi

    if have systemctl; then
        printf '\n=== systemd ===\n'
        systemctl is-enabled "$SERVICE_NAME" 2>/dev/null || true
        systemctl is-active "$SERVICE_NAME" 2>/dev/null || true
        systemctl is-enabled "$TIMER_NAME" 2>/dev/null || true
        systemctl is-active "$TIMER_NAME" 2>/dev/null || true
        systemctl list-timers "$TIMER_NAME" --no-pager 2>/dev/null || true
    fi
}

install_service() {
    require_root
    have systemctl || die "systemd is required for installation."

    local source_path
    source_path="$(readlink -f "$0")"

    if [[ "$source_path" != "$INSTALL_PATH" ]]; then
        install -m 0755 "$source_path" "$INSTALL_PATH"
        log "Installed executable to ${INSTALL_PATH}."
    fi

    cat >"$SERVICE_PATH" <<EOF
[Unit]
Description=Block SMTP port 25 on host and container traffic
After=network-online.target docker.service ufw.service
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=${INSTALL_PATH} apply

[Install]
WantedBy=multi-user.target
EOF

    cat >"$TIMER_PATH" <<EOF
[Unit]
Description=Periodically verify SMTP port 25 firewall rules

[Timer]
OnBootSec=30s
OnUnitActiveSec=60s
AccuracySec=10s
Persistent=true
Unit=${SERVICE_NAME}

[Install]
WantedBy=timers.target
EOF

    systemctl daemon-reload
    systemctl enable "$SERVICE_NAME" >/dev/null
    systemctl enable --now "$TIMER_NAME" >/dev/null
    systemctl start "$SERVICE_NAME"

    log "Installed and enabled ${SERVICE_NAME}."
    log "A timer verifies the rules every 60 seconds."
    log "Run: sudo ${PROGRAM_NAME} status"
}

disable_service() {
    require_root

    if have systemctl; then
        systemctl disable --now "$TIMER_NAME" >/dev/null 2>&1 || true
        systemctl stop "$SERVICE_NAME" >/dev/null 2>&1 || true
    fi

    remove_rules
    log "Service disabled. Installation files were kept."
}

uninstall_service() {
    require_root

    if have systemctl; then
        systemctl disable --now "$TIMER_NAME" >/dev/null 2>&1 || true
        systemctl disable --now "$SERVICE_NAME" >/dev/null 2>&1 || true
    fi

    remove_rules

    rm -f "$SERVICE_PATH" "$TIMER_PATH"
    if [[ -e "$INSTALL_PATH" ]]; then
        rm -f "$INSTALL_PATH"
    fi

    if have systemctl; then
        systemctl daemon-reload
        systemctl reset-failed "$SERVICE_NAME" "$TIMER_NAME" >/dev/null 2>&1 || true
    fi

    log "Uninstalled ${PROGRAM_NAME}."
}

audit_logs() {
    require_root

    local pattern="${1:-$DEFAULT_LOG_GLOB}"
    local output="${2:-/root/smtp25-audit-$(date -u +%Y%m%dT%H%M%SZ).log}"
    local -a files=()

    have zgrep || die "zgrep is required for audit mode."

    mapfile -t files < <(compgen -G "$pattern" || true)
    ((${#files[@]} > 0)) || die "No files matched: ${pattern}"

    zgrep -hE \
        "accepted tcp:[^[:space:]]+:${PORT}([[:space:]]|$)" \
        "${files[@]}" 2>/dev/null |
        sort >"$output"

    local total
    total="$(wc -l <"$output" | tr -d ' ')"

    printf 'Evidence file: %s\n' "$output"
    printf 'TCP/%s attempts: %s\n' "$PORT" "$total"

    printf '\n=== Attempts by user/email ===\n'
    sed -n 's/.* email: \([^[:space:]]*\).*/\1/p' "$output" |
        sort | uniq -c | sort -nr || true

    printf '\n=== Attempts by client IP ===\n'
    sed -nE 's/.* from (tcp:)?([^: ]+):[0-9]+ accepted .*/\2/p' "$output" |
        sort | uniq -c | sort -nr || true

    printf '\n=== User + client + destination ===\n'
    sed -nE \
        "s/.* from (tcp:)?([^: ]+):[0-9]+ accepted tcp:([^ ]+):${PORT} .* email: ([^ ]+).*/email=\4 client=\2 dst=\3:${PORT}/p" \
        "$output" |
        sort | uniq -c | sort -nr || true

    if have sha256sum; then
        printf '\n=== SHA-256 ===\n'
        sha256sum "$output"
    fi
}

watch_log() {
    local log_file="${1:-$DEFAULT_WATCH_LOG}"

    [[ -f "$log_file" ]] || die "Log file not found: ${log_file}"

    log "Watching TCP/${PORT} attempts in ${log_file}. Press Ctrl+C to stop."
    tail -Fn0 "$log_file" |
        grep --line-buffered -E \
            "accepted tcp:[^[:space:]]+:${PORT}([[:space:]]|$)"
}

show_help() {
    cat <<EOF
${PROGRAM_NAME} ${VERSION}

Block SMTP port 25 on Linux hosts and Docker traffic.

Usage:
  sudo ./${PROGRAM_NAME}.sh install
  sudo ${PROGRAM_NAME} apply
  sudo ${PROGRAM_NAME} status
  sudo ${PROGRAM_NAME} audit [LOG_GLOB] [OUTPUT_FILE]
  sudo ${PROGRAM_NAME} watch [LOG_FILE]
  sudo ${PROGRAM_NAME} disable
  sudo ${PROGRAM_NAME} uninstall

Commands:
  install     Install to ${INSTALL_PATH} and enable systemd service/timer.
  apply       Apply or repair firewall rules immediately.
  status      Show rules, packet counters, and systemd state.
  audit       Search current and rotated logs for exact TCP/${PORT} attempts.
              Default glob: ${DEFAULT_LOG_GLOB}
  watch       Watch the current access log in real time.
              Default file: ${DEFAULT_WATCH_LOG}
  disable     Stop automation and remove managed firewall rules.
  uninstall   Disable, remove rules, and delete installed files.
  version     Print version.

Examples:
  sudo ./${PROGRAM_NAME}.sh install
  sudo ${PROGRAM_NAME} audit '/opt/remnanode/access.log*'
  sudo ${PROGRAM_NAME} watch /opt/remnanode/access.log
EOF
}

main() {
    local command="${1:-help}"
    shift || true

    case "$command" in
        install)   install_service "$@" ;;
        apply)     apply_rules "$@" ;;
        status)    status_rules "$@" ;;
        audit)     audit_logs "$@" ;;
        watch)     watch_log "$@" ;;
        disable)   disable_service "$@" ;;
        uninstall) uninstall_service "$@" ;;
        version|--version|-V) printf '%s\n' "$VERSION" ;;
        help|--help|-h) show_help ;;
        *) show_help; exit 2 ;;
    esac
}

main "$@"
