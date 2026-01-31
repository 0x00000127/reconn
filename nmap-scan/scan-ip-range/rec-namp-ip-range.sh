#!/usr/bin/env bash
set -euo pipefail

log() { printf "[*] %s\n" "$*"; }
warn() { printf "[!] %s\n" "$*" >&2; }

show_help() {
  cat <<'EOF'
Usage:
  rec-nmap-ip-range.sh [OPTIONS] <target> [outdir]

Targets:
  CIDR / range / single IP / targets.txt (one target per line)

Options:
  -h, --help      Show help and exit

Environment variables:
  RATE            Nmap --min-rate (default: 2000)
  NMAP_EXTRA      Extra nmap flags (optional)

Example:
  proxychains4 -q ./rec-nmap-ip-range.sh targets.txt
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  show_help
  exit 0
fi

TARGET="${1:-}"
OUTDIR="${2:-out}"
[[ -z "$TARGET" ]] && { warn "Missing target"; show_help; exit 1; }
command -v nmap >/dev/null 2>&1 || { warn "nmap not installed"; exit 1; }

RATE="${RATE:-2000}"
NMAP_EXTRA="${NMAP_EXTRA:-}"

mkdir -p "$OUTDIR"
SUMMARY="$OUTDIR/summary.csv"
NMAP_LOG="$OUTDIR/_nmap.log"
CLEAN_TARGET="$OUTDIR/_targets.clean.txt"

echo "ip,port,proto,state,service,info" > "$SUMMARY"
: > "$NMAP_LOG"

# Sanitize targets into a clean file (supports ranges/CIDR per line)
if [[ -f "$TARGET" ]]; then
  log "Loading targets from file: $TARGET"
  awk '
    { gsub(/\r/,""); sub(/^[ \t]+/,""); sub(/[ \t]+$/,""); }
    $0=="" { next }
    $0 ~ /^#/ { next }
    { print }
  ' "$TARGET" > "$CLEAN_TARGET"
  log "Sanitized targets saved: $CLEAN_TARGET"
  NMAP_TARGET_ARGS=(-iL "$CLEAN_TARGET")
else
  log "Using direct target expression: $TARGET"
  NMAP_TARGET_ARGS=("$TARGET")
fi

log "Starting nmap scan..."
log "Flags: -sT -Pn --top-ports 200 -sV --version-light --open --min-rate $RATE"

# Run nmap and capture normal output (this is what we will parse)
nmap \
  -sT -Pn \
  --top-ports 200 \
  -sV --version-light \
  --open \
  --min-rate "$RATE" \
  $NMAP_EXTRA \
  "${NMAP_TARGET_ARGS[@]}" 2>&1 | tee "$NMAP_LOG" >/dev/null

log "Nmap scan completed"
log "Parsing: $NMAP_LOG"

host_count=0
port_count=0

# Parse normal output into per-IP blocks and port lines
awk -v outdir="$OUTDIR" -v summary="$SUMMARY" '
function trim(s){ sub(/^[ \t]+/,"",s); sub(/[ \t]+$/,"",s); return s }

BEGIN {
  ip=""
  in_ports=0
  buf=""
}

# Start of a host section:
# "Nmap scan report for NAME (IP)"
# or: "Nmap scan report for IP"
$0 ~ /^Nmap scan report for / {
  # Flush previous host if needed
  if (ip != "") {
    # write buffered nmap text
    if (buf != "") {
      hostdir = outdir "/" ip
      system("mkdir -p \"" hostdir "\"")
      nmapfile = hostdir "/nmap.txt"
      print buf > nmapfile
      close(nmapfile)
    }
  }

  buf = $0 "\n"
  in_ports = 0

  # Extract IP:
  # If line has "(x.x.x.x)" use that; else last field is IP
  if (match($0, /\(([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\)/, m)) {
    ip = m[1]
  } else {
    # last token
    n = split($0, a, " ")
    ip = a[n]
  }

  next
}

# Collect lines for the current host block
ip != "" {
  buf = buf $0 "\n"
}

# Detect port table header
ip != "" && $0 ~ /^PORT[ \t]+STATE[ \t]+SERVICE/ {
  in_ports = 1
  next
}

# End port table when we hit an empty line or a non port line
ip != "" && in_ports == 1 {
  if ($0 ~ /^$/) { in_ports = 0; next }

  # Port line example:
  # 53/tcp open  domain  dnsmasq 2.89
  # 443/tcp open  ssl/http nginx
  if (match($0, /^([0-9]+)\/(tcp|udp)[ \t]+([a-zA-Z|]+)[ \t]+([^ \t]+)[ \t]*(.*)$/, p)) {
    port = p[1]
    proto = p[2]
    state = p[3]
    service = p[4]
    info = trim(p[5])
    if (info == "") info = "-"

    hostdir = outdir "/" ip
    system("mkdir -p \"" hostdir "\"")

    openfile = hostdir "/open-ports.txt"

    # If file doesn’t exist yet, write the IP header first
    # (awk can’t easily test existence portably; just write header once per host using a flag)
    if (!(ip in wrote_header)) {
      print ip > openfile
      wrote_header[ip] = 1
    }

    print port "/" proto " " state " " service " " info >> openfile
    close(openfile)

    # summary csv
    gsub(/"/, "\"\"", info)
    printf "%s,%s,%s,%s,%s,\"%s\"\n", ip, port, proto, state, service, info >> summary
  }
}

END {
  # Flush last host block
  if (ip != "" && buf != "") {
    hostdir = outdir "/" ip
    system("mkdir -p \"" hostdir "\"")
    nmapfile = hostdir "/nmap.txt"
    print buf > nmapfile
    close(nmapfile)
  }
}
' "$NMAP_LOG"

# Remove empty folders (in case any were created without ports)
find "$OUTDIR" -mindepth 1 -maxdepth 1 -type d -empty -print -delete >/dev/null 2>&1 || true

log "Done"
log "Summary CSV: $SUMMARY"
log "Per-host folders: $OUTDIR/<ip>/"
