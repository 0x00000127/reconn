#!/usr/bin/env bash
set -euo pipefail

log() {
  printf "[*] %s\n" "$*"
}

warn() {
  printf "[!] %s\n" "$*" >&2
}

show_help() {
  cat <<'EOF'
Usage:
  rec-nmap-ip-range.sh [OPTIONS] <target> [outdir]

Targets:
  CIDR            10.0.10.0/24
  Range           10.0.10.1-50
  Single IP       10.0.10.5
  File            targets.txt   (one target/range per line)

Options:
  -h, --help      Show this help message and exit

Environment variables:
  RATE            Nmap --min-rate (default: 2000)
  NMAP_EXTRA      Extra nmap flags

Examples:
  proxychains4 -q ./rec-nmap-ip-range.sh targets.txt
  RATE=1000 NMAP_EXTRA="--host-timeout 60s" proxychains4 -q ./rec-nmap-ip-range.sh 10.0.10.0/24

Nmap flags used:
  -sT -Pn --top-ports 200 -sV --version-light --open
EOF
}

# -----------------------------
# Help flag
# -----------------------------
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
echo "ip,port,proto,state,service,info" > "$SUMMARY"

# -----------------------------
# Target handling
# -----------------------------
if [[ -f "$TARGET" ]]; then
  log "Loading targets from file: $TARGET"
  NMAP_TARGET_ARGS=(-iL "$TARGET")
else
  log "Using direct target expression: $TARGET"
  NMAP_TARGET_ARGS=("$TARGET")
fi

TMP_GNMAP="$OUTDIR/_scan.gnmap"

log "Output directory : $OUTDIR"
log "Scan type        : TCP connect (-sT)"
log "Top ports        : 200"
log "Version detect   : light"
log "Min rate         : $RATE"
log "Starting nmap scan..."

# -----------------------------
# Run nmap (proxychains wraps this)
# -----------------------------
nmap \
  -sT -Pn \
  --top-ports 200 \
  -sV --version-light \
  --open \
  --min-rate "$RATE" \
  $NMAP_EXTRA \
  -oG "$TMP_GNMAP" \
  "${NMAP_TARGET_ARGS[@]}"

log "Nmap scan completed"
log "Parsing results..."

host_count=0
port_count=0

# -----------------------------
# Parse gnmap output
# -----------------------------
while IFS= read -r line; do
  [[ "$line" == Host:* ]] || continue
  [[ "$line" == *"Ports:"* ]] || continue

  ip="$(awk '{print $2}' <<<"$line")"
  ports_field="${line#*Ports: }"

  log "Processing host: $ip"

  entries="$(
    awk -v s="$ports_field" 'BEGIN{
      n=split(s,a,",");
      for(i=1;i<=n;i++){
        gsub(/^ +| +$/,"",a[i]);
        split(a[i],b,"/");
        port=b[1]; state=b[2]; proto=b[3]; service=b[5]; info=b[7];
        if(service=="") service="-";
        if(info=="") info="-";
        if(state=="open" && proto=="tcp"){
          print port "/" proto " " state " " service " " info;
        }
      }
    }'
  )"

  if [[ -z "$entries" ]]; then
    warn "No open TCP ports found for $ip"
    continue
  fi

  hostdir="$OUTDIR/$ip"
  mkdir -p "$hostdir"
  ((host_count++))

  echo "$line" > "$hostdir/nmap.txt"

  {
    echo "$ip"
    echo "$entries"
  } > "$hostdir/open-ports.txt"

  while IFS= read -r e; do
    portproto="$(awk '{print $1}' <<<"$e")"
    state="$(awk '{print $2}' <<<"$e")"
    service="$(awk '{print $3}' <<<"$e")"
    info="$(cut -d' ' -f4- <<<"$e")"
    port="${portproto%/*}"
    proto="${portproto#*/}"
    printf "%s,%s,%s,%s,%s,\"%s\"\n" \
      "$ip" "$port" "$proto" "$state" "$service" "$info" >> "$SUMMARY"
    ((port_count++))
    log "  → $port/$proto $service"
  done <<< "$entries"

done < "$TMP_GNMAP"

log "Recon finished"
log "Hosts with open ports : $host_count"
log "Total open ports      : $port_count"
log "Summary CSV           : $SUMMARY"
