#!/usr/bin/env bash
set -euo pipefail

# ============================================
# Proxychains-safe Nmap Open Port Scanner
# ============================================

show_help() {
  cat <<'EOF'
Usage:
  scan-open-ports.sh [OPTIONS] <target> [outdir]

Targets:
  CIDR            10.0.10.0/24
  Range           10.0.10.1-50
  Single IP       10.0.10.5
  File            targets.txt   (one target per line)

Options:
  -h, --help      Show this help message and exit

Environment variables:
  PORTS           Port range to scan (default: 1-65535)
  RATE            Nmap --min-rate value (default: 2000)
  NMAP_EXTRA      Extra nmap flags
                  (default: --max-retries 2 --host-timeout 30s --scan-delay 200ms)

Examples:
  proxychains4 -q ./scan-open-ports.sh 10.0.10.0/24
  PORTS=1-1000 proxychains4 -q ./scan-open-ports.sh targets.txt
  RATE=1000 NMAP_EXTRA="--max-retries 1" proxychains4 -q ./scan-open-ports.sh 1.2.3.4

Output:
  out/<ip>/open-ports.txt
  out/<ip>/nmap.txt
  out/summary.csv
EOF
}

# -----------------------------
# Arg parsing
# -----------------------------
if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  show_help
  exit 0
fi

TARGET="${1:-}"
OUTDIR="${2:-out}"

# -----------------------------
# Defaults (Tor / proxy safe)
# -----------------------------
PORTS="${PORTS:-1-65535}"
RATE="${RATE:-2000}"
SCAN_TYPE="-sT"   # REQUIRED for proxychains
NMAP_EXTRA="${NMAP_EXTRA:---max-retries 2 --host-timeout 30s --scan-delay 200ms}"

if [[ -z "$TARGET" ]]; then
  echo "[-] Missing target"
  echo
  show_help
  exit 1
fi

if ! command -v nmap >/dev/null 2>&1; then
  echo "[-] nmap not found. Install it first."
  exit 1
fi

mkdir -p "$OUTDIR"
SUMMARY="$OUTDIR/summary.csv"
echo "ip,open_ports" > "$SUMMARY"

# -----------------------------
# Target handling
# -----------------------------
if [[ -f "$TARGET" ]]; then
  NMAP_TARGET_ARGS=(-iL "$TARGET")
else
  NMAP_TARGET_ARGS=("$TARGET")
fi

TMP_GNMAP="$OUTDIR/_scan.gnmap"

echo "[*] Target     : $TARGET"
echo "[*] Output dir: $OUTDIR"
echo "[*] Ports     : $PORTS"
echo "[*] Rate      : $RATE"
echo "[*] Scan type : TCP connect (-sT)"
echo

# -----------------------------
# Run scan (proxychains wraps this)
# -----------------------------
nmap -n -Pn $SCAN_TYPE --open \
  -p "$PORTS" \
  --min-rate "$RATE" \
  $NMAP_EXTRA \
  -oG "$TMP_GNMAP" \
  "${NMAP_TARGET_ARGS[@]}" >/dev/null

# -----------------------------
# Parse results
# -----------------------------
while IFS= read -r line; do
  [[ "$line" == Host:* ]] || continue
  [[ "$line" == *"Ports:"* ]] || continue

  ip="$(awk '{print $2}' <<<"$line")"
  ports_field="${line#*Ports: }"

  open_ports="$(
    awk -v s="$ports_field" 'BEGIN{
      n=split(s,a,",");
      for(i=1;i<=n;i++){
        gsub(/^ +| +$/,"",a[i]);
        split(a[i],b,"/");
        if(b[2]=="open" && b[3]=="tcp") print b[1];
      }
    }' | sort -n | paste -sd, -
  )"

  [[ -n "$open_ports" ]] || continue

  hostdir="$OUTDIR/$ip"
  mkdir -p "$hostdir"

  {
    echo "$ip"
    echo "$open_ports" | tr ',' '\n'
  } > "$hostdir/open-ports.txt"

  echo "$line" > "$hostdir/nmap.txt"
  echo "$ip,\"$open_ports\"" >> "$SUMMARY"

done < "$TMP_GNMAP"

echo "[*] Done"
echo "[*] Summary: $SUMMARY"
