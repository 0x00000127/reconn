#!/usr/bin/env bash
set -euo pipefail

# ============================================
# Proxychains-safe Nmap Open Port Scanner
# ============================================
# Usage:
#   proxychains4 -q ./scan-open-ports.sh 10.0.10.0/24
#   proxychains4 -q ./scan-open-ports.sh 10.0.10.1-50
#   proxychains4 -q ./scan-open-ports.sh targets.txt
#
# Output:
#   out/<ip>/open-ports.txt
#   out/<ip>/nmap.txt
#   out/summary.csv
# ============================================

TARGET="${1:-}"
OUTDIR="${2:-out}"

# Tor / proxy-safe defaults
PORTS="${PORTS:-1-65535}"
RATE="${RATE:-2000}"
SCAN_TYPE="-sT"   # FORCE TCP connect scan (required for proxychains)
NMAP_EXTRA="${NMAP_EXTRA:---max-retries 2 --host-timeout 30s --scan-delay 200ms}"

if [[ -z "$TARGET" ]]; then
  echo "Usage: $0 <ip-range|cidr|targets.txt> [outdir]"
  exit 1
fi

if ! command -v nmap >/dev/null 2>&1; then
  echo "nmap not found. Install it first."
  exit 1
fi

mkdir -p "$OUTDIR"
SUMMARY="$OUTDIR/summary.csv"
echo "ip,open_ports" > "$SUMMARY"

# Target handling
NMAP_TARGET_ARGS=()
if [[ -f "$TARGET" ]]; then
  NMAP_TARGET_ARGS=(-iL "$TARGET")
else
  NMAP_TARGET_ARGS=("$TARGET")
fi

TMP_GNMAP="$OUTDIR/_scan.gnmap"

echo "[*] Target      : $TARGET"
echo "[*] Output dir : $OUTDIR"
echo "[*] Ports      : $PORTS"
echo "[*] Scan type  : TCP connect (-sT)"
echo "[*] Rate       : $RATE"
echo

# -----------------------------
# Run Nmap (proxychains wraps this)
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

  # Open ports list
  {
    echo "$ip"
    echo "$open_ports" | tr ',' '\n'
  } > "$hostdir/open-ports.txt"

  # Raw nmap line
  echo "$line" > "$hostdir/nmap.txt"

  # Summary
  echo "$ip,\"$open_ports\"" >> "$SUMMARY"

done < "$TMP_GNMAP"

echo "[*] Done"
echo "[*] Summary: $SUMMARY"
echo "[*] Hosts with open ports:"
cut -d, -f1 "$SUMMARY" | tail -n +2
