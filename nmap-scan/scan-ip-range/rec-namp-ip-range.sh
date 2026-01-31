#!/usr/bin/env bash
set -euo pipefail

show_help() {
  cat <<'EOF'
Usage:
  rec-nmap-ip-range.sh [OPTIONS] <target> [outdir]

Targets:
  CIDR            10.0.10.0/24
  Range           10.0.10.1-50
  Single IP       10.0.10.5
  File            targets.txt   (one target per line)

Options:
  -h, --help      Show this help message and exit

Environment variables:
  RATE            Nmap --min-rate value (default: 2000)
  NMAP_EXTRA      Extra nmap flags (optional)

Examples:
  proxychains4 -q ./rec-nmap-ip-range.sh targets.txt
  RATE=1000 proxychains4 -q ./rec-nmap-ip-range.sh 10.0.10.0/24

Nmap flags used (TCP only):
  -sT -Pn --top-ports 200 -sV --version-light --open
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  show_help
  exit 0
fi

TARGET="${1:-}"
OUTDIR="${2:-out}"

if [[ -z "$TARGET" ]]; then
  echo "[-] Missing target"
  echo
  show_help
  exit 1
fi

if ! command -v nmap >/dev/null 2>&1; then
  echo "[-] nmap not found"
  exit 1
fi

RATE="${RATE:-2000}"
NMAP_EXTRA="${NMAP_EXTRA:-}"

mkdir -p "$OUTDIR"
SUMMARY="$OUTDIR/summary.csv"
echo "ip,port,proto,state,service,info" > "$SUMMARY"

if [[ -f "$TARGET" ]]; then
  NMAP_TARGET_ARGS=(-iL "$TARGET")
else
  NMAP_TARGET_ARGS=("$TARGET")
fi

TMP_GNMAP="$OUTDIR/_scan.gnmap"

echo "[*] Script     : rec-nmap-ip-range.sh"
echo "[*] Target     : $TARGET"
echo "[*] Output dir: $OUTDIR"
echo "[*] Scan      : TCP only (-sT) + top-ports 200 + light version detect"
echo "[*] Rate      : $RATE"
echo

# TCP-only scan (proxychains wraps this)
nmap \
  -sT -Pn \
  --top-ports 200 \
  -sV --version-light \
  --open \
  --min-rate "$RATE" \
  $NMAP_EXTRA \
  -oG "$TMP_GNMAP" \
  "${NMAP_TARGET_ARGS[@]}" >/dev/null

# Parse gnmap output
while IFS= read -r line; do
  [[ "$line" == Host:* ]] || continue
  [[ "$line" == *"Ports:"* ]] || continue

  ip="$(awk '{print $2}' <<<"$line")"
  ports_field="${line#*Ports: }"

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

  [[ -n "$entries" ]] || continue

  hostdir="$OUTDIR/$ip"
  mkdir -p "$hostdir"

  printf "%s\n" "$line" > "$hostdir/nmap.txt"

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
    printf "%s,%s,%s,%s,%s,\"%s\"\n" "$ip" "$port" "$proto" "$state" "$service" "$info" >> "$SUMMARY"
  done <<< "$entries"

done < "$TMP_GNMAP"

echo "[*] Done"
echo "[*] Summary CSV: $SUMMARY"
