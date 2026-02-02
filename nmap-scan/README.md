

# SCAN Target file behind tor proxy (mix CIDR/IP/domain/range)
```
proxychains4 -q nmap -sT -Pn --top-ports 1000 -sV --version-light --stats-every 3s -d 1 -oG result.gnmap --open -iL targets.txt  
```


# Get info from .namp report 

```
awk '
/^Nmap scan report for/ {
    target=$5
    ip=target
    if (match($0, /\(([^)]+)\)/, m)) {
        ip=m[1]
    }
}
/\/tcp\s+open/ {
    printf "%s,%s,%s,%s\n", target, ip, $1, $3
}
' scan.nmap

```