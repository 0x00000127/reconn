

# SCAN Targets file (mix CIDR/IP/domain/range)
```
proxychains4 -q nmap -sT -Pn --top-ports 1000 -sV --version-light --stats-every 3s -d 1 -oG result.gnmap --open -iL targets.txt  
```
