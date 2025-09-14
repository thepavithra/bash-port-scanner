#!/usr/bin/env bash
# Simple TCP port scanner (connect-scan) in pure Bash
# File: bash-port-scanner.sh
# Usage examples:
#   ./bash-port-scanner.sh -t example.com             # scans ports 1-1024
#   ./bash-port-scanner.sh -t 192.168.1.10 -r 20-80   # scans ports 20..80
#   ./bash-port-scanner.sh -t host -p 22,80,443       # scans only listed ports
#   ./bash-port-scanner.sh -t host -T 0.5 -c 200      # set timeout and concurrency

# DISCLAIMER: Only scan hosts you own or have explicit permission to test.
# Unauthorized scanning can be illegal and/or disruptive.

set -u

TARGET=""
PORTS=""
RANGE="1-1024"
TIMEOUT=1    # seconds for each connection attempt
CONCURRENCY=200
VERBOSE=0

print_help(){
  cat <<EOF
Usage: $0 -t target [options]

Options:
  -t target         Target host or IP (required)
  -p ports          Comma-separated ports (e.g. 22,80,443)
  -r start-end      Port range (e.g. 1-1024). Default: ${RANGE}
  -T timeout        Per-port connect timeout in seconds (float OK). Default: ${TIMEOUT}
  -c concurrency    Number of parallel connection attempts. Default: ${CONCURRENCY}
  -v                Verbose output (show progress)
  -h                Show this help

Examples:
  $0 -t example.com
  $0 -t 10.0.0.5 -r 1-65535 -T 0.3 -c 500
EOF
}

# parse args
while getopts ":t:p:r:T:c:vh" opt; do
  case "$opt" in
    t) TARGET="$OPTARG" ;;
    p) PORTS="$OPTARG" ;;
    r) RANGE="$OPTARG" ;;
    T) TIMEOUT="$OPTARG" ;;
    c) CONCURRENCY="$OPTARG" ;;
    v) VERBOSE=1 ;;
    h) print_help; exit 0 ;;
    :) echo "Missing argument for -$OPTARG" >&2; exit 2 ;;
    \?) echo "Invalid option: -$OPTARG" >&2; print_help; exit 2 ;;
  esac
done

if [[ -z "$TARGET" ]]; then
  echo "Target (-t) is required." >&2
  print_help
  exit 2
fi

# build list of ports to scan
ports_to_scan=()
if [[ -n "$PORTS" ]]; then
  IFS=',' read -ra LIST <<< "$PORTS"
  for p in "${LIST[@]}"; do
    ports_to_scan+=("$p")
  done
else
  if [[ "$RANGE" =~ ^([0-9]+)-([0-9]+)$ ]]; then
    start=${BASH_REMATCH[1]}
    end=${BASH_REMATCH[2]}
    if (( start < 1 )) || (( end > 65535 )) || (( start > end )); then
      echo "Invalid range: $RANGE" >&2
      exit 2
    fi
    for ((p=start;p<=end;p++)); do ports_to_scan+=("$p"); done
  else
    echo "Invalid range format: $RANGE" >&2
    exit 2
  fi
fi

# detect available methods
USE_NC=0
USE_TIMEOUT=0
if command -v nc >/dev/null 2>&1; then
  USE_NC=1
fi
if command -v timeout >/dev/null 2>&1; then
  USE_TIMEOUT=1
fi

# scanner function: attempts TCP connect
scan_port(){
  local host="$1"; local port="$2"; local t="$3"
  if (( USE_NC )); then
    # -z just checks, -w timeout (seconds)
    if nc -z -w "$t" "$host" "$port" >/dev/null 2>&1; then
      printf "%s\n" "$port"
    fi
  else
    # fallback to bash /dev/tcp with optional timeout wrapper
    if (( USE_TIMEOUT )); then
      if timeout "$t" bash -c ">/dev/tcp/$host/$port" >/dev/null 2>&1; then
        printf "%s\n" "$port"
      fi
    else
      # no timeout binary; attempt non-blocking connection by backgrounding and killing after sleep
      ( bash -c ">/dev/tcp/$host/$port" >/dev/null 2>&1 && printf "%s\n" "$port" ) &
      local bgpid=$!
      # sleep for $t seconds (may be fractional)
      sleep "$t"
      kill "$bgpid" >/dev/null 2>&1 || true
    fi
  fi
}

# concurrency control: simple job counter using jobs builtin
open_ports=()
counter=0
total=${#ports_to_scan[@]}
start_time=$(date +%s)

for idx in "${!ports_to_scan[@]}"; do
  port=${ports_to_scan[$idx]}
  ((counter++))

  # wait if too many background jobs
  while true; do
    # count running jobs
    running=$(jobs -rp | wc -l)
    if (( running < CONCURRENCY )); then break; fi
    sleep 0.01
  done

  # run scan in background, capture output into temp file
  {
    result=$(scan_port "$TARGET" "$port" "$TIMEOUT")
    if [[ -n "$result" ]]; then
      echo "open:$result"
    else
      if (( VERBOSE )); then
        echo "closed:$port"
      fi
    fi
  } &

done

wait

# collect open ports from stdout
# Because we wrote results to stdout, better run script and capture output. For neatness, suggest user run: ./bash-port-scanner.sh -t host | tee results.txt

# End of script
# Notes & tips:
# - This is a connect() style scan (safe, does full TCP handshake). It is less stealthy than SYN scans but does not require root.
# - To scan faster, increase concurrency and lower timeout; for unreliable networks, increase timeout.
# - For large scans (many thousands ports), consider using specialized tools (nmap) and always have permission.
