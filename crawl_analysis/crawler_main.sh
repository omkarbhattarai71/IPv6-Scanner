#!/bin/bash

# ==========================================
# CONFIGURATION
# ==========================================
SOURCE_IPV6="2600:1901:8120:689:0:1::"
RATE=5000

# Require the phase to be passed as an argument
if [ -z "$1" ]; then
  echo "ERROR: You must provide a phase argument!"
  echo "Usage: bash crawler.sh <phase_date> (e.g., bash crawler.sh 21_04_26)"
  exit 1
fi

PHASE="$1"
PHASE_DIR="protocols_based_probe/phase_${PHASE}"
PARQUET_FILE="candidates_${PHASE}.parquet"
TARGET_FILE="candidates_${PHASE}.txt"

# GCS paths
BUCKET_PATH="gs://ipv6-crawler-batches/batches/${PARQUET_FILE}"

mkdir -p "$PHASE_DIR"

# Logging
exec > >(tee -a "${PHASE_DIR}/run.log") 2>&1

echo "=========================================="
echo " PIPELINE STARTED"
echo " Phase: $PHASE"
echo "=========================================="

# ==========================================
# 0. DOWNLOAD FROM BUCKET
# ==========================================
echo "[0/5] Downloading parquet from bucket..."

if [ ! -f "$PARQUET_FILE" ]; then
  gsutil cp "$BUCKET_PATH" .
else
  echo "Parquet already exists, skipping download"
fi

# ==========================================
# 1. UNPACK PARQUET → TXT
# ==========================================
echo "[1/5] Converting parquet → txt..."

if [ ! -f "$TARGET_FILE" ]; then
  python3 - <<EOF
import pandas as pd
df = pd.read_parquet("$PARQUET_FILE", columns=["address"])
df["address"].to_csv("$TARGET_FILE", index=False, header=False)
EOF
else
  echo "Target TXT already exists, skipping conversion"
fi

# ==========================================
# PRE-CHECK
# ==========================================
if [ ! -s "$TARGET_FILE" ]; then
  echo "ERROR: Target file empty or missing!"
  exit 1
fi

echo "Targets loaded: $(wc -l < $TARGET_FILE)"

echo "=========================================="
echo " Starting Multi-Protocol IPv6 Discovery"
echo "=========================================="

# ==========================================
# 2. ICMPv6 Scan
# ==========================================
echo "[2/5] ICMPv6 Scan..."

sudo zmap --ipv6-target-file="$TARGET_FILE" \
  --ipv6-source-ip="$SOURCE_IPV6" \
  --probe-module=icmp6_echoscan \
  --rate="$RATE" \
  --output-file="${PHASE_DIR}/resp_icmp.txt"

# ==========================================
# 3. TCP Scans
# ==========================================
echo "[3/5] TCP Scans..."

for PORT in 80 443 8080 8443; do
  echo "  -> TCP port $PORT"

  sudo zmap --ipv6-target-file="$TARGET_FILE" \
    --ipv6-source-ip="$SOURCE_IPV6" \
    --probe-module=ipv6_tcp_synscan \
    --target-port=$PORT \
    --rate="$RATE" \
    --output-file="${PHASE_DIR}/resp_tcp${PORT}.txt"
done

# ==========================================
# 4. UDP Scan (DNS)
# ==========================================
echo "[4/5] UDP Scan (DNS)..."

sudo zmap --ipv6-target-file="$TARGET_FILE" \
  --ipv6-source-ip="$SOURCE_IPV6" \
  --probe-module=ipv6_udp \
  --target-port=53 \
  --probe-args="hex:000010000001000000000000" \
  --rate="$RATE" \
  --output-file="${PHASE_DIR}/resp_udp_53.txt"

# ==========================================
# 5. Fingerprinting
# ==========================================
echo "=========================================="
echo " Fingerprinting HTTP/HTTPS services"
echo "=========================================="

for PORT in 80 443 8080 8443; do

  INPUT="${PHASE_DIR}/resp_tcp${PORT}.txt"
  OUTPUT="${PHASE_DIR}/fingerprints_${PORT}_${PHASE}.json"

  if [ ! -s "$INPUT" ]; then
    echo "Skipping empty $INPUT"
    continue
  fi

  echo "[FINGERPRINT] Port $PORT"

  if [ "$PORT" -eq 443 ] || [ "$PORT" -eq 8443 ]; then
    zgrab2 http --use-https \
      --port=$PORT \
      --input-file="$INPUT" \
      --output-file="$OUTPUT" \
      --connections-per-host=3 \
      --senders=200
  else
    zgrab2 http \
      --port=$PORT \
      --input-file="$INPUT" \
      --output-file="$OUTPUT" \
      --connections-per-host=3 \
      --senders=200
  fi

done

# ==========================================
# 6. DATA MERGE (PROTOCOLS & FINGERPRINTS)
# ==========================================
echo "[6/7] Merging protocol data and fingerprints..."

METRICS_CSV="processed_metrics_${PHASE}.csv"

python3 - <<EOF
import json
import os

phase_dir = "${PHASE_DIR}"
phase = "${PHASE}"

def load_ips(filename):
    path = os.path.join(phase_dir, filename)
    if os.path.exists(path):
        with open(path, 'r') as f:
            return set(line.strip() for line in f if line.strip())
    return set()

# Load all protocol responses
icmp = load_ips("resp_icmp.txt")
tcp80 = load_ips("resp_tcp80.txt")
tcp443 = load_ips("resp_tcp443.txt")
tcp8080 = load_ips("resp_tcp8080.txt")
tcp8443 = load_ips("resp_tcp8443.txt")
udp53 = load_ips("resp_udp_53.txt")

# Combine to get every unique active IP
all_ips = icmp | tcp80 | tcp443 | tcp8080 | tcp8443 | udp53

fingerprints = {}

def extract_fp(port):
    json_path = os.path.join(phase_dir, f"fingerprints_{port}_{phase}.json")
    if not os.path.exists(json_path): return
    with open(json_path, 'r') as f:
        for line in f:
            try:
                data = json.loads(line.strip())
                ip = data.get("ip")
                if not ip: continue
                
                # JQ Replica: .status // .error // "success"
                http_res = data.get("data", {}).get("http", {})
                status_val = http_res.get("status")
                error_val = http_res.get("error")
                status = status_val if status_val else (error_val if error_val else "success")
                
                if ip in fingerprints and fingerprints[ip].get("status") == "success" and status != "success":
                    continue
                
                headers = http_res.get("result", {}).get("response", {}).get("headers", {})
                server = headers.get("Server", [""])[0] if "Server" in headers and headers["Server"] else ""
                hsts = headers.get("Strict-Transport-Security", [""])[0] if "Strict-Transport-Security" in headers and headers["Strict-Transport-Security"] else ""
                
                cert = http_res.get("result", {}).get("request", {}).get("tls_log", {}).get("handshake_log", {}).get("server_certificates", {}).get("certificate", {}).get("parsed", {}).get("subject", {})
                cn_raw = cert.get("common_name", [""])
                common_name = cn_raw[0] if isinstance(cn_raw, list) and len(cn_raw) > 0 else (cn_raw if isinstance(cn_raw, str) else "")
                
                fingerprints[ip] = {
                    "status": str(status).replace('"', '""'),
                    "server": str(server).replace('"', '""'),
                    "hsts": str(hsts).replace('"', '""'),
                    "common_name": str(common_name).replace('"', '""')
                }
            except Exception:
                continue

# Extract HTTPS first for best certificate data
for p in [443, 8443, 80, 8080]:
    extract_fp(p)

# Build the final dataset combining fingerprints AND protocols perfectly formatted
with open("${METRICS_CSV}", "w") as out:
    for ip in all_ips:
        fp = fingerprints.get(ip, {"status": "unknown-error", "server": "", "hsts": "", "common_name": ""})
        
        # Hardcode the double-quotes for the first 5 columns to match your exact format
        line = f'"{ip}","{fp["status"]}","{fp["server"]}","{fp["hsts"]}","{fp["common_name"]}",{ip in icmp},{ip in tcp80},{ip in tcp443},{ip in tcp8080},{ip in tcp8443},{ip in udp53}\n'
        out.write(line)

EOF

# ==========================================
# 7. UPLOAD TO BUCKET
# ==========================================
echo "[7/7] Uploading processed metrics to GCP bucket..."

if [ -s "$METRICS_CSV" ]; then
  gcloud storage cp "$METRICS_CSV" gs://ipv6-crawler-batches/processed_at_vm/
  echo "Upload successful."
else
  echo "ERROR: $METRICS_CSV is empty or missing. Skipping upload."
fi

echo "=========================================="
echo " ALL TASKS COMPLETED"
echo " Output directory: $PHASE_DIR"
echo "=========================================="
