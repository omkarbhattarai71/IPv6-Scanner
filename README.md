# Activate the venv first
source ~/IPv6-Scanner/venv/bin/activate

# Run below script to start the probing
``` nohup bash crawler_main.sh phase > nohup.out 2>&1 & ```   # phase = date(in format DD_MM_YY  in the ipv6-crawler-batches/batches/ arrived at the tail of candidates on google cloud buckets

# IPv6 Multi-Protocol Discovery & Fingerprinting Pipeline

This project performs large-scale IPv6 active measurements using:

- ICMPv6 probing
- TCP SYN scanning
- UDP DNS probing
- HTTP/HTTPS fingerprinting
- TLS certificate extraction

The pipeline uses:

- ZMap
- ZGrab2
- Python
- Google Cloud Storage (GCS)

---

# Features

## Discovery Protocols

| Protocol | Purpose |
|---|---|
| ICMPv6 | Host responsiveness |
| TCP 80 | HTTP services |
| TCP 443 | HTTPS services |
| TCP 8080 | Alternate HTTP |
| TCP 8443 | Alternate HTTPS |
| UDP 53 | DNS services |

---

# Project Structure

```bash
IPv6-Scanner/
│
├── crawler_main.sh
├── requirements.txt
├── venv/
│
├── protocols_based_probe/
│   └── phase_<DATE>/
│       ├── resp_icmp.txt
│       ├── resp_tcp80.txt
│       ├── resp_tcp443.txt
│       ├── fingerprints_443_<DATE>.json
│       └── run.log
│
├── candidates_<DATE>.parquet
├── candidates_<DATE>.txt
│
└── processed_metrics_<DATE>.csv
```

---

# System Requirements

- Ubuntu 22.04+ recommended
- Root/sudo access
- IPv6-enabled network
- Google Cloud SDK access

---

# Install System Dependencies

## Update Packages

```bash
sudo apt update
```

---

## Install Build Tools

```bash
sudo apt install -y \
    git \
    cmake \
    build-essential \
    libgmp3-dev \
    gengetopt \
    libpcap-dev \
    flex \
    byacc \
    pkg-config \
    libjson-c-dev \
    libunistring-dev \
    libjudy-dev \
    golang-go
```

---

# Install ZMap

Official Repository:

https://github.com/zmap/zmap

```bash
git clone https://github.com/zmap/zmap.git
cd zmap

mkdir build
cd build

cmake ..
make -j$(nproc)

sudo make install
```

Verify:

```bash
zmap --version
```

---

# Install ZGrab2

Official Repository:

https://github.com/zmap/zgrab2

```bash
git clone https://github.com/zmap/zgrab2.git
cd zgrab2

make

sudo make install
```

Verify:

```bash
zgrab2 --help
```

---

# Install Google Cloud SDK

Official Guide:

https://cloud.google.com/sdk/docs/install

Quick install:

```bash
sudo apt install google-cloud-cli
```

Authenticate:

```bash
gcloud auth login
```

OR using service account:

```bash
gcloud auth activate-service-account --key-file=key.json
```

Verify:

```bash
gcloud version
gsutil version
```

---

# Python Virtual Environment Setup

## Create Virtual Environment

```bash
python3 -m venv venv
```

## Activate

```bash
source venv/bin/activate
```

---

# Install Python Dependencies

```bash
pip install -r requirements.txt
```

OR manually:

```bash
pip install \
    pandas \
    pyarrow \
    fastparquet \
    numpy \
    tqdm
```

---

# requirements.txt

```txt
pandas
pyarrow
fastparquet
numpy
tqdm
```

---

# Verify IPv6 Connectivity

```bash
ip -6 addr
```

---

# Running the Pipeline

## Usage

```bash
bash crawler.sh <phase_date>
```

Example:

```bash
bash crawler_main.sh 21_04_26
```

---

# Pipeline Workflow

## Step 0 — Download Targets

Downloads candidate IPv6 addresses from GCS bucket.

---

## Step 1 — Convert Parquet → TXT

Extracts IPv6 addresses into plaintext target list.

---

## Step 2 — ICMPv6 Discovery

Uses ZMap ICMPv6 echo scanning.

Output:

```bash
resp_icmp.txt
```

---

## Step 3 — TCP SYN Discovery

Scans:

- 80
- 443
- 8080
- 8443

Outputs:

```bash
resp_tcp80.txt
resp_tcp443.txt
resp_tcp8080.txt
resp_tcp8443.txt
```

---

## Step 4 — UDP DNS Discovery

UDP probing on port 53.

Output:

```bash
resp_udp_53.txt
```

---

## Step 5 — HTTP/HTTPS Fingerprinting

Using ZGrab2:

- HTTP response collection
- TLS handshake
- Certificate extraction
- Protocols based response analysis

Outputs:

```bash
fingerprints_<PORT>_<DATE>.json
```

---

## Step 6 — Data Merge

Combines:

- Protocol responsiveness
- Fingerprints
- TLS metadata

Final dataset:

```bash
processed_metrics_<DATE>.csv
```

---

## Step 7 — Upload Results

Uploads processed dataset to Google Cloud Storage.

---

# Output CSV Format

```csv
"ip","status","server","hsts","common_name",icmp,tcp80,tcp443,tcp8080,tcp8443,udp53
```

Example:

```csv
"2600:1901::1","success","nginx","","example.com",True,False,True,False,False,False
```

---

# Important Notes

## Root Permissions

ZMap requires raw socket access.

Always run:

```bash
sudo zmap
```

---

## IPv6 Source Address

Set correctly inside:

```bash
SOURCE_IPV6="YOUR_IPV6_ADDRESS"
```

---

## Google Cloud Bucket

Update bucket paths:

```bash
BUCKET_PATH="gs://your-bucket/path"
```

---

# Troubleshooting

## Empty Scan Results

Check:

- IPv6 connectivity
- firewall rules
- source IPv6 validity

---

## ZMap Permission Error

Use sudo:

```bash
sudo zmap ...
```

---

## Parquet Read Error

Install parquet engines:

```bash
pip install pyarrow fastparquet
```

---

# Research Usage

This framework is suitable for:

- IPv6 active measurements
- Internet-wide scanning research
- Service fingerprinting
- TLS ecosystem analysis
- Security measurements
- Academic datasets

---

# Citation

## ZMap

```bibtex
@inproceedings{durumeric2013zmap,
  title={ZMap: Fast Internet-Wide Scanning and Its Security Applications},
  author={Durumeric, Zakir and Wustrow, Eric and Halderman, J Alex},
  booktitle={USENIX Security Symposium},
  year={2013}
}
```

---

## ZGrab2

```bibtex
@misc{zgrab2,
  author       = {{ZMap Project}},
  title        = {ZGrab2: Fast Application-Layer Network Scanner},
  year         = {2026},
  howpublished = {\url{https://github.com/zmap/zgrab2}},
  note         = {Accessed: 2026-05-10}
}
```

---

# License

This project is intended for academic and research purposes only.

Use responsibly and follow ethical Internet scanning practices.
