# scantls - TLS Scanner for OpenShift/Kubernetes

A DaemonSet-based tool that discovers and tests TLS configurations of all services running in OpenShift/Kubernetes clusters by directly accessing CRI-O and container network namespaces.

## Features

- **Automatic Discovery**: Finds all TLS-serving containers by accessing CRI-O directly
- **Comprehensive Testing**: Tests TLS versions (1.2, 1.3), cipher suites, and key exchange groups
- **Post-Quantum Ready**: Supports testing PQ groups (X25519MLKEM768, SecP256r1MLKEM768, SecP384r1MLKEM1024)
- **Flexible Configuration**: Configurable via `config.env` - test specific versions/ciphers or run full audit
- **CSV Output**: Results in CSV format ready for Google Sheets import
- **Status Codes**: Clear status indicators (OK, NO_TLS, LOCALHOST_ONLY, TIMEOUT, etc.)

## Quick Start

1. **Clone and configure**:
```bash
git clone <repo-url>
cd scantls
# Edit config.env as needed (optional - has sensible defaults)
```

2. **Generate manifest**:
```bash
bash generate.sh
```

3. **Deploy to cluster**:
```bash
oc apply --server-side -f resources.yaml
```

4. **Collect results**:
```bash
# View results in logs
oc logs -n scantls-system <pod-name> | grep -A 999 "=== CSV Results ==="

# Copy all timestamped CSV files from pod
POD=$(oc get pods -n scantls-system -o name | head -1 | cut -d/ -f2)
oc exec -n scantls-system $POD -- tar czf - /tmp/scantls-results-*.csv | tar xzf - --strip-components=1

# Or extract latest from logs
oc logs -n scantls-system <pod-name> | \
  sed -n '/=== CSV Results ===/,/=== End of Results ===/p' | \
  grep -v "===" > results.csv
```

**Note**: Results are saved as timestamped files (`/tmp/scantls-results-YYYYMMDD-HHMMSS.csv`) to support continuous scanning with SCAN_INTERVAL > 0.

## Configuration

Edit `config.env` to customize the scan:

### Deployment Settings
```bash
NAMESPACE=scantls-system              # Namespace for scanner
TARGET_NAMESPACE=openshift-ingress    # Namespace to scan (or ".all")
SCAN_INTERVAL=0                       # 0=one-shot, >0=continuous (seconds)
TIMEOUT=5                             # Timeout per test in seconds
SKIP_PORTS="22,53"                    # Ports to skip (comma-separated)
IMAGE=quay.io/...                     # Container image to use
```

**Note**: The scanner runs on all nodes (tolerates all taints) since pod scanning is namespace-level, not node-specific.

### TLS Testing Configuration
```bash
TLS_VERSIONS=tls1.3                   # Comma-separated: tls1.2,tls1.3
TLS13_CIPHERS=TLS_AES_128_GCM_SHA256,TLS_AES_256_GCM_SHA384,TLS_CHACHA20_POLY1305_SHA256
TLS13_GROUPS=secp256r1,secp384r1,secp521r1,X25519,X25519MLKEM768,SecP256r1MLKEM768,SecP384r1MLKEM1024
```

### Example Configurations

**Quick Test** (1-3 min for 5 pods):
```bash
TLS_VERSIONS=tls1.3
TLS13_CIPHERS=TLS_AES_128_GCM_SHA256
TLS13_GROUPS=X25519
```

**Post-Quantum Focus**:
```bash
TLS_VERSIONS=tls1.3
TLS13_CIPHERS=TLS_AES_256_GCM_SHA384
TLS13_GROUPS=X25519MLKEM768,SecP256r1MLKEM768,SecP384r1MLKEM1024
```

**Full Audit** (30-75 min for 20 pods):
```bash
TLS_VERSIONS=tls1.2,tls1.3
# All ciphers and groups (see config.env)
```

## CSV Output Format

**Fixed columns**:
- pod_namespace, pod_name, pod_ip
- container_name, port, process
- status

**Space-separated value columns**:
- tlsversions (e.g., "tls1.2 tls1.3")
- tls12ciphers (e.g., "ECDHE-RSA-AES128-GCM-SHA256 ECDHE-RSA-AES256-GCM-SHA384")
- tls12groups (e.g., "secp256r1 secp384r1 X25519")
- tls13ciphers (e.g., "TLS_AES_128_GCM_SHA256 TLS_AES_256_GCM_SHA384")
- tls13groups (e.g., "secp256r1 X25519 X25519MLKEM768")
- reason (status explanation)

**Note**: Empty fields show "NA". Each column contains space-separated values of supported features.

## Status Codes

- **OK**: TLS scan successful
- **NO_TLS**: Port open but not using TLS
- **LOCALHOST_ONLY**: Port bound to 127.0.0.1 only
- **TIMEOUT**: Connection timed out
- **SKIPPED**: Port in SKIP_PORTS list
- **ERROR**: Scan error (see reason column)

## Performance

Scan time varies based on:
- Number of endpoints discovered
- TLS versions/ciphers/groups configured
- Network latency and endpoint responsiveness
- TIMEOUT setting (default: 5s per test)

Performance data will be added after production testing.

## Requirements

- OpenShift 4.x or Kubernetes with CRI-O
- Cluster admin privileges (for SCC)
- Worker nodes with `/var/run/crio/crio.sock`

## Architecture

- **Base Image**: UBI 10.1 with OpenSSL 3.5.1 (PQ support)
- **Discovery**: Uses `crictl` via `nsenter` to access host CRI-O
- **Testing**: Enters container network namespaces to test from pod IP
- **Output**: Logs to stdout (collect via `oc logs`)

## License

Apache 2.0

## Author

Created for OpenShift TLS auditing and Post-Quantum readiness assessment.
