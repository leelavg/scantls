# scantls - TLS Scanner for OpenShift/Kubernetes

A production-ready DaemonSet that discovers and audits TLS configurations across OpenShift/Kubernetes clusters, with special focus on Post-Quantum (PQ) cryptography readiness.

## Status: ✅ Production Validated
- Tested on OpenShift 4.21 and 4.22
- Scans 1,000+ endpoints in under 2 minutes
- Successfully detects Post-Quantum groups in Go 1.23+ services
- CSV output ready for compliance reporting

## Features

- **Automatic Discovery**: Finds all TLS endpoints via CRI-O and container network namespaces
- **Comprehensive Testing**: TLS 1.2/1.3 versions, cipher suites, and key exchange groups
- **Post-Quantum Ready**: Detects MLKEM hybrid groups (X25519MLKEM768, SecP256r1MLKEM768, SecP384r1MLKEM1024)
- **Flexible Configuration**: Test specific versions/ciphers or run full audit via config.env
- **Fast & Parallel**: DaemonSet runs on all nodes simultaneously
- **CSV Output**: Space-separated values for easy spreadsheet analysis

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
# Combine results from all pods into single CSV
FIRST=true
for pod in $(oc get pods -n scantls-system -o name); do
  POD_NAME=$(echo $pod | cut -d/ -f2)
  if [ "$FIRST" = true ]; then
    # First pod: include header
    oc logs -n scantls-system $POD_NAME 2>/dev/null | sed -n '/^pod_namespace,/,/^[a-z]/p' | grep -E '^(pod_namespace|[a-z])' > scantls-results.csv
    FIRST=false
  else
    # Other pods: skip header, append data only
    oc logs -n scantls-system $POD_NAME 2>/dev/null | sed -n '/^[a-z]/p' | grep -v '^pod_namespace' >> scantls-results.csv
  fi
done
echo "Results saved to scantls-results.csv ($(wc -l < scantls-results.csv) rows)"

# Or view results from single pod
oc logs -n scantls-system <pod-name> | grep -A 999 "=== CSV Results ==="

# Or copy timestamped files from pod
POD=$(oc get pods -n scantls-system -o name | head -1 | cut -d/ -f2)
oc exec -n scantls-system $POD -- tar czf - /tmp/scantls-results-*.csv | tar xzf - --strip-components=1
```

**Note**: Results are saved as timestamped files (`/tmp/scantls-results-YYYYMMDD-HHMMSS.csv`) to support continuous scanning with SCAN_INTERVAL > 0.

## Configuration

Edit `config.env` to customize the scan:

### Deployment Settings
```bash
NAMESPACE=scantls-system              # Namespace for scanner
TARGET_NAMESPACE=.all                 # ".all" or "ns1,ns2,ns3" (comma/space-separated)
SCAN_INTERVAL=0                       # 0=one-shot, >0=continuous (seconds)
TIMEOUT=5                             # Timeout per test in seconds
SKIP_PORTS="22,53"                    # Ports to skip (comma-separated)
IMAGE=quay.io/...                     # Container image to use
```

**Multi-Namespace Support**: Use comma or space-separated list (e.g., `openshift-ingress,openshift-storage` or `openshift-ingress openshift-storage`)

**Note**: The scanner runs on all nodes (tolerates all taints). Host network pods are supported and filtered by container PID to avoid noise.

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

## Performance (Production Validated)

**OpenShift 4.22 Full Cluster Scan:**
- 1,033 endpoints across 6 nodes
- Scan time: 31-84 seconds per node
- Configuration: 6 TLS 1.2 ciphers + 4 groups, 3 TLS 1.3 ciphers + 7 groups (including 3 PQ)
- Parallel execution via DaemonSet

**PQ Detection Results:**
Successfully detected X25519MLKEM768 in production services:
- cnpg-controller-manager (PostgreSQL operator)
- noobaa-operator (Object storage)
- ocs-metrics-exporter (Storage metrics)

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
