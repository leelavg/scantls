# scantls - TLS Server Scanner for OpenShift/Kubernetes

## Project Objective
Create a DaemonSet-based tool that scans all TLS-serving servers in a namespace by directly accessing CRI-O and node-level resources. Similar structure to sanim project.

---

## VALIDATED DISCOVERY FLOW (Tested on Live Cluster)

### ✅ Step 1: Get Pod Information
```bash
POD_ID=$(nsenter -t 1 -m -u -n -i /usr/bin/crictl pods -o json --namespace openshift-ingress | jq -r '.items[0].id')
POD_INFO=$(nsenter -t 1 -m -u -n -i /usr/bin/crictl inspectp -o json $POD_ID)
POD_NAME=$(echo $POD_INFO | jq -r '.status.metadata.name')
POD_IP=$(echo $POD_INFO | jq -r '.status.network.ip')
NETNS=$(echo $POD_INFO | jq -r '.info.runtimeSpec.linux.namespaces[] | select(.type=="network") | .path')
```

**Output:**
- Pod ID: ce82cb8ab4a09c53f26daca2f3082e26c845f8f2bf57ac1c371ce8035afdacd9
- Pod Name: router-default-7cc47bc867-n9tvl
- Pod IP: 10.129.0.16
- Netns: /var/run/netns/3a14be09-7620-4fd1-8d6e-db65e2c5c26a

**Host Network Detection:**
- If NETNS is empty or null → host network pod
- If NETNS has path → pod has separate network namespace

### ✅ Step 2: Get Container and Ports
```bash
CONTAINER_ID=$(nsenter -t 1 -m -u -n -i /usr/bin/crictl ps -o json --pod $POD_ID | jq -r '.containers[0].id')
# Get all listening ports in container's netns
nsenter -t 1 -m -u -n -i nsenter --net=$NETNS ss -tlnp | grep LISTEN
```

**Output:**
```
LISTEN 0      4096         0.0.0.0:443       0.0.0.0:*    users:(("haproxy",pid=12159,fd=7))
LISTEN 0      4096         0.0.0.0:80        0.0.0.0:*    users:(("haproxy",pid=12159,fd=6))
LISTEN 0      4096               *:1936            *:*    users:(("openshift-route",pid=5089,fd=3))
```

### ✅ Step 3: Test TLS Connection
```bash
# Test if port responds to TLS
nsenter -t 1 -m -u -n -i nsenter --net=$NETNS openssl s_client -connect 127.0.0.1:443 </dev/null 2>&1 | grep -E 'New|Cipher|Protocol|Server Temp Key'
```

**Output:**
```
Peer signature type: RSA-PSS
Server Temp Key: X25519, 253 bits
New, TLSv1.3, Cipher is TLS_AES_128_GCM_SHA256
```

**CRITICAL FINDING:** openssl s_client only shows the NEGOTIATED cipher/group, NOT all supported ones. We MUST test each cipher/group individually.

### ✅ Step 4: Test Specific Ciphers/Groups
```bash
# Test TLS 1.3 with specific cipher
nsenter -t 1 -m -u -n -i nsenter --net=$NETNS \
    openssl s_client -connect 127.0.0.1:443 -tls1_3 \
    -ciphersuites TLS_AES_256_GCM_SHA384 </dev/null 2>&1 | grep "Cipher is"

# Test TLS 1.3 with specific group
nsenter -t 1 -m -u -n -i nsenter --net=$NETNS \
    openssl s_client -connect 127.0.0.1:443 -tls1_3 \
    -groups X25519MLKEM768 </dev/null 2>&1 | grep "Server Temp Key"
```

---

## Implementation Details (User-Provided)

### 1. Project Structure
- User does `git checkout` of repo
- User updates `config.env` (similar to sanim pattern)
- `generate.sh` sources config.env and overwrites defaults
- Single Containerfile + config.env + bash script → generates YAML manifest

### 2. Configuration (config.env) - ENHANCED

```bash
# Deployment Configuration
NAMESPACE=scantls-system
TARGET_NAMESPACE=openshift-ingress  # or ".all" for entire cluster
SCAN_INTERVAL=3600                  # Seconds between scans (0 = one-shot)
TIMEOUT=5                           # Timeout per endpoint in seconds
EXCLUDE_NAMESPACES=""               # Comma-separated (when TARGET_NAMESPACE=".all")
SKIP_PORTS="80,8080,22,53"          # Optional: skip known non-TLS ports
IMAGE=quay.io/youruser/scantls:latest
NODE_LABEL_FILTER=node-role.kubernetes.io/worker=

# TLS Testing Configuration
TLS_VERSIONS="tls1.2,tls1.3"        # Which TLS versions to test (comma-separated)

# TLS 1.2 Configuration
TLS12_CIPHERS="ECDHE-ECDSA-AES128-GCM-SHA256,ECDHE-ECDSA-AES256-GCM-SHA384,ECDHE-ECDSA-CHACHA20-POLY1305,ECDHE-RSA-AES128-GCM-SHA256,ECDHE-RSA-AES256-GCM-SHA384,ECDHE-RSA-CHACHA20-POLY1305"
TLS12_GROUPS="secp256r1,secp384r1,secp521r1,X25519"

# TLS 1.3 Configuration
TLS13_CIPHERS="TLS_AES_128_GCM_SHA256,TLS_AES_256_GCM_SHA384,TLS_CHACHA20_POLY1305_SHA256"
TLS13_GROUPS="secp256r1,secp384r1,secp521r1,X25519,X25519MLKEM768,SecP256r1MLKEM768,SecP384r1MLKEM1024"
```

**Configuration Examples:**

**Example 1: Test only TLS 1.3 with PQ groups**
```bash
TLS_VERSIONS="tls1.3"
TLS13_CIPHERS="TLS_AES_256_GCM_SHA384"
TLS13_GROUPS="X25519MLKEM768,SecP256r1MLKEM768,SecP384r1MLKEM1024"
```

**Example 2: Test only TLS 1.2 with specific ciphers**
```bash
TLS_VERSIONS="tls1.2"
TLS12_CIPHERS="ECDHE-RSA-AES128-GCM-SHA256,ECDHE-RSA-AES256-GCM-SHA384"
TLS12_GROUPS="secp256r1,X25519"
```

**Example 3: Quick test (minimal)**
```bash
TLS_VERSIONS="tls1.3"
TLS13_CIPHERS="TLS_AES_128_GCM_SHA256"
TLS13_GROUPS="X25519"
```

**Example 4: Full comprehensive test (default)**
```bash
TLS_VERSIONS="tls1.2,tls1.3"
# All ciphers and groups listed above
```

### 3. Container Image
- **Base Image**: `registry.redhat.io/ubi10/ubi:10.1`
- **Built-in utilities**: `nsenter`, `ss` (from util-linux, iproute packages)
- **Need to install**: `openssl`, `jq`
- **OpenSSL version**: 3.5.1 (supports Post-Quantum MLKEM)
- **crictl**: Use host's crictl via nsenter

### 4. Data Collection Requirements

**Output Columns for CSV (Dynamic based on config):**

**Fixed Columns (always present):**
1. node_name
2. pod_namespace
3. pod_name
4. pod_ip
5. container_name
6. container_id
7. port
8. process
9. status (OK, NO_TLS, LOCALHOST_ONLY, TIMEOUT, ERROR, etc.)
10. reason (error message if status != OK)

**Dynamic Columns (based on TLS_VERSIONS config):**

If `TLS_VERSIONS` contains "tls1.2":
- tls1.2_supported (true/false)
- For each cipher in TLS12_CIPHERS: tls1.2_cipher_<name> (true/false)
- For each group in TLS12_GROUPS: tls1.2_group_<name> (true/false)

If `TLS_VERSIONS` contains "tls1.3":
- tls1.3_supported (true/false)
- For each cipher in TLS13_CIPHERS: tls1.3_cipher_<name> (true/false)
- For each group in TLS13_GROUPS: tls1.3_group_<name> (true/false)

**Example CSV with minimal config (TLS 1.3 only, 1 cipher, 1 group):**
```csv
node_name,pod_namespace,pod_name,pod_ip,container_name,container_id,port,process,status,tls1.3_supported,tls1.3_cipher_AES128_GCM,tls1.3_group_X25519,reason
ip-10-0-1-129,openshift-ingress,router-default-xxx,10.129.0.16,router,e29f4398cdcb1,443,haproxy,OK,true,true,true,
ip-10-0-1-129,openshift-ingress,router-default-xxx,10.129.0.16,router,e29f4398cdcb1,80,haproxy,NO_TLS,false,false,false,Plain HTTP service
```

**Status Codes:**
- **OK**: TLS scan successful - cipher and version information available
- **NO_TLS**: Port is open but not using TLS (plain HTTP/TCP service)
- **LOCALHOST_ONLY**: Port bound to 127.0.0.1, not accessible from pod IP
- **FILTERED**: Port blocked by network policy or firewall
- **CLOSED**: Port not listening on the scanned IP address
- **MTLS_REQUIRED**: TLS handshake failed - likely requires client certificate
- **TIMEOUT**: Connection timed out
- **NO_PORTS**: Pod declares no TCP ports in its spec
- **ERROR**: Scan error occurred (see reason for details)

### 5. Performance Considerations

**Configurable Performance:**
- **Minimal config**: 1 version + 1 cipher + 1 group = 3 tests per endpoint (~6-15s)
- **Medium config**: 1 version + 3 ciphers + 4 groups = 8 tests per endpoint (~16-40s)
- **Full config**: 2 versions + 6+3 ciphers + 4+7 groups = 22 tests per endpoint (~44-110s)

**Optimization Strategy:**
1. Test TLS version first (1.2 and 1.3)
2. If version not supported, skip cipher/group tests for that version
3. Use shorter timeout for initial TLS handshake (2s)
4. Use full timeout for cipher/group tests (5s)
5. Run tests sequentially (safer with timeouts)

**Expected Scan Time (with full config):**
- Small namespace (5 pods, 10 endpoints): ~7-18 minutes
- Medium namespace (20 pods, 40 endpoints): ~30-75 minutes
- Large namespace (100 pods, 200 endpoints): ~2.5-6 hours

**Expected Scan Time (with minimal config):**
- Small namespace (5 pods, 10 endpoints): ~1-3 minutes
- Medium namespace (20 pods, 40 endpoints): ~5-12 minutes
- Large namespace (100 pods, 200 endpoints): ~25-60 minutes

### 6. Testing Strategy

**Test on Pod IP vs 127.0.0.1:**
- Always test on **pod IP** (not 127.0.0.1)
- This reveals if service is accessible from network
- Status LOCALHOST_ONLY if only 127.0.0.1 works
- For host network pods: use node IP

---

## Containerfile

```dockerfile
FROM registry.redhat.io/ubi10/ubi:10.1

# Install required tools
RUN dnf install -y \
    openssl \
    jq \
    && dnf clean all

# Script will be mounted from ConfigMap at runtime (sanim pattern)
ENTRYPOINT ["/bin/bash", "/scripts/scan-tls.sh"]
```

---

## Required Mounts & Permissions

### Volume Mounts
```yaml
volumeMounts:
  - name: crio-sock
    mountPath: /var/run/crio/crio.sock
    readOnly: true
  - name: netns
    mountPath: /var/run/netns
    mountPropagation: HostToContainer
  - name: proc
    mountPath: /host/proc
    readOnly: true
  - name: scripts
    mountPath: /scripts
    readOnly: true

volumes:
  - name: crio-sock
    hostPath:
      path: /var/run/crio/crio.sock
      type: Socket
  - name: netns
    hostPath:
      path: /var/run/netns
      type: DirectoryOrCreate
  - name: proc
    hostPath:
      path: /proc
      type: Directory
  - name: scripts
    configMap:
      name: scantls-scripts
      defaultMode: 0755
```

### SecurityContext
```yaml
securityContext:
  privileged: true
  hostPID: true
  hostNetwork: false
```

### SCC
```yaml
apiVersion: security.openshift.io/v1
kind: SecurityContextConstraints
metadata:
  name: scantls-scc
allowHostDirVolumePlugin: true
allowHostPID: true
allowPrivilegedContainer: true
allowedCapabilities:
  - SYS_ADMIN
  - NET_ADMIN
runAsUser:
  type: RunAsAny
seLinuxContext:
  type: RunAsAny
fsGroup:
  type: RunAsAny
```

---

## Implementation Plan - Detailed Chunks

### Chunk 1: Project Skeleton (15 min)
**Files:**
- config.env (with TLS configuration options)
- generate.sh (skeleton)
- Containerfile
- README.md
- LICENSE
- .gitignore

**Key Functions in generate.sh:**
```bash
# Parse TLS configuration
parse_tls_config() {
    IFS=',' read -ra TLS_VERSIONS_ARRAY <<< "$TLS_VERSIONS"
    IFS=',' read -ra TLS12_CIPHERS_ARRAY <<< "$TLS12_CIPHERS"
    IFS=',' read -ra TLS12_GROUPS_ARRAY <<< "$TLS12_GROUPS"
    IFS=',' read -ra TLS13_CIPHERS_ARRAY <<< "$TLS13_CIPHERS"
    IFS=',' read -ra TLS13_GROUPS_ARRAY <<< "$TLS13_GROUPS"
}

# Generate CSV header based on config
generate_csv_header() {
    local header="node_name,pod_namespace,pod_name,pod_ip,container_name,container_id,port,process,status"
    
    for version in "${TLS_VERSIONS_ARRAY[@]}"; do
        header+=",${version}_supported"
        
        if [[ "$version" == "tls1.2" ]]; then
            for cipher in "${TLS12_CIPHERS_ARRAY[@]}"; do
                header+=",tls1.2_cipher_$(echo $cipher | tr '-' '_' | tr '[:upper:]' '[:lower:]')"
            done
            for group in "${TLS12_GROUPS_ARRAY[@]}"; do
                header+=",tls1.2_group_$(echo $group | tr '[:upper:]' '[:lower:]')"
            done
        elif [[ "$version" == "tls1.3" ]]; then
            for cipher in "${TLS13_CIPHERS_ARRAY[@]}"; do
                header+=",tls1.3_cipher_$(echo $cipher | sed 's/TLS_//g' | tr '_' '.' | tr '[:upper:]' '[:lower:]')"
            done
            for group in "${TLS13_GROUPS_ARRAY[@]}"; do
                header+=",tls1.3_group_$(echo $group | tr '[:upper:]' '[:lower:]')"
            done
        fi
    done
    
    header+=",reason"
    echo "$header"
}
```

**Verification:**
- `bash generate.sh` runs without errors
- Creates resources.yaml skeleton
- CSV header generation works with different TLS configs

---

### Chunk 2: Core Discovery Functions (20 min)
**Functions to implement:**
```bash
get_target_namespaces()      # Returns list of namespaces to scan
get_pods_in_namespace()      # Returns pod IDs for namespace
get_pod_info()               # Returns pod name, IP, netns
get_containers_for_pod()     # Returns container IDs
get_listening_ports()        # Returns all TCP ports in netns
```

**Test in tmux pane 3.1:**
- Verify each function works
- Check JSON parsing
- Handle edge cases (no pods, host network, etc.)

---

### Chunk 3: TLS Testing Functions (25 min)
**Functions to implement:**
```bash
test_tls_handshake()         # Quick TLS test, returns status code
test_tls_version()           # Test if TLS 1.2 or 1.3 supported
test_tls12_cipher()          # Test specific TLS 1.2 cipher
test_tls13_cipher()          # Test specific TLS 1.3 cipher
test_group()                 # Test specific group (1.2 or 1.3)
scan_endpoint()              # Full scan of one endpoint based on config
```

**Enhanced scan_endpoint function:**
```bash
scan_endpoint() {
    local pod_info="$1"
    local container_id="$2"
    local port="$3"
    
    # Extract pod details
    local pod_name=$(echo "$pod_info" | jq -r '.name')
    local pod_ip=$(echo "$pod_info" | jq -r '.ip')
    local netns=$(echo "$pod_info" | jq -r '.netns')
    
    # Initialize result array
    local result=()
    result+=("$pod_name" "$pod_ip" "$port")
    
    # Test each configured TLS version
    for version in "${TLS_VERSIONS_ARRAY[@]}"; do
        if test_tls_version "$netns" "$pod_ip" "$port" "$version"; then
            result+=("true")
            
            # Test ciphers for this version
            if [[ "$version" == "tls1.2" ]]; then
                for cipher in "${TLS12_CIPHERS_ARRAY[@]}"; do
                    if test_tls12_cipher "$netns" "$pod_ip" "$port" "$cipher"; then
                        result+=("true")
                    else
                        result+=("false")
                    fi
                done
                
                # Test groups for TLS 1.2
                for group in "${TLS12_GROUPS_ARRAY[@]}"; do
                    if test_group "$netns" "$pod_ip" "$port" "tls1.2" "$group"; then
                        result+=("true")
                    else
                        result+=("false")
                    fi
                done
            elif [[ "$version" == "tls1.3" ]]; then
                # Similar for TLS 1.3...
            fi
        else
            result+=("false")
            # Add false for all ciphers/groups of this version
        fi
    done
    
    # Output CSV row
    IFS=',' ; echo "${result[*]}"
}
```

**Test in tmux pane 3.1:**
- Test each cipher/group individually
- Verify timeout handling
- Check status code logic
- Test with different TLS_VERSIONS configs

---

### Chunk 4: CSV Output Generation (15 min)
**Functions to implement:**
```bash
init_csv_header()            # Print CSV header based on config
format_csv_row()             # Format scan result as CSV row
```

**Dynamic CSV generation based on config:**
- Header changes based on TLS_VERSIONS, TLS12_CIPHERS, etc.
- Column count varies from ~13 (minimal) to ~32 (full)
- Proper escaping of CSV values

---

### Chunk 5: Main Scan Loop (15 min)
**Main script structure:**
```bash
#!/bin/bash
set -euo pipefail

# Load config from env vars with defaults
NAMESPACE="${NAMESPACE:-scantls-system}"
TARGET_NAMESPACE="${TARGET_NAMESPACE:-openshift-ingress}"
TLS_VERSIONS="${TLS_VERSIONS:-tls1.2,tls1.3}"
TLS12_CIPHERS="${TLS12_CIPHERS:-ECDHE-RSA-AES128-GCM-SHA256,ECDHE-RSA-AES256-GCM-SHA384}"
# ... more config

# Parse TLS configuration
parse_tls_config

# Initialize CSV output
init_csv_header

# Main scan loop
for ns in $(get_target_namespaces); do
    for pod_id in $(get_pods_in_namespace "$ns"); do
        pod_info=$(get_pod_info "$pod_id")
        for container_id in $(get_containers_for_pod "$pod_id"); do
            for port in $(get_listening_ports "$container_id"); do
                result=$(scan_endpoint "$pod_info" "$container_id" "$port")
                echo "$result"
            done
        done
    done
done
```

---

### Chunk 6: DaemonSet YAML Generation (15 min)
**generate.sh complete:**
- Namespace
- ConfigMap with scan script (includes TLS config parsing)
- ServiceAccount
- SCC
- DaemonSet with env vars for TLS configuration

**ConfigMap generation:**
```bash
# In generate.sh
cat >> resources.yaml <<EOF
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: scantls-scripts
  namespace: ${NAMESPACE}
data:
  scan-tls.sh: |
$(cat <<'SCRIPT_EOF'
#!/bin/bash
set -euo pipefail

# TLS Configuration from environment
TLS_VERSIONS="${TLS_VERSIONS:-tls1.2,tls1.3}"
TLS12_CIPHERS="${TLS12_CIPHERS:-ECDHE-RSA-AES128-GCM-SHA256}"
# ... rest of script
SCRIPT_EOF
)
EOF
```

---

### Chunk 7: Testing & Validation (20 min)
1. Build container image
2. Deploy to cluster with different TLS configs
3. Test minimal config first (fast)
4. Test full config on small namespace
5. Collect logs: `oc logs -n scantls-system <pod> > results.csv`
6. Import to Google Sheets
7. Verify results

**Test Scenarios:**
1. **Quick test**: `TLS_VERSIONS="tls1.3"`, `TLS13_CIPHERS="TLS_AES_128_GCM_SHA256"`, `TLS13_GROUPS="X25519"`
2. **PQ test**: `TLS_VERSIONS="tls1.3"`, `TLS13_GROUPS="X25519MLKEM768,SecP256r1MLKEM768"`
3. **Full test**: All default values

---

## Next Steps

Ready to start implementation with Chunk 1 (enhanced with configurable TLS parameters)?