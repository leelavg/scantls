#!/usr/bin/env bash
set -euo pipefail

# Default configuration
NAMESPACE="${NAMESPACE:-scantls-system}"
TARGET_NAMESPACE="${TARGET_NAMESPACE:-openshift-ingress}"
SCAN_INTERVAL="${SCAN_INTERVAL:-0}"
TIMEOUT="${TIMEOUT:-5}"
EXCLUDE_NAMESPACES="${EXCLUDE_NAMESPACES:-}"
SKIP_PORTS="${SKIP_PORTS:-22,53}"
IMAGE="${IMAGE:-quay.io/leelavg/scantls:latest}"
NODE_LABEL_FILTER="${NODE_LABEL_FILTER:-node-role.kubernetes.io/worker=}"

# TLS Configuration
TLS_VERSIONS="${TLS_VERSIONS:-tls1.3}"
TLS12_CIPHERS="${TLS12_CIPHERS:-ECDHE-RSA-AES128-GCM-SHA256,ECDHE-RSA-AES256-GCM-SHA384}"
TLS12_GROUPS="${TLS12_GROUPS:-secp256r1,X25519}"
TLS13_CIPHERS="${TLS13_CIPHERS:-TLS_AES_128_GCM_SHA256,TLS_AES_256_GCM_SHA384}"
TLS13_GROUPS="${TLS13_GROUPS:-secp256r1,X25519,X25519MLKEM768}"

# Source user config if exists
if [[ -f config.env ]]; then
  source config.env
fi

# Generate resources.yaml
cat >resources.yaml <<'OUTER_EOF'
#, Namespace for scantls resources
---
apiVersion: v1
kind: Namespace
metadata:
  name: @NAMESPACE@
#, ConfigMap containing TLS scanning script
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: scantls-scripts
  namespace: @NAMESPACE@
data:
  scan-tls.sh: |
    #!/bin/bash
    set -euo pipefail
    
    # Configuration from environment
    TARGET_NAMESPACE="${TARGET_NAMESPACE:-openshift-ingress}"
    SCAN_INTERVAL="${SCAN_INTERVAL:-0}"
    TIMEOUT="${TIMEOUT:-5}"
    EXCLUDE_NAMESPACES="${EXCLUDE_NAMESPACES:-}"
    SKIP_PORTS="${SKIP_PORTS:-22,53}"
    TLS_VERSIONS="${TLS_VERSIONS:-tls1.3}"
    TLS12_CIPHERS="${TLS12_CIPHERS:-}"
    TLS12_GROUPS="${TLS12_GROUPS:-}"
    TLS13_CIPHERS="${TLS13_CIPHERS:-}"
    TLS13_GROUPS="${TLS13_GROUPS:-}"
    
    NODE_NAME=$(hostname)
    
    # Parse arrays
    IFS=',' read -ra TLS_VERSIONS_ARRAY <<< "$TLS_VERSIONS"
    IFS=',' read -ra TLS12_CIPHERS_ARRAY <<< "$TLS12_CIPHERS"
    IFS=',' read -ra TLS12_GROUPS_ARRAY <<< "$TLS12_GROUPS"
    IFS=',' read -ra TLS13_CIPHERS_ARRAY <<< "$TLS13_CIPHERS"
    IFS=',' read -ra TLS13_GROUPS_ARRAY <<< "$TLS13_GROUPS"
    IFS=',' read -ra SKIP_PORTS_ARRAY <<< "$SKIP_PORTS"
    
    # Generate CSV header
    generate_csv_header() {
        echo "pod_namespace,pod_name,pod_ip,container_name,port,process,status,tlsversions,tls12ciphers,tls12groups,tls13ciphers,tls13groups,reason"
    }
    
    # Get target namespaces
    get_target_namespaces() {
        if [[ "$TARGET_NAMESPACE" == ".all" ]]; then
            local all_ns=$(nsenter -t 1 -m -u -n -i /usr/bin/crictl pods -o json 2>/dev/null | jq -r '.items[].metadata.namespace' | sort -u)
            if [[ -n "$EXCLUDE_NAMESPACES" ]]; then
                IFS=',' read -ra EXCLUDE_ARRAY <<< "$EXCLUDE_NAMESPACES"
                for ns in $all_ns; do
                    local skip=false
                    for exclude in "${EXCLUDE_ARRAY[@]}"; do
                        [[ "$ns" == "$exclude" ]] && skip=true && break
                    done
                    [[ "$skip" == false ]] && echo "$ns"
                done
            else
                echo "$all_ns"
            fi
        else
            # Support both space and comma-separated namespaces
            echo "$TARGET_NAMESPACE" | tr ' ,' '\n' | grep -v '^$'
        fi
    }
    
    # Get pods in namespace
    get_pods_in_namespace() {
        local ns="$1"
        nsenter -t 1 -m -u -n -i /usr/bin/crictl pods --namespace "$ns" -o json 2>/dev/null | jq -r '.items[].id'
    }
    
    # Get pod info
    get_pod_info() {
        local pod_id="$1"
        nsenter -t 1 -m -u -n -i /usr/bin/crictl inspectp -o json "$pod_id" 2>/dev/null
    }
    
    # Get containers for pod
    get_containers_for_pod() {
        local pod_id="$1"
        nsenter -t 1 -m -u -n -i /usr/bin/crictl ps --pod "$pod_id" -o json 2>/dev/null | jq -r '.containers[].id'
    }
    
    # Get network namespace for container
    get_container_netns() {
        local container_id="$1"
        nsenter -t 1 -m -u -n -i /usr/bin/crictl inspect -o json "$container_id" 2>/dev/null | \
            jq -r '.info.runtimeSpec.linux.namespaces[] | select(.type=="network") | .path'
    }
    
    # Get listening ports (optionally filtered by container PID for host network pods)
    get_listening_ports() {
        local netns="$1"
        local container_pid="$2"
        [[ -z "$netns" ]] && return
        
        local ss_output=$(nsenter -t 1 -m -u -n -i nsenter --net="$netns" ss -tlnp 2>/dev/null | grep LISTEN)
        
        # If container_pid provided (host network pod), filter by that PID
        if [[ -n "$container_pid" ]]; then
            echo "$ss_output" | grep "pid=$container_pid," | \
                awk '{
                    split($4, addr, ":");
                    port = addr[length(addr)];
                    if (match($0, /users:\(\("([^"]+)"/, proc)) {
                        process = proc[1];
                    } else {
                        process = "unknown";
                    }
                    print port ":" process;
                }' | sort -u
        else
            echo "$ss_output" | \
                awk '{
                    split($4, addr, ":");
                    port = addr[length(addr)];
                    if (match($0, /users:\(\("([^"]+)"/, proc)) {
                        process = proc[1];
                    } else {
                        process = "unknown";
                    }
                    print port ":" process;
                }' | sort -u
        fi
    }
    
    # Test TLS handshake
    test_tls_handshake() {
        local netns="$1"
        local ip="$2"
        local port="$3"
        
        timeout 2 nsenter -t 1 -m -u -n -i nsenter --net="$netns" \
            openssl s_client -connect "$ip:$port" </dev/null 2>&1 | grep -q "^CONNECTED"
    }
    
    # Test TLS version
    test_tls_version() {
        local netns="$1"
        local ip="$2"
        local port="$3"
        local version="$4"
        
        echo "      Testing $version" >&2
        
        local flag=""
        [[ "$version" == "tls1.2" ]] && flag="-tls1_2"
        [[ "$version" == "tls1.3" ]] && flag="-tls1_3"
        
        timeout "$TIMEOUT" nsenter -t 1 -m -u -n -i nsenter --net="$netns" \
            openssl s_client -connect "$ip:$port" $flag </dev/null 2>&1 | grep -q "^New, TLSv"
    }
    
    # Test TLS 1.2 cipher
    test_tls12_cipher() {
        local netns="$1"
        local ip="$2"
        local port="$3"
        local cipher="$4"
        
        echo "        Testing cipher: $cipher" >&2
        
        timeout "$TIMEOUT" nsenter -t 1 -m -u -n -i nsenter --net="$netns" \
            openssl s_client -connect "$ip:$port" -tls1_2 -cipher "$cipher" </dev/null 2>&1 | grep -q "Cipher is"
    }
    
    # Test TLS 1.3 cipher
    test_tls13_cipher() {
        local netns="$1"
        local ip="$2"
        local port="$3"
        local cipher="$4"
        
        echo "        Testing cipher: $cipher" >&2
        
        timeout "$TIMEOUT" nsenter -t 1 -m -u -n -i nsenter --net="$netns" \
            openssl s_client -connect "$ip:$port" -tls1_3 -ciphersuites "$cipher" </dev/null 2>&1 | grep -q "Cipher is"
    }
    
    # Test group
    test_group() {
        local netns="$1"
        local ip="$2"
        local port="$3"
        local version="$4"
        local group="$5"
        
        echo "        Testing group: $group" >&2
        
        local flag=""
        [[ "$version" == "tls1.2" ]] && flag="-tls1_2"
        [[ "$version" == "tls1.3" ]] && flag="-tls1_3"
        
        timeout "$TIMEOUT" nsenter -t 1 -m -u -n -i nsenter --net="$netns" \
            openssl s_client -connect "$ip:$port" $flag -groups "$group" </dev/null 2>&1 | grep -qE "(Server|Peer) Temp Key|Negotiated.*: [^<]"
    }
    
    # Scan endpoint
    scan_endpoint() {
        local pod_namespace="$1"
        local pod_name="$2"
        local pod_ip="$3"
        local container_name="$4"
        local container_id="$5"
        local netns="$6"
        local port="$7"
        local process="$8"
        
        local status=""
        local tlsversions=""
        local tls12ciphers=""
        local tls12groups=""
        local tls13ciphers=""
        local tls13groups=""
        local reason=""
        
        # Check if port should be skipped
        for skip_port in "${SKIP_PORTS_ARRAY[@]}"; do
            [[ "$port" == "$skip_port" ]] && {
                echo "      Skipped: Port $port in SKIP_PORTS list" >&2
                status="SKIPPED"
                reason="Port in SKIP_PORTS list"
                echo "$pod_namespace,$pod_name,$pod_ip,$container_name,$port,$process,$status,NA,NA,NA,NA,NA,$reason"
                return
            }
        done
        
        # Test TLS handshake
        if ! test_tls_handshake "$netns" "$pod_ip" "$port"; then
            echo "      No TLS detected on port $port" >&2
            status="NO_TLS"
            reason="No TLS handshake"
            echo "$pod_namespace,$pod_name,$pod_ip,$container_name,$port,$process,$status,NA,NA,NA,NA,NA,$reason"
            return
        fi
        
        status="OK"
        local supported_versions=()
        
        # Test each configured TLS version
        for version in "${TLS_VERSIONS_ARRAY[@]}"; do
            [[ -z "$version" ]] && continue
            
            if test_tls_version "$netns" "$pod_ip" "$port" "$version"; then
                supported_versions+=("$version")
                
                if [[ "$version" == "tls1.2" ]]; then
                    local supported_ciphers=()
                    for cipher in "${TLS12_CIPHERS_ARRAY[@]}"; do
                        [[ -z "$cipher" ]] && continue
                        if test_tls12_cipher "$netns" "$pod_ip" "$port" "$cipher"; then
                            supported_ciphers+=("$cipher")
                        fi
                    done
                    tls12ciphers="${supported_ciphers[*]}"
                    
                    local supported_groups=()
                    for group in "${TLS12_GROUPS_ARRAY[@]}"; do
                        [[ -z "$group" ]] && continue
                        if test_group "$netns" "$pod_ip" "$port" "tls1.2" "$group"; then
                            supported_groups+=("$group")
                        fi
                    done
                    tls12groups="${supported_groups[*]}"
                    
                elif [[ "$version" == "tls1.3" ]]; then
                    local supported_ciphers=()
                    for cipher in "${TLS13_CIPHERS_ARRAY[@]}"; do
                        [[ -z "$cipher" ]] && continue
                        if test_tls13_cipher "$netns" "$pod_ip" "$port" "$cipher"; then
                            supported_ciphers+=("$cipher")
                        fi
                    done
                    tls13ciphers="${supported_ciphers[*]}"
                    
                    local supported_groups=()
                    for group in "${TLS13_GROUPS_ARRAY[@]}"; do
                        [[ -z "$group" ]] && continue
                        if test_group "$netns" "$pod_ip" "$port" "tls1.3" "$group"; then
                            supported_groups+=("$group")
                        fi
                    done
                    tls13groups="${supported_groups[*]}"
                fi
            fi
        done
        
        tlsversions="${supported_versions[*]}"
        if [[ ${#supported_versions[@]} -gt 0 ]]; then
            reason="Supports: ${supported_versions[*]}"
        fi
        
        # Replace empty fields with NA
        [[ -z "$tlsversions" ]] && tlsversions="NA"
        [[ -z "$tls12ciphers" ]] && tls12ciphers="NA"
        [[ -z "$tls12groups" ]] && tls12groups="NA"
        [[ -z "$tls13ciphers" ]] && tls13ciphers="NA"
        [[ -z "$tls13groups" ]] && tls13groups="NA"
        [[ -z "$reason" ]] && reason="NA"
        
        echo "$pod_namespace,$pod_name,$pod_ip,$container_name,$port,$process,$status,$tlsversions,$tls12ciphers,$tls12groups,$tls13ciphers,$tls13groups,$reason"
    }
    
    # Main scan loop
    main() {
        local start_time=$(date +%s)
        local timestamp=$(date -u +"%Y%m%d-%H%M%S")
        local result_file="/tmp/scantls-results-${timestamp}.csv"
        
        echo "Starting TLS scan on node: $NODE_NAME" >&2
        echo "Start time: $(date -u +"%Y-%m-%d %H:%M:%S UTC")" >&2
        echo "Target namespace: $TARGET_NAMESPACE" >&2
        echo "TLS versions: $TLS_VERSIONS" >&2
        echo "Writing results to: ${result_file}" >&2
        
        # Print CSV header to file
        generate_csv_header > "${result_file}"
        
        # Scan each namespace
        for ns in $(get_target_namespaces); do
            echo "Scanning namespace: $ns" >&2
            
            for pod_id in $(get_pods_in_namespace "$ns"); do
                local pod_info=$(get_pod_info "$pod_id")
                [[ -z "$pod_info" ]] && continue
                
                local pod_name=$(echo "$pod_info" | jq -r '.status.metadata.name')
                local pod_namespace=$(echo "$pod_info" | jq -r '.status.metadata.namespace')
                local pod_ip=$(echo "$pod_info" | jq -r '.status.network.ip // empty')
                
                # Don't skip yet - host network pods have no pod_ip, will use node IP
                echo "  Scanning pod: $pod_name (IP: ${pod_ip:-<host-network>})" >&2
                
                for container_id in $(get_containers_for_pod "$pod_id"); do
                    local netns=$(get_container_netns "$container_id")
                    local container_name=$(nsenter -t 1 -m -u -n -i /usr/bin/crictl inspect -o json "$container_id" 2>/dev/null | jq -r '.status.metadata.name')
                    local container_pid=""
                    
                    # Handle host network pods (no separate netns)
                    if [[ -z "$netns" ]]; then
                        echo "    Host network pod detected, filtering by container PID" >&2
                        netns="/proc/1/ns/net"
                        # Get container PID to filter ports
                        container_pid=$(nsenter -t 1 -m -u -n -i /usr/bin/crictl inspect -o json "$container_id" 2>/dev/null | jq -r '.info.pid')
                        # Use node IP for host network pods
                        local node_ip=$(hostname -I | awk '{print $1}')
                        [[ -n "$node_ip" ]] && pod_ip="$node_ip"
                    fi
                    
                    for port_info in $(get_listening_ports "$netns" "$container_pid"); do
                        IFS=':' read -r port process <<< "$port_info"
                        echo "    Testing port: $port ($process)" >&2
                        scan_endpoint "$pod_namespace" "$pod_name" "$pod_ip" "$container_name" "$container_id" "$netns" "$port" "$process" >> "${result_file}"
                    done
                done
            done
        done
        
        local end_time=$(date +%s)
        local duration=$((end_time - start_time))
        local row_count=$(($(wc -l < "${result_file}") - 1))
        echo "Scan complete" >&2
        echo "End time: $(date -u +"%Y-%m-%d %H:%M:%S UTC")" >&2
        echo "Duration: ${duration}s ($(date -u -d @${duration} +"%H:%M:%S"))" >&2
        echo "Total rows: ${row_count}" >&2
        echo "Result file: ${result_file}" >&2
        echo "" >&2
        echo "=== CSV Results ===" >&2
        cat "${result_file}"
        echo "" >&2
        echo "=== End of Results ===" >&2
    }
    
    # Run main if SCAN_INTERVAL is 0, otherwise loop
    if [[ "$SCAN_INTERVAL" -eq 0 ]]; then
        main
        echo "Scan complete. Sleeping indefinitely to preserve logs..." >&2
        sleep infinity
    else
        while true; do
            main
            echo "Sleeping for $SCAN_INTERVAL seconds..." >&2
            sleep "$SCAN_INTERVAL"
        done
    fi
#, ServiceAccount for scantls pods
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: scantls
  namespace: @NAMESPACE@
#, SecurityContextConstraints for privileged scanning
---
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
users:
  - system:serviceaccount:@NAMESPACE@:scantls
#, DaemonSet for TLS scanning on each node
---
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: scantls
  namespace: @NAMESPACE@
spec:
  selector:
    matchLabels:
      app: scantls
  template:
    metadata:
      labels:
        app: scantls
    spec:
      serviceAccountName: scantls
      hostPID: true
      tolerations:
      - operator: Exists
      containers:
      - name: scanner
        image: @IMAGE@
        command: ["/bin/bash"]
        args: ["/scripts/scan-tls.sh"]
        env:
        - name: TARGET_NAMESPACE
          value: "@TARGET_NAMESPACE@"
        - name: SCAN_INTERVAL
          value: "@SCAN_INTERVAL@"
        - name: TIMEOUT
          value: "@TIMEOUT@"
        - name: EXCLUDE_NAMESPACES
          value: "@EXCLUDE_NAMESPACES@"
        - name: SKIP_PORTS
          value: "@SKIP_PORTS@"
        - name: TLS_VERSIONS
          value: "@TLS_VERSIONS@"
        - name: TLS12_CIPHERS
          value: "@TLS12_CIPHERS@"
        - name: TLS12_GROUPS
          value: "@TLS12_GROUPS@"
        - name: TLS13_CIPHERS
          value: "@TLS13_CIPHERS@"
        - name: TLS13_GROUPS
          value: "@TLS13_GROUPS@"
        securityContext:
          privileged: true
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
OUTER_EOF

# Substitute all variables in one sed command
sed -i \
  -e "s|@NAMESPACE@|${NAMESPACE}|g" \
  -e "s|@IMAGE@|${IMAGE}|g" \
  -e "s|@TARGET_NAMESPACE@|${TARGET_NAMESPACE}|g" \
  -e "s|@SCAN_INTERVAL@|${SCAN_INTERVAL}|g" \
  -e "s|@TIMEOUT@|${TIMEOUT}|g" \
  -e "s|@EXCLUDE_NAMESPACES@|${EXCLUDE_NAMESPACES}|g" \
  -e "s|@SKIP_PORTS@|${SKIP_PORTS}|g" \
  -e "s|@TLS_VERSIONS@|${TLS_VERSIONS}|g" \
  -e "s|@TLS12_CIPHERS@|${TLS12_CIPHERS}|g" \
  -e "s|@TLS12_GROUPS@|${TLS12_GROUPS}|g" \
  -e "s|@TLS13_CIPHERS@|${TLS13_CIPHERS}|g" \
  -e "s|@TLS13_GROUPS@|${TLS13_GROUPS}|g" \
  resources.yaml

echo "Generated resources.yaml successfully"
echo "Deploy with: oc apply --server-side -f resources.yaml"
