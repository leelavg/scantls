FROM registry.redhat.io/ubi10/ubi:10.1

# Install required tools
RUN dnf install -y \
    openssl \
    jq \
    hostname \
    && dnf clean all

# Script will be mounted from ConfigMap at runtime
ENTRYPOINT ["/bin/bash", "/scripts/scan-tls.sh"]