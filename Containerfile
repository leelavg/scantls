FROM registry.access.redhat.com/ubi10/ubi:10.1

# Install required tools
RUN dnf install -y \
    openssl \
    jq \
    hostname \
    && dnf clean all

# Default shell - script path specified in DaemonSet
ENTRYPOINT ["/bin/bash"]