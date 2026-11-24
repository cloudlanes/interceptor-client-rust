#!/bin/sh
# Runs this repository's TLS-stack spike (E13-T004) against the reference server.
#
#   sh spike/run.sh
#
# 1. Writes test TLS material with spike/certs.sh (a CA, the server's certificate, and a client
#    certificate for mTLS) into a temporary directory.
# 2. Starts the broker image (INTERCEPTOR_SERVER_IMAGE, ghcr.io/cloudlanes/interceptor-broker:main
#    by default) on a private Docker network, under the network alias ion.conformance.test, so
#    the spike connects by the name in the server certificate. It waits for /readyz.
# 3. Runs the spike in its toolchain container on that network: SPIKE_IMAGE and SPIKE_CMD from
#    spike/spike.conf, with the repository mounted at /src and the ION_SPIKE_* environment set.
# 4. Removes the containers, the network and the TLS directory.
#
# This file is identical in every interceptor-client-* repository; spike/spike.conf differs.
set -eu

repo=$(cd "$(dirname "$0")/.." && pwd)
. "$repo/spike/spike.conf"
image=${INTERCEPTOR_SERVER_IMAGE:-ghcr.io/cloudlanes/interceptor-broker:main}
suffix=$$
network=ion-spike-$suffix
broker=ion-spike-broker-$suffix
tls=$(mktemp -d)

cleanup() {
    docker rm -f "$broker" >/dev/null 2>&1 || true
    docker network rm "$network" >/dev/null 2>&1 || true
    rm -rf "$tls"
}
trap cleanup EXIT INT TERM

sh "$repo/spike/certs.sh" "$tls"
docker network create "$network" >/dev/null
# The broker refuses to start without io_uring, which Docker's default seccomp profile blocks.
docker run -d --name "$broker" --network "$network" --network-alias ion.conformance.test \
    --security-opt seccomp=unconfined \
    -v "$tls:/etc/interceptor/tls:ro" \
    -e INTERCEPTOR_CLUSTER_ID=spike -e INTERCEPTOR_TLS_CERT_SOURCE=file \
    "$image" >/dev/null

ready=0
for _ in $(seq 1 120); do
    if docker run --rm --network "$network" curlimages/curl:8.11.1 \
        -sf -o /dev/null http://ion.conformance.test:9101/readyz 2>/dev/null; then
        ready=1
        break
    fi
    sleep 1
done
if [ "$ready" != 1 ]; then
    echo "the reference server did not become ready" >&2
    docker logs "$broker" >&2 || true
    exit 1
fi

# shellcheck disable=SC2086 # SPIKE_VOLUMES is a list of -v options.
docker run --rm --network "$network" \
    -v "$repo:/src" -v "$tls:/tls:ro" ${SPIKE_VOLUMES:-} \
    -e ION_SPIKE_ADDR=ion.conformance.test:5674 \
    -e ION_SPIKE_METRICS=ion.conformance.test:9100 \
    -e ION_SPIKE_TLS_DIR=/tls \
    -e ION_SPIKE_BULK_MIB="${ION_SPIKE_BULK_MIB:-256}" \
    -w /src "$SPIKE_IMAGE" sh -c "$SPIKE_CMD"
