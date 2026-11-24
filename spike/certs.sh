#!/bin/sh
# Test TLS material for the TLS-stack spikes (E13-T004): what conformance/certs.sh writes for the
# reference server (ca.crt, tls.crt, tls.key), plus a client certificate signed by the same CA
# (client.crt, client.key), so the spike can authenticate with mTLS. The broker verifies client
# certificates against ca.crt in its TLS directory.
#
#   sh spike/certs.sh "$dir"
#
# This file is identical in every interceptor-client-* repository. Test-only: the CA key is
# deleted and the certificates expire after two days.
set -eu

dir=${1:?usage: certs.sh <dir>}
mkdir -p "$dir"
cd "$dir"

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 \
    -subj /CN=interceptor-spike-ca \
    -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign \
    -keyout ca.key -out ca.crt 2>/dev/null

cat >server.ext <<'EOF'
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = DNS:ion.conformance.test, DNS:localhost, IP:127.0.0.1
EOF
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -subj /CN=ion.conformance.test -keyout tls.key -out tls.csr 2>/dev/null
openssl x509 -req -in tls.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 2 \
    -extfile server.ext -out tls.crt 2>/dev/null

cat >client.ext <<'EOF'
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = clientAuth
EOF
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -subj /CN=ion-spike -keyout client.key -out client.csr 2>/dev/null
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 2 \
    -extfile client.ext -out client.crt 2>/dev/null

rm -f ca.key ca.srl tls.csr client.csr server.ext client.ext
# The broker runs as uid 10001 and reads the bind-mounted key.
chmod 0644 ca.crt tls.crt tls.key client.crt client.key
