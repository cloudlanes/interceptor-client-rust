#!/bin/sh
# Test TLS material for the reference server the conformance suite starts: a throwaway CA, and a
# server certificate for `ion.conformance.test`, `localhost` and 127.0.0.1 signed by it. The
# harness sends SNI `ion.conformance.test` and trusts only `ca.crt`.
#
#   sh conformance/certs.sh "$dir"   # writes ca.crt, tls.crt, tls.key; then INTERCEPTOR_TLS_DIR="$dir"
#
# This file is identical in every interceptor-client-* repository; the shared CI template
# (interceptor-server .github/workflows/client-conformance.yml) runs it. Test-only: the CA key is
# deleted and the certificates expire after two days.
set -eu

dir=${1:?usage: certs.sh <dir>}
mkdir -p "$dir"
cd "$dir"

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 \
    -subj /CN=interceptor-conformance-ca \
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

rm -f ca.key ca.srl tls.csr server.ext
# The broker runs as uid 10001 and reads the bind-mounted key.
chmod 0644 ca.crt tls.crt tls.key
