# interceptor-client-rust

The official **Rust** client for [interceptor-server](https://github.com/cloudlanes/interceptor-server), speaking the native **ion** protocol: TCP + TLS 1.3, ALPN `interceptor-ion/1`, default port 5674.

> **Status: scaffold.** This repository holds the project layout, CI and the conformance harness (E13-T002). The client API comes with E13-T011.

The client follows the shared API specification (`interceptor-docs/client-api/v1.md`) in four modules: core messaging, management, pipelines and ad-hoc SQL. Each module has an idiomatic Rust shape.

| | |
|---|---|
| Minimum runtime | Rust stable (current and previous) |
| TLS stack | `tokio` + `tokio-rustls` |
| Speaks | ion major 1 (`interceptor-ion/1`): every 0.x and 1.x release |

## Layout

| Path | What |
|---|---|
| `src/` | The `interceptor-client` crate |
| `conformance/conformance.rs` | The conformance harness (`cargo test --test conformance`) |
| `conformance/certs.sh` | Test TLS material for the reference server (the same file in all six client repositories) |
| `spike/` | The TLS-stack spike (E13-T004): the `tls_spike` example (`cargo run --release --example tls_spike`); `ion-rs` and `tokio-rustls` are dev-dependencies, so the library stays dependency-free. `spike/run.sh` runs it against the reference server; see below |
| `.github/workflows/ci.yml` | CI: build and test, then the conformance suite |

## Building

```sh
cargo test
```

## Conformance suite

Every `interceptor-client-*` repository runs the shared ion conformance corpus against a reference `interceptor-server`, started with this language's testcontainers tooling (clients.md § Shared conformance test suite). A client release is blocked if any vector fails for its ion major.

Today the suite is empty. The harness starts the broker image, waits for `/readyz`, opens TLS 1.3 to port 5674 and requires the broker to negotiate `interceptor-ion/1`. It runs no vectors. The corpus comes with E10-T023 and the runner with E13-T009. Until then, the harness fails if it finds a vector in the corpus directory, so a populated corpus cannot pass unrun.

Running it locally needs Docker:

```sh
sh conformance/certs.sh /tmp/interceptor-tls
export INTERCEPTOR_TLS_DIR=/tmp/interceptor-tls
# optional: export INTERCEPTOR_SERVER_IMAGE=ghcr.io/cloudlanes/interceptor-broker:main
cargo test --locked --test conformance -- --nocapture
```

| Env | Meaning |
|---|---|
| `INTERCEPTOR_TLS_DIR` | `ca.crt`, `tls.crt`, `tls.key` from `conformance/certs.sh`. When unset, the suite skips. |
| `INTERCEPTOR_SERVER_IMAGE` | The broker image. Default `ghcr.io/cloudlanes/interceptor-broker:main`. |
| `INTERCEPTOR_ION_ALPN` | The ion major under test. Default `interceptor-ion/1`. |
| `INTERCEPTOR_CONFORMANCE_CORPUS` | The corpus directory for that major |

- **io_uring.** The broker needs io_uring, and Docker's default seccomp profile blocks it. So the harness starts the broker with `seccomp=unconfined`.
- **SNI.** The harness sends SNI `ion.conformance.test`, which the test certificate covers along with `localhost` and `127.0.0.1`. The broker rejects connections without SNI.

## TLS-stack spike (E13-T004)

`spike/main.rs` shows that `tokio` + `tokio-rustls` carries ion end to end against the reference server (clients.md § Per-language transport stack):

1. TLS 1.3 with ALPN `interceptor-ion/1`, SNI `ion.conformance.test` and a client certificate.
2. The control stream: `ClientHandshake` → `ServerHandshake`, then `Authenticate { kind: mtls }` → `AuthenticateResult { ok: true }`. A control frame is a big-endian `u32` length followed by one Apache Ion binary value.
3. `PING` / `PONG`, and one `DATA` round trip on client stream 1: a management stream whose `OPEN` carries `ListNamespaces`, answered with a `DATA` frame and `FIN`.
4. A second connection resumes the TLS session from the first one's ticket and authenticates again. The broker's resumption counter must grow.
5. Throughput: bulk `DATA` frames through this language's TLS stack on loopback.

Run it with Docker:

```sh
sh spike/run.sh
```

`spike/run.sh` (the same in all six repositories) writes test TLS material with `spike/certs.sh` and starts the broker image (`INTERCEPTOR_SERVER_IMAGE`) on a private Docker network as `ion.conformance.test`. It then runs the spike in the toolchain container that `spike/spike.conf` names. `spike/certs.sh` is `conformance/certs.sh` plus a client certificate for mTLS; the broker verifies client certificates against the `ca.crt` in its TLS directory.

| Env | Meaning |
|---|---|
| `ION_SPIKE_ADDR` | The broker's ion `host:port` |
| `ION_SPIKE_METRICS` | The broker's metrics `host:port`. It serves HTTPS, so the host must be a name in the server certificate. |
| `ION_SPIKE_TLS_DIR` | `spike/certs.sh` output |
| `ION_SPIKE_SNI` | Default `ion.conformance.test` |
| `ION_SPIKE_BULK_MIB` | Default 256 |

### Results

One run per language through `spike/run.sh`, each against a fresh broker built from interceptor-server `HEAD`: Linux containers on an OrbStack VM (Apple M1 Pro, 10 vCPUs). "Full" is the first connection's TCP + TLS handshake, which includes start-up and JIT warm-up. "Resumed" is the second connection's handshake, resumed from a ticket; the broker's `interceptor_ion_session_resumption_total{outcome="resumed"}` went from 0 to 1 in every run. Bulk is 256 MiB of 64 KiB `DATA` frames to a TLS 1.3 sink in the same process on loopback, so it is the language's own TLS on both ends.

| Language | Stack (runtime) | Full | Resumed | `PING` RTT | Bulk `DATA` |
|---|---|---|---|---|---|
| Rust | `tokio-rustls` 0.26, ring | 30.2 ms | 0.3 ms | 0.02 ms | 2867 MiB/s |
| Go | `crypto/tls` (Go 1.22) | 34.7 ms | 0.5 ms | 0.02 ms | 2853 MiB/s |
| Python | `asyncio` + `ssl`, OpenSSL 3.5 (3.11) | 31.4 ms | 0.9 ms | 0.07 ms | 1052 MiB/s |
| .NET | `SslStream`, OpenSSL (.NET 10 runtime, `net8.0` target) | 91.0 ms | 1.6 ms | 0.52 ms | 1572 MiB/s |
| Node.js | `node:tls` (Node 20) | 59.0 ms | 2.0 ms | 0.12 ms | 948 MiB/s |
| Java | Netty 4.2 `SslHandler`, JDK engine (Java 17) | 82.1 ms | 5.4 ms | 0.81 ms | 502 MiB/s |
| Java | Netty 4.2 `SslHandler`, OpenSSL engine (`netty-tcnative` BoringSSL) | 79.9 ms | 2.3 ms | 0.85 ms | 1101 MiB/s |

Stream 1 is answered with `Error(permanent.unauthorised)`: the spike's mTLS principal holds no rights, so `ListNamespaces` is refused. That is still the server's `DATA` reply and `FIN` on a client stream.

### Findings

- **.NET 8 does not resume mTLS sessions on Linux.** `SslStream` on the .NET 8 runtime never resumes a TLS session that offered a client certificate, whether the certificate comes from `ClientCertificates`, `ClientCertificateContext` or `LocalCertificateSelectionCallback`. Without a client certificate it resumes. The .NET 10 runtime resumes in all four cases. On .NET 8, an mTLS client therefore pays a full handshake on every reconnect, including redirects. It still works. The .NET spike targets `net8.0` and runs on the .NET 10 runtime (`RollForward=Major`).
- **Python's asyncio TLS cannot resume.** `asyncio.open_connection(ssl=...)` and `start_tls` take no `session`. The spike drives `ssl.SSLObject` over two `ssl.MemoryBIO`s on a plain asyncio socket, which is what asyncio does internally, and passes the saved `SSLSession` to `wrap_bio`. Two details: TLS 1.3 tickets arrive after the handshake, so the session is taken after the first reads; and after the peer's `close_notify`, `SSLObject.read` returns `b""` instead of raising.
- **Python needs no native framing extension.** At 64 KiB frames, throughput is bound by OpenSSL, not by Python. The pure-Python framing loop alone handles 6.6 M frames/s encoding and 5.5 M frames/s decoding 256-byte frames: header `struct` pack/unpack and zero-copy `memoryview` slices. At 100,000 small frames per second, that is under 2 % of one core. `amazon.ion` already loads its C extension (`ionc`) for the Ion control frames. Revisit only if a profile of the real client says otherwise.
- **Java: the JDK engine is the slowest stack.** It reaches about 0.5 GiB/s, and the JDK reports no TLS resumption, so the spike checks it on the broker. Netty's OpenSSL engine on BoringSSL (`netty-tcnative-boringssl-static`) more than doubles bulk throughput, with the same API. The client should default to the JDK engine, which has no native dependency, and use `netty-tcnative` when it is on the class path.
- **Resumption is keyed by the server name in every stack.** Java's `SslContext.newHandler(alloc, host, port)` and .NET's `TargetHost` key the session cache. A redirect to another pod (`ion-<ordinal>.<domain>`) is a different name, so the client resumes only with that pod's own ticket, as clients.md expects.
- **Rust specifics.** `rustls`' default in-memory session store keeps the tickets, and `handshake_kind()` reports `Resumed`. The bulk loop rewrites one reused 64 KiB + 10 byte buffer's header in place.

## Retry policy (E13-T007)

`src/retry.rs`: `RetryPolicy::decide` implements the shared reconnect, retry and redirect policy (`interceptor-docs/client-api/retry-policy.md`). The function is pure: given an operation's retry class, its attempt (retries, consecutive redirects, a random `u32` for jitter) and what happened (a stream error, a connection error, a `Close`, or a lost connection), it returns the action (retry, surface or continue), the delay, and what happens to the connection (keep it, connect to an endpoint, connect through the Service, or close it). The client code that will apply these decisions arrives with the client itself.

- **Defaults:** `initialRetryDelay` 100 ms, `maxRetryDelay` 5 s, `maxRetries` unlimited for sends and 10 for every other call.
- **Backoff:** exponential with equal jitter, in integers, so the same jitter gives the same delay in all six languages.
- **Vectors:** `conformance/retry-policy-v1.json`, identical in all six repositories and generated by interceptor-server (`interceptor_ion::retry_policy`). `tests/retry_policy.rs` runs every vector as a unit test (`cargo test --test retry_policy`), so CI's `build` job runs them. `serde_json` is a dev-dependency only, so the library stays dependency-free.

## CI

`.github/workflows/ci.yml` runs on pull requests, on pushes to `main` and by hand:

| Job | What fails it |
|---|---|
| `build` | Formatting, lint, build or unit tests, on the minimum runtime |
| `conformance` | interceptor-server's reusable `client-conformance.yml` template. It sets up the toolchain, pulls the broker image from GHCR, writes test TLS material, and runs `cargo test --locked --test conformance -- --nocapture`. |
| `ci` | Any other job not passing. Make it the required status check on `main`. |

The template and the broker image live in the private `interceptor-server` repository. Two settings make them reachable from here:

- interceptor-server's **Actions → Access** must be open to the organisation.
- The `interceptor-broker` package must grant this repository read access (package settings → **Manage Actions access**).

## Security

See [SECURITY.md](SECURITY.md).

## License

MIT. See [LICENSE](LICENSE).
