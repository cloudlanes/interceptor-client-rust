//! The ion conformance suite against the reference server (clients.md § Shared conformance test
//! suite). The shared CI template (interceptor-server `client-conformance.yml`) sets the
//! environment below and runs `cargo test --test conformance`.
//!
//! - `INTERCEPTOR_TLS_DIR`: `ca.crt`, `tls.crt`, `tls.key` from `conformance/certs.sh`. Unset, the
//!   suite skips, so a plain `cargo test` needs no Docker.
//! - `INTERCEPTOR_SERVER_IMAGE`: the broker image, `ghcr.io/cloudlanes/interceptor-broker:main` by
//!   default.
//! - `INTERCEPTOR_ION_ALPN`: the ion major under test, `interceptor-ion/1` by default.
//! - `INTERCEPTOR_CONFORMANCE_CORPUS`: the corpus directory for that major.
//!
//! The suite is empty for now: it starts the broker, checks that it negotiates ion over TLS 1.3,
//! and runs no vectors. The corpus and its runner come with E10-T023 and E13-T009.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use testcontainers::core::wait::HttpWaitStrategy;
use testcontainers::core::{AccessMode, IntoContainerPort, Mount, WaitFor};
use testcontainers::runners::AsyncRunner;
use testcontainers::{GenericImage, ImageExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

const DEFAULT_IMAGE: &str = "ghcr.io/cloudlanes/interceptor-broker:main";
const DEFAULT_ALPN: &str = "interceptor-ion/1";
const SNI: &str = "ion.conformance.test";
const ION_PORT: u16 = 5674;
const ADMIN_PORT: u16 = 9101;

#[tokio::test]
async fn reference_server_negotiates_ion_and_the_corpus_runs() {
    let Some(tls_dir) = std::env::var_os("INTERCEPTOR_TLS_DIR").map(PathBuf::from) else {
        eprintln!("INTERCEPTOR_TLS_DIR is unset: skipping the conformance suite");
        return;
    };
    let image = std::env::var("INTERCEPTOR_SERVER_IMAGE").unwrap_or_else(|_| DEFAULT_IMAGE.into());
    let alpn = std::env::var("INTERCEPTOR_ION_ALPN").unwrap_or_else(|_| DEFAULT_ALPN.into());

    let (name, tag) = image.rsplit_once(':').unwrap_or((&image, "latest"));
    let broker = GenericImage::new(name, tag)
        .with_exposed_port(ION_PORT.tcp())
        .with_exposed_port(ADMIN_PORT.tcp())
        .with_wait_for(WaitFor::http(
            HttpWaitStrategy::new("/readyz")
                .with_port(ADMIN_PORT.tcp())
                .with_expected_status_code(200_u16),
        ))
        .with_mount(
            Mount::bind_mount(tls_dir.to_string_lossy(), "/etc/interceptor/tls")
                .with_access_mode(AccessMode::ReadOnly),
        )
        .with_env_var("INTERCEPTOR_CLUSTER_ID", "conformance")
        .with_env_var("INTERCEPTOR_TLS_CERT_SOURCE", "file")
        // The broker refuses to start without io_uring, which Docker's default profile blocks.
        .with_security_opt("seccomp=unconfined")
        .start()
        .await
        .expect("the reference server starts and becomes ready");

    let host = broker.get_host().await.expect("container host").to_string();
    let port = broker.get_host_port_ipv4(ION_PORT).await.expect("ion port");
    let negotiated = handshake(&tls_dir, &host, port, &alpn).await;
    assert_eq!(negotiated, alpn, "the broker negotiates {alpn}");

    let vectors = corpus_vectors();
    assert!(
        vectors.is_empty(),
        "the corpus has {} vector(s) but this harness has no runner yet (E13-T009): {vectors:?}",
        vectors.len()
    );
    eprintln!("conformance: {alpn} negotiated; 0 vectors run");
}

/// Opens TLS 1.3 to the broker with SNI [`SNI`], trusting only the test CA, and returns the
/// negotiated ALPN protocol.
async fn handshake(tls_dir: &Path, host: &str, port: u16, alpn: &str) -> String {
    let mut roots = RootCertStore::empty();
    for cert in CertificateDer::pem_file_iter(tls_dir.join("ca.crt")).expect("ca.crt") {
        roots
            .add(cert.expect("a CA certificate"))
            .expect("a valid CA");
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("TLS 1.3")
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![alpn.as_bytes().to_vec()];

    let tcp = TcpStream::connect((host, port)).await.expect("TCP connect");
    let server = ServerName::try_from(SNI).expect("SNI name");
    let tls = TlsConnector::from(Arc::new(config))
        .connect(server, tcp)
        .await
        .expect("TLS 1.3 handshake");
    let (_, session) = tls.get_ref();
    let protocol = session
        .alpn_protocol()
        .expect("the broker selects an ALPN protocol");
    String::from_utf8(protocol.to_vec()).expect("a UTF-8 ALPN token")
}

/// The corpus files for the ion major under test; none when the directory is unset or empty.
fn corpus_vectors() -> Vec<PathBuf> {
    let Some(dir) = std::env::var_os("INTERCEPTOR_CONFORMANCE_CORPUS") else {
        return Vec::new();
    };
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    entries
        .filter_map(Result::ok)
        .filter(|e| e.file_type().is_ok_and(|t| t.is_file()))
        .map(|e| e.path())
        .collect()
}
