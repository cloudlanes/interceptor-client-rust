//! TLS-stack spike (E13-T004, clients.md § Per-language transport stack): `tokio` +
//! `tokio-rustls` against the reference server.
//!
//! 1. TLS 1.3 with ALPN `interceptor-ion/1`, SNI `ION_SPIKE_SNI` and a client certificate.
//! 2. The control stream: `ClientHandshake` → `ServerHandshake`, `Authenticate { kind: mtls }` →
//!    `AuthenticateResult { ok: true }`. A control frame is a big-endian `u32` length and one
//!    Apache Ion binary value.
//! 3. `PING` / `PONG`, and one `DATA` round trip on client stream 1: a management stream whose
//!    `OPEN` carries `ListNamespaces`, answered by a `Response` or `Error` and `FIN`.
//! 4. A second connection resumes the TLS session from the first one's ticket and authenticates
//!    again; the broker's `interceptor_ion_session_resumption_total{outcome="resumed"}` must grow.
//! 5. Throughput: `ION_SPIKE_BULK_MIB` MiB of 64 KiB `DATA` frames to an in-process TLS 1.3 sink
//!    on loopback.
//!
//! Environment: `ION_SPIKE_ADDR` (broker ion `host:port`), `ION_SPIKE_METRICS` (broker metrics
//! `host:port`, HTTPS; the host must be a name in the server certificate), `ION_SPIKE_TLS_DIR` (`spike/certs.sh` output), `ION_SPIKE_SNI`
//! (`ion.conformance.test`), `ION_SPIKE_BULK_MIB` (256).
//!
//! `cargo run --release --example tls_spike`

use std::io;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use ion_rs::v1_0::Binary;
use ion_rs::{Element, Struct};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{ClientConfig, HandshakeKind, ProtocolVersion, RootCertStore, ServerConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector, client::TlsStream};

const ALPN: &[u8] = b"interceptor-ion/1";
const DATA: u8 = 0x00;
const WINDOW_UPDATE: u8 = 0x01;
const RESET: u8 = 0x02;
const PING: u8 = 0x03;
const PONG: u8 = 0x04;
const OPEN: u8 = 0x01;
const FIN: u8 = 0x02;
const MANAGEMENT: u8 = 0x05;
const HEADER: usize = 10;
const BULK_FRAME: usize = 64 * 1024;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

struct Settings {
    addr: String,
    metrics: String,
    tls_dir: PathBuf,
    sni: String,
    bulk_mib: usize,
}

impl Settings {
    fn from_env() -> Result<Self> {
        let var = |name: &str| std::env::var(name).map_err(|_| format!("{name} is unset"));
        Ok(Self {
            addr: var("ION_SPIKE_ADDR")?,
            metrics: var("ION_SPIKE_METRICS")?,
            tls_dir: var("ION_SPIKE_TLS_DIR")?.into(),
            sni: std::env::var("ION_SPIKE_SNI").unwrap_or_else(|_| "ion.conformance.test".into()),
            bulk_mib: std::env::var("ION_SPIKE_BULK_MIB")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(256),
        })
    }
}

/// One ion frame as read: stream id, type, flags, payload.
struct Frame {
    stream: u32,
    kind: u8,
    flags: u8,
    payload: Vec<u8>,
}

/// An ion connection over a client TLS stream.
struct Ion {
    tls: TlsStream<TcpStream>,
    /// Control-stream bytes not yet consumed as whole control frames.
    control: Vec<u8>,
}

impl Ion {
    async fn write_frame(
        &mut self,
        stream: u32,
        kind: u8,
        flags: u8,
        payload: &[u8],
    ) -> Result<()> {
        let mut out = Vec::with_capacity(HEADER + payload.len());
        out.extend_from_slice(&stream.to_be_bytes());
        out.extend_from_slice(&[kind, flags]);
        out.extend_from_slice(&u32::try_from(payload.len())?.to_be_bytes());
        out.extend_from_slice(payload);
        self.tls.write_all(&out).await?;
        self.tls.flush().await?;
        Ok(())
    }

    /// The next frame, answering `PING`s and skipping `WINDOW_UPDATE`s on the way.
    async fn read_frame(&mut self) -> Result<Frame> {
        loop {
            let mut header = [0u8; HEADER];
            self.tls.read_exact(&mut header).await?;
            let length = u32::from_be_bytes(header[6..10].try_into()?) as usize;
            let mut payload = vec![0; length];
            self.tls.read_exact(&mut payload).await?;
            let frame = Frame {
                stream: u32::from_be_bytes(header[0..4].try_into()?),
                kind: header[4],
                flags: header[5],
                payload,
            };
            match frame.kind {
                WINDOW_UPDATE => {}
                PING => self.write_frame(0, PONG, 0, &frame.payload).await?,
                _ => return Ok(frame),
            }
        }
    }

    async fn send_control(&mut self, frame: &Element) -> Result<()> {
        let payload = framed(frame)?;
        self.write_frame(0, DATA, 0, &payload).await
    }

    /// The next whole control frame on stream 0.
    async fn read_control(&mut self) -> Result<Element> {
        loop {
            if let Some(element) = unframe(&mut self.control)? {
                return Ok(element);
            }
            let frame = self.read_frame().await?;
            match (frame.stream, frame.kind) {
                (0, DATA) => self.control.extend_from_slice(&frame.payload),
                (stream, kind) => {
                    return Err(format!("unexpected frame {kind} on stream {stream}").into());
                }
            }
        }
    }
}

/// A control frame's bytes: a big-endian `u32` length, then the Ion binary value.
fn framed(frame: &Element) -> Result<Vec<u8>> {
    let ion = frame.encode_as(Binary)?;
    let mut out = Vec::with_capacity(4 + ion.len());
    out.extend_from_slice(&u32::try_from(ion.len())?.to_be_bytes());
    out.extend_from_slice(&ion);
    Ok(out)
}

/// Takes one whole control frame off the front of `buffer`, if it holds one.
fn unframe(buffer: &mut Vec<u8>) -> Result<Option<Element>> {
    if buffer.len() < 4 {
        return Ok(None);
    }
    let length = u32::from_be_bytes(buffer[..4].try_into()?) as usize;
    if buffer.len() < 4 + length {
        return Ok(None);
    }
    let element = Element::read_one(&buffer[4..4 + length])?;
    buffer.drain(..4 + length);
    Ok(Some(element))
}

/// `Type::{fields}`.
fn annotated(annotation: &str, fields: Struct) -> Element {
    Element::from(fields).with_annotations([annotation])
}

/// The frame type of a control frame: its first annotation.
fn frame_type(element: &Element) -> String {
    element
        .annotations()
        .iter()
        .next()
        .and_then(|symbol| symbol.text())
        .unwrap_or("")
        .to_owned()
}

fn field<'a>(element: &'a Element, name: &str) -> Option<&'a Element> {
    element.as_struct().and_then(|fields| fields.get(name))
}

/// Fails with the server's `Error` frame if `element` is one.
fn check(element: &Element, expected: &str) -> Result<()> {
    let kind = frame_type(element);
    if kind == expected {
        return Ok(());
    }
    let code = field(element, "code")
        .and_then(Element::as_text)
        .unwrap_or("?");
    Err(format!("expected {expected}, got {kind} ({code})").into())
}

fn certificates(path: PathBuf) -> Result<Vec<CertificateDer<'static>>> {
    Ok(CertificateDer::pem_file_iter(path)?.collect::<std::result::Result<_, _>>()?)
}

fn client_config(settings: &Settings) -> Result<Arc<ClientConfig>> {
    let mut roots = RootCertStore::empty();
    for certificate in certificates(settings.tls_dir.join("ca.crt"))? {
        roots.add(certificate)?;
    }
    let mut config = ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_root_certificates(roots)
        .with_client_auth_cert(
            certificates(settings.tls_dir.join("client.crt"))?,
            PrivateKeyDer::from_pem_file(settings.tls_dir.join("client.key"))?,
        )?;
    config.alpn_protocols = vec![ALPN.to_vec()];
    // The default in-memory session store keeps the server's tickets for resumption.
    Ok(Arc::new(config))
}

/// TLS 1.3 to `addr`, checked: version, ALPN, and whether it resumed.
async fn connect(config: &Arc<ClientConfig>, addr: &str, sni: &str) -> Result<(Ion, bool, f64)> {
    let started = Instant::now();
    let tcp = TcpStream::connect(addr).await?;
    tcp.set_nodelay(true)?;
    let tls = TlsConnector::from(Arc::clone(config))
        .connect(ServerName::try_from(sni.to_owned())?, tcp)
        .await?;
    let elapsed = started.elapsed().as_secs_f64() * 1e3;
    let (_, connection) = tls.get_ref();
    if connection.protocol_version() != Some(ProtocolVersion::TLSv1_3) {
        return Err("not TLS 1.3".into());
    }
    if connection.alpn_protocol() != Some(ALPN) {
        return Err("ALPN interceptor-ion/1 was not negotiated".into());
    }
    let resumed = connection.handshake_kind() == Some(HandshakeKind::Resumed);
    Ok((
        Ion {
            tls,
            control: Vec::new(),
        },
        resumed,
        elapsed,
    ))
}

/// The ion handshake and mTLS authentication; returns the principal.
async fn authenticate(ion: &mut Ion, sni: &str) -> Result<String> {
    let version = Struct::builder()
        .with_field("minor", 0)
        .with_field("patch", 0)
        .build();
    let hello = Struct::builder()
        .with_field("version", version)
        .with_field("capabilities", Struct::builder().build())
        .with_field("client_id", "spike-rust")
        .with_field("expected_server_name", sni)
        .with_field("max_frame_size", 65_536)
        .build();
    ion.send_control(&annotated("ClientHandshake", hello))
        .await?;
    check(&ion.read_control().await?, "ServerHandshake")?;

    let credential = Struct::builder()
        .with_field("kind", ion_rs::Symbol::from("mtls"))
        .with_field("token", "")
        .build();
    ion.send_control(&annotated("Authenticate", credential))
        .await?;
    let result = ion.read_control().await?;
    check(&result, "AuthenticateResult")?;
    if field(&result, "ok").and_then(Element::as_bool) != Some(true) {
        return Err("authentication refused".into());
    }
    Ok(field(&result, "principal")
        .and_then(Element::as_text)
        .unwrap_or("")
        .to_owned())
}

async fn ping(ion: &mut Ion) -> Result<f64> {
    let opaque = 0x1e2d_3c4b_5a69_7887_u64.to_be_bytes();
    let started = Instant::now();
    ion.write_frame(0, PING, 0, &opaque).await?;
    let frame = ion.read_frame().await?;
    if frame.kind != PONG || frame.payload != opaque {
        return Err("PING was not answered by its PONG".into());
    }
    Ok(started.elapsed().as_secs_f64() * 1e3)
}

/// Opens management stream 1 with `ListNamespaces` and reads the reply until the server's `FIN`.
async fn client_stream(ion: &mut Ion) -> Result<String> {
    let request = annotated(
        "Request",
        Struct::builder()
            .with_field("rpc", "ListNamespaces")
            .with_field("body", Struct::builder().build())
            .build(),
    );
    let mut payload = vec![MANAGEMENT];
    payload.extend_from_slice(&framed(&request)?);
    ion.write_frame(1, DATA, OPEN, &payload).await?;
    let mut reply = Vec::new();
    loop {
        let frame = ion.read_frame().await?;
        match (frame.stream, frame.kind) {
            (1, DATA) => {
                reply.extend_from_slice(&frame.payload);
                if frame.flags & FIN != 0 {
                    break;
                }
            }
            (1, RESET) => {
                return Err(format!(
                    "stream 1 reset: {}",
                    String::from_utf8_lossy(&frame.payload)
                )
                .into());
            }
            (stream, kind) => {
                return Err(format!("unexpected frame {kind} on stream {stream}").into());
            }
        }
    }
    ion.write_frame(1, DATA, FIN, &[]).await?;
    let answer = unframe(&mut reply)?.ok_or("stream 1 carried no whole frame")?;
    let kind = frame_type(&answer);
    match kind.as_str() {
        "Response" => Ok(kind),
        "Error" => Ok(format!(
            "Error({})",
            field(&answer, "code")
                .and_then(Element::as_text)
                .unwrap_or("?")
        )),
        other => Err(format!("stream 1 answered {other}").into()),
    }
}

/// Ends the connection: `Close`, then whatever the server sends until it closes.
async fn close(mut ion: Ion) -> Result<()> {
    let close = annotated(
        "Close",
        Struct::builder().with_field("reason", "spike_done").build(),
    );
    ion.send_control(&close).await?;
    let mut sink = [0u8; 4096];
    while ion.tls.read(&mut sink).await.unwrap_or(0) > 0 {}
    Ok(())
}

/// `interceptor_ion_session_resumption_total{outcome="resumed"}` on the broker's metrics
/// endpoint, which serves HTTPS with the same certificate as ion.
async fn resumed_total(settings: &Settings) -> Result<f64> {
    let mut roots = RootCertStore::empty();
    for certificate in certificates(settings.tls_dir.join("ca.crt"))? {
        roots.add(certificate)?;
    }
    let config = ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_root_certificates(roots)
        .with_no_client_auth();
    let host = settings
        .metrics
        .rsplit_once(':')
        .map_or(settings.metrics.as_str(), |(host, _)| host);
    let tcp = TcpStream::connect(&settings.metrics).await?;
    let mut tls = TlsConnector::from(Arc::new(config))
        .connect(ServerName::try_from(host.to_owned())?, tcp)
        .await?;
    tls.write_all(format!("GET /metrics HTTP/1.0\r\nHost: {host}\r\n\r\n").as_bytes())
        .await?;
    let mut body = Vec::new();
    // The server may end without close_notify; what was read is enough.
    let _ = tls.read_to_end(&mut body).await;
    Ok(String::from_utf8_lossy(&body)
        .lines()
        .find(|line| {
            line.starts_with("interceptor_ion_session_resumption_total")
                && line.contains("outcome=\"resumed\"")
        })
        .and_then(|line| line.rsplit(' ').next())
        .and_then(|value| value.parse().ok())
        .unwrap_or(0.0))
}

/// MiB/s of `mib` MiB of 64 KiB `DATA` frames through the client stack to a loopback TLS 1.3
/// sink, timed until the sink acknowledges the last byte.
async fn throughput(settings: &Settings) -> Result<f64> {
    let mut server = ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_no_client_auth()
        .with_single_cert(
            certificates(settings.tls_dir.join("tls.crt"))?,
            PrivateKeyDer::from_pem_file(settings.tls_dir.join("tls.key"))?,
        )?;
    server.alpn_protocols = vec![ALPN.to_vec()];
    let acceptor = TlsAcceptor::from(Arc::new(server));
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?.to_string();
    let sink = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await?;
        tcp.set_nodelay(true)?;
        let mut tls = acceptor.accept(tcp).await?;
        let mut header = [0u8; HEADER];
        let mut payload = vec![0u8; BULK_FRAME];
        loop {
            tls.read_exact(&mut header).await?;
            let length = u32::from_be_bytes(header[6..10].try_into().expect("4 bytes")) as usize;
            tls.read_exact(&mut payload[..length]).await?;
            if header[5] & FIN != 0 {
                tls.write_all(&[1]).await?;
                tls.flush().await?;
                return Ok::<_, io::Error>(());
            }
        }
    });

    let mut roots = RootCertStore::empty();
    for certificate in certificates(settings.tls_dir.join("ca.crt"))? {
        roots.add(certificate)?;
    }
    let mut config = ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![ALPN.to_vec()];
    let (mut ion, _, _) = connect(&Arc::new(config), &addr, "localhost").await?;

    let frames = settings.bulk_mib * 1024 * 1024 / BULK_FRAME;
    // One reused buffer: the header is rewritten in place, the payload is never touched.
    let mut out = vec![0xA5u8; HEADER + BULK_FRAME];
    out[..4].copy_from_slice(&1u32.to_be_bytes());
    out[4] = DATA;
    out[6..10].copy_from_slice(&u32::try_from(BULK_FRAME)?.to_be_bytes());
    let started = Instant::now();
    for i in 0..frames {
        out[5] = if i == 0 { OPEN } else { 0 } | if i + 1 == frames { FIN } else { 0 };
        ion.tls.write_all(&out).await?;
    }
    ion.tls.flush().await?;
    let mut ack = [0u8; 1];
    ion.tls.read_exact(&mut ack).await?;
    let seconds = started.elapsed().as_secs_f64();
    sink.await??;
    #[allow(clippy::cast_precision_loss)]
    Ok(settings.bulk_mib as f64 / seconds)
}

#[tokio::main]
async fn main() -> Result<()> {
    let settings = Settings::from_env()?;
    let config = client_config(&settings)?;

    let (mut ion, resumed, tls_ms) = connect(&config, &settings.addr, &settings.sni).await?;
    if resumed {
        return Err("the first connection resumed".into());
    }
    let principal = authenticate(&mut ion, &settings.sni).await?;
    let rtt = ping(&mut ion).await?;
    let reply = client_stream(&mut ion).await?;
    close(ion).await?;
    println!(
        "spike rust: full handshake {tls_ms:.1} ms, principal {principal}, PING RTT {rtt:.2} ms, stream 1 → {reply}"
    );

    let before = resumed_total(&settings).await?;
    let (mut ion, resumed, tls_ms) = connect(&config, &settings.addr, &settings.sni).await?;
    if !resumed {
        return Err("the second connection did not resume the TLS session".into());
    }
    authenticate(&mut ion, &settings.sni).await?;
    ping(&mut ion).await?;
    close(ion).await?;
    let after = resumed_total(&settings).await?;
    if after <= before {
        return Err(format!("the broker counted no resumption ({before} → {after})").into());
    }
    println!(
        "spike rust: resumed handshake {tls_ms:.1} ms (broker resumed count {before} → {after})"
    );

    let mib_s = throughput(&settings).await?;
    println!(
        "spike rust: bulk DATA {} MiB at {mib_s:.0} MiB/s",
        settings.bulk_mib
    );
    println!("SPIKE rust ok");
    Ok(())
}
