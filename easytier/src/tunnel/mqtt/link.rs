//! One MQTT broker connection shared by the tunnel sessions relayed over it.

use std::{net::SocketAddr, sync::Arc, time::Duration};

use anyhow::Context as _;
use bytes::{Bytes, BytesMut};
use easytier_core::socket::tcp::{TcpBindOptions, TcpConnectOptions, TcpSocketPurpose};
use tokio::{
    io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _},
    sync::mpsc,
};
use tokio_util::task::AbortOnDropHandle;

use super::{
    MqttEndpoint,
    codec::{Connect, LastWill, Packet, Publish},
};

/// Largest MQTT packet accepted from the broker. Tunnel frames stay far below
/// it; the limit only bounds memory for hostile or misconfigured brokers.
const MAX_INCOMING_PACKET: usize = 64 * 1024;
const BROKER_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const OUTGOING_QUEUE: usize = 256;
const INCOMING_QUEUE: usize = 256;

trait BrokerStream: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin> BrokerStream for T {}

#[derive(Debug, thiserror::Error)]
#[error("mqtt broker connection closed")]
pub(crate) struct LinkClosed;

enum Outgoing {
    Publish { topic: Arc<str>, payload: Bytes },
    Disconnect,
}

/// Publishes to the broker through the link's writer task.
#[derive(Clone)]
pub(crate) struct LinkSender {
    tx: mpsc::Sender<Outgoing>,
}

impl LinkSender {
    pub(crate) async fn publish(&self, topic: Arc<str>, payload: Bytes) -> Result<(), LinkClosed> {
        self.tx
            .send(Outgoing::Publish { topic, payload })
            .await
            .map_err(|_| LinkClosed)
    }

    /// Queues a publish without waiting, for best-effort control frames.
    pub(crate) fn try_publish(&self, topic: Arc<str>, payload: Bytes) {
        let _ = self.tx.try_send(Outgoing::Publish { topic, payload });
    }

    /// Sends DISCONNECT after everything already queued, so the broker
    /// closes the connection without firing the last will.
    pub(crate) async fn disconnect(&self) {
        if self.tx.send(Outgoing::Disconnect).await.is_ok() {
            let _ = tokio::time::timeout(Duration::from_secs(1), self.tx.closed()).await;
        }
    }
}

pub(crate) struct MqttLink {
    pub sender: LinkSender,
    pub incoming: mpsc::Receiver<Publish>,
    /// Owns the connection; dropping it tears the connection down.
    pub task: AbortOnDropHandle<()>,
}

pub(crate) struct LinkOptions {
    pub client_id: String,
    pub subscriptions: Vec<String>,
    pub last_will: Option<(String, Bytes)>,
    pub bind: TcpBindOptions,
}

pub(crate) async fn connect(
    endpoint: &MqttEndpoint,
    options: LinkOptions,
) -> anyhow::Result<MqttLink> {
    tokio::time::timeout(BROKER_HANDSHAKE_TIMEOUT, connect_inner(endpoint, options))
        .await
        .with_context(|| format!("mqtt broker handshake timed out: {}", endpoint.public_url))?
}

async fn connect_inner(endpoint: &MqttEndpoint, options: LinkOptions) -> anyhow::Result<MqttLink> {
    let mut stream = open_stream(endpoint, &options.bind).await?;
    let mut read_buf = BytesMut::with_capacity(4096);

    write_packet(
        &mut stream,
        &Packet::Connect(Connect {
            client_id: options.client_id,
            keep_alive_secs: endpoint.keep_alive.as_secs() as u16,
            clean_session: true,
            username: endpoint.username.clone(),
            password: endpoint.password.clone(),
            last_will: options.last_will.map(|(topic, payload)| LastWill {
                topic,
                payload,
                qos: endpoint.qos,
            }),
        }),
    )
    .await?;
    match read_packet(&mut stream, &mut read_buf).await? {
        Packet::ConnAck { code: 0, .. } => {}
        Packet::ConnAck { code, .. } => {
            anyhow::bail!("mqtt broker refused connection: {}", connack_reason(code))
        }
        packet => anyhow::bail!("expected mqtt CONNACK, got {packet:?}"),
    }

    let pkid = 1;
    write_packet(
        &mut stream,
        &Packet::Subscribe {
            pkid,
            filters: options
                .subscriptions
                .iter()
                .map(|filter| (filter.clone(), endpoint.qos))
                .collect(),
        },
    )
    .await?;
    // Publishes may race ahead of the SUBACK; keep them for the session layer.
    let mut early = Vec::new();
    loop {
        match read_packet(&mut stream, &mut read_buf).await? {
            Packet::SubAck { pkid: ack, codes } if ack == pkid => {
                if codes.iter().any(|code| *code >= 0x80) {
                    anyhow::bail!(
                        "mqtt broker rejected subscription to {:?}",
                        options.subscriptions
                    );
                }
                break;
            }
            Packet::Publish(publish) => early.push(publish),
            _ => {}
        }
    }

    let (sender_tx, sender_rx) = mpsc::channel(OUTGOING_QUEUE);
    let (incoming_tx, incoming) = mpsc::channel(INCOMING_QUEUE.max(early.len()));
    for publish in early {
        let _ = incoming_tx.try_send(publish);
    }
    let task = tokio::spawn(run_link(
        stream,
        read_buf,
        endpoint.qos,
        endpoint.keep_alive,
        sender_rx,
        incoming_tx,
    ));
    Ok(MqttLink {
        sender: LinkSender { tx: sender_tx },
        incoming,
        task: AbortOnDropHandle::new(task),
    })
}

fn connack_reason(code: u8) -> &'static str {
    match code {
        1 => "unacceptable protocol version",
        2 => "client identifier rejected",
        3 => "server unavailable",
        4 => "bad user name or password",
        5 => "not authorized",
        _ => "unknown reason",
    }
}

async fn open_stream(
    endpoint: &MqttEndpoint,
    bind: &TcpBindOptions,
) -> anyhow::Result<Box<dyn BrokerStream>> {
    let addrs =
        crate::common::dns::socket_addrs(&endpoint.broker, || Some(endpoint.default_port()))
            .await
            .with_context(|| format!("failed to resolve mqtt broker {}", endpoint.public_url))?;
    let socket = connect_any(&addrs, bind).await?;
    if !endpoint.tls {
        return Ok(Box::new(socket));
    }
    let connector =
        tokio_rustls::TlsConnector::from(Arc::new(tls::client_config(endpoint.insecure)?));
    let stream = connector
        .connect(tls::server_name(&endpoint.broker)?, socket)
        .await
        .with_context(|| format!("mqtt broker TLS handshake failed: {}", endpoint.public_url))?;
    Ok(Box::new(stream))
}

async fn connect_any(
    addrs: &[SocketAddr],
    bind: &TcpBindOptions,
) -> anyhow::Result<crate::socket::tcp::RuntimeTcpSocket> {
    let mut last_error = None;
    for addr in addrs {
        let options = TcpConnectOptions {
            remote_addr: *addr,
            bind: bind.clone(),
            purpose: TcpSocketPurpose::ManualConnect,
        };
        match crate::socket::tcp::connect_tcp(options).await {
            Ok(socket) => return Ok(socket),
            Err(error) => last_error = Some(error),
        }
    }
    match last_error {
        Some(error) => Err(error).context("failed to connect to mqtt broker"),
        None => anyhow::bail!("mqtt broker resolved to no address"),
    }
}

async fn write_packet<W: AsyncWrite + Unpin>(
    stream: &mut W,
    packet: &Packet,
) -> anyhow::Result<()> {
    let mut buf = BytesMut::new();
    packet.encode(&mut buf);
    stream.write_all(&buf).await?;
    stream.flush().await?;
    Ok(())
}

async fn read_packet<R: AsyncRead + Unpin>(
    stream: &mut R,
    buf: &mut BytesMut,
) -> anyhow::Result<Packet> {
    loop {
        if let Some(packet) = Packet::decode(buf, MAX_INCOMING_PACKET)? {
            return Ok(packet);
        }
        buf.reserve(4096);
        if stream.read_buf(buf).await? == 0 {
            anyhow::bail!("mqtt broker closed the connection");
        }
    }
}

async fn run_link(
    stream: Box<dyn BrokerStream>,
    read_buf: BytesMut,
    qos: u8,
    keep_alive: Duration,
    outgoing: mpsc::Receiver<Outgoing>,
    incoming: mpsc::Sender<Publish>,
) {
    let (reader, writer) = tokio::io::split(stream);
    let (ack_tx, ack_rx) = mpsc::unbounded_channel();
    let result = tokio::select! {
        result = read_loop(reader, read_buf, keep_alive, incoming, ack_tx) => result,
        result = write_loop(writer, qos, keep_alive, outgoing, ack_rx) => result,
    };
    if let Err(error) = result {
        tracing::warn!(?error, "mqtt broker connection ended");
    }
}

async fn read_loop<R: AsyncRead + Unpin>(
    mut reader: R,
    mut buf: BytesMut,
    keep_alive: Duration,
    incoming: mpsc::Sender<Publish>,
    acks: mpsc::UnboundedSender<u16>,
) -> anyhow::Result<()> {
    // The writer pings every half keep-alive, so silence for longer than a
    // keep-alive and a half means the broker (or the path to it) is gone.
    let idle_limit = keep_alive + keep_alive / 2;
    loop {
        let packet = tokio::time::timeout(idle_limit, read_packet(&mut reader, &mut buf))
            .await
            .context("mqtt broker stopped responding")??;
        match packet {
            Packet::Publish(publish) => {
                if publish.qos > 0 {
                    let _ = acks.send(publish.pkid);
                }
                if incoming.send(publish).await.is_err() {
                    return Ok(());
                }
            }
            Packet::Disconnect => anyhow::bail!("mqtt broker sent DISCONNECT"),
            _ => {}
        }
    }
}

async fn write_loop<W: AsyncWrite + Unpin>(
    mut writer: W,
    qos: u8,
    keep_alive: Duration,
    mut outgoing: mpsc::Receiver<Outgoing>,
    mut acks: mpsc::UnboundedReceiver<u16>,
) -> anyhow::Result<()> {
    let mut ping = tokio::time::interval(keep_alive / 2);
    ping.tick().await;
    let mut next_pkid: u16 = 1;
    let mut buf = BytesMut::new();
    loop {
        tokio::select! {
            message = outgoing.recv() => {
                let Some(message) = message else {
                    // Every sender is gone: nothing can use this link anymore.
                    Packet::Disconnect.encode(&mut buf);
                    writer.write_all(&buf).await?;
                    return Ok(());
                };
                let mut next = Some(message);
                // Coalesce whatever is already queued into a single write.
                while let Some(message) = next.take() {
                    match message {
                        Outgoing::Publish { topic, payload } => {
                            let pkid = if qos > 0 {
                                let pkid = next_pkid;
                                next_pkid = next_pkid.checked_add(1).unwrap_or(1);
                                pkid
                            } else {
                                0
                            };
                            Packet::Publish(Publish {
                                topic: topic.to_string(),
                                qos,
                                pkid,
                                payload,
                            })
                            .encode(&mut buf);
                        }
                        Outgoing::Disconnect => {
                            Packet::Disconnect.encode(&mut buf);
                            writer.write_all(&buf).await?;
                            writer.flush().await?;
                            return Ok(());
                        }
                    }
                    if buf.len() < 64 * 1024 {
                        next = outgoing.try_recv().ok();
                    }
                }
            }
            Some(pkid) = acks.recv() => Packet::PubAck(pkid).encode(&mut buf),
            _ = ping.tick() => Packet::PingReq.encode(&mut buf),
        }
        writer.write_all(&buf).await?;
        writer.flush().await?;
        buf.clear();
    }
}

mod tls {
    use std::sync::Arc;

    use rustls::{
        DigitallySignedStruct, SignatureScheme,
        client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
        crypto::CryptoProvider,
        pki_types::{CertificateDer, ServerName, UnixTime},
    };

    pub(super) fn client_config(insecure: bool) -> anyhow::Result<rustls::ClientConfig> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let builder = rustls::ClientConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()?;
        let config = if insecure {
            builder
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoCertificateVerification(provider)))
                .with_no_client_auth()
        } else {
            let roots =
                rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            builder.with_root_certificates(roots).with_no_client_auth()
        };
        Ok(config)
    }

    pub(super) fn server_name(url: &url::Url) -> anyhow::Result<ServerName<'static>> {
        Ok(match url.host() {
            Some(url::Host::Domain(domain)) => ServerName::try_from(domain.to_owned())?,
            Some(url::Host::Ipv4(ip)) => ServerName::IpAddress(std::net::IpAddr::V4(ip).into()),
            Some(url::Host::Ipv6(ip)) => ServerName::IpAddress(std::net::IpAddr::V6(ip).into()),
            None => anyhow::bail!("mqtt broker url has no host: {url}"),
        })
    }

    /// Used only with `insecure=true`, for brokers with self-signed
    /// certificates. Tunnel payloads stay protected by EasyTier's own
    /// encryption; the broker credentials do not.
    #[derive(Debug)]
    struct NoCertificateVerification(Arc<CryptoProvider>);

    impl ServerCertVerifier for NoCertificateVerification {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, rustls::Error> {
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            rustls::crypto::verify_tls12_signature(
                message,
                cert,
                dss,
                &self.0.signature_verification_algorithms,
            )
        }

        fn verify_tls13_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            rustls::crypto::verify_tls13_signature(
                message,
                cert,
                dss,
                &self.0.signature_verification_algorithms,
            )
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            self.0.signature_verification_algorithms.supported_schemes()
        }
    }
}
