//! Tunnels relayed through an MQTT broker.
//!
//! `mqtt://[user:pass@]broker[:port]/<topic>` (or `mqtts://` for TLS) works as
//! both a listener and a peer URL. The listener keeps a connection to the
//! broker and accepts sessions published on `<topic>`; a peer connecting to the
//! same URL reaches it through the broker, so neither side needs a reachable
//! address. Each session carries an ordinary EasyTier byte stream, framed and
//! encrypted by the tunnel layer like any other transport.
//!
//! Query parameters: `qos=0|1` (default 1), `keepalive=<seconds>` (default 30),
//! and for `mqtts` `insecure=true` to accept an unverified broker certificate.

mod codec;
mod link;
mod session;

use std::time::Duration;

use anyhow::Context as _;
use async_trait::async_trait;
use easytier_core::{
    connectivity::transport::ConnectedByteStream,
    listener::transport::AcceptedTransport,
    socket::{SocketContext, SocketListener, tcp::TcpBindOptions},
};
use tokio::sync::mpsc;
use tokio_util::task::AbortOnDropHandle;

use crate::socket::tcp::RuntimeTcpSocket;

pub(crate) const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const SESSION_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const RECONNECT_MIN_DELAY: Duration = Duration::from_secs(1);
const RECONNECT_MAX_DELAY: Duration = Duration::from_secs(30);
const ACCEPT_QUEUE: usize = 16;

pub(crate) fn supports_scheme(scheme: &str) -> bool {
    matches!(scheme, "mqtt" | "mqtts")
}

/// A parsed `mqtt://` / `mqtts://` URL.
#[derive(Debug, Clone)]
pub(crate) struct MqttEndpoint {
    broker: url::Url,
    /// The URL without its password, safe to log and to advertise to peers.
    public_url: url::Url,
    tls: bool,
    topic: String,
    username: Option<String>,
    password: Option<String>,
    qos: u8,
    keep_alive: Duration,
    insecure: bool,
}

fn decode_component(value: &str) -> anyhow::Result<String> {
    Ok(percent_encoding::percent_decode_str(value)
        .decode_utf8()
        .context("mqtt url component is not valid utf-8")?
        .into_owned())
}

fn parse_bool(value: &str) -> anyhow::Result<bool> {
    match value {
        "1" | "true" | "yes" => Ok(true),
        "0" | "false" | "no" => Ok(false),
        _ => anyhow::bail!("invalid boolean: {value}"),
    }
}

impl MqttEndpoint {
    pub(crate) fn parse(url: &url::Url) -> anyhow::Result<Self> {
        let tls = match url.scheme() {
            "mqtt" => false,
            "mqtts" => true,
            scheme => anyhow::bail!("not an mqtt url scheme: {scheme}"),
        };
        if url.host_str().is_none_or(str::is_empty) {
            anyhow::bail!("mqtt url needs a broker host: {url}");
        }
        if url.fragment().is_some() {
            anyhow::bail!("mqtt topic must not contain wildcards or a fragment: {url}");
        }

        let topic = decode_component(url.path())?.trim_matches('/').to_owned();
        if topic.is_empty() {
            anyhow::bail!("mqtt url needs a topic path, e.g. mqtt://broker:1883/easytier/my-node");
        }
        if topic.contains(['+', '#', '\0']) {
            anyhow::bail!("mqtt topic must not contain wildcards: {topic}");
        }

        let username = Some(decode_component(url.username())?).filter(|user| !user.is_empty());
        let password = url.password().map(decode_component).transpose()?;

        let mut qos = 1;
        let mut keep_alive = Duration::from_secs(30);
        let mut insecure = false;
        for (key, value) in url.query_pairs() {
            match &*key {
                "qos" => {
                    qos = match &*value {
                        "0" => 0,
                        "1" => 1,
                        _ => anyhow::bail!("mqtt qos must be 0 or 1: {value}"),
                    }
                }
                "keepalive" => {
                    let secs: u64 = value
                        .parse()
                        .with_context(|| format!("invalid mqtt keepalive: {value}"))?;
                    if !(5..=3600).contains(&secs) {
                        anyhow::bail!("mqtt keepalive must be between 5 and 3600 seconds");
                    }
                    keep_alive = Duration::from_secs(secs);
                }
                "insecure" => insecure = parse_bool(&value)?,
                key => anyhow::bail!("unknown mqtt url parameter: {key}"),
            }
        }

        let mut public_url = url.clone();
        let _ = public_url.set_password(None);

        Ok(Self {
            broker: url.clone(),
            public_url,
            tls,
            topic,
            username,
            password,
            qos,
            keep_alive,
            insecure,
        })
    }

    fn default_port(&self) -> u16 {
        if self.tls { 8883 } else { 1883 }
    }

    fn topics(&self) -> session::Topics {
        session::Topics::new(&self.topic)
    }
}

/// Opens a session to the listener on `url`'s topic, relayed by the broker.
pub(crate) async fn connect(
    url: &url::Url,
) -> anyhow::Result<ConnectedByteStream<RuntimeTcpSocket>> {
    let endpoint = MqttEndpoint::parse(url)?;
    let topics = endpoint.topics();
    let session_id = session::new_id();
    let link = link::connect(
        &endpoint,
        link::LinkOptions {
            client_id: format!("et-{}", session::new_id()),
            subscriptions: vec![topics.to_connector(&session_id).to_string()],
            // Lets the listener drop the session at once if this node vanishes.
            last_will: Some((
                topics.handshake(&session_id).to_string(),
                session::Frame::control(session::FrameKind::Rst).encode(),
            )),
            bind: TcpBindOptions::default(),
        },
    )
    .await?;
    let stream =
        session::connect_session(link, &topics, &session_id, SESSION_HANDSHAKE_TIMEOUT).await?;
    let mut remote_url = endpoint.public_url.clone();
    remote_url.set_fragment(Some(&session_id));
    Ok(ConnectedByteStream::new(
        RuntimeTcpSocket::from_duplex(stream),
        None,
        endpoint.public_url,
        Some(remote_url),
    ))
}

/// Accepts sessions published to its topic. The broker connection is kept
/// up by a background task that reconnects with backoff for as long as the
/// listener lives, so a broker outage never stops the listener for good.
pub(crate) struct MqttListener {
    url: url::Url,
    socket_context: SocketContext,
    endpoint: Option<MqttEndpoint>,
    accepted: Option<mpsc::Receiver<session::AcceptedSession>>,
    supervisor: Option<AbortOnDropHandle<()>>,
}

impl MqttListener {
    pub(crate) fn new(url: url::Url, socket_context: SocketContext) -> Self {
        Self {
            url,
            socket_context,
            endpoint: None,
            accepted: None,
            supervisor: None,
        }
    }
}

impl std::fmt::Debug for MqttListener {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MqttListener")
            .field("url", &self.local_url())
            .field("running", &self.supervisor.is_some())
            .finish()
    }
}

async fn supervise_listener(
    endpoint: MqttEndpoint,
    bind: TcpBindOptions,
    accepted: mpsc::Sender<session::AcceptedSession>,
) {
    let topics = endpoint.topics();
    let mut delay = RECONNECT_MIN_DELAY;
    while !accepted.is_closed() {
        let listener_id = session::new_id();
        let result = link::connect(
            &endpoint,
            link::LinkOptions {
                client_id: format!("et-{listener_id}"),
                subscriptions: vec![
                    topics.handshake_filter(),
                    topics.to_listener_filter(&listener_id),
                ],
                last_will: None,
                bind: bind.clone(),
            },
        )
        .await;
        match result {
            Ok(link) => {
                tracing::info!(url = %endpoint.public_url, "mqtt listener connected to broker");
                delay = RECONNECT_MIN_DELAY;
                session::serve_listener(link, &topics, &listener_id, &accepted).await;
                tracing::warn!(url = %endpoint.public_url, "mqtt listener lost broker connection");
            }
            Err(error) => {
                tracing::warn!(url = %endpoint.public_url, ?error, "mqtt listener failed to reach broker");
            }
        }
        tokio::time::sleep(delay).await;
        delay = (delay * 2).min(RECONNECT_MAX_DELAY);
    }
}

#[async_trait]
impl SocketListener for MqttListener {
    type Accepted = AcceptedTransport<RuntimeTcpSocket>;

    async fn listen(&mut self) -> anyhow::Result<()> {
        if self.supervisor.is_some() {
            return Ok(());
        }
        let endpoint = MqttEndpoint::parse(&self.url)?;
        let (accepted_tx, accepted_rx) = mpsc::channel(ACCEPT_QUEUE);
        let bind = TcpBindOptions::default().with_context(self.socket_context.clone());
        self.supervisor = Some(AbortOnDropHandle::new(tokio::spawn(supervise_listener(
            endpoint.clone(),
            bind,
            accepted_tx,
        ))));
        self.endpoint = Some(endpoint);
        self.accepted = Some(accepted_rx);
        Ok(())
    }

    async fn accept(&mut self) -> anyhow::Result<Self::Accepted> {
        let (Some(accepted), Some(endpoint)) = (self.accepted.as_mut(), self.endpoint.as_ref())
        else {
            anyhow::bail!("mqtt listener is not started");
        };
        let session = accepted
            .recv()
            .await
            .ok_or_else(|| anyhow::anyhow!("mqtt listener stopped"))?;
        let mut remote_url = endpoint.public_url.clone();
        remote_url.set_fragment(Some(&session.session_id));
        Ok(AcceptedTransport::ByteStream {
            socket: RuntimeTcpSocket::from_duplex(session.stream),
            local_url: endpoint.public_url.clone(),
            remote_url: Some(remote_url),
        })
    }

    fn local_url(&self) -> url::Url {
        match &self.endpoint {
            Some(endpoint) => endpoint.public_url.clone(),
            None => {
                let mut url = self.url.clone();
                let _ = url.set_password(None);
                url
            }
        }
    }
}

#[cfg(test)]
mod tests;
