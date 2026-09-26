//! Reliable byte streams multiplexed over MQTT topics.
//!
//! With the configured base topic `T`, a listener subscribes to `T/c/+` for
//! handshakes and to `T/d/<listener-id>/+` for session data. A connector picks
//! a random session id `S`, subscribes to `T/s/S` and publishes SYN to `T/c/S`.
//! Each listener answers with SYN_ACK carrying its id; the connector keeps the
//! first answer and sends data to `T/d/<listener-id>/S`, so a listener only
//! allocates a session once its SYN_ACK was the one chosen. Listeners reply on
//! `T/s/S`.
//!
//! Every DATA frame carries a per-direction sequence number. Duplicates (QoS 1
//! redelivery) are dropped and any gap closes the session, so the byte stream
//! handed to the tunnel layer is either intact or closed, never corrupted.

use std::{collections::HashMap, sync::Arc, time::Duration};

use bytes::{Buf, BufMut, Bytes, BytesMut};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _, DuplexStream},
    sync::mpsc,
    task::JoinSet,
};

use super::link::{LinkClosed, LinkSender, MqttLink};

const FRAME_VERSION: u8 = 1;
const FRAME_HEADER_LEN: usize = 10;
/// Bytes of tunnel stream carried by one MQTT message.
const MAX_FRAME_PAYLOAD: usize = 16 * 1024;
const DUPLEX_BUFFER: usize = 64 * 1024;
const SESSION_QUEUE: usize = 512;
const MAX_LISTENER_SESSIONS: usize = 256;
const SYN_RETRY_INTERVAL: Duration = Duration::from_secs(1);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum FrameKind {
    Syn = 1,
    SynAck = 2,
    Data = 3,
    Fin = 4,
    Rst = 5,
}

impl FrameKind {
    fn from_u8(value: u8) -> Option<Self> {
        Some(match value {
            1 => Self::Syn,
            2 => Self::SynAck,
            3 => Self::Data,
            4 => Self::Fin,
            5 => Self::Rst,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Frame {
    pub kind: FrameKind,
    pub seq: u64,
    pub payload: Bytes,
}

impl Frame {
    pub(crate) fn new(kind: FrameKind, seq: u64, payload: Bytes) -> Self {
        Self { kind, seq, payload }
    }

    pub(crate) fn control(kind: FrameKind) -> Self {
        Self::new(kind, 0, Bytes::new())
    }

    pub(crate) fn encode(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(FRAME_HEADER_LEN + self.payload.len());
        buf.put_u8(FRAME_VERSION);
        buf.put_u8(self.kind as u8);
        buf.put_u64(self.seq);
        buf.put_slice(&self.payload);
        buf.freeze()
    }

    pub(crate) fn decode(mut data: Bytes) -> Option<Self> {
        if data.len() < FRAME_HEADER_LEN || data[0] != FRAME_VERSION {
            return None;
        }
        data.advance(1);
        let kind = FrameKind::from_u8(data.get_u8())?;
        let seq = data.get_u64();
        Some(Self::new(kind, seq, data))
    }
}

#[derive(Debug, Clone)]
pub(crate) struct Topics {
    base: Arc<str>,
}

impl Topics {
    pub(crate) fn new(base: &str) -> Self {
        Self { base: base.into() }
    }

    pub(crate) fn handshake(&self, session: &str) -> Arc<str> {
        format!("{}/c/{session}", self.base).into()
    }

    pub(crate) fn handshake_filter(&self) -> String {
        format!("{}/c/+", self.base)
    }

    pub(crate) fn to_listener(&self, listener: &str, session: &str) -> Arc<str> {
        format!("{}/d/{listener}/{session}", self.base).into()
    }

    pub(crate) fn to_listener_filter(&self, listener: &str) -> String {
        format!("{}/d/{listener}/+", self.base)
    }

    pub(crate) fn to_connector(&self, session: &str) -> Arc<str> {
        format!("{}/s/{session}", self.base).into()
    }

    fn strip<'a>(&self, topic: &'a str, kind: &str) -> Option<&'a str> {
        topic
            .strip_prefix(&*self.base)?
            .strip_prefix('/')?
            .strip_prefix(kind)?
            .strip_prefix('/')
    }
}

pub(crate) fn new_id() -> String {
    uuid::Uuid::new_v4().simple().to_string()
}

fn is_valid_id(id: &str) -> bool {
    id.len() == 32 && id.bytes().all(|byte| byte.is_ascii_hexdigit())
}

enum SessionEnd {
    PeerClosed,
    LocalClosed,
    Failed(&'static str),
}

/// Moves bytes between one end of a duplex pipe and the MQTT peer until
/// either side closes.
async fn pump(
    stream: DuplexStream,
    sender: LinkSender,
    out_topic: Arc<str>,
    mut next_out_seq: u64,
    mut inbound: mpsc::Receiver<Frame>,
) {
    let (mut reader, mut writer) = tokio::io::split(stream);

    let receive = async {
        let mut expected = 0u64;
        while let Some(frame) = inbound.recv().await {
            match frame.kind {
                FrameKind::Data if frame.seq < expected => {}
                FrameKind::Data if frame.seq > expected => {
                    return SessionEnd::Failed("mqtt message lost, sequence gap");
                }
                FrameKind::Data => {
                    expected += 1;
                    if !frame.payload.is_empty() && writer.write_all(&frame.payload).await.is_err()
                    {
                        return SessionEnd::LocalClosed;
                    }
                }
                FrameKind::Fin | FrameKind::Rst => return SessionEnd::PeerClosed,
                FrameKind::Syn | FrameKind::SynAck => {}
            }
        }
        SessionEnd::Failed("mqtt broker connection lost")
    };

    let send = async {
        let mut buf = vec![0u8; MAX_FRAME_PAYLOAD];
        loop {
            let n = match reader.read(&mut buf).await {
                Ok(0) | Err(_) => return SessionEnd::LocalClosed,
                Ok(n) => n,
            };
            let frame = Frame::new(
                FrameKind::Data,
                next_out_seq,
                Bytes::copy_from_slice(&buf[..n]),
            );
            next_out_seq += 1;
            if sender
                .publish(out_topic.clone(), frame.encode())
                .await
                .is_err()
            {
                return SessionEnd::Failed("mqtt broker connection lost");
            }
        }
    };

    let end = tokio::select! {
        end = receive => end,
        end = send => end,
    };
    match end {
        SessionEnd::PeerClosed => {}
        SessionEnd::LocalClosed => {
            sender.try_publish(out_topic.clone(), Frame::control(FrameKind::Fin).encode());
        }
        SessionEnd::Failed(reason) => {
            tracing::debug!(%out_topic, reason, "mqtt session closed");
            sender.try_publish(out_topic.clone(), Frame::control(FrameKind::Rst).encode());
        }
    }
}

/// Performs the connector handshake over `link` and spawns the task relaying
/// the returned pipe. The link is closed when the session ends.
pub(crate) async fn connect_session(
    link: MqttLink,
    topics: &Topics,
    session_id: &str,
    handshake_timeout: Duration,
) -> anyhow::Result<DuplexStream> {
    let MqttLink {
        sender,
        mut incoming,
        task,
    } = link;
    let reply_topic = topics.to_connector(session_id);
    let syn_topic = topics.handshake(session_id);

    let handshake = async {
        let mut retry = tokio::time::interval(SYN_RETRY_INTERVAL);
        loop {
            tokio::select! {
                _ = retry.tick() => {
                    sender
                        .publish(syn_topic.clone(), Frame::control(FrameKind::Syn).encode())
                        .await?;
                }
                publish = incoming.recv() => {
                    let publish = publish.ok_or(LinkClosed)?;
                    if *publish.topic != *reply_topic {
                        continue;
                    }
                    match Frame::decode(publish.payload) {
                        Some(frame) if frame.kind == FrameKind::SynAck => {
                            let listener_id = String::from_utf8_lossy(&frame.payload).into_owned();
                            if is_valid_id(&listener_id) {
                                return Ok::<_, anyhow::Error>(listener_id);
                            }
                        }
                        Some(frame) if frame.kind == FrameKind::Rst => {
                            anyhow::bail!("mqtt listener rejected the session");
                        }
                        _ => {}
                    }
                }
            }
        }
    };
    let listener_id = tokio::time::timeout(handshake_timeout, handshake)
        .await
        .map_err(|_| anyhow::anyhow!("no mqtt listener answered on this topic"))??;

    let data_topic = topics.to_listener(&listener_id, session_id);
    // Sequence 0 opens the session on the listener that won the handshake.
    sender
        .publish(data_topic.clone(), Frame::control(FrameKind::Data).encode())
        .await?;

    let (local, remote) = tokio::io::duplex(DUPLEX_BUFFER);
    let (frame_tx, frame_rx) = mpsc::channel(SESSION_QUEUE);
    tokio::spawn(async move {
        let _task = task;
        let forward = async {
            while let Some(publish) = incoming.recv().await {
                if *publish.topic != *reply_topic {
                    continue;
                }
                if let Some(frame) = Frame::decode(publish.payload)
                    && frame_tx.send(frame).await.is_err()
                {
                    return;
                }
            }
        };
        tokio::select! {
            _ = forward => {}
            _ = pump(remote, sender.clone(), data_topic, 1, frame_rx) => {}
        }
        sender.disconnect().await;
    });
    Ok(local)
}

pub(crate) struct AcceptedSession {
    pub stream: DuplexStream,
    pub session_id: String,
}

/// Serves sessions for one listener until the broker connection is lost.
/// Every session relayed over the link ends with it.
pub(crate) async fn serve_listener(
    link: MqttLink,
    topics: &Topics,
    listener_id: &str,
    accepted: &mpsc::Sender<AcceptedSession>,
) {
    let MqttLink {
        sender,
        mut incoming,
        task: _task,
    } = link;
    let mut sessions: HashMap<String, mpsc::Sender<Frame>> = HashMap::new();
    let mut pumps = JoinSet::new();
    let reject = |session_id: &str| {
        sender.try_publish(
            topics.to_connector(session_id),
            Frame::control(FrameKind::Rst).encode(),
        );
    };

    loop {
        let publish = tokio::select! {
            publish = incoming.recv() => match publish {
                Some(publish) => publish,
                None => break,
            },
            Some(_) = pumps.join_next(), if !pumps.is_empty() => continue,
        };
        let Some(frame) = Frame::decode(publish.payload) else {
            continue;
        };

        if let Some(session_id) = topics.strip(&publish.topic, "c") {
            if !is_valid_id(session_id) {
                continue;
            }
            match frame.kind {
                FrameKind::Syn => sender.try_publish(
                    topics.to_connector(session_id),
                    Frame::new(
                        FrameKind::SynAck,
                        0,
                        Bytes::copy_from_slice(listener_id.as_bytes()),
                    )
                    .encode(),
                ),
                FrameKind::Fin | FrameKind::Rst => {
                    sessions.remove(session_id);
                }
                _ => {}
            }
            continue;
        }

        let Some((target, session_id)) = topics
            .strip(&publish.topic, "d")
            .and_then(|rest| rest.split_once('/'))
        else {
            continue;
        };
        if target != listener_id || !is_valid_id(session_id) {
            continue;
        }

        if let Some(session) = sessions.get(session_id) {
            match session.try_send(frame) {
                Ok(()) => {}
                Err(mpsc::error::TrySendError::Full(_)) => {
                    tracing::warn!(session_id, "mqtt session receive queue overflow");
                    sessions.remove(session_id);
                    reject(session_id);
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    sessions.remove(session_id);
                }
            }
            continue;
        }

        if frame.kind != FrameKind::Data || frame.seq != 0 {
            // Data for a session this listener does not know, e.g. from
            // before a broker reconnect: tell the connector to give up.
            if frame.kind == FrameKind::Data {
                reject(session_id);
            }
            continue;
        }
        if sessions.len() >= MAX_LISTENER_SESSIONS {
            sessions.retain(|_, session| !session.is_closed());
            if sessions.len() >= MAX_LISTENER_SESSIONS {
                tracing::warn!(session_id, "too many mqtt sessions, rejecting");
                reject(session_id);
                continue;
            }
        }

        let (local, remote) = tokio::io::duplex(DUPLEX_BUFFER);
        let (frame_tx, frame_rx) = mpsc::channel(SESSION_QUEUE);
        let _ = frame_tx.try_send(frame);
        let session = AcceptedSession {
            stream: local,
            session_id: session_id.to_owned(),
        };
        if accepted.try_send(session).is_err() {
            reject(session_id);
            continue;
        }
        sessions.insert(session_id.to_owned(), frame_tx);
        pumps.spawn(pump(
            remote,
            sender.clone(),
            topics.to_connector(session_id),
            0,
            frame_rx,
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_round_trip() {
        let frame = Frame::new(FrameKind::Data, 42, Bytes::from_static(b"payload"));
        assert_eq!(Frame::decode(frame.encode()), Some(frame));
        assert_eq!(
            Frame::decode(Frame::control(FrameKind::Fin).encode()),
            Some(Frame::control(FrameKind::Fin))
        );
        assert_eq!(Frame::decode(Bytes::from_static(b"\x02short")), None);
        let mut bad_version = BytesMut::from(&Frame::control(FrameKind::Syn).encode()[..]);
        bad_version[0] = 9;
        assert_eq!(Frame::decode(bad_version.freeze()), None);
    }

    #[test]
    fn topics_round_trip() {
        let topics = Topics::new("home/et");
        let session = new_id();
        let listener = new_id();
        assert!(is_valid_id(&session));
        assert_eq!(&*topics.handshake(&session), format!("home/et/c/{session}"));
        assert_eq!(
            topics.strip(&topics.handshake(&session), "c"),
            Some(session.as_str())
        );
        let data = topics.to_listener(&listener, &session);
        assert_eq!(
            topics.strip(&data, "d"),
            Some(format!("{listener}/{session}").as_str())
        );
        assert_eq!(topics.strip("home/etx/c/abc", "c"), None);
        assert_eq!(topics.strip("home/et/s/abc", "c"), None);
    }
}
