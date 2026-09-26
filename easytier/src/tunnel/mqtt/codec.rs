//! The subset of MQTT 3.1.1 needed to relay tunnel streams through a broker.

use bytes::{Buf, BufMut, Bytes, BytesMut};

const CONNECT: u8 = 0x10;
const CONNACK: u8 = 0x20;
const PUBLISH: u8 = 0x30;
const PUBACK: u8 = 0x40;
const SUBSCRIBE: u8 = 0x82;
const SUBACK: u8 = 0x90;
const PINGREQ: u8 = 0xC0;
const PINGRESP: u8 = 0xD0;
const DISCONNECT: u8 = 0xE0;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub(crate) enum CodecError {
    #[error("malformed mqtt remaining length")]
    MalformedLength,
    #[error("mqtt packet of {0} bytes exceeds the {1} byte limit")]
    PacketTooLarge(usize, usize),
    #[error("malformed mqtt packet: {0}")]
    Malformed(&'static str),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LastWill {
    pub topic: String,
    pub payload: Bytes,
    pub qos: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Connect {
    pub client_id: String,
    pub keep_alive_secs: u16,
    pub clean_session: bool,
    pub username: Option<String>,
    pub password: Option<String>,
    pub last_will: Option<LastWill>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Publish {
    pub topic: String,
    pub qos: u8,
    pub pkid: u16,
    pub payload: Bytes,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Packet {
    Connect(Connect),
    ConnAck {
        session_present: bool,
        code: u8,
    },
    Publish(Publish),
    PubAck(u16),
    Subscribe {
        pkid: u16,
        filters: Vec<(String, u8)>,
    },
    SubAck {
        pkid: u16,
        codes: Vec<u8>,
    },
    PingReq,
    PingResp,
    Disconnect,
    /// A packet this client never acts on, identified by its type nibble.
    Other(u8),
}

fn put_remaining_length(buf: &mut BytesMut, mut len: usize) {
    loop {
        let mut byte = (len % 128) as u8;
        len /= 128;
        if len > 0 {
            byte |= 0x80;
        }
        buf.put_u8(byte);
        if len == 0 {
            break;
        }
    }
}

fn put_str(buf: &mut BytesMut, value: &str) {
    put_bytes(buf, value.as_bytes());
}

fn put_bytes(buf: &mut BytesMut, value: &[u8]) {
    buf.put_u16(value.len() as u16);
    buf.put_slice(value);
}

fn str_len(value: &str) -> usize {
    2 + value.len()
}

impl Packet {
    pub(crate) fn encode(&self, buf: &mut BytesMut) {
        match self {
            Packet::Connect(connect) => encode_connect(connect, buf),
            Packet::ConnAck {
                session_present,
                code,
            } => {
                buf.put_u8(CONNACK);
                put_remaining_length(buf, 2);
                buf.put_u8(u8::from(*session_present));
                buf.put_u8(*code);
            }
            Packet::Publish(publish) => {
                let mut len = str_len(&publish.topic) + publish.payload.len();
                if publish.qos > 0 {
                    len += 2;
                }
                buf.put_u8(PUBLISH | (publish.qos << 1));
                put_remaining_length(buf, len);
                put_str(buf, &publish.topic);
                if publish.qos > 0 {
                    buf.put_u16(publish.pkid);
                }
                buf.put_slice(&publish.payload);
            }
            Packet::PubAck(pkid) => {
                buf.put_u8(PUBACK);
                put_remaining_length(buf, 2);
                buf.put_u16(*pkid);
            }
            Packet::Subscribe { pkid, filters } => {
                let len = 2 + filters
                    .iter()
                    .map(|(filter, _)| str_len(filter) + 1)
                    .sum::<usize>();
                buf.put_u8(SUBSCRIBE);
                put_remaining_length(buf, len);
                buf.put_u16(*pkid);
                for (filter, qos) in filters {
                    put_str(buf, filter);
                    buf.put_u8(*qos);
                }
            }
            Packet::SubAck { pkid, codes } => {
                buf.put_u8(SUBACK);
                put_remaining_length(buf, 2 + codes.len());
                buf.put_u16(*pkid);
                buf.put_slice(codes);
            }
            Packet::PingReq => buf.put_slice(&[PINGREQ, 0]),
            Packet::PingResp => buf.put_slice(&[PINGRESP, 0]),
            Packet::Disconnect => buf.put_slice(&[DISCONNECT, 0]),
            Packet::Other(kind) => buf.put_slice(&[*kind << 4, 0]),
        }
    }

    /// Decodes one packet from the front of `buf`, or returns `None` when the
    /// buffer does not hold a complete packet yet.
    pub(crate) fn decode(
        buf: &mut BytesMut,
        max_size: usize,
    ) -> Result<Option<Packet>, CodecError> {
        let Some((header_len, remaining)) = peek_header(buf)? else {
            return Ok(None);
        };
        if remaining > max_size {
            return Err(CodecError::PacketTooLarge(remaining, max_size));
        }
        if buf.len() < header_len + remaining {
            return Ok(None);
        }
        let first = buf[0];
        buf.advance(header_len);
        let body = buf.split_to(remaining).freeze();
        decode_body(first, body).map(Some)
    }
}

fn encode_connect(connect: &Connect, buf: &mut BytesMut) {
    let mut flags = 0u8;
    let mut len = str_len("MQTT") + 1 + 1 + 2 + str_len(&connect.client_id);
    if connect.clean_session {
        flags |= 0x02;
    }
    if let Some(will) = &connect.last_will {
        flags |= 0x04 | (will.qos << 3);
        len += str_len(&will.topic) + 2 + will.payload.len();
    }
    if let Some(username) = &connect.username {
        flags |= 0x80;
        len += str_len(username);
    }
    if let Some(password) = &connect.password {
        flags |= 0x40;
        len += str_len(password);
    }

    buf.put_u8(CONNECT);
    put_remaining_length(buf, len);
    put_str(buf, "MQTT");
    buf.put_u8(4);
    buf.put_u8(flags);
    buf.put_u16(connect.keep_alive_secs);
    put_str(buf, &connect.client_id);
    if let Some(will) = &connect.last_will {
        put_str(buf, &will.topic);
        put_bytes(buf, &will.payload);
    }
    if let Some(username) = &connect.username {
        put_str(buf, username);
    }
    if let Some(password) = &connect.password {
        put_str(buf, password);
    }
}

fn peek_header(buf: &[u8]) -> Result<Option<(usize, usize)>, CodecError> {
    let mut remaining = 0usize;
    let mut multiplier = 1usize;
    for (index, byte) in buf.iter().skip(1).take(4).enumerate() {
        remaining += usize::from(byte & 0x7F) * multiplier;
        if byte & 0x80 == 0 {
            return Ok(Some((index + 2, remaining)));
        }
        multiplier *= 128;
    }
    if buf.len() >= 5 {
        return Err(CodecError::MalformedLength);
    }
    Ok(None)
}

fn take_u16(body: &mut Bytes) -> Result<u16, CodecError> {
    if body.remaining() < 2 {
        return Err(CodecError::Malformed("truncated u16"));
    }
    Ok(body.get_u16())
}

fn take_bytes(body: &mut Bytes) -> Result<Bytes, CodecError> {
    let len = usize::from(take_u16(body)?);
    if body.remaining() < len {
        return Err(CodecError::Malformed("truncated string"));
    }
    Ok(body.split_to(len))
}

fn take_str(body: &mut Bytes) -> Result<String, CodecError> {
    String::from_utf8(take_bytes(body)?.to_vec())
        .map_err(|_| CodecError::Malformed("invalid utf-8"))
}

fn take_u8(body: &mut Bytes) -> Result<u8, CodecError> {
    if !body.has_remaining() {
        return Err(CodecError::Malformed("truncated u8"));
    }
    Ok(body.get_u8())
}

fn decode_body(first: u8, mut body: Bytes) -> Result<Packet, CodecError> {
    match first >> 4 {
        1 => decode_connect(body),
        2 => {
            let session_present = take_u8(&mut body)? & 0x01 != 0;
            let code = take_u8(&mut body)?;
            Ok(Packet::ConnAck {
                session_present,
                code,
            })
        }
        3 => {
            let qos = (first >> 1) & 0x03;
            if qos > 2 {
                return Err(CodecError::Malformed("invalid publish qos"));
            }
            let topic = take_str(&mut body)?;
            let pkid = if qos > 0 { take_u16(&mut body)? } else { 0 };
            Ok(Packet::Publish(Publish {
                topic,
                qos,
                pkid,
                payload: body,
            }))
        }
        4 => Ok(Packet::PubAck(take_u16(&mut body)?)),
        8 => {
            let pkid = take_u16(&mut body)?;
            let mut filters = Vec::new();
            while body.has_remaining() {
                let filter = take_str(&mut body)?;
                filters.push((filter, take_u8(&mut body)?));
            }
            Ok(Packet::Subscribe { pkid, filters })
        }
        9 => {
            let pkid = take_u16(&mut body)?;
            Ok(Packet::SubAck {
                pkid,
                codes: body.to_vec(),
            })
        }
        12 => Ok(Packet::PingReq),
        13 => Ok(Packet::PingResp),
        14 => Ok(Packet::Disconnect),
        kind => Ok(Packet::Other(kind)),
    }
}

fn decode_connect(mut body: Bytes) -> Result<Packet, CodecError> {
    if take_str(&mut body)? != "MQTT" || take_u8(&mut body)? != 4 {
        return Err(CodecError::Malformed("unsupported protocol"));
    }
    let flags = take_u8(&mut body)?;
    let keep_alive_secs = take_u16(&mut body)?;
    let client_id = take_str(&mut body)?;
    let last_will = if flags & 0x04 != 0 {
        Some(LastWill {
            topic: take_str(&mut body)?,
            payload: take_bytes(&mut body)?,
            qos: (flags >> 3) & 0x03,
        })
    } else {
        None
    };
    let username = if flags & 0x80 != 0 {
        Some(take_str(&mut body)?)
    } else {
        None
    };
    let password = if flags & 0x40 != 0 {
        Some(take_str(&mut body)?)
    } else {
        None
    };
    Ok(Packet::Connect(Connect {
        client_id,
        keep_alive_secs,
        clean_session: flags & 0x02 != 0,
        username,
        password,
        last_will,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip(packet: Packet) {
        let mut buf = BytesMut::new();
        packet.encode(&mut buf);
        let mut partial = BytesMut::from(&buf[..buf.len() - 1]);
        assert_eq!(Packet::decode(&mut partial, 1 << 20).unwrap(), None);
        let decoded = Packet::decode(&mut buf, 1 << 20).unwrap().unwrap();
        assert_eq!(decoded, packet);
        assert!(buf.is_empty());
    }

    #[test]
    fn packets_round_trip() {
        round_trip(Packet::Connect(Connect {
            client_id: "et-client".to_owned(),
            keep_alive_secs: 30,
            clean_session: true,
            username: Some("user".to_owned()),
            password: Some("pass".to_owned()),
            last_will: Some(LastWill {
                topic: "et/c/1".to_owned(),
                payload: Bytes::from_static(b"bye"),
                qos: 1,
            }),
        }));
        round_trip(Packet::ConnAck {
            session_present: false,
            code: 0,
        });
        round_trip(Packet::Publish(Publish {
            topic: "et/d/abc".to_owned(),
            qos: 1,
            pkid: 7,
            payload: Bytes::from(vec![0xAB; 300]),
        }));
        round_trip(Packet::Publish(Publish {
            topic: "et/d/abc".to_owned(),
            qos: 0,
            pkid: 0,
            payload: Bytes::from_static(b"x"),
        }));
        round_trip(Packet::PubAck(9));
        round_trip(Packet::Subscribe {
            pkid: 1,
            filters: vec![("et/c/+".to_owned(), 1), ("et/d/x/+".to_owned(), 0)],
        });
        round_trip(Packet::SubAck {
            pkid: 1,
            codes: vec![1, 0x80],
        });
        round_trip(Packet::PingReq);
        round_trip(Packet::PingResp);
        round_trip(Packet::Disconnect);
    }

    #[test]
    fn rejects_oversized_and_malformed_packets() {
        let mut buf = BytesMut::new();
        Packet::Publish(Publish {
            topic: "t".to_owned(),
            qos: 0,
            pkid: 0,
            payload: Bytes::from(vec![0; 1000]),
        })
        .encode(&mut buf);
        assert!(matches!(
            Packet::decode(&mut buf, 100),
            Err(CodecError::PacketTooLarge(_, 100))
        ));

        let mut buf = BytesMut::from(&[0x30, 0xFF, 0xFF, 0xFF, 0xFF, 0x01][..]);
        assert_eq!(
            Packet::decode(&mut buf, usize::MAX),
            Err(CodecError::MalformedLength)
        );
    }
}
