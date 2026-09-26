use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};

use bytes::BytesMut;
use easytier_core::socket::{
    SocketContext, SocketListener,
    tcp::{VirtualTcpSocket, VirtualTcpSplit},
};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::{TcpListener, TcpStream},
    sync::mpsc,
    task::JoinSet,
};

use super::{
    codec::{LastWill, Packet, Publish},
    *,
};

fn topic_matches(filter: &str, topic: &str) -> bool {
    let mut filter = filter.split('/');
    let mut topic = topic.split('/');
    loop {
        match (filter.next(), topic.next()) {
            (Some("#"), _) => return true,
            (Some("+"), Some(_)) => {}
            (Some(level), Some(name)) if level == name => {}
            (None, None) => return true,
            _ => return false,
        }
    }
}

struct BrokerClient {
    id: u64,
    filters: Vec<(String, u8)>,
    tx: mpsc::UnboundedSender<Packet>,
}

#[derive(Default)]
struct BrokerState {
    clients: Vec<BrokerClient>,
    next_id: u64,
}

impl BrokerState {
    fn route(&self, publish: &Publish) {
        for client in &self.clients {
            if let Some((_, qos)) = client
                .filters
                .iter()
                .find(|(filter, _)| topic_matches(filter, &publish.topic))
            {
                let qos = publish.qos.min(*qos);
                let _ = client.tx.send(Packet::Publish(Publish {
                    qos,
                    pkid: if qos > 0 { 1 } else { 0 },
                    ..publish.clone()
                }));
            }
        }
    }
}

/// A just-enough MQTT 3.1.1 broker for exercising the transport in tests.
struct TestBroker {
    addr: SocketAddr,
    tasks: JoinSet<()>,
}

impl TestBroker {
    async fn start() -> Self {
        Self::start_on(SocketAddr::from(([127, 0, 0, 1], 0))).await
    }

    async fn start_on(addr: SocketAddr) -> Self {
        let listener = TcpListener::bind(addr).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let state = Arc::new(Mutex::new(BrokerState::default()));
        let mut tasks = JoinSet::new();
        tasks.spawn(async move {
            let mut clients = JoinSet::new();
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                clients.spawn(serve_broker_client(stream, state.clone()));
            }
        });
        Self { addr, tasks }
    }

    fn url(&self, path: &str) -> url::Url {
        format!("mqtt://{}/{path}", self.addr).parse().unwrap()
    }

    fn stop(mut self) {
        self.tasks.abort_all();
    }
}

async fn serve_broker_client(stream: TcpStream, state: Arc<Mutex<BrokerState>>) {
    let (mut reader, mut writer) = stream.into_split();
    let (tx, mut rx) = mpsc::unbounded_channel::<Packet>();
    let id = {
        let mut state = state.lock().unwrap();
        state.next_id += 1;
        let id = state.next_id;
        state.clients.push(BrokerClient {
            id,
            filters: Vec::new(),
            tx: tx.clone(),
        });
        id
    };
    let write = async move {
        while let Some(packet) = rx.recv().await {
            let mut buf = BytesMut::new();
            packet.encode(&mut buf);
            if writer.write_all(&buf).await.is_err() {
                break;
            }
        }
    };
    let mut will: Option<LastWill> = None;
    let read = async {
        let mut buf = BytesMut::new();
        loop {
            while let Some(packet) = Packet::decode(&mut buf, 1 << 20).unwrap() {
                match packet {
                    Packet::Connect(connect) => {
                        will = connect.last_will;
                        let _ = tx.send(Packet::ConnAck {
                            session_present: false,
                            code: 0,
                        });
                    }
                    Packet::Subscribe { pkid, filters } => {
                        let codes = filters.iter().map(|(_, qos)| *qos).collect();
                        let mut state = state.lock().unwrap();
                        let client = state.clients.iter_mut().find(|c| c.id == id).unwrap();
                        client.filters.extend(filters);
                        let _ = tx.send(Packet::SubAck { pkid, codes });
                    }
                    Packet::Publish(publish) => {
                        if publish.qos > 0 {
                            let _ = tx.send(Packet::PubAck(publish.pkid));
                        }
                        state.lock().unwrap().route(&publish);
                    }
                    Packet::PingReq => {
                        let _ = tx.send(Packet::PingResp);
                    }
                    Packet::Disconnect => {
                        will = None;
                        return;
                    }
                    _ => {}
                }
            }
            if reader.read_buf(&mut buf).await.unwrap_or(0) == 0 {
                return;
            }
        }
    };
    tokio::select! {
        _ = read => {}
        _ = write => {}
    }
    let mut state = state.lock().unwrap();
    state.clients.retain(|client| client.id != id);
    if let Some(will) = will {
        state.route(&Publish {
            topic: will.topic,
            qos: will.qos,
            pkid: 0,
            payload: will.payload,
        });
    }
}

async fn start_listener(url: &url::Url) -> MqttListener {
    let mut listener = MqttListener::new(url.clone(), SocketContext::default());
    listener.listen().await.unwrap();
    listener
}

async fn accept_stream(listener: &mut MqttListener) -> VirtualTcpSplit {
    let accepted = tokio::time::timeout(Duration::from_secs(10), listener.accept())
        .await
        .expect("accept timed out")
        .unwrap();
    let AcceptedTransport::ByteStream {
        socket, local_url, ..
    } = accepted
    else {
        panic!("mqtt listener must accept byte streams");
    };
    assert_eq!(local_url.password(), None);
    socket.into_split()
}

/// Retries while the listener is still subscribing, as the peer connector would.
async fn connect_stream(url: &url::Url) -> VirtualTcpSplit {
    for _ in 0..20 {
        if let Ok(connected) = connect(url).await {
            let (socket, _, remote_url, _) = connected.into_parts();
            assert_eq!(remote_url.password(), None);
            return socket.into_split();
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    panic!("could not connect to mqtt listener");
}

#[test]
fn parses_endpoint_urls() {
    let endpoint = MqttEndpoint::parse(
        &"mqtts://user%40x:p%3Ass@broker.example/home/et/?qos=0&keepalive=60&insecure=true"
            .parse()
            .unwrap(),
    )
    .unwrap();
    assert!(endpoint.tls);
    assert_eq!(endpoint.default_port(), 8883);
    assert_eq!(endpoint.topic, "home/et");
    assert_eq!(endpoint.username.as_deref(), Some("user@x"));
    assert_eq!(endpoint.password.as_deref(), Some("p:ss"));
    assert_eq!(endpoint.qos, 0);
    assert_eq!(endpoint.keep_alive, Duration::from_secs(60));
    assert!(endpoint.insecure);
    assert_eq!(endpoint.public_url.password(), None);
    assert_eq!(endpoint.public_url.username(), "user%40x");

    let endpoint = MqttEndpoint::parse(&"mqtt://broker/et".parse().unwrap()).unwrap();
    assert_eq!((endpoint.default_port(), endpoint.qos), (1883, 1));

    for invalid in [
        "mqtt://broker",
        "mqtt://broker/",
        "mqtt://broker/a/+/b",
        "mqtt://broker/a/#",
        "mqtt://broker/a/%23",
        "mqtt://broker/et?qos=2",
        "mqtt://broker/et?keepalive=1",
        "mqtt://broker/et?unknown=1",
        "tcp://broker/et",
    ] {
        assert!(
            MqttEndpoint::parse(&invalid.parse().unwrap()).is_err(),
            "{invalid} should be rejected"
        );
    }
}

#[tokio::test]
async fn relays_byte_streams_through_broker() {
    let broker = TestBroker::start().await;
    let url = broker.url("et/relay");
    let mut listener = start_listener(&url).await;

    let (mut client_reader, mut client_writer) = connect_stream(&url).await;
    let (mut server_reader, mut server_writer) = accept_stream(&mut listener).await;

    // Larger than one frame so ordering across many messages is exercised.
    let payload: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
    let sent = payload.clone();
    let writer = tokio::spawn(async move {
        client_writer.write_all(&sent).await.unwrap();
        client_writer
    });
    let mut received = vec![0u8; payload.len()];
    server_reader.read_exact(&mut received).await.unwrap();
    assert_eq!(received, payload);

    server_writer.write_all(b"pong").await.unwrap();
    let mut reply = [0u8; 4];
    client_reader.read_exact(&mut reply).await.unwrap();
    assert_eq!(&reply, b"pong");

    // Closing one end reaches the other as EOF.
    drop(writer.await.unwrap());
    drop(client_reader);
    let mut rest = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), server_reader.read_to_end(&mut rest))
        .await
        .expect("server side should see the session close")
        .unwrap();
    assert!(rest.is_empty());
    broker.stop();
}

#[tokio::test]
async fn qos0_sessions_work() {
    let broker = TestBroker::start().await;
    let url = broker.url("et/qos0?qos=0");
    let mut listener = start_listener(&url).await;
    let (mut client_reader, mut client_writer) = connect_stream(&url).await;
    let (mut server_reader, mut server_writer) = accept_stream(&mut listener).await;

    client_writer.write_all(b"hello").await.unwrap();
    let mut buf = [0u8; 5];
    server_reader.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"hello");
    server_writer.write_all(b"world").await.unwrap();
    client_reader.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"world");
    broker.stop();
}

#[tokio::test]
async fn only_one_listener_serves_a_session() {
    let broker = TestBroker::start().await;
    let url = broker.url("et/shared");
    let mut first = start_listener(&url).await;
    let mut second = start_listener(&url).await;

    let (mut client_reader, mut client_writer) = connect_stream(&url).await;
    client_writer.write_all(b"ping").await.unwrap();

    let (mut server_reader, mut server_writer) = tokio::select! {
        split = accept_stream(&mut first) => split,
        split = accept_stream(&mut second) => split,
    };
    let mut buf = [0u8; 4];
    server_reader.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"ping");
    server_writer.write_all(b"pong").await.unwrap();
    client_reader.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"pong");

    // The other listener never received a session for it.
    let other = tokio::time::timeout(Duration::from_millis(500), async {
        tokio::select! {
            accepted = first.accept() => accepted,
            accepted = second.accept() => accepted,
        }
    })
    .await;
    assert!(
        other.is_err(),
        "a second listener accepted the same session"
    );
    broker.stop();
}

#[tokio::test]
async fn connector_disappearance_closes_listener_session() {
    let broker = TestBroker::start().await;
    let url = broker.url("et/will");
    let mut listener = start_listener(&url).await;
    let client = connect_stream(&url).await;
    let (mut server_reader, _server_writer) = accept_stream(&mut listener).await;

    // Dropping the pipe ends the connector session, which must reach the
    // listener either as FIN or via the last will.
    drop(client);
    let mut rest = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), server_reader.read_to_end(&mut rest))
        .await
        .expect("listener session should close")
        .unwrap();
    broker.stop();
}

#[tokio::test]
async fn listener_survives_broker_restart() {
    let broker = TestBroker::start().await;
    let addr = broker.addr;
    let url = broker.url("et/restart");
    let mut listener = start_listener(&url).await;
    let (_client_reader, _client_writer) = connect_stream(&url).await;
    let (mut server_reader, _server_writer) = accept_stream(&mut listener).await;

    broker.stop();
    let mut rest = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), server_reader.read_to_end(&mut rest))
        .await
        .expect("sessions end with the broker connection")
        .unwrap();

    let broker = TestBroker::start_on(addr).await;
    let (mut client_reader, mut client_writer) = connect_stream(&url).await;
    let (mut server_reader, mut server_writer) = accept_stream(&mut listener).await;
    client_writer.write_all(b"again").await.unwrap();
    let mut buf = [0u8; 5];
    server_reader.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"again");
    server_writer.write_all(b"ok").await.unwrap();
    let mut buf = [0u8; 2];
    client_reader.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"ok");
    broker.stop();
}

#[tokio::test]
async fn connect_fails_without_listener() {
    let broker = TestBroker::start().await;
    let url = broker.url("et/nobody");
    let error = tokio::time::timeout(Duration::from_secs(20), connect(&url))
        .await
        .expect("connect must give up on its own")
        .err()
        .expect("nobody listens on this topic");
    assert!(error.to_string().contains("no mqtt listener"), "{error:?}");
    broker.stop();
}
