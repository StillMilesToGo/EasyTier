use std::{sync::Arc, time::Duration};

use async_trait::async_trait;
use easytier_core::{
    connectivity::{
        protocol::{
            ClientProtocolUpgrader, ServerProtocolAdmission, ServerProtocolUpgrade,
            ServerProtocolUpgrader, raw,
        },
        transport::ConnectedTransport,
    },
    socket::udp::UdpSession,
    tunnel::Tunnel,
};

use crate::{
    common::global_ctx::ArcGlobalCtx,
    socket::tcp::RuntimeTcpSocket,
    tunnel::mqtt::{CONNECT_TIMEOUT, supports_scheme},
};

use super::{ClientAdapter, ServerAdapter};

/// MQTT sessions arrive as host byte streams that are already relayed end to
/// end, so both directions only apply EasyTier's stream framing.
#[derive(Default)]
struct MqttAdapter;

pub(super) fn client_adapter(_global_ctx: &ArcGlobalCtx) -> ClientAdapter {
    Arc::new(MqttAdapter)
}

pub(super) fn server_adapter(_global_ctx: &ArcGlobalCtx) -> ServerAdapter {
    Arc::new(MqttAdapter)
}

#[async_trait]
impl ClientProtocolUpgrader<RuntimeTcpSocket> for MqttAdapter {
    fn supports_scheme(&self, scheme: &str) -> bool {
        supports_scheme(scheme)
    }

    fn connect_timeout(&self, scheme: &str) -> Option<Duration> {
        supports_scheme(scheme).then_some(CONNECT_TIMEOUT)
    }

    async fn upgrade_client(
        &self,
        connected: ConnectedTransport<RuntimeTcpSocket>,
        _requested_url: url::Url,
    ) -> anyhow::Result<Box<dyn Tunnel>> {
        let ConnectedTransport::ByteStream(stream) = connected else {
            anyhow::bail!("MQTT protocol requires a host-created byte stream");
        };
        Ok(raw::upgrade_connected_byte_stream(stream)?)
    }
}

#[async_trait]
impl ServerProtocolUpgrader<RuntimeTcpSocket> for MqttAdapter {
    fn supports_scheme(&self, scheme: &str) -> bool {
        supports_scheme(scheme)
    }

    async fn upgrade_tcp(
        &self,
        _socket: RuntimeTcpSocket,
        _local_url: url::Url,
    ) -> anyhow::Result<ServerProtocolUpgrade> {
        anyhow::bail!("MQTT protocol requires a byte stream")
    }

    async fn upgrade_udp(
        &self,
        _session: UdpSession,
        _local_url: url::Url,
        _admission: Option<ServerProtocolAdmission>,
    ) -> anyhow::Result<ServerProtocolUpgrade> {
        anyhow::bail!("MQTT protocol requires a byte stream")
    }

    async fn upgrade_byte_stream(
        &self,
        socket: RuntimeTcpSocket,
        local_url: url::Url,
        remote_url: Option<url::Url>,
    ) -> anyhow::Result<ServerProtocolUpgrade> {
        Ok(ServerProtocolUpgrade::Tunnel(
            raw::upgrade_accepted_byte_stream(socket, local_url, remote_url)?,
        ))
    }
}
