//! PROXY protocol (HAProxy) header encoding for TCP port forwards.
//!
//! See <https://www.haproxy.org/download/2.9/doc/proxy-protocol.txt>.

use std::net::{IpAddr, Ipv6Addr, SocketAddr};

use crate::config::gateway::ProxyProtocolVersion;

const V2_SIGNATURE: [u8; 12] = [
    0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
];
/// Protocol version 2, PROXY command.
const V2_VERSION_PROXY: u8 = 0x21;
const V2_TCP_OVER_IPV4: u8 = 0x11;
const V2_TCP_OVER_IPV6: u8 = 0x21;

/// Address pair carried by the header. Both sides share one address family:
/// a mixed pair is promoted to IPv6 with IPv4-mapped addresses.
enum AddressPair {
    V4 {
        source: SocketAddr,
        destination: SocketAddr,
    },
    V6 {
        source: (Ipv6Addr, u16),
        destination: (Ipv6Addr, u16),
    },
}

impl AddressPair {
    fn new(source: SocketAddr, destination: SocketAddr) -> Self {
        let source = SocketAddr::new(source.ip().to_canonical(), source.port());
        let destination = SocketAddr::new(destination.ip().to_canonical(), destination.port());
        match (source.ip(), destination.ip()) {
            (IpAddr::V4(_), IpAddr::V4(_)) => Self::V4 {
                source,
                destination,
            },
            _ => Self::V6 {
                source: (to_ipv6(source.ip()), source.port()),
                destination: (to_ipv6(destination.ip()), destination.port()),
            },
        }
    }
}

fn to_ipv6(ip: IpAddr) -> Ipv6Addr {
    match ip {
        IpAddr::V4(ip) => ip.to_ipv6_mapped(),
        IpAddr::V6(ip) => ip,
    }
}

/// Encodes the header announcing that `source` connected to `destination`.
pub(super) fn encode_header(
    version: ProxyProtocolVersion,
    source: SocketAddr,
    destination: SocketAddr,
) -> Vec<u8> {
    let addresses = AddressPair::new(source, destination);
    match version {
        ProxyProtocolVersion::V1 => encode_v1(&addresses),
        ProxyProtocolVersion::V2 => encode_v2(&addresses),
    }
}

fn encode_v1(addresses: &AddressPair) -> Vec<u8> {
    let line = match addresses {
        AddressPair::V4 {
            source,
            destination,
        } => format!(
            "PROXY TCP4 {} {} {} {}\r\n",
            source.ip(),
            destination.ip(),
            source.port(),
            destination.port()
        ),
        AddressPair::V6 {
            source,
            destination,
        } => format!(
            "PROXY TCP6 {} {} {} {}\r\n",
            source.0, destination.0, source.1, destination.1
        ),
    };
    line.into_bytes()
}

fn encode_v2(addresses: &AddressPair) -> Vec<u8> {
    let mut header = Vec::with_capacity(16 + 36);
    header.extend_from_slice(&V2_SIGNATURE);
    header.push(V2_VERSION_PROXY);
    match addresses {
        AddressPair::V4 {
            source,
            destination,
        } => {
            let (IpAddr::V4(source_ip), IpAddr::V4(destination_ip)) =
                (source.ip(), destination.ip())
            else {
                unreachable!("V4 address pair holds IPv4 addresses");
            };
            header.push(V2_TCP_OVER_IPV4);
            header.extend_from_slice(&12u16.to_be_bytes());
            header.extend_from_slice(&source_ip.octets());
            header.extend_from_slice(&destination_ip.octets());
            header.extend_from_slice(&source.port().to_be_bytes());
            header.extend_from_slice(&destination.port().to_be_bytes());
        }
        AddressPair::V6 {
            source,
            destination,
        } => {
            header.push(V2_TCP_OVER_IPV6);
            header.extend_from_slice(&36u16.to_be_bytes());
            header.extend_from_slice(&source.0.octets());
            header.extend_from_slice(&destination.0.octets());
            header.extend_from_slice(&source.1.to_be_bytes());
            header.extend_from_slice(&destination.1.to_be_bytes());
        }
    }
    header
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(value: &str) -> SocketAddr {
        value.parse().unwrap()
    }

    #[test]
    fn v1_ipv4_header() {
        let header = encode_header(
            ProxyProtocolVersion::V1,
            addr("192.168.1.10:51234"),
            addr("10.0.0.1:8080"),
        );
        assert_eq!(header, b"PROXY TCP4 192.168.1.10 10.0.0.1 51234 8080\r\n");
    }

    #[test]
    fn v1_ipv6_header() {
        let header = encode_header(
            ProxyProtocolVersion::V1,
            addr("[2001:db8::1]:51234"),
            addr("[2001:db8::2]:443"),
        );
        assert_eq!(header, b"PROXY TCP6 2001:db8::1 2001:db8::2 51234 443\r\n");
    }

    #[test]
    fn v1_mixed_families_promote_to_mapped_ipv6() {
        let header = encode_header(
            ProxyProtocolVersion::V1,
            addr("192.168.1.10:51234"),
            addr("[2001:db8::2]:443"),
        );
        assert_eq!(
            header,
            b"PROXY TCP6 ::ffff:192.168.1.10 2001:db8::2 51234 443\r\n"
        );
    }

    #[test]
    fn v1_mapped_ipv4_pair_stays_ipv4() {
        let header = encode_header(
            ProxyProtocolVersion::V1,
            addr("[::ffff:192.168.1.10]:51234"),
            addr("[::ffff:10.0.0.1]:8080"),
        );
        assert_eq!(header, b"PROXY TCP4 192.168.1.10 10.0.0.1 51234 8080\r\n");
    }

    #[test]
    fn v2_ipv4_header() {
        let header = encode_header(
            ProxyProtocolVersion::V2,
            addr("192.168.1.10:51234"),
            addr("10.0.0.1:8080"),
        );
        let mut expected = V2_SIGNATURE.to_vec();
        expected.extend_from_slice(&[0x21, 0x11, 0x00, 0x0C]);
        expected.extend_from_slice(&[192, 168, 1, 10, 10, 0, 0, 1]);
        expected.extend_from_slice(&51234u16.to_be_bytes());
        expected.extend_from_slice(&8080u16.to_be_bytes());
        assert_eq!(header, expected);
    }

    #[test]
    fn v2_ipv6_header() {
        let source = addr("[2001:db8::1]:51234");
        let destination = addr("[2001:db8::2]:443");
        let header = encode_header(ProxyProtocolVersion::V2, source, destination);
        assert_eq!(header.len(), 16 + 36);
        assert_eq!(&header[..12], &V2_SIGNATURE);
        assert_eq!(&header[12..16], &[0x21, 0x21, 0x00, 0x24]);
        assert_eq!(
            &header[16..32],
            &"2001:db8::1".parse::<Ipv6Addr>().unwrap().octets()
        );
        assert_eq!(
            &header[32..48],
            &"2001:db8::2".parse::<Ipv6Addr>().unwrap().octets()
        );
        assert_eq!(&header[48..50], &51234u16.to_be_bytes());
        assert_eq!(&header[50..52], &443u16.to_be_bytes());
    }
}
