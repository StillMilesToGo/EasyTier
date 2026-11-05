package host

import internalhost "github.com/easytier/easytier/easytier-go/internal/host"

// P2PPolicy controls when an instance attempts peer-to-peer connections.
type P2PPolicy = internalhost.P2PPolicy

// HolePunchingPolicy selects the hole-punching methods available to an instance.
type HolePunchingPolicy = internalhost.HolePunchingPolicy

// PortForwardProtocol identifies the transport used by a port-forward rule.
type PortForwardProtocol = internalhost.PortForwardProtocol

const (
	PortForwardTCP PortForwardProtocol = internalhost.PortForwardTCP
	PortForwardUDP PortForwardProtocol = internalhost.PortForwardUDP
)

// ProxyProtocolVersion selects the PROXY protocol header a TCP port forward
// sends to its destination. The zero value sends no header.
type ProxyProtocolVersion = internalhost.ProxyProtocolVersion

const (
	ProxyProtocolNone ProxyProtocolVersion = internalhost.ProxyProtocolNone
	ProxyProtocolV1   ProxyProtocolVersion = internalhost.ProxyProtocolV1
	ProxyProtocolV2   ProxyProtocolVersion = internalhost.ProxyProtocolV2
)

// PortForwardConfig exposes a host socket through the EasyTier data plane.
type PortForwardConfig = internalhost.PortForwardConfig

// InstanceConfig is an immutable EasyTier instance configuration.
type InstanceConfig = internalhost.InstanceConfig

// InstanceConfigBuilder builds a validated InstanceConfig.
type InstanceConfigBuilder = internalhost.InstanceConfigBuilder

// NewInstanceConfigBuilder starts a configuration for networkName.
func NewInstanceConfigBuilder(networkName string) *InstanceConfigBuilder {
	return internalhost.NewInstanceConfigBuilder(networkName)
}
