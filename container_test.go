package firewall

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// The detector must catch every interface a container runtime allocates without
// swallowing an operator's own interfaces, which are managed normally. The
// br-<12 hex> case is the sharp edge: Docker's generated bridges must match while
// a hand-named br-lan must not.
func TestIsContainerRuntimeIface(t *testing.T) {
	runtime := []string{
		"docker0", "docker_gwbridge", "br-1a2b3c4d5e6f",
		"podman0", "podman1", "cni-podman0",
		"cni0", "flannel.1", "cilium_host", "weave", "kube-ipvs0",
		"cali1234567890a", "lxc00aa",
		"!docker0", "cali+", // Negated and wildcard forms still identify the runtime.
	}
	for _, name := range runtime {
		require.True(t, isContainerRuntimeIface(name), "%q must be detected as a container-runtime interface", name)
	}

	operator := []string{
		"", "eth0", "ens3", "wlan0", "bridge0",
		"br-1a2b3c4d5e6",  // Too short for a Docker network ID.
		"br-1A2B3C4D5E6F", // Docker lowercases its hex; an uppercase name is not its.
		"dockerish0",      // Not an interface Docker creates.
		// An operator's bridge that happens to be 12 hex characters. A generated
		// network ID practically always carries a numeral, so requiring one keeps
		// names spelled in hex letters managed.
		"br-deadbeefcafe", "br-cafedecadeff",
		"br-1a2b3c4d5e6f7", // One character too long for a network ID.
		"br-lan", "br-wan", "br-100", "vmbr0", "virbr0", "lxdbr0",
		// A veth pair is not a container-runtime signal on its own: systemd-nspawn,
		// libvirt and hand-built netns setups all use them, and a runtime's own rules
		// match the bridge rather than the container-side leg.
		"veth1a2b3c", "vethwe-bridge",
		"tun0", "wg0", "bond0", "lo",
	}
	for _, name := range operator {
		require.False(t, isContainerRuntimeIface(name), "%q is the operator's interface and must stay managed", name)
	}
}

func TestIsContainerRuntimeChain(t *testing.T) {
	runtime := []string{
		"DOCKER", "DOCKER-USER", "DOCKER-ISOLATION-STAGE-1", "DOCKER-INGRESS",
		"DOCKER-FORWARD", "DOCKER-BRIDGE", "DOCKER-CT", "DOCKER-INTERNAL",
		"NETAVARK_FORWARD", "NETAVARK-ISOLATION-2", "NETAVARK-HOSTPORT-DNAT",
		"CNI-FORWARD", "CNI-ADMIN",
		"KUBE-SERVICES", "KUBE-NODEPORTS", "KUBE-FIREWALL",
		"CALI-INPUT", "cali-fw-cali123", "CILIUM_POST_mangle", "FLANNEL-FWD", "WEAVE",
	}
	for _, name := range runtime {
		require.True(t, isContainerRuntimeChain(name), "%q must be detected as a container-runtime chain", name)
	}

	operator := []string{"", "INPUT", "OUTPUT", "FORWARD", "ufw-user-input", "f2b-sshd", "DOCKERISH"}
	for _, name := range operator {
		require.False(t, isContainerRuntimeChain(name), "%q must stay managed", name)
	}
}

// Docker's native nftables backend names its chains generically
// (filter-forward-in, nat-postrouting-out), so the table name is the only signal.
// The listing form carries the family, which must be tolerated.
func TestIsContainerRuntimeTable(t *testing.T) {
	for _, name := range []string{"docker-bridges", "ip docker-bridges", "ip6 docker-bridges", "inet netavark", "ip kube-proxy"} {
		require.True(t, isContainerRuntimeTable(name), "%q must be detected as a container-runtime table", name)
	}
	for _, name := range []string{"", "inet filter", "ip nat", "inet go-firewall", "filter"} {
		require.False(t, isContainerRuntimeTable(name), "%q must stay managed", name)
	}
}

// Docker and podman add a hairpin masquerade per published port, and it carries
// no interface match, so shape is the only signal. It must not swallow an
// operator's ordinary masquerade or a whole-subnet self-masquerade.
func TestIsHairpinMasquerade(t *testing.T) {
	hairpin := []*NATRule{
		{Kind: Masquerade, Source: "172.17.0.2/32", Destination: "172.17.0.2/32", Proto: TCP, Port: 80},
		{Kind: Masquerade, Source: "10.89.0.4", Destination: "10.89.0.4/32", Proto: UDP, Port: 53},
		{Kind: Masquerade, Source: "fd00::2/128", Destination: "fd00::2/128", Proto: TCP, Port: 443},
	}
	for _, r := range hairpin {
		require.True(t, r.isContainerRuntime(), "hairpin masquerade %s must be out of scope", r.Source)
	}

	managed := []*NATRule{
		{Kind: Masquerade, Interface: "eth0"},                                 // Ordinary egress NAT.
		{Kind: Masquerade, Source: "10.0.0.0/24", Destination: "10.0.0.0/24"}, // A subnet, not a host.
		{Kind: Masquerade, Source: "10.0.0.5/32", Destination: "10.0.0.6/32"}, // Different hosts.
		{Kind: Masquerade, Source: "10.0.0.5/32"},                             // No destination.
		{Kind: SNAT, Source: "10.0.0.5/32", Destination: "10.0.0.5/32", ToAddress: "203.0.113.1"},
		{Kind: DNAT, Destination: "203.0.113.1/32", ToAddress: "10.0.0.5"},
	}
	for _, r := range managed {
		require.False(t, r.isContainerRuntime(), "%+v is the operator's NAT rule and must stay managed", *r)
	}
}
