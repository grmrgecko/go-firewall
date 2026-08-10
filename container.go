package firewall

import (
	"net"
	"regexp"
	"strings"
)

// Container runtimes and CNI plugins do not merely add firewall rules, they own
// and continuously reconcile them: dockerd, podman/netavark, kube-proxy and the
// CNI plugins each rewrite their rules on daemon start, network create and
// container start. Rewriting or deleting one of those rules severs live container
// networking for services the consumer never asked this library to touch, and the
// owning daemon reinstates it on its own schedule, so the change does not even
// hold. Every read path therefore treats such a rule as out of scope: it never
// reaches a caller, so it never enters a desired set, and the file-rewrite paths
// preserve its line verbatim.
//
// This is not the ownership filter the package deliberately avoids. The library
// still manages foreign rules — a hand-written system rule is reconciled like any
// other. The distinction is a live, self-reconciling owner, not authorship.

// containerRuntimeIfaces names interfaces a container runtime or CNI plugin
// creates and manages. A rule matching on one of these is that runtime's.
var containerRuntimeIfaces = map[string]bool{
	// Docker.
	"docker0":         true,
	"docker_gwbridge": true,
	// Podman.
	"cni-podman0": true,
	// Kubernetes CNI plugins.
	"cni0":         true,
	"flannel.1":    true,
	"tunl0":        true,
	"vxlan.calico": true,
	"cilium_host":  true,
	"cilium_net":   true,
	"cilium_vxlan": true,
	"weave":        true,
	"kube-bridge":  true,
	"kube-ipvs0":   true,
	"nodelocaldns": true,
}

// containerRuntimeIfacePrefixes names interface prefixes a container runtime or
// CNI plugin allocates per network or per container, where the suffix is a
// generated index or identifier.
var containerRuntimeIfacePrefixes = []string{
	"podman", // podman0, podman1, ... per podman network.
	"cali",   // Calico's per-workload interfaces; matches its own `cali+` rules.
	"lxc",    // Cilium's per-endpoint interfaces, and LXC's container interfaces.
}

// dockerBridgeRe matches the bridge Docker creates for a user-defined network:
// "br-" followed by the first 12 hex digits of the network ID. The pattern is
// deliberately exact rather than a "br-" prefix so an operator's own bridge —
// br-lan, br-wan, br-100 — is still managed normally.
var dockerBridgeRe = regexp.MustCompile(`^br-[0-9a-f]{12}$`)

// isDockerBridge reports whether name is a bridge Docker generated for a
// user-defined network. Beyond the name pattern it requires at least one numeral,
// which rules out a hand-named bridge that happens to be spelled in hex letters
// (br-deadbeefcafe) while costing Docker nothing: a network ID is random hex, so
// the odds of its first 12 digits holding no numeral are about 1 in 195,000.
//
// This stays a heuristic. A bridge renamed through the network's
// com.docker.network.bridge.name option is not detectable by name at all, and a
// bridge deliberately named as 12 hex digits including a numeral is a false
// positive. Both are accepted: the pattern covers the default every
// docker compose project produces, which is the case that actually occurs.
func isDockerBridge(name string) bool {
	return dockerBridgeRe.MatchString(name) && strings.ContainsAny(name, "0123456789")
}

// containerRuntimeChains names the iptables/nftables chains a container runtime
// or CNI plugin creates and reconciles. A trailing "-" or "_" marks a prefix
// whose remainder is generated (a network name, a service hash, an index).
var containerRuntimeChains = []string{
	// Docker: DOCKER itself, plus DOCKER-USER, DOCKER-INGRESS, DOCKER-ISOLATION-*
	// and the DOCKER-FORWARD/BRIDGE/CT/INTERNAL set Docker 28 introduced.
	"DOCKER", "DOCKER-",
	// Podman: netavark, and the CNI stack older releases used.
	"NETAVARK", "NETAVARK_", "NETAVARK-", "CNI-",
	// Kubernetes kube-proxy and kubelet.
	"KUBE-",
	// CNI plugins.
	"CALI-", "cali-", "CILIUM_", "FLANNEL-", "WEAVE", "WEAVE-",
}

// containerRuntimeTables names the nftables tables a container runtime or CNI
// plugin owns outright. Every rule in one of these is the runtime's, whatever
// chain it sits in — Docker's native nftables backend, for example, uses generic
// chain names (filter-forward-in, nat-postrouting-out) that carry no marker of
// their own.
var containerRuntimeTables = map[string]bool{
	"docker-bridges": true, // dockerd with firewall-backend=nftables.
	"netavark":       true, // podman/netavark.
	"kube-proxy":     true,
	"kube-router":    true,
	"calico":         true,
	"cilium":         true,
}

// isContainerRuntimeIface reports whether name is an interface a container
// runtime or CNI plugin manages.
func isContainerRuntimeIface(name string) bool {
	if name == "" {
		return false
	}
	// An interface match may be negated; the underlying name still identifies the
	// runtime, and a negated match is just as much its rule.
	name = strings.TrimPrefix(name, "!")
	name = strings.TrimSpace(name)
	if containerRuntimeIfaces[name] {
		return true
	}
	if isDockerBridge(name) {
		return true
	}
	// An iptables interface match may carry a trailing "+" wildcard (cali+).
	bare := strings.TrimSuffix(name, "+")
	for _, p := range containerRuntimeIfacePrefixes {
		if strings.HasPrefix(bare, p) {
			return true
		}
	}
	return false
}

// isContainerRuntimeChain reports whether name is a chain a container runtime or
// CNI plugin creates and reconciles.
func isContainerRuntimeChain(name string) bool {
	if name == "" {
		return false
	}
	for _, c := range containerRuntimeChains {
		// A generated-suffix entry matches by prefix; an exact entry must match whole
		// so a user chain merely starting with one is still managed.
		if strings.HasSuffix(c, "-") || strings.HasSuffix(c, "_") {
			if strings.HasPrefix(name, c) {
				return true
			}
			continue
		}
		if name == c {
			return true
		}
	}
	return false
}

// isContainerRuntimeTable reports whether an nftables table is one a container
// runtime or CNI plugin owns outright. It accepts either a bare table name or the
// "family name" form the ruleset listing produces (e.g. "ip docker-bridges").
func isContainerRuntimeTable(name string) bool {
	if name == "" {
		return false
	}
	if i := strings.LastIndex(name, " "); i >= 0 {
		name = name[i+1:]
	}
	return containerRuntimeTables[name]
}

// isContainerRuntime reports whether the rule belongs to a container runtime or
// CNI plugin, by the interfaces it matches on. Chain and table membership are
// checked by the backends that can see them, before a rule is ever built.
func (r *Rule) isContainerRuntime() bool {
	if r == nil {
		return false
	}
	return isContainerRuntimeIface(r.InInterface) || isContainerRuntimeIface(r.OutInterface)
}

// isHairpinMasquerade reports whether the NAT rule is a container runtime's
// hairpin (loopback) masquerade: the row Docker and podman add per published port
// so a container reaching its own published address is NATed back to itself. It
// carries no interface match, so it is the one container NAT rule the interface
// signal cannot see, and it is identified by its shape instead — a masquerade
// whose source and destination are the same single host. Nothing else generates
// that: masquerading a host's traffic to itself is meaningless outside a
// port-publishing loopback.
func (r *NATRule) isHairpinMasquerade() bool {
	if r.Kind != Masquerade || r.Source == "" || !addrEqual(r.Source, r.Destination) {
		return false
	}
	// canonAddr collapses a host prefix (/32, /128) onto the bare address, so a
	// source that canonicalizes back to a plain IP is a single host, not a network.
	// A masquerade of a whole subnet onto itself is not the hairpin shape.
	c, ok := canonAddr(r.Source)
	return ok && net.ParseIP(strings.TrimPrefix(c, "!")) != nil
}

// isContainerRuntime reports whether the NAT rule belongs to a container runtime
// or CNI plugin. It is the NATRule counterpart of Rule.isContainerRuntime.
func (r *NATRule) isContainerRuntime() bool {
	if r == nil {
		return false
	}
	return isContainerRuntimeIface(r.Interface) || r.isHairpinMasquerade()
}
