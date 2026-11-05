//go:build integration && !linux

package firewall

import (
	"fmt"
	"os/exec"
	"strings"
)

// rawCopyPlanter reports that no backend on this platform keeps a raw-iptables side
// store: the csf/apf pre-hook and ufw's before.rules are Linux-only constructs. The
// shared suite skips its raw-copy probe on a nil result. See the Linux implementation
// in integration_linux_test.go.
func rawCopyPlanter(mgr Manager) func(*Rule) error {
	return nil
}

// foreignSeeder returns a function seeding a foreign rule for the backend, or nil
// when this platform has no seeder for it; the shared suite skips its foreignrule
// probe on a nil result. pf seeds a rule into an anchor of its own, standing in
// for an operator's anchor outside the library's. Seeding wf (netsh advfirewall)
// the same way is still open.
func foreignSeeder(mgr Manager) func(zone string) (*foreignSeed, error) {
	if mgr.Type() != PFType {
		return nil
	}
	return func(string) (*foreignSeed, error) {
		const anchor = "foreignseed"
		undo := func() { _ = exec.Command("pfctl", "-a", anchor, "-F", "rules").Run() }
		cmd := exec.Command("pfctl", "-a", anchor, "-f", "-")
		cmd.Stdin = strings.NewReader("pass in quick inet proto tcp from 192.0.2.10 to any port 8100:8200\n")
		if out, err := cmd.CombinedOutput(); err != nil {
			undo()
			return nil, fmt.Errorf("pfctl -a %s -f -: %v: %s", anchor, err, out)
		}
		return &foreignSeed{
			rule:    &Rule{Family: IPv4, Source: "192.0.2.10", Proto: TCP, Ports: []PortRange{{Start: 8100, End: 8200}}, Action: Accept},
			inScope: false, // pf reports other anchors but writes only to its own.
			narrow:  &Rule{Family: IPv4, Source: "192.0.2.10", Proto: TCP, Port: 8123, Action: Accept},
			undo:    undo,
		}, nil
	}
}

// foreignNATSeeder returns a function seeding an rdr rule into a pf anchor of its
// own, or nil when this platform has no NAT seeder for the backend.
func foreignNATSeeder(mgr Manager) func() (*foreignNATSeed, error) {
	if mgr.Type() != PFType {
		return nil
	}
	return func() (*foreignNATSeed, error) {
		const anchor = "foreignnatseed"
		undo := func() { _ = exec.Command("pfctl", "-a", anchor, "-F", "nat").Run() }
		cmd := exec.Command("pfctl", "-a", anchor, "-f", "-")
		cmd.Stdin = strings.NewReader("rdr inet proto tcp from any to any port 8124 -> 192.0.2.20 port 80\n")
		if out, err := cmd.CombinedOutput(); err != nil {
			undo()
			return nil, fmt.Errorf("pfctl -a %s -f -: %v: %s", anchor, err, out)
		}
		return &foreignNATSeed{
			rule: &NATRule{Kind: DNAT, Family: IPv4, Proto: TCP, Port: 8124, ToAddress: "192.0.2.20", ToPort: 80},
			undo: undo,
		}, nil
	}
}

// foreignMACSeeder reports no MAC zone-source seeder on this platform: the MAC
// source is a firewalld construct and firewalld is Linux-only.
func foreignMACSeeder(mgr Manager) func(zone string) (*foreignSeed, error) {
	return nil
}

// foreignProtocolSeeder reports no zone protocol-entry seeder on this platform,
// for the same reason as foreignMACSeeder.
func foreignProtocolSeeder(mgr Manager) func(zone string) (*foreignSeed, error) {
	return nil
}

// unmanagedRawRuleSeeder reports no unmanaged raw rules file on this platform:
// the before/after split is a ufw construct and ufw is Linux-only.
func unmanagedRawRuleSeeder(mgr Manager) func() (*Rule, func(), error) {
	return nil
}

// zoneInterfaceSeeder reports no interface-to-zone seeder on this platform: the
// interface binding is a firewalld construct and firewalld is Linux-only.
func zoneInterfaceSeeder(mgr Manager) func(iface, zoneName string) (func(), error) {
	return nil
}
