//go:build integration

package firewall

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// linuxBackends lists every Linux backend in the same order NewManager probes them.
func linuxBackends() []backendFactory {
	return []backendFactory{
		{"firewalld", func(ctx context.Context, p string) (Manager, error) { return NewFirewallD(ctx, p) }},
		{"ufw", func(ctx context.Context, p string) (Manager, error) { return NewUFW(ctx, p) }},
		{"csf", func(ctx context.Context, p string) (Manager, error) { return NewCSF(ctx, p) }},
		{"apf", func(ctx context.Context, p string) (Manager, error) { return NewAPF(ctx, p) }},
		{"iptables", func(ctx context.Context, p string) (Manager, error) { return NewIPTables(ctx, p) }},
		{"nft", func(ctx context.Context, p string) (Manager, error) { return NewNFT(ctx, p) }},
	}
}

// TestIntegration runs the capability-driven suite against the Linux backends.
// See integration_test.go for the shared suite and runIntegration.
func TestIntegration(t *testing.T) {
	runIntegration(t, linuxBackends())
}

// rawCopyPlanter returns a function that writes a rule directly into the backend's
// raw-iptables side store — the csf/apf pre-hook, ufw's before.rules — standing in
// for a copy a customer added by hand, or nil when the backend keeps no such store.
// It lives here rather than in the shared suite because it names the Linux-only
// backend types, which do not compile for the pf and Windows targets.
func rawCopyPlanter(mgr Manager) func(*Rule) error {
	switch b := mgr.(type) {
	case *APF:
		return func(r *Rule) error { _, err := b.hook().edit(r, false); return err }
	case *CSF:
		return func(r *Rule) error { _, err := b.hook().edit(r, false); return err }
	case *UFW:
		return func(r *Rule) error { return b.editIPTablesRules(r, false) }
	}
	return nil
}

// foreignSeeder returns a function seeding a foreign rule with the backend's own
// tooling, or nil when the backend has no seeder on this platform. The seeding
// commands/paths are inherently backend-specific; the assertions in the shared
// foreignrule subtest are not.
func foreignSeeder(mgr Manager) func(zone string) (*foreignSeed, error) {
	switch mgr.Type() {
	case IPTablesType:
		// The iptables backend manages the persistent save files (rules.v4 /
		// rules.v6), so the operator-style seed is a hand-edited save-file line,
		// not a live `iptables -A` (which the file model deliberately never sees).
		ipt, ok := mgr.(*IPTables)
		if !ok {
			return nil
		}
		return func(string) (*foreignSeed, error) {
			undo, err := insertSaveFileRule(ipt.IP4Path, "-A INPUT -p tcp --dport 8123 -j ACCEPT")
			if err != nil {
				return nil, err
			}
			return &foreignSeed{
				rule:    &Rule{Family: IPv4, Proto: TCP, Port: 8123, Action: Accept},
				inScope: true,
				undo:    undo,
			}, nil
		}
	case NFTType:
		return func(string) (*foreignSeed, error) {
			const table = "foreignseed"
			// The seed carries an address match on purpose: an ip table is its own
			// family qualifier, so the row states no nfproto and the reader must take
			// the family from the table or the network-header offsets are ambiguous
			// and the whole row reads back as an opaque slot.
			cmds := [][]string{
				{"add", "table", "ip", table},
				{"add", "chain", "ip", table, "input", "{", "type", "filter", "hook", "input", "priority", "0", ";", "policy", "accept", ";", "}"},
				{"add", "rule", "ip", table, "input", "ip", "saddr", "192.0.2.10", "tcp", "dport", "8100-8200", "accept"},
			}
			for _, c := range cmds {
				if out, err := exec.Command("nft", c...).CombinedOutput(); err != nil {
					_ = exec.Command("nft", "delete", "table", "ip", table).Run()
					return nil, fmt.Errorf("nft %s: %v: %s", strings.Join(c, " "), err, out)
				}
			}
			return &foreignSeed{
				rule:    &Rule{Family: IPv4, Source: "192.0.2.10", Proto: TCP, Ports: []PortRange{{Start: 8100, End: 8200}}, Action: Accept},
				inScope: false, // nft reports foreign tables but writes only to its own.
				narrow:  &Rule{Family: IPv4, Source: "192.0.2.10", Proto: TCP, Port: 8123, Action: Accept},
				undo:    func() { _ = exec.Command("nft", "delete", "table", "ip", table).Run() },
			}, nil
		}
	case UFWType:
		return func(string) (*foreignSeed, error) {
			if out, err := exec.Command("ufw", "allow", "8123/tcp").CombinedOutput(); err != nil {
				return nil, fmt.Errorf("ufw: %v: %s", err, out)
			}
			return &foreignSeed{
				rule:    &Rule{Proto: TCP, Port: 8123, Action: Accept},
				inScope: true,
				undo:    func() { _ = exec.Command("ufw", "--force", "delete", "allow", "8123/tcp").Run() },
			}, nil
		}
	case FirewallDType:
		return func(zone string) (*foreignSeed, error) {
			if out, err := exec.Command("firewall-cmd", "--permanent", "--zone="+zone, "--add-port=8123/tcp").CombinedOutput(); err != nil {
				return nil, fmt.Errorf("firewall-cmd: %v: %s", err, out)
			}
			return &foreignSeed{
				rule: &Rule{Proto: TCP, Port: 8123, Action: Accept},
				// firewalld's container is the zone itself, so every rule read from
				// it — foreign included — carries the informational flag.
				hasPrefix: true,
				inScope:   true,
				undo: func() {
					_ = exec.Command("firewall-cmd", "--permanent", "--zone="+zone, "--remove-port=8123/tcp").Run()
				},
			}, nil
		}
	case CSFType:
		return func(string) (*foreignSeed, error) {
			undo, err := appendConfigLine(CSFAllow, "198.51.100.99")
			if err != nil {
				return nil, err
			}
			return &foreignSeed{
				rule:    &Rule{Direction: DirAny, Family: IPv4, Source: "198.51.100.99", Action: Accept},
				inScope: true,
				undo:    undo,
			}, nil
		}
	case APFType:
		return func(string) (*foreignSeed, error) {
			undo, err := appendConfigLine(APFAllow, "198.51.100.99")
			if err != nil {
				return nil, err
			}
			return &foreignSeed{
				rule:    &Rule{Direction: DirAny, Family: IPv4, Source: "198.51.100.99", Action: Accept},
				inScope: true,
				undo:    undo,
			}, nil
		}
	}
	return nil
}

// foreignNATSeeder returns a function seeding a DNAT rule into a foreign nftables
// table, or nil for every other Linux backend: only nft reports NAT rules from
// outside the tables it writes to.
func foreignNATSeeder(mgr Manager) func() (*foreignNATSeed, error) {
	if mgr.Type() != NFTType {
		return nil
	}
	return func() (*foreignNATSeed, error) {
		const table = "foreignnatseed"
		undo := func() { _ = exec.Command("nft", "delete", "table", "ip", table).Run() }
		cmds := [][]string{
			{"add", "table", "ip", table},
			{"add", "chain", "ip", table, "prerouting", "{", "type", "nat", "hook", "prerouting", "priority", "-100", ";", "}"},
			{"add", "rule", "ip", table, "prerouting", "tcp", "dport", "8124", "dnat", "to", "192.0.2.20:80"},
		}
		for _, c := range cmds {
			if out, err := exec.Command("nft", c...).CombinedOutput(); err != nil {
				undo()
				return nil, fmt.Errorf("nft %s: %v: %s", strings.Join(c, " "), err, out)
			}
		}
		return &foreignNATSeed{
			rule: &NATRule{Kind: DNAT, Family: IPv4, Proto: TCP, Port: 8124, ToAddress: "192.0.2.20", ToPort: 80},
			undo: undo,
		}, nil
	}
}

// foreignMACSeeder returns a function seeding a foreign MAC zone source with the
// backend's own tooling, or nil when the backend has no MAC-source construct on
// this platform. Only firewalld models one (a zone source) and only firewall-cmd
// can seed it; the assertions in the shared foreignmacsource subtest are not
// backend-specific.
func foreignMACSeeder(mgr Manager) func(zone string) (*foreignSeed, error) {
	if mgr.Type() != FirewallDType {
		return nil
	}
	return func(zone string) (*foreignSeed, error) {
		const mac = "00:11:22:33:44:55"
		if out, err := exec.Command("firewall-cmd", "--permanent", "--zone="+zone, "--add-source="+mac).CombinedOutput(); err != nil {
			return nil, fmt.Errorf("firewall-cmd: %v: %s", err, out)
		}
		return &foreignSeed{
			rule:      &Rule{Source: mac, Action: Accept},
			hasPrefix: true,
			inScope:   true,
			undo: func() {
				_ = exec.Command("firewall-cmd", "--permanent", "--zone="+zone, "--remove-source="+mac).Run()
			},
		}, nil
	}
}

// foreignProtocolSeeder returns a function seeding a foreign bare-protocol allow
// with the backend's own tooling, or nil when the backend has no distinct
// protocol-entry construct on this platform. Only firewalld stores one (a zone
// protocol entry, distinct from the rich-rule form the library writes).
func foreignProtocolSeeder(mgr Manager) func(zone string) (*foreignSeed, error) {
	if mgr.Type() != FirewallDType {
		return nil
	}
	return func(zone string) (*foreignSeed, error) {
		const proto = "gre"
		if out, err := exec.Command("firewall-cmd", "--permanent", "--zone="+zone, "--add-protocol="+proto).CombinedOutput(); err != nil {
			return nil, fmt.Errorf("firewall-cmd: %v: %s", err, out)
		}
		return &foreignSeed{
			rule:      &Rule{Proto: GRE, Action: Accept},
			hasPrefix: true,
			inScope:   true,
			undo: func() {
				_ = exec.Command("firewall-cmd", "--permanent", "--zone="+zone, "--remove-protocol="+proto).Run()
			},
		}, nil
	}
}

// unmanagedRawRuleSeeder returns a function injecting a parseable rule into a
// raw rules file the backend deliberately does not manage, or nil when the
// backend keeps no such file on this platform. Only ufw has the before/after
// split: the library writes raw rules into before.rules only, so a rule seeded
// into after.rules must stay invisible to GetRules. The returned probe is what
// the seeded line would read back as if it were (wrongly) surfaced.
func unmanagedRawRuleSeeder(mgr Manager) func() (*Rule, func(), error) {
	if mgr.Type() != UFWType {
		return nil
	}
	return func() (*Rule, func(), error) {
		const afterPath = "/etc/ufw/after.rules"
		orig, err := os.ReadFile(afterPath)
		if err != nil {
			return nil, nil, err
		}
		// Inject before the real COMMIT directive. after.rules carries a "# don't
		// delete the 'COMMIT' line" comment, so match the standalone COMMIT line
		// rather than the first literal.
		lines := strings.Split(string(orig), "\n")
		placed := false
		for i, l := range lines {
			if strings.TrimSpace(l) == "COMMIT" {
				lines = append(lines[:i:i], append([]string{"-A ufw-after-input -p tcp -m tcp --dport 8765 -j ACCEPT"}, lines[i:]...)...)
				placed = true
				break
			}
		}
		if !placed {
			return nil, nil, fmt.Errorf("%s has no COMMIT directive to inject before", afterPath)
		}
		if err := os.WriteFile(afterPath, []byte(strings.Join(lines, "\n")), 0o640); err != nil {
			return nil, nil, err
		}
		probe := &Rule{Family: IPv4, Proto: TCP, Port: 8765, Action: Accept}
		return probe, func() { _ = os.WriteFile(afterPath, orig, 0o640) }, nil
	}
}

// zoneInterfaceSeeder returns a function binding an interface to a named zone
// out of band (permanent config only, so nothing filters at runtime), or nil
// when the backend has no interface-to-zone mapping on this platform. Only
// firewalld models one and only firewall-cmd can seed it; the assertions in the
// shared zones subtest are not backend-specific.
func zoneInterfaceSeeder(mgr Manager) func(iface, zoneName string) (func(), error) {
	if mgr.Type() != FirewallDType {
		return nil
	}
	return func(iface, zoneName string) (func(), error) {
		if out, err := exec.Command("firewall-cmd", "--permanent", "--zone="+zoneName, "--add-interface="+iface).CombinedOutput(); err != nil {
			return nil, fmt.Errorf("firewall-cmd: %v: %s", err, out)
		}
		return func() {
			_ = exec.Command("firewall-cmd", "--permanent", "--zone="+zoneName, "--remove-interface="+iface).Run()
		}, nil
	}
}

// insertSaveFileRule inserts one iptables-save rule line into path's *filter
// section, before its COMMIT, returning an undo that restores the original
// content byte for byte.
func insertSaveFileRule(path, line string) (func(), error) {
	orig, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	lines := strings.Split(string(orig), "\n")
	inFilter, placed := false, false
	for i, l := range lines {
		trimmed := strings.TrimSpace(l)
		if strings.HasPrefix(trimmed, "*") {
			inFilter = trimmed == "*filter"
			continue
		}
		if inFilter && trimmed == "COMMIT" {
			lines = append(lines[:i:i], append([]string{line}, lines[i:]...)...)
			placed = true
			break
		}
	}
	if !placed {
		return nil, fmt.Errorf("%s has no *filter COMMIT to insert before", path)
	}
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")), 0o600); err != nil {
		return nil, err
	}
	return func() { _ = os.WriteFile(path, orig, 0o600) }, nil
}

// appendConfigLine appends one line to a config file, returning an undo that
// restores the original content byte for byte.
func appendConfigLine(path, line string) (func(), error) {
	orig, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	content := string(orig)
	if content != "" && !strings.HasSuffix(content, "\n") {
		content += "\n"
	}
	// The file exists, so WriteFile keeps its mode; the permission argument only
	// applies on create.
	if err := os.WriteFile(path, []byte(content+line+"\n"), 0o600); err != nil {
		return nil, err
	}
	return func() { _ = os.WriteFile(path, orig, 0o600) }, nil
}
