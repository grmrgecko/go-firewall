//go:build integration && !linux

package firewall

// rawCopyPlanter reports that no backend on this platform keeps a raw-iptables side
// store: the csf/apf pre-hook and ufw's before.rules are Linux-only constructs. The
// shared suite skips its raw-copy probe on a nil result. See the Linux implementation
// in integration_linux_test.go.
func rawCopyPlanter(mgr Manager) func(*Rule) error {
	return nil
}

// foreignSeeder reports no out-of-band foreign-rule seeder on this platform; the
// Linux implementation in integration_linux_test.go covers the Linux backends.
// The shared suite skips its foreignrule probe on a nil result. Seeding pf (pfctl
// anchors) and wf (netsh advfirewall) the same way is still open.
func foreignSeeder(mgr Manager) func(zone string) (*foreignSeed, error) {
	return nil
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
