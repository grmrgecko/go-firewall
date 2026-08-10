package firewall

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
)

func TestIPTablesRules(t *testing.T) {
	fw := new(IPTables)

	// Parse a rule that is expected to parse right.
	rule, err := fw.UnmarshalRule(`-A INPUT -s 192.168.0.0/24 -p udp -m udp --dport 23 -j ACCEPT`, IPv4)
	require.NoError(t, err)

	// Re-encode the rule which should result in expected rich rule.
	richRule, err := fw.MarshalRule(rule)
	require.NoError(t, err)
	require.Equal(t, `-A INPUT -s 192.168.0.0/24 -p udp -m udp --dport 23 -j ACCEPT`, richRule,
		"the rich rule did not encode as expected")

	// Try encoding a bunch of invalid rules.
	invalidRules := []string{
		`-A TEST -s 192.168.0.0/24 -j DROP`,
		`-s 192.168.0.0/24 -p udp -m udp --dport 23 -j ACCEPT`,
		`-A INPUT -s 192.168.0.0/24 -p udp -m udp --dport 23`,
		`-A INPUT -s 192.168.0.0/24 -p udp -m udp --dport 23 -j MARK`,
		`-A INPUT -s 192.168.0.0/24 -p tcp -m udp --dport 23 -j DROP`,
	}
	for _, richRule := range invalidRules {
		_, err := fw.UnmarshalRule(richRule, IPv4)
		require.Error(t, err, "this rich rule was parsed when it should be invalid: %s", richRule)
	}

	// Test rules we typically set.
	validRules := []string{
		`-A INPUT -p udp -m udp --dport 4789 -j ACCEPT`,
		`-A OUTPUT -p udp -m udp --dport 4789 -j ACCEPT`,
		`-A INPUT -s 203.0.113.10 -p tcp -m tcp --dport 4789 -j ACCEPT`,
		`-A OUTPUT -d 203.0.113.10 -p tcp -m tcp --dport 4791 -j ACCEPT`,
	}
	for _, richRule := range validRules {
		_, err := fw.UnmarshalRule(richRule, IPv4)
		require.NoError(t, err, "this rich rule was not parsed when it should be valid: %s", richRule)
	}

	// A port without a concrete protocol cannot be expressed in iptables
	// (`-m tcp/udp --dport` is invalid without `-p tcp/udp`), so validateRule
	// must reject it before the encoder emits an invalid rule.
	require.Error(t, fw.validateRule(&Rule{Port: 80, Proto: ProtocolAny, Action: Accept}),
		"expected a port with no protocol to be rejected")
}

func TestIPTablesFeatureRules(t *testing.T) {
	fw := new(IPTables)

	// Confirm representative encodings.
	cases := []struct {
		rule *Rule
		want string
	}{
		{&Rule{Proto: ICMP, Action: Reject}, "-A INPUT -p icmp -j REJECT"},
		{&Rule{Proto: ICMPv6, Action: Accept}, "-A INPUT -p icmpv6 -j ACCEPT"},
		{&Rule{Proto: ICMP, ICMPType: Ptr[uint8](8), Action: Accept}, "-A INPUT -p icmp -m icmp --icmp-type 8 -j ACCEPT"},
		{&Rule{Family: IPv6, Proto: ICMPv6, ICMPType: Ptr[uint8](128), Action: Accept}, "-A INPUT -p icmpv6 -m icmp6 --icmpv6-type 128 -j ACCEPT"},
		{&Rule{Proto: TCP, Ports: []PortRange{{Start: 80}, {Start: 443}}, Action: Accept}, "-A INPUT -p tcp -m multiport --dports 80,443 -j ACCEPT"},
		{&Rule{Proto: UDP, Ports: []PortRange{{Start: 1000, End: 2000}}, Action: Accept}, "-A INPUT -p udp -m multiport --dports 1000:2000 -j ACCEPT"},
		{&Rule{Proto: TCP, Port: 22, State: StateNew | StateEstablished, Action: Accept}, "-A INPUT -p tcp -m tcp --dport 22 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT"},
		{&Rule{InInterface: "eth0", Proto: TCP, Port: 22, Action: Accept}, "-A INPUT -i eth0 -p tcp -m tcp --dport 22 -j ACCEPT"},
		{&Rule{Direction: DirOutput, OutInterface: "eth1", Action: Drop}, "-A OUTPUT -o eth1 -j DROP"},
	}
	for _, c := range cases {
		got, err := fw.MarshalRule(c.rule)
		require.NoError(t, err, "failed to marshal %+v", *c.rule)
		require.Equal(t, c.want, got, "marshal %+v", *c.rule)
	}

	// Round-trip every new-feature rule shape.
	rules := []*Rule{
		{Proto: TCP, Ports: []PortRange{{Start: 80}, {Start: 443}, {Start: 8000, End: 8100}}, Action: Accept},
		{Proto: UDP, Ports: []PortRange{{Start: 1000, End: 2000}}, Action: Accept},
		{Proto: TCP, Port: 22, State: StateEstablished | StateRelated, Action: Accept},
		{Source: "10.0.0.0/8", Proto: TCP, Port: 22, State: StateNew, Action: Accept},
		{InInterface: "eth0", Proto: TCP, Port: 22, Action: Accept},
		{Direction: DirOutput, OutInterface: "eth1", Proto: UDP, Port: 53, Action: Accept},
		{Proto: ICMP, Action: Accept},
		{Proto: ICMPv6, Action: Accept},
		{Proto: ICMP, ICMPType: Ptr[uint8](8), Action: Accept},
		{Family: IPv6, Proto: ICMPv6, ICMPType: Ptr[uint8](135), Action: Accept},
	}
	for _, r := range rules {
		spec, err := fw.MarshalRule(r)
		require.NoError(t, err, "failed to marshal %+v", *r)

		parsed, err := fw.UnmarshalRule(spec, r.Family)
		require.NoError(t, err, "failed to parse %q", spec)
		require.True(t, parsed.Equal(r, true),
			"round-trip mismatch: input %+v, spec %q, output %+v", *r, spec, parsed)
	}

	// Bare `--icmp-type <name>` and `--dport`/`--sport` (without an explicit `-m`),
	// as used in ufw's iptables rules files, must parse.
	icmpRule, err := fw.UnmarshalRule("-A INPUT -p icmp --icmp-type echo-request -j ACCEPT", IPv4)
	require.NoError(t, err)
	require.Equal(t, ICMP, icmpRule.Proto, "unexpected bare icmp-type parse: %+v", *icmpRule)
	require.NotNil(t, icmpRule.ICMPType, "unexpected bare icmp-type parse: %+v", *icmpRule)
	require.EqualValues(t, 8, *icmpRule.ICMPType, "unexpected bare icmp-type parse: %+v", *icmpRule)

	dportRule, err := fw.UnmarshalRule("-A INPUT -p udp --dport 5353 -j ACCEPT", IPv4)
	require.NoError(t, err)
	require.Equal(t, UDP, dportRule.Proto, "unexpected bare dport parse: %+v", *dportRule)
	require.EqualValues(t, 5353, dportRule.Port, "unexpected bare dport parse: %+v", *dportRule)

	sportRule, err := fw.UnmarshalRule("-A INPUT -p tcp --sport 1234 -j ACCEPT", IPv4)
	require.NoError(t, err)
	require.Equal(t, TCP, sportRule.Proto, "unexpected bare sport parse: %+v", *sportRule)
	require.EqualValues(t, 1234, sportRule.SourcePort, "unexpected bare sport parse: %+v", *sportRule)

	// The legacy `-m state --state` match must also parse.
	r, err := fw.UnmarshalRule("-A INPUT -p tcp -m tcp --dport 22 -m state --state NEW,ESTABLISHED -j ACCEPT", IPv4)
	require.NoError(t, err)
	require.Equal(t, StateNew|StateEstablished, r.State, "unexpected state parse")
}

// An iptables-save line may carry a leading [pkts:bytes] counter prefix; the
// parser must capture it onto the rule and keep parsing the rest of the line.
func TestIPTablesCounterPrefix(t *testing.T) {
	fw := new(IPTables)
	r, err := fw.UnmarshalRule("[42:3360] -A INPUT -p tcp -m tcp --dport 22 -j ACCEPT", IPv4)
	require.NoError(t, err)
	require.Equal(t, uint64(42), r.Packets, "packet counter not captured")
	require.Equal(t, uint64(3360), r.Bytes, "byte counter not captured")
	require.True(t, r.EqualBase(&Rule{Family: IPv4, Proto: TCP, Port: 22, Action: Accept}, true),
		"counters must not be part of rule identity: %+v", r)

	// A line without a counter prefix still parses, with zero counters.
	r2, err := fw.UnmarshalRule("-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT", IPv4)
	require.NoError(t, err)
	require.Zero(t, r2.Packets)
	require.Zero(t, r2.Bytes)
}

// A nat rule in the OUTPUT chain (locally-generated DNAT) cannot be represented
// distinctly by the NATRule model, so it must be treated as foreign: skipped on
// read (never surfaced as a PREROUTING DNAT) and preserved verbatim by
// rewriteNATRules (never relocated to PREROUTING or dropped on Restore).
func TestIPTablesNATOutputChainPreserved(t *testing.T) {
	// UnmarshalNATRule rejects an OUTPUT-chain rule so natRulesInFile skips it.
	f := new(IPTables)
	_, err := f.UnmarshalNATRule("-A OUTPUT -p tcp -m tcp --dport 81 -j DNAT --to-destination 10.0.0.6", IPv4)
	require.Error(t, err, "an OUTPUT-chain nat rule must not be surfaced as a managed NAT rule")

	dir := t.TempDir()
	p4 := filepath.Join(dir, "iptables")
	save := "*nat\n" +
		":PREROUTING ACCEPT [0:0]\n:INPUT ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\n:POSTROUTING ACCEPT [0:0]\n" +
		"-A PREROUTING -p tcp -m tcp --dport 80 -j DNAT --to-destination 10.0.0.5\n" +
		"-A OUTPUT -p tcp -m tcp --dport 81 -j DNAT --to-destination 10.0.0.6\n" +
		"COMMIT\n"
	require.NoError(t, os.WriteFile(p4, []byte(save), 0644))
	fw := &IPTables{IP4Path: p4, IP6Path: filepath.Join(dir, "ip6tables")}

	// GetNATRules-side read surfaces only the PREROUTING rule; the OUTPUT rule is skipped.
	got, err := fw.natRulesInFile(p4)
	require.NoError(t, err)
	require.Len(t, got, 1, "only the PREROUTING nat rule should be surfaced, not the OUTPUT one")
	require.EqualValues(t, 80, got[0].Port)

	// Restore-side rewrite replaces the managed (PREROUTING) rules but preserves the
	// foreign OUTPUT rule verbatim.
	require.NoError(t, fw.rewriteNATRules(p4, []string{"-A PREROUTING -p tcp -m tcp --dport 90 -j DNAT --to-destination 10.0.0.9"}))
	data, err := os.ReadFile(p4)
	require.NoError(t, err)
	require.Contains(t, string(data), "-A OUTPUT -p tcp -m tcp --dport 81 -j DNAT --to-destination 10.0.0.6",
		"the OUTPUT nat rule must be preserved verbatim, not relocated or dropped")
	require.Contains(t, string(data), "--dport 90", "the rewritten PREROUTING rule must be present")
	require.NotContains(t, string(data), "--dport 80", "the old managed PREROUTING rule must be replaced")
}

// TestIPTablesAddRulePreservesUnmodeledRule verifies an additive AddRule keeps a
// pre-existing INPUT/OUTPUT rule the parser cannot model (here an -m recent
// rate-limit rule). GetRules cannot represent such a rule, so a rewrite that
// dropped it would silently delete a foreign rule the read-modify-write add must
// keep.
func TestIPTablesAddRulePreservesUnmodeledRule(t *testing.T) {
	dir := t.TempDir()
	p4 := filepath.Join(dir, "iptables")
	p6 := filepath.Join(dir, "ip6tables")
	recent := "-A INPUT -p tcp -m tcp --dport 22 -m recent --update --seconds 60 --hitcount 4 -j DROP"
	orphanLog := "-A INPUT -p udp -m udp --dport 53 -j LOG --log-prefix \"dns: \""
	save := "*filter\n:INPUT ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\n:FORWARD ACCEPT [0:0]\n" +
		recent + "\n" +
		"-A INPUT -p tcp -m tcp --dport 80 -j ACCEPT\n" +
		orphanLog + "\n" +
		"-A FORWARD -p tcp -m tcp --dport 8080 -j ACCEPT\n" +
		"COMMIT\n"
	require.NoError(t, os.WriteFile(p4, []byte(save), 0644))
	require.NoError(t, os.WriteFile(p6, []byte("*filter\n:INPUT ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\n:FORWARD ACCEPT [0:0]\nCOMMIT\n"), 0644))
	fw := &IPTables{IP4Path: p4, IP6Path: p6}
	ctx := context.Background()

	// The -m recent rule and the orphan LOG are not modeled, so GetRules cannot see
	// them; only the two modeled rules surface: the INPUT dport 80 and the FORWARD
	// dport 8080, the forward chain being modeled too.
	rules, err := fw.GetRules(ctx, "")
	require.NoError(t, err)
	require.Len(t, rules, 2, "only the two modeled rules should surface")

	// Additively add a new rule.
	require.NoError(t, fw.AddRule(ctx, "", &Rule{Family: IPv4, Proto: TCP, Port: 443, Action: Accept}))

	data, err := os.ReadFile(p4)
	require.NoError(t, err)
	got := string(data)
	require.Contains(t, got, recent, "the foreign -m recent rule must be preserved by an additive add")
	require.Contains(t, got, orphanLog, "the standalone LOG rule must be preserved")
	require.Contains(t, got, "-A FORWARD -p tcp -m tcp --dport 8080 -j ACCEPT", "the FORWARD rule must be preserved")
	require.Contains(t, got, "--dport 443", "the newly added rule must be present")
	require.Contains(t, got, "--dport 80", "the pre-existing modeled rule must be preserved")
}

// A comment containing a backslash, an embedded double-quote or a non-ASCII
// rune must round-trip byte-for-byte: strconv.Quote (the previous encoding)
// renders these as Go string-literal escapes that shlex.Split — the parser
// GetRules reads such a line back with — does not interpret, so the comment
// came back mangled (e.g. a literal tab as a two-character "\t") and never
// compared equal to the desired rule, so Sync churned on it forever.
func TestIPTablesCommentSpecialCharsRoundTrip(t *testing.T) {
	dir := t.TempDir()
	scaffold := "*filter\n:INPUT ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\nCOMMIT\n"
	p4 := filepath.Join(dir, "iptables")
	p6 := filepath.Join(dir, "ip6tables")
	require.NoError(t, os.WriteFile(p4, []byte(scaffold), 0644))
	require.NoError(t, os.WriteFile(p6, []byte(scaffold), 0644))
	fw := &IPTables{IP4Path: p4, IP6Path: p6}
	ctx := context.Background()

	cases := []struct {
		port    uint16
		comment string
	}{
		{22, `back\slash`},
		{23, `quote"inside`},
		{24, "tab\ttab"},
		{25, "unicode ключ"},
	}
	for _, c := range cases {
		require.NoError(t, fw.AddRule(ctx, "", &Rule{Family: IPv4, Proto: TCP, Port: c.port, Action: Accept, Comment: c.comment}))
	}

	rules, err := fw.GetRules(ctx, "")
	require.NoError(t, err)
	byPort := map[uint16]*Rule{}
	for _, r := range rules {
		byPort[r.Port] = r
	}
	for _, c := range cases {
		require.Equal(t, c.comment, byPort[c.port].Comment, "comment %q must round-trip unchanged", c.comment)
	}

	// A literal newline cannot be expressed (it would split the rules file's
	// one-line-per-rule format), so it is rejected rather than silently mangled.
	err = fw.AddRule(ctx, "", &Rule{Family: IPv4, Proto: TCP, Port: 26, Action: Accept, Comment: "line1\nline2"})
	require.Error(t, err, "a comment containing a newline must be rejected")
}

// A user comment that itself begins with the configured prefix must survive the
// round-trip intact: GetRules strips the prefix exactly once, so a comment of
// "myapp is great" (stored as "myapp myapp is great") must read back whole and
// not be truncated to "is great".
func TestIPTablesCommentBeginningWithPrefix(t *testing.T) {
	dir := t.TempDir()
	scaffold := "*filter\n:INPUT ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\nCOMMIT\n"
	p4 := filepath.Join(dir, "iptables")
	p6 := filepath.Join(dir, "ip6tables")
	require.NoError(t, os.WriteFile(p4, []byte(scaffold), 0644))
	require.NoError(t, os.WriteFile(p6, []byte(scaffold), 0644))
	fw := &IPTables{IP4Path: p4, IP6Path: p6, rulePrefix: "myapp"}
	ctx := context.Background()

	require.NoError(t, fw.AddRule(ctx, "", &Rule{Family: IPv4, Proto: TCP, Port: 8080, Action: Accept, Comment: "myapp is great"}))

	rules, err := fw.GetRules(ctx, "")
	require.NoError(t, err)
	require.Len(t, rules, 1)
	require.Equal(t, "myapp is great", rules[0].Comment, "prefix must be stripped exactly once")
	require.True(t, rules[0].HasPrefix)
}

// A single contiguous port range on a `-m tcp/udp/sctp --dport` — the form
// iptables-save emits and ufw's before.rules use — must parse. The module-match
// handlers must accept the range form, so GetRules reports the rule rather than
// dropping it (and re-adding a duplicate every reconcile).
func TestIPTablesModulePortRangeParse(t *testing.T) {
	cases := []struct {
		spec string
		src  bool
	}{
		{`-A INPUT -p tcp -m tcp --dport 1000:2000 -j ACCEPT`, false},
		{`-A INPUT -p tcp -m tcp --sport 1000:2000 -j ACCEPT`, true},
		{`-A INPUT -p udp -m udp --dport 1000:2000 -j ACCEPT`, false},
		{`-A INPUT -p sctp -m sctp --dport 1000:2000 -j ACCEPT`, false},
	}
	for _, c := range cases {
		r, err := unmarshalIPTablesRule(c.spec, IPv4)
		require.NoError(t, err, "range on module match must parse: %s", c.spec)
		specs := r.PortSpecs()
		if c.src {
			specs = r.SourcePortSpecs()
		}
		require.Equal(t, []PortRange{{Start: 1000, End: 2000}}, specs, "range not captured: %s", c.spec)
	}
}

// iptables applies and prints a default --limit-burst 5 on every -m limit match.
// A rule added with Burst 0 must still compare equal to the one iptables-save
// lists back with burst 5 (mirrors the nft burst-5 normalization).
func TestIPTablesRateBurstDefaultNormalized(t *testing.T) {
	orig := &Rule{Family: IPv4, Proto: TCP, Port: 22, Action: Accept, RateLimit: &RateLimit{Rate: 10, Unit: PerMinute}}
	saved := `-A INPUT -p tcp -m tcp --dport 22 -m limit --limit 10/min --limit-burst 5 -j ACCEPT`
	got, err := unmarshalIPTablesRule(saved, IPv4)
	require.NoError(t, err)
	require.NotNil(t, got.RateLimit)
	require.Equal(t, uint(0), got.RateLimit.Burst, "iptables' default burst of 5 must normalize to the unset 0")
	require.True(t, got.EqualBase(orig, true), "a burst-5 read-back must equal the burst-0 original")
}

// A DNAT rule on SCTP (which carries ports) must round-trip: the `-m sctp
// --dport` match iptables emits must parse back.
func TestIPTablesSCTPNATRoundTrip(t *testing.T) {
	f := &IPTables{rulePrefix: "myapp"}
	orig := &NATRule{Kind: DNAT, Family: IPv4, Proto: SCTP, Port: 132, ToAddress: "10.0.0.5", ToPort: 132}
	spec, err := f.MarshalNATRule(orig)
	require.NoError(t, err)
	got, err := f.UnmarshalNATRule(spec, IPv4)
	require.NoError(t, err)
	require.True(t, orig.EqualBase(got), "sctp nat rule must round-trip; got %+v", got)
}

// iptables labels an ICMPv6 type with an ICMPv6 name, several of which mean a
// different number under ICMPv4 (echo-request is 128 vs 8, destination-unreachable
// is 1 vs 3). The `--icmpv6-type`/`-m icmp6` flags must resolve names through the
// ICMPv6 table, not the ICMPv4 one. Library-written rules emit the number, so the
// round-trip tests never exercised the name path — but ufw's before6.rules do.
func TestIPTablesICMPv6TypeNameParse(t *testing.T) {
	// -m icmp6 module form.
	r, err := unmarshalIPTablesRule("-A INPUT -p ipv6-icmp -m icmp6 --icmpv6-type echo-request -j ACCEPT", IPv6)
	require.NoError(t, err)
	require.NotNil(t, r.ICMPType)
	require.Equal(t, uint8(128), *r.ICMPType, "icmpv6 echo-request is type 128")

	// Bare --icmpv6-type form (no -m icmp6).
	r2, err := unmarshalIPTablesRule("-A INPUT -p ipv6-icmp --icmpv6-type destination-unreachable -j ACCEPT", IPv6)
	require.NoError(t, err)
	require.NotNil(t, r2.ICMPType)
	require.Equal(t, uint8(1), *r2.ICMPType, "icmpv6 destination-unreachable is type 1")

	// The ICMPv4 name path must be unchanged.
	r3, err := unmarshalIPTablesRule("-A INPUT -p icmp --icmp-type echo-request -j ACCEPT", IPv4)
	require.NoError(t, err)
	require.NotNil(t, r3.ICMPType)
	require.Equal(t, uint8(8), *r3.ICMPType, "icmp echo-request is type 8")
}

// GetDefaultPolicy reads both family save files: it returns the shared policy
// when they agree and errors when they diverge, rather than silently reporting
// only the IPv4 policy.
func TestIPTablesGetDefaultPolicyBothFamilies(t *testing.T) {
	dir := t.TempDir()
	write := func(name, in string) string {
		p := filepath.Join(dir, name)
		body := "*filter\n:INPUT " + in + " [0:0]\n:OUTPUT ACCEPT [0:0]\n:FORWARD ACCEPT [0:0]\nCOMMIT\n"
		require.NoError(t, os.WriteFile(p, []byte(body), 0644))
		return p
	}
	ctx := context.Background()

	// Agreement: both files DROP input -> policy reports DROP.
	f := &IPTables{IP4Path: write("iptables", "DROP"), IP6Path: write("ip6tables", "DROP")}
	pol, err := f.GetDefaultPolicy(ctx, "")
	require.NoError(t, err)
	require.Equal(t, Drop, pol.Input)

	// Divergence: v4 ACCEPT, v6 DROP -> error, because there is no single policy.
	f = &IPTables{IP4Path: write("iptables2", "ACCEPT"), IP6Path: write("ip6tables2", "DROP")}
	_, err = f.GetDefaultPolicy(ctx, "")
	require.Error(t, err, "a v4/v6 policy mismatch must be surfaced, not hidden")
}

// iptables Backup captures only the INPUT/OUTPUT filter rules and the nat rules,
// so Restore must splice those back into the existing save file and leave
// everything it did not capture untouched: chain default policies, the FORWARD
// chain, user-defined chains, and the *mangle/*raw tables. The old scaffold-based
// Restore silently reset a DROP policy to ACCEPT and deleted all of that.
func TestIPTablesRestorePreservesUnmanaged(t *testing.T) {
	dir := t.TempDir()
	// A realistic save file: hardened DROP policies, a FORWARD rule, a *mangle
	// table, and a *nat table with a managed DNAT plus a foreign DOCKER chain.
	save := "*mangle\n:PREROUTING ACCEPT [0:0]\n:POSTROUTING ACCEPT [0:0]\n" +
		"-A PREROUTING -j MARK --set-mark 1\nCOMMIT\n" +
		"*nat\n:PREROUTING ACCEPT [0:0]\n:INPUT ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\n:POSTROUTING ACCEPT [0:0]\n:DOCKER - [0:0]\n" +
		"-A PREROUTING -p tcp --dport 80 -j DNAT --to-destination 10.0.0.5:8080\n-A DOCKER -j RETURN\nCOMMIT\n" +
		"*filter\n:INPUT DROP [0:0]\n:OUTPUT DROP [0:0]\n:FORWARD DROP [0:0]\n" +
		"-A INPUT -p tcp --dport 22 -j ACCEPT\n-A FORWARD -s 10.0.0.0/8 -j ACCEPT\nCOMMIT\n"
	scaffold := "*filter\n:INPUT ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\n:FORWARD ACCEPT [0:0]\nCOMMIT\n"
	p4 := filepath.Join(dir, "iptables")
	p6 := filepath.Join(dir, "ip6tables")
	require.NoError(t, os.WriteFile(p4, []byte(save), 0644))
	require.NoError(t, os.WriteFile(p6, []byte(scaffold), 0644))
	// A staging path keeps Backup's address-set read on the file rather than the
	// live kernel, which an unprivileged test cannot query.
	f := &IPTables{IP4Path: p4, IP6Path: p6, IPSetPath: filepath.Join(dir, "ipsets")}
	ctx := context.Background()

	backup, err := f.Backup(ctx, "")
	require.NoError(t, err)
	require.NoError(t, f.Restore(ctx, "", backup))

	out, err := os.ReadFile(p4)
	require.NoError(t, err)
	got := string(out)

	// Policies and unmanaged content Backup never captured must survive.
	require.Contains(t, got, ":INPUT DROP", "the INPUT DROP policy must not flip to ACCEPT")
	require.Contains(t, got, ":FORWARD DROP", "the FORWARD DROP policy must survive")
	require.Contains(t, got, "-A FORWARD -s 10.0.0.0/8 -j ACCEPT", "the FORWARD rule must survive")
	require.Contains(t, got, "*mangle", "the mangle table must survive")
	require.Contains(t, got, "MARK --set-mark 1", "the mangle rule must survive")
	require.Contains(t, got, ":DOCKER", "the foreign nat chain must survive")
	require.Contains(t, got, "-A DOCKER -j RETURN", "the foreign nat chain's rule must survive")

	// The managed rules Backup captured must be re-applied.
	require.Contains(t, got, "--dport 22", "the managed INPUT rule must be restored")
	require.Contains(t, got, "DNAT", "the managed nat rule must be restored")

	// Restore must be idempotent: a second Backup/Restore reproduces the same file.
	backup2, err := f.Backup(ctx, "")
	require.NoError(t, err)
	require.NoError(t, f.Restore(ctx, "", backup2))
	out2, err := os.ReadFile(p4)
	require.NoError(t, err)
	require.Equal(t, got, string(out2), "Restore must be idempotent")
}

// TestIPTablesInsertForeignChainPosition guards the InsertRule position counting
// against a foreign chain whose name merely starts with the target chain name
// (e.g. firewalld's "INPUT_direct"). GetRules numbers only exact INPUT/OUTPUT
// rules, so the insert path must count the same way. With the prefix-match bug
// the foreign line is miscounted and the new rule lands one slot too early.
func TestIPTablesInsertForeignChainPosition(t *testing.T) {
	dir := t.TempDir()
	// A foreign INPUT_direct chain precedes two managed INPUT rules. GetRules
	// reports the INPUT rules as #1 (dport 22) and #2 (dport 80); the
	// INPUT_direct line is not an INPUT rule and must not be counted.
	save := "*filter\n:INPUT ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\n" +
		"-A INPUT_direct -j DROP\n" +
		"-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT\n" +
		"-A INPUT -p tcp -m tcp --dport 80 -j ACCEPT\n" +
		"COMMIT\n"
	scaffold := "*filter\n:INPUT ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\nCOMMIT\n"
	p4 := filepath.Join(dir, "iptables")
	p6 := filepath.Join(dir, "ip6tables")
	require.NoError(t, os.WriteFile(p4, []byte(save), 0644))
	require.NoError(t, os.WriteFile(p6, []byte(scaffold), 0644))
	fw := &IPTables{IP4Path: p4, IP6Path: p6}
	ctx := context.Background()

	// Insert at INPUT position 2, i.e. between dport 22 (#1) and dport 80 (#2).
	require.NoError(t, fw.InsertRule(ctx, "", 2, &Rule{Family: IPv4, Proto: TCP, Port: 443, Action: Accept}))

	rules, err := fw.GetRules(ctx, "")
	require.NoError(t, err)
	var got *Rule
	for _, r := range rules {
		if r.Port == 443 {
			got = r
		}
	}
	require.NotNil(t, got, "the inserted rule should be present after InsertRule")
	require.Equal(t, 2, got.Number,
		"the rule must land at INPUT position 2, not be miscounted past the foreign INPUT_direct chain")
}

// TestIPTablesMoveForeignChainPosition is the MoveRule analogue: moving a rule to
// a 1-based position must count only exact INPUT rules, ignoring a foreign chain
// whose name starts with INPUT.
func TestIPTablesMoveForeignChainPosition(t *testing.T) {
	dir := t.TempDir()
	// INPUT rules on read: #1 dport 22, #2 dport 80, #3 dport 443. Move dport 443
	// to position 1; it must become #1 with 22 and 80 shifting down.
	save := "*filter\n:INPUT ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\n" +
		"-A INPUT_direct -j DROP\n" +
		"-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT\n" +
		"-A INPUT -p tcp -m tcp --dport 80 -j ACCEPT\n" +
		"-A INPUT -p tcp -m tcp --dport 443 -j ACCEPT\n" +
		"COMMIT\n"
	scaffold := "*filter\n:INPUT ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\nCOMMIT\n"
	p4 := filepath.Join(dir, "iptables")
	p6 := filepath.Join(dir, "ip6tables")
	require.NoError(t, os.WriteFile(p4, []byte(save), 0644))
	require.NoError(t, os.WriteFile(p6, []byte(scaffold), 0644))
	fw := &IPTables{IP4Path: p4, IP6Path: p6}
	ctx := context.Background()

	require.NoError(t, fw.MoveRule(ctx, "", &Rule{Family: IPv4, Proto: TCP, Port: 443, Action: Accept}, 1))

	rules, err := fw.GetRules(ctx, "")
	require.NoError(t, err)
	byPort := map[uint16]int{}
	for _, r := range rules {
		byPort[r.Port] = r.Number
	}
	require.Equal(t, 1, byPort[443], "moved rule must land at INPUT position 1, ahead of the foreign chain miscount")
	require.Equal(t, 2, byPort[22], "the displaced first rule shifts to position 2")
	require.Equal(t, 3, byPort[80], "the displaced second rule shifts to position 3")
}

// scanSaveGroups numbers each chain's groups the way GetRules does, and the
// InsertRule/MoveRule position math reads those numbers straight off the same
// scan — so a divergence here breaks Rule.Number's promise to mirror the position
// argument. It pins the four cases that decide a number: a LOG line paired with
// the action line directly under it is one logical rule carrying both lines, an
// orphan LOG line resolves to no rule, a line the parser rejects resolves to no
// rule, and an intervening line of either kind breaks a pair that would otherwise
// have formed. Chains are numbered independently.
func TestIPTablesScanSaveGroupsNumbering(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "iptables.save")
	content := strings.Join([]string{
		"*filter",
		":INPUT ACCEPT [0:0]",
		":OUTPUT ACCEPT [0:0]",
		"-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT",
		// A bare LOG line whose match fields agree with nothing below it.
		`-A INPUT -j LOG --log-prefix "audit "`,
		"-A INPUT -p tcp -m tcp --dport 80 -j ACCEPT",
		// A LOG line and the action line directly under it: one logged rule.
		`-A INPUT -p tcp -m tcp --dport 443 -j LOG --log-prefix "https "`,
		"-A INPUT -p tcp -m tcp --dport 443 -j ACCEPT",
		// A foreign line the model cannot hold, wedged between a LOG line and the
		// action it would otherwise have paired with.
		`-A INPUT -p tcp -m tcp --dport 8443 -j LOG --log-prefix "alt "`,
		"-A INPUT -p tcp -m tcp --tcp-flags SYN,ACK SYN -j DROP",
		"-A INPUT -p tcp -m tcp --dport 8443 -j ACCEPT",
		"-A OUTPUT -p tcp -m tcp --dport 25 -j ACCEPT",
		"COMMIT",
		"",
	}, "\n")
	require.NoError(t, os.WriteFile(path, []byte(content), 0644))

	type got struct {
		chain   string
		number  int
		resolve bool // The group resolved to a rule GetRules would report.
		lines   int
	}
	var seen []got
	f := &IPTables{}
	require.NoError(t, f.scanSaveFile(path, IPv4, func(g iptGroup) error {
		if g.chain != "" {
			seen = append(seen, got{g.chain, g.number, g.rule != nil, len(g.raw)})
		}
		return nil
	}))

	require.Equal(t, []got{
		{"INPUT", 1, true, 1},  // dport 22
		{"INPUT", 0, false, 1}, // orphan LOG: no rule, no number
		{"INPUT", 2, true, 1},  // dport 80
		{"INPUT", 3, true, 2},  // the logged pair, both lines in one group
		{"INPUT", 0, false, 1}, // LOG line the foreign line below orphaned
		{"INPUT", 0, false, 1}, // the unmodeled --tcp-flags line
		{"INPUT", 4, true, 1},  // dport 8443, its LOG partnership broken
		{"OUTPUT", 1, true, 1}, // OUTPUT numbers from 1 independently
	}, seen)
}

// TestIPTablesInsertPastConsecutiveOrphanLogs pins the walker fix: two foreign
// orphan LOG lines (no matching action) that GetRules drops must not shift the
// 1-based insert position. The old stateful walker swallowed the line after each
// LOG line, so with two consecutive orphan LOGs an insert drifted one position.
func TestIPTablesInsertPastConsecutiveOrphanLogs(t *testing.T) {
	dir := t.TempDir()
	save := "*filter\n:INPUT ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\n" +
		"-A INPUT -p udp -m udp --dport 53 -j LOG --log-prefix \"dns: \"\n" +
		"-A INPUT -p udp -m udp --dport 123 -j LOG --log-prefix \"ntp: \"\n" +
		"-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT\n" +
		"-A INPUT -p tcp -m tcp --dport 80 -j ACCEPT\n" +
		"COMMIT\n"
	scaffold := "*filter\n:INPUT ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\nCOMMIT\n"
	p4 := filepath.Join(dir, "iptables")
	p6 := filepath.Join(dir, "ip6tables")
	require.NoError(t, os.WriteFile(p4, []byte(save), 0644))
	require.NoError(t, os.WriteFile(p6, []byte(scaffold), 0644))
	fw := &IPTables{IP4Path: p4, IP6Path: p6}
	ctx := context.Background()

	// GetRules reports #1 dport 22, #2 dport 80 (the orphan LOGs are not rules).
	// Insert at position 2, i.e. between them.
	require.NoError(t, fw.InsertRule(ctx, "", 2, &Rule{Family: IPv4, Proto: TCP, Port: 443, Action: Accept}))

	rules, err := fw.GetRules(ctx, "")
	require.NoError(t, err)
	byPort := map[uint16]int{}
	for _, r := range rules {
		byPort[r.Port] = r.Number
	}
	require.Equal(t, 1, byPort[22], "the first rule stays at position 1")
	require.Equal(t, 2, byPort[443], "inserted rule must land at INPUT position 2, past the two orphan LOG lines")
	require.Equal(t, 3, byPort[80], "the displaced second rule shifts to position 3")

	// The foreign orphan LOG lines must survive the insert.
	got, err := os.ReadFile(p4)
	require.NoError(t, err)
	require.Contains(t, string(got), "dns: ", "orphan LOG line must be preserved")
	require.Contains(t, string(got), "ntp: ", "orphan LOG line must be preserved")
}

// TestIPTablesMovePastConsecutiveOrphanLogs is the MoveRule analogue: moving a
// rule to a position after two orphan LOG lines must count only logical rules.
func TestIPTablesMovePastConsecutiveOrphanLogs(t *testing.T) {
	dir := t.TempDir()
	save := "*filter\n:INPUT ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\n" +
		"-A INPUT -p udp -m udp --dport 53 -j LOG --log-prefix \"dns: \"\n" +
		"-A INPUT -p udp -m udp --dport 123 -j LOG --log-prefix \"ntp: \"\n" +
		"-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT\n" +
		"-A INPUT -p tcp -m tcp --dport 80 -j ACCEPT\n" +
		"COMMIT\n"
	scaffold := "*filter\n:INPUT ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\nCOMMIT\n"
	p4 := filepath.Join(dir, "iptables")
	p6 := filepath.Join(dir, "ip6tables")
	require.NoError(t, os.WriteFile(p4, []byte(save), 0644))
	require.NoError(t, os.WriteFile(p6, []byte(scaffold), 0644))
	fw := &IPTables{IP4Path: p4, IP6Path: p6}
	ctx := context.Background()

	// Move dport 22 (currently #1) to position 2; it must end up #2 with dport 80
	// at #1, not be miscounted onto the orphan LOG lines.
	require.NoError(t, fw.MoveRule(ctx, "", &Rule{Family: IPv4, Proto: TCP, Port: 22, Action: Accept}, 2))

	rules, err := fw.GetRules(ctx, "")
	require.NoError(t, err)
	byPort := map[uint16]int{}
	for _, r := range rules {
		byPort[r.Port] = r.Number
	}
	require.Equal(t, 1, byPort[80], "the displaced second rule becomes position 1")
	require.Equal(t, 2, byPort[22], "the moved rule must land at position 2, past the two orphan LOG lines")
}

// A counter-annotated (iptables-save -c) nat line must parse, matching the
// filter parser. The nat parser must strip the leading [pkts:bytes] prefix, so
// a counter-annotated save file's NAT rules survive in GetNATRules/Backup and
// can be removed.
func TestIPTablesNATCounterPrefix(t *testing.T) {
	fw := new(IPTables)
	plain := `-A PREROUTING -p tcp -m tcp --dport 80 -j DNAT --to-destination 10.0.0.1`
	counter := `[0:0] -A PREROUTING -p tcp -m tcp --dport 80 -j DNAT --to-destination 10.0.0.1`

	rp, err := fw.UnmarshalNATRule(plain, IPv4)
	require.NoError(t, err)
	rc, err := fw.UnmarshalNATRule(counter, IPv4)
	require.NoError(t, err, "counter-prefixed NAT rule should parse")
	require.True(t, rp.EqualBase(rc), "counter-prefixed NAT rule should equal the plain one")
}

// A "replace" must remove a pre-existing counter-annotated filter rule. The
// filter parser reads such lines (populating Packets/Bytes), so the file-rewrite
// path must recognise them as rules too — otherwise a Sync-based replace or
// Restore leaves stale foreign rules behind.
func TestIPTablesReplaceStripsCounterRules(t *testing.T) {
	dir := t.TempDir()
	p4 := filepath.Join(dir, "iptables")
	p6 := filepath.Join(dir, "ip6tables")
	v4 := strings.Join([]string{
		"*filter",
		":INPUT ACCEPT [0:0]",
		":OUTPUT ACCEPT [0:0]",
		":FORWARD ACCEPT [0:0]",
		"[7:420] -A INPUT -p tcp -m tcp --dport 9999 -j ACCEPT",
		"COMMIT",
		"",
	}, "\n")
	require.NoError(t, os.WriteFile(p4, []byte(v4), 0o644))
	require.NoError(t, os.WriteFile(p6, []byte("*filter\n:INPUT ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\n:FORWARD ACCEPT [0:0]\nCOMMIT\n"), 0o644))

	f := &IPTables{IP4Path: p4, IP6Path: p6}
	_, _, err := Sync(context.Background(), f, "", []*Rule{{Family: IPv4, Proto: TCP, Port: 22, Action: Accept}})
	require.NoError(t, err)

	got, err := os.ReadFile(p4)
	require.NoError(t, err)
	require.NotContains(t, string(got), "9999", "stale counter-annotated rule must be removed by replace; file:\n%s", got)
	require.Contains(t, string(got), "--dport 22", "desired rule must be present")
}

// A reconcile must preserve rules in chains the library does not model. A rule in
// a user-defined chain (CUSTOM) is never surfaced by GetRules, so the file-rewrite
// add and remove paths must keep it verbatim. The FORWARD chain, by contrast, is a
// modeled direction: GetRules surfaces its rules and a Sync-based reconcile manages
// them like INPUT/OUTPUT.
func TestIPTablesManagesForwardRules(t *testing.T) {
	dir := t.TempDir()
	p4 := filepath.Join(dir, "iptables")
	p6 := filepath.Join(dir, "ip6tables")
	v4 := strings.Join([]string{
		"*filter",
		":INPUT ACCEPT [0:0]",
		":OUTPUT ACCEPT [0:0]",
		":FORWARD ACCEPT [0:0]",
		"-A FORWARD -s 10.0.0.0/8 -j ACCEPT",
		"-A INPUT -p tcp -m tcp --dport 9999 -j ACCEPT",
		"-A CUSTOM -j ACCEPT",
		"COMMIT",
		"",
	}, "\n")
	require.NoError(t, os.WriteFile(p4, []byte(v4), 0o644))
	require.NoError(t, os.WriteFile(p6, []byte("*filter\n:INPUT ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\n:FORWARD ACCEPT [0:0]\nCOMMIT\n"), 0o644))

	f := &IPTables{IP4Path: p4, IP6Path: p6}

	// The FORWARD rule now surfaces as a modeled forward-direction rule.
	rules, err := f.GetRules(context.Background(), "")
	require.NoError(t, err)
	fwd := &Rule{Direction: DirForward, Family: IPv4, Source: "10.0.0.0/8", Action: Accept}
	found := false
	for _, r := range rules {
		if r.Equal(fwd, true) {
			found = true
		}
	}
	require.True(t, found, "the FORWARD rule should be modeled; got %+v", rules)

	// Additive add: existing rules survive.
	require.NoError(t, f.AddRule(context.Background(), "", &Rule{Family: IPv4, Proto: TCP, Port: 22, Action: Accept}))
	got, err := os.ReadFile(p4)
	require.NoError(t, err)
	require.Contains(t, string(got), "-A FORWARD -s 10.0.0.0/8 -j ACCEPT", "an additive add keeps existing FORWARD rules; file:\n%s", got)
	require.Contains(t, string(got), "--dport 22", "desired rule must be present")

	// Full replace via Sync: every modeled chain — INPUT, OUTPUT and FORWARD — is
	// reconciled to exactly the desired set, so the unlisted FORWARD and INPUT rules
	// are removed and a desired FORWARD rule is added; a rule in a user-defined chain
	// is still preserved verbatim.
	desired := []*Rule{
		{Family: IPv4, Proto: TCP, Port: 22, Action: Accept},
		{Direction: DirForward, Family: IPv4, Source: "192.168.0.0/16", Action: Accept},
	}
	_, _, err = Sync(context.Background(), f, "", desired)
	require.NoError(t, err)
	got, err = os.ReadFile(p4)
	require.NoError(t, err)
	require.NotContains(t, string(got), "10.0.0.0/8", "the replace reconciles away the unwanted FORWARD rule; file:\n%s", got)
	require.NotContains(t, string(got), "9999", "the replace reconciles away the unwanted INPUT rule; file:\n%s", got)
	require.Contains(t, string(got), "-A FORWARD -s 192.168.0.0/16 -j ACCEPT", "the desired FORWARD rule is added; file:\n%s", got)
	require.Contains(t, string(got), "--dport 22", "desired input rule present")
	require.Contains(t, string(got), "-A CUSTOM -j ACCEPT", "a user-defined chain rule is preserved; file:\n%s", got)
}

// A negated match in a -m udp/sctp block must not be mis-parsed. Grouping "!"
// with --source-port consumed the following token and parsed the option name as a
// port; the loop must reject the negation like the tcp loop and still parse a
// normal udp source/destination port.
func TestIPTablesUDPNegationParse(t *testing.T) {
	fw := new(IPTables)

	// A normal udp source-port rule still round-trips.
	got, err := fw.UnmarshalRule("-A INPUT -p udp -m udp --sport 53 -j ACCEPT", IPv4)
	require.NoError(t, err)
	require.Equal(t, uint16(53), got.SourcePort)

	// A negated port match cannot be represented and must be rejected cleanly.
	_, err = fw.UnmarshalRule("-A INPUT -p udp -m udp ! --dport 80 -j ACCEPT", IPv4)
	require.Error(t, err, "a negated udp port match must be rejected, not mis-parsed")
}

// An additive add must preserve a standalone LOG rule (no terminal action). Such a
// rule cannot be modeled as a Rule, so GetRules drops it; if the file-rewrite path
// also drops it, an AddRule silently deletes a foreign audit-log rule.
func TestIPTablesAddPreservesOrphanLog(t *testing.T) {
	dir := t.TempDir()
	p4 := filepath.Join(dir, "iptables")
	p6 := filepath.Join(dir, "ip6tables")
	v4 := strings.Join([]string{
		"*filter",
		":INPUT ACCEPT [0:0]",
		":OUTPUT ACCEPT [0:0]",
		":FORWARD ACCEPT [0:0]",
		`-A INPUT -j LOG --log-prefix "audit "`,
		"-A INPUT -p tcp -m tcp --dport 9999 -j ACCEPT",
		"COMMIT",
		"",
	}, "\n")
	require.NoError(t, os.WriteFile(p4, []byte(v4), 0o644))
	require.NoError(t, os.WriteFile(p6, []byte("*filter\n:INPUT ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\n:FORWARD ACCEPT [0:0]\nCOMMIT\n"), 0o644))

	f := &IPTables{IP4Path: p4, IP6Path: p6}
	require.NoError(t, f.AddRule(context.Background(), "", &Rule{Family: IPv4, Proto: TCP, Port: 22, Action: Accept}))

	got, err := os.ReadFile(p4)
	require.NoError(t, err)
	require.Contains(t, string(got), "-j LOG", "an additive add must not delete a standalone LOG rule; file:\n%s", got)
	require.Contains(t, string(got), "--dport 9999", "existing INPUT rule must survive an additive add")
	require.Contains(t, string(got), "--dport 22", "desired rule must be present")
}

// iptables-save always appends the connlimit counting key (--connlimit-saddr by
// default, or --connlimit-daddr) after a connlimit match. The parser did not
// consume that trailing flag, so it errored ("unsupported option") and
// parseFilterFile silently dropped the whole rule: a per-source connection-limit
// rule vanished from GetRules/Backup and could never be reconciled or removed.
func TestIPTablesConnlimitSaddrRoundTrip(t *testing.T) {
	fw := new(IPTables)

	// The exact form iptables-save emits for a per-source connlimit rule.
	saved := "-A INPUT -p tcp -m tcp --dport 80 -m connlimit --connlimit-above 20 --connlimit-mask 32 --connlimit-saddr -j REJECT --reject-with icmp-port-unreachable"
	got, err := fw.UnmarshalRule(saved, IPv4)
	require.NoError(t, err, "connlimit rule with --connlimit-saddr must parse")
	want := &Rule{Family: IPv4, Proto: TCP, Port: 80, ConnLimit: &ConnLimit{Count: 20, PerSource: true}, Action: Reject}
	require.True(t, want.Equal(got, false), "per-source connlimit must round-trip: got %+v", got.ConnLimit)

	// --connlimit-daddr must also be consumed rather than dropping the rule.
	daddr := "-A INPUT -p tcp -m tcp --dport 80 -m connlimit --connlimit-above 5 --connlimit-mask 24 --connlimit-daddr -j DROP"
	got, err = fw.UnmarshalRule(daddr, IPv4)
	require.NoError(t, err, "connlimit rule with --connlimit-daddr must parse")
	require.NotNil(t, got.ConnLimit)

	// A global (mask 0) connlimit still parses and counts globally.
	global := "-A INPUT -p tcp -m tcp --dport 80 -m connlimit --connlimit-above 100 --connlimit-mask 0 --connlimit-saddr -j DROP"
	got, err = fw.UnmarshalRule(global, IPv4)
	require.NoError(t, err)
	require.False(t, got.ConnLimit.PerSource, "mask 0 must count globally")
}

// iptables-save spells an ICMP type carrying a code as `type/code` (e.g. `3/1`).
// The parser rejected the token as an invalid type and dropped the whole rule;
// the Rule model has no code field, so the type is taken and the code ignored.
func TestIPTablesICMPTypeCode(t *testing.T) {
	fw := new(IPTables)
	got, err := fw.UnmarshalRule("-A INPUT -p icmp -m icmp --icmp-type 3/1 -j DROP", IPv4)
	require.NoError(t, err, "icmp type/code rule must parse")
	require.NotNil(t, got.ICMPType)
	require.Equal(t, uint8(3), *got.ICMPType)
	require.Equal(t, Drop, got.Action)
}

// MoveRule must operate only on the *filter table. A full iptables-save dump also
// carries INPUT/OUTPUT chains in *nat/*mangle; the move must not pull a
// foreign rule out of one of those tables and splice it into *filter (which both
// corrupts the source table and installs a foreign rule as a filter rule).
func TestIPTablesMoveRuleFilterScope(t *testing.T) {
	dir := t.TempDir()
	p4 := filepath.Join(dir, "iptables")
	save := "*filter\n:INPUT ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\n:FORWARD ACCEPT [0:0]\n" +
		"-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT\n" +
		"-A INPUT -p tcp -m tcp --dport 80 -j ACCEPT\n" +
		"COMMIT\n" +
		"*mangle\n:INPUT ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\n" +
		"-A INPUT -p tcp -m tcp --dport 25 -j DROP\n" +
		"COMMIT\n"
	require.NoError(t, os.WriteFile(p4, []byte(save), 0644))
	fw := &IPTables{IP4Path: p4}

	// The dport-25 rule lives only in *mangle. Moving it must be a no-op on *filter
	// and leave the file untouched.
	require.NoError(t, fw.MoveRule(context.Background(), "", &Rule{Proto: TCP, Port: 25, Action: Drop}, 1))
	data, err := os.ReadFile(p4)
	require.NoError(t, err)
	require.Equal(t, save, string(data), "a rule living only in *mangle must not be moved as a filter rule")
}

// ipsetParseType decodes the family and set type from an `ipset save` create
// line's fields, defaulting to IPv4 hash:ip.
func TestIPSetParseType(t *testing.T) {
	f := new(IPTables)
	fam, typ := f.ipsetParseType([]string{"create", "s", "hash:ip"})
	require.Equal(t, IPv4, fam)
	require.Equal(t, SetHashIP, typ)

	fam, typ = f.ipsetParseType([]string{"create", "s", "hash:net", "family", "inet6", "hashsize", "1024"})
	require.Equal(t, IPv6, fam, "family inet6 must decode to IPv6")
	require.Equal(t, SetHashNet, typ)

	fam, typ = f.ipsetParseType([]string{"create", "s", "hash:ip", "family", "inet"})
	require.Equal(t, IPv4, fam, "family inet stays IPv4")
	require.Equal(t, SetHashIP, typ)
}

// A foreign, standalone `-j LOG` audit line that does not belong to the rule
// being removed must be preserved. The remove path holds a LOG line back as
// "pending" and only folds it into the following action line when their match
// fields agree (iptSameMatch). When they do not agree, removing the action line
// must not also drop the unrelated LOG line.
func TestRemoveRulePreservesUnrelatedLogLine(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "iptables.save")
	content := strings.Join([]string{
		"*filter",
		":INPUT ACCEPT [0:0]",
		":OUTPUT ACCEPT [0:0]",
		`-A INPUT -j LOG --log-prefix "audit "`,
		"-A INPUT -p tcp --dport 22 -j ACCEPT",
		"COMMIT",
		"",
	}, "\n")
	require.NoError(t, os.WriteFile(path, []byte(content), 0644))

	f := &IPTables{IP4Path: path}
	// Remove the unlogged tcp/22 rule; the standalone audit LOG line is unrelated.
	target := &Rule{Proto: TCP, Port: 22, Action: Accept}
	require.NoError(t, f.RemoveRule(context.Background(), "", target))

	got, err := os.ReadFile(path)
	require.NoError(t, err)
	out := string(got)

	require.NotContains(t, out, "--dport 22", "the targeted rule must be removed")
	require.Contains(t, out, `LOG --log-prefix "audit "`,
		"an unrelated standalone LOG line must not be removed with the rule")
}

// The MoveRule path has the mirror defect: a standalone `-j LOG` line that does
// not coalesce with the moved rule must not be lifted and dragged to the new
// position. Moving dport 80 to position 1 must reorder it ahead of dport 22 while
// the audit line stays exactly where it was — it begins no logical rule, so it
// neither takes a position nor travels with one.
func TestMoveRuleDoesNotDragUnrelatedLogLine(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "iptables.save")
	content := strings.Join([]string{
		"*filter",
		":INPUT ACCEPT [0:0]",
		`-A INPUT -j LOG --log-prefix "audit "`,
		"-A INPUT -p tcp --dport 22 -j ACCEPT",
		"-A INPUT -p tcp --dport 80 -j ACCEPT",
		"COMMIT",
		"",
	}, "\n")
	require.NoError(t, os.WriteFile(path, []byte(content), 0644))

	f := &IPTables{IP4Path: path}
	require.NoError(t, f.MoveRule(context.Background(), "", &Rule{Proto: TCP, Port: 80, Action: Accept}, 1))

	data, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, []string{
		"*filter",
		":INPUT ACCEPT [0:0]",
		`-A INPUT -j LOG --log-prefix "audit "`,
		"-A INPUT -p tcp --dport 80 -j ACCEPT",
		"-A INPUT -p tcp --dport 22 -j ACCEPT",
		"COMMIT",
	}, strings.Split(strings.TrimRight(string(data), "\n"), "\n"))
}

func TestIPTablesLogLimitRoundTrip(t *testing.T) {
	f := &IPTables{}

	// A logged rule is two lines that coalesce back to one logical rule.
	logged := &Rule{Port: 22, Proto: TCP, Action: Accept, Log: true, LogPrefix: "ssh"}
	lines, err := f.marshalRuleLines(logged)
	require.NoError(t, err)
	require.Len(t, lines, 2, "a logged rule should be a LOG line plus an action line")
	var parsed []*Rule
	for _, l := range lines {
		r, perr := f.UnmarshalRule(l, IPv4)
		require.NoError(t, perr, "line %q", l)
		parsed = append(parsed, r)
	}
	coalesced := coalesceLoggedRules(parsed)
	require.Len(t, coalesced, 1)
	require.True(t, coalesced[0].EqualBase(logged, true), "want %+v got %+v", logged, coalesced[0])

	// Rate and connection limits round-trip on a single line.
	for _, orig := range []*Rule{
		// A non-default burst round-trips; the default of 5 is normalized to 0 (it
		// is indistinguishable from iptables' applied default), covered separately
		// by TestIPTablesRateBurstDefaultNormalized.
		{Port: 22, Proto: TCP, Action: Accept, RateLimit: &RateLimit{Rate: 10, Unit: PerMinute, Burst: 3}},
		{Proto: TCP, Port: 80, Action: Reject, ConnLimit: &ConnLimit{Count: 20, PerSource: true}},
		{Proto: TCP, Port: 80, Action: Reject, ConnLimit: &ConnLimit{Count: 20, PerSource: false}},
		{Proto: TCP, Port: 80, SourcePort: 1234, Action: Accept},
		{Proto: TCP, Port: 80, SourcePorts: []PortRange{{Start: 1000, End: 2000}}, Action: Accept},
	} {
		spec, err := f.MarshalRule(orig)
		require.NoError(t, err)
		got, err := f.UnmarshalRule(spec, IPv4)
		require.NoError(t, err, "spec %q", spec)
		require.True(t, got.EqualBase(orig, true), "spec %q: want %+v got %+v", spec, orig, got)
	}
}

// Address sets are staged in the ipset file and reach the kernel only on Reload,
// so every mutation is a file edit and every read comes back off the file. None
// of this shells out to ipset, which is what lets the test run anywhere.
func TestIPTablesAddressSetStaging(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "ipsets")
	f := &IPTables{IPSetPath: path}

	set := &AddressSet{Name: "block", Family: IPv6, Type: SetHashNet, Entries: []string{"2001:db8::/64"}}
	require.NoError(t, f.AddAddressSet(ctx, set))
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, "create block hash:net family inet6\nadd block 2001:db8::/64\n", string(data),
		"the staging file holds ipset save format, not a dump of live state")

	// Entries are staged into the file, and adding one already there is a no-op.
	require.NoError(t, f.AddAddressSetEntry(ctx, "block", "2001:db8:1::/64"))
	require.NoError(t, f.AddAddressSetEntry(ctx, "block", "2001:db8:1::/64"))
	got, err := f.GetAddressSet(ctx, "block")
	require.NoError(t, err)
	require.Equal(t, []string{"2001:db8::/64", "2001:db8:1::/64"}, got.Entries)
	require.Equal(t, IPv6, got.Family)
	require.Equal(t, SetHashNet, got.Type)

	require.NoError(t, f.RemoveAddressSetEntry(ctx, "block", "2001:db8::/64"))
	// A missing entry, and an entry on a set that is not staged, are both no-ops.
	require.NoError(t, f.RemoveAddressSetEntry(ctx, "block", "192.0.2.1"))
	require.NoError(t, f.RemoveAddressSetEntry(ctx, "ghost", "192.0.2.1"))
	got, err = f.GetAddressSet(ctx, "block")
	require.NoError(t, err)
	require.Equal(t, []string{"2001:db8:1::/64"}, got.Entries)

	// Re-declaring a staged set merges entries; re-declaring it with a different
	// family or type is a conflict rather than a silent rewrite.
	require.NoError(t, f.AddAddressSet(ctx, &AddressSet{
		Name: "block", Family: IPv6, Type: SetHashNet, Entries: []string{"2001:db8:2::/64"}}))
	got, err = f.GetAddressSet(ctx, "block")
	require.NoError(t, err)
	require.Equal(t, []string{"2001:db8:1::/64", "2001:db8:2::/64"}, got.Entries)
	require.ErrorContains(t,
		f.AddAddressSet(ctx, &AddressSet{Name: "block", Family: IPv4, Type: SetHashNet}),
		"already staged")

	// An entry on a set that was never staged reports what ipset itself would.
	require.ErrorContains(t, f.AddAddressSetEntry(ctx, "ghost", "192.0.2.1"), "does not exist")

	// Removal drops the set from the file and queues the kernel-side destroy for
	// Reload; removing an unstaged set is a no-op that queues nothing.
	require.NoError(t, f.RemoveAddressSet(ctx, "block"))
	require.Equal(t, []string{"block"}, f.pendingSetRemovals)
	require.NoError(t, f.RemoveAddressSet(ctx, "ghost"))
	require.Equal(t, []string{"block"}, f.pendingSetRemovals)
	sets, err := f.GetAddressSets(ctx)
	require.NoError(t, err)
	require.Empty(t, sets)

	// Staging the set again before that Reload cancels the queued destroy, which
	// would otherwise delete the set the caller just asked for.
	require.NoError(t, f.AddAddressSet(ctx, set))
	require.Empty(t, f.pendingSetRemovals)
}

// A FamilyAny set is staged as IPv4: a set is family-typed, so the file always
// names a concrete family for `ipset restore` to create it with.
func TestIPTablesAddressSetFamilyAnyStagedAsIPv4(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "ipsets")
	f := &IPTables{IPSetPath: path}

	require.NoError(t, f.AddAddressSet(ctx, &AddressSet{Name: "any", Type: SetHashIP}))
	got, err := f.GetAddressSet(ctx, "any")
	require.NoError(t, err)
	require.Equal(t, IPv4, got.Family)
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Contains(t, string(data), "family inet")
}

// The save-format decode is single-pass and must survive the oddities a real
// staging file carries, since a misread here silently changes what Reload loads.
func TestIPTablesIPSetSaveDecode(t *testing.T) {
	f := &IPTables{}
	lines := []string{
		"create v4 hash:ip family inet hashsize 1024 maxelem 65536",
		"add v4 192.0.2.1 timeout 600",
		`add v4 192.0.2.2 comment "note"`,
		"create v6 hash:net family inet6",
		"add v6 2001:db8::/64",
		// A second create for a name already decoded, and an add naming a set this
		// file never declares, are both dropped rather than corrupting the decode.
		"create v4 hash:net family inet6",
		"add ghost 198.51.100.1",
		"",
		"# a comment",
	}
	want := []*AddressSet{
		{Name: "v4", Family: IPv4, Type: SetHashIP, Entries: []string{"192.0.2.1", "192.0.2.2"}},
		{Name: "v6", Family: IPv6, Type: SetHashNet, Entries: []string{"2001:db8::/64"}},
	}
	path := filepath.Join(t.TempDir(), "ipsets")
	require.NoError(t, os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0600))
	scanned, err := f.scanIPSetSave(path)
	require.NoError(t, err)
	require.Equal(t, want, scanned)

	// What the backend renders round-trips through the decode unchanged.
	rendered := filepath.Join(t.TempDir(), "rendered")
	require.NoError(t, os.WriteFile(rendered, f.marshalIPSetSave(want), 0600))
	round, err := f.scanIPSetSave(rendered)
	require.NoError(t, err)
	require.Equal(t, want, round)

	// A staging file that was never written decodes as no sets, not an error.
	missing, err := f.scanIPSetSave(filepath.Join(t.TempDir(), "absent"))
	require.NoError(t, err)
	require.Empty(t, missing)
}

// Encoding entries for the kernel is work the `ipset` binary used to do for us,
// so the address/CIDR forms a set can hold are pinned here. Decoding must land
// back on the exact string the save-format decode produces for the same entry,
// or a set read live and the same set read from a staging file would not compare
// equal.
func TestIPSetEntryEncoding(t *testing.T) {
	for _, tc := range []struct {
		entry string
		ip    string
		cidr  uint8
		// decoded is the entry as it reads back, which differs from entry only
		// where host bits were supplied and the kernel masks them off.
		decoded string
	}{
		{entry: "192.0.2.10", ip: "192.0.2.10", cidr: 0, decoded: "192.0.2.10"},
		{entry: "10.0.0.0/8", ip: "10.0.0.0", cidr: 8, decoded: "10.0.0.0/8"},
		{entry: "192.0.2.5/24", ip: "192.0.2.0", cidr: 24, decoded: "192.0.2.0/24"},
		{entry: "2001:db8::1", ip: "2001:db8::1", cidr: 0, decoded: "2001:db8::1"},
		{entry: "2001:db8::/64", ip: "2001:db8::", cidr: 64, decoded: "2001:db8::/64"},
	} {
		got, err := ipsetEncodeEntry(tc.entry)
		require.NoError(t, err, "entry %q", tc.entry)
		require.Equal(t, tc.ip, got.IP.String(), "entry %q", tc.entry)
		require.Equal(t, tc.cidr, got.CIDR, "entry %q", tc.entry)
		require.True(t, got.Replace, "entry %q must carry the kernel's exist flag", tc.entry)
		require.Equal(t, tc.decoded, ipsetDecodeEntry(*got), "entry %q", tc.entry)
	}

	// A prefix covering the whole address is dropped, which is how `ipset save`
	// writes a single host held in a hash:net set.
	require.Equal(t, "192.0.2.1", ipsetDecodeEntry(netlink.IPSetEntry{IP: net.ParseIP("192.0.2.1"), CIDR: 32}))
	require.Equal(t, "2001:db8::1", ipsetDecodeEntry(netlink.IPSetEntry{IP: net.ParseIP("2001:db8::1"), CIDR: 128}))
	// An entry the kernel sent without an address has no representation.
	require.Empty(t, ipsetDecodeEntry(netlink.IPSetEntry{}))

	for _, bad := range []string{"", "not-an-ip", "192.0.2.0/33", "example.com", "192.0.2.1-192.0.2.9"} {
		_, err := ipsetEncodeEntry(bad)
		require.Error(t, err, "entry %q must be rejected rather than sent to the kernel", bad)
	}
}

// setRefFamily consults the staged sets first and falls back to the live kernel
// for a set that exists only there, and a rule that already carries a family
// bypasses resolution entirely.
func TestIPTablesSetRefFamilyFallbackChain(t *testing.T) {
	dir := t.TempDir()
	scaffold := "*filter\n:INPUT ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\nCOMMIT\n"
	p4 := filepath.Join(dir, "iptables")
	p6 := filepath.Join(dir, "ip6tables")
	require.NoError(t, os.WriteFile(p4, []byte(scaffold), 0644))
	require.NoError(t, os.WriteFile(p6, []byte(scaffold), 0644))
	ipsets := filepath.Join(dir, "ipsets")
	require.NoError(t, os.WriteFile(ipsets, []byte(
		"create bootset hash:ip family inet6\nadd bootset 2001:db8::1\n"), 0644))
	f := &IPTables{IP4Path: p4, IP6Path: p6, IPSetPath: ipsets}
	ctx := context.Background()

	// The live query knows no sets; "errored" additionally exercises the
	// netlink-failure path, which falls through to the declared sets.
	prev := ipsetLiveFamily
	t.Cleanup(func() { ipsetLiveFamily = prev })
	ipsetLiveFamily = func(name string) (Family, bool, error) {
		if name == "errored" {
			return FamilyAny, false, fmt.Errorf("netlink unavailable")
		}
		return FamilyAny, false, nil
	}

	// Declared only in the persistence file: pinned to its inet6 family.
	require.NoError(t, f.AddRule(ctx, "", &Rule{Proto: TCP, Port: 4220, Source: "bootset", Action: Accept}))
	d4, err := os.ReadFile(p4)
	require.NoError(t, err)
	d6, err := os.ReadFile(p6)
	require.NoError(t, err)
	require.Contains(t, string(d6), "--match-set bootset src")
	require.NotContains(t, string(d4), "bootset",
		"a set declared inet6 in boot config must not produce an iptables line")

	// A netlink failure still falls through to the declared file; the set is
	// not there either, so the add fails as unknown rather than writing a
	// blind line.
	err = f.AddRule(ctx, "", &Rule{Proto: TCP, Port: 4221, Source: "errored", Action: Accept})
	require.ErrorContains(t, err, `"errored"`)

	// A rule that already carries a family is written as declared: no source
	// knows "errored", so success proves resolution was never consulted.
	require.NoError(t, f.AddRule(ctx, "", &Rule{Family: IPv4, Proto: TCP, Port: 4222, Source: "errored", Action: Accept}))
	d4, err = os.ReadFile(p4)
	require.NoError(t, err)
	require.Contains(t, string(d4), "--match-set errored src")
}

func TestIPTablesNATRoundTrip(t *testing.T) {
	f := &IPTables{}
	cases := []*NATRule{
		{Kind: DNAT, Family: IPv4, Proto: TCP, Port: 80, ToAddress: "10.0.0.5", ToPort: 8080, Interface: "eth0"},
		{Kind: Redirect, Family: IPv4, Proto: TCP, Port: 80, ToPort: 8080},
		{Kind: SNAT, Family: IPv4, Source: "10.0.0.0/24", ToAddress: "1.2.3.4", Interface: "eth1"},
		// SNAT with a source-port translation is now accepted: iptables emits it
		// as --to-source addr:port (pf/nft reject it in their own MarshalNATRule).
		{Kind: SNAT, Family: IPv4, Proto: TCP, Source: "10.0.0.0/24", ToAddress: "1.2.3.4", ToPort: 8443, Interface: "eth1"},
		{Kind: Masquerade, Family: IPv4, Interface: "eth1"},
	}
	for _, orig := range cases {
		spec, err := f.MarshalNATRule(orig)
		require.NoError(t, err)
		got, err := f.UnmarshalNATRule(spec, IPv4)
		require.NoError(t, err, "spec %q", spec)
		require.True(t, got.EqualBase(orig), "spec %q: want %+v got %+v", spec, orig, got)
	}
}

func TestIPTablesProtocolAndComment(t *testing.T) {
	f := &IPTables{}
	cases := []*Rule{
		{Proto: SCTP, Port: 9000, Action: Accept},
		{Proto: GRE, Action: Accept},
		{Proto: ESP, Action: Accept},
		{Proto: AH, Action: Drop},
		{Proto: TCP, Port: 22, Action: Accept, Comment: "ssh access"},
	}
	for _, orig := range cases {
		spec, err := f.MarshalRule(orig)
		require.NoError(t, err)
		got, err := f.UnmarshalRule(spec, IPv4)
		require.NoError(t, err, "spec %q", spec)
		require.True(t, got.EqualBase(orig, true), "spec %q: want %+v got %+v", spec, orig, got)
		require.Equal(t, orig.Comment, got.Comment, "spec %q comment", spec)
	}
}

// TestIPTablesNATParserRejectsUnmodeledMatches pins the shapes UnmarshalNATRule
// must leave foreign: a negated interface/protocol/port match (reading
// `! -o docker0` as a plain match would invert Docker's stock masquerade rule),
// an unknown protocol token, and a source-or-destination multiport option.
func TestIPTablesNATParserRejectsUnmodeledMatches(t *testing.T) {
	fw := new(IPTables)
	foreign := []string{
		"-A POSTROUTING -s 172.17.0.0/16 ! -o docker0 -j MASQUERADE",
		"-A PREROUTING ! -i eth0 -p tcp -m tcp --dport 80 -j REDIRECT --to-ports 8080",
		"-A PREROUTING ! -p tcp -j REDIRECT --to-ports 8080",
		"-A PREROUTING -p tcp -m tcp ! --dport 80 -j REDIRECT --to-ports 8080",
		"-A PREROUTING -p udplite -j REDIRECT --to-ports 8080",
		"-A PREROUTING -p 47 -j REDIRECT --to-ports 8080",
		"-A PREROUTING -p udp -m multiport --ports 5060 -j REDIRECT --to-ports 5061",
	}
	for _, spec := range foreign {
		_, err := fw.UnmarshalNATRule(spec, IPv4)
		require.Error(t, err, "line must stay foreign: %s", spec)
	}

	// A negated address still models, and the plain forms still parse.
	r, err := fw.UnmarshalNATRule("-A POSTROUTING ! -s 172.17.0.0/16 -o eth0 -j MASQUERADE", IPv4)
	require.NoError(t, err)
	require.Equal(t, "!172.17.0.0/16", r.Source)
	require.Equal(t, "eth0", r.Interface)
	r, err = fw.UnmarshalNATRule("-A PREROUTING -p tcp -m tcp --dport 8080 -j DNAT --to-destination 10.0.0.5:80", IPv4)
	require.NoError(t, err)
	require.Equal(t, DNAT, r.Kind)
	require.EqualValues(t, 8080, r.Port)
}

// TestIPTablesRewriteNATPreservesUnmodeled pins that a Restore-style nat rewrite
// keeps managed-chain lines the model cannot hold — Docker's addrtype jump — while
// still replacing the modeled rules.
func TestIPTablesRewriteNATPreservesUnmodeled(t *testing.T) {
	dir := t.TempDir()
	save := "*nat\n:PREROUTING ACCEPT [0:0]\n:POSTROUTING ACCEPT [0:0]\n" +
		"-A PREROUTING -m addrtype --dst-type LOCAL -j DOCKER\n" +
		"-A PREROUTING -p tcp -m tcp --dport 8080 -j DNAT --to-destination 10.0.0.5:80\n" +
		"-A POSTROUTING -s 172.17.0.0/16 ! -o docker0 -j MASQUERADE\n" +
		"COMMIT\n*filter\n:INPUT ACCEPT [0:0]\nCOMMIT\n"
	p := filepath.Join(dir, "iptables")
	require.NoError(t, os.WriteFile(p, []byte(save), 0644))
	fw := &IPTables{IP4Path: p, IP6Path: filepath.Join(dir, "ip6tables")}

	require.NoError(t, fw.rewriteNATRules(p, []string{"-A PREROUTING -p tcp -m tcp --dport 9090 -j DNAT --to-destination 10.0.0.6:90"}))
	got, err := os.ReadFile(p)
	require.NoError(t, err)
	body := string(got)
	require.Contains(t, body, "-j DOCKER", "Docker's unmodeled prerouting jump must survive the rewrite")
	require.Contains(t, body, "! -o docker0", "Docker's negated masquerade must survive the rewrite")
	require.Contains(t, body, "--dport 9090", "the desired rule must be written")
	require.NotContains(t, body, "--dport 8080", "the replaced modeled rule must be gone")
}

// TestIPTablesLogPairSplitByForeignLine pins that a LOG line and an action line
// separated by an unmodeled foreign line are not coalesced into one logged rule:
// the pair reads apart everywhere (GetRules, positions, removal), so reporting a
// merged rule would surface one no removal could ever find.
func TestIPTablesLogPairSplitByForeignLine(t *testing.T) {
	dir := t.TempDir()
	save := "*filter\n:INPUT ACCEPT [0:0]\n" +
		"-A INPUT -p tcp -m tcp --dport 80 -j LOG --log-prefix \"web: \"\n" +
		"-A INPUT -m recent --name probe --set -j DROP\n" +
		"-A INPUT -p tcp -m tcp --dport 80 -j ACCEPT\n" +
		"COMMIT\n"
	p := filepath.Join(dir, "iptables")
	require.NoError(t, os.WriteFile(p, []byte(save), 0644))
	fw := &IPTables{IP4Path: p, IP6Path: filepath.Join(dir, "ip6tables")}

	rules, err := fw.parseFilterFile(p, IPv4)
	require.NoError(t, err)
	require.Len(t, rules, 1, "only the plain accept is a modeled rule")
	require.False(t, rules[0].Log, "the accept must not inherit the separated LOG line")

	// Removing the reported rule must find its line even with the split pair.
	ctx := context.Background()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "ip6tables"), []byte("*filter\nCOMMIT\n"), 0644))
	require.NoError(t, fw.RemoveRule(ctx, "", &Rule{Family: IPv4, Proto: TCP, Port: 80, Action: Accept}))
	got, err := os.ReadFile(p)
	require.NoError(t, err)
	require.NotContains(t, string(got), "-j ACCEPT", "the reported rule must be removable")
	require.Contains(t, string(got), "-j LOG", "the orphaned LOG line is unmodeled and preserved")
	require.Contains(t, string(got), "-m recent", "the foreign line is preserved")
}

// TestIPTablesInsertPositionSkipsForeignLine pins that Insert positions count
// only the rules GetRules reports: an unmodeled foreign line holds no position,
// so Rule.Number and the InsertRule position argument cannot diverge.
func TestIPTablesInsertPositionSkipsForeignLine(t *testing.T) {
	dir := t.TempDir()
	save := "*filter\n:INPUT ACCEPT [0:0]\n" +
		"-A INPUT -m recent --name probe --set -j DROP\n" +
		"-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT\n" +
		"-A INPUT -p tcp -m tcp --dport 80 -j ACCEPT\n" +
		"COMMIT\n"
	p4 := filepath.Join(dir, "iptables")
	p6 := filepath.Join(dir, "ip6tables")
	require.NoError(t, os.WriteFile(p4, []byte(save), 0644))
	require.NoError(t, os.WriteFile(p6, []byte("*filter\nCOMMIT\n"), 0644))
	fw := &IPTables{IP4Path: p4, IP6Path: p6}
	ctx := context.Background()

	// GetRules reports #1 dport 22, #2 dport 80. Insert at 2 = between them.
	require.NoError(t, fw.InsertRule(ctx, "", 2, &Rule{Family: IPv4, Proto: TCP, Port: 443, Action: Accept}))
	rules, err := fw.GetRules(ctx, "")
	require.NoError(t, err)
	byPort := map[uint16]int{}
	for _, r := range rules {
		byPort[r.Port] = r.Number
	}
	require.Equal(t, 1, byPort[22])
	require.Equal(t, 2, byPort[443], "position 2 must land between the two modeled rules, not before dport 22")
	require.Equal(t, 3, byPort[80])
	got, err := os.ReadFile(p4)
	require.NoError(t, err)
	require.Contains(t, string(got), "-m recent", "the foreign line survives the insert")
}

// dockerSaveFile is a realistic iptables-save dump of a host running Docker: the
// classic DOCKER-* chain layout plus an operator's own INPUT and FORWARD rules
// and a hand-named br-lan bridge, which must stay managed. Only three of Docker's
// lines parse as modeled rules — the two FORWARD accepts and the per-published-
// port hairpin masquerade — and those are the ones the library must not touch.
const dockerSaveFile = "*nat\n:PREROUTING ACCEPT [0:0]\n:INPUT ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\n:POSTROUTING ACCEPT [0:0]\n:DOCKER - [0:0]\n" +
	"-A PREROUTING -m addrtype --dst-type LOCAL -j DOCKER\n" +
	"-A POSTROUTING -s 172.17.0.0/16 ! -o docker0 -j MASQUERADE\n" +
	"-A POSTROUTING -s 172.17.0.2/32 -d 172.17.0.2/32 -p tcp -m tcp --dport 80 -j MASQUERADE\n" +
	"-A POSTROUTING -o eth0 -j MASQUERADE\n" +
	"-A DOCKER ! -i docker0 -p tcp -m tcp --dport 8080 -j DNAT --to-destination 172.17.0.2:80\n" +
	"COMMIT\n" +
	"*filter\n:INPUT DROP [0:0]\n:FORWARD DROP [0:0]\n:OUTPUT ACCEPT [0:0]\n" +
	":DOCKER - [0:0]\n:DOCKER-USER - [0:0]\n:DOCKER-ISOLATION-STAGE-1 - [0:0]\n" +
	"-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT\n" +
	"-A FORWARD -j DOCKER-USER\n" +
	"-A FORWARD -j DOCKER-ISOLATION-STAGE-1\n" +
	"-A FORWARD -o docker0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT\n" +
	"-A FORWARD -o docker0 -j DOCKER\n" +
	"-A FORWARD -i docker0 ! -o docker0 -j ACCEPT\n" +
	"-A FORWARD -i docker0 -o docker0 -j ACCEPT\n" +
	"-A FORWARD -i br-1a2b3c4d5e6f -o br-1a2b3c4d5e6f -j ACCEPT\n" +
	"-A FORWARD -i br-lan -o eth0 -j ACCEPT\n" +
	"-A DOCKER-USER -j RETURN\n" +
	"COMMIT\n"

// dockerTestFirewall stages the Docker save file and returns the backend plus the
// IPv4 file path.
func dockerTestFirewall(t *testing.T) (*IPTables, string) {
	t.Helper()
	dir := t.TempDir()
	p4 := filepath.Join(dir, "iptables")
	p6 := filepath.Join(dir, "ip6tables")
	require.NoError(t, os.WriteFile(p4, []byte(dockerSaveFile), 0644))
	require.NoError(t, os.WriteFile(p6, []byte("*filter\n:INPUT ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\n:FORWARD ACCEPT [0:0]\nCOMMIT\n"), 0644))
	// A staging path keeps Backup's address-set read on the file rather than the
	// live kernel, which an unprivileged test cannot query.
	return &IPTables{IP4Path: p4, IP6Path: p6, IPSetPath: filepath.Join(dir, "ipsets")}, p4
}

// Docker owns and continuously reconciles its rules, so GetRules must not report
// them: a reported rule enters no desired set, and Sync would delete it and sever
// container networking. The operator's own rules — including one on a hand-named
// br-lan bridge — must still be reported and keep correct Numbers, since a
// container rule consumes no logical position, exactly like an unmodeled line.
func TestIPTablesGetRulesHidesContainerRuntime(t *testing.T) {
	f, _ := dockerTestFirewall(t)

	rules, err := f.GetRules(context.Background(), "")
	require.NoError(t, err)

	for _, r := range rules {
		require.False(t, isContainerRuntimeIface(r.InInterface),
			"a rule on container interface %q must not be reported", r.InInterface)
		require.False(t, isContainerRuntimeIface(r.OutInterface),
			"a rule on container interface %q must not be reported", r.OutInterface)
	}

	require.Len(t, rules, 2, "only the operator's two rules are in scope")

	require.Equal(t, DirInput, rules[0].Direction)
	require.EqualValues(t, 22, rules[0].Port)
	require.Equal(t, 1, rules[0].Number)

	// The operator's FORWARD rule is the only reported forward rule, so it is
	// number 1 in that chain — Docker's rules consume no logical position.
	require.Equal(t, DirForward, rules[1].Direction)
	require.Equal(t, "br-lan", rules[1].InInterface, "a hand-named bridge stays managed")
	require.Equal(t, "eth0", rules[1].OutInterface)
	require.Equal(t, 1, rules[1].Number)
}

// The nat counterpart: Docker's hairpin masquerade is the only nat line that
// parses, and it must be hidden, while the operator's egress masquerade is
// reported and numbered as the first POSTROUTING rule.
func TestIPTablesGetNATRulesHidesContainerRuntime(t *testing.T) {
	f, _ := dockerTestFirewall(t)

	nats, err := f.GetNATRules(context.Background(), "")
	require.NoError(t, err)
	require.Len(t, nats, 1, "only the operator's masquerade is in scope")
	require.Equal(t, "eth0", nats[0].Interface)
	require.Equal(t, 1, nats[0].Number)
}

// A Backup/Restore round trip is the sharpest test: Backup captures only what
// GetRules reports, and Restore rewrites the managed chains from that set. Every
// Docker line must survive verbatim, or restoring a backup would tear down
// container networking on a host that was running fine.
func TestIPTablesRestorePreservesContainerRuntime(t *testing.T) {
	f, p4 := dockerTestFirewall(t)
	ctx := context.Background()

	backup, err := f.Backup(ctx, "")
	require.NoError(t, err)
	for _, r := range backup.Rules {
		require.False(t, r.isContainerRuntime(), "a container rule must never reach a backup")
	}
	require.NoError(t, f.Restore(ctx, "", backup))

	out, err := os.ReadFile(p4)
	require.NoError(t, err)
	got := string(out)

	for _, line := range []string{
		"-A FORWARD -j DOCKER-USER",
		"-A FORWARD -j DOCKER-ISOLATION-STAGE-1",
		"-A FORWARD -o docker0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
		"-A FORWARD -o docker0 -j DOCKER",
		"-A FORWARD -i docker0 ! -o docker0 -j ACCEPT",
		"-A FORWARD -i docker0 -o docker0 -j ACCEPT",
		"-A FORWARD -i br-1a2b3c4d5e6f -o br-1a2b3c4d5e6f -j ACCEPT",
		"-A POSTROUTING -s 172.17.0.2/32 -d 172.17.0.2/32 -p tcp -m tcp --dport 80 -j MASQUERADE",
		"-A POSTROUTING -s 172.17.0.0/16 ! -o docker0 -j MASQUERADE",
		"-A PREROUTING -m addrtype --dst-type LOCAL -j DOCKER",
		"-A DOCKER ! -i docker0 -p tcp -m tcp --dport 8080 -j DNAT --to-destination 172.17.0.2:80",
	} {
		require.Contains(t, got, line, "Docker's rule must survive a Backup/Restore round trip")
	}

	// The operator's own rules are still restored, and the round trip is stable.
	require.Contains(t, got, "--dport 22")
	require.Contains(t, got, "-A FORWARD -i br-lan -o eth0 -j ACCEPT")

	backup2, err := f.Backup(ctx, "")
	require.NoError(t, err)
	require.NoError(t, f.Restore(ctx, "", backup2))
	out2, err := os.ReadFile(p4)
	require.NoError(t, err)
	require.Equal(t, got, string(out2), "Restore must be idempotent with container rules present")
}

// Sync is the path that would actually do the damage: it removes every reported
// rule the desired set does not cover. With Docker's rules hidden, a caller
// syncing only its own INPUT rule must leave every Docker line intact.
func TestIPTablesSyncLeavesContainerRuntimeIntact(t *testing.T) {
	f, p4 := dockerTestFirewall(t)
	ctx := context.Background()

	desired := []*Rule{{Direction: DirInput, Proto: TCP, Port: 443, Action: Accept}}
	_, removed, err := Sync(ctx, f, "", desired)
	require.NoError(t, err)
	require.Equal(t, 2, removed, "only the operator's two rules are reconciled")

	out, err := os.ReadFile(p4)
	require.NoError(t, err)
	got := string(out)
	require.Contains(t, got, "-A FORWARD -i docker0 -o docker0 -j ACCEPT", "Sync must not delete Docker's rule")
	require.Contains(t, got, "-A FORWARD -o docker0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT")
	require.Contains(t, got, "-A FORWARD -i br-1a2b3c4d5e6f -o br-1a2b3c4d5e6f -j ACCEPT")
	require.Contains(t, got, "--dport 443", "the desired rule is applied")
	require.NotContains(t, got, "--dport 22", "the operator's stale rule is reconciled away")
}

// Even a caller that hand-builds a rule matching a Docker line exactly must not
// be able to remove it through RemoveRule.
func TestIPTablesRemoveRuleRefusesContainerRuntime(t *testing.T) {
	f, p4 := dockerTestFirewall(t)

	target := &Rule{Direction: DirForward, InInterface: "docker0", OutInterface: "docker0", Action: Accept}
	require.NoError(t, f.RemoveRule(context.Background(), "", target))

	out, err := os.ReadFile(p4)
	require.NoError(t, err)
	require.Contains(t, string(out), "-A FORWARD -i docker0 -o docker0 -j ACCEPT",
		"Docker's rule must survive an exact-match removal attempt")
}
