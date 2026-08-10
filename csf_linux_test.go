package firewall

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// A TCPUDP port-only reject must be written to csf.deny as explicit tcp and
// udp advanced lines: csf's linefilter defaults a protocol-less line to -p tcp,
// so a single protocol-less line would leave udp open while the library reported
// the port blocked for all protocols.
func TestCSFTCPUDPRejectFansOut(t *testing.T) {
	ctx := context.Background()
	fw := new(CSF)
	dir := t.TempDir()
	path := filepath.Join(dir, "csf.deny")
	require.NoError(t, os.WriteFile(path, nil, 0644))

	reject := &Rule{Family: IPv4, Proto: TCPUDP, Port: 80, Action: Reject}
	require.NoError(t, fw.EditIPList(ctx, path, Reject, reject, false))

	data, err := os.ReadFile(path)
	require.NoError(t, err)
	text := string(data)
	require.Contains(t, text, "tcp|in|d=80|s=0.0.0.0/0", "tcp line must be present")
	require.Contains(t, text, "udp|in|d=80|s=0.0.0.0/0", "udp line must be present so udp is actually blocked")
	// No protocol-less line (which csf would silently treat as tcp only).
	for _, line := range strings.Split(text, "\n") {
		require.False(t, strings.HasPrefix(strings.TrimSpace(line), "in|"),
			"a protocol-less advanced line silently means tcp-only in csf: %q", line)
	}
}

// A port-only deny whose action is Drop (csf.conf's default DROP for an inbound
// deny) must still be written. The placeholder branch keys on "not an accept",
// not on Reject, so a Drop deny is written rather than skipped while AddRule
// reports success and leaves the port open.
func TestCSFPortOnlyDropDenyIsWritten(t *testing.T) {
	ctx := context.Background()
	fw := new(CSF)
	dir := t.TempDir()
	path := filepath.Join(dir, "csf.deny")
	require.NoError(t, os.WriteFile(path, nil, 0644))

	drop := &Rule{Family: IPv4, Proto: TCP, Port: 3306, Action: Drop}
	require.NoError(t, fw.EditIPList(ctx, path, Drop, drop, false))

	data, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Contains(t, string(data), "tcp|in|d=3306|s=0.0.0.0/0",
		"a port-only Drop deny must be written with the any-network placeholder")
}

// A TCPUDP port deny is written as a tcp line and a udp line, so it must be
// idempotent on re-add, read back as a single TCPUDP rule, and be fully
// removed by one RemoveRule. The add/remove matcher must treat a TCPUDP rule as
// covering its tcp and udp lines, not compare it exactly and let re-adds
// duplicate the pair while removal is a silent no-op.
func TestCSFTCPUDPPortDenyRoundTrip(t *testing.T) {
	ctx := context.Background()
	fw := new(CSF)
	dir := t.TempDir()
	path := filepath.Join(dir, "csf.deny")
	require.NoError(t, os.WriteFile(path, nil, 0644))

	deny := &Rule{Family: IPv4, Proto: TCPUDP, Port: 80, Action: Drop}

	// Add fans the TCPUDP deny out to a tcp and a udp line.
	require.NoError(t, fw.EditIPList(ctx, path, Drop, deny, false))
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, 1, strings.Count(string(data), "tcp|in|d=80|s=0.0.0.0/0"))
	require.Equal(t, 1, strings.Count(string(data), "udp|in|d=80|s=0.0.0.0/0"))

	// Re-adding is idempotent: neither line is duplicated.
	require.NoError(t, fw.EditIPList(ctx, path, Drop, deny, false))
	data, err = os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, 1, strings.Count(string(data), "tcp|in|d=80|s=0.0.0.0/0"),
		"re-adding a TCPUDP deny must not duplicate its tcp line")
	require.Equal(t, 1, strings.Count(string(data), "udp|in|d=80|s=0.0.0.0/0"),
		"re-adding a TCPUDP deny must not duplicate its udp line")

	// The fanned lines read back as their own rules and cover the TCPUDP deny.
	parsed, err := fw.ParseIPList(path, Drop)
	require.NoError(t, err)
	require.True(t, deny.CoveredBy(parsed), "the tcp+udp deny lines must cover the TCPUDP rule")
	for _, g := range parsed {
		require.True(t, deny.Covers(g), "a fanned line must not widen the rule: %+v", g)
	}

	// A single RemoveRule must drop every fanned line.
	require.NoError(t, fw.EditIPList(ctx, path, Drop, deny, true))
	data, err = os.ReadFile(path)
	require.NoError(t, err)
	require.NotContains(t, string(data), "d=80",
		"removing a TCPUDP deny must delete all of its fanned lines")
}

// A port-only deny fans out across family (and protocol), but the file may already
// hold a subset of those lines — a prior single-family add, or a manual edit. The
// add must heal the missing lines rather than treat the rule as fully present the
// moment one fan-out line matches: otherwise the other family/protocol stays open
// while the library reports the port blocked. The gate must check every fan-out
// line, not skip the whole fan-out on a single "exists" match.
func TestCSFPortOnlyDenyHealsMissingFamily(t *testing.T) {
	ctx := context.Background()
	// IPv6 enabled, so the deny fans out across families and the missing v6 line heals.
	fw := &CSF{ipv6Enabled: true}
	dir := t.TempDir()
	path := filepath.Join(dir, "csf.deny")

	// The file already has only the IPv4 fan-out line.
	require.NoError(t, os.WriteFile(path, []byte("tcp|in|d=80|s=0.0.0.0/0\n"), 0644))

	// Adding a FamilyAny port-80 TCP deny must add the missing IPv6 line (and not
	// duplicate the existing IPv4 one).
	deny := &Rule{Family: FamilyAny, Proto: TCP, Port: 80, Action: Drop}
	require.NoError(t, fw.EditIPList(ctx, path, Drop, deny, false))

	data, err := os.ReadFile(path)
	require.NoError(t, err)
	text := string(data)
	require.Equal(t, 1, strings.Count(text, "tcp|in|d=80|s=0.0.0.0/0"),
		"the pre-existing IPv4 line must be preserved, not duplicated")
	require.Equal(t, 1, strings.Count(text, "tcp|in|d=80|s=::/0"),
		"the missing IPv6 line must be added so IPv6:80 is actually blocked")

	// A TCPUDP deny whose udp line already exists must add the missing tcp line.
	path2 := filepath.Join(dir, "csf.deny2")
	require.NoError(t, os.WriteFile(path2, []byte("udp|in|d=53|s=0.0.0.0/0\n"), 0644))
	anyDeny := &Rule{Family: IPv4, Proto: TCPUDP, Port: 53, Action: Drop}
	require.NoError(t, fw.EditIPList(ctx, path2, Drop, anyDeny, false))
	data2, err := os.ReadFile(path2)
	require.NoError(t, err)
	require.Equal(t, 1, strings.Count(string(data2), "udp|in|d=53|s=0.0.0.0/0"),
		"the pre-existing udp line must be preserved")
	require.Equal(t, 1, strings.Count(string(data2), "tcp|in|d=53|s=0.0.0.0/0"),
		"the missing tcp line must be added so tcp:53 is actually blocked")
}

// A csf advanced rule with an address, a port, and TCPUDP cannot be expressed as a
// single line: csf.pl defaults a protocol-less line to tcp, so udp would be silently
// left open. AddRule must therefore fan the rule into a tcp rule and a udp rule
// before it reaches MarshalAdvRule, each of which marshals to its own line.
func TestCSFAdvRuleTCPUDPWithAddressFansOut(t *testing.T) {
	fw := new(CSF)
	both := &Rule{Family: IPv4, Proto: TCPUDP, Port: 443, Source: "192.0.2.10", Action: Drop}
	subs := expandProtocols(both)
	require.Len(t, subs, 2, "a TCPUDP rule must fan out before it is marshalled")

	var lines []string
	for _, sub := range subs {
		lines = append(lines, fw.MarshalAdvRule(sub))
	}
	require.Equal(t, []string{"tcp|in|d=443|s=192.0.2.10", "udp|in|d=443|s=192.0.2.10"}, lines,
		"each transport must get its own line so udp is not left open")
}

func TestCSFParseAdvRuleIPv6(t *testing.T) {
	fw := new(CSF)

	// An IPv6 source with a port must parse (the field separator is '|', so a
	// colon in the value is an IPv6 address, not a range/list separator).
	r := fw.ParseAdvRule("tcp|in|d=22|s=2001:db8::1", Accept)
	require.NotNil(t, r, "expected IPv6 advanced rule to parse")
	require.Equal(t, IPv6, r.Family, "expected IPv6 family")
	require.Equal(t, "2001:db8::1", r.Source)
	require.EqualValues(t, 22, r.Port)
	require.Equal(t, TCP, r.Proto)
	require.False(t, r.IsOutput())

	// An IPv4 destination with a port still parses.
	r = fw.ParseAdvRule("tcp|out|d=80|d=192.0.2.1", Accept)
	require.NotNil(t, r, "expected IPv4 advanced rule to parse")
	require.Equal(t, IPv4, r.Family)
	require.Equal(t, "192.0.2.1", r.Destination)
	require.EqualValues(t, 80, r.Port)

	// A destination port range is neither a valid IP nor a single port, so it
	// must still be rejected.
	require.Nil(t, fw.ParseAdvRule("tcp|in|d=1000:2000", Accept),
		"expected a port range to be rejected")

	// A comma-separated address list is still rejected.
	require.Nil(t, fw.ParseAdvRule("tcp|in|s=192.0.2.1,192.0.2.2", Accept),
		"expected a multi-address rule to be rejected")
}

func TestCSFFeatureRules(t *testing.T) {
	fw := new(CSF)

	// Advanced-rule encodings.
	cases := []struct {
		rule *Rule
		want string
	}{
		{&Rule{Proto: TCP, Ports: []PortRange{{Start: 80}, {Start: 443}}, Source: "1.2.3.4", Family: IPv4, Action: Accept}, "tcp|in|d=80,443|s=1.2.3.4"},
		{&Rule{Proto: TCP, Ports: []PortRange{{Start: 2000, End: 3000}}, Source: "1.2.3.4", Family: IPv4, Action: Accept}, "tcp|in|d=2000_3000|s=1.2.3.4"},
		{&Rule{Proto: ICMP, ICMPType: Ptr[uint8](8), Source: "44.33.22.11", Family: IPv4, Action: Accept}, "icmp|in|d=8|s=44.33.22.11"},
		{&Rule{Direction: DirOutput, Proto: UDP, Port: 53, Destination: "192.0.2.1", Family: IPv4, Action: Accept}, "udp|out|d=53|d=192.0.2.1"},
	}
	for _, c := range cases {
		got := fw.MarshalAdvRule(c.rule)
		require.Equal(t, c.want, got, "marshal %+v", *c.rule)

		parsed := fw.ParseAdvRule(got, c.rule.Action)
		require.NotNil(t, parsed, "failed to parse %q", got)
		require.True(t, parsed.Equal(c.rule, true),
			"round-trip mismatch: input %+v, line %q, output %+v", *c.rule, got, parsed)
	}

	// An ICMP type given by name resolves to its number.
	r := fw.ParseAdvRule("icmp|in|d=ping|s=44.33.22.11", Accept)
	require.NotNil(t, r, "expected icmp type 8 from name ping")
	require.NotNil(t, r.ICMPType, "expected icmp type 8 from name ping")
	require.EqualValues(t, 8, *r.ICMPType, "expected icmp type 8 from name ping")

	// csf reuses the port position for the ICMP type in BOTH the s= and d= fields
	// (csf.pl maps `s=<n>` to `--icmp-type <n>` for an icmp rule, just like `d=`).
	// A foreign rule that carries the type in s= must therefore read back as the
	// ICMP type, not as a nonsensical source port.
	r = fw.ParseAdvRule("icmp|in|s=8|d=44.33.22.11", Accept)
	require.NotNil(t, r, "expected icmp rule with type in s= to parse")
	require.NotNil(t, r.ICMPType, "expected s=8 to be read as icmp type 8")
	require.EqualValues(t, 8, *r.ICMPType, "expected icmp type 8 from s=8")
	require.False(t, r.HasSourcePorts(), "an icmp type must not be read as a source port")
	require.Equal(t, "44.33.22.11", r.Destination)

	// A colon range in an advanced rule is invalid (csf uses underscores there).
	require.Nil(t, fw.ParseAdvRule("tcp|in|d=1000:2000|s=1.2.3.4", Accept),
		"expected colon range in advanced rule to be rejected")

	// csf.conf port lists parse single ports and colon ranges.
	rules := fw.ParsePorts("20,21,30000:35000", IPv4, TCP, DirInput)
	require.Len(t, rules, 3, "expected 3 port rules")
	require.Len(t, rules[2].Ports, 1)
	require.Equal(t, PortRange{Start: 30000, End: 35000}, rules[2].Ports[0],
		"expected a 30000-35000 range rule")

	// EditRulePort adds a colon range token to the matching csf.conf port list.
	require.Equal(t, `TCP_IN = "22,2000:3000"`,
		fw.EditRulePort(`TCP_IN = "22"`, "TCP_IN", "22",
			&Rule{Proto: TCP, Ports: []PortRange{{Start: 2000, End: 3000}}, Action: Accept}, false),
		"unexpected csf.conf port edit")
}

func TestCSFSourcePorts(t *testing.T) {
	fw := new(CSF)

	// Source ports round-trip through the s= port-flow field, including a
	// multiport list and an underscore range.
	cases := []struct {
		rule *Rule
		want string
	}{
		{&Rule{Proto: TCP, SourcePort: 1234, Destination: "192.0.2.1", Family: IPv4, Action: Accept}, "tcp|in|s=1234|d=192.0.2.1"},
		{&Rule{Proto: UDP, SourcePorts: []PortRange{{Start: 80}, {Start: 443}}, Source: "1.2.3.4", Family: IPv4, Action: Accept}, "udp|in|s=80,443|s=1.2.3.4"},
		{&Rule{Proto: TCP, SourcePorts: []PortRange{{Start: 2000, End: 3000}}, Source: "1.2.3.4", Family: IPv4, Action: Accept}, "tcp|in|s=2000_3000|s=1.2.3.4"},
	}
	for _, c := range cases {
		got := fw.MarshalAdvRule(c.rule)
		require.Equal(t, c.want, got, "marshal %+v", *c.rule)

		parsed := fw.ParseAdvRule(got, c.rule.Action)
		require.NotNil(t, parsed, "failed to parse %q", got)
		require.True(t, parsed.Equal(c.rule, true),
			"round-trip mismatch: input %+v, line %q, output %+v", *c.rule, got, parsed)
	}
}

func TestCSFConnLimit(t *testing.T) {
	fw := new(CSF)

	// A csf.conf CONNLIMIT value parses into per-port reject rules carrying a
	// per-source connection cap. csf's CONNLIMIT chain rejects the excess with a
	// TCP reset (-j REJECT --reject-with tcp-reset), so the action is Reject.
	rules := fw.ParseConnLimit("22;5,80;20")
	require.Len(t, rules, 2)
	require.Equal(t, TCP, rules[1].Proto)
	require.EqualValues(t, 80, rules[1].Port)
	require.Equal(t, Reject, rules[1].Action)
	require.NotNil(t, rules[1].ConnLimit)
	require.EqualValues(t, 20, rules[1].ConnLimit.Count)
	require.True(t, rules[1].ConnLimit.PerSource)

	// Editing the CONNLIMIT list adds, removes, and updates a port's entry.
	require.Equal(t, `CONNLIMIT = "22;5,80;20"`, fw.editConnLimit("22;5", 80, 20, false))
	require.Equal(t, `CONNLIMIT = "80;20"`, fw.editConnLimit("22;5,80;20", 22, 5, true))
	require.Equal(t, `CONNLIMIT = "80;50"`, fw.editConnLimit("80;20", 80, 50, false))
}

// ParseConnLimit's reported Family must follow csf.conf's IPV6 setting: csf.pl
// only installs the ip6tables CONNLIMIT rule when IPV6 is enabled, so on the
// shipped default (IPV6="0") CONNLIMIT protects IPv4 only, not both families.
func TestCSFConnLimitFamily(t *testing.T) {
	disabled := &CSF{ipv6Enabled: false}
	rules := disabled.ParseConnLimit("22;5")
	require.Len(t, rules, 1)
	require.Equal(t, IPv4, rules[0].Family,
		"CONNLIMIT must report IPv4-only when csf.conf IPV6 is off")

	enabled := &CSF{ipv6Enabled: true}
	rules = enabled.ParseConnLimit("22;5")
	require.Len(t, rules, 1)
	require.Equal(t, FamilyAny, rules[0].Family,
		"CONNLIMIT must report dual-stack (FamilyAny) when csf.conf IPV6 is on")
}

func TestCSFRedirectNAT(t *testing.T) {
	fw := new(CSF)

	cases := []struct {
		rule *NATRule
		want string
	}{
		// A local port redirect (IPy = "*").
		{&NATRule{Kind: Redirect, Proto: TCP, Port: 666, ToPort: 25}, "*|666|*|25|tcp"},
		// A forward to another host with a fixed destination address.
		{&NATRule{Kind: DNAT, Proto: TCP, Destination: "192.168.254.62", Port: 666, ToAddress: "10.0.0.1", ToPort: 25, Family: IPv4}, "192.168.254.62|666|10.0.0.1|25|tcp"},
		// A full-IP forward, all ports (portA/portB unset).
		{&NATRule{Kind: DNAT, Proto: TCP, Destination: "192.168.254.62", ToAddress: "10.0.0.1", Family: IPv4}, "192.168.254.62|*|10.0.0.1|*|tcp"},
	}
	for _, c := range cases {
		got := fw.MarshalNATRule(c.rule)
		require.Equal(t, c.want, got, "marshal %+v", *c.rule)

		parsed := fw.UnmarshalNATRule(got)
		require.NotNil(t, parsed, "failed to parse %q", got)
		require.True(t, parsed.EqualBase(c.rule), "round-trip mismatch: input %+v, line %q, output %+v", *c.rule, got, parsed)
	}

	// A malformed csf.redirect line is ignored by the parser.
	require.Nil(t, fw.UnmarshalNATRule("nonsense|line"))
}

func TestCSFIPListComment(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "csf.allow")
	fw := &CSF{rulePrefix: "myapp"}
	ctx := context.Background()

	require.NoError(t, os.WriteFile(path, []byte(
		"# myapp trusted office\n"+
			"tcp|in|d=22|s=10.0.0.0/24\n"+
			"\n"+
			"# unrelated note\n"+
			"# separated by blank\n"+
			"192.0.2.5\n"+
			"2001:db8::1 # inline ignored\n",
	), 0644))

	rules, err := fw.ParseIPList(path, Accept)
	require.NoError(t, err)

	// Advanced rule keeps the comment immediately above it.
	adv := rules[0]
	require.Equal(t, "trusted office", adv.Comment)
	require.Equal(t, "10.0.0.0/24", adv.Source)
	require.EqualValues(t, 22, adv.Port)

	// A bare IPv4 line is one bidirectional DirAny rule carrying the accumulated comment.
	host := rules[1]
	require.Equal(t, DirAny, host.Direction)
	require.Equal(t, "192.0.2.5", host.Source)
	require.Equal(t, "unrelated note separated by blank", host.Comment)

	// Inline comment is ignored, not treated as a rule comment.
	v6 := rules[2]
	require.Equal(t, DirAny, v6.Direction)
	require.Equal(t, "", v6.Comment)
	require.Equal(t, "2001:db8::1", v6.Source)

	// Add a rule with a comment: a prefixed full-line comment is written above it.
	add := &Rule{Proto: TCP, Port: 443, Source: "192.0.2.10", Action: Accept, Comment: "web"}
	require.NoError(t, fw.EditIPList(ctx, path, Accept, add, false))
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Contains(t, string(data), "# myapp web\n")
	require.Contains(t, string(data), "tcp|in|d=443|s=192.0.2.10")

	// Removing the rule drops the comment line above it as well.
	require.NoError(t, fw.EditIPList(ctx, path, Accept, add, true))
	data, err = os.ReadFile(path)
	require.NoError(t, err)
	require.NotContains(t, string(data), "# myapp web")
	require.NotContains(t, string(data), "192.0.2.10")

	// A port-only rule has nowhere to go in an IP-list file; no dangling
	// comment line should be written even when a comment is supplied.
	portOnly := &Rule{Proto: TCP, Port: 8080, Action: Accept, Comment: "not-stored"}
	require.NoError(t, fw.EditIPList(ctx, path, Accept, portOnly, false))
	data, err = os.ReadFile(path)
	require.NoError(t, err)
	require.NotContains(t, string(data), "not-stored")

	// A rule appended after instructional header comments must still report
	// HasPrefix: the prefix tag starts a fresh comment block so header
	// comments are not absorbed into the rule's comment.
	headerPath := filepath.Join(dir, "header_csf.allow")
	require.NoError(t, os.WriteFile(headerPath, []byte(
		"# This is the csf.allow file.\n"+
			"# Add hosts/rules below, one per line.\n"+
			"# Format: proto|flow|port|ip\n",
	), 0644))
	appendRule := &Rule{Proto: TCP, Port: 3456, Source: "192.0.2.10/32", Action: Accept}
	require.NoError(t, fw.EditIPList(ctx, headerPath, Accept, appendRule, false))
	parsed, err := fw.ParseIPList(headerPath, Accept)
	require.NoError(t, err)
	require.Len(t, parsed, 1)
	require.True(t, parsed[0].HasPrefix, "rule after header comments must be flagged with the prefix")
	require.Equal(t, "", parsed[0].Comment)
}

// TestCSFRemovePreservesForeignHeader verifies that removing a managed rule keeps
// a foreign section header sitting directly above its prefix tag. ParseIPList
// treats the tag as starting a fresh comment block, so the header is not part of
// the rule's comment; removal must mirror that and not delete it.
func TestCSFRemovePreservesForeignHeader(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "csf.allow")
	fw := &CSF{rulePrefix: "myapp"}
	ctx := context.Background()

	require.NoError(t, os.WriteFile(path, []byte(
		"# Section: web servers\n"+
			"# myapp trusted\n"+
			"192.0.2.50\n",
	), 0644))

	require.NoError(t, fw.EditIPList(ctx, path, Accept, &Rule{Source: "192.0.2.50", Action: Accept}, true))
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	got := string(data)
	require.NotContains(t, got, "192.0.2.50", "the managed rule must be removed")
	require.NotContains(t, got, "# myapp trusted", "the rule's own tag comment is removed with it")
	require.Contains(t, got, "# Section: web servers", "the foreign section header must be preserved")
}

// csf.deny encodes no action of its own, so a rule added with Action Drop must be
// found and removed by the same Drop rule rather than leaking.
func TestCSFDropRuleRemovable(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "csf.deny")
	require.NoError(t, os.WriteFile(path, nil, 0644))
	fw := new(CSF)
	drop := &Rule{Proto: TCP, Port: 3306, Source: "1.2.3.4", Action: Drop}

	require.NoError(t, fw.EditIPList(context.Background(), path, Reject, drop, false))
	require.NoError(t, fw.EditIPList(context.Background(), path, Reject, drop, false))
	require.NoError(t, fw.EditIPList(context.Background(), path, Reject, drop, true))
	data, _ := os.ReadFile(path)
	require.NotContains(t, string(data), "1.2.3.4", "a Drop rule must be removable by the same Drop rule")
}

// csf.conf's CONNLIMIT is a single dual-stack config key (it caps both v4 and v6
// connections; there is no separate v6 variant), so a connection-limit rule read
// from it must be FamilyAny — not IPv4 — or a FamilyAny desired connlimit rule
// (the natural shape: no address, so no family is implied) never matches its own
// read-back and Sync removes-and-re-adds it every reconcile, firing csf -r each
// time.
func TestCSFConnLimitFamilyIsAny(t *testing.T) {
	// csf.pl only installs the ip6tables CONNLIMIT rule when csf.conf's IPV6 is
	// enabled; only then does a dual-stack FamilyAny read-back (and the
	// FamilyAny-desired-rule match below) hold. See TestCSFConnLimitFamily for
	// the IPV6-disabled (stock default) case, where CONNLIMIT is IPv4-only.
	f := &CSF{ipv6Enabled: true}
	rules := f.ParseConnLimit("80;20")
	require.Len(t, rules, 1)
	require.Equal(t, FamilyAny, rules[0].Family,
		"a dual-stack CONNLIMIT entry must read back as FamilyAny when csf.conf IPV6 is on")

	desired := &Rule{Proto: TCP, Port: 80, Action: Reject, ConnLimit: &ConnLimit{Count: 20, PerSource: true}}
	require.True(t, desired.Equal(rules[0], true),
		"FamilyAny connlimit must equal the CSF read-back or Sync churns")
}

// A port-only reject (no address) must be written so csf actually enforces it.
// csf's advanced-rule handler only emits an iptables rule when the line carries a
// source/destination IP alongside the port, so a bare "d=80" was parsed by csf
// and then silently never applied — the port stayed open while the library
// reported it blocked. The rule must be written with the "any" network as the
// address (so csf enforces it) and must still round-trip and remove: parseAddr
// normalizes the "any" network back to an empty address, and a family-neutral rule
// writes one line per family, which cover it between them.
func TestCSFPortOnlyRejectRoundTrip(t *testing.T) {
	// IPv6 enabled, so a family-neutral reject writes a line per family.
	fw := &CSF{ipv6Enabled: true}
	ctx := context.Background()

	for _, rule := range []*Rule{
		{Action: Reject, Proto: TCP, Port: 80},
		{Action: Reject, Proto: TCP, Port: 80, Family: IPv4},
		{Action: Reject, Proto: TCP, Port: 8080, Family: IPv6},
		{Action: Reject, Proto: TCP, Port: 443, Direction: DirOutput},
	} {
		deny := filepath.Join(t.TempDir(), "csf.deny")
		require.NoError(t, os.WriteFile(deny, nil, 0o644))
		require.NoError(t, fw.EditIPList(ctx, deny, Reject, rule, false))

		// The written line must carry an address, or csf never applies it.
		raw, err := os.ReadFile(deny)
		require.NoError(t, err)
		require.True(t, strings.Contains(string(raw), "0.0.0.0/0") || strings.Contains(string(raw), "::/0"),
			"port-only reject (%s) must be written with an address so csf enforces it; got:\n%s", rule.Family, raw)

		// A concrete-family rule is one line; a family-neutral one is a line per family.
		wantRows := 1
		if rule.impliedFamily() == FamilyAny {
			wantRows = 2
		}
		got, err := fw.ParseIPList(deny, Reject)
		require.NoError(t, err)
		require.Len(t, got, wantRows, "port-only reject (%s) must round-trip to %d row(s)", rule.Family, wantRows)
		require.True(t, rule.CoveredBy(got), "read-back rows must cover the written rule: %+v", got)
		for _, g := range got {
			require.True(t, rule.Covers(g), "read-back row must not widen the written rule: %+v", g)
		}

		// It must also be removable (matched back on delete).
		require.NoError(t, fw.EditIPList(ctx, deny, Reject, rule, true))
		got, err = fw.ParseIPList(deny, Reject)
		require.NoError(t, err)
		require.Len(t, got, 0, "rule (%s) must be fully removed", rule.Family)
	}
}

// A bare all-protocol host rule (address, no port) is the one portless address
// shape csf.allow/csf.deny express, written as the plain address line. The
// inexpressible shapes — a concrete-protocol host or a source+destination pair —
// are diverted to the hook by AddRule (shapeNeedsHook) and never reach this
// writer, so only the legitimate write is exercised here.
func TestCSFBareHostWritten(t *testing.T) {
	fw := new(CSF)
	ctx := context.Background()

	list := filepath.Join(t.TempDir(), "csf.allow")
	require.NoError(t, os.WriteFile(list, nil, 0o644))
	require.NoError(t, fw.EditIPList(ctx, list, Accept, &Rule{Source: "1.2.3.4", Action: Accept}, false))
	got, err := os.ReadFile(list)
	require.NoError(t, err)
	require.Contains(t, string(got), "1.2.3.4", "an any-protocol host rule must be written as a plain address")
}

// A port-only "any"-source deny is written to csf.deny as a family-specific
// placeholder line (0.0.0.0/0 for IPv4, ::/0 for IPv6). The two lines cover
// different families, so adding the IPv6 twin while the IPv4 line already exists
// must write it — EditIPList matches an existing line with EqualForDedup, so without
// the family coverage gate the IPv6 add was silently dropped as a false duplicate,
// leaving IPv6 open and making Sync churn forever.
func TestCSFCrossFamilyAdvDenyBothWritten(t *testing.T) {
	ctx := context.Background()
	fw := new(CSF)
	dir := t.TempDir()
	path := filepath.Join(dir, "csf.deny")
	require.NoError(t, os.WriteFile(path, nil, 0644))

	v4 := &Rule{Family: IPv4, Proto: TCP, Port: 80, Action: Drop}
	v6 := &Rule{Family: IPv6, Proto: TCP, Port: 80, Action: Drop}

	require.NoError(t, fw.EditIPList(ctx, path, Drop, v4, false))
	require.NoError(t, fw.EditIPList(ctx, path, Drop, v6, false))

	data, err := os.ReadFile(path)
	require.NoError(t, err)
	text := string(data)
	require.Equal(t, 1, strings.Count(text, "tcp|in|d=80|s=0.0.0.0/0"), "IPv4 deny line must be present")
	require.Equal(t, 1, strings.Count(text, "tcp|in|d=80|s=::/0"), "IPv6 deny line must be present, not dropped as a false duplicate")

	// Removing only the IPv6 twin must leave the IPv4 line intact (family-scoped
	// removal must not delete the other family's line).
	require.NoError(t, fw.EditIPList(ctx, path, Drop, v6, true))
	data, err = os.ReadFile(path)
	require.NoError(t, err)
	text = string(data)
	require.Equal(t, 1, strings.Count(text, "tcp|in|d=80|s=0.0.0.0/0"), "removing IPv6 must not drop the IPv4 line")
	require.Equal(t, 0, strings.Count(text, "tcp|in|d=80|s=::/0"), "the IPv6 line must be removed")
}

// A FamilyAny port-only deny writes both placeholder lines and must still be
// idempotent on re-add and fully removable — EditIPList's EqualForDedup/
// EqualForRemoval gate must not disturb the FamilyAny case.
func TestCSFFamilyAnyAdvDenyRoundTrip(t *testing.T) {
	ctx := context.Background()
	// IPv6 enabled, so a FamilyAny deny fans out to both placeholder lines.
	fw := &CSF{ipv6Enabled: true}
	dir := t.TempDir()
	path := filepath.Join(dir, "csf.deny")
	require.NoError(t, os.WriteFile(path, nil, 0644))

	deny := &Rule{Family: FamilyAny, Proto: TCP, Port: 22, Action: Drop}
	require.NoError(t, fw.EditIPList(ctx, path, Drop, deny, false))
	// Re-add is idempotent.
	require.NoError(t, fw.EditIPList(ctx, path, Drop, deny, false))
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, 1, strings.Count(string(data), "tcp|in|d=22|s=0.0.0.0/0"))
	require.Equal(t, 1, strings.Count(string(data), "tcp|in|d=22|s=::/0"))
	// One removal clears both family lines.
	require.NoError(t, fw.EditIPList(ctx, path, Drop, deny, true))
	data, err = os.ReadFile(path)
	require.NoError(t, err)
	require.NotContains(t, string(data), "d=22", "a FamilyAny removal must clear both placeholder lines")
}

// CSF expresses IPv4 and IPv6 opens through separate config keys (TCP_IN vs
// TCP6_IN), so a `TCP_IN="53"` + `UDP6_IN="53"` config produces a tcp/IPv4 rule and
// a udp/IPv6 rule. Those cover different families, and neither a TCPUDP/IPv4 rule nor
// its IPv6 twin may be reported as present against them — treating the pair as one
// both-transports rule drops a family's coverage and makes Sync churn forever.
func TestCSFCrossFamilyPairCoversNeitherTransportPair(t *testing.T) {
	stored := []*Rule{
		{Family: IPv4, Proto: TCP, Port: 53, Action: Accept},
		{Family: IPv6, Proto: UDP, Port: 53, Action: Accept},
	}

	require.False(t, (&Rule{Family: IPv4, Proto: TCPUDP, Port: 53, Action: Accept}).CoveredBy(stored),
		"udp/IPv6 must not stand in for the missing udp/IPv4 open")
	require.False(t, (&Rule{Family: IPv6, Proto: TCPUDP, Port: 53, Action: Accept}).CoveredBy(stored),
		"tcp/IPv4 must not stand in for the missing tcp/IPv6 open")
	require.False(t, (&Rule{Family: FamilyAny, Proto: TCPUDP, Port: 53, Action: Accept}).CoveredBy(stored))

	// Each stored rule still covers exactly its own cell.
	require.True(t, (&Rule{Family: IPv4, Proto: TCP, Port: 53, Action: Accept}).CoveredBy(stored))
	require.True(t, (&Rule{Family: IPv6, Proto: UDP, Port: 53, Action: Accept}).CoveredBy(stored))
}

// GetRules reports both the library's own rules and foreign ones, each tagged
// with HasPrefix and with the configured prefix stripped from the surfaced comment.
func TestCSFHasPrefixFlag(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "csf.allow")
	fw := &CSF{rulePrefix: "myapp"}

	require.NoError(t, os.WriteFile(path, []byte(
		"# myapp web\n"+
			"tcp|in|d=443|s=192.0.2.10\n"+
			"\n"+
			"# hand-added by an admin\n"+
			"tcp|in|d=22|s=10.0.0.0/24\n",
	), 0644))

	rules, err := fw.ParseIPList(path, Accept)
	require.NoError(t, err)
	require.Len(t, rules, 2)

	// Our rule: prefix stripped from the comment, flagged as carrying the prefix.
	require.Equal(t, "web", rules[0].Comment)
	require.True(t, rules[0].HasPrefix, "prefixed comment sets HasPrefix")

	// The admin's rule: comment surfaces unchanged, no prefix.
	require.Equal(t, "hand-added by an admin", rules[1].Comment)
	require.False(t, rules[1].HasPrefix, "a comment without the prefix is not flagged")
}

// With csf.conf's IPV6 off, csf installs no IPv6 rule from its config, so a
// family-neutral port-only deny must be written as the IPv4 line alone. An IPv6
// placeholder line would sit inert in csf.deny and read back as an IPv6 rule csf does
// not enforce and AddRule would reject. Removal still matches the target against every
// line, so a v6 line written while IPv6 was on is swept regardless.
func TestCSFPortOnlyDenyIPv6DisabledWritesV4Only(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	off := new(CSF)

	path := filepath.Join(dir, "csf.deny")
	require.NoError(t, os.WriteFile(path, nil, 0644))
	deny := &Rule{Family: FamilyAny, Proto: TCP, Port: 80, Action: Drop}
	require.NoError(t, off.EditIPList(ctx, path, Drop, deny, false))

	data, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Contains(t, string(data), "tcp|in|d=80|s=0.0.0.0/0", "the IPv4 line must be written")
	require.NotContains(t, string(data), "::/0",
		"no IPv6 line may be written while csf's IPv6 handling is off")

	// The rows read back cover the rule, and only for the family csf enforces.
	got, err := off.ParseIPList(path, Drop)
	require.NoError(t, err)
	require.Len(t, got, 1)
	require.Equal(t, IPv4, got[0].impliedFamily())

	// A rule pinned to IPv6 still writes its line: the AddRule IPv6 gate stops a
	// fresh add, and Restore bypasses that gate on purpose to reproduce a snapshot.
	v6path := filepath.Join(dir, "csf.deny.v6")
	require.NoError(t, os.WriteFile(v6path, nil, 0644))
	v6 := &Rule{Family: IPv6, Proto: TCP, Port: 80, Action: Drop}
	require.NoError(t, off.EditIPList(ctx, v6path, Drop, v6, false))
	data, err = os.ReadFile(v6path)
	require.NoError(t, err)
	require.Contains(t, string(data), "tcp|in|d=80|s=::/0")

	// Switching IPv6 off must not strand the v6 line written while it was on.
	on := &CSF{ipv6Enabled: true}
	bothPath := filepath.Join(dir, "csf.deny.both")
	require.NoError(t, os.WriteFile(bothPath, nil, 0644))
	require.NoError(t, on.EditIPList(ctx, bothPath, Drop, deny, false))
	data, err = os.ReadFile(bothPath)
	require.NoError(t, err)
	require.Contains(t, string(data), "::/0")
	require.NoError(t, off.EditIPList(ctx, bothPath, Drop, deny, true))
	data, err = os.ReadFile(bothPath)
	require.NoError(t, err)
	require.NotContains(t, string(data), "d=80",
		"removal must sweep the stale IPv6 line even with IPv6 off")
}

// A protocol-less advanced line is enforced by csf.pl as `-p tcp` (its protocol
// default), so it must read back as TCP: a ProtocolAny read-back would report an
// all-protocol rule csf does not enforce, and one whose removal the iptables
// validity check rejects.
func TestCSFAdvRuleProtocolDefaultsTCP(t *testing.T) {
	fw := new(CSF)
	r := fw.ParseAdvRule("in|d=80|s=192.0.2.1", Drop)
	require.NotNil(t, r)
	require.Equal(t, TCP, r.Proto, "csf enforces a protocol-less advanced line as tcp")
	require.EqualValues(t, 80, r.Port)
	require.Equal(t, "192.0.2.1", r.Source)
}

// csf.pl accepts a colon-delimited advanced line (converting `:` to `|` when the
// line has no pipe), so the parser must read it; an IPv6 literal keeps parsing as
// a plain address, never as a colon-delimited rule.
func TestCSFColonDelimitedAdvRule(t *testing.T) {
	fw := new(CSF)
	r := fw.parseListLine("tcp:in:d=22:s=192.0.2.1", Drop)
	require.NotNil(t, r, "a colon-delimited advanced line must parse")
	require.Equal(t, TCP, r.Proto)
	require.EqualValues(t, 22, r.Port)
	require.Equal(t, "192.0.2.1", r.Source)

	v6 := fw.parseListLine("2001:db8::7", Drop)
	require.NotNil(t, v6)
	require.Equal(t, "2001:db8::7", v6.Source, "an IPv6 literal is a plain address line")
	require.Equal(t, DirAny, v6.Direction)
}

// With csf.conf's IPV6 off, a family-agnostic port add must not touch the *6_*
// lists (their entries would be inert), a removal must still sweep them, and a
// concrete-IPv6 row written by Restore keeps its family.
func TestCSFEditRulePortIPv6Disabled(t *testing.T) {
	off := &CSF{}
	anyFam := &Rule{Proto: TCP, Port: 8080, Action: Accept}

	got := off.EditRulePort(`TCP6_IN = "22"`, "TCP6_IN", "22", anyFam, false)
	require.Equal(t, `TCP6_IN = "22"`, got, "a family-agnostic add must not touch TCP6_IN while IPv6 is off")
	got = off.EditRulePort(`TCP_IN = "22"`, "TCP_IN", "22", anyFam, false)
	require.Contains(t, got, "8080", "the IPv4 list still takes the add")

	// Removal sweeps the inert v6 entry so it does not outlive the rule.
	got = off.EditRulePort(`TCP6_IN = "22,8080"`, "TCP6_IN", "22,8080", anyFam, true)
	require.NotContains(t, got, "8080", "a removal must sweep the v6 list even with IPv6 off")

	// A concrete-IPv6 rule (Restore reproducing a snapshot) keeps its family.
	v6 := &Rule{Family: IPv6, Proto: TCP, Port: 8080, Action: Accept}
	got = off.EditRulePort(`TCP6_IN = "22"`, "TCP6_IN", "22", v6, false)
	require.Contains(t, got, "8080", "a concrete-IPv6 write keeps its family")

	on := &CSF{ipv6Enabled: true}
	got = on.EditRulePort(`TCP6_IN = "22"`, "TCP6_IN", "22", anyFam, false)
	require.Contains(t, got, "8080", "with IPv6 on the v6 list takes the add")
}

// With IPV6 off a concrete-IPv6 NAT rule is rejected outright: csf neither
// applies a v6 redirect nor flushes the v6 nat table, so neither store could
// keep the rule in sync (the NAT analog of the AddRule IPv6 gate, mirroring apf).
func TestCSFNATIPv6Gating(t *testing.T) {
	off := new(CSF)
	err := off.AddNATRule(context.Background(), "", &NATRule{Kind: DNAT, Family: IPv6, Proto: TCP, Port: 8080, ToAddress: "2001:db8::5"})
	require.ErrorIs(t, err, ErrUnsupportedNAT, "a concrete-IPv6 nat add must be rejected while IPV6 is off")
}

// csfLiveSave is a trimmed `iptables-save -c -t filter` capture from a host
// running csf, covering each shape it generates: a config port-list accept (its
// interface frame plus a NEW state match), an allow-list address in the
// per-direction ALLOW chains, a deny-list address whose outbound half jumps into
// csf's logging drop chain, and a raw pre-hook rule carrying no frame at all.
var csfLiveSave = []string{
	"*filter",
	":INPUT DROP [0:0]",
	"[9:540] -A INPUT ! -i lo -j LOCALINPUT",
	"[3:180] -A INPUT ! -i lo -p tcp -m conntrack --ctstate NEW -m tcp --dport 22 -j ACCEPT",
	"[5:300] -A INPUT ! -i lo -p tcp -m conntrack --ctstate NEW -m tcp --dport 80 -j ACCEPT",
	"[7:420] -A INPUT -p tcp -m conntrack --ctstate NEW -m tcp --dport 9100 -m comment --comment gofw -j ACCEPT",
	"[2:120] -A OUTPUT ! -o lo -p tcp -m conntrack --ctstate NEW -m tcp --dport 25 -j ACCEPT",
	"[1:60] -A ALLOWIN -s 203.0.113.5/32 ! -i lo -j ACCEPT",
	"[1:40] -A ALLOWOUT -d 203.0.113.5/32 ! -o lo -j ACCEPT",
	"[4:240] -A DENYIN -s 203.0.113.9/32 ! -i lo -j DROP",
	"[6:360] -A DENYOUT -d 203.0.113.9/32 ! -o lo -j LOGDROPOUT",
	"[6:360] -A LOGDROPOUT -j REJECT --reject-with icmp-port-unreachable",
	"COMMIT",
}

// TestCSFParseLiveRules verifies csf's own framing is undone on read: the
// interface match and the NEW state it stamps on a config rule are dropped, a
// jump into its logging drop chain is restored to the action that chain applies,
// and a pre-hook rule (which carries no frame) keeps the state it was written
// with. csf's internal chains contribute no rules of their own.
func TestCSFParseLiveRules(t *testing.T) {
	fw := new(CSF)
	rules := fw.parseLiveRules(csfLiveSave, IPv4)
	require.Len(t, rules, 8, "the LOCALINPUT jump and the LOGDROPOUT chain body model no rule")

	// A config port-list accept: framing gone, counters kept.
	require.EqualValues(t, 22, rules[0].Port)
	require.Equal(t, DirInput, rules[0].Direction)
	require.Empty(t, rules[0].InInterface, "csf's interface frame is not part of the rule")
	require.Zero(t, rules[0].State, "csf's NEW state frame is not part of the rule")
	require.EqualValues(t, 3, rules[0].Packets)

	// A pre-hook rule carries no frame, so its own state match survives.
	require.EqualValues(t, 9100, rules[2].Port)
	require.Equal(t, StateNew, rules[2].State, "a rule csf did not frame keeps the state it matches on")

	// The deny list's outbound half reads back as the action its chain ends in.
	require.Equal(t, Drop, rules[6].Action)
	require.Equal(t, Reject, rules[7].Action, "LOGDROPOUT applies csf.conf's DROP_OUT")
	require.EqualValues(t, 6, rules[7].Packets)
}

// TestCSFApplyCountersLists verifies the allow and deny lists count both halves
// of a bidirectional entry: the allow entry sums its two rows through ordinary
// coverage, and the deny entry's outbound row — which carries DROP_OUT while the
// entry reads back as DROP — is claimed by claimDenyOutRows.
func TestCSFApplyCountersLists(t *testing.T) {
	fw := new(CSF)
	live := fw.parseLiveRules(csfLiveSave, IPv4)

	allow := &Rule{Direction: DirAny, Family: IPv4, Source: "203.0.113.5", Action: Accept}
	deny := &Rule{Direction: DirAny, Family: IPv4, Source: "203.0.113.9", Action: Drop}
	port := &Rule{Direction: DirInput, Family: IPv4, Proto: TCP, Port: 22, Action: Accept}
	targets := []*Rule{allow, deny, port}

	leftover := applyLiveCounters(targets, live)
	fw.claimDenyOutRows(targets, leftover)

	require.EqualValues(t, 3, port.Packets, "a config port rule counts its framed row")
	require.EqualValues(t, 2, allow.Packets, "a bidirectional allow sums its ALLOWIN and ALLOWOUT rows")
	require.EqualValues(t, 100, allow.Bytes)
	require.EqualValues(t, 10, deny.Packets, "a bidirectional deny sums its DENYIN and DENYOUT rows")
	require.EqualValues(t, 600, deny.Bytes)
}

// TestCSFClaimDenyOutRowsIsScoped verifies the outbound-deny claim does not
// absorb a row belonging to a different entry: it must still match every field
// but the action, and it only applies to a bidirectional rule.
func TestCSFClaimDenyOutRowsIsScoped(t *testing.T) {
	fw := new(CSF)
	other := &Rule{Direction: DirAny, Family: IPv4, Source: "198.51.100.1", Action: Drop}
	oneWay := &Rule{Direction: DirOutput, Family: IPv4, Destination: "203.0.113.9", Action: Reject}
	leftover := []*Rule{
		{Direction: DirOutput, Family: IPv4, Destination: "203.0.113.9", Action: Reject, Packets: 6, Bytes: 360},
	}
	fw.claimDenyOutRows([]*Rule{other, oneWay}, leftover)

	require.Zero(t, other.Packets, "an unrelated deny entry must not absorb the row")
	require.Zero(t, oneWay.Packets, "a one-way deny matches on identity and is not claimed here")
}
