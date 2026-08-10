package firewall

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAPFAdvRules(t *testing.T) {
	fw := new(APF)

	// Advanced-rule encodings, including underscore ranges and bracketed IPv6.
	cases := []struct {
		rule *Rule
		want string
	}{
		{&Rule{Proto: TCP, Port: 22, Source: "192.168.2.1", Family: IPv4, Action: Accept}, "tcp:in:d=22:s=192.168.2.1"},
		{&Rule{Proto: TCP, Ports: []PortRange{{Start: 6000, End: 7000}}, Source: "192.168.5.0/24", Family: IPv4, Action: Accept}, "tcp:in:d=6000_7000:s=192.168.5.0/24"},
		{&Rule{Proto: TCP, Port: 443, Source: "2001:db8::/32", Family: IPv6, Action: Accept}, "tcp:in:d=443:s=[2001:db8::/32]"},
		{&Rule{Direction: DirOutput, Proto: UDP, Port: 53, Destination: "192.0.2.1", Family: IPv4, Action: Accept}, "udp:out:d=53:d=192.0.2.1"},
	}
	for _, c := range cases {
		got := fw.MarshalAdvRule(c.rule)
		require.Equal(t, c.want, got, "marshal %+v", *c.rule)

		parsed := fw.ParseAdvRule(got, c.rule.Action)
		require.NotNil(t, parsed, "failed to parse %q", got)
		require.True(t, parsed.Equal(c.rule, true),
			"round-trip mismatch: input %+v, line %q, output %+v", *c.rule, got, parsed)
	}

	// A bracketed IPv6 host address parses back without brackets.
	r := fw.ParseAdvRule("tcp:in:d=443:s=[2001:db8::1]", Accept)
	require.NotNil(t, r)
	require.Equal(t, "2001:db8::1", r.Source)
	require.Equal(t, IPv6, r.Family)
	require.EqualValues(t, 443, r.Port)
}

// A port-only deny whose action is Drop (conf.apf's default ALL_STOP=DROP) must
// still be written to deny_hosts. The placeholder branch keys on "not an accept",
// not on Reject, so a Drop deny is written rather than skipped while AddRule
// reports success and leaves the port open.
func TestAPFPortOnlyDropDenyIsWritten(t *testing.T) {
	ctx := context.Background()
	fw := new(APF)
	dir := t.TempDir()
	path := filepath.Join(dir, "deny_hosts.rules")
	require.NoError(t, os.WriteFile(path, nil, 0644))

	drop := &Rule{Family: IPv4, Proto: TCP, Port: 3306, Action: Drop}
	require.NoError(t, fw.EditIPList(ctx, path, Drop, drop, false))

	data, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Contains(t, string(data), "tcp:in:d=3306:s=0.0.0.0/0",
		"a port-only Drop deny must be written with the any-network placeholder")
}

func TestAPFSourcePorts(t *testing.T) {
	fw := new(APF)

	// Source ports round-trip through the s= port-flow field (single port and
	// underscore range).
	cases := []struct {
		rule *Rule
		want string
	}{
		{&Rule{Proto: TCP, SourcePort: 1234, Destination: "192.0.2.1", Family: IPv4, Action: Accept}, "tcp:in:s=1234:d=192.0.2.1"},
		{&Rule{Proto: UDP, SourcePorts: []PortRange{{Start: 1024, End: 2048}}, Source: "192.0.2.1", Family: IPv4, Action: Accept}, "udp:in:s=1024_2048:s=192.0.2.1"},
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

func TestAPFConnLimit(t *testing.T) {
	fw := new(APF)

	// IG_TCP_CLIMIT parses into per-port reject rules with a per-source cap; an
	// underscore port range is preserved.
	rules := fw.ParseConnLimit("80:50,8080_8090:25", TCP)
	require.Len(t, rules, 2)
	require.Equal(t, Reject, rules[0].Action)
	require.EqualValues(t, 80, rules[0].Port)
	require.NotNil(t, rules[0].ConnLimit)
	require.EqualValues(t, 50, rules[0].ConnLimit.Count)
	require.True(t, rules[0].ConnLimit.PerSource)
	require.Len(t, rules[1].Ports, 1)
	require.Equal(t, PortRange{Start: 8080, End: 8090}, rules[1].Ports[0])

	// Editing adds a range entry and removes a port entry.
	added := fw.editConnLimit("IG_TCP_CLIMIT", "80:50",
		&Rule{Proto: TCP, Ports: []PortRange{{Start: 8080, End: 8090}}, Action: Reject, ConnLimit: &ConnLimit{Count: 25, PerSource: true}}, false)
	require.Equal(t, `IG_TCP_CLIMIT="80:50,8080_8090:25"`, added)
	removed := fw.editConnLimit("IG_TCP_CLIMIT", "80:50,443:100",
		&Rule{Proto: TCP, Port: 443, Action: Reject, ConnLimit: &ConnLimit{Count: 100, PerSource: true}}, true)
	require.Equal(t, `IG_TCP_CLIMIT="80:50"`, removed)
}

func TestAPFPortAndICMPConfig(t *testing.T) {
	fw := new(APF)

	// Port lists parse single ports and underscore ranges.
	rules := fw.ParsePorts("21,22,6000_7000", TCP, DirInput)
	require.Len(t, rules, 3, "expected 3 port rules")
	require.Len(t, rules[2].Ports, 1)
	require.Equal(t, PortRange{Start: 6000, End: 7000}, rules[2].Ports[0],
		"expected a 6000-7000 range rule")

	// ICMP type lists become ICMP rules, one per type.
	icmp := fw.ParseICMPTypes("3,5,8", ICMP, DirInput)
	require.Len(t, icmp, 3, "expected 3 icmp rules")
	require.Equal(t, ICMP, icmp[2].Proto)
	require.NotNil(t, icmp[2].ICMPType, "expected icmp type 8 rule, got %+v", *icmp[2])
	require.EqualValues(t, 8, *icmp[2].ICMPType, "expected icmp type 8 rule")

	// EditRulePort adds a range token to the matching port list.
	got := fw.EditRulePort(`IG_TCP_CPORTS="22"`, "IG_TCP_CPORTS", "22",
		&Rule{Proto: TCP, Ports: []PortRange{{Start: 6000, End: 7000}}, Action: Accept}, false)
	require.Equal(t, `IG_TCP_CPORTS="22,6000_7000"`, got, "unexpected port edit")

	// EditRulePort adds an ICMP type to the icmp type list.
	got = fw.EditRulePort(`IG_ICMP_TYPES="3,5"`, "IG_ICMP_TYPES", "3,5",
		&Rule{Proto: ICMP, ICMPType: Ptr[uint8](8), Action: Accept}, false)
	require.Equal(t, `IG_ICMP_TYPES="3,5,8"`, got, "unexpected icmp edit")
}

// TestAPFICMPNamedTypeReconcile guards ICMP-type reconciliation against a conf.apf
// list that spells a type by name (e.g. "echo-request") rather than its number.
// The read path resolves names to numbers, so removal/add must compare by resolved
// number or a foreign name-based entry can never be removed (Sync never converges)
// and an add would append a numeric duplicate.
func TestAPFICMPNamedTypeReconcile(t *testing.T) {
	// Removing ICMP type 8 must clear a name-based "echo-request" entry.
	fw := new(APF)
	got := fw.EditRulePort(`IG_ICMP_TYPES="echo-request"`, "IG_ICMP_TYPES", "echo-request",
		&Rule{Proto: ICMP, ICMPType: Ptr[uint8](8), Action: Accept}, true)
	require.Equal(t, `IG_ICMP_TYPES=""`, got, "a name-based echo-request entry must be removed for type 8")
	require.True(t, fw.ConfigChanged, "the config must be marked changed when the entry is removed")

	// Adding type 8 when "echo-request" is already present must not duplicate it.
	fw = new(APF)
	got = fw.EditRulePort(`IG_ICMP_TYPES="echo-request"`, "IG_ICMP_TYPES", "echo-request",
		&Rule{Proto: ICMP, ICMPType: Ptr[uint8](8), Action: Accept}, false)
	require.Equal(t, `IG_ICMP_TYPES="echo-request"`, got, "adding a type already present by name must not duplicate")
	require.False(t, fw.ConfigChanged, "no change when the type is already present by name")

	// The same holds for ICMPv6, resolved through the ICMPv6 name table (128).
	fw = new(APF)
	got = fw.EditRulePort(`IG_ICMPV6_TYPES="echo-request"`, "IG_ICMPV6_TYPES", "echo-request",
		&Rule{Proto: ICMPv6, ICMPType: Ptr[uint8](128), Action: Accept}, true)
	require.Equal(t, `IG_ICMPV6_TYPES=""`, got, "a name-based ICMPv6 echo-request entry must be removed for type 128")
}

// apf carries ICMPv6 types and the "all" wildcard natively; both must round-trip
// through the conf.apf type lists and stay off the raw-iptables hook.
func TestAPFICMPv6AndAllWildcard(t *testing.T) {
	fw := new(APF)

	// IG_ICMPV6_TYPES parses to IPv6 ICMPv6 accepts, one per type.
	v6 := fw.ParseICMPTypes("1,2,128,129", ICMPv6, DirInput)
	require.Len(t, v6, 4)
	require.Equal(t, ICMPv6, v6[3].Proto)
	require.Equal(t, IPv6, v6[3].Family)
	require.EqualValues(t, 129, *v6[3].ICMPType)

	// The "all" wildcard parses to a typeless (all-types) accept.
	all := fw.ParseICMPTypes("all", ICMP, DirOutput)
	require.Len(t, all, 1)
	require.Nil(t, all[0].ICMPType, "'all' must be an all-types rule")
	require.True(t, all[0].IsOutput())

	// Writing an ICMPv6 type into its native list.
	got := fw.EditRulePort(`IG_ICMPV6_TYPES="1,2"`, "IG_ICMPV6_TYPES", "1,2",
		&Rule{Proto: ICMPv6, ICMPType: Ptr[uint8](128), Action: Accept}, false)
	require.Equal(t, `IG_ICMPV6_TYPES="1,2,128"`, got)

	// Writing the "all" wildcard for a typeless ICMP accept.
	got = fw.EditRulePort(`EG_ICMP_TYPES=""`, "EG_ICMP_TYPES", "",
		&Rule{Proto: ICMP, Direction: DirOutput, Action: Accept}, false)
	require.Equal(t, `EG_ICMP_TYPES="all"`, got)

	// A native ICMPv6 accept is routed to conf.apf, not the hook.
	require.True(t, fw.nativeICMPv6(&Rule{Proto: ICMPv6, ICMPType: Ptr[uint8](128), Action: Accept}))
	require.True(t, fw.isConfRule(&Rule{Proto: ICMPv6, ICMPType: Ptr[uint8](128), Action: Accept}))
	// An ICMPv6 rule that also needs state matching stays on the hook path.
	require.False(t, fw.nativeICMPv6(&Rule{Proto: ICMPv6, ICMPType: Ptr[uint8](128), State: StateEstablished, Action: Accept}))
}

func TestAPFIPListComment(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "allow_hosts.rules")
	fw := &APF{rulePrefix: "myapp"}
	ctx := context.Background()

	require.NoError(t, os.WriteFile(path, []byte(
		"# myapp trusted office\n"+
			"tcp:in:d=22:s=10.0.0.0/24\n"+
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
	require.Contains(t, string(data), "tcp:in:d=443:s=192.0.2.10")

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
	headerPath := filepath.Join(dir, "header_allow_hosts.rules")
	require.NoError(t, os.WriteFile(headerPath, []byte(
		"# This is the apf allow_hosts.rules file.\n"+
			"# Add hosts/rules below, one per line.\n"+
			"# Format: proto:flow:port:ip\n",
	), 0644))
	appendRule := &Rule{Proto: TCP, Port: 3456, Source: "192.0.2.10/32", Action: Accept}
	require.NoError(t, fw.EditIPList(ctx, headerPath, Accept, appendRule, false))
	parsed, err := fw.ParseIPList(headerPath, Accept)
	require.NoError(t, err)
	require.Len(t, parsed, 1)
	require.True(t, parsed[0].HasPrefix, "rule after header comments must be flagged with the prefix")
	require.Equal(t, "", parsed[0].Comment)
}

// TestAPFRemovePreservesForeignHeader verifies that removing a managed rule keeps
// a foreign section header sitting directly above its prefix tag. ParseIPList
// treats the tag as starting a fresh comment block, so the header is not part of
// the rule's comment; removal must mirror that and not delete it.
func TestAPFRemovePreservesForeignHeader(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "allow_hosts.rules")
	fw := &APF{rulePrefix: "myapp"}
	ctx := context.Background()

	require.NoError(t, os.WriteFile(path, []byte(
		"# Section: web servers\n"+
			"# myapp trusted\n"+
			"tcp:in:d=22:s=192.0.2.50/32\n",
	), 0644))

	require.NoError(t, fw.EditIPList(ctx, path, Accept, &Rule{Proto: TCP, Port: 22, Source: "192.0.2.50/32", Action: Accept}, true))
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	got := string(data)
	require.NotContains(t, got, "tcp:in:d=22", "the managed rule must be removed")
	require.NotContains(t, got, "# myapp trusted", "the rule's own tag comment is removed with it")
	require.Contains(t, got, "# Section: web servers", "the foreign section header must be preserved")
}

// conf.apf's ALL_STOP accepts DROP, REJECT and PROHIBIT (upstream apf builds a
// dedicated PROHIBIT chain that rejects with an ICMP prohibited response). This
// model has no third action, so PROHIBIT must map to Reject like REJECT does,
// not silently fall into the DROP default alongside genuinely unrecognized
// values.
func TestAPFParseStopAction(t *testing.T) {
	fw := new(APF)
	cases := []struct {
		val  string
		want Action
	}{
		{"DROP", Drop},
		{"REJECT", Reject},
		{"PROHIBIT", Reject},
		{"prohibit", Reject},
		{`"PROHIBIT"`, Reject},
		{"", Drop},
		{"BOGUS", Drop},
	}
	for _, c := range cases {
		require.Equal(t, c.want, fw.parseStopAction(c.val), "ALL_STOP=%q", c.val)
	}
}

// conf.apf's ALL_STOP, TCP_STOP and UDP_STOP are independent settings (upstream
// apf_validate.sh validates each separately with no equality constraint, and
// they may be set differently on a real host). readStopAction/stopKey must
// read the setting matching a deny's protocol, not conflate them, so a fixture
// where they diverge is read back correctly.
func TestAPFReadStopActionIndependentSettings(t *testing.T) {
	fw := new(APF)
	dir := t.TempDir()
	conf := filepath.Join(dir, "conf.apf")
	require.NoError(t, os.WriteFile(conf, []byte("ALL_STOP=\"DROP\"\nTCP_STOP=\"REJECT\"\nUDP_STOP=\"DROP\"\n"), 0o644))

	require.Equal(t, Drop, fw.readStopAction(conf, "ALL_STOP"))
	require.Equal(t, Reject, fw.readStopAction(conf, "TCP_STOP"))
	require.Equal(t, Drop, fw.readStopAction(conf, "UDP_STOP"))

	require.Equal(t, "ALL_STOP", fw.stopKey(ProtocolAny))
	require.Equal(t, "TCP_STOP", fw.stopKey(TCP))
	require.Equal(t, "UDP_STOP", fw.stopKey(UDP))
}

// APF's IG_*_CPORTS lists are dual-stack (one list applied to both v4 and v6), so
// a port rule read from them must be FamilyAny, not IPv4. Otherwise a FamilyAny
// desired rule (the default) never matches its own read-back and Sync churns.
func TestAPFPortListFamilyIsAny(t *testing.T) {
	f := new(APF)
	rules := f.ParsePorts("22", TCP, DirInput)
	require.Len(t, rules, 1)
	require.Equal(t, FamilyAny, rules[0].Family,
		"a dual-stack CPORTS entry must read back as FamilyAny")

	// End to end: a default (FamilyAny) desired rule equals its read-back.
	desired := &Rule{Proto: TCP, Port: 22, Action: Accept}
	require.True(t, desired.Equal(rules[0], true),
		"FamilyAny tcp/22 must equal the APF read-back or Sync churns")
}

// APF's IG_*_CLIMIT lists are likewise dual-stack, so a connection-limit rule
// read from them must be FamilyAny to reconcile with a FamilyAny desired rule.
func TestAPFConnLimitFamilyIsAny(t *testing.T) {
	f := new(APF)
	rules := f.ParseConnLimit("80:50", TCP)
	require.Len(t, rules, 1)
	require.Equal(t, FamilyAny, rules[0].Family,
		"a dual-stack CLIMIT entry must read back as FamilyAny")

	desired := &Rule{Proto: TCP, Port: 80, Action: Reject, ConnLimit: &ConnLimit{Count: 50, PerSource: true}}
	require.True(t, desired.Equal(rules[0], true),
		"FamilyAny connlimit must equal the APF read-back or Sync churns")
}

// A port-only deny must not corrupt the rule's family. apf requires an address
// field, so it writes an "any" placeholder matching the rule's family. A
// family-neutral rule writes one line per family: two rows that cover the rule
// between them.
//
// The rule action is Drop, not Reject: a tcp port-carrying deny_hosts entry is an
// apf "advanced" entry, which apf routes through TCP_STOP (not ALL_STOP) — Drop is
// the stock default for both, and is the value denyActionFor actually resolves
// to here since no real conf.apf exists in this test environment. Using an action
// apf would not actually apply to this entry would make EditIPList reject it.
func TestAPFPortOnlyRejectFamily(t *testing.T) {
	// IPv6 enabled, so a family-neutral deny fans out to both families (see filterFamiliesIPv6).
	fw := &APF{ipv6Enabled: true}
	ctx := context.Background()
	for _, rule := range []*Rule{
		{Action: Drop, Proto: TCP, Port: 80},
		{Action: Drop, Proto: TCP, Port: 80, Family: IPv4},
		{Action: Drop, Proto: TCP, Port: 8080, Family: IPv6},
	} {
		deny := filepath.Join(t.TempDir(), "deny_hosts.rules")
		require.NoError(t, os.WriteFile(deny, nil, 0o644))
		require.NoError(t, fw.EditIPList(ctx, deny, Drop, rule, false))

		// A concrete-family rule is one line; a family-neutral one is a line per family.
		// Either way the rows read back cover exactly the rule that was written.
		wantRows := 1
		if rule.impliedFamily() == FamilyAny {
			wantRows = 2
		}
		got, err := fw.ParseIPList(deny, Drop)
		require.NoError(t, err)
		require.Len(t, got, wantRows, "port-only deny (%s) must round-trip to %d row(s)", rule.Family, wantRows)
		require.True(t, rule.CoveredBy(got), "read-back rows must cover the written rule; want family=%s", rule.Family)
		for _, g := range got {
			require.True(t, rule.Covers(g), "read-back row must not widen the written rule: %+v", g)
		}

		// It must also be removable (matched back on delete).
		require.NoError(t, fw.EditIPList(ctx, deny, Drop, rule, true))
		got, err = fw.ParseIPList(deny, Drop)
		require.NoError(t, err)
		require.Len(t, got, 0, "rule (%s) must be fully removed", rule.Family)
	}
}

// A port-only deny fans out across family, but the file may already hold a subset of
// those lines — a prior single-family add, a manual edit, or the same rule added
// twice by a reconcile. The add must note each fan-out line present and write only
// the rest. A single-"exists" gate does not cover a family-neutral target: one line
// present must not count as the whole rule, and a present IPv4 line must not leave
// the IPv6 twin unwritten.
func TestAPFPortOnlyDenyHealsAndDoesNotDuplicate(t *testing.T) {
	ctx := context.Background()
	// IPv6 enabled, so the deny fans out to an IPv4 and an IPv6 line.
	fw := &APF{ipv6Enabled: true}
	dir := t.TempDir()

	// Adding the same family-neutral deny twice must leave one line per family.
	path := filepath.Join(dir, "deny_hosts.rules")
	require.NoError(t, os.WriteFile(path, nil, 0o644))
	deny := &Rule{Family: FamilyAny, Proto: TCP, Port: 80, Action: Drop}
	require.NoError(t, fw.EditIPList(ctx, path, Drop, deny, false))
	require.NoError(t, fw.EditIPList(ctx, path, Drop, deny, false))

	data, err := os.ReadFile(path)
	require.NoError(t, err)
	text := string(data)
	require.Equal(t, 1, strings.Count(text, "tcp:in:d=80:s=0.0.0.0/0"),
		"re-adding the rule must not duplicate the IPv4 line")
	require.Equal(t, 1, strings.Count(text, "tcp:in:d=80:s=[::/0]"),
		"re-adding the rule must not duplicate the IPv6 line")

	// A file holding only the IPv4 line must gain the missing IPv6 one, so IPv6:80 is
	// actually blocked rather than reported blocked while open.
	path2 := filepath.Join(dir, "deny_hosts2.rules")
	require.NoError(t, os.WriteFile(path2, []byte("tcp:in:d=80:s=0.0.0.0/0\n"), 0o644))
	require.NoError(t, fw.EditIPList(ctx, path2, Drop, deny, false))

	data2, err := os.ReadFile(path2)
	require.NoError(t, err)
	text2 := string(data2)
	require.Equal(t, 1, strings.Count(text2, "tcp:in:d=80:s=0.0.0.0/0"),
		"the pre-existing IPv4 line must be preserved, not duplicated")
	require.Equal(t, 1, strings.Count(text2, "tcp:in:d=80:s=[::/0]"),
		"the missing IPv6 line must be added")
}

// A bare all-protocol host rule (address, no port) is the one portless address
// shape apf's trust files express, written as the plain address line. The
// inexpressible shapes — a concrete-protocol host or a source+destination pair —
// are diverted to the hook by AddRule (shapeNeedsHook) and never reach this
// writer, so only the legitimate write is exercised here.
func TestAPFBareHostWritten(t *testing.T) {
	fw := new(APF)
	ctx := context.Background()

	list := filepath.Join(t.TempDir(), "allow_hosts.rules")
	require.NoError(t, os.WriteFile(list, nil, 0o644))
	require.NoError(t, fw.EditIPList(ctx, list, Accept, &Rule{Source: "1.2.3.4", Action: Accept}, false))
	got, err := os.ReadFile(list)
	require.NoError(t, err)
	require.Contains(t, string(got), "1.2.3.4", "an any-protocol host rule must be written as a plain address")
}

// TestAPFMultiPortRemovalSweepsCPortsTokens covers removal of a multi-port
// accept against a conf.apf CPORTS list: the rule lives in the hook now, but an
// earlier per-port add (or a manual edit) may hold the same ports as list
// tokens, so removeFamilyAnyPort's EditConf sweep must strip exactly the
// target's tokens and no others.
func TestAPFMultiPortRemovalSweepsCPortsTokens(t *testing.T) {
	fw := new(APF)
	target := &Rule{Proto: TCP, Ports: []PortRange{{Start: 80, End: 80}, {Start: 443, End: 443}}, Action: Accept}
	require.Equal(t, `IG_TCP_CPORTS="22"`,
		fw.EditRulePort(`IG_TCP_CPORTS="22,80,443"`, "IG_TCP_CPORTS", "22,80,443", target, true),
		"a multi-port removal must strip each of its own port tokens and keep the rest")
}

// APF EditIPList must write the missing IPv6 line when adding the IPv6 twin of an
// existing IPv4 port-only deny; the family-specific EqualBase check must not
// treat the IPv4 line as covering IPv6 and write nothing, leaving IPv6 open.
func TestAPFCrossFamilyDenyAddsMissingFamily(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "deny_hosts.rules")
	require.NoError(t, os.WriteFile(path, []byte("tcp:in:d=80:s=0.0.0.0/0\n"), 0o644))

	f := &APF{}
	r := &Rule{Proto: TCP, Port: 80, Direction: DirInput, Family: IPv6, Action: Drop}
	require.NoError(t, f.EditIPList(context.Background(), path, Drop, r, false))

	out, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Contains(t, string(out), "::", "an IPv6 (::/0) deny line must be written so IPv6 port 80 is blocked")
	require.Contains(t, string(out), "0.0.0.0/0", "the existing IPv4 deny must be preserved")
}

// APF RemoveRule of an IPv4-pinned port-only deny must not take out the IPv6 twin:
// EqualForRemoval gates the family so removing one family keeps the other.
func TestAPFCrossFamilyRemoveKeepsOppositeFamily(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "deny_hosts.rules")
	require.NoError(t, os.WriteFile(path, []byte("tcp:in:d=80:s=0.0.0.0/0\ntcp:in:d=80:s=[::/0]\n"), 0o644))

	f := &APF{}
	// Remove only the IPv4 port-80 deny.
	r := &Rule{Proto: TCP, Port: 80, Direction: DirInput, Family: IPv4, Action: Drop}
	require.NoError(t, f.EditIPList(context.Background(), path, Drop, r, true))

	out, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Contains(t, string(out), "[::/0]", "the IPv6 deny must survive removing the IPv4 twin")
	require.NotContains(t, string(out), "0.0.0.0/0", "the IPv4 deny must be removed")
}

// Editing an existing connection-limit entry's count must record a config change
// so Reload runs apf --restart and the new limit is applied; an unchanged count
// must not trigger a spurious restart.
func TestAPFConnLimitCountChangeReloads(t *testing.T) {
	fw := new(APF)

	// Changing the count from 50 to 25 must flag a config change.
	fw.ConfigChanged = false
	out := fw.editConnLimit("IG_TCP_CLIMIT", "80:50",
		&Rule{Proto: TCP, Port: 80, Action: Reject, ConnLimit: &ConnLimit{Count: 25, PerSource: true}}, false)
	require.Equal(t, `IG_TCP_CLIMIT="80:25"`, out)
	require.True(t, fw.ConfigChanged, "a changed connlimit count must set ConfigChanged")

	// Re-applying the same count must not flag a change.
	fw.ConfigChanged = false
	out = fw.editConnLimit("IG_TCP_CLIMIT", "80:25",
		&Rule{Proto: TCP, Port: 80, Action: Reject, ConnLimit: &ConnLimit{Count: 25, PerSource: true}}, false)
	require.Equal(t, `IG_TCP_CLIMIT="80:25"`, out)
	require.False(t, fw.ConfigChanged, "an unchanged connlimit count must not set ConfigChanged")
}

// TestAPFTCPUDPCPortsFanOut covers the write half of the both-transports port accept:
// conf.apf's CPORTS lists are per-transport, so a TCPUDP port must be added to (and
// removed from) both. EditRulePort must key a TCPUDP rule into both the TCP and UDP
// lists, not match neither and leave the port unopened.
func TestAPFTCPUDPCPortsFanOut(t *testing.T) {
	fw := new(APF)
	r := &Rule{Proto: TCPUDP, Port: 80, Action: Accept, Direction: DirInput}

	require.Equal(t, `IG_TCP_CPORTS="22,80"`,
		fw.EditRulePort(`IG_TCP_CPORTS="22"`, "IG_TCP_CPORTS", "22", r, false),
		"a tcpudp port must be added to the tcp list")
	require.Equal(t, `IG_UDP_CPORTS="53,80"`,
		fw.EditRulePort(`IG_UDP_CPORTS="53"`, "IG_UDP_CPORTS", "53", r, false),
		"a tcpudp port must be added to the udp list")

	// Removal clears it from both lists.
	require.Equal(t, `IG_TCP_CPORTS="22"`,
		fw.EditRulePort(`IG_TCP_CPORTS="22,80"`, "IG_TCP_CPORTS", "22,80", r, true))
	require.Equal(t, `IG_UDP_CPORTS="53"`,
		fw.EditRulePort(`IG_UDP_CPORTS="53,80"`, "IG_UDP_CPORTS", "53,80", r, true))

	// A concrete transport still touches only its own list.
	tcp := &Rule{Proto: TCP, Port: 80, Action: Accept, Direction: DirInput}
	require.Equal(t, `IG_UDP_CPORTS="53"`,
		fw.EditRulePort(`IG_UDP_CPORTS="53"`, "IG_UDP_CPORTS", "53", tcp, false),
		"a tcp rule must not open the udp port")

	// An outbound rule touches only the egress lists.
	out := &Rule{Proto: TCPUDP, Port: 80, Action: Accept, Direction: DirOutput}
	require.Equal(t, `IG_TCP_CPORTS="22"`,
		fw.EditRulePort(`IG_TCP_CPORTS="22"`, "IG_TCP_CPORTS", "22", out, false))
	require.Equal(t, `EG_TCP_CPORTS="22,80"`,
		fw.EditRulePort(`EG_TCP_CPORTS="22"`, "EG_TCP_CPORTS", "22", out, false))
}

// TestAPFTCPUDPCPortsReadBack covers the read half: apf's CPORTS lists are keyed per
// transport, so a TCPUDP port is one entry in each and reads back as one rule per
// list — two dual-stack rules that together cover the TCPUDP rule that was written.
// A port in only one list covers only its own transport.
func TestAPFTCPUDPCPortsReadBack(t *testing.T) {
	fw := new(APF)
	rules := append(fw.ParsePorts("80", TCP, DirInput), fw.ParsePorts("80", UDP, DirInput)...)
	require.Len(t, rules, 2, "the two lists parse independently")
	for _, r := range rules {
		require.Equal(t, FamilyAny, r.Family, "a CPORTS entry is dual-stack")
	}

	both := &Rule{Proto: TCPUDP, Port: 80, Action: Accept, Direction: DirInput}
	require.True(t, both.CoveredBy(rules), "the tcp+udp CPORTS entries cover the TCPUDP rule")

	// A port in only one list leaves the other transport uncovered.
	tcpOnly := fw.ParsePorts("80", TCP, DirInput)
	require.Len(t, tcpOnly, 1)
	require.Equal(t, TCP, tcpOnly[0].Proto)
	require.False(t, both.CoveredBy(tcpOnly), "the tcp entry alone must not cover a TCPUDP rule")
	require.True(t, (&Rule{Proto: TCP, Port: 80, Action: Accept, Direction: DirInput}).CoveredBy(tcpOnly))
}

// TestAPFTCPUDPAdvRule: apf's advanced rule treats a missing protocol field as both
// transports (its trust parser derives a -p tcp and a -p udp rule from it), so TCPUDP
// is written by omitting the field and must read back as TCPUDP — never ProtocolAny,
// which would claim every IP protocol is matched.
func TestAPFTCPUDPAdvRule(t *testing.T) {
	fw := new(APF)
	r := &Rule{Proto: TCPUDP, Port: 80, Source: "192.0.2.1", Action: Accept, Direction: DirInput}

	line := fw.MarshalAdvRule(r)
	require.Equal(t, "in:d=80:s=192.0.2.1", line, "the protocol field is omitted for both transports")

	back := fw.ParseAdvRule(line, Accept)
	require.NotNil(t, back)
	require.Equal(t, TCPUDP, back.Proto, "a protocol-less advanced line is tcp+udp, not every protocol")
	require.True(t, back.EqualBase(r, true))

	// A concrete transport names itself and round-trips unchanged.
	line = fw.MarshalAdvRule(&Rule{Proto: TCP, Port: 80, Source: "192.0.2.1", Action: Accept})
	require.Equal(t, "tcp:in:d=80:s=192.0.2.1", line)
	require.Equal(t, TCP, fw.ParseAdvRule(line, Accept).Proto)
}

// With conf.apf's USE_IPV6 off, apf installs no IPv6 rule from its config, so a
// family-neutral port-only deny must be written as the IPv4 line alone (see
// filterFamiliesIPv6). Removal still sweeps both families.
func TestAPFPortOnlyDenyIPv6DisabledWritesV4Only(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	off := new(APF)

	path := filepath.Join(dir, "deny_hosts.rules")
	require.NoError(t, os.WriteFile(path, nil, 0o644))
	deny := &Rule{Family: FamilyAny, Proto: TCP, Port: 80, Action: Drop}
	require.NoError(t, off.EditIPList(ctx, path, Drop, deny, false))

	data, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Contains(t, string(data), "tcp:in:d=80:s=0.0.0.0/0", "the IPv4 line must be written")
	require.NotContains(t, string(data), "[::/0]",
		"no IPv6 line may be written while apf's IPv6 handling is off")

	got, err := off.ParseIPList(path, Drop)
	require.NoError(t, err)
	require.Len(t, got, 1)
	require.Equal(t, IPv4, got[0].impliedFamily())

	// Switching IPv6 off must not strand the v6 line written while it was on.
	on := &APF{ipv6Enabled: true}
	bothPath := filepath.Join(dir, "deny_hosts.both.rules")
	require.NoError(t, os.WriteFile(bothPath, nil, 0o644))
	require.NoError(t, on.EditIPList(ctx, bothPath, Drop, deny, false))
	data, err = os.ReadFile(bothPath)
	require.NoError(t, err)
	require.Contains(t, string(data), "[::/0]")
	require.NoError(t, off.EditIPList(ctx, bothPath, Drop, deny, true))
	data, err = os.ReadFile(bothPath)
	require.NoError(t, err)
	require.NotContains(t, string(data), "d=80",
		"removal must sweep the stale IPv6 line even with IPv6 off")
}

// With USE_IPV6 off a family-agnostic NAT rule is written for IPv4 only and a
// concrete-IPv6 one is rejected outright; removal still sweeps both families so
// a stale v6 line does not survive an IPv6 switch-off.
func TestAPFNATIPv6Gating(t *testing.T) {
	off := new(APF)
	masq := &NATRule{Kind: Masquerade, Interface: "eth0"}
	rows := filterNATFamiliesIPv6(false, masq)
	require.Len(t, rows, 1, "a family-agnostic write must narrow to IPv4 while IPv6 is off")
	require.Equal(t, IPv4, rows[0].impliedFamily())
	// Removal still sweeps both families: the family-agnostic target covers the
	// stale IPv6 line through EqualForRemoval's family check.
	v6 := *masq
	v6.Family = IPv6
	require.True(t, v6.EqualForRemoval(masq), "removal must still cover the IPv6 line")

	err := off.AddNATRule(context.Background(), "", &NATRule{Kind: DNAT, Family: IPv6, Proto: TCP, Port: 8080, ToAddress: "2001:db8::5"})
	require.ErrorIs(t, err, ErrUnsupportedNAT, "a concrete-IPv6 nat add must be rejected while IPv6 is off")

	rows = filterNATFamiliesIPv6(true, masq)
	require.Len(t, rows, 2, "with IPv6 on a family-agnostic write fans out to both families")
}

// confKeyApplies mirrors EditRulePort's routing guards; EditConf keys its
// missing-config-line detection on it.
func TestAPFConfKeyApplies(t *testing.T) {
	fw := new(APF)
	port := &Rule{Proto: TCP, Port: 80, Action: Accept}
	require.True(t, fw.confKeyApplies("IG_TCP_CPORTS", port))
	require.False(t, fw.confKeyApplies("IG_UDP_CPORTS", port))
	require.False(t, fw.confKeyApplies("EG_TCP_CPORTS", port))

	both := &Rule{Proto: TCPUDP, Port: 53, Action: Accept}
	require.True(t, fw.confKeyApplies("IG_TCP_CPORTS", both))
	require.True(t, fw.confKeyApplies("IG_UDP_CPORTS", both))

	icmp6 := &Rule{Proto: ICMPv6, ICMPType: Ptr[uint8](128), Action: Accept}
	require.True(t, fw.confKeyApplies("IG_ICMPV6_TYPES", icmp6))
	require.False(t, fw.confKeyApplies("IG_ICMP_TYPES", icmp6))

	climit := &Rule{Proto: TCP, Port: 80, Action: Reject, ConnLimit: &ConnLimit{Count: 5, PerSource: true}}
	require.True(t, fw.confKeyApplies("IG_TCP_CLIMIT", climit))
	require.False(t, fw.confKeyApplies("IG_TCP_CPORTS", climit),
		"a connlimit rule must never touch the accept port lists")
}

// apfLiveSave is a trimmed `iptables-save -c -t filter` capture from a host
// running apf, covering each shape it generates: a conf.apf port-list accept, an
// ICMP-type accept carrying apf's ICMP_LIM framing, a bare trust-list address
// (one entry, one row per direction), and an advanced trust line.
var apfLiveSave = []string{
	"*filter",
	":INPUT DROP [0:0]",
	"[9:540] -A INPUT -j TALLOW",
	"[3:180] -A INPUT -p tcp -m tcp --dport 22 -j ACCEPT",
	"[5:300] -A INPUT -p udp -m udp --dport 53 -j ACCEPT",
	"[4:336] -A INPUT -p icmp -m icmp --icmp-type 8 -m limit --limit 30/sec -j ACCEPT",
	"[2:120] -A OUTPUT -p tcp -m tcp --dport 25 -j ACCEPT",
	"[1:60] -A TALLOW -s 172.31.5.5/32 -j ACCEPT",
	"[1:44] -A TALLOW -d 172.31.5.5/32 -j ACCEPT",
	"[7:420] -A TALLOW -s 172.31.7.7/32 -p tcp -m multiport --dports 8443 -j ACCEPT",
	"[8:480] -A TDENY -s 172.31.9.9/32 -j DROP",
	"COMMIT",
}

// TestAPFParseLiveRules verifies apf's framing is undone on read: the rate it
// attaches to every accepted ICMP type is dropped, and a row in its trust chains
// — which are entered from both INPUT and OUTPUT — takes its direction from the
// address side it matches on.
func TestAPFParseLiveRules(t *testing.T) {
	fw := new(APF)
	// The capture's ICMP row carries apf's stock ICMP_LIM; state the rate here
	// rather than reading conf.apf, which is not present under test.
	rules := fw.decodeLiveRules(apfLiveSave, IPv4, &RateLimit{Rate: 30, Unit: PerSecond})
	require.Len(t, rules, 8, "the jump into TALLOW models no rule of its own")

	require.EqualValues(t, 22, rules[0].Port)
	require.EqualValues(t, 3, rules[0].Packets)

	icmp := rules[2]
	require.Equal(t, ICMP, icmp.Proto)
	require.Nil(t, icmp.RateLimit, "apf's ICMP_LIM framing is not part of the rule")
	require.EqualValues(t, 4, icmp.Packets)

	// The trust chains carry no direction, so the row's address side supplies it.
	require.Equal(t, DirInput, rules[4].Direction, "a source match is the inbound half")
	require.Equal(t, DirOutput, rules[5].Direction, "a destination match is the outbound half")
	require.Equal(t, DirInput, rules[6].Direction)
	require.EqualValues(t, 8443, rules[6].Port)
}

// TestAPFApplyCounters verifies an apf entry that spans more than one axis sums
// every row it materializes into: a CPORTS entry is dual-stack (FamilyAny) and a
// bare trust address is bidirectional (DirAny).
func TestAPFApplyCounters(t *testing.T) {
	fw := new(APF)
	live := fw.decodeLiveRules(apfLiveSave, IPv4, &RateLimit{Rate: 30, Unit: PerSecond})

	port := &Rule{Direction: DirInput, Family: FamilyAny, Proto: TCP, Port: 22, Action: Accept}
	host := &Rule{Direction: DirAny, Family: IPv4, Source: "172.31.5.5", Action: Accept}
	adv := &Rule{Direction: DirInput, Family: IPv4, Proto: TCP, Port: 8443, Source: "172.31.7.7", Action: Accept}
	applyLiveCounters([]*Rule{port, host, adv}, live)

	require.EqualValues(t, 3, port.Packets, "a dual-stack CPORTS entry counts this family's row")
	require.EqualValues(t, 2, host.Packets, "a bare trust address sums both directions")
	require.EqualValues(t, 104, host.Bytes)
	require.EqualValues(t, 7, adv.Packets, "an advanced trust line matches its single row")
}

// TestAPFCountableRulesSpansFamilies verifies a dual-stack entry is offered to
// both families' rulesets, so its counters accumulate across the two rather than
// reporting only IPv4.
func TestAPFCountableRulesSpansFamilies(t *testing.T) {
	dual := &Rule{Direction: DirInput, Family: FamilyAny, Proto: TCP, Port: 22, Action: Accept}
	v4only := &Rule{Direction: DirInput, Family: IPv4, Proto: TCP, Port: 80, Action: Accept}
	rules := []*Rule{dual, v4only}

	require.Len(t, countableRules(rules, IPv4), 2)
	require.Equal(t, []*Rule{dual}, countableRules(rules, IPv6),
		"only the family-agnostic rule is offered to the IPv6 ruleset")

	// Both families' rows add up onto the one reported rule.
	v4 := []*Rule{{Direction: DirInput, Family: IPv4, Proto: TCP, Port: 22, Action: Accept, Packets: 3, Bytes: 180}}
	v6 := []*Rule{{Direction: DirInput, Family: IPv6, Proto: TCP, Port: 22, Action: Accept, Packets: 2, Bytes: 160}}
	applyLiveCounters(countableRules(rules, IPv4), v4)
	applyLiveCounters(countableRules(rules, IPv6), v6)
	require.EqualValues(t, 5, dual.Packets)
	require.EqualValues(t, 340, dual.Bytes)
}
