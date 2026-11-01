package firewall

import (
	"testing"

	firewalld "github.com/grmrgecko/go-firewalld"
	"github.com/stretchr/testify/require"
)

// TestFirewallDZonePortRulesSkipsUnmodeledProto verifies a zone port on an
// unmodeled protocol (dccp) is not surfaced. Such a rule would read back as
// ProtocolAny, which RemoveRule and MarshalRichRule reject, so Sync could never
// reconcile it away. Modeled protocols (tcp/udp/sctp) still surface normally.
func TestFirewallDZonePortRulesSkipsUnmodeledProto(t *testing.T) {
	fw := new(FirewallD)
	ports := []firewalld.Port{
		{Port: "443", Protocol: "dccp"},
		{Port: "22", Protocol: "tcp"},
		{Port: "49152-49215", Protocol: "udp"},
	}
	rules := fw.zonePortRules(ports, false)
	require.Len(t, rules, 2, "the dccp port must be skipped, only tcp/udp surface")
	require.Equal(t, TCP, rules[0].Proto)
	require.EqualValues(t, 22, rules[0].Port)
	require.Equal(t, UDP, rules[1].Proto)
	require.Equal(t, []PortRange{{Start: 49152, End: 49215}}, rules[1].Ports)

	// Source ports bind to the source-port fields and likewise skip dccp.
	src := fw.zonePortRules([]firewalld.Port{{Port: "53", Protocol: "dccp"}, {Port: "53", Protocol: "udp"}}, true)
	require.Len(t, src, 1, "the dccp source port must be skipped")
	require.EqualValues(t, 53, src[0].SourcePort)
	require.EqualValues(t, 0, src[0].Port, "a source-port rule must not set the destination port")
}

func TestFirewallDRichRules(t *testing.T) {
	fw := new(FirewallD)

	// Parse a rule that is expected to parse right: an action-scoped limit
	// (after accept) is the traffic limit RateLimit models.
	rule, err := fw.UnmarshalRichRule(`rule family="ipv4" source address="192.168.0.0/24" port port=23 protocol=udp log audit accept limit value="1/m"`)
	require.NoError(t, err)

	// Re-encode the rule which should result in expected rich rule. The log and
	// rate limit round-trip (audit is still not modeled and is dropped).
	richRule, err := fw.MarshalRichRule(rule)
	require.NoError(t, err)
	require.Equal(t, `rule family="ipv4" source address="192.168.0.0/24" port port="23" protocol="udp" log level="info" accept limit value="1/m"`, richRule,
		"the rich rule did not encode as expected")

	// A log-scoped limit (directly after log) throttles only the logging, which
	// the model cannot hold; reading it as a traffic limit would let a rewrite
	// change what the rule enforces, so it must stay unmodeled.
	_, err = fw.UnmarshalRichRule(`rule family="ipv4" source address="192.168.0.0/24" port port=23 protocol=udp log limit value="1/m" audit accept`)
	require.Error(t, err, "a log-scoped limit must be rejected")

	// Try encoding a bunch of invalid rules.
	invalidRules := []string{
		`rule family=ipv4 source address="192.168.0.0/24" service name=ftp reject`,
		`family="ipv4" source address="192.168.0.0/24" port port=23 protocol=udp accept`,
		`rule family="ipv4" source address="192.168.0.0/24" port port=23 protocol=udp`,
		`rule family="ipv6" source address="1:2:3:4:6::" forward-port to-addr="1::2:3:4:7" to-port="4012" protocol="tcp" port="4011"`,
		// A port on a protocol this library does not model (dccp) reads back as
		// ProtocolAny, which MarshalRichRule cannot re-emit, so parsing must reject
		// it rather than surface a rule Restore would choke on. The same applies to a
		// port on a modeled but portless protocol (gre) and to a source-port element.
		`rule family="ipv4" port port="80" protocol="dccp" accept`,
		`rule family="ipv4" port port="80" protocol="gre" accept`,
		`rule family="ipv4" source-port port="1024" protocol="dccp" accept`,
	}
	for _, richRule := range invalidRules {
		_, err := fw.UnmarshalRichRule(richRule)
		require.Error(t, err, "this rich rule was parsed when it should be invalid: %s", richRule)
	}

	// Test rules we typically set.
	validRules := []string{
		`rule priority="10" family="ipv6" port port="4789" protocol="udp" accept`,
		`rule priority="10" family="ipv4" source address="203.0.113.10" port port="4789" protocol="tcp" accept`,
		`rule priority="10" family="ipv4" destination address="203.0.113.10" port port="4791" protocol="tcp" accept`,
	}
	for _, richRule := range validRules {
		_, err := fw.UnmarshalRichRule(richRule)
		require.NoError(t, err, "this rich rule was not parsed when it should be valid: %s", richRule)
	}

	// A port without a concrete protocol cannot be expressed as a rich rule
	// (protocol="any" is invalid), so marshalling must error rather than emit a
	// rule firewalld will refuse.
	_, err = fw.MarshalRichRule(&Rule{Port: 80, Proto: ProtocolAny, Action: Accept})
	require.Error(t, err, "expected error marshalling a port with no protocol")

	// firewalld's zone/rich-rule model has no forward chain, so a forward rule is
	// rejected with the ErrUnsupportedForward sentinel.
	_, err = fw.MarshalRichRule(&Rule{Direction: DirForward, Proto: TCP, Port: 80, Action: Accept})
	require.ErrorIs(t, err, ErrUnsupportedForward, "a forward rule must be rejected")
}

func TestFirewallDFeatureRules(t *testing.T) {
	fw := new(FirewallD)

	// Confirm representative encodings.
	cases := []struct {
		rule *Rule
		want string
	}{
		// A bare (untyped) ICMP/ICMPv6 protocol match needs no family qualifier:
		// firewalld accepts a familyless `protocol value="ipv6-icmp"` rule just
		// like any other protocol, and the protocol value string alone tells the
		// read path ICMP from ICMPv6. An explicit Family is still honored verbatim.
		{&Rule{Proto: ICMP, Action: Accept}, `rule protocol value="icmp" accept`},
		{&Rule{Proto: ICMPv6, Action: Accept}, `rule protocol value="ipv6-icmp" accept`},
		{&Rule{Family: IPv6, Proto: ICMPv6, Action: Accept}, `rule family="ipv6" protocol value="ipv6-icmp" accept`},
		{&Rule{Proto: TCP, Ports: []PortRange{{Start: 1000, End: 2000}}, Action: Accept}, `rule port port="1000-2000" protocol="tcp" accept`},
	}
	for _, c := range cases {
		got, err := fw.MarshalRichRule(c.rule)
		require.NoError(t, err, "failed to marshal %+v", *c.rule)
		require.Equal(t, c.want, got, "marshal %+v", *c.rule)
	}

	// Round-trip ICMP and port-range rules.
	rules := []*Rule{
		{Proto: ICMP, Action: Accept},
		{Family: IPv6, Proto: ICMPv6, Action: Drop},
		{Proto: TCP, Ports: []PortRange{{Start: 1000, End: 2000}}, Action: Accept},
		{Family: IPv4, Source: "192.168.0.0/24", Proto: UDP, Port: 23, Action: Accept},
	}
	for _, r := range rules {
		rich, err := fw.MarshalRichRule(r)
		require.NoError(t, err, "failed to marshal %+v", *r)

		parsed, err := fw.UnmarshalRichRule(rich)
		require.NoError(t, err, "failed to parse %q", rich)
		require.True(t, parsed.Equal(r, false),
			"round-trip mismatch: input %+v, rich %q, output %+v", *r, rich, parsed)
	}

	// Features a rich rule cannot express are rejected. A port list is not among
	// them: AddRule/RemoveRule fan it into a row per spec with expandPorts before
	// the marshaller runs, so a list never reaches it.
	unsupported := []*Rule{
		{Proto: TCP, Port: 22, State: StateEstablished, Action: Accept},
		{InInterface: "eth0", Proto: TCP, Port: 22, Action: Accept},
	}
	for _, r := range unsupported {
		_, err := fw.MarshalRichRule(r)
		require.Error(t, err, "expected error marshalling unsupported rule %+v", *r)
	}
}

func TestFirewallDICMPType(t *testing.T) {
	fw := new(FirewallD)

	// A specific ICMP type encodes to an icmp-type element, resolved by family:
	// echo-request is type 8 for IPv4 and 128 for IPv6, but the same firewalld
	// name is used for both.
	cases := []struct {
		rule *Rule
		want string
	}{
		{&Rule{Family: IPv4, Proto: ICMP, ICMPType: Ptr[uint8](8), Action: Accept},
			`rule family="ipv4" icmp-type name="echo-request" accept`},
		{&Rule{Family: IPv6, Proto: ICMPv6, ICMPType: Ptr[uint8](128), Action: Accept},
			`rule family="ipv6" icmp-type name="echo-request" accept`},
		{&Rule{Family: IPv6, Proto: ICMPv6, ICMPType: Ptr[uint8](136), Action: Drop},
			`rule family="ipv6" icmp-type name="neighbour-advertisement" drop`},
		// The ICMP protocol pins the family, so an unset Family is derived from it
		// (ICMP => ipv4) rather than rejected.
		{&Rule{Proto: ICMP, ICMPType: Ptr[uint8](8), Action: Accept},
			`rule family="ipv4" icmp-type name="echo-request" accept`},
		// ICMPv6 => ipv6.
		{&Rule{Proto: ICMPv6, ICMPType: Ptr[uint8](128), Action: Accept},
			`rule family="ipv6" icmp-type name="echo-request" accept`},
	}
	for _, c := range cases {
		got, err := fw.MarshalRichRule(c.rule)
		require.NoError(t, err, "failed to marshal %+v", *c.rule)
		require.Equal(t, c.want, got, "marshal %+v", *c.rule)

		parsed, err := fw.UnmarshalRichRule(got)
		require.NoError(t, err, "failed to parse %q", got)
		require.True(t, parsed.Equal(c.rule, false),
			"round-trip mismatch: input %+v, rich %q, output %+v", *c.rule, got, parsed)
	}

	// Rules a firewalld icmp-type element cannot express are rejected.
	unsupported := []*Rule{
		// A type with no firewalld name in that family cannot be expressed.
		{Family: IPv4, Proto: ICMP, ICMPType: Ptr[uint8](200), Action: Accept},
		// echo-request is 128 in IPv6; the IPv4 number 8 has no IPv6 name.
		{Family: IPv6, Proto: ICMPv6, ICMPType: Ptr[uint8](8), Action: Accept},
		// An ICMP type only applies to an ICMP/ICMPv6 protocol.
		{Family: IPv4, Proto: TCP, Port: 80, ICMPType: Ptr[uint8](8), Action: Accept},
	}
	for _, r := range unsupported {
		_, err := fw.MarshalRichRule(r)
		require.Error(t, err, "expected error marshalling %+v", *r)
	}
}

// firewalld's destination grammar accepts an ipset (like the source), so a rule
// matching a destination ipset must marshal to `destination ipset="..."` and
// round-trip, rather than being rejected or read back as invisible. Unlike a
// source ipset, firewalld rejects a familyless destination ipset with
// MISSING_FAMILY, so the caller must supply a concrete Family.
func TestFirewallDDestinationIPSet(t *testing.T) {
	fw := new(FirewallD)

	rule := &Rule{Family: IPv4, Destination: "myset", Proto: TCP, Port: 443, Action: Accept}
	got, err := fw.MarshalRichRule(rule)
	require.NoError(t, err)
	require.Contains(t, got, `destination ipset="myset"`, "unexpected marshal: %q", got)

	parsed, err := fw.UnmarshalRichRule(got)
	require.NoError(t, err)
	require.Equal(t, "myset", parsed.Destination)
	require.False(t, parsed.IsOutput(),
		"a destination element is an inbound-frame match, not a direction signal")

	// A negated destination ipset round-trips too.
	neg := &Rule{Family: IPv4, Destination: "!badset", Proto: TCP, Port: 443, Action: Drop}
	got, err = fw.MarshalRichRule(neg)
	require.NoError(t, err)
	require.Contains(t, got, `destination NOT ipset="badset"`, "unexpected marshal: %q", got)
	parsed, err = fw.UnmarshalRichRule(got)
	require.NoError(t, err)
	require.Equal(t, "!badset", parsed.Destination)
}

// A destination ipset with no explicit Family is rejected rather than marshaled
// into a rule firewalld refuses at apply time. A source ipset, by contrast,
// needs no family.
func TestFirewallDDestinationIPSetRequiresFamily(t *testing.T) {
	fw := new(FirewallD)

	_, err := fw.MarshalRichRule(&Rule{Destination: "myset", Proto: TCP, Port: 443, Action: Accept})
	require.Error(t, err, "a familyless destination ipset must be rejected")

	got, err := fw.MarshalRichRule(&Rule{Source: "myset", Proto: TCP, Port: 443, Action: Accept})
	require.NoError(t, err, "a familyless source ipset is valid and must not be rejected")
	require.Contains(t, got, `source ipset="myset"`, "unexpected marshal: %q", got)
	require.NotContains(t, got, "family=", "a familyless source ipset must not gain a family attribute")
}

func TestFirewallDSourcePort(t *testing.T) {
	fw := new(FirewallD)

	// Source-port matches encode to the source-port rich-rule element.
	cases := []struct {
		rule *Rule
		want string
	}{
		{&Rule{Proto: TCP, SourcePort: 1024, Action: Accept},
			`rule source-port port="1024" protocol="tcp" accept`},
		{&Rule{Family: IPv4, Proto: TCP, SourcePort: 1024, Action: Accept},
			`rule family="ipv4" source-port port="1024" protocol="tcp" accept`},
		{&Rule{Proto: UDP, SourcePorts: []PortRange{{Start: 1000, End: 2000}}, Action: Accept},
			`rule source-port port="1000-2000" protocol="udp" accept`},
	}
	for _, c := range cases {
		got, err := fw.MarshalRichRule(c.rule)
		require.NoError(t, err, "failed to marshal %+v", *c.rule)
		require.Equal(t, c.want, got, "marshal %+v", *c.rule)

		parsed, err := fw.UnmarshalRichRule(got)
		require.NoError(t, err, "failed to parse %q", got)
		require.True(t, parsed.Equal(c.rule, false),
			"round-trip mismatch: input %+v, rich %q, output %+v", *c.rule, got, parsed)
	}

	// A rich rule carries a single port element, so these cannot be expressed. A
	// source-port list is not tested here: AddRule/RemoveRule fan it into a row per
	// spec with expandPorts before the marshaller runs, so a list never reaches it.
	unsupported := []*Rule{
		// A destination port and a source port cannot coexist in one rule.
		{Proto: TCP, Port: 80, SourcePort: 1024, Action: Accept},
		// A source port needs a concrete tcp/udp protocol.
		{SourcePort: 1024, Action: Accept},
	}
	for _, r := range unsupported {
		_, err := fw.MarshalRichRule(r)
		require.Error(t, err, "expected error marshalling %+v", *r)
	}

	// The destination+source port rejection reports the source-port sentinel.
	_, err := fw.MarshalRichRule(&Rule{Proto: TCP, Port: 80, SourcePort: 1024, Action: Accept})
	require.ErrorIs(t, err, ErrUnsupportedSourcePort)
}

// A concrete-family bare-port accept is stored as a rich rule (zoneEntryEligible
// requires FamilyAny), so a family-agnostic port opened per family becomes two rich
// rules. Removing it with a FamilyAny target must locate both against the stored rich
// rules with EqualForRemoval — the family-strict Equal matches neither and leaves
// the port open. The firewalld family-agnostic remove must not no-op.
func TestFirewallDFamilyAnyRichRuleRemovable(t *testing.T) {
	fw := new(FirewallD)
	v4, err := fw.UnmarshalRichRule(`rule family="ipv4" port port="3492" protocol="tcp" accept`)
	require.NoError(t, err)
	v6, err := fw.UnmarshalRichRule(`rule family="ipv6" port port="3492" protocol="tcp" accept`)
	require.NoError(t, err)

	// The two stored rich rules cover the family-agnostic rule between them.
	target := &Rule{Family: FamilyAny, Proto: TCP, Port: 3492, Action: Accept}
	require.True(t, target.CoveredBy([]*Rule{v4, v6}))

	// The family-strict matcher finds neither stored rich rule.
	require.False(t, target.Equal(v4, false))
	require.False(t, target.Equal(v6, false))

	// EqualForRemoval finds both, so RemoveRule clears every rich rule the target
	// covers.
	require.True(t, v4.EqualForRemoval(target, false))
	require.True(t, v6.EqualForRemoval(target, false))
}

// A merged TCPUDP rule has no single rich-rule form (a rich rule port element
// carries one protocol), so AddRule and RemoveRule fan it into a tcp row and a
// udp row with expandProtocols before the marshaller runs.
func TestFirewallDMarshalRejectsMergedProtocol(t *testing.T) {
	fw := new(FirewallD)

	// expandProtocols yields a tcp row and a udp row, each of which marshals cleanly.
	subs := expandProtocols(&Rule{Port: 80, Proto: TCPUDP, Action: Accept})
	require.Len(t, subs, 2, "a TCPUDP rule fans into a tcp row and a udp row")
	require.Equal(t, TCP, subs[0].Proto)
	require.Equal(t, UDP, subs[1].Proto)
	for _, sub := range subs {
		rich, merr := fw.MarshalRichRule(sub)
		require.NoError(t, merr, "an expanded transport row must marshal: %+v", *sub)
		require.Contains(t, rich, `protocol="`+sub.Proto.String()+`"`)
	}
}

// A rich rule's port element carries one protocol, so a port opened for both tcp and
// udp in the same zone is two rich rules. Each reads back as its own rule (both
// family-agnostic, since neither names a family), and together they cover the TCPUDP
// rule that was written. A TCPUDP target reaches both on removal.
func TestFirewallDTCPUDPRichRulePair(t *testing.T) {
	fw := new(FirewallD)
	tcp, err := fw.UnmarshalRichRule(`rule port port="3492" protocol="tcp" accept`)
	require.NoError(t, err)
	udp, err := fw.UnmarshalRichRule(`rule port port="3492" protocol="udp" accept`)
	require.NoError(t, err)
	require.Equal(t, FamilyAny, tcp.impliedFamily(), "a familyless rich rule covers both families")

	target := &Rule{Proto: TCPUDP, Port: 3492, Action: Accept}
	require.True(t, target.CoveredBy([]*Rule{tcp, udp}), "the tcp/udp rich-rule pair covers the TCPUDP rule")
	require.False(t, target.CoveredBy([]*Rule{tcp}), "the tcp rich rule alone leaves udp uncovered")

	// The TCPUDP target reaches each concrete stored row on removal.
	require.True(t, tcp.EqualForRemoval(target, false))
	require.True(t, udp.EqualForRemoval(target, false))
}

// A rich rule cannot express a specific rate-limit burst, but the netfilter default
// burst (5) is treated as "unset" everywhere else in the library and reads back as 0
// from nft/iptables. MarshalRichRule must therefore accept a Burst=5 rule (rendering
// the bare rate) instead of rejecting it — otherwise a desired set that is portable
// across nft/iptables/firewalld aborts Sync on firewalld alone. The raw-burst guard
// must honor normBurst.
func TestFirewallDRateLimitDefaultBurstAccepted(t *testing.T) {
	fw := new(FirewallD)

	// Burst=5 (the netfilter default) must marshal to the bare rate and round-trip.
	def := &Rule{Proto: TCP, Port: 22, Action: Accept,
		RateLimit: &RateLimit{Rate: 10, Unit: PerMinute, Burst: netfilterDefaultBurst}}
	got, err := fw.MarshalRichRule(def)
	require.NoError(t, err, "a default-burst rate limit must be accepted")
	require.Contains(t, got, `limit value="10/m"`)

	// It round-trips: the read-back rule (Burst 0) still equals the desired rule, so
	// Sync does not churn.
	parsed, err := fw.UnmarshalRichRule(got)
	require.NoError(t, err)
	require.True(t, parsed.Equal(def, false),
		"a default-burst rule must equal its read-back so Sync is stable")

	// A genuinely non-default burst is still unexpressible and rejected.
	_, err = fw.MarshalRichRule(&Rule{Proto: TCP, Port: 22, Action: Accept,
		RateLimit: &RateLimit{Rate: 10, Unit: PerMinute, Burst: 20}})
	require.ErrorIs(t, err, ErrUnsupportedRateLimit)
}

// A FamilyAny rule that matches a concrete IP address must be marshaled with a
// family attribute: firewalld requires one whenever a rich rule uses an address
// (it rejects a familyless address rule) and stores the rule under that family.
// The rule must then still reconcile against firewalld's family-normalized
// read-back under the family-sensitive Equal that Sync/RemoveRule use.
func TestFirewallDFamilyAnyAddressGetsFamily(t *testing.T) {
	fw := new(FirewallD)
	orig := &Rule{Source: "10.0.0.1", Proto: TCP, Port: 22, Action: Accept}
	rich, err := fw.MarshalRichRule(orig)
	require.NoError(t, err)
	require.Contains(t, rich, `family="ipv4"`, "a rich rule with an IP address must declare its family")

	// firewalld lists the rule back with the family it stored it under.
	canon := `rule family="ipv4" source address="10.0.0.1" port port="22" protocol="tcp" accept`
	got, err := fw.UnmarshalRichRule(canon)
	require.NoError(t, err)
	require.True(t, orig.Equal(got, false),
		"a FamilyAny address rule must reconcile with its family-normalized read-back")

	// A bare (addressless) rule stays unqualified — firewalld applies it to both
	// families and needs no family attribute.
	bare, err := fw.MarshalRichRule(&Rule{Proto: TCP, Port: 22, Action: Accept})
	require.NoError(t, err)
	require.NotContains(t, bare, "family=", "an addressless rule must not be pinned to a family")
}

// A log prefix (or address) containing a space must survive the rich-rule parse,
// which needs a quote-aware tokenizer.
func TestFirewallDLogPrefixWithSpaces(t *testing.T) {
	fw := new(FirewallD)
	orig := &Rule{Family: IPv4, Proto: TCP, Port: 22, Action: Accept, Log: true, LogPrefix: "drop ssh"}
	rich, err := fw.MarshalRichRule(orig)
	require.NoError(t, err)
	got, err := fw.UnmarshalRichRule(rich)
	require.NoError(t, err)
	require.True(t, got.Log)
	require.Equal(t, "drop ssh", got.LogPrefix)
}

// lone range must take the zone-entry (AddPort/RemovePort) path — only a genuine
// multi-element list forces the rich-rule path. Gating on HasPortSet (true for a
// single range) left a foreign zone-port range unremovable, so Sync could never
// converge on it.
func TestFirewalldZoneEntryEligibleRange(t *testing.T) {
	fw := new(FirewallD)
	eligible := []struct {
		name string
		rule *Rule
	}{
		{"single port", &Rule{Proto: TCP, Port: 22, Action: Accept}},
		{"single port in slice", &Rule{Proto: TCP, Ports: []PortRange{{Start: 22, End: 22}}, Action: Accept}},
		{"single contiguous range", &Rule{Proto: TCP, Ports: []PortRange{{Start: 1000, End: 2000}}, Action: Accept}},
		{"single source-port range", &Rule{Proto: UDP, SourcePorts: []PortRange{{Start: 1000, End: 2000}}, Action: Accept}},
		{"bare source", &Rule{Source: "10.0.0.0/24", Action: Accept}},
	}
	for _, c := range eligible {
		require.Truef(t, fw.zoneEntryEligible(c.rule), "%s must use the zone-entry path", c.name)
	}

	ineligible := []struct {
		name string
		rule *Rule
	}{
		{"multi-port list", &Rule{Proto: TCP, Ports: []PortRange{{Start: 80, End: 80}, {Start: 443, End: 443}}, Action: Accept}},
		{"port list with a range", &Rule{Proto: TCP, Ports: []PortRange{{Start: 80, End: 80}, {Start: 1000, End: 2000}}, Action: Accept}},
		{"multi source-port list", &Rule{Proto: TCP, SourcePorts: []PortRange{{Start: 80, End: 80}, {Start: 90, End: 90}}, Action: Accept}},
		{"drop action", &Rule{Proto: TCP, Port: 22, Action: Drop}},
		{"logging", &Rule{Proto: TCP, Port: 22, Action: Accept, Log: true}},
		{"rate limit", &Rule{Proto: TCP, Port: 22, Action: Accept, RateLimit: &RateLimit{Rate: 1, Unit: PerSecond}}},
		{"concrete family", &Rule{Family: IPv4, Proto: TCP, Port: 22, Action: Accept}},
		{"icmp", &Rule{Proto: ICMP, Action: Accept}},
	}
	for _, c := range ineligible {
		require.Falsef(t, fw.zoneEntryEligible(c.rule), "%s must use the rich-rule path", c.name)
	}
}

// TestFirewallDBareICMPFamilyPinned guards that a bare (untyped) ICMP/ICMPv6 rule
// is left unqualified by family and still round-trips correctly. firewalld only
// requires a family for a source/destination address, never for a bare protocol
// match, and the protocol value string alone ("icmp" vs "ipv6-icmp") tells the
// read path ICMP from ICMPv6.
func TestFirewallDBareICMPFamilyPinned(t *testing.T) {
	fw := new(FirewallD)

	v6, err := fw.MarshalRichRule(&Rule{Proto: ICMPv6, Action: Accept})
	require.NoError(t, err)
	require.NotContains(t, v6, `family=`, "a bare icmpv6 rule needs no family qualifier")
	require.Contains(t, v6, `value="ipv6-icmp"`)

	v4, err := fw.MarshalRichRule(&Rule{Proto: ICMP, Action: Accept})
	require.NoError(t, err)
	require.NotContains(t, v4, `family=`, "a bare icmp rule needs no family qualifier")

	// The rich rule must round-trip back to an equal rule.
	parsed, err := fw.UnmarshalRichRule(v6)
	require.NoError(t, err)
	require.True(t, parsed.Equal(&Rule{Proto: ICMPv6, Action: Accept}, false),
		"the familyless icmpv6 rich rule should round-trip to the original rule")

	// An explicit Family is still honored verbatim.
	explicit, err := fw.MarshalRichRule(&Rule{Family: IPv6, Proto: ICMPv6, Action: Accept})
	require.NoError(t, err)
	require.Contains(t, explicit, `family="ipv6"`, "an explicit Family must still be emitted")

	// A *typed* ICMP match still needs the family qualifier: firewalld resolves an
	// icmp-type name without a protocol element, so this library's own read path
	// depends on the family to disambiguate an ICMPv4 name from the identically
	// named ICMPv6 one.
	typed, err := fw.MarshalRichRule(&Rule{Proto: ICMPv6, ICMPType: Ptr[uint8](128), Action: Accept})
	require.NoError(t, err)
	require.Contains(t, typed, `family="ipv6"`, "a typed icmpv6 rule must still pin family=ipv6")
}

// TestFirewallDSourceProtoNotZoneSource guards that a source combined with a
// concrete protocol is NOT routed to a bare zone source (which would drop the
// protocol and widen the rule to every protocol). Such a rule must take the
// rich-rule path, which preserves the protocol match.
func TestFirewallDSourceProtoNotZoneSource(t *testing.T) {
	fw := new(FirewallD)

	// A plain source with no protocol is a zone source.
	require.True(t, fw.sourceZoneShape(&Rule{Source: "1.2.3.4", Action: Accept}),
		"a bare source with no protocol should map to a zone source")

	// A source with a concrete protocol must not: it is a rich rule.
	require.False(t, fw.sourceZoneShape(&Rule{Source: "1.2.3.4", Proto: TCP, Action: Accept}),
		"a source+protocol rule must not be encoded as a bare zone source")

	// A negated source is a rich rule too.
	require.False(t, fw.sourceZoneShape(&Rule{Source: "!1.2.3.4", Action: Accept}))

	// The rich rule that AddRule now falls through to keeps the protocol match.
	rich, err := fw.MarshalRichRule(&Rule{Source: "1.2.3.4", Proto: TCP, Action: Accept})
	require.NoError(t, err)
	require.Contains(t, rich, `source address="1.2.3.4"`)
	require.Contains(t, rich, `protocol value="tcp"`, "the protocol match must survive on the rich-rule path")
}

// firewalld expresses the portless protocols as a bare protocol element and
// SCTP as a port protocol; both round-trip through a rich rule.
func TestFirewallDProtocolExtras(t *testing.T) {
	fw := new(FirewallD)
	cases := []*Rule{
		{Proto: GRE, Action: Accept},
		{Proto: ESP, Action: Accept},
		{Family: IPv4, Source: "192.168.0.0/24", Proto: SCTP, Port: 9000, Action: Accept},
	}
	for _, orig := range cases {
		rich, err := fw.MarshalRichRule(orig)
		require.NoError(t, err, "%+v", orig)
		got, err := fw.UnmarshalRichRule(rich)
		require.NoError(t, err, "rich %q", rich)
		require.True(t, got.EqualBase(orig, true), "rich %q: want %+v got %+v", rich, orig, got)
	}
}

// forwardPort builds a firewalld ForwardPort from a NAT rule and rejects the
// shapes firewalld's forward-port model cannot express.
func TestFWForwardPort(t *testing.T) {
	fw := new(FirewallD)
	// DNAT to another host: ToAddr is set.
	fp, err := fw.forwardPort(&NATRule{Kind: DNAT, Proto: TCP, Port: 80, ToAddress: "10.0.0.5", ToPort: 8080})
	require.NoError(t, err)
	require.Equal(t, firewalld.ForwardPort{Port: "80", Protocol: "tcp", ToAddr: "10.0.0.5", ToPort: "8080"}, fp)

	// Redirect to a local port: ToAddr is empty.
	fp, err = fw.forwardPort(&NATRule{Kind: Redirect, Proto: UDP, Port: 53, ToPort: 5353})
	require.NoError(t, err)
	require.Equal(t, firewalld.ForwardPort{Port: "53", Protocol: "udp", ToAddr: "", ToPort: "5353"}, fp)

	// A single contiguous range is allowed. A port list never reaches forwardPort:
	// AddNATRule/RemoveNATRule fan it into one forward-port per spec beforehand.
	fp, err = fw.forwardPort(&NATRule{Kind: DNAT, Proto: TCP, Ports: []PortRange{{Start: 1000, End: 2000}}, ToAddress: "10.0.0.5", ToPort: 3000})
	require.NoError(t, err)
	require.Equal(t, "1000-2000", fp.Port)

	bad := []struct {
		name string
		rule *NATRule
	}{
		{"non tcp/udp", &NATRule{Kind: DNAT, Proto: ICMP, Port: 80, ToAddress: "10.0.0.5"}},
		{"no port", &NATRule{Kind: DNAT, Proto: TCP, ToAddress: "10.0.0.5"}},
		{"interface", &NATRule{Kind: DNAT, Proto: TCP, Port: 80, Interface: "eth0", ToAddress: "10.0.0.5", ToPort: 8080}},
		{"source match", &NATRule{Kind: DNAT, Proto: TCP, Port: 80, Source: "1.2.3.4", ToAddress: "10.0.0.5", ToPort: 8080}},
	}
	for _, c := range bad {
		_, err := fw.forwardPort(c.rule)
		require.Errorf(t, err, "forwardPort should reject %s", c.name)
	}
}

// firewalld's ICMPv6 icmp-type table was missing destination-unreachable (type
// 1), which real firewalld defines for both ipv4 and ipv6. A rich rule using that
// name on IPv6 failed to resolve on read and was silently dropped from
// GetRules/Backup (and unmarshalling failed). It must round-trip.
func TestFirewalldICMPv6DestinationUnreachable(t *testing.T) {
	fw := new(FirewallD)

	n, ok := fw.icmpTypeNumber(true, "destination-unreachable")
	require.True(t, ok, "destination-unreachable must be a known ICMPv6 type")
	require.Equal(t, uint8(1), n, "ICMPv6 destination-unreachable is type 1")

	r := &Rule{Family: IPv6, Proto: ICMPv6, ICMPType: Ptr[uint8](1), Action: Reject}
	rr, err := fw.MarshalRichRule(r)
	require.NoError(t, err)
	require.Contains(t, rr, "destination-unreachable", "rich rule should carry the type name")
	back, err := fw.UnmarshalRichRule(rr)
	require.NoError(t, err, "an icmpv6 destination-unreachable rich rule must parse")
	require.True(t, r.Equal(back, false), "icmpv6 destination-unreachable must round-trip: got %+v", back)
}

// modeledForwardPort must reject the forward-port shapes the write side
// (forwardPort) cannot re-create — otherwise GetNATRules would surface entries
// that can never be removed or restored, and Restore would destroy them.
func TestFirewallDModeledForwardPort(t *testing.T) {
	fw := new(FirewallD)

	dnat := fw.modeledForwardPort(firewalld.ForwardPort{Port: "8080", Protocol: "tcp", ToPort: "80", ToAddr: "10.0.0.5"})
	require.NotNil(t, dnat)
	require.Equal(t, DNAT, dnat.Kind)
	require.EqualValues(t, 8080, dnat.Port)
	require.EqualValues(t, 80, dnat.ToPort)

	redirect := fw.modeledForwardPort(firewalld.ForwardPort{Port: "8443", Protocol: "udp", ToPort: "443"})
	require.NotNil(t, redirect)
	require.Equal(t, Redirect, redirect.Kind)

	// Shapes forwardPort rejects stay unmodeled: a non-tcp/udp protocol and a
	// target-port range.
	require.Nil(t, fw.modeledForwardPort(firewalld.ForwardPort{Port: "9999", Protocol: "sctp", ToPort: "80", ToAddr: "10.0.0.5"}))
	require.Nil(t, fw.modeledForwardPort(firewalld.ForwardPort{Port: "9999", Protocol: "dccp"}))
	require.Nil(t, fw.modeledForwardPort(firewalld.ForwardPort{Port: "8080", Protocol: "tcp", ToPort: "8080-8090", ToAddr: "10.0.0.5"}))
}

// Validate that firewalld older than 0.7, which has no rich rule priority,
// gets rules without one and does not advertise the capability.
func TestFirewallDPriorityGate(t *testing.T) {
	rule := &Rule{Priority: 10, Family: IPv6, Port: 4789, Proto: UDP, Action: Accept}
	tests := []struct {
		name       string
		noPriority bool
		want       string
	}{
		{"Supported", false, `rule priority="10" family="ipv6" port port="4789" protocol="udp" accept`},
		{"Unsupported", true, `rule family="ipv6" port port="4789" protocol="udp" accept`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fw := &FirewallD{noPriority: tt.noPriority}
			got, err := fw.MarshalRichRule(rule)
			require.NoError(t, err)
			require.Equal(t, tt.want, got)
			require.Equal(t, !tt.noPriority, fw.Capabilities().Priority)
		})
	}
}
