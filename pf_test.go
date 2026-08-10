//go:build darwin || freebsd

package firewall

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestPFICMP6TypeNameParse verifies that an icmp6-type printed by name resolves
// through the ICMPv6 table: pfctl reuses ICMPv4 spellings (e.g. echoreq) for
// different ICMPv6 numbers, so the ICMPv4 table would decode it wrongly.
func TestPFICMP6TypeNameParse(t *testing.T) {
	f := &PF{anchor: "go_firewall"}

	// echoreq is ICMPv6 type 128 (it is 8 under ICMPv4).
	line, err := f.MarshalRule(&Rule{Family: IPv6, Proto: ICMPv6, ICMPType: Ptr[uint8](128), Action: Accept})
	require.NoError(t, err)
	named := strings.Replace(line, "icmp6-type 128", "icmp6-type echoreq", 1)
	require.NotEqual(t, line, named, "marshaled rule should contain the numeric icmp6 type")
	got, err := f.UnmarshalRule(named)
	require.NoError(t, err)
	require.NotNil(t, got.ICMPType)
	require.Equal(t, uint8(128), *got.ICMPType, "echoreq must resolve to ICMPv6 type 128, not the ICMPv4 8")

	// An ICMPv4 rule must still resolve echoreq to 8.
	line4, err := f.MarshalRule(&Rule{Family: IPv4, Proto: ICMP, ICMPType: Ptr[uint8](8), Action: Accept})
	require.NoError(t, err)
	named4 := strings.Replace(line4, "icmp-type 8", "icmp-type echoreq", 1)
	got4, err := f.UnmarshalRule(named4)
	require.NoError(t, err)
	require.NotNil(t, got4.ICMPType)
	require.Equal(t, uint8(8), *got4.ICMPType)
}

// TestPFTranslationBoundary verifies the nat/rdr anchors are inserted before the
// first filtering statement and AFTER any queueing (altq/queue) section — pf.conf
// sections are strictly ordered options → normalization → queueing → translation
// → filtering, so treating a queueing keyword as the boundary would splice the
// anchors ahead of it and produce a ruleset pfctl -f rejects.
func TestPFTranslationBoundary(t *testing.T) {
	fw := new(PF)
	// altq/queue precede the first pass/block; the boundary must be the pass line.
	conf := []string{
		"set skip on lo",
		"scrub in all",
		`altq on em0 bandwidth 100Mb hfsc queue { q_def }`,
		`queue q_def bandwidth 100% hfsc(default)`,
		"pass out all",
		"block in all",
	}
	require.Equal(t, 4, fw.translationBoundary(conf),
		"anchors must go after the queueing section, at the first pass/block")

	// No filtering statements: append at the end.
	require.Equal(t, 2, fw.translationBoundary([]string{"set skip on lo", "scrub in all"}))

	// antispoof and anchor also open the filtering section.
	require.Equal(t, 0, fw.translationBoundary([]string{"antispoof for em0"}))
	require.Equal(t, 1, fw.translationBoundary([]string{"scrub in all", `anchor "foo"`}))
}

// TestPFHighICMPTypeNames verifies the high ICMPv4 type names pfctl prints (31-40)
// round-trip: MarshalRule emits the numeric type, pfctl re-spells it by name on
// -sr, and UnmarshalRule must resolve that name back to the number.
func TestPFHighICMPTypeNames(t *testing.T) {
	f := &PF{anchor: "go_firewall"}
	for name, num := range map[string]uint8{"photuris": 40, "skip": 39, "mobregreq": 35, "ipv6-where": 33} {
		line, err := f.MarshalRule(&Rule{Family: IPv4, Proto: ICMP, ICMPType: Ptr(num), Action: Accept})
		require.NoError(t, err)
		named := strings.Replace(line, "icmp-type "+strconv.Itoa(int(num)), "icmp-type "+name, 1)
		require.NotEqual(t, line, named, "expected numeric icmp-type in %q", line)
		got, err := f.UnmarshalRule(named)
		require.NoError(t, err, "pfctl name %q (type %d) must parse", name, num)
		require.NotNil(t, got.ICMPType)
		require.Equal(t, num, *got.ICMPType, "%s must resolve to %d", name, num)
	}
}

// TestPFProtocolAndComment round-trips the added protocols and a rule comment
// (a pf label) through the pf rule encoder.
func TestPFProtocolAndComment(t *testing.T) {
	f := &PF{anchor: "go_firewall"}
	cases := []*Rule{
		{Family: IPv4, Proto: SCTP, Port: 9000, Action: Accept},
		{Family: IPv4, Proto: GRE, Action: Accept},
		{Family: IPv4, Proto: ESP, Action: Accept},
		{Family: IPv4, Proto: TCP, Port: 22, Action: Accept, Comment: "ssh access"},
	}
	for _, orig := range cases {
		line, err := f.MarshalRule(orig)
		require.NoError(t, err)
		got, err := f.UnmarshalRule(line)
		require.NoError(t, err, "line %q", line)
		require.True(t, got.EqualBase(orig, true), "line %q: want %+v got %+v", line, orig, got)
		require.Equal(t, orig.Comment, got.Comment, "line %q comment", line)
	}
}

// TestPFAnchorPreservesUnmodeled verifies parseAnchorRules keeps a rule line it
// cannot model as an opaque row (nil rule, raw text preserved) instead of dropping
// it, so a read-modify-write rewrite of our anchor does not silently delete a
// foreign rule loaded into it. The rules slice stays 1:1 with raw so the physical
// row edits (insert/move/remove) never misalign.
func TestPFAnchorPreservesUnmodeled(t *testing.T) {
	fw := &PF{anchor: "go_firewall"}
	// The middle line uses a pf port operator (port > 1023) this backend does not
	// model, so it cannot become a Rule; the two surrounding lines are modeled.
	out := []string{
		"pass in quick inet proto tcp from any to any port = 22 keep state",
		"pass in quick inet proto tcp from any to any port > 1023 keep state",
		"pass out quick inet proto udp from any to any port = 53 keep state",
	}
	rules, raw := fw.parseAnchorRules(out)
	require.Len(t, rules, 3, "every physical row needs a slot, the opaque one included")
	require.Len(t, raw, 3, "raw must stay 1:1 with rules")
	require.NotNil(t, rules[0])
	require.Nil(t, rules[1], "the unmodeled line must be an opaque (nil) row")
	require.NotNil(t, rules[2])
	require.Equal(t, out[1], raw[1], "the unmodeled line's text must be preserved verbatim")
}

// TestPFReorderRowsKeepsOpaque verifies the move/remove row rebuild keeps an opaque
// (nil) row in place and maps the target position to the correct physical index past
// it, so relocating a modeled rule never drops or displaces a foreign line sharing
// our anchor.
func TestPFReorderRowsKeepsOpaque(t *testing.T) {
	fw := new(PF)
	ruleA := &Rule{Family: IPv4, Port: 22, Proto: TCP, Action: Accept}
	ruleB := &Rule{Family: IPv4, Port: 53, Proto: UDP, Action: Accept}
	rules := []*Rule{ruleA, nil, ruleB}
	raw := []string{"lineA", "opaque", "lineB"}

	// Move ruleB (a distinct rule) to the front.
	out, moved := fw.reorderRows(rules, raw, ruleB, 1)
	require.True(t, moved)
	require.Equal(t, []string{"lineB", "lineA", "opaque"}, out,
		"the opaque line must be kept; only the modeled rule relocates")
}

func TestPFRules(t *testing.T) {
	fw := &PF{anchor: "go_firewall"}

	// Marshal a representative rule and confirm the pf rule line.
	line, err := fw.MarshalRule(&Rule{
		Family: IPv4,
		Source: "192.168.0.0/24",
		Port:   23,
		Proto:  UDP,
		Action: Accept,
	})
	require.NoError(t, err)
	require.Equal(t, "pass in quick inet proto udp from 192.168.0.0/24 to any port 23", line,
		"unexpected rule line")

	// The normalized form emitted by `pfctl -sr` must parse back to an
	// equivalent rule.
	rule, err := fw.UnmarshalRule("pass in quick inet proto udp from 192.168.0.0/24 to any port = 23 keep state")
	require.NoError(t, err)
	want := &Rule{Family: IPv4, Source: "192.168.0.0/24", Port: 23, Proto: UDP, Action: Accept}
	require.True(t, rule.Equal(want, true), "parsed rule does not match: got %+v", rule)

	// Round-trip the rules we typically set across directions, families and
	// actions.
	rules := []*Rule{
		{Family: IPv4, Port: 4789, Proto: UDP, Action: Accept},
		{Direction: DirOutput, Family: IPv6, Port: 4789, Proto: UDP, Action: Accept},
		{Family: IPv4, Source: "203.0.113.10", Port: 4789, Proto: TCP, Action: Accept},
		{Direction: DirOutput, Family: IPv4, Destination: "203.0.113.10", Port: 4791, Proto: TCP, Action: Reject},
		{Family: IPv6, Source: "!2001:db8::1", Action: Drop},
		// A non-address Source/Destination names a pf table, referenced as <name>.
		{Family: IPv4, Source: "blocklist", Port: 22, Proto: TCP, Action: Drop},
		{Direction: DirOutput, Family: IPv4, Destination: "!allowlist", Port: 80, Proto: TCP, Action: Accept},
	}
	for _, r := range rules {
		line, err := fw.MarshalRule(r)
		require.NoError(t, err, "failed to marshal %+v", *r)

		parsed, err := fw.UnmarshalRule(line)
		require.NoError(t, err, "failed to parse %q", line)
		require.True(t, parsed.Equal(r, true),
			"round-trip mismatch: input %+v, line %q, output %+v", *r, line, parsed)
	}

	// A non-address Source is emitted as a pf table reference in angle brackets.
	setLine, err := fw.MarshalRule(&Rule{Family: IPv4, Source: "blocklist", Port: 22, Proto: TCP, Action: Drop})
	require.NoError(t, err)
	require.Contains(t, setLine, "from <blocklist>")

	// Invalid lines must be rejected.
	invalidRules := []string{
		"pass in quick inet proto foo from any to any",
		"frobnicate in quick from any to any",
		"pass sideways quick from any to any",
	}
	for _, line := range invalidRules {
		_, err := fw.UnmarshalRule(line)
		require.Error(t, err, "line parsed when it should be invalid: %s", line)
	}

	// A port without a concrete protocol cannot be expressed in pf.
	require.Error(t, fw.validateRule(&Rule{Port: 80, Proto: ProtocolAny, Action: Accept}),
		"expected a port with no protocol to be rejected")

	// A single source port and a contiguous source-port range round-trip and are
	// accepted; a discrete source-port list does not round-trip (pfctl expands it),
	// so it is rejected rather than emitted.
	require.NoError(t, fw.validateRule(&Rule{Proto: TCP, SourcePort: 1024, Action: Accept}),
		"a single source port is valid")
	require.NoError(t, fw.validateRule(&Rule{Proto: TCP, SourcePorts: []PortRange{{Start: 1024, End: 2048}}, Action: Accept}),
		"a source-port range is valid")
	require.Error(t, fw.validateRule(&Rule{Proto: TCP, SourcePorts: []PortRange{{Start: 80, End: 80}, {Start: 443, End: 443}}, Action: Accept}),
		"a discrete source-port list must be rejected")
}

// pf exposes per-rule counters through `pfctl -vsr`, which prints a
// `[ Evaluations: N  Packets: N  Bytes: N  States: N ]` continuation line under
// each rule (and may prefix rules with a @N number in a verbose listing).
// parseAnchorRules attaches those counters to the preceding rule.
func TestPFRuleCounters(t *testing.T) {
	fw := &PF{anchor: "go_firewall"}

	out := []string{
		"@0 pass in quick proto tcp from any to any port = 22",
		"  [ Evaluations: 100        Packets: 40         Bytes: 2400        States: 2     ]",
		"  [ Inserted: uid 0 pid 1 State Creations: 2     ]",
		"pass in quick proto udp from any to any port = 53",
		"  [ Evaluations: 5          Packets: 5          Bytes: 300         States: 0     ]",
	}
	rules, raw := fw.parseAnchorRules(out)
	require.Len(t, rules, 2, "expected two rules parsed")
	require.Len(t, raw, 2, "raw must exclude the continuation lines")

	// The @N prefix is stripped so the raw text stays loadable by pfctl -f.
	require.NotContains(t, raw[0], "@0", "the rule-number prefix must be stripped: %q", raw[0])

	require.EqualValues(t, 40, rules[0].Packets)
	require.EqualValues(t, 2400, rules[0].Bytes)
	require.EqualValues(t, 22, rules[0].Port)
	require.EqualValues(t, 5, rules[1].Packets)
	require.EqualValues(t, 300, rules[1].Bytes)

	// The counter parser only fires on a line that carries both counters.
	p, b, ok := fw.parseRuleCounters("[ Evaluations: 1  Packets: 7  Bytes: 500  States: 0 ]")
	require.True(t, ok)
	require.EqualValues(t, 7, p)
	require.EqualValues(t, 500, b)
	_, _, ok = fw.parseRuleCounters("[ Inserted: uid 0 pid 1 State Creations: 2 ]")
	require.False(t, ok, "a non-counter continuation line must not report counters")
}

func TestPFFeatureRules(t *testing.T) {
	fw := &PF{anchor: "go_firewall"}

	// Confirm representative encodings.
	cases := []struct {
		rule *Rule
		want string
	}{
		{&Rule{Proto: ICMP, Action: Accept}, "pass in quick inet proto icmp from any to any"},
		{&Rule{Proto: ICMPv6, Action: Accept}, "pass in quick inet6 proto icmp6 from any to any"},
		{&Rule{Proto: ICMP, ICMPType: Ptr[uint8](8), Action: Accept}, "pass in quick inet proto icmp from any to any icmp-type 8"},
		{&Rule{Proto: ICMPv6, ICMPType: Ptr[uint8](135), Action: Accept}, "pass in quick inet6 proto icmp6 from any to any icmp6-type 135"},
		{&Rule{Proto: UDP, Ports: []PortRange{{Start: 1000, End: 2000}}, Action: Accept}, "pass in quick proto udp from any to any port 1000:2000"},
		{&Rule{InInterface: "em0", Proto: TCP, Port: 22, Action: Accept}, "pass in quick on em0 proto tcp from any to any port 22"},
		{&Rule{Direction: DirOutput, OutInterface: "em1", Action: Drop}, "block drop out quick on em1 from any to any"},
	}
	for _, c := range cases {
		got, err := fw.MarshalRule(c.rule)
		require.NoError(t, err, "failed to marshal %+v", *c.rule)
		require.Equal(t, c.want, got, "marshal %+v", *c.rule)
	}

	// Round-trip every new-feature rule shape.
	rules := []*Rule{
		{Proto: ICMP, Action: Accept},
		{Proto: ICMPv6, Action: Drop},
		{Family: IPv6, Proto: ICMPv6, Action: Accept},
		{Proto: ICMP, ICMPType: Ptr[uint8](8), Action: Accept},
		{Family: IPv6, Proto: ICMPv6, ICMPType: Ptr[uint8](135), Action: Accept},
		{Proto: UDP, Ports: []PortRange{{Start: 1000, End: 2000}}, Action: Accept},
		{InInterface: "em0", Proto: TCP, Port: 22, Action: Accept},
		{Direction: DirOutput, OutInterface: "em1", Proto: UDP, Port: 53, Action: Accept},
	}
	for _, r := range rules {
		line, err := fw.MarshalRule(r)
		require.NoError(t, err, "failed to marshal %+v", *r)

		parsed, err := fw.UnmarshalRule(line)
		require.NoError(t, err, "failed to parse %q", line)
		require.True(t, parsed.Equal(r, true),
			"round-trip mismatch: input %+v, line %q, output %+v", *r, line, parsed)
	}

	// A discrete destination-port list has no single-row pf form: pfctl expands
	// `port { 80 443 }` into one rule per port on load, so validateRule rejects it
	// and AddRule fans the list into one row per port with expandPorts instead.
	require.ErrorIs(t, fw.validateRule(&Rule{Proto: TCP, Ports: []PortRange{{Start: 80}, {Start: 443}}, Action: Accept}),
		ErrUnsupported, "a destination-port list must be rejected under pf")

	// pf cannot express a connection-state match in this model.
	require.Error(t, fw.validateRule(&Rule{Proto: TCP, Port: 22, State: StateEstablished, Action: Accept}),
		"expected a state match to be rejected under pf")

	// Interface/direction mismatches must be rejected.
	require.Error(t, fw.validateRule(&Rule{Direction: DirOutput, InInterface: "em0", Action: Accept}),
		"expected an input interface on an output rule to be rejected")
	require.Error(t, fw.validateRule(&Rule{OutInterface: "em0", Action: Accept}),
		"expected an output interface on an input rule to be rejected")

	// pf has no distinct forward chain, so a forward rule is rejected with the
	// ErrUnsupportedForward sentinel.
	require.ErrorIs(t, fw.validateRule(&Rule{Direction: DirForward, Proto: TCP, Port: 22, Action: Accept}),
		ErrUnsupportedForward, "a forward rule must be rejected")
}

func TestPFLogLimitRoundTrip(t *testing.T) {
	fw := &PF{anchor: "go_firewall"}
	cases := []*Rule{
		{Family: IPv4, Port: 22, Proto: TCP, Action: Accept, Log: true},
		{Family: IPv4, Port: 22, Proto: TCP, Action: Accept,
			ConnLimit: &ConnLimit{Count: 100, PerSource: true},
			RateLimit: &RateLimit{Rate: 15, Unit: PerSecond}},
		{Family: IPv4, Port: 22, Proto: TCP, Action: Accept,
			RateLimit: &RateLimit{Rate: 10, Unit: PerMinute}},
	}
	for _, orig := range cases {
		line, err := fw.MarshalRule(orig)
		require.NoError(t, err)
		got, err := fw.UnmarshalRule(line)
		require.NoError(t, err, "line %q", line)
		require.True(t, got.EqualBase(orig, true), "line %q: want %+v got %+v", line, orig, got)
	}

	// pf has no log prefix, and limits require an accept rule.
	require.Error(t, fw.validateRule(&Rule{Family: IPv4, Proto: TCP, Port: 22, Action: Accept, Log: true, LogPrefix: "x"}),
		"expected pf to reject a log prefix")
	require.Error(t, fw.validateRule(&Rule{Family: IPv4, Proto: TCP, Port: 22, Action: Drop, RateLimit: &RateLimit{Rate: 1, Unit: PerSecond}}),
		"expected pf to reject a limit on a non-accept rule")
	require.Error(t, fw.validateRule(&Rule{Family: IPv4, Proto: TCP, Port: 22, Action: Accept, ConnLimit: &ConnLimit{Count: 5, PerSource: false}}),
		"expected pf to reject a non-per-source connection limit")
}

func TestPFNATRoundTrip(t *testing.T) {
	fw := &PF{anchor: "go_firewall"}
	cases := []*NATRule{
		{Kind: DNAT, Family: IPv4, Proto: TCP, Port: 80, ToAddress: "10.0.0.5", ToPort: 8080, Interface: "em0"},
		{Kind: SNAT, Family: IPv4, Source: "10.0.0.0/24", ToAddress: "1.2.3.4", Interface: "em0"},
		{Kind: Masquerade, Family: IPv4, Interface: "em0"},
	}
	for _, orig := range cases {
		line, err := fw.MarshalNATRule(orig)
		require.NoError(t, err)
		got, err := fw.UnmarshalNATRule(line)
		require.NoError(t, err, "line %q", line)
		require.True(t, got.EqualBase(orig), "line %q: want %+v got %+v", line, orig, got)
	}

	// pfctl prints a well-known translation port by its /etc/services name, e.g. a
	// DNAT to port 80 reads back as `-> 10.0.0.5 port http`. The target port must
	// resolve through the service-name lookup like a match port; a number-only
	// parse fails and anchorNATRules silently drops the rule from the snapshot.
	named, err := fw.UnmarshalNATRule("rdr on em0 inet proto tcp from any to any port www -> 10.0.0.5 port http")
	require.NoError(t, err, "a named nat target port must parse")
	require.Equal(t, uint16(80), named.ToPort, "named target port http must resolve to 80")

	// pf has no portless redirect and masquerade needs an interface.
	require.Error(t, fw.validateNAT(&NATRule{Kind: Redirect, Family: IPv4, Proto: TCP, Port: 80, ToPort: 8080}),
		"expected pf to reject a redirect")
	require.Error(t, fw.validateNAT(&NATRule{Kind: Masquerade, Family: IPv4}),
		"expected pf masquerade to require an interface")
}

// pf's max-src-conn-rate has no burst term, so a rate limit carrying a non-zero
// Burst cannot be honored and must be rejected rather than marshaled into a rule
// that reads back with Burst 0 and fails rule-identity comparison.
func TestPFRateLimitBurstRejected(t *testing.T) {
	fw := &PF{anchor: "go_firewall"}
	require.ErrorIs(t, fw.validateRule(&Rule{Family: IPv4, Proto: TCP, Port: 22, Action: Accept,
		RateLimit: &RateLimit{Rate: 10, Unit: PerMinute, Burst: 5}}),
		ErrUnsupported, "a rate-limit burst must be rejected, not silently dropped")

	// A burst-less rate limit still round-trips.
	orig := &Rule{Family: IPv4, Proto: TCP, Port: 22, Action: Accept,
		RateLimit: &RateLimit{Rate: 10, Unit: PerMinute}}
	line, err := fw.MarshalRule(orig)
	require.NoError(t, err)
	got, err := fw.UnmarshalRule(line)
	require.NoError(t, err)
	require.True(t, got.EqualBase(orig, true), "line %q", line)
}

// A pf label (user comment) containing consecutive spaces must round-trip: the
// line tokenizer collapses whitespace, so the label is recovered from the raw
// line rather than the split tokens.
func TestPFLabelConsecutiveSpaces(t *testing.T) {
	fw := &PF{anchor: "go_firewall"}
	for _, comment := range []string{"web  server", "a   b   c", `has "quote"  and spaces`} {
		orig := &Rule{Family: IPv4, Proto: TCP, Port: 22, Action: Accept, Comment: comment}
		line, err := fw.MarshalRule(orig)
		require.NoError(t, err)
		got, err := fw.UnmarshalRule(line)
		require.NoError(t, err, "line %q", line)
		require.Equal(t, comment, got.Comment, "label whitespace must survive; line %q", line)
	}
}

// A pf rule written per family lives in two anchor rows. RemoveRule/MoveRule must
// locate both from a FamilyAny target with EqualForRemoval, not the family-strict
// Equal — which matches neither, so the port stays open. The pf remove must not
// no-op on a family-agnostic target.
func TestPFFamilyAnyTargetMatchesBothTwins(t *testing.T) {
	f := &PF{anchor: "go_firewall"}
	v4, err := f.UnmarshalRule("pass in quick inet proto tcp from any to any port = 22")
	require.NoError(t, err)
	v6, err := f.UnmarshalRule("pass in quick inet6 proto tcp from any to any port = 22")
	require.NoError(t, err)

	// The two rows cover the family-agnostic rule between them.
	target := &Rule{Family: FamilyAny, Proto: TCP, Port: 22, Action: Accept, Direction: DirInput}
	require.True(t, target.CoveredBy([]*Rule{v4, v6}))

	// The family-strict matcher finds neither physical row.
	require.False(t, target.Equal(v4, true))
	require.False(t, target.Equal(v6, true))

	// EqualForRemoval finds both, so RemoveRule clears both anchor rows and MoveRule
	// can locate the rule.
	require.True(t, v4.EqualForRemoval(target, true))
	require.True(t, v6.EqualForRemoval(target, true))
}

// MoveRule must relocate every physical row a target covers, not just the first.
// Moving only the first row of a v4/v6 pair leaves the twin at the earlier index —
// which then wins on the next read, making a move to a LATER position a silent no-op.
// reorderRows moves the covered rows as a block.
func TestPFReorderRowsFamilyPair(t *testing.T) {
	fw := new(PF)
	mk := func(fam Family, port uint16) *Rule {
		return &Rule{Family: fam, Proto: TCP, Port: port, Action: Accept}
	}
	// Physical anchor rows: A is a v4/v6 pair (rows 0,1); B is a v4/v6 pair (rows 2,3).
	// GetRules reports four rules, numbered 1..4.
	rules := []*Rule{mk(IPv4, 22), mk(IPv6, 22), mk(IPv4, 80), mk(IPv6, 80)}
	raw := []string{"A_v4", "A_v6", "B_v4", "B_v6"}

	// Move both A rows past B. Once A is pulled out, two rows remain, so position 3 is
	// past the end and appends.
	out, moved := fw.reorderRows(rules, raw, mk(FamilyAny, 22), 3)
	require.True(t, moved)
	require.Equal(t, []string{"B_v4", "B_v6", "A_v4", "A_v6"}, out,
		"both rows the target covers must move together, landing after B")

	// Move both B rows up to the front.
	out, moved = fw.reorderRows(rules, raw, mk(FamilyAny, 80), 1)
	require.True(t, moved)
	require.Equal(t, []string{"B_v4", "B_v6", "A_v4", "A_v6"}, out)

	// A concrete-family target relocates only its own family row, never the twin.
	// Three rows remain after A_v4 is pulled out, so position 4 appends.
	out, moved = fw.reorderRows(rules, raw, mk(IPv4, 22), 4)
	require.True(t, moved)
	require.Equal(t, []string{"A_v6", "B_v4", "B_v6", "A_v4"}, out)

	// A rule that matches nothing reports no move (MoveRule then skips the reload).
	_, moved = fw.reorderRows(rules, raw, mk(FamilyAny, 443), 1)
	require.False(t, moved)
}

// pf's nat translation maps to an address only; it has no source-port form, so a
// SNAT rule carrying a ToPort is rejected here rather than dropped silently. The
// shared validate accepts the shape, since iptables emits it as
// --to-source addr:port, so the rejection lives in pf's own validateNAT.
func TestPFMarshalRejectsSNATPort(t *testing.T) {
	f := &PF{anchor: "go_firewall"}
	require.ErrorIs(t, f.validateNAT(&NATRule{Kind: SNAT, Proto: TCP, ToAddress: "192.0.2.1", ToPort: 80}),
		ErrUnsupportedNAT, "a source-port SNAT must be rejected")
	// A portless SNAT still marshals.
	require.NoError(t, f.validateNAT(&NATRule{Kind: SNAT, ToAddress: "192.0.2.1"}))
	_, err := f.MarshalNATRule(&NATRule{Kind: SNAT, ToAddress: "192.0.2.1"})
	require.NoError(t, err)
}

// expandProtocols fans a TCPUDP rule into a tcp rule and a udp rule, each of which
// marshals to a valid concrete-protocol pf line and round-trips. pf has no both-
// transports form, so the write path fans out before the row-level marshaller.
func TestPFExpandProtocolsMarshal(t *testing.T) {
	f := &PF{anchor: "go_firewall"}
	subs := expandProtocols(&Rule{Family: IPv4, Proto: TCPUDP, Port: 22, Action: Accept})
	require.Len(t, subs, 2, "TCPUDP must fan into two concrete-transport rules")
	require.Equal(t, TCP, subs[0].Proto)
	require.Equal(t, UDP, subs[1].Proto)
	for _, sub := range subs {
		line, err := f.MarshalRule(sub)
		require.NoError(t, err, "each fanned transport must marshal")
		parsed, err := f.UnmarshalRule(line)
		require.NoError(t, err, "line %q", line)
		require.True(t, parsed.Equal(sub, true), "round-trip mismatch for %q", line)
	}
}

// Every modeled anchor row is its own rule, so filterAnchors is the identity over
// them. An opaque (nil) row — an anchor line pf keeps but this backend cannot model —
// occupies a physical slot without consuming a logical position, so the rules after
// it must still map to their own physical rows.
func TestPFFilterAnchorsSkipOpaqueRows(t *testing.T) {
	fw := new(PF)
	mk := func(proto Protocol, port uint16) *Rule {
		return &Rule{Family: IPv4, Proto: proto, Port: port, Action: Accept}
	}
	rules := []*Rule{mk(TCP, 22), mk(UDP, 22), mk(TCP, 80), mk(UDP, 80)}
	require.Equal(t, []int{0, 1, 2, 3}, fw.filterAnchors(rules),
		"every modeled row is its own anchor")
	require.Equal(t, 1, fw.logicalInsertIndex(fw.filterAnchors(rules), len(rules), 2))
	require.Equal(t, 4, fw.logicalInsertIndex(fw.filterAnchors(rules), len(rules), 5),
		"a position past the last logical rule appends")

	// An unmodeled line sits at physical row 1, shifting the rows after it.
	withOpaque := []*Rule{mk(TCP, 22), nil, mk(UDP, 22), mk(TCP, 80)}
	anchors := fw.filterAnchors(withOpaque)
	require.Equal(t, []int{0, 2, 3}, anchors, "the opaque row consumes no logical position")
	require.Equal(t, 2, fw.logicalInsertIndex(anchors, len(withOpaque), 2),
		"logical rule 2 lives at physical row 2, past the opaque line")
}

// reorderRows must relocate every physical row a target covers together: pfctl stores
// tcp and udp as separate rows, so a caller moving a TCPUDP rule (matched via
// EqualForRemoval's protocol coverage) moves both. A concrete-transport target moves
// only its own transport row, never the twin's.
func TestPFReorderRowsTransportPair(t *testing.T) {
	fw := new(PF)
	mk := func(proto Protocol, port uint16) *Rule {
		return &Rule{Family: IPv4, Proto: proto, Port: port, Action: Accept}
	}
	rules := []*Rule{mk(TCP, 22), mk(UDP, 22), mk(TCP, 80), mk(UDP, 80)}
	raw := []string{"A_tcp", "A_udp", "B_tcp", "B_udp"}

	// Move both A rows past B. Two rows remain once A is pulled out, so position 3
	// appends.
	out, moved := fw.reorderRows(rules, raw, mk(TCPUDP, 22), 3)
	require.True(t, moved)
	require.Equal(t, []string{"B_tcp", "B_udp", "A_tcp", "A_udp"}, out,
		"both transport rows the target covers must move together, landing after B")

	// A concrete-transport target relocates only its own transport row. Three rows
	// remain, so position 4 appends.
	out, moved = fw.reorderRows(rules, raw, mk(TCP, 22), 4)
	require.True(t, moved)
	require.Equal(t, []string{"A_udp", "B_tcp", "B_udp", "A_tcp"}, out)
}

// writeFileLines must preserve the original file's mode (not loosen it to 0644)
// and must not leave a fixed-name temp file behind.
func TestWriteFileLinesPreservesMode(t *testing.T) {
	fw := new(PF)
	dir := t.TempDir()
	path := filepath.Join(dir, "pf.conf")
	require.NoError(t, os.WriteFile(path, []byte("old\n"), 0600))

	require.NoError(t, fw.writeFileLines(path, []string{"line1", "line2"}))

	// Content replaced.
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, "line1\nline2\n", string(data))

	// Mode preserved, not widened to 0644.
	fi, err := os.Stat(path)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0600), fi.Mode().Perm(), "mode must be preserved")

	// No stale fixed-name temp file (the old fixed "<path>.tmp" scheme) remains.
	_, err = os.Stat(path + ".tmp")
	require.True(t, os.IsNotExist(err), "fixed-name temp file must not linger")

	// A brand-new file defaults to 0600 rather than 0644.
	newPath := filepath.Join(dir, "new.conf")
	require.NoError(t, fw.writeFileLines(newPath, []string{"x"}))
	fi, err = os.Stat(newPath)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0600), fi.Mode().Perm())
}

// readFileLines must handle a pf.conf line longer than bufio.Scanner's default
// 64 KB token cap rather than failing with a "token too long" error.
func TestReadFileLinesLongLine(t *testing.T) {
	fw := new(PF)
	dir := t.TempDir()
	path := filepath.Join(dir, "pf.conf")
	long := strings.Repeat("a", 300*1024) // 300 KB, well past the 64 KB default
	require.NoError(t, os.WriteFile(path, []byte(long+"\nshort\n"), 0600))

	lines, err := fw.readFileLines(path)
	require.NoError(t, err, "a long line must not overflow the scanner")
	require.Len(t, lines, 2)
	require.Equal(t, long, lines[0])
	require.Equal(t, "short", lines[1])
}

// MarshalRule must reject a destination-port list (as it already does for a
// source-port list): pfctl expands a discrete port list (`port { 80 443 }`)
// into one rule per port on load, so a list has no single-row form. AddRule
// fans a list into one row per port with expandPorts, so the row-level
// marshaller only ever sees a single spec. A single contiguous range stays one
// token and must still be allowed.
func TestPFMarshalRejectsDestPortList(t *testing.T) {
	f := &PF{anchor: "go_firewall"}

	// A destination-port list must be rejected as unsupported.
	err := f.validateRule(&Rule{
		Proto:  TCP,
		Ports:  []PortRange{{Start: 80, End: 80}, {Start: 443, End: 443}},
		Action: Accept,
	})
	require.Error(t, err, "a destination-port list must be rejected")
	require.ErrorIs(t, err, ErrUnsupported)

	// A single contiguous range still round-trips as one token, so it is allowed.
	line, err := f.MarshalRule(&Rule{
		Proto:  TCP,
		Ports:  []PortRange{{Start: 1000, End: 2000}},
		Action: Accept,
	})
	require.NoError(t, err, "a single contiguous range must remain expressible")
	require.Contains(t, line, "1000:2000")
}

// parseAddr must not mutate the caller's token slice when stripping a leading
// "!" negation.
func TestParsePFAddrDoesNotMutateTokens(t *testing.T) {
	fw := new(PF)
	tokens := []string{"!1.2.3.4", "port", "22"}
	val, neg, next, err := fw.parseAddr(tokens, 0)
	require.NoError(t, err)
	require.Equal(t, "1.2.3.4", val)
	require.Equal(t, "!", neg)
	require.Equal(t, 0, next)
	require.Equal(t, "!1.2.3.4", tokens[0], "the caller's slice must be left unchanged")

	// The separate-"!" token form advances the index and leaves tokens intact.
	tokens = []string{"!", "1.2.3.4"}
	val, neg, next, err = fw.parseAddr(tokens, 0)
	require.NoError(t, err)
	require.Equal(t, "1.2.3.4", val)
	require.Equal(t, "!", neg)
	require.Equal(t, 1, next)
	require.Equal(t, "!", tokens[0])
}

// A verbose listing prints a counters continuation under every rule, including an
// unmodeled one held as an opaque nil row; attaching those counters must not
// dereference the nil slot.
func TestPFVerboseCountersAfterUnmodeledRow(t *testing.T) {
	fw := &PF{anchor: "go_firewall"}
	out := []string{
		"pass in quick inet proto tcp from any to any port > 1023 keep state",
		"  [ Evaluations: 100        Packets: 40         Bytes: 2400        States: 2     ]",
		"pass in quick inet proto udp from any to any port = 53 keep state",
		"  [ Evaluations: 5          Packets: 5          Bytes: 300         States: 0     ]",
	}
	rules, raw := fw.parseAnchorRules(out)
	require.Len(t, rules, 2)
	require.Len(t, raw, 2)
	require.Nil(t, rules[0], "the unmodeled line stays an opaque row")
	require.NotNil(t, rules[1])
	require.EqualValues(t, 5, rules[1].Packets, "counters still attach to the modeled rule")
}

// A portable backup may carry DirAny or TCPUDP rules captured from a backend that
// stores them as one row; marshalExpanded (behind Restore) must fan them out
// exactly as the add paths do rather than fail or drop a half.
func TestPFMarshalExpandedMergedRules(t *testing.T) {
	fw := &PF{anchor: "go_firewall"}
	merged := &Rule{Direction: DirAny, Family: FamilyAny, Proto: TCPUDP, Port: 53, Action: Accept}
	lines, err := fw.marshalExpanded([]*Rule{merged})
	require.NoError(t, err)
	require.Len(t, lines, 4, "DirAny x TCPUDP must expand to four rows")
	var in, out, tcp, udp int
	for _, l := range lines {
		if strings.Contains(l, "pass in ") {
			in++
		}
		if strings.Contains(l, "pass out ") {
			out++
		}
		if strings.Contains(l, "proto tcp") {
			tcp++
		}
		if strings.Contains(l, "proto udp") {
			udp++
		}
	}
	require.Equal(t, 2, in)
	require.Equal(t, 2, out)
	require.Equal(t, 2, tcp)
	require.Equal(t, 2, udp)

	// A concrete rule passes through unchanged.
	lines, err = fw.marshalExpanded([]*Rule{{Family: IPv4, Proto: TCP, Port: 22, Action: Accept}})
	require.NoError(t, err)
	require.Len(t, lines, 1)
}

// A nat source-port match and a dynamic-target port pool have no faithful model;
// both must error so the line is preserved as an opaque row rather than mis-read.
func TestPFNATParserKeepsUnmodeledShapesOpaque(t *testing.T) {
	fw := &PF{anchor: "go_firewall"}
	opaque := []string{
		"nat on em0 inet from 10.0.0.0/8 port = 500 to any -> 192.0.2.1",
		"nat on em0 inet from 10.0.0.0/8 to any -> (em0) port 1024:65535",
	}
	for _, line := range opaque {
		_, err := fw.UnmarshalNATRule(line)
		require.Error(t, err, "line must stay opaque: %s", line)
	}
	// The plain forms still parse.
	r, err := fw.UnmarshalNATRule("nat on em0 inet from 10.0.0.0/8 to any -> (em0)")
	require.NoError(t, err)
	require.Equal(t, Masquerade, r.Kind)
	r, err = fw.UnmarshalNATRule("rdr on em0 inet proto tcp from any to any port = 8080 -> 10.0.0.5 port 80")
	require.NoError(t, err)
	require.Equal(t, DNAT, r.Kind)
	require.EqualValues(t, 8080, r.Port)
	require.EqualValues(t, 80, r.ToPort)
}

// insertRows must place every cell of a merged rule in one pass over the anchor's
// rows, so a rule spanning directions and transports is written by a single anchor
// load rather than one read-rewrite cycle per cell. The cells go in at the
// requested index in the order ruleCells fans them out, and the surrounding rows
// keep their positions.
func TestPFInsertRowsPlacesEveryCell(t *testing.T) {
	fw := &PF{anchor: "go_firewall"}
	merged := &Rule{Direction: DirAny, Family: IPv4, Proto: TCPUDP, Port: 53, Action: Accept}
	cells := fw.ruleCells(merged)
	require.Len(t, cells, 4, "DirAny x TCPUDP occupies four anchor rows")

	// An empty anchor: with no placement point every cell appends.
	out, changed, err := fw.insertRows(nil, nil, cells, func(int, *Rule) bool { return false })
	require.NoError(t, err)
	require.True(t, changed)
	require.Len(t, out, 4, "all four rows must land in the one pass")

	// A populated anchor with the insert predicate selecting physical row 1: the
	// block goes in ahead of that row, leaving the existing rows in order.
	existing := []*Rule{{Family: IPv4, Proto: TCP, Port: 22, Action: Accept}, {Family: IPv4, Proto: TCP, Port: 80, Action: Accept}}
	raw := []string{"first", "second"}
	out, changed, err = fw.insertRows(existing, raw, cells, func(i int, _ *Rule) bool { return i == 1 })
	require.NoError(t, err)
	require.True(t, changed)
	require.Len(t, out, 6)
	require.Equal(t, "first", out[0])
	require.Equal(t, "second", out[5], "the rows either side of the insert keep their order")
	want := make([]string, len(cells))
	for i, cell := range cells {
		line, mErr := fw.MarshalRule(cell)
		require.NoError(t, mErr)
		want[i] = line
	}
	require.Equal(t, want, out[1:5], "the cells go in together, in ruleCells order")
}

// The add-time dedup must ask whether an existing row *covers* the cell, not
// whether it is exactly equal: an anchor row written without an af matches both
// families, so re-adding its IPv4 half would leave a redundant row Sync then
// reports forever. The coverage is one-way, so a concrete-family row must not
// swallow its opposite-family twin — that would leave the twin's family un-firewalled.
func TestPFInsertRowsDedupUsesCoverage(t *testing.T) {
	fw := &PF{anchor: "go_firewall"}
	never := func(int, *Rule) bool { return false }

	// An af-less row covers the concrete-family cell it spans.
	dual, err := fw.UnmarshalRule("pass in quick proto tcp from any to any port = 22")
	require.NoError(t, err)
	v4Cell := &Rule{Family: IPv4, Direction: DirInput, Proto: TCP, Port: 22, Action: Accept}
	_, changed, err := fw.insertRows([]*Rule{dual}, []string{"dual"}, []*Rule{v4Cell}, never)
	require.NoError(t, err)
	require.False(t, changed, "a row covering the cell must not be duplicated")

	// A concrete IPv4 row does not cover the IPv6 cell, which must still be written.
	v4Row, err := fw.UnmarshalRule("pass in quick inet proto tcp from any to any port = 22")
	require.NoError(t, err)
	v6Cell := &Rule{Family: IPv6, Direction: DirInput, Proto: TCP, Port: 22, Action: Accept}
	out, changed, err := fw.insertRows([]*Rule{v4Row}, []string{"v4"}, []*Rule{v6Cell}, never)
	require.NoError(t, err)
	require.True(t, changed, "an opposite-family twin is not a duplicate")
	require.Len(t, out, 2)
	require.Contains(t, out[1], "inet6")

	// A partially-present set fills in only the missing cell rather than re-adding
	// the rule whole, so an edit interrupted part-way converges on a retry.
	missing := &Rule{Family: IPv4, Direction: DirInput, Proto: TCP, Port: 80, Action: Accept}
	out, changed, err = fw.insertRows([]*Rule{v4Row}, []string{"v4"}, []*Rule{v4Cell, missing}, never)
	require.NoError(t, err)
	require.True(t, changed)
	require.Len(t, out, 2, "only the absent cell is added")
	require.Contains(t, out[1], "port 80")
}

// A concrete-family removal that matches a genuine dual-family row (an anchor rule
// with no af, covering both) must not drop both families: the untargeted family is
// re-marshalled into the removed row's own slot, so it keeps its coverage and its
// place in the anchor. Opaque rows are never removal targets and stay put.
func TestPFRemoveRowsSplitsDualRowInPlace(t *testing.T) {
	fw := &PF{anchor: "go_firewall"}
	dual, err := fw.UnmarshalRule("pass in quick proto tcp from any to any port = 22")
	require.NoError(t, err)
	tail := &Rule{Family: IPv4, Direction: DirInput, Proto: TCP, Port: 80, Action: Accept}

	rules := []*Rule{nil, dual, tail}
	raw := []string{"opaque", "dual", "tail"}
	cell := &Rule{Family: IPv4, Direction: DirInput, Proto: TCP, Port: 22, Action: Accept}

	out, changed, err := fw.removeRows(rules, raw, []*Rule{cell})
	require.NoError(t, err)
	require.True(t, changed)
	require.Len(t, out, 3, "the dual row is replaced, not dropped")
	require.Equal(t, "opaque", out[0], "an opaque row is never a removal target")
	require.Contains(t, out[1], "inet6", "the untargeted family survives in the dual row's slot")
	require.Equal(t, "tail", out[2])

	// A target matching nothing leaves the rows untouched, so no anchor load runs.
	_, changed, err = fw.removeRows(rules, raw, []*Rule{{Family: IPv4, Direction: DirInput, Proto: UDP, Port: 9999, Action: Accept}})
	require.NoError(t, err)
	require.False(t, changed)
}
