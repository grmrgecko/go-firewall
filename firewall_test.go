package firewall

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"
)

// Rule identity compares addresses semantically: a bare host, its /32 (or /128)
// form, and a differently spelled but equal IPv6 address are the same address.
// Backends re-spell addresses on read (nft strips a /32, iptables-save adds it),
// so an exact string compare would report the rule as changed on every reconcile.
func TestAddrEqualCanonicalizesHostPrefix(t *testing.T) {
	require.True(t, addrEqual("1.2.3.4", "1.2.3.4/32"))
	require.True(t, addrEqual("2001:db8::1", "2001:0db8::1/128"))
	require.True(t, addrEqual("10.0.0.5/24", "10.0.0.0/24"), "host bits are masked to the network")
	require.True(t, addrEqual("!1.2.3.4", "!1.2.3.4/32"), "negation is preserved")
	require.False(t, addrEqual("1.2.3.4", "1.2.3.5"))
	require.False(t, addrEqual("1.2.3.4", "!1.2.3.4/32"), "a negation must not match its non-negated form")
	require.False(t, addrEqual("", "0.0.0.0/0"), "an any-address is not the empty match")
	require.False(t, addrEqual("myset", "myotherset"), "non-IP tokens compare verbatim")

	a := &Rule{Family: IPv4, Source: "1.2.3.4/32", Proto: TCP, Port: 22, Action: Accept}
	b := &Rule{Family: IPv4, Source: "1.2.3.4", Proto: TCP, Port: 22, Action: Accept}
	require.True(t, a.EqualBase(b, true), "a /32 host and its bare form are the same rule")
}

// A Backup serializes to portable JSON and decodes back identically, including
// enum fields, pointers, port lists, limits and comments.
func TestBackupJSONRoundTrip(t *testing.T) {
	icmpType := uint8(8)
	original := &Backup{
		Rules: []*Rule{
			{
				Direction: DirOutput, Priority: 5, Family: IPv4,
				Source: "10.0.0.0/8", Destination: "!192.168.1.5",
				Port: 443, Ports: []PortRange{{Start: 8000, End: 8100}, {Start: 9000, End: 9000}},
				SourcePort: 53,
				Proto:      TCP, State: StateNew | StateEstablished,
				InInterface: "eth0", OutInterface: "eth1",
				Action: Accept, Log: true, LogPrefix: "https",
				RateLimit: &RateLimit{Rate: 20, Unit: PerSecond, Burst: 10},
				ConnLimit: &ConnLimit{Count: 100, PerSource: true},
				Comment:   "ingress",
			},
			{Family: IPv6, Proto: ICMPv6, ICMPType: &icmpType, Action: Drop},
			{Family: FamilyAny, Proto: GRE, Action: Reject},
		},
		NATRules: []*NATRule{
			{Kind: DNAT, Family: IPv4, Proto: TCP, Port: 8080, ToAddress: "10.0.0.5", ToPort: 80, Interface: "eth0"},
			{Kind: Masquerade, Family: IPv4, Interface: "eth1"},
			{Kind: Redirect, Family: IPv4, Proto: UDP, Port: 5353, ToPort: 5353},
		},
		// A direction left ActionInvalid (Forward here) must survive the round-trip
		// as "invalid" so SetDefaultPolicy leaves it unchanged on restore.
		DefaultPolicy: &DefaultPolicy{Input: Drop, Output: Accept, Forward: ActionInvalid},
		AddressSets: []*AddressSet{
			{Name: "blocklist", Family: IPv4, Type: SetHashNet, Entries: []string{"192.0.2.0/24", "198.51.100.0/24"}},
			{Name: "allow6", Family: IPv6, Type: SetHashIP, Entries: []string{"2001:db8::1"}},
		},
	}

	var buf bytes.Buffer
	require.NoError(t, WriteBackup(&buf, original))

	// The encoding carries the stable names, not bare numbers.
	require.Contains(t, buf.String(), `"accept"`)
	require.Contains(t, buf.String(), `"ipv4"`)
	require.Contains(t, buf.String(), `"dnat"`)
	require.Contains(t, buf.String(), `"hash:net"`)    // set type as a stable name
	require.Contains(t, buf.String(), `"invalid"`)     // ActionInvalid policy direction
	require.NotContains(t, buf.String(), `"Family":1`) // no numeric family encoding

	got, err := ReadBackup(&buf)
	require.NoError(t, err)
	require.Len(t, got.Rules, len(original.Rules))
	require.Len(t, got.NATRules, len(original.NATRules))

	for i := range original.Rules {
		require.True(t, reflect.DeepEqual(original.Rules[i], got.Rules[i]),
			"rule %d: want %+v got %+v", i, original.Rules[i], got.Rules[i])
	}
	for i := range original.NATRules {
		require.True(t, reflect.DeepEqual(original.NATRules[i], got.NATRules[i]),
			"nat rule %d: want %+v got %+v", i, original.NATRules[i], got.NATRules[i])
	}
	require.True(t, reflect.DeepEqual(original.DefaultPolicy, got.DefaultPolicy),
		"default policy: want %+v got %+v", original.DefaultPolicy, got.DefaultPolicy)
	require.True(t, reflect.DeepEqual(original.AddressSets, got.AddressSets),
		"address sets: want %+v got %+v", original.AddressSets, got.AddressSets)
}

// isSetRef must treat the "any" wildcard as an address, not a named set, so a
// backend never emits set-match syntax for the match-all token.
func TestIsSetRefTreatsAnyAsWildcard(t *testing.T) {
	for _, a := range []string{"any", "!any", " any ", ""} {
		require.False(t, isSetRef(a), "isSetRef(%q) must be false", a)
	}
	for _, a := range []string{"1.2.3.4", "10.0.0.0/8", "!192.168.1.1"} {
		require.False(t, isSetRef(a), "isSetRef(%q) is an address", a)
	}
	for _, a := range []string{"myset", "!blocklist"} {
		require.True(t, isSetRef(a), "isSetRef(%q) is a set reference", a)
	}
}

// A port set whose ranges are contiguous or overlapping must compare equal to
// the coalesced form a backend lists back (nft merges adjacent ranges on read),
// so rule identity is coalescing-invariant and Sync does not churn.
func TestPortRangesEqualCoalesces(t *testing.T) {
	cases := []struct {
		name string
		a, b []PortRange
		want bool
	}{
		{"contiguous singletons and range", []PortRange{{22, 22}, {23, 23}, {24, 30}}, []PortRange{{22, 30}}, true},
		{"adjacent ranges merge", []PortRange{{100, 200}, {201, 300}}, []PortRange{{100, 300}}, true},
		{"single plus adjacent range", []PortRange{{80, 80}, {81, 90}}, []PortRange{{80, 90}}, true},
		{"overlapping ranges", []PortRange{{100, 200}, {150, 250}}, []PortRange{{100, 250}}, true},
		{"order independence", []PortRange{{443, 443}, {80, 80}}, []PortRange{{80, 80}, {443, 443}}, true},
		{"discrete singletons equal to their span", []PortRange{{80, 80}, {81, 81}}, []PortRange{{80, 81}}, true},
		{"non-contiguous stays distinct", []PortRange{{80, 80}, {443, 443}}, []PortRange{{80, 443}}, false},
		{"gap of one is not contiguous", []PortRange{{80, 80}, {82, 82}}, []PortRange{{80, 82}}, false},
		{"top-of-range does not wrap", []PortRange{{65534, 65535}}, []PortRange{{65534, 65534}, {65535, 65535}}, true},
	}
	for _, c := range cases {
		require.Equalf(t, c.want, portRangesEqual(c.a, c.b), "portRangesEqual(%v,%v)", c.a, c.b)
		require.Equalf(t, c.want, portRangesEqual(c.b, c.a), "portRangesEqual is symmetric for %v,%v", c.a, c.b)
	}
}

// A rule spanning all three axes has eight cells, so a backend that can store none of
// them reports it as eight physical rows. Those rows cover it exactly, and dropping
// any one of them breaks the coverage — which is what keeps Sync from re-adding a
// rule that is already fully installed, and from calling a half-installed rule done.
func TestAllThreeAxesCoverage(t *testing.T) {
	// No address, so nothing pins the family: the rule genuinely spans both.
	var rows []*Rule
	for _, fam := range []Family{IPv4, IPv6} {
		for _, proto := range []Protocol{TCP, UDP} {
			rows = append(rows,
				&Rule{Family: fam, Proto: proto, Port: 53, Direction: DirInput, Action: Accept},
				&Rule{Family: fam, Proto: proto, SourcePort: 53, Direction: DirOutput, Action: Accept},
			)
		}
	}
	require.Len(t, rows, 8)

	want := &Rule{Family: FamilyAny, Proto: TCPUDP, Port: 53, Direction: DirAny, Action: Accept}
	require.Len(t, want.cells(true), 8, "the rule spans eight concrete cells")
	require.True(t, want.CoveredBy(rows), "the eight rows cover the rule")

	for i := range rows {
		missing := append(append([]*Rule{}, rows[:i]...), rows[i+1:]...)
		require.False(t, want.CoveredBy(missing), "dropping row %d must break coverage", i)
	}

	// An address pins the family, so the same rule then spans only four cells: the
	// direction swap moves it to the destination, and both halves stay IPv4.
	addressed := &Rule{Proto: TCPUDP, Source: "192.0.2.1", Port: 53, Direction: DirAny, Action: Accept}
	require.Len(t, addressed.cells(true), 4, "an IPv4 source pins the family axis")
}

// The port axis is a merged axis like family/transport/direction: a list rule
// spans one cell per spec, a stored set of single-port rows covers it, and a
// range covers its interior. This keeps Sync from re-adding a list rule whose
// ports are already installed as single-port rows on a backend that fans lists
// out (firewalld, pf), and from keeping a wider row the desired set narrowed.
func TestPortAxisCoverage(t *testing.T) {
	list := &Rule{Family: IPv4, Proto: TCP, Ports: []PortRange{{Start: 80, End: 80}, {Start: 443, End: 443}}, Action: Accept}
	rows := []*Rule{
		{Family: IPv4, Proto: TCP, Port: 80, Action: Accept},
		{Family: IPv4, Proto: TCP, Port: 443, Action: Accept},
	}

	require.Len(t, list.cells(true), 2, "a two-port list spans two cells")
	require.True(t, list.CoveredBy(rows), "single-port rows cover the list rule")
	require.True(t, list.Covers(rows[0]), "the list covers each single-port row")
	require.False(t, rows[0].Covers(list), "coverage is asymmetric: a single port cannot cover the list")
	require.True(t, rows[0].CoveredBy([]*Rule{list}), "a single-port row is covered by the list")
	require.False(t, list.CoveredBy(rows[:1]), "dropping one port breaks coverage")

	// A range covers the ports inside it; a port never covers the range.
	rng := &Rule{Proto: TCP, Ports: []PortRange{{Start: 1000, End: 2000}}, Action: Accept}
	require.True(t, rng.Covers(&Rule{Proto: TCP, Port: 1500, Action: Accept}))
	require.False(t, (&Rule{Proto: TCP, Port: 1500, Action: Accept}).Covers(rng))

	// A discrete set covers only the ports it names, never the span between them.
	require.False(t, list.Covers(&Rule{Proto: TCP, Ports: []PortRange{{Start: 80, End: 443}}, Action: Accept}))

	// The cross product with the other axes: a TCPUDP two-port list spans four
	// cells (two transports times two ports, family pinned), and every one must
	// be covered.
	both := &Rule{Family: IPv4, Proto: TCPUDP, Ports: []PortRange{{Start: 80, End: 80}, {Start: 443, End: 443}}, Action: Accept}
	require.Len(t, both.cells(true), 4)
	require.True(t, both.CoveredBy([]*Rule{
		{Proto: TCP, Port: 80, Action: Accept},
		{Proto: TCP, Port: 443, Action: Accept},
		{Proto: UDP, Ports: []PortRange{{Start: 80, End: 80}, {Start: 443, End: 443}}, Action: Accept},
	}), "a merged row covers the udp cells while single-port rows cover tcp")

	// Source ports expand independently of destination ports.
	src := &Rule{Family: IPv4, Proto: TCP, SourcePorts: []PortRange{{Start: 1024, End: 1024}, {Start: 2048, End: 2048}}, Action: Accept}
	require.Len(t, src.cells(true), 2)
	require.True(t, src.CoveredBy([]*Rule{
		{Proto: TCP, SourcePort: 1024, Action: Accept},
		{Proto: TCP, SourcePort: 2048, Action: Accept},
	}))
}

// TestRuleCovers pins the exported coverage relation: a merged rule contains its
// concrete halves on every axis, never the reverse, and ProtocolAny is not a merged
// value.
func TestRuleCovers(t *testing.T) {
	merged := &Rule{Family: FamilyAny, Proto: TCPUDP, Direction: DirAny, Port: 53, Action: Accept}
	cell := &Rule{Family: IPv4, Proto: TCP, Direction: DirInput, Port: 53, Action: Accept}

	require.True(t, merged.Covers(cell), "a rule merged on every axis covers each of its cells")
	require.False(t, cell.Covers(merged), "coverage is asymmetric: a concrete rule cannot cover a merged one")
	require.True(t, cell.Covers(cell), "a rule covers itself")

	// Each axis independently.
	require.True(t, (&Rule{Family: FamilyAny, Proto: TCP, Port: 53, Action: Accept}).
		Covers(&Rule{Family: IPv6, Proto: TCP, Port: 53, Action: Accept}))
	require.True(t, (&Rule{Proto: TCPUDP, Port: 53, Action: Accept}).
		Covers(&Rule{Proto: UDP, Port: 53, Action: Accept}))
	require.True(t, (&Rule{Proto: TCP, Direction: DirAny, Port: 53, Action: Accept}).
		Covers(&Rule{Proto: TCP, Direction: DirOutput, SourcePort: 53, Action: Accept}),
		"a DirAny rule covers its role-swapped output half")

	// Siblings never cover each other.
	require.False(t, (&Rule{Family: IPv4, Proto: TCP, Port: 53, Action: Accept}).
		Covers(&Rule{Family: IPv6, Proto: TCP, Port: 53, Action: Accept}))
	require.False(t, (&Rule{Proto: TCP, Port: 53, Action: Accept}).
		Covers(&Rule{Proto: UDP, Port: 53, Action: Accept}))

	// ProtocolAny matches every IP protocol; it is not the merged tcp/udp value and
	// so covers neither transport.
	require.False(t, (&Rule{Proto: ProtocolAny, Action: Accept}).Covers(&Rule{Proto: TCP, Action: Accept}))
	require.True(t, (&Rule{Proto: ProtocolAny, Action: Accept}).Covers(&Rule{Proto: ProtocolAny, Action: Accept}))

	// An ordinary field must still match exactly.
	require.False(t, merged.Covers(&Rule{Family: IPv4, Proto: TCP, Direction: DirInput, Port: 53, Action: Drop}),
		"a different action is a different rule")
	require.False(t, merged.Covers(&Rule{Family: IPv4, Proto: TCP, Direction: DirInput, Port: 54, Action: Accept}))
}

// TestNATCoveredBy mirrors Rule.CoveredBy over the axes NAT merges on: family,
// and the match ports. A Redirect
// carries no translation address, so its family is genuinely FamilyAny — a DNAT's
// ToAddress would pin the family through impliedFamily.
func TestNATCoveredBy(t *testing.T) {
	want := &NATRule{Kind: Redirect, Family: FamilyAny, Proto: TCP, Port: 80, ToPort: 8080}
	v4 := &NATRule{Kind: Redirect, Family: IPv4, Proto: TCP, Port: 80, ToPort: 8080}
	v6 := &NATRule{Kind: Redirect, Family: IPv6, Proto: TCP, Port: 80, ToPort: 8080}

	require.True(t, want.Covers(v4))
	require.False(t, v4.Covers(want))
	require.False(t, v4.Covers(v6))

	require.False(t, want.CoveredBy([]*NATRule{v4}))
	require.True(t, want.CoveredBy([]*NATRule{v4, v6}))
	require.True(t, v6.CoveredBy([]*NATRule{want}))

	// A DNAT's translation address pins the family, so a FamilyAny DNAT to an IPv4
	// target is already an IPv4 rule and one concrete rule covers it.
	dnatAny := &NATRule{Kind: DNAT, Family: FamilyAny, Proto: TCP, Port: 80, ToAddress: "192.0.2.9"}
	dnatV4 := &NATRule{Kind: DNAT, Family: IPv4, Proto: TCP, Port: 80, ToAddress: "192.0.2.9"}
	require.True(t, dnatAny.CoveredBy([]*NATRule{dnatV4}),
		"the translation address already pins this rule to IPv4")

	// The match ports are the second axis: a port-list DNAT spans one cell per
	// port and is covered by the single-port rows a fanned-out backend stores.
	list := &NATRule{Kind: DNAT, Proto: TCP, Ports: []PortRange{{Start: 80, End: 80}, {Start: 443, End: 443}}, ToAddress: "192.0.2.9", ToPort: 8080}
	p80 := &NATRule{Kind: DNAT, Proto: TCP, Port: 80, ToAddress: "192.0.2.9", ToPort: 8080}
	p443 := &NATRule{Kind: DNAT, Proto: TCP, Port: 443, ToAddress: "192.0.2.9", ToPort: 8080}
	require.Len(t, list.cells(), 2, "a two-port list spans two cells")
	require.True(t, list.Covers(p80), "the list covers each single-port row")
	require.False(t, p80.Covers(list), "a single port cannot cover the list")
	require.True(t, list.CoveredBy([]*NATRule{p80, p443}))
	require.False(t, list.CoveredBy([]*NATRule{p80}), "dropping one port breaks coverage")
	require.True(t, p80.CoveredBy([]*NATRule{list}), "a single-port row is covered by the list")
}

// impliedFamily resolves the family a rule effectively targets from any of its
// sources: the Family field alone (a port-only rule carries no address), an
// address, or a family-pinned ICMP protocol. Backends key family fan-outs and
// the csf/apf IPv6 gates on it, so a concrete family must win over an absent
// one and a rule pinning nothing must stay FamilyAny.
func TestImpliedFamily(t *testing.T) {
	v6 := []*Rule{
		{Proto: ProtocolAny, Source: "2001:db8::1", Action: Accept},
		{Family: IPv6, Proto: TCP, Port: 22, Source: "2001:db8::1", Action: Accept},
		{Family: IPv6, Proto: TCP, Port: 8080, Action: Drop},
		{Proto: ICMPv6, ICMPType: Ptr[uint8](128), Action: Accept},
		{Proto: ICMPv6, ICMPType: Ptr[uint8](128), State: StateEstablished, Action: Accept},
	}
	for _, r := range v6 {
		require.Equal(t, IPv6, r.impliedFamily(), "expected %+v to imply IPv6", *r)
	}

	v4 := []*Rule{
		{Family: IPv4, Proto: TCP, Port: 22, Source: "192.0.2.1", Action: Accept},
		{Proto: ProtocolAny, Source: "192.0.2.1", Action: Accept},
		{Proto: ICMP, ICMPType: Ptr[uint8](8), Action: Accept},
	}
	for _, r := range v4 {
		require.Equal(t, IPv4, r.impliedFamily(), "expected %+v to imply IPv4", *r)
	}

	anyFam := []*Rule{
		{Proto: TCP, Port: 8080, Action: Drop},
		{Proto: TCP, Port: 22, Action: Accept, State: StateNew},
	}
	for _, r := range anyFam {
		require.Equal(t, FamilyAny, r.impliedFamily(), "expected %+v to imply neither family", *r)
	}
}

// setRefFamilyFrom is the shared core every backend's set-family resolution
// runs through: it pins a set-referencing rule to its set's single family from
// whatever store the backend's lookup reads, and an unknown set or a
// mixed-family pair cannot produce a loadable rule, so both error.
func TestSetRefFamilyFrom(t *testing.T) {
	lookup := func(name string) (Family, bool, error) {
		switch name {
		case "v4set":
			return IPv4, true, nil
		case "v6set":
			return IPv6, true, nil
		case "macset":
			// A family-untyped set (hash:mac and friends).
			return FamilyAny, true, nil
		}
		return FamilyAny, false, nil
	}

	fam, err := setRefFamilyFrom(lookup, "v4set", "")
	require.NoError(t, err)
	require.Equal(t, IPv4, fam)

	fam, err = setRefFamilyFrom(lookup, "", "v6set")
	require.NoError(t, err)
	require.Equal(t, IPv6, fam)

	// The "!" negation and "@" set marker are stripped before lookup.
	fam, err = setRefFamilyFrom(lookup, "!@v6set", "")
	require.NoError(t, err)
	require.Equal(t, IPv6, fam)

	// A family-untyped set matches as IPv4.
	fam, err = setRefFamilyFrom(lookup, "macset", "")
	require.NoError(t, err)
	require.Equal(t, IPv4, fam)

	// Both fields naming same-family sets agree.
	fam, err = setRefFamilyFrom(lookup, "v4set", "v4set")
	require.NoError(t, err)
	require.Equal(t, IPv4, fam)

	// Sets of different families cannot share one rule.
	_, err = setRefFamilyFrom(lookup, "v4set", "v6set")
	require.ErrorContains(t, err, "different families")

	// An unknown set errors rather than guessing a family.
	_, err = setRefFamilyFrom(lookup, "ghost", "")
	require.ErrorContains(t, err, `"ghost"`)
}
