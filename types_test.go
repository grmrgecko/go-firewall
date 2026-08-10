package firewall

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

// ParseICMPType resolves a numeric or named ICMP type, selecting the ICMPv6 name
// table when v6 is set so a name shared with ICMPv4 maps to its v6 number. It is
// the exported resolver the CLI relies on, so its name coverage must match the
// tables the backends emit.
func TestParseICMPType(t *testing.T) {
	cases := []struct {
		tok  string
		v6   bool
		want uint8
		ok   bool
	}{
		{"8", false, 8, true},    // numeric parses in either family
		{"255", true, 255, true}, // numbers are family-independent
		{"echo-request", false, 8, true},
		{"ECHO-REQUEST", false, 8, true},  // case-insensitive
		{"echo-request", true, 128, true}, // same name, different v6 number
		{"destination-unreachable", false, 3, true},
		{"destination-unreachable", true, 1, true},
		{"nd-neighbor-solicit", true, 135, true},
		// info-request/info-reply live only in the v4 table; route them through
		// here to prove they resolve.
		{"info-request", false, 15, true},
		{"info-reply", false, 16, true},
		// A v4-only name is unknown under v6, and vice versa.
		{"source-quench", true, 0, false},
		{"packet-too-big", false, 0, false},
		{"not-a-type", false, 0, false},
	}
	for _, c := range cases {
		got, ok := ParseICMPType(c.tok, c.v6)
		require.Equalf(t, c.ok, ok, "ParseICMPType(%q, v6=%v) ok", c.tok, c.v6)
		if c.ok {
			require.Equalf(t, c.want, got, "ParseICMPType(%q, v6=%v)", c.tok, c.v6)
		}
	}
}

// Enums render as their stable string name (not a bare number) and round-trip
// through encoding/json. A backup must stay readable and meaningful even if an
// iota constant is later reordered.
func TestEnumJSON(t *testing.T) {
	cases := []struct {
		name string
		in   any
		want string // the quoted JSON string expected
	}{
		{"action-accept", Accept, `"accept"`},
		{"action-drop", Drop, `"drop"`},
		{"action-invalid", ActionInvalid, `"invalid"`},
		{"family-v4", IPv4, `"ipv4"`},
		{"family-v6", IPv6, `"ipv6"`},
		{"family-any", FamilyAny, `"any"`},
		{"proto-tcp", TCP, `"tcp"`},
		{"proto-sctp", SCTP, `"sctp"`},
		{"proto-any", ProtocolAny, `"any"`},
		{"natkind", DNAT, `"dnat"`},
		{"rateunit", PerMinute, `"minute"`},
		{"direction", DirForward, `"forward"`},
		{"settype", SetHashNet, `"hash:net"`},
		{"connstate", ConnState(StateEstablished | StateRelated), `"established,related"`},
		{"connstate-zero", ConnState(0), `""`},
	}
	for _, c := range cases {
		out, err := json.Marshal(c.in)
		require.NoError(t, err, c.name)
		require.Equal(t, c.want, string(out), "%s: marshal", c.name)
	}

	// Round-trip each value through marshal -> unmarshal.
	roundTrips := []struct {
		name string
		mk   func() any     // fresh addressable value to unmarshal into
		eq   func(any) bool // reports whether it equals the marshal source
	}{
		{"action", func() any { var v Action; return &v }, func(g any) bool { return *g.(*Action) == Accept }},
		{"family", func() any { var v Family; return &v }, func(g any) bool { return *g.(*Family) == IPv4 }},
		{"proto", func() any { var v Protocol; return &v }, func(g any) bool { return *g.(*Protocol) == TCP }},
		{"connstate", func() any { var v ConnState; return &v }, func(g any) bool { return *g.(*ConnState) == (StateNew | StateEstablished) }},
		{"rateunit", func() any { var v RateUnit; return &v }, func(g any) bool { return *g.(*RateUnit) == PerHour }},
		{"natkind", func() any { var v NATKind; return &v }, func(g any) bool { return *g.(*NATKind) == Masquerade }},
		{"direction", func() any { var v Direction; return &v }, func(g any) bool { return *g.(*Direction) == DirOutput }},
		{"settype", func() any { var v SetType; return &v }, func(g any) bool { return *g.(*SetType) == SetHashIP }},
	}
	marshalVals := map[string]any{
		"action":    Accept,
		"family":    IPv4,
		"proto":     TCP,
		"connstate": ConnState(StateNew | StateEstablished),
		"rateunit":  PerHour,
		"natkind":   Masquerade,
		"direction": DirOutput,
		"settype":   SetHashIP,
	}
	for _, rt := range roundTrips {
		data, err := json.Marshal(marshalVals[rt.name])
		require.NoError(t, err, rt.name)
		dst := rt.mk()
		require.NoError(t, json.Unmarshal(data, dst), "%s: unmarshal %s", rt.name, data)
		require.True(t, rt.eq(dst), "%s: round-trip mismatch (got %+v)", rt.name, dst)
	}
}
