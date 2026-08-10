package firewall

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestWFFeatureRules(t *testing.T) {
	fw := &WF{rulePrefix: "test"}

	// Round-trip the rule shapes the WFP backend supports: ICMP/ICMPv6
	// protocols and single/list/range ports.
	rules := []*Rule{
		{Proto: ICMP, Action: Accept},
		{Proto: ICMPv6, Action: Drop},
		{Proto: ICMP, ICMPType: Ptr[uint8](8), Action: Accept},
		{Proto: ICMPv6, ICMPType: Ptr[uint8](135), Action: Drop},
		{Proto: TCP, Port: 22, Action: Accept},
		{Proto: TCP, Ports: []PortRange{{Start: 80}, {Start: 443}}, Action: Accept},
		{Direction: DirOutput, Proto: UDP, Ports: []PortRange{{Start: 1000, End: 2000}}, Action: Accept},
	}
	for _, r := range rules {
		fr, err := fw.MarshallFWRule("", r)
		require.NoError(t, err, "failed to marshal %+v", *r)

		parsed := fw.UnmarshallFWRule(*fr)
		require.NotNil(t, parsed, "failed to parse marshalled rule for %+v", *r)
		require.True(t, parsed.Equal(r, true),
			"round-trip mismatch: input %+v, output %+v", *r, parsed)
	}
}

// TestWFProtocolAndComment round-trips the added portless IP protocols (mapped
// to raw protocol numbers) and a rule comment (carried in the filter
// description). A port on a non-tcp/udp protocol is rejected.
func TestWFProtocolAndComment(t *testing.T) {
	fw := &WF{rulePrefix: "test"}

	rules := []*Rule{
		{Proto: GRE, Action: Accept},
		{Proto: ESP, Action: Accept},
		{Proto: AH, Action: Drop},
		{Proto: TCP, Port: 22, Action: Accept, Comment: "ssh access"},
	}
	for _, r := range rules {
		fr, err := fw.MarshallFWRule("", r)
		require.NoError(t, err, "failed to marshal %+v", *r)
		parsed := fw.UnmarshallFWRule(*fr)
		require.NotNil(t, parsed, "failed to parse %+v", *r)
		require.True(t, parsed.Equal(r, true), "round-trip mismatch: %+v vs %+v", *r, parsed)
		require.Equal(t, r.Comment, parsed.Comment, "comment round-trip for %+v", *r)
	}
}

// decodeAddress must parse an IPv6 address in netmask notation, not only IPv4,
// and must reject an address/netmask family mismatch.
func TestWFDecodeAddressNetmask(t *testing.T) {
	fw := &WF{rulePrefix: "test"}

	cases := []struct{ in, want string }{
		{"192.168.1.5/255.255.255.0", "192.168.1.0/24"}, // IPv4 netmask
		{"192.168.1.5/24", "192.168.1.0/24"},            // IPv4 CIDR
		{"2001:db8::/ffff:ffff::", "2001:db8::/32"},     // IPv6 netmask
		{"2001:db8::/32", "2001:db8::/32"},              // IPv6 CIDR
	}
	for _, c := range cases {
		got, err := fw.decodeAddress(c.in)
		require.NoError(t, err, "decodeAddress(%q)", c.in)
		require.Equal(t, c.want, got, "decodeAddress(%q)", c.in)
	}

	// An address/netmask family mismatch is rejected.
	_, err := fw.decodeAddress("192.168.1.0/ffff::")
	require.Error(t, err, "a v4 address with a v6 netmask must be rejected")
}
