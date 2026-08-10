package firewall

import (
	"net"
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"github.com/stretchr/testify/require"
)

// nftEncodeRule marshals a rule, failing the test if it cannot be expressed.
func nftEncodeRule(t *testing.T, f *NFT, r *Rule) *nftEncoded {
	t.Helper()
	enc, err := f.MarshalRule(r)
	require.NoError(t, err, "failed to marshal %+v", *r)
	return enc
}

// nftDecodeRule decodes an encoding back into a rule, resolving whatever anonymous
// sets the encoding staged rather than reaching for a live ruleset.
func nftDecodeRule(t *testing.T, f *NFT, enc *nftEncoded) *Rule {
	t.Helper()
	got, err := f.UnmarshalRule(
		&nftables.Rule{Exprs: enc.exprs, UserData: enc.userData},
		enc.chain, newStagedSetReader(enc), f.tableRef())
	require.NoError(t, err, "failed to decode encoding")
	return got
}

// nftRoundTrip encodes a rule and decodes the result, which is the shape every
// read-after-write path depends on: a rule that does not survive this makes Sync
// re-add it on every pass.
func nftRoundTrip(t *testing.T, f *NFT, r *Rule) *Rule {
	t.Helper()
	return nftDecodeRule(t, f, nftEncodeRule(t, f, r))
}

// nftExprKinds names the expressions an encoding produced, in order, so a test can
// assert the shape of an encoding without pinning every field.
func nftExprKinds(exprs []expr.Any) []string {
	var out []string
	for _, e := range exprs {
		switch e.(type) {
		case *expr.Meta:
			out = append(out, "meta")
		case *expr.Cmp:
			out = append(out, "cmp")
		case *expr.Payload:
			out = append(out, "payload")
		case *expr.Bitwise:
			out = append(out, "bitwise")
		case *expr.Lookup:
			out = append(out, "lookup")
		case *expr.Range:
			out = append(out, "range")
		case *expr.Ct:
			out = append(out, "ct")
		case *expr.Connlimit:
			out = append(out, "connlimit")
		case *expr.Dynset:
			out = append(out, "dynset")
		case *expr.Limit:
			out = append(out, "limit")
		case *expr.Log:
			out = append(out, "log")
		case *expr.Counter:
			out = append(out, "counter")
		case *expr.Verdict:
			out = append(out, "verdict")
		case *expr.Reject:
			out = append(out, "reject")
		case *expr.Immediate:
			out = append(out, "immediate")
		case *expr.NAT:
			out = append(out, "nat")
		case *expr.Masq:
			out = append(out, "masq")
		case *expr.Redir:
			out = append(out, "redir")
		default:
			out = append(out, "unknown")
		}
	}
	return out
}

// Every rule shape the backend can express must survive an encode/decode round
// trip, across both directions, both families and each match axis.
func TestNFTRuleRoundTrip(t *testing.T) {
	f := &NFT{table: "go_firewall"}

	rules := []*Rule{
		// Addresses and families.
		{Family: IPv4, Source: "192.168.0.0/24", Port: 23, Proto: UDP, Action: Accept},
		{Family: IPv4, Source: "1.2.3.4", Proto: TCP, Port: 22, Action: Accept},
		{Family: IPv4, Source: "1.2.3.4/32", Proto: TCP, Port: 22, Action: Accept},
		{Family: IPv4, Source: "10.0.0.0/12", Action: Drop},
		{Family: IPv4, Destination: "203.0.113.10", Port: 4791, Proto: TCP, Action: Reject},
		{Family: IPv6, Source: "2001:db8::1", Action: Drop},
		{Family: IPv6, Source: "2001:db8::/32", Action: Drop},
		{Family: IPv6, Destination: "2001:db8::/48", Proto: TCP, Port: 80, Action: Accept},
		// Negation.
		{Family: IPv6, Source: "!2001:db8::1", Action: Drop},
		{Family: IPv4, Destination: "!10.0.0.0/8", Action: Drop},
		// Named set references.
		{Family: IPv4, Source: "blocklist", Port: 22, Proto: TCP, Action: Drop},
		{Direction: DirOutput, Family: IPv6, Destination: "!allowlist", Port: 80, Proto: TCP, Action: Accept},
		// Family pinned with no address at all.
		{Family: IPv4, Port: 4789, Proto: UDP, Action: Accept},
		{Direction: DirOutput, Family: IPv6, Port: 4789, Proto: UDP, Action: Accept},
		// Ports: single, span, list, mixed list, source ports.
		{Proto: TCP, Port: 22, Action: Accept},
		{Proto: UDP, Ports: []PortRange{{Start: 1000, End: 2000}}, Action: Accept},
		{Proto: TCP, Ports: []PortRange{{Start: 80}, {Start: 443}}, Action: Accept},
		{Proto: TCP, Ports: []PortRange{{Start: 80}, {Start: 443}, {Start: 8000, End: 8100}}, Action: Accept},
		{Proto: TCP, SourcePort: 1024, Action: Accept},
		{Proto: TCP, SourcePorts: []PortRange{{Start: 1024, End: 65535}}, Action: Accept},
		{Proto: TCP, Port: 22, SourcePort: 1024, Action: Accept},
		// Protocols with no ports.
		{Proto: SCTP, Action: Accept},
		{Proto: GRE, Action: Accept},
		{Proto: ESP, Action: Accept},
		{Proto: AH, Action: Accept},
		// ICMP.
		{Proto: ICMP, Action: Accept},
		{Proto: ICMPv6, Action: Accept},
		{Proto: ICMP, ICMPType: Ptr[uint8](8), Action: Accept},
		{Family: IPv6, Proto: ICMPv6, ICMPType: Ptr[uint8](128), Action: Accept},
		// Both transports in a single row.
		{Proto: TCPUDP, Port: 53, Action: Accept},
		{Proto: TCPUDP, Ports: []PortRange{{Start: 80}, {Start: 443}}, Action: Accept},
		// Connection state.
		{Proto: TCP, Port: 22, State: StateEstablished, Action: Accept},
		{Proto: TCP, Port: 22, State: StateNew | StateEstablished, Action: Accept},
		{State: StateEstablished | StateRelated, Action: Accept},
		{State: StateInvalid, Action: Drop},
		// Interfaces, including a wildcard and a forward rule matching both.
		{InInterface: "eth0", Proto: TCP, Port: 22, Action: Accept},
		{InInterface: "eth*", Action: Accept},
		{Direction: DirOutput, OutInterface: "eth1", Proto: UDP, Port: 53, Action: Accept},
		{Direction: DirForward, InInterface: "eth0", OutInterface: "eth1", Proto: TCP, Port: 22, Action: Accept},
		// Rate and connection limits.
		{Proto: TCP, Port: 22, RateLimit: &RateLimit{Rate: 5, Unit: PerMinute}, Action: Accept},
		{Proto: TCP, Port: 22, RateLimit: &RateLimit{Rate: 100, Unit: PerSecond, Burst: 20}, Action: Accept},
		{Proto: TCP, Port: 22, ConnLimit: &ConnLimit{Count: 10}, Action: Drop},
		{Family: IPv4, Proto: TCP, Port: 22, ConnLimit: &ConnLimit{Count: 10, PerSource: true}, Action: Drop},
		{Family: IPv6, Proto: TCP, Port: 22, ConnLimit: &ConnLimit{Count: 3, PerSource: true}, Action: Drop},
		// Logging and comments.
		{Proto: TCP, Port: 22, Log: true, Action: Accept},
		{Proto: TCP, Port: 22, Log: true, LogPrefix: "ssh drop ", Action: Drop},
		{Proto: TCP, Port: 22, Comment: "managed by go-firewall", Action: Accept},
	}

	for _, r := range rules {
		got := nftRoundTrip(t, f, r)
		require.True(t, got.Equal(r, true),
			"round-trip mismatch: input %+v, output %+v", *r, *got)
		require.Equal(t, r.Comment, got.Comment, "comment must round-trip for %+v", *r)
	}
}

// In an inet table a network-header offset names a different field in each
// family, so every rule that resolves to a concrete family must carry the
// nfproto guard — without it an IPv4 source-address match also matches inside an
// IPv6 source address.
func TestNFTFamilyGuardAlwaysEmitted(t *testing.T) {
	f := &NFT{table: "go_firewall"}

	for _, r := range []*Rule{
		{Family: IPv4, Source: "1.2.3.4", Action: Drop},
		{Family: IPv6, Destination: "2001:db8::1", Action: Drop},
		{Family: IPv4, Proto: TCP, Port: 22, Action: Accept},
		{Family: IPv4, Proto: TCP, Port: 22, ConnLimit: &ConnLimit{Count: 2, PerSource: true}, Action: Drop},
	} {
		enc := nftEncodeRule(t, f, r)
		require.Equal(t, "meta", nftExprKinds(enc.exprs)[0], "expected a leading family guard for %+v", *r)
		meta := enc.exprs[0].(*expr.Meta)
		require.Equal(t, expr.MetaKeyNFPROTO, meta.Key, "expected an nfproto guard for %+v", *r)
		cmp := enc.exprs[1].(*expr.Cmp)
		require.Equal(t, []byte{f.nfprotoByte(r.impliedFamily())}, cmp.Data)
	}

	// A rule with no family to pin carries no guard.
	enc := nftEncodeRule(t, f, &Rule{Proto: TCP, Port: 22, Action: Accept})
	meta := enc.exprs[0].(*expr.Meta)
	require.Equal(t, expr.MetaKeyL4PROTO, meta.Key, "an unpinned rule must not claim a family")
}

// A per-source connection limit counts in a named dynamic set keyed on the
// source address. The set is family-typed, so its key must name the family's own
// address field and the set must be created alongside the rule.
func TestNFTPerSourceConnLimit(t *testing.T) {
	f := &NFT{table: "go_firewall"}

	r := &Rule{Family: IPv4, Proto: TCP, Port: 22, ConnLimit: &ConnLimit{Count: 10, PerSource: true}, Action: Drop}
	enc := nftEncodeRule(t, f, r)

	require.NotNil(t, enc.meterSet, "a per-source limit must create its counting set")
	require.True(t, enc.meterSet.Dynamic, "the counting set must be dynamic")
	require.Equal(t, nftables.TypeIPAddr, enc.meterSet.KeyType)

	var ds *expr.Dynset
	for _, e := range enc.exprs {
		if v, ok := e.(*expr.Dynset); ok {
			ds = v
		}
	}
	require.NotNil(t, ds, "expected a dynset statement")
	require.Equal(t, enc.meterSet.Name, ds.SetName)
	require.Len(t, ds.Exprs, 1)
	cl, ok := ds.Exprs[0].(*expr.Connlimit)
	require.True(t, ok, "the dynset must carry a connlimit")
	require.Equal(t, uint32(10), cl.Count)
	require.Equal(t, uint32(expr.NFT_CONNLIMIT_F_INV), cl.Flags, "the count must be an over-limit test")

	// The IPv6 form keys on the v6 source address instead.
	enc6 := nftEncodeRule(t, f, &Rule{Family: IPv6, Proto: TCP, Port: 22, ConnLimit: &ConnLimit{Count: 10, PerSource: true}, Action: Drop})
	require.Equal(t, nftables.TypeIP6Addr, enc6.meterSet.KeyType)
	require.NotEqual(t, enc.meterSet.Name, enc6.meterSet.Name, "each family counts in its own set")

	// The set name is derived from rule identity, so re-adding the same rule
	// reuses its counting state while a different rule gets its own.
	require.Equal(t, enc.meterSet.Name, nftEncodeRule(t, f, r).meterSet.Name)
	other := &Rule{Family: IPv4, Proto: TCP, Port: 443, ConnLimit: &ConnLimit{Count: 10, PerSource: true}, Action: Drop}
	require.NotEqual(t, enc.meterSet.Name, nftEncodeRule(t, f, other).meterSet.Name)

	// A family-agnostic per-source limit has no single row: the caller must fan
	// it out first, so validateRule rejects it.
	require.Error(t, f.validateRule(&Rule{Proto: TCP, Port: 22, ConnLimit: &ConnLimit{Count: 10, PerSource: true}, Action: Drop}),
		"a FamilyAny per-source limit must be expanded first")
	require.True(t, f.perSourceFamilySplit(&Rule{Proto: TCP, ConnLimit: &ConnLimit{Count: 1, PerSource: true}, Action: Drop}))
}

// A both-transports rule stays a single row: the protocol is an anonymous set of
// the two transport numbers, and the ports match through the shared offsets.
func TestNFTTCPUDPSingleRow(t *testing.T) {
	f := &NFT{table: "go_firewall"}
	enc := nftEncodeRule(t, f, &Rule{Proto: TCPUDP, Port: 53, Action: Accept})

	require.Len(t, enc.anonSets, 1, "the protocol pair rides one anonymous set")
	set := enc.anonSets[0]
	require.Equal(t, nftables.TypeInetProto, set.set.KeyType)
	require.True(t, set.set.Anonymous && set.set.Constant)
	require.ElementsMatch(t,
		[][]byte{{6}, {17}},
		[][]byte{set.elements[0].Key, set.elements[1].Key},
		"the set must hold tcp and udp")

	require.Equal(t, []string{"meta", "lookup", "payload", "cmp", "counter", "verdict"}, nftExprKinds(enc.exprs))
}

// The library's connection-state bits and the kernel's do not share an ordering,
// so the mapping between them is explicit and must stay symmetric.
func TestNFTConnStateMask(t *testing.T) {
	f := new(NFT)
	for _, c := range []struct {
		state ConnState
		mask  uint32
	}{
		{StateNew, 0x08},
		{StateEstablished, 0x02},
		{StateRelated, 0x04},
		{StateInvalid, 0x01},
		{StateEstablished | StateRelated, 0x06},
		{StateNew | StateEstablished | StateRelated | StateInvalid, 0x0f},
	} {
		require.Equal(t, c.mask, f.ctStateMask(c.state), "encoding %v", c.state.Strings())
		got, ok := f.connStateForMask(c.mask)
		require.True(t, ok, "decoding mask %#x", c.mask)
		require.Equal(t, c.state, got, "decoding mask %#x", c.mask)
	}

	// A mask carrying a state the model cannot hold (untracked) is rejected
	// rather than narrowed to the states that did map, so the row stays opaque.
	_, ok := f.connStateForMask(0x40)
	require.False(t, ok, "an unmodelled ct state must not decode")
	_, ok = f.connStateForMask(0x02 | 0x40)
	require.False(t, ok, "a partly unmodelled ct state mask must not decode")
}

// nft shortens a byte-aligned prefix to a narrower payload load rather than
// masking, so the decoder must accept that form as well as the masked one this
// backend writes.
func TestNFTShortenedPrefixDecodes(t *testing.T) {
	f := &NFT{table: "go_firewall"}

	for _, c := range []struct {
		fam    Family
		offset uint32
		length uint32
		data   []byte
		want   string
	}{
		{IPv4, 12, 1, []byte{10}, "10.0.0.0/8"},
		{IPv4, 12, 2, []byte{192, 168}, "192.168.0.0/16"},
		{IPv6, 8, 4, []byte{0x20, 0x01, 0x0d, 0xb8}, "2001:db8::/32"},
	} {
		nr := &nftables.Rule{Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{f.nfprotoByte(c.fam)}},
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: c.offset, Len: c.length},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: c.data},
			&expr.Verdict{Kind: expr.VerdictDrop},
		}}
		got, err := f.UnmarshalRule(nr, "input", newStagedSetReader(), f.tableRef())
		require.NoError(t, err)
		require.Equal(t, c.want, got.Source)
	}
}

// A row carrying a construct the Rule model cannot hold must fail to decode, so
// the caller keeps it as an opaque slot instead of misrepresenting it.
func TestNFTUnmodelledRowsRejected(t *testing.T) {
	f := &NFT{table: "go_firewall"}
	sets := newStagedSetReader()

	cases := map[string][]expr.Any{
		"unknown l4proto": {
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{2}},
			&expr.Verdict{Kind: expr.VerdictAccept},
		},
		"jump verdict": {
			&expr.Verdict{Kind: expr.VerdictJump, Chain: "other"},
		},
		"unmodelled expression": {
			&expr.Quota{Bytes: 100},
			&expr.Verdict{Kind: expr.VerdictAccept},
		},
		"address without a family guard": {
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 12, Len: 4},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{1, 2, 3, 4}},
			&expr.Verdict{Kind: expr.VerdictAccept},
		},
		"under-limit connection count": {
			&expr.Connlimit{Count: 5},
			&expr.Verdict{Kind: expr.VerdictAccept},
		},
		"no verdict at all": {
			&expr.Counter{},
		},
	}
	for name, exprs := range cases {
		_, err := f.UnmarshalRule(&nftables.Rule{Exprs: exprs}, "input", sets, f.tableRef())
		require.Error(t, err, "expected %s to stay opaque", name)
	}
}

// An ip or ip6 table is itself the family qualifier, so an operator's rules in
// one carry no nfproto match. Reading those rows against the table's family is
// what keeps a foreign address match — a literal or an address set — out of the
// opaque bucket, and what reports the one family the row can ever match.
func TestNFTForeignTableFamilyFromTable(t *testing.T) {
	f := &NFT{table: "go_firewall"}
	sets := newStagedSetReader()

	for _, c := range []struct {
		name   string
		tbl    *nftables.Table
		offset uint32
		length uint32
		data   []byte
		want   *Rule
	}{
		{
			name: "ip table address match", offset: 12, length: 4, data: []byte{192, 0, 2, 10},
			tbl:  &nftables.Table{Family: nftables.TableFamilyIPv4, Name: "filter"},
			want: &Rule{Family: IPv4, Source: "192.0.2.10", Action: Accept},
		},
		{
			name: "ip6 table address match", offset: 8, length: 16,
			data: net.ParseIP("2001:db8::1").To16(),
			tbl:  &nftables.Table{Family: nftables.TableFamilyIPv6, Name: "filter"},
			want: &Rule{Family: IPv6, Source: "2001:db8::1", Action: Accept},
		},
	} {
		nr := &nftables.Rule{Exprs: []expr.Any{
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: c.offset, Len: c.length},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: c.data},
			&expr.Verdict{Kind: expr.VerdictAccept},
		}}
		got, err := f.UnmarshalRule(nr, "input", sets, c.tbl)
		require.NoError(t, err, c.name)
		require.Equal(t, c.want.Family, got.Family, c.name)
		require.Equal(t, c.want.Source, got.Source, c.name)
	}

	// A set reference is the same case: the set's own family is not needed to read
	// the row, because the table already pinned it.
	nr := &nftables.Rule{Exprs: []expr.Any{
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 12, Len: 4},
		&expr.Lookup{SourceRegister: 1, SetName: "allowlist"},
		&expr.Verdict{Kind: expr.VerdictAccept},
	}}
	got, err := f.UnmarshalRule(nr, "input", sets, &nftables.Table{Family: nftables.TableFamilyIPv4, Name: "filter"})
	require.NoError(t, err)
	require.Equal(t, IPv4, got.Family)
	require.Equal(t, "allowlist", got.Source)

	// A row with no family evidence at all still takes the table's family: an ip
	// table can only ever match IPv4.
	nr = &nftables.Rule{Exprs: []expr.Any{
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{6}},
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.BigEndian.PutUint16(8123)},
		&expr.Verdict{Kind: expr.VerdictAccept},
	}}
	got, err = f.UnmarshalRule(nr, "input", sets, &nftables.Table{Family: nftables.TableFamilyIPv4, Name: "filter"})
	require.NoError(t, err)
	require.Equal(t, IPv4, got.Family)

	// The backend's own inet table settles nothing, so an unguarded address match
	// there stays opaque (see TestNFTUnmodelledRowsRejected).
	fam, ok := f.familyForTable(f.tableRef())
	require.False(t, ok)
	require.Equal(t, FamilyAny, fam)
}

// nftables reports the default burst of 5 on every limit even when none was
// asked for, so the default must read back as unset or a rule never matches its
// own read-back and Sync re-adds it forever.
func TestNFTRateBurstDefaultNormalized(t *testing.T) {
	f := &NFT{table: "go_firewall"}

	got := nftRoundTrip(t, f, &Rule{Proto: TCP, Port: 22, RateLimit: &RateLimit{Rate: 5, Unit: PerMinute}, Action: Accept})
	require.NotNil(t, got.RateLimit)
	require.Zero(t, got.RateLimit.Burst, "the netfilter default burst must read as unset")

	// An explicit burst of something other than the default survives intact.
	got = nftRoundTrip(t, f, &Rule{Proto: TCP, Port: 22, RateLimit: &RateLimit{Rate: 5, Unit: PerHour, Burst: 20}, Action: Accept})
	require.Equal(t, uint(20), got.RateLimit.Burst)
	require.Equal(t, PerHour, got.RateLimit.Unit)
}

// The counters a listed rule carries are reported onto the rule but are not part
// of its identity.
func TestNFTCounters(t *testing.T) {
	f := &NFT{table: "go_firewall"}
	nr := &nftables.Rule{Exprs: []expr.Any{
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{6}},
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.BigEndian.PutUint16(22)},
		&expr.Counter{Packets: 42, Bytes: 336},
		&expr.Verdict{Kind: expr.VerdictAccept},
	}}
	r, err := f.UnmarshalRule(nr, "input", newStagedSetReader(), f.tableRef())
	require.NoError(t, err)
	require.Equal(t, uint64(42), r.Packets)
	require.Equal(t, uint64(336), r.Bytes)
	require.True(t, r.EqualBase(&Rule{Proto: TCP, Port: 22, Action: Accept}, true),
		"counters must not be part of rule identity: %+v", r)
}

// A comment and a log prefix ride in user data and a log expression rather than
// a quoted string, so characters the textual interface could never carry now
// round-trip verbatim.
func TestNFTCommentAndPrefixVerbatim(t *testing.T) {
	f := &NFT{table: "go_firewall"}

	for _, s := range []string{`has "quotes"`, "has # hash", "  leading and trailing  ", `back\slash`} {
		got := nftRoundTrip(t, f, &Rule{Proto: TCP, Port: 22, Comment: s, Action: Accept})
		require.Equal(t, s, got.Comment, "comment must survive verbatim")

		got = nftRoundTrip(t, f, &Rule{Proto: TCP, Port: 22, Log: true, LogPrefix: s, Action: Accept})
		require.Equal(t, s, got.LogPrefix, "log prefix must survive verbatim")
	}

	// Both are length-capped by nftables, so an over-long value is rejected up
	// front rather than being silently truncated by the kernel.
	require.Error(t, f.validateRule(&Rule{Action: Accept, Comment: string(make([]byte, nftCommentMax+1))}))
	require.Error(t, f.validateRule(&Rule{Action: Accept, Log: true, LogPrefix: string(make([]byte, nftLogPrefixMax+1))}))
}

// Shapes nftables cannot express must be rejected by validateRule, which the
// encoding entry points run, rather than producing a rule that would not read
// back as written.
func TestNFTMarshalRejections(t *testing.T) {
	f := &NFT{table: "go_firewall"}

	cases := map[string]*Rule{
		"port without a protocol":           {Port: 80, Proto: ProtocolAny, Action: Accept},
		"input interface on an output rule": {Direction: DirOutput, InInterface: "eth0", Action: Accept},
		"output interface on an input rule": {OutInterface: "eth0", Action: Accept},
		"no action":                         {Proto: TCP, Port: 22},
	}
	for name, r := range cases {
		require.Error(t, f.validateRule(r), "expected %s to be rejected", name)
	}
}

// Every NAT kind must survive an encode/decode round trip.
func TestNFTNATRoundTrip(t *testing.T) {
	f := &NFT{table: "go_firewall"}

	rules := []*NATRule{
		{Kind: DNAT, Proto: TCP, Port: 80, ToAddress: "192.168.1.2"},
		{Kind: DNAT, Proto: TCP, Port: 80, ToAddress: "192.168.1.2", ToPort: 8080},
		{Kind: DNAT, Proto: UDP, Ports: []PortRange{{Start: 5000, End: 5100}}, ToAddress: "192.168.1.2"},
		{Kind: DNAT, Proto: TCP, Port: 80, ToAddress: "2001:db8::1", ToPort: 8080},
		{Kind: SNAT, Proto: TCP, Interface: "eth0", ToAddress: "1.2.3.4"},
		{Kind: SNAT, Interface: "eth0", ToAddress: "2001:db8::1"},
		{Kind: Redirect, Proto: TCP, Port: 80, ToPort: 8080},
		{Kind: Masquerade, Interface: "eth0"},
		{Kind: Masquerade},
		{Kind: DNAT, Family: IPv4, Source: "10.0.0.0/8", Proto: TCP, Port: 80, ToAddress: "192.168.1.2"},
		{Kind: SNAT, Proto: SCTP, Interface: "eth0", ToAddress: "1.2.3.4"},
	}
	for _, r := range rules {
		enc, err := f.MarshalNATRule(r)
		require.NoError(t, err, "failed to marshal %+v", *r)
		got, err := f.UnmarshalNATRule(
			&nftables.Rule{Exprs: enc.exprs}, newStagedSetReader(enc), f.tableRef())
		require.NoError(t, err, "failed to decode %+v", *r)
		require.True(t, got.EqualBase(r), "round-trip mismatch: input %+v, output %+v", *r, *got)
	}

	// DNAT lands in prerouting, SNAT in postrouting.
	enc, err := f.MarshalNATRule(&NATRule{Kind: DNAT, Proto: TCP, Port: 80, ToAddress: "1.2.3.4"})
	require.NoError(t, err)
	require.Equal(t, "prerouting", enc.chain)
	enc, err = f.MarshalNATRule(&NATRule{Kind: SNAT, ToAddress: "1.2.3.4"})
	require.NoError(t, err)
	require.Equal(t, "postrouting", enc.chain)
}

// A family-agnostic NAT rule is one unpinned row covering both families, so it
// must not acquire a family guard on the way out.
func TestNFTFamilyAnyNATIsDualStack(t *testing.T) {
	f := &NFT{table: "go_firewall"}
	enc, err := f.MarshalNATRule(&NATRule{Kind: Masquerade, Interface: "eth0"})
	require.NoError(t, err)
	for _, e := range enc.exprs {
		if m, ok := e.(*expr.Meta); ok {
			require.NotEqual(t, expr.MetaKeyNFPROTO, m.Key,
				"a family-agnostic masquerade must stay unpinned")
		}
	}
}

// nftables' snat expression carries no port, so a source-port translation is a
// shape this backend genuinely cannot express and must report as unsupported
// rather than silently dropping the port.
func TestNFTNATRejections(t *testing.T) {
	f := &NFT{table: "go_firewall"}

	err := f.validateNAT(&NATRule{Kind: SNAT, Proto: TCP, ToAddress: "1.2.3.4", ToPort: 8080})
	require.ErrorIs(t, err, ErrUnsupportedNAT, "snat cannot translate the source port")

	// A CIDR translation target has no single address to rewrite to; the encoder
	// rejects it while building the nat expression.
	_, err = f.MarshalNATRule(&NATRule{Kind: DNAT, Proto: TCP, Port: 80, ToAddress: "10.0.0.0/8"})
	require.Error(t, err, "a translation target must be a single address")
}

// An address set's entries are stored as element keys — discrete addresses in a
// plain set, boundary markers in an interval set — and must be rendered back as
// the CIDR or range they came from.
func TestNFTAddressSetElements(t *testing.T) {
	f := new(NFT)
	// A discrete set holds one element per address.
	elems, err := f.setElements("1.2.3.4", false)
	require.NoError(t, err)
	require.Len(t, elems, 1)
	require.Equal(t, []byte{1, 2, 3, 4}, elems[0].Key)

	// A range cannot be stored in a discrete set.
	_, err = f.setElements("10.0.0.0/8", false)
	require.Error(t, err)

	// An interval set stores the inclusive start and an exclusive end marker.
	elems, err = f.setElements("10.0.0.0/8", true)
	require.NoError(t, err)
	require.Len(t, elems, 2)
	require.Equal(t, []byte{10, 0, 0, 0}, elems[0].Key)
	require.Equal(t, []byte{11, 0, 0, 0}, elems[1].Key)
	require.True(t, elems[1].IntervalEnd)

	// Round-trip each entry form through the element encoding and back.
	for _, c := range []struct {
		entry    string
		interval bool
	}{
		{"1.2.3.4", false},
		{"2001:db8::1", false},
		{"10.0.0.0/8", true},
		{"192.168.1.0/24", true},
		{"2001:db8::/32", true},
		{"10.0.0.1-10.0.0.9", true},
	} {
		els, eerr := f.setElements(c.entry, c.interval)
		require.NoError(t, eerr, "encoding %q", c.entry)
		got := f.addressSetEntries(&nftSetContents{
			set:      &nftables.Set{Interval: c.interval},
			elements: els,
		})
		require.Equal(t, []string{c.entry}, got, "round-trip of %q", c.entry)
	}
}

// A dynamic set is connection-limit counting state and an anonymous set is a
// rule's own inline literal; neither is a caller-managed address set.
func TestNFTAddressSetKeyTypes(t *testing.T) {
	f := new(NFT)
	kt, err := f.setKeyType(IPv4)
	require.NoError(t, err)
	require.Equal(t, nftables.TypeIPAddr, kt)
	require.Equal(t, IPv4, f.familyForKeyType(kt))

	kt, err = f.setKeyType(IPv6)
	require.NoError(t, err)
	require.Equal(t, nftables.TypeIP6Addr, kt)
	require.Equal(t, IPv6, f.familyForKeyType(kt))

	// An nftables set carries a single address type, so an unspecified family
	// resolves to IPv4 rather than failing.
	kt, err = f.setKeyType(FamilyAny)
	require.NoError(t, err)
	require.Equal(t, nftables.TypeIPAddr, kt)
}

// An interface name is compared against a fixed-width NUL-padded buffer, while a
// trailing '*' makes it a prefix match against just the leading characters.
func TestNFTInterfaceEncoding(t *testing.T) {
	f := new(NFT)
	exact := f.ifnameBytes("eth0")
	require.Len(t, exact, 16, "an exact interface match is fixed width")
	require.Equal(t, "eth0", f.ifnameString(exact))

	wild := f.ifnameBytes("eth*")
	require.Equal(t, []byte("eth"), wild, "a wildcard compares only the prefix")
	require.Equal(t, "eth*", f.ifnameString(wild))
}

// The table name is derived from the rule prefix and must be a valid nftables
// identifier, which cannot begin with a digit.
func TestNFTSanitizeName(t *testing.T) {
	require.Equal(t, "fw_1fw", sanitizeNFTName("1fw"))
	require.Equal(t, "go_firewall", sanitizeNFTName(""))
	require.Equal(t, "go_firewall", sanitizeNFTName("!!!"))
	require.Equal(t, "my_fw", sanitizeNFTName("my-fw"))
	require.Equal(t, "my_fw", sanitizeNFTName("my.fw"))
}

// A concrete-family removal of a merged row must keep the coverage the caller
// never named, across both the family and the transport axis.
func TestNFTSplitMergedRowTwoAxes(t *testing.T) {
	f := &NFT{table: "go_firewall"}

	// A single row covering both families and both transports.
	merged := &Rule{Proto: TCPUDP, Port: 53, Action: Accept}
	// Removing only the IPv4 TCP half leaves three cells behind.
	target := &Rule{Family: IPv4, Proto: TCP, Port: 53, Action: Accept}
	remainder := splitMergedRow(merged, target)
	require.NotEmpty(t, remainder, "removing one cell must leave the rest in place")

	// Every remainder must still be expressible, or the removal would fail
	// halfway through and drop coverage it meant to keep.
	for _, r := range remainder {
		_, err := f.MarshalRule(r)
		require.NoError(t, err, "remainder %+v must be expressible", *r)
	}
}
