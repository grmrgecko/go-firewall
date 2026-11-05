package firewall

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"github.com/google/nftables/userdata"
	"go4.org/netipx"
	"golang.org/x/sys/unix"
)

const (
	// NFTDefaultTable is the table name used when no rule prefix is supplied.
	NFTDefaultTable = "go_firewall"
	// nftMeterSetSize is the dynamic-set size nft itself gives a meter, kept so a
	// set this backend creates is indistinguishable from one nft would have made.
	nftMeterSetSize = 65535
	// nftCommentMax is the longest rule comment nftables stores (its own limit).
	nftCommentMax = 128
	// nftLogPrefixMax is the longest log prefix the kernel's nf_log accepts.
	nftLogPrefixMax = 127
)

// NFT manages firewall rules through the nftables netlink API. To avoid
// clobbering rules owned by other tooling, every rule this backend creates lives
// in a private `inet` table (named after the rule prefix) with its own input and
// output base chains. Writes are scoped to that table; reads also report rules
// found in other tables so callers can see the whole ruleset.
type NFT struct {
	// table is the nftables table this backend owns.
	table string
	// mu guards the ensured/natEnsured flags so concurrent callers do not race on
	// the one-time table/chain setup.
	mu sync.Mutex
	// ensured records whether the private table/chains have been created this
	// session, so the setup runs only once.
	ensured bool
	// natEnsured records the same for the nat base chains, which are created
	// lazily only when a NAT rule is first written.
	natEnsured bool
}

// nftSetID hands out the transaction-local identifiers an anonymous set is
// referenced by within a batch. Only uniqueness inside one batch matters, so a
// process-wide counter is sufficient; it also keeps the library's own
// auto-allocation (which only runs for a set with ID 0) out of the picture.
var nftSetID atomic.Uint32

// nextSetID returns the next anonymous-set identifier.
func (f *NFT) nextSetID() uint32 {
	return nftSetID.Add(1)
}

// sanitizeNFTName reduces an arbitrary prefix to a valid nftables identifier
// (letters, digits and underscores), falling back to the default when nothing
// usable remains.
func sanitizeNFTName(prefix string) string {
	var b strings.Builder
	for _, r := range prefix {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_':
			b.WriteRune(r)
		case r == '-' || r == ' ' || r == '.':
			b.WriteRune('_')
		}
	}
	name := strings.Trim(b.String(), "_")
	if name == "" {
		return NFTDefaultTable
	}
	// An nftables identifier must begin with a letter; a digit-led prefix would
	// make every later table/chain creation fail.
	if c := name[0]; c >= '0' && c <= '9' {
		name = "fw_" + name
	}
	return name
}

// nftConn returns a transaction scope for one operation. Despite the name this
// opens nothing: nftables.New only allocates, and the netlink socket is dialed
// and closed per operation inside the library either way, so there is no
// connection here worth caching on the backend.
//
// What the value does carry is a batch: staged additions and deletions
// accumulate on it until Flush sends and clears them all. That is why each
// operation takes its own rather than sharing one — a Flush on a shared scope
// would commit whatever another caller had half-staged.
func nftConn() (*nftables.Conn, error) {
	return nftables.New()
}

// NewNFT constructs an nftables-backed Manager, deriving the private table name
// from rulePrefix and verifying nf_tables is reachable over netlink.
func NewNFT(ctx context.Context, rulePrefix string) (*NFT, error) {
	nft := &NFT{table: sanitizeNFTName(rulePrefix)}

	// Confirm the nf_tables subsystem answers. Opening the socket alone proves
	// little, so list the ruleset's tables: that fails without the kernel module
	// or the privileges every later operation needs.
	c, err := nftConn()
	if err != nil {
		return nil, fmt.Errorf("unable to open the nftables netlink socket: %s", err)
	}
	if _, err := c.ListTables(); err != nil {
		return nil, fmt.Errorf("unable to list the nftables ruleset: %s", err)
	}

	return nft, nil
}

// Type returns the manager type.
func (f *NFT) Type() string {
	return NFTType
}

// Capabilities returns the set of features this backend can express.
func (f *NFT) Capabilities() Capabilities {
	return Capabilities{
		Output:               true,
		Forward:              true,
		IPv6:                 true,
		PortPair:             true,
		ConnState:            true,
		InterfaceMatch:       true,
		Logging:              true,
		RateLimit:            true,
		ConnLimit:            true,
		NAT:                  true,
		RuleOrdering:         true,
		DefaultPolicy:        true,
		RuleCounters:         true,
		AddressSets:          true,
		Comments:             true,
		Negation:             true,
		RejectAction:         true,
		FamilyWithoutAddress: true,
	}
}

// GetZone reports no zone; nftables has no interface-to-zone mapping in this model.
func (f *NFT) GetZone(ctx context.Context, iface string) (zoneName string, err error) {
	return "", nil
}

// tableRef returns the netlink handle for this backend's private inet table.
func (f *NFT) tableRef() *nftables.Table {
	return &nftables.Table{Family: nftables.TableFamilyINet, Name: f.table}
}

// chainRef returns the netlink handle for one of the private table's chains.
// Only the name and table identify a chain for rule operations, so the hook
// properties are left unset here; ensureTable owns their definition.
func (f *NFT) chainRef(name string) *nftables.Chain {
	return &nftables.Chain{Name: name, Table: f.tableRef()}
}

// nftFilterChains lists the private table's filter base chains, in the order a
// read enumerates them.
var nftFilterChains = []string{"input", "output", "forward"}

// nftNATChains lists the private table's nat base chains, in read order.
var nftNATChains = []string{"prerouting", "postrouting"}

// directionForChain returns the rule direction a filter base-chain name maps
// to (the inverse of chainForDirection).
func (f *NFT) directionForChain(chain string) Direction {
	switch chain {
	case "output":
		return DirOutput
	case "forward":
		return DirForward
	}
	return DirInput
}

// chainForDirection returns the filter base-chain name a rule of the given
// direction lives in.
func (f *NFT) chainForDirection(d Direction) string {
	switch d {
	case DirOutput:
		return "output"
	case DirForward:
		return "forward"
	}
	return "input"
}

// familyName renders a netlink table family as the keyword nft prints, so a
// foreign rule's recorded table reads the way an operator would write it
// ("inet filter"). The container-runtime table check parses this same form.
func (f *NFT) familyName(fam nftables.TableFamily) string {
	switch fam {
	case nftables.TableFamilyIPv4:
		return "ip"
	case nftables.TableFamilyIPv6:
		return "ip6"
	case nftables.TableFamilyINet:
		return "inet"
	case nftables.TableFamilyARP:
		return "arp"
	case nftables.TableFamilyBridge:
		return "bridge"
	case nftables.TableFamilyNetdev:
		return "netdev"
	}
	return "unknown"
}

// familyForTable returns the family every row of a single-family table matches.
// An ip or ip6 table is the family qualifier for its own rules, so those rows
// carry no nfproto match of their own; an inet table (this backend's own, and
// the arp/bridge/netdev families) settles nothing, reporting false.
func (f *NFT) familyForTable(tbl *nftables.Table) (Family, bool) {
	if tbl == nil {
		return FamilyAny, false
	}
	switch tbl.Family {
	case nftables.TableFamilyIPv4:
		return IPv4, true
	case nftables.TableFamilyIPv6:
		return IPv6, true
	}
	return FamilyAny, false
}

// isNotExist reports whether a netlink error means the object is simply absent,
// which every read path treats as "nothing there yet" rather than a failure.
func (f *NFT) isNotExist(err error) bool {
	return errors.Is(err, unix.ENOENT)
}

// -----------------------------------------------------------------------------
// Expression encoding
// -----------------------------------------------------------------------------

// nftAnonSet is an anonymous constant set an encoded rule references. It must be
// created in the same netlink batch as the rule, before the rule's own message.
type nftAnonSet struct {
	set      *nftables.Set
	elements []nftables.SetElement
}

// nftEncoded is a marshalled rule: the chain it belongs in, the expression list
// the kernel stores, the comment as nftables user data, any anonymous sets the
// expressions reference, and the named dynamic set a per-source connection limit
// counts in. Encoding is pure — nothing here touches the kernel — so a caller
// can inspect the result before committing it.
type nftEncoded struct {
	chain    string
	exprs    []expr.Any
	userData []byte
	anonSets []nftAnonSet
	// meterSet is the named dynamic set a per-source connection-limit rule
	// counts in; it outlives the batch and is created separately.
	meterSet *nftables.Set
}

// ifnameBytes renders an interface name as the comparison operand nftables
// expects: a trailing '*' is a prefix match, compared against just the leading
// characters, and anything else is an exact match against the fixed 16-byte
// (IFNAMSIZ) NUL-padded buffer.
func (f *NFT) ifnameBytes(name string) []byte {
	if strings.HasSuffix(name, "*") {
		return []byte(strings.TrimSuffix(name, "*"))
	}
	b := make([]byte, unix.IFNAMSIZ)
	copy(b, name)
	return b
}

// ifnameString reverses ifnameBytes: a full-width operand is an exact name with
// its NUL padding trimmed, a short one a prefix match rendered back with '*'.
func (f *NFT) ifnameString(data []byte) string {
	if len(data) == unix.IFNAMSIZ {
		return string(bytes.TrimRight(data, "\x00"))
	}
	return string(bytes.TrimRight(data, "\x00")) + "*"
}

// nfprotoByte returns the NFPROTO constant a family pins to.
func (f *NFT) nfprotoByte(fam Family) byte {
	if fam == IPv6 {
		return unix.NFPROTO_IPV6
	}
	return unix.NFPROTO_IPV4
}

// familyForNFProto reverses nfprotoByte.
func (f *NFT) familyForNFProto(b byte) (Family, bool) {
	switch b {
	case unix.NFPROTO_IPV4:
		return IPv4, true
	case unix.NFPROTO_IPV6:
		return IPv6, true
	}
	return FamilyAny, false
}

// addrField describes where a source or destination address sits in the network
// header of the given family, which is what a payload load must name.
func addrField(fam Family, source bool) (offset, length uint32) {
	if fam == IPv6 {
		if source {
			return 8, 16
		}
		return 24, 16
	}
	if source {
		return 12, 4
	}
	return 16, 4
}

// ipProtoByte returns the IP protocol number nftables matches a protocol by.
func (f *NFT) ipProtoByte(p Protocol) (byte, bool) {
	switch p {
	case TCP:
		return unix.IPPROTO_TCP, true
	case UDP:
		return unix.IPPROTO_UDP, true
	case ICMP:
		return unix.IPPROTO_ICMP, true
	case ICMPv6:
		return unix.IPPROTO_ICMPV6, true
	case SCTP:
		return unix.IPPROTO_SCTP, true
	case GRE:
		return unix.IPPROTO_GRE, true
	case ESP:
		return unix.IPPROTO_ESP, true
	case AH:
		return unix.IPPROTO_AH, true
	}
	return 0, false
}

// protocolForByte reverses ipProtoByte, returning ProtocolAny for a protocol the
// Rule model has no field for.
func (f *NFT) protocolForByte(b byte) Protocol {
	switch b {
	case unix.IPPROTO_TCP:
		return TCP
	case unix.IPPROTO_UDP:
		return UDP
	case unix.IPPROTO_ICMP:
		return ICMP
	case unix.IPPROTO_ICMPV6:
		return ICMPv6
	case unix.IPPROTO_SCTP:
		return SCTP
	case unix.IPPROTO_GRE:
		return GRE
	case unix.IPPROTO_ESP:
		return ESP
	case unix.IPPROTO_AH:
		return AH
	}
	return ProtocolAny
}

// nftConnStates maps the library's connection-state bits onto the kernel's ct
// state bits, which do not share an ordering: the library counts from new,
// netfilter from invalid.
var nftConnStates = []struct {
	state ConnState
	bit   uint32
}{
	{StateNew, 0x08},
	{StateEstablished, 0x02},
	{StateRelated, 0x04},
	{StateInvalid, 0x01},
}

// ctStateMask renders a connection-state set as the kernel bitmask a ct state
// match tests against.
func (f *NFT) ctStateMask(s ConnState) uint32 {
	var mask uint32
	for _, cs := range nftConnStates {
		if s&cs.state != 0 {
			mask |= cs.bit
		}
	}
	return mask
}

// connStateForMask reverses ctStateMask, reporting false when the mask carries a
// state the Rule model cannot hold (untracked, say), so the row stays opaque
// rather than being silently narrowed to the states that did map.
func (f *NFT) connStateForMask(mask uint32) (ConnState, bool) {
	var state ConnState
	var covered uint32
	for _, cs := range nftConnStates {
		if mask&cs.bit != 0 {
			state |= cs.state
			covered |= cs.bit
		}
	}
	if covered != mask {
		return 0, false
	}
	return state, true
}

// rateUnitSeconds returns the number of seconds a rate unit spans, which is how
// nftables expresses a limit's interval.
func rateUnitSeconds(u RateUnit) uint64 {
	switch u {
	case PerMinute:
		return 60
	case PerHour:
		return 3600
	case PerDay:
		return 86400
	}
	return 1
}

// rateUnitForSeconds reverses rateUnitSeconds.
func (f *NFT) rateUnitForSeconds(s uint64) (RateUnit, bool) {
	switch s {
	case 1:
		return PerSecond, true
	case 60:
		return PerMinute, true
	case 3600:
		return PerHour, true
	case 86400:
		return PerDay, true
	}
	return PerSecond, false
}

// addrBytes renders an address or CIDR as the network-header operand a match
// compares against: the raw address bytes plus, for a prefix, the mask to apply
// first. A host address yields a nil mask.
func (f *NFT) addrBytes(fam Family, addr string) (value, mask []byte, err error) {
	width := 4
	if fam == IPv6 {
		width = 16
	}
	if _, ipnet, cerr := net.ParseCIDR(addr); cerr == nil {
		ones, bits := ipnet.Mask.Size()
		if bits/8 != width {
			return nil, nil, fmt.Errorf("address %q does not match the rule's family", addr)
		}
		network := ipnet.IP.To16()
		if width == 4 {
			network = ipnet.IP.To4()
		}
		if ones == bits {
			// A host prefix is the address itself; no masking needed.
			return network, nil, nil
		}
		return network, ipnet.Mask, nil
	}
	ip := net.ParseIP(addr)
	if ip == nil {
		return nil, nil, fmt.Errorf("invalid address %q", addr)
	}
	if width == 4 {
		v4 := ip.To4()
		if v4 == nil {
			return nil, nil, fmt.Errorf("address %q is not IPv4", addr)
		}
		return v4, nil, nil
	}
	if ip.To4() != nil {
		return nil, nil, fmt.Errorf("address %q is not IPv6", addr)
	}
	return ip.To16(), nil, nil
}

// cmpOp returns the comparison a match uses, inverted when the value was negated.
func (f *NFT) cmpOp(neg bool) expr.CmpOp {
	if neg {
		return expr.CmpOpNeq
	}
	return expr.CmpOpEq
}

// encodeAddr appends the expressions matching a source or destination address.
// A named set is referenced by a lookup; an address or CIDR loads the header
// field and compares it, masking first when the value is a prefix.
func (f *NFT) encodeAddr(exprs []expr.Any, fam Family, value string, source bool) ([]expr.Any, error) {
	neg, bare := splitAddrNeg(strings.TrimSpace(value))
	offset, length := addrField(fam, source)
	exprs = append(exprs, &expr.Payload{
		DestRegister: 1,
		Base:         expr.PayloadBaseNetworkHeader,
		Offset:       offset,
		Len:          length,
	})
	if isSetRef(value) {
		exprs = append(exprs, &expr.Lookup{
			SourceRegister: 1,
			SetName:        bare,
			Invert:         neg,
		})
		return exprs, nil
	}
	val, mask, err := f.addrBytes(fam, bare)
	if err != nil {
		return nil, err
	}
	if mask != nil {
		// A prefix match is the masked field compared against the network
		// address. nft shortens a byte-aligned prefix to a narrower payload load
		// instead; both forms are accepted on read, and this one covers every
		// prefix length with a single shape.
		exprs = append(exprs, &expr.Bitwise{
			SourceRegister: 1,
			DestRegister:   1,
			Len:            uint32(len(val)),
			Mask:           mask,
			Xor:            make([]byte, len(val)),
		})
	}
	exprs = append(exprs, &expr.Cmp{Op: f.cmpOp(neg), Register: 1, Data: val})
	return exprs, nil
}

// portElements renders port ranges as the elements of an anonymous set. An
// interval element is the inclusive start plus an end marker at the exclusive
// upper bound, which is how nftables stores a span.
func (f *NFT) portElements(specs []PortRange, interval bool) []nftables.SetElement {
	var elems []nftables.SetElement
	for _, p := range specs {
		elems = append(elems, nftables.SetElement{Key: binaryutil.BigEndian.PutUint16(p.Start)})
		if interval {
			elems = append(elems, nftables.SetElement{
				Key:         binaryutil.BigEndian.PutUint16(p.End + 1),
				IntervalEnd: true,
			})
		}
	}
	return elems
}

// encodePorts appends the expressions matching a source or destination port. A
// single discrete port compares directly, a single span is a range, and a list
// becomes an anonymous set (an interval set when any member is a span).
func (f *NFT) encodePorts(enc *nftEncoded, specs []PortRange, source bool) {
	offset := uint32(2)
	if source {
		offset = 0
	}
	enc.exprs = append(enc.exprs, &expr.Payload{
		DestRegister: 1,
		Base:         expr.PayloadBaseTransportHeader,
		Offset:       offset,
		Len:          2,
	})

	if len(specs) == 1 {
		p := specs[0]
		if p.Start == p.End {
			enc.exprs = append(enc.exprs, &expr.Cmp{
				Op: expr.CmpOpEq, Register: 1, Data: binaryutil.BigEndian.PutUint16(p.Start),
			})
			return
		}
		enc.exprs = append(enc.exprs, &expr.Range{
			Op:       expr.CmpOpEq,
			Register: 1,
			FromData: binaryutil.BigEndian.PutUint16(p.Start),
			ToData:   binaryutil.BigEndian.PutUint16(p.End),
		})
		return
	}

	interval := false
	for _, p := range specs {
		if p.Start != p.End {
			interval = true
			break
		}
	}
	set := &nftables.Set{
		Table:     f.tableRef(),
		ID:        f.nextSetID(),
		Name:      "__set%d",
		Anonymous: true,
		Constant:  true,
		Interval:  interval,
		KeyType:   nftables.TypeInetService,
	}
	enc.anonSets = append(enc.anonSets, nftAnonSet{set: set, elements: f.portElements(specs, interval)})
	enc.exprs = append(enc.exprs, &expr.Lookup{SourceRegister: 1, SetName: set.Name, SetID: set.ID})
}

// encodeTCPUDP appends the both-transports protocol match: an anonymous set of
// the two protocol numbers, which keeps a TCPUDP rule a single nftables row.
func (f *NFT) encodeTCPUDP(enc *nftEncoded) {
	set := &nftables.Set{
		Table:     f.tableRef(),
		ID:        f.nextSetID(),
		Name:      "__set%d",
		Anonymous: true,
		Constant:  true,
		KeyType:   nftables.TypeInetProto,
	}
	enc.anonSets = append(enc.anonSets, nftAnonSet{set: set, elements: []nftables.SetElement{
		{Key: []byte{unix.IPPROTO_TCP}},
		{Key: []byte{unix.IPPROTO_UDP}},
	}})
	enc.exprs = append(enc.exprs,
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Lookup{SourceRegister: 1, SetName: set.Name, SetID: set.ID},
	)
}

// validateRule reports whether the rule is valid for nftables, applying the
// universal Rule.validate and then this encoder's shape constraints. The
// encoding entry points run it before marshalling; MarshalRule itself is a pure
// encoder. Unlike the other backends it does not reject TCPUDP: nft carries both
// transports in one row.
func (f *NFT) validateRule(r *Rule) error {
	if err := r.validate(); err != nil {
		return err
	}
	// A comment rides in the rule's user data and a log prefix in the log
	// expression; both are length-capped by nftables and the kernel.
	if len(r.Comment) > nftCommentMax {
		return fmt.Errorf("an nftables comment may not exceed %d bytes", nftCommentMax)
	}
	if len(r.LogPrefix) > nftLogPrefixMax {
		return fmt.Errorf("an nftables log prefix may not exceed %d bytes", nftLogPrefixMax)
	}
	// A per-source connection limit counts in a family-typed meter (its key is
	// the source address field), so a FamilyAny rule must be expanded to concrete
	// families by the caller before reaching the marshaller.
	if r.ConnLimit != nil && r.ConnLimit.PerSource && r.impliedFamily() == FamilyAny {
		return fmt.Errorf("a per-source connection limit counts in a family-typed meter; the caller must expand the rule to concrete families first")
	}
	// A connection-state match must name states nftables knows.
	if r.State != 0 && f.ctStateMask(r.State) == 0 {
		return fmt.Errorf("no valid connection state was provided")
	}
	// The rule must carry a valid verdict.
	switch r.Action {
	case Accept, Drop, Reject:
	default:
		return fmt.Errorf("no valid action was provided")
	}
	return nil
}

// MarshalRule encodes a filter rule as the nftables expression list the kernel
// stores, plus the anonymous sets and meter set it references. It is a pure
// encoder: callers run validateRule first.
func (f *NFT) MarshalRule(r *Rule) (*nftEncoded, error) {
	enc := &nftEncoded{chain: f.chainForDirection(r.Direction)}
	fam := r.impliedFamily()

	// Interface match.
	if r.InInterface != "" {
		enc.exprs = append(enc.exprs,
			&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: f.ifnameBytes(r.InInterface)},
		)
	}
	if r.OutInterface != "" {
		enc.exprs = append(enc.exprs,
			&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: f.ifnameBytes(r.OutInterface)},
		)
	}

	// Family pin. In an inet table a network-header offset means different fields
	// in the two families, so every rule that resolves to a concrete family states
	// it — not only the address-less ones. Without the guard an IPv4 source-address
	// load also matches inside an IPv6 source address.
	if fam != FamilyAny {
		enc.exprs = append(enc.exprs,
			&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{f.nfprotoByte(fam)}},
		)
	}

	// Address matches, honoring negation and named-set references.
	var err error
	if r.Source != "" {
		if enc.exprs, err = f.encodeAddr(enc.exprs, fam, r.Source, true); err != nil {
			return nil, err
		}
	}
	if r.Destination != "" {
		if enc.exprs, err = f.encodeAddr(enc.exprs, fam, r.Destination, false); err != nil {
			return nil, err
		}
	}

	// Protocol and port matches. A TCPUDP rule pins both transports with an
	// anonymous set and matches its ports through the shared transport-header
	// offsets, which is valid precisely because l4proto is constrained to
	// port-carrying protocols; that keeps the rule a single row needing no
	// fan-out. Every other protocol names itself before its ports.
	srcSpecs := r.SourcePortSpecs()
	hasPorts := r.HasPorts() || len(srcSpecs) > 0
	switch {
	case r.Proto == TCPUDP:
		f.encodeTCPUDP(enc)
	case r.Proto != ProtocolAny:
		pb, ok := f.ipProtoByte(r.Proto)
		if !ok {
			return nil, fmt.Errorf("unsupported protocol %s", r.Proto)
		}
		enc.exprs = append(enc.exprs,
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{pb}},
		)
	case hasPorts:
		// A port match loads the transport header, so it needs a protocol to load
		// it from. Rule.validate rejects this at the entry points; the encoder
		// repeats it because the internal split paths marshal directly.
		return nil, fmt.Errorf("a port match requires a protocol")
	}
	if r.HasPorts() {
		f.encodePorts(enc, r.PortSpecs(), false)
	}
	if len(srcSpecs) > 0 {
		f.encodePorts(enc, srcSpecs, true)
	}
	if r.Proto.IsICMP() && r.ICMPType != nil {
		// The message type is the first byte of the ICMP header.
		enc.exprs = append(enc.exprs,
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseTransportHeader,
				Offset:       0,
				Len:          1,
			},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{*r.ICMPType}},
		)
	}

	// Connection-tracking state: the state register is masked to the requested
	// states and matches when any of them is set.
	if r.State != 0 {
		enc.exprs = append(enc.exprs,
			&expr.Ct{Key: expr.CtKeySTATE, Register: 1},
			&expr.Bitwise{
				SourceRegister: 1,
				DestRegister:   1,
				Len:            4,
				Mask:           binaryutil.NativeEndian.PutUint32(f.ctStateMask(r.State)),
				Xor:            []byte{0, 0, 0, 0},
			},
			&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: []byte{0, 0, 0, 0}},
		)
	}

	// Rate limit: the statement matches only while under the rate, so over-rate
	// packets fall through to later rules rather than taking this rule's verdict.
	if r.RateLimit != nil {
		burst := uint32(r.RateLimit.Burst)
		if burst == 0 {
			burst = netfilterDefaultBurst
		}
		enc.exprs = append(enc.exprs, &expr.Limit{
			Type:  expr.LimitTypePkts,
			Rate:  uint64(r.RateLimit.Rate),
			Unit:  expr.LimitTime(rateUnitSeconds(r.RateLimit.Unit)),
			Burst: burst,
		})
	}

	// Connection limit. Per-source counting keys the count on the source address
	// in a named dynamic set — the set is family-typed, so a FamilyAny rule was
	// fanned out into one row per family before reaching here.
	if r.ConnLimit != nil {
		if r.ConnLimit.PerSource {
			name := f.meterName(enc.chain, r)
			keyType := nftables.TypeIPAddr
			if fam == IPv6 {
				keyType = nftables.TypeIP6Addr
			}
			enc.meterSet = &nftables.Set{
				Table:   f.tableRef(),
				Name:    name,
				KeyType: keyType,
				Dynamic: true,
				Size:    nftMeterSetSize,
			}
			offset, length := addrField(fam, true)
			enc.exprs = append(enc.exprs,
				&expr.Payload{
					DestRegister: 1,
					Base:         expr.PayloadBaseNetworkHeader,
					Offset:       offset,
					Len:          length,
				},
				&expr.Dynset{
					SrcRegKey: 1,
					SetName:   name,
					Operation: uint32(unix.NFT_DYNSET_OP_ADD),
					Exprs: []expr.Any{
						&expr.Connlimit{Count: uint32(r.ConnLimit.Count), Flags: expr.NFT_CONNLIMIT_F_INV},
					},
				},
			)
		} else {
			enc.exprs = append(enc.exprs, &expr.Connlimit{
				Count: uint32(r.ConnLimit.Count),
				Flags: expr.NFT_CONNLIMIT_F_INV,
			})
		}
	}

	// Logging, emitted just before the verdict so the packet is logged and then
	// the action is applied.
	if r.Log {
		lg := &expr.Log{Level: expr.LogLevelWarning}
		if r.LogPrefix != "" {
			lg.Key = 1 << unix.NFTA_LOG_PREFIX
			lg.Data = []byte(r.LogPrefix)
		}
		enc.exprs = append(enc.exprs, lg)
	}

	// A counter so GetRules can report per-rule packet/byte statistics. The
	// counter has no effect on matching and is ignored when comparing rules.
	enc.exprs = append(enc.exprs, &expr.Counter{})

	// Verdict. validateRule has already rejected an invalid action.
	switch r.Action {
	case Accept:
		enc.exprs = append(enc.exprs, &expr.Verdict{Kind: expr.VerdictAccept})
	case Drop:
		enc.exprs = append(enc.exprs, &expr.Verdict{Kind: expr.VerdictDrop})
	case Reject:
		// The inet table's reject default: an ICMPX port-unreachable, which the
		// kernel renders per family.
		enc.exprs = append(enc.exprs, &expr.Reject{
			Type: unix.NFT_REJECT_ICMPX_UNREACH,
			Code: unix.NFT_REJECT_ICMPX_PORT_UNREACH,
		})
	}

	// An optional user comment, stored as nftables user data. Unlike the textual
	// interface this has no quoting, so any comment within the length cap round
	// trips verbatim.
	if r.Comment != "" {
		enc.userData = userdata.AppendString(nil, userdata.TypeComment, r.Comment)
	}

	return enc, nil
}

// validateNAT reports whether the NAT rule is valid for nftables, applying the
// universal NATRule.validate and then this encoder's constraints. The encoding
// entry points run it before marshalling; MarshalNATRule is a pure encoder.
func (f *NFT) validateNAT(r *NATRule) error {
	if err := r.validate(); err != nil {
		return err
	}
	// nft's snat expression maps only to an address; a source-port translation has
	// no representation here (iptables emits it as --to-source addr:port).
	if r.Kind == SNAT && r.ToPort != 0 {
		return fmt.Errorf("nftables snat does not translate the source port: %w", ErrUnsupportedNAT)
	}
	return nil
}

// MarshalNATRule encodes a NAT rule as an expression list, returning it in the
// chain it belongs in (prerouting for destination NAT, postrouting for source
// NAT). It is a pure encoder: callers run validateNAT first.
func (f *NFT) MarshalNATRule(r *NATRule) (*nftEncoded, error) {
	enc := &nftEncoded{chain: "prerouting"}
	if r.Kind.isSource() {
		enc.chain = "postrouting"
	}
	fam := r.impliedFamily()

	// Interface, bound to the NAT direction: outbound for source NAT, inbound
	// for destination NAT.
	if r.Interface != "" {
		key := expr.MetaKeyIIFNAME
		if r.Kind.isSource() {
			key = expr.MetaKeyOIFNAME
		}
		enc.exprs = append(enc.exprs,
			&expr.Meta{Key: key, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: f.ifnameBytes(r.Interface)},
		)
	}

	// Family pin, for the same reason as a filter rule.
	if fam != FamilyAny {
		enc.exprs = append(enc.exprs,
			&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{f.nfprotoByte(fam)}},
		)
	}

	var err error
	if r.Source != "" {
		if enc.exprs, err = f.encodeAddr(enc.exprs, fam, r.Source, true); err != nil {
			return nil, err
		}
	}
	if r.Destination != "" {
		if enc.exprs, err = f.encodeAddr(enc.exprs, fam, r.Destination, false); err != nil {
			return nil, err
		}
	}

	if r.Proto != ProtocolAny {
		pb, ok := f.ipProtoByte(r.Proto)
		if !ok {
			return nil, fmt.Errorf("unsupported protocol %s", r.Proto)
		}
		enc.exprs = append(enc.exprs,
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{pb}},
		)
	}
	if r.HasPorts() {
		f.encodePorts(enc, r.PortSpecs(), false)
	}

	// The translation. An address goes into register 1 and a port into register
	// 2, which the nat expression then names; redirect takes only a port and
	// reads it from register 1.
	switch r.Kind {
	case DNAT, SNAT:
		natType := expr.NATTypeDestNAT
		if r.Kind == SNAT {
			natType = expr.NATTypeSourceNAT
		}
		n := &expr.NAT{Type: natType, Family: uint32(f.nfprotoByte(fam))}
		if r.ToAddress != "" {
			val, mask, aerr := f.addrBytes(fam, r.ToAddress)
			if aerr != nil {
				return nil, aerr
			}
			if mask != nil {
				return nil, fmt.Errorf("a nat translation target must be a single address, not a prefix")
			}
			enc.exprs = append(enc.exprs, &expr.Immediate{Register: 1, Data: val})
			n.RegAddrMin, n.RegAddrMax = 1, 1
		}
		if r.ToPort != 0 {
			enc.exprs = append(enc.exprs, &expr.Immediate{
				Register: 2, Data: binaryutil.BigEndian.PutUint16(r.ToPort),
			})
			n.RegProtoMin, n.RegProtoMax = 2, 2
		}
		enc.exprs = append(enc.exprs, n)
	case Redirect:
		rd := &expr.Redir{}
		if r.ToPort != 0 {
			enc.exprs = append(enc.exprs, &expr.Immediate{
				Register: 1, Data: binaryutil.BigEndian.PutUint16(r.ToPort),
			})
			rd.RegisterProtoMin, rd.RegisterProtoMax = 1, 1
			rd.Flags = unix.NF_NAT_RANGE_PROTO_SPECIFIED
		}
		enc.exprs = append(enc.exprs, rd)
	case Masquerade:
		enc.exprs = append(enc.exprs, &expr.Masq{})
	}

	return enc, nil
}

// meterName derives the dynamic-set name a per-source connection-limit rule
// counts in. The name is a hash of the rule's identity (chain, family, match,
// limit and verdict) so two distinct per-source rules never share counting
// state, while a re-add — or a split's re-add — of the same rule deterministically
// reuses its set. The comment is excluded, as it is not part of rule identity.
func (f *NFT) meterName(chain string, r *Rule) string {
	h := fnv.New64a()
	_, _ = fmt.Fprintf(h, "%s|%d|%d|%s|%s|%d|%s|%s|%v|%d|%d|%d",
		chain, r.impliedFamily(), r.Proto, r.Source, r.Destination,
		r.State, FormatPortRanges(r.PortSpecs(), ","), FormatPortRanges(r.SourcePortSpecs(), ","),
		r.Log, r.Action, r.ConnLimit.Count, r.Priority)
	return fmt.Sprintf("cl%016x", h.Sum64())
}

// perSourceFamilySplit reports whether a rule must be fanned out into one row
// per family before marshalling: a per-source connection limit counts in a
// family-typed dynamic set, so a FamilyAny rule has no single nftables row —
// the family analog of the DirAny fan-out.
func (f *NFT) perSourceFamilySplit(r *Rule) bool {
	return r.perSourceLimited() && r.impliedFamily() == FamilyAny
}

// -----------------------------------------------------------------------------
// Expression decoding
// -----------------------------------------------------------------------------

// nftSetContents is a set's definition together with its elements, which a
// lookup expression must be resolved against to recover the values it matches.
type nftSetContents struct {
	set      *nftables.Set
	elements []nftables.SetElement
}

// nftSetReader resolves the sets a rule's lookups reference, caching each read
// so decoding a chain full of set-referencing rules costs one dump per set.
type nftSetReader struct {
	conn  *nftables.Conn
	cache map[string]*nftSetContents
	// staged holds sets that exist only in an in-flight batch, keyed by the
	// transaction-local identifier a lookup names them by. Every anonymous set
	// shares the same placeholder name until the kernel resolves it, so an
	// encoding can only be decoded back through its identifiers.
	staged map[uint32]*nftSetContents
}

// newSetReader returns a set resolver bound to a netlink connection.
func newSetReader(c *nftables.Conn) *nftSetReader {
	return &nftSetReader{conn: c, cache: make(map[string]*nftSetContents)}
}

// newStagedSetReader returns a resolver over the anonymous sets encoded rules
// carry, so an encoding can be decoded back without ever reaching the kernel.
func newStagedSetReader(encs ...*nftEncoded) *nftSetReader {
	s := &nftSetReader{staged: make(map[uint32]*nftSetContents)}
	for _, enc := range encs {
		for _, as := range enc.anonSets {
			s.staged[as.set.ID] = &nftSetContents{set: as.set, elements: as.elements}
		}
	}
	return s
}

// resolve reads the set a lookup names. A set staged in the current batch is
// named by its transaction-local identifier; one already in the ruleset is named
// by the name the kernel assigned it.
func (s *nftSetReader) resolve(tbl *nftables.Table, lk *expr.Lookup) (*nftSetContents, error) {
	if lk.SetID != 0 {
		if sc, ok := s.staged[lk.SetID]; ok {
			return sc, nil
		}
	}
	if s.conn == nil {
		return nil, fmt.Errorf("set %q is not available", lk.SetName)
	}
	key := fmt.Sprintf("%d|%s|%s", tbl.Family, tbl.Name, lk.SetName)
	if c, ok := s.cache[key]; ok {
		return c, nil
	}
	set, err := s.conn.GetSetByName(tbl, lk.SetName)
	if err != nil {
		return nil, err
	}
	elems, err := s.conn.GetSetElements(set)
	if err != nil {
		return nil, err
	}
	c := &nftSetContents{set: set, elements: elems}
	s.cache[key] = c
	return c, nil
}

// portRangesFromSet reconstructs the port ranges a set holds. A plain set lists
// discrete ports; an interval set lists boundary markers, each span being an
// inclusive start followed by an end marker at the exclusive upper bound.
func (f *NFT) portRangesFromSet(sc *nftSetContents) ([]PortRange, error) {
	type elem struct {
		port uint16
		end  bool
	}
	var elems []elem
	for _, e := range sc.elements {
		if len(e.Key) != 2 {
			return nil, fmt.Errorf("unsupported port set element width %d", len(e.Key))
		}
		elems = append(elems, elem{port: binaryutil.BigEndian.Uint16(e.Key), end: e.IntervalEnd})
	}
	sort.Slice(elems, func(i, j int) bool {
		if elems[i].port == elems[j].port {
			return !elems[i].end && elems[j].end
		}
		return elems[i].port < elems[j].port
	})

	var specs []PortRange
	if !sc.set.Interval {
		for _, e := range elems {
			specs = append(specs, PortRange{Start: e.port, End: e.port})
		}
		return specs, nil
	}
	open := false
	var start uint16
	for _, e := range elems {
		if !e.end {
			start, open = e.port, true
			continue
		}
		if !open {
			// A leading end marker closes the span below the first element, which
			// carries no range of its own.
			continue
		}
		if e.port == 0 {
			return nil, fmt.Errorf("invalid interval end 0 in port set")
		}
		specs = append(specs, PortRange{Start: start, End: e.port - 1})
		open = false
	}
	if open {
		// An unterminated span runs to the top of the port space.
		specs = append(specs, PortRange{Start: start, End: 65535})
	}
	return specs, nil
}

// protocolFromSet decodes an l4proto lookup. The only set this backend writes,
// and the only one a single Proto field can hold, is the both-transports pair;
// anything else belongs to a foreign rule whose coverage the model cannot carry,
// so it is rejected rather than narrowed to one member.
func (f *NFT) protocolFromSet(sc *nftSetContents) (Protocol, error) {
	if len(sc.elements) != 2 {
		return ProtocolAny, fmt.Errorf("unsupported l4proto set of %d members", len(sc.elements))
	}
	var got [2]Protocol
	for i, e := range sc.elements {
		if len(e.Key) != 1 {
			return ProtocolAny, fmt.Errorf("unsupported l4proto set element width %d", len(e.Key))
		}
		got[i] = f.protocolForByte(e.Key[0])
	}
	if (got[0] == TCP && got[1] == UDP) || (got[0] == UDP && got[1] == TCP) {
		return TCPUDP, nil
	}
	return ProtocolAny, fmt.Errorf("unsupported l4proto set")
}

// maskPrefixLen returns the prefix length a contiguous network mask represents,
// reporting false for a non-contiguous mask the address model cannot render.
func (f *NFT) maskPrefixLen(mask []byte) (int, bool) {
	ones, bits := net.IPMask(mask).Size()
	if bits == 0 {
		return 0, false
	}
	return ones, true
}

// addrFromPayload reconstructs the address or CIDR a network-header match names.
// It accepts both shapes nftables stores: a full-width load with an optional
// mask, and the shortened load nft emits for a byte-aligned prefix.
func (f *NFT) addrFromPayload(fam Family, p *expr.Payload, mask, data []byte) (string, error) {
	width := 4
	if fam == IPv6 {
		width = 16
	}
	if int(p.Len) > width || len(data) != int(p.Len) {
		return "", fmt.Errorf("unsupported address match width %d", p.Len)
	}

	full := make([]byte, width)
	copy(full, data)
	ip := net.IP(full)

	switch {
	case int(p.Len) < width:
		// A shortened load compares only the leading bytes: a byte-aligned prefix.
		return (&net.IPNet{IP: ip, Mask: net.CIDRMask(int(p.Len)*8, width*8)}).String(), nil
	case mask != nil:
		ones, ok := f.maskPrefixLen(mask)
		if !ok {
			return "", fmt.Errorf("unsupported non-contiguous address mask")
		}
		if ones == width*8 {
			return ip.String(), nil
		}
		return (&net.IPNet{IP: ip, Mask: net.CIDRMask(ones, width*8)}).String(), nil
	default:
		return ip.String(), nil
	}
}

// nftDecoder walks a rule's expression list, pairing each value-producing
// expression (a meta, payload or ct load) with the test that follows it.
type nftDecoder struct {
	f    *NFT
	sets *nftSetReader
	tbl  *nftables.Table
	fam  Family
	// load is the most recent value-producing expression, awaiting its test.
	load expr.Any
	// mask is a pending bitwise mask applied to the loaded value.
	mask []byte
	// portLow is the lower bound of a port range the nft CLI spelled as a
	// `cmp gte` awaiting its closing `cmp lte`; nil when none is open.
	portLow *portBound
}

// portBound is the open lower bound of a port range: its value and whether the
// load it compared was the source port.
type portBound struct {
	port   uint16
	source bool
}

// setPort stores a decoded port match, keeping the single-port form for a lone
// discrete port so it round-trips against rules built that way.
func (f *NFT) setPort(r *Rule, specs []PortRange, source bool) {
	single := len(specs) == 1 && specs[0].Start == specs[0].End
	if source {
		if single {
			r.SourcePort = specs[0].Start
		} else {
			r.SourcePorts = specs
		}
		return
	}
	if single {
		r.Port = specs[0].Start
	} else {
		r.Ports = specs
	}
}

// applyCmp folds a comparison into the rule, interpreting it against the value
// the preceding load produced.
func (d *nftDecoder) applyCmp(r *Rule, c *expr.Cmp) error {
	if c.Op != expr.CmpOpEq && c.Op != expr.CmpOpNeq {
		return d.applyPortBound(r, c)
	}
	neg := c.Op == expr.CmpOpNeq
	switch l := d.load.(type) {
	case *expr.Meta:
		switch l.Key {
		case expr.MetaKeyNFPROTO:
			if len(c.Data) != 1 {
				return fmt.Errorf("unsupported nfproto match")
			}
			fam, ok := d.f.familyForNFProto(c.Data[0])
			if !ok {
				return fmt.Errorf("unsupported nfproto %d", c.Data[0])
			}
			r.Family, d.fam = fam, fam
		case expr.MetaKeyL4PROTO:
			if len(c.Data) != 1 {
				return fmt.Errorf("unsupported l4proto match")
			}
			p := d.f.protocolForByte(c.Data[0])
			if p == ProtocolAny {
				return fmt.Errorf("unsupported l4proto %d", c.Data[0])
			}
			r.Proto = p
		case expr.MetaKeyIIFNAME:
			r.InInterface = d.f.ifnameString(c.Data)
		case expr.MetaKeyOIFNAME:
			r.OutInterface = d.f.ifnameString(c.Data)
		default:
			return fmt.Errorf("unsupported meta key %d", l.Key)
		}
	case *expr.Payload:
		switch l.Base {
		case expr.PayloadBaseNetworkHeader:
			if d.fam == FamilyAny {
				// Without a family guard a network-header offset is ambiguous
				// between the two families in an inet table.
				return fmt.Errorf("address match without a family qualifier")
			}
			soff, _ := addrField(d.fam, true)
			doff, _ := addrField(d.fam, false)
			addr, aerr := d.f.addrFromPayload(d.fam, l, d.mask, c.Data)
			if aerr != nil {
				return aerr
			}
			if neg {
				addr = "!" + addr
			}
			switch l.Offset {
			case soff:
				r.Source = addr
			case doff:
				r.Destination = addr
			default:
				return fmt.Errorf("unsupported network header offset %d", l.Offset)
			}
		case expr.PayloadBaseTransportHeader:
			// The model has no negated port, so `dport != 22` must not read as port 22.
			if neg {
				return fmt.Errorf("unsupported negated transport header match")
			}
			switch {
			case l.Offset == 2 && l.Len == 2:
				d.f.setPort(r, []PortRange{{Start: binaryutil.BigEndian.Uint16(c.Data), End: binaryutil.BigEndian.Uint16(c.Data)}}, false)
			case l.Offset == 0 && l.Len == 2:
				d.f.setPort(r, []PortRange{{Start: binaryutil.BigEndian.Uint16(c.Data), End: binaryutil.BigEndian.Uint16(c.Data)}}, true)
			case l.Offset == 0 && l.Len == 1:
				// The ICMP message type.
				if !r.Proto.IsICMP() {
					return fmt.Errorf("an icmp type match requires an icmp protocol")
				}
				r.ICMPType = Ptr(c.Data[0])
			default:
				return fmt.Errorf("unsupported transport header offset %d width %d", l.Offset, l.Len)
			}
		default:
			return fmt.Errorf("unsupported payload base %d", l.Base)
		}
	case *expr.Ct:
		if l.Key != expr.CtKeySTATE {
			return fmt.Errorf("unsupported ct key %d", l.Key)
		}
		if d.mask == nil || len(d.mask) != 4 || c.Op != expr.CmpOpNeq {
			return fmt.Errorf("unsupported ct state match")
		}
		state, ok := d.f.connStateForMask(binaryutil.NativeEndian.Uint32(d.mask))
		if !ok {
			return fmt.Errorf("unsupported ct state mask")
		}
		r.State = state
	default:
		return fmt.Errorf("comparison without a value to compare")
	}
	return nil
}

// applyLookup folds a set lookup into the rule.
func (d *nftDecoder) applyLookup(r *Rule, lk *expr.Lookup) error {
	switch l := d.load.(type) {
	case *expr.Meta:
		if l.Key != expr.MetaKeyL4PROTO {
			return fmt.Errorf("unsupported meta set lookup")
		}
		sc, err := d.sets.resolve(d.tbl, lk)
		if err != nil {
			return err
		}
		p, err := d.f.protocolFromSet(sc)
		if err != nil {
			return err
		}
		r.Proto = p
	case *expr.Payload:
		switch l.Base {
		case expr.PayloadBaseNetworkHeader:
			if d.fam == FamilyAny {
				return fmt.Errorf("address set lookup without a family qualifier")
			}
			soff, _ := addrField(d.fam, true)
			doff, _ := addrField(d.fam, false)
			name := lk.SetName
			if lk.Invert {
				name = "!" + name
			}
			switch l.Offset {
			case soff:
				r.Source = name
			case doff:
				r.Destination = name
			default:
				return fmt.Errorf("unsupported network header offset %d", l.Offset)
			}
		case expr.PayloadBaseTransportHeader:
			if l.Len != 2 || (l.Offset != 0 && l.Offset != 2) {
				return fmt.Errorf("unsupported port set lookup")
			}
			sc, err := d.sets.resolve(d.tbl, lk)
			if err != nil {
				return err
			}
			specs, err := d.f.portRangesFromSet(sc)
			if err != nil {
				return err
			}
			if len(specs) == 0 {
				return fmt.Errorf("empty port set")
			}
			d.f.setPort(r, specs, l.Offset == 0)
		default:
			return fmt.Errorf("unsupported payload base %d", l.Base)
		}
	default:
		return fmt.Errorf("set lookup without a value to look up")
	}
	return nil
}

// applyRange folds a range test into the rule; nftables uses one for a single
// port span.
func (d *nftDecoder) applyRange(r *Rule, rg *expr.Range) error {
	l, ok := d.load.(*expr.Payload)
	if !ok || l.Base != expr.PayloadBaseTransportHeader || l.Len != 2 {
		return fmt.Errorf("unsupported range match")
	}
	if l.Offset != 0 && l.Offset != 2 {
		return fmt.Errorf("unsupported range offset %d", l.Offset)
	}
	if rg.Op != expr.CmpOpEq || len(rg.FromData) != 2 || len(rg.ToData) != 2 {
		return fmt.Errorf("unsupported range match")
	}
	d.f.setPort(r, []PortRange{{
		Start: binaryutil.BigEndian.Uint16(rg.FromData),
		End:   binaryutil.BigEndian.Uint16(rg.ToData),
	}}, l.Offset == 0)
	return nil
}

// applyPortBound folds an ordering comparison into the rule. The nft CLI writes a
// port range on a plain chain row as `cmp gte` then `cmp lte` on one transport
// port load rather than as a range expression, so the pair is joined into a
// single PortRange. Any other ordering comparison has no form in the model.
func (d *nftDecoder) applyPortBound(r *Rule, c *expr.Cmp) error {
	l, ok := d.load.(*expr.Payload)
	if !ok || l.Base != expr.PayloadBaseTransportHeader || l.Len != 2 || (l.Offset != 0 && l.Offset != 2) ||
		d.mask != nil || len(c.Data) != 2 {
		return fmt.Errorf("unsupported comparison op %d", c.Op)
	}
	port := binaryutil.BigEndian.Uint16(c.Data)
	source := l.Offset == 0
	switch c.Op {
	case expr.CmpOpGte:
		if d.portLow != nil {
			return fmt.Errorf("unsupported port comparison")
		}
		d.portLow = &portBound{port: port, source: source}
	case expr.CmpOpLte:
		if d.portLow == nil || d.portLow.source != source || d.portLow.port > port {
			return fmt.Errorf("unsupported open-ended port comparison")
		}
		d.f.setPort(r, []PortRange{{Start: d.portLow.port, End: port}}, source)
		d.portLow = nil
	default:
		return fmt.Errorf("unsupported comparison op %d", c.Op)
	}
	return nil
}

// finish rejects a row whose decoding left a port range open: a lone `cmp gte`
// (such as `dport >= 1024`) has no form in the model, and dropping it would read
// the row as matching every port.
func (d *nftDecoder) finish() error {
	if d.portLow != nil {
		return fmt.Errorf("unsupported open-ended port comparison")
	}
	return nil
}

// applyDynset folds a per-source connection limit into the rule. The dynamic set
// is keyed on the source address loaded just before it, which is what pins the
// rule's family.
func (d *nftDecoder) applyDynset(r *Rule, ds *expr.Dynset) error {
	var cl *expr.Connlimit
	for _, inner := range ds.Exprs {
		if c, ok := inner.(*expr.Connlimit); ok {
			cl = c
		}
	}
	if cl == nil {
		return fmt.Errorf("unsupported dynamic set statement")
	}
	if cl.Flags&expr.NFT_CONNLIMIT_F_INV == 0 {
		return fmt.Errorf("unsupported under-limit connection count")
	}
	l, ok := d.load.(*expr.Payload)
	if !ok || l.Base != expr.PayloadBaseNetworkHeader {
		return fmt.Errorf("unsupported connection-limit key")
	}
	if d.fam == FamilyAny {
		return fmt.Errorf("connection-limit key without a family qualifier")
	}
	soff, slen := addrField(d.fam, true)
	if l.Offset != soff || l.Len != slen {
		return fmt.Errorf("unsupported connection-limit key offset %d", l.Offset)
	}
	r.ConnLimit = &ConnLimit{Count: uint(cl.Count), PerSource: true}
	r.meterSet = ds.SetName
	return nil
}

// UnmarshalRule decodes a chain row's expression list into a filter rule. It
// returns an error for any row carrying a construct the model cannot hold, so
// the caller can keep the row as an opaque slot rather than misrepresenting it.
func (f *NFT) UnmarshalRule(nr *nftables.Rule, chain string, sets *nftSetReader, tbl *nftables.Table) (*Rule, error) {
	r := &Rule{Direction: f.directionForChain(chain)}
	d := &nftDecoder{f: f, sets: sets, tbl: tbl}
	// A row in a single-family table states no nfproto of its own: the table is
	// the qualifier, so seed the family from it. Without this an operator's
	// `table ip filter` rule matching an address (or an address set) has no family
	// to read its network-header offsets against and the whole row goes opaque.
	if fam, ok := f.familyForTable(tbl); ok {
		r.Family, d.fam = fam, fam
	}

	for _, e := range nr.Exprs {
		switch v := e.(type) {
		case *expr.Meta, *expr.Payload, *expr.Ct:
			d.load, d.mask = v, nil
		case *expr.Bitwise:
			d.mask = v.Mask
		case *expr.Cmp:
			if err := d.applyCmp(r, v); err != nil {
				return nil, err
			}
		case *expr.Lookup:
			if err := d.applyLookup(r, v); err != nil {
				return nil, err
			}
		case *expr.Range:
			if err := d.applyRange(r, v); err != nil {
				return nil, err
			}
		case *expr.Dynset:
			if err := d.applyDynset(r, v); err != nil {
				return nil, err
			}
		case *expr.Connlimit:
			if v.Flags&expr.NFT_CONNLIMIT_F_INV == 0 {
				return nil, fmt.Errorf("unsupported under-limit connection count")
			}
			r.ConnLimit = &ConnLimit{Count: uint(v.Count)}
		case *expr.Limit:
			if v.Type != expr.LimitTypePkts || v.Over {
				return nil, fmt.Errorf("unsupported limit statement")
			}
			unit, ok := f.rateUnitForSeconds(uint64(v.Unit))
			if !ok {
				return nil, fmt.Errorf("unsupported rate unit %d", v.Unit)
			}
			// nftables applies a default burst of 5 packets to every limit and
			// reports it back even when none was requested, so the default reads
			// as unset.
			r.RateLimit = &RateLimit{Rate: uint(v.Rate), Unit: unit, Burst: normBurst(uint(v.Burst))}
		case *expr.Log:
			r.Log = true
			if len(v.Data) > 0 {
				r.LogPrefix = string(v.Data)
			}
		case *expr.Counter:
			r.Packets, r.Bytes = v.Packets, v.Bytes
		case *expr.Verdict:
			switch v.Kind {
			case expr.VerdictAccept:
				r.Action = Accept
			case expr.VerdictDrop:
				r.Action = Drop
			default:
				return nil, fmt.Errorf("unsupported verdict %d", v.Kind)
			}
		case *expr.Reject:
			r.Action = Reject
		default:
			return nil, fmt.Errorf("unsupported expression %T", e)
		}
	}

	if err := d.finish(); err != nil {
		return nil, err
	}
	if r.Action == ActionInvalid {
		return nil, fmt.Errorf("no valid action was provided")
	}
	// The comment rides in the rule's user data rather than its expressions.
	if comment, ok := userdata.GetString(nr.UserData, userdata.TypeComment); ok {
		r.Comment = comment
	}
	return r, nil
}

// UnmarshalNATRule decodes a nat chain row's expression list into a NAT rule.
func (f *NFT) UnmarshalNATRule(nr *nftables.Rule, sets *nftSetReader, tbl *nftables.Table) (*NATRule, error) {
	r := &NATRule{}
	// The NAT matches reuse the filter decoder, which works against a Rule; the
	// shared fields are copied across once the walk is done.
	match := &Rule{}
	d := &nftDecoder{f: f, sets: sets, tbl: tbl}
	immediates := map[uint32][]byte{}
	// The table settles the family for a single-family table's rows, as in
	// UnmarshalRule; a nat expression naming its own family overrides it below.
	if fam, ok := f.familyForTable(tbl); ok {
		match.Family, d.fam = fam, fam
	}

	for _, e := range nr.Exprs {
		switch v := e.(type) {
		case *expr.Meta, *expr.Payload, *expr.Ct:
			d.load, d.mask = v, nil
		case *expr.Bitwise:
			d.mask = v.Mask
		case *expr.Cmp:
			if err := d.applyCmp(match, v); err != nil {
				return nil, err
			}
		case *expr.Lookup:
			if err := d.applyLookup(match, v); err != nil {
				return nil, err
			}
		case *expr.Range:
			if err := d.applyRange(match, v); err != nil {
				return nil, err
			}
		case *expr.Immediate:
			immediates[v.Register] = v.Data
		case *expr.Counter:
			// A foreign nat rule may carry a counter; it is not part of the model.
		case *expr.NAT:
			r.Kind = DNAT
			if v.Type == expr.NATTypeSourceNAT {
				r.Kind = SNAT
			}
			if fam, ok := f.familyForNFProto(byte(v.Family)); ok {
				r.Family = fam
			}
			if v.RegAddrMin != 0 {
				data, ok := immediates[v.RegAddrMin]
				if !ok {
					return nil, fmt.Errorf("nat address register %d was never loaded", v.RegAddrMin)
				}
				r.ToAddress = net.IP(data).String()
			}
			if v.RegProtoMin != 0 {
				data, ok := immediates[v.RegProtoMin]
				if !ok || len(data) != 2 {
					return nil, fmt.Errorf("nat port register %d was never loaded", v.RegProtoMin)
				}
				r.ToPort = binaryutil.BigEndian.Uint16(data)
			}
		case *expr.Redir:
			r.Kind = Redirect
			if v.RegisterProtoMin != 0 {
				data, ok := immediates[v.RegisterProtoMin]
				if !ok || len(data) != 2 {
					return nil, fmt.Errorf("redirect port register %d was never loaded", v.RegisterProtoMin)
				}
				r.ToPort = binaryutil.BigEndian.Uint16(data)
			}
		case *expr.Masq:
			r.Kind = Masquerade
		default:
			return nil, fmt.Errorf("unsupported expression %T", e)
		}
	}

	if err := d.finish(); err != nil {
		return nil, err
	}
	if r.Kind == NATInvalid {
		return nil, fmt.Errorf("no nat action was provided")
	}

	// Carry the decoded matches across. The interface is direction-bound, so
	// whichever side the match named is the rule's interface.
	if match.Family != FamilyAny {
		r.Family = match.Family
	}
	r.Source, r.Destination = match.Source, match.Destination
	r.Proto = match.Proto
	r.Port, r.Ports = match.Port, match.Ports
	if match.InInterface != "" {
		r.Interface = match.InInterface
	} else if match.OutInterface != "" {
		r.Interface = match.OutInterface
	}
	if r.Family == FamilyAny {
		r.Family = r.impliedFamily()
	}
	return r, nil
}

// -----------------------------------------------------------------------------
// Reading
// -----------------------------------------------------------------------------

// listChain returns the chain's rules with their nftables handles, 1:1 with its
// physical rows. A row the model cannot parse is kept as an opaque slot — a nil
// rule with its handle — so a rewrite deletes only rows the model understands
// and the position math stays aligned; GetRules and the dedup scans skip the
// nil entries.
func (f *NFT) listChain(c *nftables.Conn, sets *nftSetReader, chain string) (rules []*Rule, handles []uint64, err error) {
	tbl := f.tableRef()
	rows, err := c.GetRules(tbl, f.chainRef(chain))
	if err != nil {
		// A missing table or chain simply means there are no rules yet.
		if f.isNotExist(err) {
			return nil, nil, nil
		}
		return nil, nil, err
	}
	for _, nr := range rows {
		rule, perr := f.UnmarshalRule(nr, chain, sets, tbl)
		if perr != nil {
			rules = append(rules, nil)
			handles = append(handles, nr.Handle)
			continue
		}
		// Rules live in this backend's own table; membership in the library's
		// private table is what sets HasPrefix, so record the table and flag it
		// as carrying the prefix.
		rule.table = f.table
		rule.HasPrefix = true
		rules = append(rules, rule)
		handles = append(handles, nr.Handle)
	}
	return rules, handles, nil
}

// listNATChain is listChain for the nat base chains.
func (f *NFT) listNATChain(c *nftables.Conn, sets *nftSetReader, chain string) (rules []*NATRule, handles []uint64, err error) {
	tbl := f.tableRef()
	rows, err := c.GetRules(tbl, f.chainRef(chain))
	if err != nil {
		if f.isNotExist(err) {
			return nil, nil, nil
		}
		return nil, nil, err
	}
	for _, nr := range rows {
		rule, perr := f.UnmarshalNATRule(nr, sets, tbl)
		if perr != nil {
			rules = append(rules, nil)
			handles = append(handles, nr.Handle)
			continue
		}
		rule.table = f.table
		rule.HasPrefix = true
		rules = append(rules, rule)
		handles = append(handles, nr.Handle)
	}
	return rules, handles, nil
}

// foreignChains returns every chain in the ruleset that is not in this backend's
// own table, paired with the table it belongs to. Chains are dumped once per
// family rather than once per table.
func (f *NFT) foreignChains(c *nftables.Conn) ([]*nftables.Chain, error) {
	tables, err := c.ListTables()
	if err != nil {
		return nil, err
	}
	families := map[nftables.TableFamily]bool{}
	keep := map[string]bool{}
	for _, t := range tables {
		if t.Family == nftables.TableFamilyINet && t.Name == f.table {
			continue
		}
		// A container runtime's table is out of scope entirely: it is the
		// runtime's to reconcile, and this backend could not remove it anyway
		// (mutations are scoped to our own table), so reporting it would only make
		// Sync try, no-op, and over-count removed on every run.
		if isContainerRuntimeTable(f.familyName(t.Family) + " " + t.Name) {
			continue
		}
		families[t.Family] = true
		keep[fmt.Sprintf("%d|%s", t.Family, t.Name)] = true
	}

	var out []*nftables.Chain
	for fam := range families {
		chains, cerr := c.ListChainsOfTableFamily(fam)
		if cerr != nil {
			return nil, cerr
		}
		for _, ch := range chains {
			if !keep[fmt.Sprintf("%d|%s", ch.Table.Family, ch.Table.Name)] {
				continue
			}
			if isContainerRuntimeChain(ch.Name) {
				continue
			}
			out = append(out, ch)
		}
	}
	return out, nil
}

// listForeignRules walks the ruleset and returns best-effort parsed rules that
// live outside this backend's own inet table. Because arbitrary foreign tables
// use constructs the Rule model cannot represent, any row that fails to decode
// is skipped rather than erroring the whole read. This gives callers visibility
// of rules in other tables alongside the library's own.
func (f *NFT) listForeignRules(c *nftables.Conn, sets *nftSetReader) ([]*Rule, error) {
	chains, err := f.foreignChains(c)
	if err != nil {
		// No ruleset (or netlink unavailable for listing): nothing foreign to report.
		return nil, nil
	}
	var rules []*Rule
	for _, ch := range chains {
		rows, rerr := c.GetRules(ch.Table, ch)
		if rerr != nil {
			continue
		}
		for _, nr := range rows {
			rule, perr := f.UnmarshalRule(nr, ch.Name, sets, ch.Table)
			if perr != nil || rule == nil {
				continue
			}
			if rule.isContainerRuntime() {
				continue
			}
			// A rule from another table: record where it came from; it is not ours,
			// so HasPrefix stays false.
			rule.table = f.familyName(ch.Table.Family) + " " + ch.Table.Name
			rules = append(rules, rule)
		}
	}
	return rules, nil
}

// listForeignNATRules is listForeignRules for NAT rules.
func (f *NFT) listForeignNATRules(c *nftables.Conn, sets *nftSetReader) ([]*NATRule, error) {
	chains, err := f.foreignChains(c)
	if err != nil {
		return nil, nil
	}
	var rules []*NATRule
	for _, ch := range chains {
		rows, rerr := c.GetRules(ch.Table, ch)
		if rerr != nil {
			continue
		}
		for _, nr := range rows {
			rule, perr := f.UnmarshalNATRule(nr, sets, ch.Table)
			if perr != nil || rule == nil {
				continue
			}
			if rule.isHairpinMasquerade() {
				continue
			}
			rule.table = f.familyName(ch.Table.Family) + " " + ch.Table.Name
			rules = append(rules, rule)
		}
	}
	return rules, nil
}

// listOwnRules returns the library's own filter rules from its private table, one
// rule per physical chain row. A read does not create the table; listChain returns
// nothing when the table does not yet exist. nftables' inet table stores a
// family-agnostic rule as one unpinned row and a both-transports rule as one
// l4proto-set row, so UnmarshalRule reports FamilyAny and TCPUDP straight off the
// row that carries them; nothing is collapsed here. Number per direction (input
// then output chain) so each rule's Number matches the InsertRule/MoveRule
// position within its chain.
func (f *NFT) listOwnRules(c *nftables.Conn, sets *nftSetReader) ([]*Rule, error) {
	var rules []*Rule
	for _, chain := range nftFilterChains {
		chainRules, _, cerr := f.listChain(c, sets, chain)
		if cerr != nil {
			return nil, cerr
		}
		// Opaque (nil) rows stay in the chain but are not reportable rules.
		for _, r := range chainRules {
			if r != nil {
				rules = append(rules, r)
			}
		}
	}
	numberByDirection(rules)
	return rules, nil
}

// listOwnNATRules returns the library's own NAT rules from its private table, one
// rule per physical chain row.
func (f *NFT) listOwnNATRules(c *nftables.Conn, sets *nftSetReader) ([]*NATRule, error) {
	var rules []*NATRule
	for _, chain := range nftNATChains {
		chainRules, _, cerr := f.listNATChain(c, sets, chain)
		if cerr != nil {
			return nil, cerr
		}
		for _, r := range chainRules {
			if r != nil {
				rules = append(rules, r)
			}
		}
	}
	// The nat chains live in the same inet table, so a family-agnostic translation is
	// one unpinned row that reads back as FamilyAny; nothing is collapsed here. Number
	// per nat chain (prerouting then postrouting) so each rule's Number matches the
	// InsertNATRule/MoveNATRule position within its chain.
	numberNATByChain(rules)
	return rules, nil
}

// GetRules returns the existing filter rules from the zone.
func (f *NFT) GetRules(ctx context.Context, zoneName string) (rules []*Rule, err error) {
	c, err := nftConn()
	if err != nil {
		return nil, err
	}
	sets := newSetReader(c)

	// The library's own rules, then foreign rules from every other table.
	rules, err = f.listOwnRules(c, sets)
	if err != nil {
		return nil, err
	}
	foreign, ferr := f.listForeignRules(c, sets)
	if ferr != nil {
		return nil, ferr
	}
	rules = append(rules, foreign...)
	return rules, nil
}

// GetNATRules returns the existing NAT rules from the zone.
func (f *NFT) GetNATRules(ctx context.Context, zoneName string) (rules []*NATRule, err error) {
	c, err := nftConn()
	if err != nil {
		return nil, err
	}
	sets := newSetReader(c)

	rules, err = f.listOwnNATRules(c, sets)
	if err != nil {
		return nil, err
	}
	foreign, ferr := f.listForeignNATRules(c, sets)
	if ferr != nil {
		return nil, ferr
	}
	rules = append(rules, foreign...)
	return rules, nil
}

// -----------------------------------------------------------------------------
// Table and chain setup
// -----------------------------------------------------------------------------

// nftBaseChain describes one of the private table's base chains.
type nftBaseChain struct {
	name     string
	chType   nftables.ChainType
	hook     *nftables.ChainHook
	priority *nftables.ChainPriority
}

// nftFilterBaseChains defines the filter hooks the private table installs.
var nftFilterBaseChains = []nftBaseChain{
	{"input", nftables.ChainTypeFilter, nftables.ChainHookInput, nftables.ChainPriorityFilter},
	{"output", nftables.ChainTypeFilter, nftables.ChainHookOutput, nftables.ChainPriorityFilter},
	{"forward", nftables.ChainTypeFilter, nftables.ChainHookForward, nftables.ChainPriorityFilter},
}

// nftNATBaseChains defines the nat hooks, created lazily on first NAT write.
var nftNATBaseChains = []nftBaseChain{
	{"prerouting", nftables.ChainTypeNAT, nftables.ChainHookPrerouting, nftables.ChainPriorityNATDest},
	{"postrouting", nftables.ChainTypeNAT, nftables.ChainHookPostrouting, nftables.ChainPriorityNATSource},
}

// ensureTable creates the private table and its filter base chains if they do
// not already exist. Adding an existing table or chain re-asserts it rather than
// failing, so re-running is safe.
//
// The chain definitions deliberately leave the policy unset: re-adding an
// existing base chain re-asserts the named properties, so stating "accept" here
// would revert a default-drop policy a prior SetDefaultPolicy set. A base chain
// created without a policy defaults to accept (the intended initial default),
// and omitting it leaves any existing policy untouched.
func (f *NFT) ensureTable(ctx context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.ensured {
		return nil
	}
	c, err := nftConn()
	if err != nil {
		return err
	}
	tbl := c.AddTable(f.tableRef())
	for _, bc := range nftFilterBaseChains {
		c.AddChain(&nftables.Chain{
			Name:     bc.name,
			Table:    tbl,
			Type:     bc.chType,
			Hooknum:  bc.hook,
			Priority: bc.priority,
		})
	}
	if err := c.Flush(); err != nil {
		return fmt.Errorf("failed to set up nftables table %s: %s", f.table, err)
	}
	f.ensured = true
	return nil
}

// ensureNATChains creates the private table's nat base chains (prerouting for
// destination NAT, postrouting for source NAT) if they do not already exist. It
// is called lazily the first time a NAT rule is written so filter-only use never
// installs nat hooks.
func (f *NFT) ensureNATChains(ctx context.Context) error {
	if err := f.ensureTable(ctx); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.natEnsured {
		return nil
	}
	c, err := nftConn()
	if err != nil {
		return err
	}
	tbl := f.tableRef()
	accept := nftables.ChainPolicyAccept
	for _, bc := range nftNATBaseChains {
		c.AddChain(&nftables.Chain{
			Name:     bc.name,
			Table:    tbl,
			Type:     bc.chType,
			Hooknum:  bc.hook,
			Priority: bc.priority,
			Policy:   &accept,
		})
	}
	if err := c.Flush(); err != nil {
		return fmt.Errorf("failed to set up nftables nat chains for %s: %s", f.table, err)
	}
	f.natEnsured = true
	return nil
}

// -----------------------------------------------------------------------------
// Placement
// -----------------------------------------------------------------------------

// registerSets stages the sets an encoded rule references. Anonymous sets are
// created in the same batch as the rule that looks them up; the named meter set
// outlives any single rule, so it is created only when absent.
func (f *NFT) registerSets(c *nftables.Conn, enc *nftEncoded) error {
	for _, as := range enc.anonSets {
		if err := c.AddSet(as.set, as.elements); err != nil {
			return err
		}
	}
	if enc.meterSet != nil {
		_, err := c.GetSetByName(f.tableRef(), enc.meterSet.Name)
		switch {
		case err == nil:
			// The set already counts for this rule; reusing it keeps the counting
			// state a re-add is meant to inherit.
		case f.isNotExist(err):
			if aerr := c.AddSet(enc.meterSet, nil); aerr != nil {
				return aerr
			}
		default:
			return err
		}
	}
	return nil
}

// placeRule stages an encoded rule for addition at the 0-based physical index
// insPos. nftables positions a new rule relative to an existing one's handle, so
// an index inside the chain inserts before the row currently there and an index
// at or past the end appends. A negative index appends too, which is how AddRule
// asks for a plain append.
func (f *NFT) placeRule(c *nftables.Conn, enc *nftEncoded, insPos int, handles []uint64) error {
	if err := f.registerSets(c, enc); err != nil {
		return err
	}
	nr := &nftables.Rule{
		Table:    f.tableRef(),
		Chain:    f.chainRef(enc.chain),
		Exprs:    enc.exprs,
		UserData: enc.userData,
	}
	if insPos >= 0 && insPos < len(handles) {
		nr.Position = handles[insPos]
		c.InsertRule(nr)
		return nil
	}
	c.AddRule(nr)
	return nil
}

// ruleExists reports whether existing already contains a rule matching r.
// Opaque (nil) rows never match.
func (f *NFT) ruleExists(existing []*Rule, r *Rule) bool {
	for _, e := range existing {
		if e != nil && e.EqualForDedup(r, true) {
			return true
		}
	}
	return false
}

// natRuleExists is ruleExists for NAT rules. Opaque (nil) rows never match.
func (f *NFT) natRuleExists(existing []*NATRule, r *NATRule) bool {
	for _, e := range existing {
		if e != nil && e.EqualForDedup(r) {
			return true
		}
	}
	return false
}

// physicalIndex maps a 1-based position over the modeled (non-nil) rows to the
// 0-based physical row index it lands at, keeping opaque rows pinned in place;
// a position past the last modeled row maps to the end of the chain.
func physicalIndex[T any](rows []*T, position int) int {
	seen := 0
	for i, e := range rows {
		if e == nil {
			continue
		}
		seen++
		if seen == position {
			return i
		}
	}
	return len(rows)
}

// -----------------------------------------------------------------------------
// Filter rule mutations
// -----------------------------------------------------------------------------

// nextSurvivingHandle returns the handle of the first row after index i that a
// removal keeps, or 0 when every later row is being deleted (so a replacement
// belongs at the end of the chain).
func (f *NFT) nextSurvivingHandle(matched []bool, handles []uint64, i int) uint64 {
	for j := i + 1; j < len(handles); j++ {
		if !matched[j] {
			return handles[j]
		}
	}
	return 0
}

// removeCovered deletes every chain row the target covers and re-adds each
// merged row's untargeted remainder (see splitMergedRow) in the row's own slot,
// so coverage the caller never named survives in place. The deletions and the
// replacements ride one netlink transaction, so the chain is never briefly
// missing the coverage it keeps. It reports whether any row was deleted.
func (f *NFT) removeCovered(c *nftables.Conn, chain string, rules []*Rule, handles []uint64, r *Rule) (bool, error) {
	matched := make([]bool, len(rules))
	splits := make([][]*Rule, len(rules))
	deleted := false
	for i, e := range rules {
		if e == nil || !e.EqualForRemoval(r, true) {
			continue
		}
		matched[i] = true
		deleted = true
		// A concrete target that matched a multi-state row would drop coverage
		// the caller never asked to remove: an unpinned inet row covers both
		// families, and an l4proto-set row both transports.
		splits[i] = splitMergedRow(e, r)
	}
	if !deleted {
		return false, nil
	}

	tbl := f.tableRef()
	ch := f.chainRef(chain)
	for i := range rules {
		if !matched[i] {
			continue
		}
		if err := c.DelRule(&nftables.Rule{Table: tbl, Chain: ch, Handle: handles[i]}); err != nil {
			return false, err
		}
	}

	// Each remainder takes its row's slot: it is inserted before the first row
	// the removal keeps, which is exactly where the deleted row sat. Walking the
	// rows in ascending order keeps several remainders in their original order.
	for i := range rules {
		if !matched[i] {
			continue
		}
		before := f.nextSurvivingHandle(matched, handles, i)
		for _, s := range splits[i] {
			// A remainder is synthesized here rather than supplied by a caller, so
			// it takes the check an entry point would have run.
			if verr := f.validateRule(s); verr != nil {
				return false, verr
			}
			enc, merr := f.MarshalRule(s)
			if merr != nil {
				return false, merr
			}
			if err := f.registerSets(c, enc); err != nil {
				return false, err
			}
			nr := &nftables.Rule{Table: tbl, Chain: ch, Exprs: enc.exprs, UserData: enc.userData}
			if before != 0 {
				nr.Position = before
				c.InsertRule(nr)
			} else {
				c.AddRule(nr)
			}
		}
	}
	if err := c.Flush(); err != nil {
		return false, err
	}

	// A deleted per-source connection-limit row leaves its counting set behind;
	// drop each removed row's meter set now that its rule is gone. The delete is
	// best-effort: one that fails (a surviving row — foreign, or a remainder
	// re-added above — still references the set) leaves the set in place, which
	// is the correct outcome.
	f.sweepMeterSets(rules, matched)
	return true, nil
}

// sweepMeterSets removes the counting sets of the rows a removal deleted. Each
// delete runs in its own transaction so one still-referenced set does not block
// the rest.
func (f *NFT) sweepMeterSets(rules []*Rule, matched []bool) {
	for i, e := range rules {
		if !matched[i] || e == nil || e.meterSet == "" {
			continue
		}
		c, err := nftConn()
		if err != nil {
			return
		}
		c.DelSet(&nftables.Set{Table: f.tableRef(), Name: e.meterSet})
		_ = c.Flush()
	}
}

// insertRule places a rule in its chain, at a 1-based position over the modeled
// rows or, for a negative position, appended.
func (f *NFT) insertRule(ctx context.Context, zoneName string, position int, r *Rule) error {
	if err := f.ensureTable(ctx); err != nil {
		return err
	}

	// A DirAny rule fans out into an input row plus its role-swapped output row;
	// place each in its own chain at the requested position.
	if r.Direction == DirAny {
		for _, sub := range expandDirections(r) {
			if err := f.insertRule(ctx, zoneName, position, sub); err != nil {
				return err
			}
		}
		return nil
	}

	// A FamilyAny per-source connection limit has no single row (its meter set is
	// family-typed): fan out into a v4 row and a v6 row, each with its own set.
	if f.perSourceFamilySplit(r) {
		for _, sub := range expandFamilies(r) {
			if err := f.insertRule(ctx, zoneName, position, sub); err != nil {
				return err
			}
		}
		return nil
	}

	// Verify the rule is valid for nftables. The fan-outs above run first:
	// validateRule asserts a per-source connection limit already carries a
	// concrete family.
	if err := f.validateRule(r); err != nil {
		return err
	}

	c, err := nftConn()
	if err != nil {
		return err
	}

	// A family-agnostic set reference is pinned to the set's own family.
	r, err = f.resolveSetRefFamily(ctx, c, r)
	if err != nil {
		return err
	}

	enc, err := f.MarshalRule(r)
	if err != nil {
		return err
	}

	// Skip if an equivalent rule already exists.
	existing, handles, err := f.listChain(c, newSetReader(c), enc.chain)
	if err != nil {
		return err
	}
	if f.ruleExists(existing, r) {
		return nil
	}

	insPos := -1
	if position >= 1 {
		// A position counts the modeled rows, matching GetRules' numbering;
		// physicalIndex maps it past any opaque rows to the chain's real index.
		insPos = physicalIndex(existing, position)
	}
	if err := f.placeRule(c, enc, insPos, handles); err != nil {
		return err
	}
	return c.Flush()
}

// AddRule adds a rule to the zone.
func (f *NFT) AddRule(ctx context.Context, zoneName string, r *Rule) error {
	return f.insertRule(ctx, zoneName, -1, r)
}

// InsertRule inserts rule before the given 1-based position. position <= 0 is
// treated as 1 (prepend); a position larger than the current rule count appends
// the rule. Normalizing here keeps insertRule's -1 sentinel reserved for
// AddRule's plain append.
func (f *NFT) InsertRule(ctx context.Context, zoneName string, position int, r *Rule) error {
	if position <= 0 {
		position = 1
	}
	return f.insertRule(ctx, zoneName, position, r)
}

// MoveRule moves an existing rule to the given 1-based position.
func (f *NFT) MoveRule(ctx context.Context, zoneName string, r *Rule, position int) error {
	if position <= 0 {
		position = 1
	}

	// A DirAny rule occupies a slot in both chains; move each half to the requested
	// position within its own chain.
	if r.Direction == DirAny {
		if err := f.ensureTable(ctx); err != nil {
			return err
		}
		for _, sub := range expandDirections(r) {
			if err := f.MoveRule(ctx, zoneName, sub, position); err != nil {
				return err
			}
		}
		return nil
	}

	// A FamilyAny per-source connection limit occupies one row per family; move
	// each to the requested position, mirroring the insertRule fan-out.
	if f.perSourceFamilySplit(r) {
		if err := f.ensureTable(ctx); err != nil {
			return err
		}
		for _, sub := range expandFamilies(r) {
			if err := f.MoveRule(ctx, zoneName, sub, position); err != nil {
				return err
			}
		}
		return nil
	}

	// Verify the rule is valid for nftables; the fan-outs above have already split
	// a per-source connection limit per family.
	if err := f.validateRule(r); err != nil {
		return err
	}

	if err := f.ensureTable(ctx); err != nil {
		return err
	}

	c, err := nftConn()
	if err != nil {
		return err
	}

	// A family-agnostic set reference is pinned to the set's own family so the
	// re-add below marshals; the rows it targets are already pinned on read.
	r, err = f.resolveSetRefFamily(ctx, c, r)
	if err != nil {
		return err
	}

	chain := f.chainForDirection(r.Direction)
	rules, handles, err := f.listChain(c, newSetReader(c), chain)
	if err != nil {
		return err
	}

	// The target's current position is its first matching row's position among
	// the modeled rows; moving it there is a no-op.
	firstLogical := -1
	logical := 0
	for _, e := range rules {
		if e == nil {
			continue
		}
		logical++
		if firstLogical < 0 && e.EqualForRemoval(r, true) {
			firstLogical = logical
		}
	}
	if firstLogical < 0 || position == firstLogical {
		return nil
	}

	// nftables has no native move. Delete every row the target covers — a
	// FamilyAny or TCPUDP target spans rows the chain may hold separately, so all
	// of them relocate — but a concrete target that matched a merged row must not
	// take the untargeted coverage with it: removeCovered re-adds each merged
	// row's remainder in its own slot, and only the targeted rule moves.
	if _, err := f.removeCovered(c, chain, rules, handles, r); err != nil {
		return err
	}

	// The rewrite changed the chain's handles, so read it back before placing the
	// rule at its new position. Flush emptied the batch, so the same scope takes
	// the follow-up placement; the set reader is rebuilt because its cache
	// predates the rewrite.
	after, afterHandles, err := f.listChain(c, newSetReader(c), chain)
	if err != nil {
		return err
	}
	enc, err := f.MarshalRule(r)
	if err != nil {
		return err
	}
	if err := f.placeRule(c, enc, physicalIndex(after, position), afterHandles); err != nil {
		return err
	}
	return c.Flush()
}

// RemoveRule removes a rule from the zone. A target that matches nothing in the
// library's own table but matches a rule in another table returns
// ErrForeignTable: GetRules reports that rule, but this backend writes only to
// its own table, so the rule is left in place. Foreign rules are deliberately not
// deleted by handle: Sync removes every reported rule outside the desired set, so
// that would wipe every other table on the host, and a foreign rule is parsed
// best-effort, so its handle may carry more than the parsed Rule shows.
func (f *NFT) RemoveRule(ctx context.Context, zoneName string, r *Rule) error {
	if err := f.ensureTable(ctx); err != nil {
		return err
	}

	// A DirAny target removes both its input row and its role-swapped output row,
	// each from its own chain. Both halves run even when one fails, so a foreign
	// input row cannot stop the output row in our own table from being removed;
	// the joined error keeps errors.Is working on each half's error.
	if r.Direction == DirAny {
		var errs []error
		for _, sub := range expandDirections(r) {
			errs = append(errs, f.RemoveRule(ctx, zoneName, sub))
		}
		return errors.Join(errs...)
	}

	// Verify the rule is valid for nftables. Only the encoding paths run
	// validateRule: a removal target is matched against parsed rows, never
	// encoded, and RemoveRule has no per-family fan-out, so a FamilyAny
	// per-source connection limit is a legitimate target here.
	if err := r.validate(); err != nil {
		return err
	}

	c, err := nftConn()
	if err != nil {
		return err
	}
	chain := f.chainForDirection(r.Direction)
	sets := newSetReader(c)
	rules, handles, err := f.listChain(c, sets, chain)
	if err != nil {
		return err
	}
	// Delete every row the target covers, not just the first: a FamilyAny target
	// clears both an unpinned row and any family-pinned rows it spans, and a TCPUDP
	// target clears both transports. A concrete-family target still removes only its
	// own family — see EqualForRemoval; removeCovered re-adds each merged row's
	// untargeted remainder in the row's own slot.
	deleted, err := f.removeCovered(c, chain, rules, handles, r)
	if err != nil || deleted {
		return err
	}

	// Nothing in our table matched. Removing an absent rule stays a no-op, but a
	// target that GetRules reports from another table must not read as removed.
	foreign, err := f.listForeignRules(c, sets)
	if err != nil {
		return err
	}
	for _, e := range foreign {
		if e.EqualForRemoval(r, true) {
			return fmt.Errorf("%w: nftables table %s", ErrForeignTable, e.table)
		}
	}
	return nil
}

// -----------------------------------------------------------------------------
// NAT rule mutations
// -----------------------------------------------------------------------------

// removeCoveredNAT is removeCovered for NAT rules: it deletes every chain row
// the target covers and re-adds each dual-family row's untargeted family
// remainder (see splitNATDualRow) in the row's own slot, so family coverage the
// caller never named survives in place. Family is the only axis a NAT rule
// spans, so a concrete-family target never splits a row it matches.
func (f *NFT) removeCoveredNAT(c *nftables.Conn, chain string, rules []*NATRule, handles []uint64, r *NATRule) (bool, error) {
	matched := make([]bool, len(rules))
	splits := make([]*NATRule, len(rules))
	deleted := false
	for i, e := range rules {
		if e == nil || !e.EqualForRemoval(r) {
			continue
		}
		matched[i] = true
		deleted = true
		// A concrete target that matched a genuine dual-family row (an unpinned
		// inet row covering both) would drop the family the caller did not name.
		splits[i] = splitNATDualRow(e, r)
	}
	if !deleted {
		return false, nil
	}

	tbl := f.tableRef()
	ch := f.chainRef(chain)
	for i := range rules {
		if !matched[i] {
			continue
		}
		if err := c.DelRule(&nftables.Rule{Table: tbl, Chain: ch, Handle: handles[i]}); err != nil {
			return false, err
		}
	}
	for i := range rules {
		if !matched[i] || splits[i] == nil {
			continue
		}
		// A remainder is synthesized here rather than supplied by a caller, so it
		// takes the check an entry point would have run.
		if verr := f.validateNAT(splits[i]); verr != nil {
			return false, verr
		}
		enc, merr := f.MarshalNATRule(splits[i])
		if merr != nil {
			return false, merr
		}
		if err := f.registerSets(c, enc); err != nil {
			return false, err
		}
		nr := &nftables.Rule{Table: tbl, Chain: ch, Exprs: enc.exprs, UserData: enc.userData}
		if before := f.nextSurvivingHandle(matched, handles, i); before != 0 {
			nr.Position = before
			c.InsertRule(nr)
		} else {
			c.AddRule(nr)
		}
	}
	return true, c.Flush()
}

// addNATRule places a NAT rule in its chain, at a 1-based position over the
// modeled rows or, for a negative position, appended.
func (f *NFT) addNATRule(ctx context.Context, position int, r *NATRule) error {
	// Verify the rule is valid for nftables.
	if err := f.validateNAT(r); err != nil {
		return err
	}

	if err := f.ensureNATChains(ctx); err != nil {
		return err
	}

	c, err := nftConn()
	if err != nil {
		return err
	}

	// A family-agnostic set reference is pinned to the set's own family.
	r, err = f.resolveNATSetRefFamily(ctx, c, r)
	if err != nil {
		return err
	}

	enc, err := f.MarshalNATRule(r)
	if err != nil {
		return err
	}

	existing, handles, err := f.listNATChain(c, newSetReader(c), enc.chain)
	if err != nil {
		return err
	}
	if f.natRuleExists(existing, r) {
		return nil
	}

	insPos := -1
	if position >= 1 {
		insPos = physicalIndex(existing, position)
	}
	if err := f.placeRule(c, enc, insPos, handles); err != nil {
		return err
	}
	return c.Flush()
}

// AddNATRule adds a NAT rule to the zone.
func (f *NFT) AddNATRule(ctx context.Context, zoneName string, r *NATRule) error {
	return f.addNATRule(ctx, -1, r)
}

// InsertNATRule inserts a NAT rule before the given 1-based position within its
// nat chain. position <= 0 is treated as 1; a position larger than the chain's
// current rule count appends the rule.
func (f *NFT) InsertNATRule(ctx context.Context, zoneName string, position int, r *NATRule) error {
	if position <= 0 {
		position = 1
	}
	return f.addNATRule(ctx, position, r)
}

// MoveNATRule moves an existing NAT rule to the given 1-based position within
// its nat chain. position <= 0 is treated as 1; a position larger than the
// chain's current rule count moves the rule to the end.
func (f *NFT) MoveNATRule(ctx context.Context, zoneName string, r *NATRule, position int) error {
	if position <= 0 {
		position = 1
	}

	// Verify the rule is valid for nftables.
	if err := f.validateNAT(r); err != nil {
		return err
	}

	if err := f.ensureNATChains(ctx); err != nil {
		return err
	}

	c, err := nftConn()
	if err != nil {
		return err
	}
	r, err = f.resolveNATSetRefFamily(ctx, c, r)
	if err != nil {
		return err
	}
	enc, err := f.MarshalNATRule(r)
	if err != nil {
		return err
	}

	rules, handles, err := f.listNATChain(c, newSetReader(c), enc.chain)
	if err != nil {
		return err
	}

	// The target's current position is its first matched row's position among the
	// modeled rows; moving it there is a no-op.
	firstLogical := -1
	logical := 0
	for _, e := range rules {
		if e == nil {
			continue
		}
		logical++
		if firstLogical < 0 && e.EqualForRemoval(r) {
			firstLogical = logical
		}
	}
	if firstLogical < 0 || position == firstLogical {
		return nil
	}

	// nftables has no native move; see MoveRule for why the covered rows are
	// deleted and each dual row's untargeted family re-added in its own slot.
	if _, err := f.removeCoveredNAT(c, enc.chain, rules, handles, r); err != nil {
		return err
	}

	// Flush emptied the batch, so the same scope takes the follow-up placement
	// against the handles the rewrite left behind.
	after, afterHandles, err := f.listNATChain(c, newSetReader(c), enc.chain)
	if err != nil {
		return err
	}
	if err := f.placeRule(c, enc, physicalIndex(after, position), afterHandles); err != nil {
		return err
	}
	return c.Flush()
}

// RemoveNATRule removes a NAT rule from the zone.
func (f *NFT) RemoveNATRule(ctx context.Context, zoneName string, r *NATRule) error {
	// Verify the rule is valid for nftables.
	if err := r.validate(); err != nil {
		return err
	}

	if err := f.ensureNATChains(ctx); err != nil {
		return err
	}

	chain := "prerouting"
	if r.Kind.isSource() {
		chain = "postrouting"
	}

	c, err := nftConn()
	if err != nil {
		return err
	}
	sets := newSetReader(c)
	rules, handles, err := f.listNATChain(c, sets, chain)
	if err != nil {
		return err
	}
	// Delete every matching row (see RemoveRule): a FamilyAny NAT target must clear
	// both the unpinned row it names and any family-pinned rows it covers, while a
	// concrete-family target removes only its own family. A concrete-family target
	// that matched a genuine dual-family row re-adds the untargeted family in the
	// row's slot, so a bare masquerade/redirect does not silently stop translating
	// the other family.
	deleted, err := f.removeCoveredNAT(c, chain, rules, handles, r)
	if err != nil || deleted {
		return err
	}

	// Nothing in our table matched. As in RemoveRule, an absent rule is a no-op but
	// a target GetNATRules reports from another table must not read as removed.
	foreign, err := f.listForeignNATRules(c, sets)
	if err != nil {
		return err
	}
	for _, e := range foreign {
		if e.EqualForRemoval(r) {
			return fmt.Errorf("%w: nftables table %s", ErrForeignTable, e.table)
		}
	}
	return nil
}

// -----------------------------------------------------------------------------
// Default policy
// -----------------------------------------------------------------------------

// chainPolicies reads the policy of the private table's filter base chains. A
// chain that does not exist yet has no policy to report and is left as
// ActionInvalid.
func (f *NFT) chainPolicies(c *nftables.Conn) (map[string]Action, error) {
	out := map[string]Action{}
	chains, err := c.ListChainsOfTableFamily(nftables.TableFamilyINet)
	if err != nil {
		if f.isNotExist(err) {
			return out, nil
		}
		return nil, err
	}
	for _, ch := range chains {
		if ch.Table.Name != f.table || ch.Policy == nil {
			continue
		}
		switch *ch.Policy {
		case nftables.ChainPolicyAccept:
			out[ch.Name] = Accept
		case nftables.ChainPolicyDrop:
			out[ch.Name] = Drop
		}
	}
	return out, nil
}

// GetDefaultPolicy returns the default action applied to packets that match no rule.
func (f *NFT) GetDefaultPolicy(ctx context.Context, zoneName string) (*DefaultPolicy, error) {
	c, err := nftConn()
	if err != nil {
		return nil, err
	}
	policies, err := f.chainPolicies(c)
	if err != nil {
		return nil, err
	}
	return &DefaultPolicy{
		Input:   policies["input"],
		Output:  policies["output"],
		Forward: policies["forward"],
	}, nil
}

// SetDefaultPolicy sets the policy of the named directions. nftables chain
// policies may only be accept or drop; reject is not expressible. Re-adding the
// base chain with a policy is how a policy is changed, so its hook properties
// are restated alongside.
func (f *NFT) SetDefaultPolicy(ctx context.Context, zoneName string, policy *DefaultPolicy) error {
	if policy == nil {
		return fmt.Errorf("policy cannot be nil")
	}
	if err := f.ensureTable(ctx); err != nil {
		return err
	}

	wanted := map[string]Action{
		"input":   policy.Input,
		"output":  policy.Output,
		"forward": policy.Forward,
	}
	c, err := nftConn()
	if err != nil {
		return err
	}
	tbl := f.tableRef()
	for _, bc := range nftFilterBaseChains {
		action, ok := wanted[bc.name]
		if !ok || action == ActionInvalid {
			continue
		}
		var pol nftables.ChainPolicy
		switch action {
		case Accept:
			pol = nftables.ChainPolicyAccept
		case Drop:
			pol = nftables.ChainPolicyDrop
		default:
			return fmt.Errorf("nftables chain policy may only be accept or drop")
		}
		c.AddChain(&nftables.Chain{
			Name:     bc.name,
			Table:    tbl,
			Type:     bc.chType,
			Hooknum:  bc.hook,
			Priority: bc.priority,
			Policy:   &pol,
		})
	}
	return c.Flush()
}

// -----------------------------------------------------------------------------
// Address sets
// -----------------------------------------------------------------------------

// setKeyType returns the nftables key type a family's addresses are stored as.
func (f *NFT) setKeyType(family Family) (nftables.SetDatatype, error) {
	switch family {
	case IPv6:
		return nftables.TypeIP6Addr, nil
	case IPv4, FamilyAny:
		// An nftables set carries a single address type, so an unspecified family
		// resolves to IPv4.
		return nftables.TypeIPAddr, nil
	}
	return nftables.SetDatatype{}, fmt.Errorf("a set requires a concrete ip family: %w", ErrUnsupportedSet)
}

// familyForKeyType reverses setKeyType.
func (f *NFT) familyForKeyType(t nftables.SetDatatype) Family {
	switch t.Name {
	case "ipv6_addr":
		return IPv6
	case "ipv4_addr":
		return IPv4
	}
	return FamilyAny
}

// addrFromKey decodes a set element key as an address.
func (f *NFT) addrFromKey(key []byte) (netip.Addr, bool) {
	return netip.AddrFromSlice(key)
}

// addressSetEntries reconstructs the entries a set holds. A plain set lists
// discrete addresses; an interval set lists boundary markers, each span an
// inclusive start and an exclusive end, reported back as a CIDR when the span is
// exactly one and as a "lo-hi" range otherwise.
func (f *NFT) addressSetEntries(sc *nftSetContents) []string {
	type elem struct {
		addr netip.Addr
		end  bool
	}
	var elems []elem
	for _, e := range sc.elements {
		addr, ok := f.addrFromKey(e.Key)
		if !ok {
			continue
		}
		elems = append(elems, elem{addr: addr, end: e.IntervalEnd})
	}
	sort.Slice(elems, func(i, j int) bool {
		if elems[i].addr == elems[j].addr {
			return !elems[i].end && elems[j].end
		}
		return elems[i].addr.Less(elems[j].addr)
	})

	var entries []string
	if !sc.set.Interval {
		for _, e := range elems {
			entries = append(entries, e.addr.String())
		}
		return entries
	}
	open := false
	var start netip.Addr
	for _, e := range elems {
		if !e.end {
			start, open = e.addr, true
			continue
		}
		if !open {
			continue
		}
		// The stored end is exclusive; the span runs to the address below it.
		last := e.addr.Prev()
		if !last.IsValid() || last.Less(start) {
			open = false
			continue
		}
		rng := netipx.IPRangeFrom(start, last)
		if p, ok := rng.Prefix(); ok {
			entries = append(entries, p.String())
		} else {
			entries = append(entries, rng.String())
		}
		open = false
	}
	return entries
}

// setElements renders an entry — an address, a CIDR or a "lo-hi" range — as the
// element(s) a set stores it as. An interval set records the inclusive start and
// an end marker at the exclusive upper bound.
func (f *NFT) setElements(entry string, interval bool) ([]nftables.SetElement, error) {
	entry = strings.TrimSpace(entry)
	var from, to netip.Addr
	switch {
	case strings.Contains(entry, "/"):
		p, err := netip.ParsePrefix(entry)
		if err != nil {
			return nil, fmt.Errorf("invalid set entry %q: %s", entry, err)
		}
		rng := netipx.RangeOfPrefix(p.Masked())
		from, to = rng.From(), rng.To()
	case strings.Contains(entry, "-"):
		rng, err := netipx.ParseIPRange(entry)
		if err != nil {
			return nil, fmt.Errorf("invalid set entry %q: %s", entry, err)
		}
		from, to = rng.From(), rng.To()
	default:
		addr, err := netip.ParseAddr(entry)
		if err != nil {
			return nil, fmt.Errorf("invalid set entry %q: %s", entry, err)
		}
		from, to = addr, addr
	}

	if !interval {
		if from != to {
			return nil, fmt.Errorf("set entry %q spans a range, which requires an interval set", entry)
		}
		return []nftables.SetElement{{Key: from.AsSlice()}}, nil
	}
	end := to.Next()
	if !end.IsValid() {
		return nil, fmt.Errorf("set entry %q reaches the end of the address space", entry)
	}
	return []nftables.SetElement{
		{Key: from.AsSlice()},
		{Key: end.AsSlice(), IntervalEnd: true},
	}, nil
}

// getAddressSet reads a single nftables set as an AddressSet, or nil if it does
// not exist.
func (f *NFT) getAddressSet(c *nftables.Conn, name string) (*AddressSet, error) {
	set, err := c.GetSetByName(f.tableRef(), name)
	if err != nil {
		// A missing set is a no-op for the callers that probe with it; any other
		// failure must surface rather than reading as "not there", or a Backup
		// would silently capture fewer sets than exist.
		if f.isNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	// A dynamic set is connection-limit counting state, not an address set;
	// report it as not-found so no caller manages it as data.
	if set.Dynamic {
		return nil, nil
	}
	elems, err := c.GetSetElements(set)
	if err != nil {
		return nil, err
	}
	out := &AddressSet{Name: name, Family: f.familyForKeyType(set.KeyType)}
	if set.Interval {
		out.Type = SetHashNet
	}
	out.Entries = f.addressSetEntries(&nftSetContents{set: set, elements: elems})
	return out, nil
}

// GetAddressSets returns the address sets managed by this backend.
func (f *NFT) GetAddressSets(ctx context.Context) ([]*AddressSet, error) {
	if err := f.ensureTable(ctx); err != nil {
		return nil, err
	}
	c, err := nftConn()
	if err != nil {
		return nil, err
	}
	sets, err := c.GetSets(f.tableRef())
	if err != nil {
		return nil, err
	}
	result := make([]*AddressSet, 0, len(sets))
	for _, s := range sets {
		// A dynamic set is a per-source connection-limit meter, rule mechanics
		// rather than a caller-managed address set; reporting one would let a
		// Backup/Restore or a caller's sweep manage counting state as data. An
		// anonymous set is a rule's own inline literal, likewise not data.
		if s.Dynamic || s.Anonymous {
			continue
		}
		detail, derr := f.getAddressSet(c, s.Name)
		if derr != nil {
			return nil, derr
		}
		if detail == nil {
			continue
		}
		result = append(result, detail)
	}
	return result, nil
}

// GetAddressSet returns a single address set by name, or an error if it does not exist.
func (f *NFT) GetAddressSet(ctx context.Context, name string) (*AddressSet, error) {
	if err := f.ensureTable(ctx); err != nil {
		return nil, err
	}
	c, err := nftConn()
	if err != nil {
		return nil, err
	}
	set, err := f.getAddressSet(c, name)
	if err != nil {
		return nil, err
	}
	if set == nil {
		return nil, fmt.Errorf("address set %q not found", name)
	}
	return set, nil
}

// setMatches reports whether an existing set's definition matches a requested
// family/type, so AddAddressSet can tell a harmless re-add of an identical set
// apart from a genuine type/family conflict, which must surface as an error
// rather than being silently swallowed. A nil existing set never matches.
func (f *NFT) setMatches(existing *AddressSet, wantFamily Family, wantType SetType) bool {
	if existing == nil {
		return false
	}
	if wantFamily == FamilyAny {
		wantFamily = IPv4
	}
	return existing.Family == wantFamily && existing.Type == wantType
}

// AddAddressSet creates an address set. Adding a set that already exists (by name)
// with the same definition is a no-op.
func (f *NFT) AddAddressSet(ctx context.Context, set *AddressSet) error {
	if set == nil || set.Name == "" {
		return fmt.Errorf("an address set requires a name")
	}
	if err := f.ensureTable(ctx); err != nil {
		return err
	}
	keyType, err := f.setKeyType(set.Family)
	if err != nil {
		return err
	}

	c, err := nftConn()
	if err != nil {
		return err
	}
	// An existing set is only acceptable when it is the same set; a differing
	// definition is a genuine conflict.
	if existing, gerr := f.getAddressSet(c, set.Name); gerr != nil {
		return gerr
	} else if existing != nil {
		if !f.setMatches(existing, set.Family, set.Type) {
			return fmt.Errorf("address set %q already exists with a different definition", set.Name)
		}
		return nil
	}

	interval := set.Type == SetHashNet
	var elems []nftables.SetElement
	for _, e := range set.Entries {
		els, eerr := f.setElements(e, interval)
		if eerr != nil {
			return eerr
		}
		elems = append(elems, els...)
	}
	if err := c.AddSet(&nftables.Set{
		Table:    f.tableRef(),
		Name:     set.Name,
		KeyType:  keyType,
		Interval: interval,
	}, elems); err != nil {
		return err
	}
	return c.Flush()
}

// RemoveAddressSet removes an address set by name.
func (f *NFT) RemoveAddressSet(ctx context.Context, name string) error {
	if err := f.ensureTable(ctx); err != nil {
		return err
	}
	c, err := nftConn()
	if err != nil {
		return err
	}
	c.DelSet(&nftables.Set{Table: f.tableRef(), Name: name})
	if err := c.Flush(); err != nil {
		if f.isNotExist(err) {
			return nil
		}
		return err
	}
	return nil
}

// setEntryElements resolves the set an entry is being written to and renders the
// entry as its element(s), so an interval set's boundary markers match the set's
// actual definition rather than a guess.
func (f *NFT) setEntryElements(c *nftables.Conn, name, entry string) (*nftables.Set, []nftables.SetElement, error) {
	set, err := c.GetSetByName(f.tableRef(), name)
	if err != nil {
		if f.isNotExist(err) {
			return nil, nil, fmt.Errorf("address set %q not found", name)
		}
		return nil, nil, err
	}
	elems, err := f.setElements(entry, set.Interval)
	if err != nil {
		return nil, nil, err
	}
	return set, elems, nil
}

// AddAddressSetEntry adds an entry to the named set.
func (f *NFT) AddAddressSetEntry(ctx context.Context, name, entry string) error {
	if err := f.ensureTable(ctx); err != nil {
		return err
	}
	c, err := nftConn()
	if err != nil {
		return err
	}
	set, elems, err := f.setEntryElements(c, name, entry)
	if err != nil {
		return err
	}
	if err := c.SetAddElements(set, elems); err != nil {
		return err
	}
	return c.Flush()
}

// RemoveAddressSetEntry removes an entry from the named set.
func (f *NFT) RemoveAddressSetEntry(ctx context.Context, name, entry string) error {
	if err := f.ensureTable(ctx); err != nil {
		return err
	}
	c, err := nftConn()
	if err != nil {
		return err
	}
	set, elems, err := f.setEntryElements(c, name, entry)
	if err != nil {
		return err
	}
	if err := c.SetDeleteElements(set, elems); err != nil {
		return err
	}
	return c.Flush()
}

// setRefFamily resolves the single family of the named address set(s) a rule
// references through the shared resolver core, reading each set from this
// backend's own store — nft named sets are not kernel ipsets, so the ipset
// resolver cannot see them. A named set is family-typed, so a family-agnostic
// set-referencing rule is pinned to the set's own family rather than rejected:
// its rows could never match the other family anyway.
func (f *NFT) setRefFamily(c *nftables.Conn, source, destination string) (Family, error) {
	return setRefFamilyFrom(func(name string) (Family, bool, error) {
		set, err := f.getAddressSet(c, name)
		if err != nil {
			return FamilyAny, false, err
		}
		if set == nil {
			return FamilyAny, false, nil
		}
		return set.Family, true, nil
	}, source, destination)
}

// resolveSetRefFamily returns r pinned to its referenced set's family when the
// rule is family-agnostic and names a set; every other rule passes through
// unchanged. Callers resolve before marshalling, so MarshalRule never sees an
// unpinned set reference.
func (f *NFT) resolveSetRefFamily(ctx context.Context, c *nftables.Conn, r *Rule) (*Rule, error) {
	return resolveSetRefRule(r, func(source, destination string) (Family, error) {
		return f.setRefFamily(c, source, destination)
	})
}

// resolveNATSetRefFamily is resolveSetRefFamily for NAT rules.
func (f *NFT) resolveNATSetRefFamily(ctx context.Context, c *nftables.Conn, r *NATRule) (*NATRule, error) {
	return resolveSetRefNAT(r, func(source, destination string) (Family, error) {
		return f.setRefFamily(c, source, destination)
	})
}

// -----------------------------------------------------------------------------
// Backup and lifecycle
// -----------------------------------------------------------------------------

// Backup captures the filter and NAT rules in this backend's private table.
func (f *NFT) Backup(ctx context.Context, zoneName string) (*Backup, error) {
	c, err := nftConn()
	if err != nil {
		return nil, err
	}
	sets := newSetReader(c)

	// Read the private table directly rather than GetRules: Restore refills only
	// this table, so the backup must not pull in rules from foreign tables (they
	// would be re-added into the wrong table on Restore).
	rules, err := f.listOwnRules(c, sets)
	if err != nil {
		return nil, err
	}
	natRules, err := f.listOwnNATRules(c, sets)
	if err != nil {
		return nil, err
	}
	backup := &Backup{Rules: rules, NATRules: natRules}
	if err := captureBackupState(ctx, f, zoneName, backup); err != nil {
		return nil, err
	}
	return backup, nil
}

// Restore replaces the managed rules with the contents of a Backup.
func (f *NFT) Restore(ctx context.Context, zoneName string, backup *Backup) error {
	if backup == nil {
		return fmt.Errorf("backup cannot be nil")
	}
	if err := f.ensureTable(ctx); err != nil {
		return err
	}
	if err := f.ensureNATChains(ctx); err != nil {
		return err
	}

	// Clear the modeled rows by handle rather than flushing the table: an
	// unmodeled row (a foreign construct hand-added into the private table) is
	// invisible to Backup, so a flush would destroy state the snapshot cannot
	// reproduce.
	if err := f.clearModeledRows(ctx); err != nil {
		return err
	}

	// Recreate the sets on a clean slate before the rules that reference them. The
	// clear above removed every modeled rule, so no modeled rule holds a set
	// reference and each set can be removed and rebuilt; the clean rebuild is
	// required because AddAddressSet is a no-op on an existing set and would not
	// otherwise restore a flushed set's elements. An unmodeled row that still
	// references a set surfaces here as a delete-set error rather than being
	// silently destroyed.
	if err := restoreBackupSets(ctx, f, backup, true); err != nil {
		return err
	}

	for _, r := range backup.Rules {
		if err := f.AddRule(ctx, zoneName, r); err != nil {
			return err
		}
	}
	for _, r := range backup.NATRules {
		if err := f.AddNATRule(ctx, zoneName, r); err != nil {
			return err
		}
	}
	return applyBackupPolicy(ctx, f, zoneName, backup)
}

// clearModeledRows deletes every modeled rule row from the private table's
// filter and nat chains by handle, in one netlink transaction, leaving unmodeled
// (opaque) rows in place. Chain hooks and policies are untouched. The cleared
// rows' per-source meter sets are swept afterwards, best-effort, so a restore
// does not strand counting state; a rule the restore re-adds auto-creates its
// set again.
func (f *NFT) clearModeledRows(ctx context.Context) error {
	c, err := nftConn()
	if err != nil {
		return err
	}
	sets := newSetReader(c)
	tbl := f.tableRef()
	staged := false

	var staleRules []*Rule
	var staleMatched []bool
	for _, chain := range nftFilterChains {
		rules, handles, lerr := f.listChain(c, sets, chain)
		if lerr != nil {
			return lerr
		}
		ch := f.chainRef(chain)
		for i, e := range rules {
			if e == nil {
				continue
			}
			if derr := c.DelRule(&nftables.Rule{Table: tbl, Chain: ch, Handle: handles[i]}); derr != nil {
				return derr
			}
			staged = true
			staleRules = append(staleRules, e)
			staleMatched = append(staleMatched, true)
		}
	}
	for _, chain := range nftNATChains {
		rules, handles, lerr := f.listNATChain(c, sets, chain)
		if lerr != nil {
			return lerr
		}
		ch := f.chainRef(chain)
		for i, e := range rules {
			if e == nil {
				continue
			}
			if derr := c.DelRule(&nftables.Rule{Table: tbl, Chain: ch, Handle: handles[i]}); derr != nil {
				return derr
			}
			staged = true
		}
	}
	if !staged {
		return nil
	}
	if err := c.Flush(); err != nil {
		return err
	}
	f.sweepMeterSets(staleRules, staleMatched)
	return nil
}

// Reload is a no-op; nftables applies changes immediately, so there is nothing to reload.
func (f *NFT) Reload(ctx context.Context) error {
	return nil
}

// Close closes the connection to the manager.
func (f *NFT) Close(ctx context.Context) error {
	return nil
}
