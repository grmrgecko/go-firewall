package firewall

import (
	"fmt"
	"strconv"
	"strings"
)

// Action is the firewall action taken on a rule's matching packets.
type Action uint8

const (
	// ActionInvalid is the zero value of Action, meaning no action; it is
	// rejected when authoring a rule or policy.
	ActionInvalid Action = iota
	// Accept permits matching packets through.
	Accept
	// Reject refuses matching packets with an error response to the sender.
	Reject
	// Drop silently discards matching packets.
	Drop
)

// String returns the canonical lower-case name of the action.
func (t Action) String() string {
	switch t {
	case Accept:
		return "accept"
	case Reject:
		return "reject"
	case Drop:
		return "drop"
	}
	return "invalid"
}

// ParseAction parses a caller-supplied action token (case-insensitive),
// accepting only the concrete actions Accept, Reject and Drop. The sentinel
// "invalid" (ActionInvalid) is rejected here so callers cannot author a rule or
// policy with no real action; backup decoding round-trips it separately in
// Action.UnmarshalJSON.
func ParseAction(s string) (Action, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "accept":
		return Accept, nil
	case "reject":
		return Reject, nil
	case "drop":
		return Drop, nil
	}
	return 0, fmt.Errorf("unknown action %q", s)
}

// Family is the IP family a rule targets.
type Family uint8

const (
	// FamilyAny targets both IPv4 and IPv6.
	FamilyAny Family = iota
	// IPv4 targets IPv4 traffic only.
	IPv4
	// IPv6 targets IPv6 traffic only.
	IPv6
)

// String returns the canonical lower-case name of the family.
func (t Family) String() string {
	switch t {
	case IPv4:
		return "ipv4"
	case IPv6:
		return "ipv6"
	}
	return "any"
}

// ParseFamily parses a family token (case-insensitive), accepting the canonical
// name emitted by Family.String plus the common aliases (v4/inet4, v6/inet6).
// An unknown value is an error.
func ParseFamily(s string) (Family, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "any":
		return FamilyAny, nil
	case "ipv4", "v4", "inet4":
		return IPv4, nil
	case "ipv6", "v6", "inet6":
		return IPv6, nil
	}
	return 0, fmt.Errorf("unknown family %q", s)
}

// Protocol is the network protocol a rule matches.
type Protocol uint8

const (
	// ProtocolAny matches every IP protocol and is the zero value.
	ProtocolAny Protocol = iota
	// UDP is the connectionless transport protocol.
	UDP
	// TCP is the connection-oriented transport protocol.
	TCP
	// ICMP and ICMPv6 are the control-message protocols. ICMP implies IPv4 and
	// ICMPv6 implies IPv6.
	ICMP
	ICMPv6
	// SCTP is a transport protocol that, like TCP and UDP, carries ports.
	SCTP
	// GRE, ESP and AH are portless IP protocols (tunneling and IPsec). A rule
	// carrying one of these cannot also match a port.
	GRE
	ESP
	AH
	// TCPUDP matches TCP and UDP together.
	TCPUDP
)

// String returns the canonical lower-case name of the protocol.
func (t Protocol) String() string {
	switch t {
	case UDP:
		return "udp"
	case TCP:
		return "tcp"
	case TCPUDP:
		return "tcpudp"
	case ICMP:
		return "icmp"
	case ICMPv6:
		return "icmpv6"
	case SCTP:
		return "sctp"
	case GRE:
		return "gre"
	case ESP:
		return "esp"
	case AH:
		return "ah"
	}
	return "any"
}

// IsICMP reports whether the protocol is ICMP or ICMPv6.
func (t Protocol) IsICMP() bool {
	return t == ICMP || t == ICMPv6
}

// HasPorts reports whether the protocol carries layer-4 ports (TCP, UDP, SCTP or
// the merged TCPUDP). A port match is only meaningful and only valid for these
// protocols.
func (t Protocol) HasPorts() bool {
	return t == TCP || t == UDP || t == SCTP || t == TCPUDP
}

// oppositeProtocol returns the other transport of the TCP/UDP pair a TCPUDP rule
// fans out to: UDP for TCP and vice versa. Every other protocol has no twin and
// returns ProtocolAny (the sentinel meaning "no pair"). It is the protocol analog of
// oppositeFamily, and supports the dual-row split on removal.
func oppositeProtocol(p Protocol) Protocol {
	switch p {
	case TCP:
		return UDP
	case UDP:
		return TCP
	default:
		return ProtocolAny
	}
}

// Ptr returns a pointer to v. It is a convenience for setting optional rule
// fields such as ICMPType, e.g. firewall.Ptr[uint8](8).
func Ptr[T any](v T) *T {
	return &v
}

// icmpNameToNum maps the ICMP type names various tools accept (and their common
// aliases) to their numeric type. It is used when reading a rule whose ICMP type
// is written by name; rules this library writes always emit the number, which
// every backend accepts.
var icmpNameToNum = map[string]uint8{
	"echo-reply":              0,
	"pong":                    0,
	"destination-unreachable": 3,
	"source-quench":           4,
	"redirect":                5,
	"echo-request":            8,
	"ping":                    8,
	"router-advertisement":    9,
	"router-solicitation":     10,
	"time-exceeded":           11,
	"ttl-exceeded":            11,
	"parameter-problem":       12,
	"timestamp-request":       13,
	"timestamp-reply":         14,
	"info-request":            15,
	"info-reply":              16,
	"address-mask-request":    17,
	"address-mask-reply":      18,
	"traceroute":              30,
}

// icmpv6NameToNum maps the ICMPv6 type names nftables, ip6tables and ufw print
// to their numeric type (both the nftables nd-* spellings and the ip6tables
// long forms such as router-solicitation). ICMPv6 reuses several names from
// ICMPv4 (echo-request, destination-unreachable, ...) for *different* numbers,
// so a name read from an ICMPv6 rule must be resolved through this table rather
// than icmpNameToNum.
var icmpv6NameToNum = map[string]uint8{
	"destination-unreachable": 1,
	"packet-too-big":          2,
	"time-exceeded":           3,
	"ttl-exceeded":            3,
	"parameter-problem":       4,
	"echo-request":            128,
	"ping":                    128,
	"echo-reply":              129,
	"pong":                    129,
	"mld-listener-query":      130,
	"mld-listener-report":     131,
	"mld-listener-done":       132,
	"mld-listener-reduction":  132,
	"nd-router-solicit":       133,
	"router-solicitation":     133,
	"nd-router-advert":        134,
	"router-advertisement":    134,
	"nd-neighbor-solicit":     135,
	"neighbor-solicitation":   135,
	"neighbour-solicitation":  135,
	"nd-neighbor-advert":      136,
	"neighbor-advertisement":  136,
	"neighbour-advertisement": 136,
	"nd-redirect":             137,
	"redirect":                137,
	"router-renumbering":      138,
	"ind-neighbor-solicit":    141,
	"ind-neighbor-advert":     142,
	"mld2-listener-report":    143,
}

// parseICMPType parses an ICMP type token as either a number (0-255) or one of
// the well-known IPv4 names in icmpNameToNum.
func parseICMPType(tok string) (uint8, bool) {
	return parseICMPTypeFamily(tok, false)
}

// parseICMPTypeFamily parses an ICMP type token like parseICMPType, but resolves
// names through the ICMPv6 table when v6 is true. Numbers parse identically in
// either family (and rules this library writes always emit the number), so only
// the name path is family-dependent.
func parseICMPTypeFamily(tok string, v6 bool) (uint8, bool) {
	tok = strings.TrimSpace(tok)
	if n, err := strconv.ParseUint(tok, 10, 8); err == nil {
		return uint8(n), true
	}
	if v6 {
		if n, ok := icmpv6NameToNum[strings.ToLower(tok)]; ok {
			return n, true
		}
		return 0, false
	}
	if n, ok := icmpNameToNum[strings.ToLower(tok)]; ok {
		return n, true
	}
	return 0, false
}

// ParseICMPType parses an ICMP type token as either a number (0-255) or a
// well-known type name, resolving names through the ICMPv6 table when v6 is true
// (the same name maps to a different number under ICMPv6 — e.g. echo-request is 8
// for ICMPv4 but 128 for ICMPv6). It is the exported form of the resolution the
// backends use internally, so a caller or CLI authoring a rule by name accepts
// exactly the spellings the library itself emits and reads back.
func ParseICMPType(tok string, v6 bool) (uint8, bool) {
	return parseICMPTypeFamily(tok, v6)
}

// GetProtocol converts a string to the network protocol. The common spellings
// each backend emits for ICMPv6 (icmpv6, ipv6-icmp, icmp6) are all recognized.
// An unknown token resolves to ProtocolAny (the widest match), so a caller that
// must distinguish an unknown protocol from a genuine "any" checks the token
// itself, as the save-file parsers do.
func GetProtocol(proto string) Protocol {
	switch {
	case strings.EqualFold("udp", proto):
		return UDP
	case strings.EqualFold("tcp", proto):
		return TCP
	case strings.EqualFold("tcpudp", proto):
		return TCPUDP
	case strings.EqualFold("icmp", proto):
		return ICMP
	case strings.EqualFold("icmpv6", proto),
		strings.EqualFold("ipv6-icmp", proto),
		strings.EqualFold("icmp6", proto):
		return ICMPv6
	case strings.EqualFold("sctp", proto):
		return SCTP
	case strings.EqualFold("gre", proto):
		return GRE
	case strings.EqualFold("esp", proto),
		strings.EqualFold("ipsec-esp", proto):
		return ESP
	case strings.EqualFold("ah", proto),
		strings.EqualFold("ipsec-ah", proto):
		return AH
	}
	return ProtocolAny
}

// PortRange is an inclusive range of ports. A single port is represented with
// End equal to Start (or End left zero, which normalizes to Start).
type PortRange struct {
	// Start is the first port in the inclusive range.
	Start uint16
	// End is the last port in the inclusive range.
	End uint16
}

// normalized returns the range with a zero or inverted End collapsed to a single
// port at Start.
func (pr PortRange) normalized() PortRange {
	if pr.End == 0 || pr.End < pr.Start {
		pr.End = pr.Start
	}
	return pr
}

// String renders the range as "80" for a single port or "80-90" for a span.
func (pr PortRange) String() string {
	pr = pr.normalized()
	if pr.Start == pr.End {
		return strconv.FormatUint(uint64(pr.Start), 10)
	}
	return fmt.Sprintf("%d-%d", pr.Start, pr.End)
}

// ParsePortRange parses a single "80" or "80-90"/"80:90" token into a PortRange.
func ParsePortRange(s string) (PortRange, error) {
	s = strings.TrimSpace(s)
	sep := "-"
	if strings.Contains(s, ":") {
		sep = ":"
	}
	lo, hi, isRange := strings.Cut(s, sep)
	start, err := strconv.ParseUint(strings.TrimSpace(lo), 10, 16)
	if err != nil {
		return PortRange{}, fmt.Errorf("invalid port %q", lo)
	}
	pr := PortRange{Start: uint16(start), End: uint16(start)}
	if isRange {
		end, err := strconv.ParseUint(strings.TrimSpace(hi), 10, 16)
		if err != nil {
			return PortRange{}, fmt.Errorf("invalid port %q", hi)
		}
		pr.End = uint16(end)
		if pr.End < pr.Start {
			return PortRange{}, fmt.Errorf("port range end %d is below start %d", pr.End, pr.Start)
		}
	}
	return pr, nil
}

// ParsePortRanges parses a separated list such as "80,443,1000-2000" into a slice
// of PortRange values. sep is the separator between entries (typically ",").
func ParsePortRanges(s, sep string) ([]PortRange, error) {
	var out []PortRange
	for _, tok := range strings.Split(s, sep) {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			continue
		}
		pr, err := ParsePortRange(tok)
		if err != nil {
			return nil, err
		}
		out = append(out, pr)
	}
	return out, nil
}

// FormatPortRanges renders a slice of ranges as a separated list.
func FormatPortRanges(prs []PortRange, sep string) string {
	parts := make([]string, len(prs))
	for i, pr := range prs {
		parts[i] = pr.String()
	}
	return strings.Join(parts, sep)
}

// ConnState is a set of connection-tracking states to match, combined as a
// bitmask (e.g. StateEstablished|StateRelated). The zero value matches no
// particular state (i.e. the rule is stateless).
type ConnState uint8

const (
	// StateNew matches packets starting a new connection.
	StateNew ConnState = 1 << iota
	// StateEstablished matches packets belonging to an existing connection.
	StateEstablished
	// StateRelated matches packets starting a connection related to an existing
	// one.
	StateRelated
	// StateInvalid matches packets the tracker cannot associate with a connection.
	StateInvalid
)

// connStateNames lists the states in canonical rendering order.
var connStateNames = []struct {
	bit  ConnState
	name string
}{
	{StateNew, "new"},
	{StateEstablished, "established"},
	{StateRelated, "related"},
	{StateInvalid, "invalid"},
}

// Strings returns the set states as lower-case names in canonical order.
func (s ConnState) Strings() []string {
	var out []string
	for _, cs := range connStateNames {
		if s&cs.bit != 0 {
			out = append(out, cs.name)
		}
	}
	return out
}

// String renders the state set as a comma-separated list (e.g.
// "established,related"), or the empty string when no state is set.
func (s ConnState) String() string {
	return strings.Join(s.Strings(), ",")
}

// ParseConnState parses state names (case-insensitive) into a ConnState bitmask.
// Each token may itself be a comma-separated list. An unknown name is an error.
func ParseConnState(tokens ...string) (ConnState, error) {
	var state ConnState
	for _, tok := range tokens {
		for _, name := range strings.Split(tok, ",") {
			name = strings.TrimSpace(name)
			if name == "" {
				continue
			}
			matched := false
			for _, cs := range connStateNames {
				if strings.EqualFold(name, cs.name) {
					state |= cs.bit
					matched = true
					break
				}
			}
			if !matched {
				return 0, fmt.Errorf("unknown connection state %q", name)
			}
		}
	}
	return state, nil
}

// RateUnit is the time unit a RateLimit is expressed over.
type RateUnit uint8

const (
	// PerSecond expresses a rate per second.
	PerSecond RateUnit = iota
	// PerMinute expresses a rate per minute.
	PerMinute
	// PerHour expresses a rate per hour.
	PerHour
	// PerDay expresses a rate per day.
	PerDay
)

// String returns the canonical (nftables-style) unit name.
func (u RateUnit) String() string {
	switch u {
	case PerMinute:
		return "minute"
	case PerHour:
		return "hour"
	case PerDay:
		return "day"
	}
	return "second"
}

// ParseRateUnit parses a rate-unit token, accepting the long, short and
// single-letter spellings the various backends emit (e.g. second/sec/s).
func ParseRateUnit(s string) (RateUnit, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "s", "sec", "second", "seconds":
		return PerSecond, nil
	case "m", "min", "minute", "minutes":
		return PerMinute, nil
	case "h", "hour", "hours":
		return PerHour, nil
	case "d", "day", "days":
		return PerDay, nil
	}
	return 0, fmt.Errorf("unknown rate unit %q", s)
}

// RateLimit caps the rate at which a rule matches packets: up to Rate packets
// per Unit, with an optional Burst allowance. A nil *RateLimit on a Rule means
// no rate limiting. Backends that cannot express a rate limit reject a rule
// carrying one rather than applying it unlimited.
type RateLimit struct {
	// Rate is the maximum number of matching packets allowed per Unit.
	Rate uint
	// Unit is the time window Rate is counted over.
	Unit RateUnit
	// Burst is an optional allowance for bursts above Rate. 0 leaves the burst
	// at the backend default.
	Burst uint
}

// String renders the limit as "<rate>/<unit>" (e.g. "10/minute").
func (rl RateLimit) String() string {
	return fmt.Sprintf("%d/%s", rl.Rate, rl.Unit)
}

// parseRateToken parses a "<rate>/<unit>" token (e.g. "10/minute") into its
// numeric rate and unit. Backends use it when decoding a rule.
func parseRateToken(tok string) (uint, RateUnit, error) {
	num, unitStr, ok := strings.Cut(strings.TrimSpace(tok), "/")
	if !ok {
		return 0, 0, fmt.Errorf("invalid rate %q", tok)
	}
	n, err := strconv.ParseUint(strings.TrimSpace(num), 10, 32)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid rate %q", tok)
	}
	unit, err := ParseRateUnit(unitStr)
	if err != nil {
		return 0, 0, err
	}
	return uint(n), unit, nil
}

// ConnLimit caps the number of concurrent connections a rule matches. When
// PerSource is set the cap is applied per source address; otherwise it is a
// single global cap. A nil *ConnLimit means no connection limiting.
type ConnLimit struct {
	// Count is the maximum number of concurrent connections the rule matches.
	Count uint
	// PerSource, when set, applies Count per source address rather than as a
	// single global cap.
	PerSource bool
}

// netfilterDefaultBurst is the burst the kernel's xt_limit applies when a rule
// names none (5). nft and iptables always print it back, and their read paths
// collapse it to 0 (unset), so a caller that sets Burst=5 is asking for exactly
// that default; normBurst folds the two spellings together.
const netfilterDefaultBurst = 5

// normBurst folds an explicit burst of the netfilter default (5) to 0 (unset)
// so a rule that names Burst=5 matches its own read-back, which reports the
// default as 0.
func normBurst(b uint) uint {
	if b == netfilterDefaultBurst {
		return 0
	}
	return b
}

// eqRateLimit reports whether two optional rate limits are equal, treating nil
// as a distinct "unset" value. The burst is compared through normBurst so an
// explicit default burst (5) and an unset burst (0) count as the same limit.
func eqRateLimit(a, b *RateLimit) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.Rate == b.Rate && a.Unit == b.Unit && normBurst(a.Burst) == normBurst(b.Burst)
}

// eqConnLimit reports whether two optional connection limits are equal, treating
// nil as a distinct "unset" value.
func eqConnLimit(a, b *ConnLimit) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

// Direction names the traffic direction a default policy or rule applies to.
type Direction uint8

const (
	// DirInput is the inbound (input) direction. It must remain the zero value so
	// a rule with no explicit direction is an input rule.
	DirInput Direction = iota
	// DirOutput is the outbound (output) direction.
	DirOutput
	// DirForward is the routing (forward) direction, where a backend models it.
	DirForward
	// DirAny applies to both the input and output directions. It is the direction
	// analog of FamilyAny: a backend that can store a bidirectional rule as one
	// object reads it back as DirAny, while one that cannot fans it into a concrete
	// input row plus a role-swapped output row on write (expandDirections). It never
	// covers DirForward (a routed rule has no input/output twin) and must be declared
	// last so DirInput stays the zero value.
	DirAny
)

// String returns the canonical lower-case name of the direction.
func (d Direction) String() string {
	switch d {
	case DirOutput:
		return "output"
	case DirForward:
		return "forward"
	case DirAny:
		return "any"
	}
	return "input"
}

// ParseDirection parses a direction token (case-insensitive), accepting the
// canonical name emitted by Direction.String. An unknown value is an error.
func ParseDirection(s string) (Direction, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "input", "in":
		return DirInput, nil
	case "output", "out":
		return DirOutput, nil
	case "forward", "fwd":
		return DirForward, nil
	case "any", "both":
		return DirAny, nil
	}
	return 0, fmt.Errorf("unknown direction %q", s)
}

// DefaultPolicy describes the default action a firewall applies to packets that
// match no rule, per direction. A field left as ActionInvalid has backend-
// defined meaning: on Get it means the backend does not expose that direction,
// and on Set it means the direction should be left unchanged.
type DefaultPolicy struct {
	// Input is the default action for inbound packets.
	Input Action
	// Output is the default action for outbound packets.
	Output Action
	// Forward is the default action for routed packets.
	Forward Action
}

// get returns the action for a direction on a DefaultPolicy.
func (p *DefaultPolicy) get(d Direction) Action {
	switch d {
	case DirOutput:
		return p.Output
	case DirForward:
		return p.Forward
	}
	return p.Input
}

// set assigns the action for a direction on a DefaultPolicy.
func (p *DefaultPolicy) set(d Direction, a Action) {
	switch d {
	case DirOutput:
		p.Output = a
	case DirForward:
		p.Forward = a
	default:
		p.Input = a
	}
}

// SetType names the kind of entries an AddressSet holds.
type SetType uint8

const (
	// SetHashIP is a set of individual IP addresses.
	SetHashIP SetType = iota
	// SetHashNet is a set of CIDR network ranges.
	SetHashNet
)

// String returns the ipset-style name of the set type.
func (t SetType) String() string {
	switch t {
	case SetHashNet:
		return "hash:net"
	}
	return "hash:ip"
}

// ParseSetType parses a set-type token (case-insensitive), accepting the
// canonical name emitted by SetType.String ("hash:ip"/"hash:net") plus the short
// aliases "ip"/"net". An unknown value is an error.
func ParseSetType(s string) (SetType, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "hash:ip", "ip":
		return SetHashIP, nil
	case "hash:net", "net":
		return SetHashNet, nil
	}
	return 0, fmt.Errorf("unknown set type %q", s)
}

// AddressSet is a named collection of addresses (an ipset, an nftables set or a
// pf table) that rules can match against. It is managed separately from filter
// and NAT rules through the Manager's address-set methods.
type AddressSet struct {
	// Name of the set. Backends that namespace sets (nftables table, pf anchor)
	// keep it within their own container.
	Name string
	// Family restricts the set to an IP family. Some backends require a concrete
	// family (nftables inet sets carry a single address type); FamilyAny is
	// resolved to IPv4 by those backends.
	Family Family
	// Type is the entry kind, defaulting to SetHashIP when zero.
	Type SetType
	// Entries are the addresses or CIDRs in the set.
	Entries []string
}

// ruleLine is one line a rule materializes into in a csf.allow/csf.deny or apf
// allow_hosts/deny_hosts file, paired with the rule that line reads back as. A rule
// spanning a family or transport axis the native line cannot carry has no single
// form, so it fans out into one line per cell. EditIPList marks the lines the file
// already holds as it scans and writes only the rest, so a partially present fan-out
// — one family written by an earlier single-family add, or a line lost to a manual
// edit — is completed rather than left half open or duplicated wholesale.
type ruleLine struct {
	// line is the exact text written to the list file.
	line string
	// read is the rule that line parses back to, which is what an existing line in
	// the file is compared against to decide whether the line is already present.
	read *Rule
}
