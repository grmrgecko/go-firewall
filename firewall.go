package firewall

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
)

// Sentinel errors a caller can match with errors.Is to tell apart a genuine
// failure from a feature the active backend cannot express. The helpers below
// (unsupportedNAT, unsupportedOrdering, ...) wrap these, and per-backend marshal
// paths use fmt.Errorf("...: %w", err) so the message stays readable while the
// sentinel is preserved for programmatic handling.
var (
	// ErrUnsupported is the common ancestor of every unsupported-feature error.
	// errors.Is returns true for any of the more specific sentinels below.
	ErrUnsupported = errors.New("feature unsupported by this firewall backend")
	// ErrUnsupportedNAT is returned when a backend cannot express NAT.
	ErrUnsupportedNAT = fmt.Errorf("%w: NAT", ErrUnsupported)
	// ErrUnsupportedOrdering is returned by backends whose rule model is not
	// ordered, for InsertRule/MoveRule.
	ErrUnsupportedOrdering = fmt.Errorf("%w: explicit rule ordering", ErrUnsupported)
	// ErrUnsupportedPolicy is returned when a backend cannot read or set a
	// default policy.
	ErrUnsupportedPolicy = fmt.Errorf("%w: default-policy management", ErrUnsupported)
	// ErrUnsupportedSet is returned when a backend cannot manage address sets
	// (ipset/nftset/tables).
	ErrUnsupportedSet = fmt.Errorf("%w: address sets", ErrUnsupported)
	// ErrUnsupportedLog is returned when per-rule logging cannot be expressed.
	ErrUnsupportedLog = fmt.Errorf("%w: per-rule logging", ErrUnsupported)
	// ErrUnsupportedRateLimit is returned when rate limiting cannot be expressed.
	ErrUnsupportedRateLimit = fmt.Errorf("%w: rate limiting", ErrUnsupported)
	// ErrUnsupportedConnLimit is returned when connection limiting cannot be
	// expressed.
	ErrUnsupportedConnLimit = fmt.Errorf("%w: connection limiting", ErrUnsupported)
	// ErrUnsupportedState is returned when connection-state matching cannot be
	// expressed.
	ErrUnsupportedState = fmt.Errorf("%w: connection-state matching", ErrUnsupported)
	// ErrUnsupportedInterface is returned when per-rule interface matching
	// cannot be expressed.
	ErrUnsupportedInterface = fmt.Errorf("%w: per-rule interface matching", ErrUnsupported)
	// ErrUnsupportedSourcePort is returned when source-port matching cannot be
	// expressed.
	ErrUnsupportedSourcePort = fmt.Errorf("%w: source-port matching", ErrUnsupported)
	// ErrUnsupportedForward is returned when a backend cannot express a rule in
	// the forward (routing) chain.
	ErrUnsupportedForward = fmt.Errorf("%w: forward-chain rules", ErrUnsupported)
)

// unsupportedNAT is the error a backend returns from its NAT methods when its
// model cannot express network address translation. backend names the backend.
//
//nolint:unused // only the wf backend needs it, and the authoritative `unused` run is GOOS=linux.
func unsupportedNAT(backend string) error {
	return fmt.Errorf("%s does not support NAT in this model: %w", backend, ErrUnsupportedNAT)
}

// unsupportedOrdering is returned by backends that do not support explicit
// rule ordering for InsertRule or MoveRule.
func unsupportedOrdering(backend string) error {
	return fmt.Errorf("%s does not support explicit rule ordering in this model: %w", backend, ErrUnsupportedOrdering)
}

// unsupportedPolicy is returned by backends that cannot read or set a default
// policy through this model.
func unsupportedPolicy(backend string) error {
	return fmt.Errorf("%s does not support default-policy management in this model: %w", backend, ErrUnsupportedPolicy)
}

// unsupportedSet is returned by backends that cannot manage address sets
// (ipset/nftset/tables) through this model.
//
//nolint:unused // only the wf backend needs it, and the authoritative `unused` run is GOOS=linux.
func unsupportedSet(backend string) error {
	return fmt.Errorf("%s does not support address sets in this model: %w", backend, ErrUnsupportedSet)
}

// unsupportedForward is the error a backend returns when it cannot express a
// rule in the forward (routing) chain. backend names the backend.
func unsupportedForward(backend string) error {
	return fmt.Errorf("%s does not support forward-chain rules in this model: %w", backend, ErrUnsupportedForward)
}

// familyOfAddr infers the IP family of an address or CIDR string, ignoring a
// leading '!' negation. It returns FamilyAny when the family cannot be
// determined.
func familyOfAddr(addr string) Family {
	fam, _ := parseAddrFamily(strings.TrimPrefix(strings.TrimSpace(addr), "!"))
	return fam
}

// parseAddrFamily parses an address (IP or CIDR) and reports its family, or false
// when the value is not a valid address. The boolean is what distinguishes it from
// familyOfAddr, which folds an unset and an unparseable address into FamilyAny:
// config-file parsers classify a line by whether it is an address at all.
func parseAddrFamily(v string) (Family, bool) {
	cidrIP, _, err := net.ParseCIDR(v)
	ip := net.ParseIP(v)
	if err != nil && ip == nil {
		return FamilyAny, false
	}
	if (cidrIP != nil && cidrIP.To4() == nil) || (ip != nil && ip.To4() == nil) {
		return IPv6, true
	}
	return IPv4, true
}

// canonAddr canonicalizes an address match-string to a stable form and reports
// whether it parsed as an IP or CIDR. It exists because backends print the same
// address differently: nft and ufw strip a /32 (or /128) host prefix and
// zero-compress IPv6, while iptables-save adds the /32 — so the literal a rule
// was written with rarely matches the literal read back. A leading "!" negation
// is preserved; a host (bare or /32,/128) normalizes to its bare canonical form;
// a network keeps its masked base and prefix. Non-IP tokens (ipset/zone names,
// MAC addresses, "any", "") do not parse and are compared verbatim by addrEqual.
func canonAddr(s string) (string, bool) {
	s = strings.TrimSpace(s)
	neg := ""
	if strings.HasPrefix(s, "!") {
		neg = "!"
		s = strings.TrimSpace(s[1:])
	}
	if s == "" {
		return "", false
	}
	if ip, ipnet, err := net.ParseCIDR(s); err == nil {
		if ones, bits := ipnet.Mask.Size(); ones == bits {
			// A host prefix (/32 or /128) is the same address as the bare host.
			return neg + ip.String(), true
		}
		return neg + ipnet.String(), true
	}
	if ip := net.ParseIP(s); ip != nil {
		return neg + ip.String(), true
	}
	return "", false
}

// addrEqual reports whether two address match-strings denote the same address,
// treating a bare host and its /32 (or /128) form — and differing IPv6 spellings
// — as equal. It underpins rule identity so a rule survives the round-trip
// through a backend that re-spells addresses (see canonAddr). Tokens that are not
// IPs/CIDRs fall back to exact string comparison.
func addrEqual(a, b string) bool {
	if a == b {
		return true
	}
	ca, oka := canonAddr(a)
	cb, okb := canonAddr(b)
	if !oka || !okb {
		return false
	}
	return ca == cb
}

// splitAddrNeg splits an optional leading "!" negation from an address or set
// match-string, returning whether it was negated and the bare remainder.
func splitAddrNeg(addr string) (neg bool, bare string) {
	if strings.HasPrefix(addr, "!") {
		return true, addr[1:]
	}
	return false, addr
}

// isSetRef reports whether a Source/Destination match-string names an address set
// (an ipset, an nft named set, a pf table) rather than an IP or CIDR. A set
// reference is any non-empty token that, after an optional leading "!" negation,
// does not parse as an address or subnet. An empty string means "any" and is not a
// set reference. Backends that support address sets (Capabilities().AddressSets)
// translate such a token into their native set-match syntax; the set itself is
// family-typed, so a set-referencing rule should carry a concrete Family.
func isSetRef(addr string) bool {
	_, bare := splitAddrNeg(strings.TrimSpace(addr))
	// An empty token and the literal "any" both mean the address wildcard, not a
	// named set; canonAddr cannot parse "any", so guard it explicitly.
	if bare == "" || bare == "any" {
		return false
	}
	_, ok := canonAddr(addr)
	return !ok
}

// setRefFamilyFrom resolves the single concrete family of the address set(s) a
// rule references, using lookup to read a named set's family from wherever the
// backend keeps its sets (the live kernel, its own config file, a D-Bus query).
// A named set is family-typed, so this is what pins a family-agnostic
// set-referencing rule to the one family it could ever match. An optional
// leading "!" negation and "@" set marker are stripped before lookup. A set the
// lookup cannot find, or a source/destination pair naming sets of different
// families, cannot produce a loadable rule, so both are errors. With no set
// reference among the arguments the result is IPv4; callers guard on isSetRef,
// so that arm is only a safe default.
func setRefFamilyFrom(lookup func(name string) (Family, bool, error), source, destination string) (Family, error) {
	fam := FamilyAny
	for _, ref := range []string{source, destination} {
		if !isSetRef(ref) {
			continue
		}
		_, bare := splitAddrNeg(strings.TrimSpace(ref))
		name := strings.TrimPrefix(bare, "@")
		sf, found, err := lookup(name)
		if err != nil {
			return FamilyAny, err
		}
		if !found {
			return FamilyAny, fmt.Errorf("rule references unknown address set %q", name)
		}
		// A family-untyped set (hash:mac and friends) matches as IPv4.
		if sf != IPv6 {
			sf = IPv4
		}
		if fam != FamilyAny && sf != fam {
			return FamilyAny, fmt.Errorf("rule references address sets of different families")
		}
		fam = sf
	}
	if fam == FamilyAny {
		fam = IPv4
	}
	return fam, nil
}

// resolveSetRefRule returns r pinned to its referenced set's family when the
// rule is family-agnostic and names a set — resolve supplies the family from the
// backend's set store — and passes every other rule through unchanged. Callers
// resolve before fanning out per family, so a set-referencing rule is never
// written for a family its single-family set can never match.
func resolveSetRefRule(r *Rule, resolve func(source, destination string) (Family, error)) (*Rule, error) {
	if r.impliedFamily() != FamilyAny || (!isSetRef(r.Source) && !isSetRef(r.Destination)) {
		return r, nil
	}
	fam, err := resolve(r.Source, r.Destination)
	if err != nil {
		return nil, err
	}
	rc := *r
	rc.Family = fam
	return &rc, nil
}

// resolveSetRefNAT is resolveSetRefRule for NAT rules.
func resolveSetRefNAT(r *NATRule, resolve func(source, destination string) (Family, error)) (*NATRule, error) {
	if r.impliedFamily() != FamilyAny || (!isSetRef(r.Source) && !isSetRef(r.Destination)) {
		return r, nil
	}
	fam, err := resolve(r.Source, r.Destination)
	if err != nil {
		return nil, err
	}
	rc := *r
	rc.Family = fam
	return &rc, nil
}

// Rule is a firewall filter rule: a packet match and the action applied to
// matching packets. Its identity is the match fields and action; the derived
// fields (HasPrefix, Number, Packets, Bytes, Comment) describe how the backend
// stores or reports it and do not affect equality.
type Rule struct {
	// Direction is the traffic direction the rule applies to: DirInput,
	// DirOutput, DirForward or DirAny.
	Direction Direction
	// Priority orders this rule relative to others on backends that advertise
	// Capabilities().Priority.
	Priority int
	// Family is the IP family the rule targets. FamilyAny targets both and is
	// resolved from an address or ICMP protocol when left unset.
	Family Family
	// Source matches the packet's source address or CIDR. A leading "!" negates
	// the match, and a non-IP token names an address set where supported. Empty
	// matches any source.
	Source string
	// Destination matches the packet's destination address or CIDR, with the
	// same semantics as Source. Empty matches any destination.
	Destination string
	// Port is the single destination port to match; Ports takes precedence when
	// non-empty.
	Port uint16
	// Ports is a list of destination port ranges to match.
	Ports []PortRange
	// SourcePort is the single source port to match; SourcePorts takes
	// precedence when non-empty.
	SourcePort uint16
	// SourcePorts is a list of source port ranges to match.
	SourcePorts []PortRange
	// Proto is the network protocol the rule matches. ProtocolAny matches every
	// protocol.
	Proto Protocol
	// ICMPType, when set, restricts an ICMP/ICMPv6 rule to a single message
	// type. A nil pointer matches every type. It is only meaningful when Proto
	// is ICMP or ICMPv6.
	ICMPType *uint8
	// State restricts the rule to the given connection-tracking states. The
	// zero value applies no state match.
	State ConnState
	// InInterface matches the inbound interface the packet arrived on. Empty
	// matches any interface.
	InInterface string
	// OutInterface matches the outbound interface the packet leaves on. Empty
	// matches any interface.
	OutInterface string
	// Action is the action applied to matching packets.
	Action Action
	// Log, when set, logs each matched packet before the Action is applied.
	Log bool
	// LogPrefix is an optional label attached to the log line when Log is set.
	LogPrefix string
	// RateLimit caps the packet rate the rule matches; nil applies no limit.
	RateLimit *RateLimit
	// ConnLimit caps the concurrent connections the rule matches; nil applies
	// no limit.
	ConnLimit *ConnLimit
	// Packets is the per-rule packet counter, populated by GetRules on backends
	// that advertise Capabilities().RuleCounters.
	Packets uint64
	// Bytes is the per-rule byte counter, populated alongside Packets.
	Bytes uint64
	// Comment is an optional human-readable label stored alongside the rule on
	// backends that advertise Capabilities().Comments.
	Comment string
	// HasPrefix reports whether the rule carries the library's configured
	// prefix. It is derived on read and purely informational — the library
	// itself never branches on it.
	HasPrefix bool
	// Number is the rule's 1-based position within its chain, populated by
	// GetRules on backends that advertise Capabilities().RuleOrdering. It
	// mirrors the position argument of InsertRule and MoveRule.
	Number int
	// table records the backend container a container backend read this rule
	// from; it backs HasPrefix for the container backends.
	table string
	// meterSet records the dynamic set a per-source connection-limit row counts
	// in, captured on read by the nftables backend so a removal can clear it.
	meterSet string
}

// IsInput reports whether the rule's direction is exactly input (inbound). It is
// a strict, single-direction test: a DirAny rule is not an input rule. Backends
// use it to route a rule to the input chain and to stamp read-back values, so it
// must not fire for DirAny; a DirAny rule reaches a per-chain path only after
// expandDirections has already split it into concrete rows. The both-directions
// coverage a DirAny rule spans is decided by coversDirection, not here.
func (r *Rule) IsInput() bool { return r.Direction == DirInput }

// IsOutput reports whether the rule's direction is exactly output (outbound). It
// is the strict output analog of IsInput; see that method for why a DirAny rule
// must not report true here.
func (r *Rule) IsOutput() bool { return r.Direction == DirOutput }

// IsForward reports whether the rule is a forward (routing) rule.
func (r *Rule) IsForward() bool { return r.Direction == DirForward }

// portSpecsFor normalizes a (Port, Ports) pair into a list of port ranges:
// Ports when set, otherwise the single Port, otherwise nil.
func portSpecsFor(port uint16, ports []PortRange) []PortRange {
	if len(ports) > 0 {
		out := make([]PortRange, len(ports))
		for i, pr := range ports {
			out[i] = pr.normalized()
		}
		return out
	}
	if port != 0 {
		return []PortRange{{Start: port, End: port}}
	}
	return nil
}

// portSpecsToRule is the inverse of portSpecsFor: it writes a parsed set of port
// ranges onto a rule's destination-port fields, using the single Port field for
// one discrete port and the Ports slice otherwise.
func portSpecsToRule(r *Rule, specs []PortRange) {
	if len(specs) == 1 && specs[0].Start == specs[0].End {
		r.Port = specs[0].Start
		return
	}
	r.Ports = specs
}

// sourcePortSpecsToRule writes a parsed set of port ranges onto a rule's
// source-port fields, mirroring portSpecsToRule for the source side.
func sourcePortSpecsToRule(r *Rule, specs []PortRange) {
	if len(specs) == 1 && specs[0].Start == specs[0].End {
		r.SourcePort = specs[0].Start
		return
	}
	r.SourcePorts = specs
}

// natPortSpecsToRule is portSpecsToRule for NAT rules: it writes a parsed set
// of match-port ranges onto the rule's Port/Ports fields.
func natPortSpecsToRule(r *NATRule, specs []PortRange) {
	if len(specs) == 1 && specs[0].Start == specs[0].End {
		r.Port = specs[0].Start
		return
	}
	r.Ports = specs
}

// PortSpecs returns the rule's destination ports as a normalized list of
// ranges: Ports when set, otherwise the single Port, otherwise nil.
func (r *Rule) PortSpecs() []PortRange {
	return portSpecsFor(r.Port, r.Ports)
}

// SourcePortSpecs returns the rule's source ports as a normalized list of
// ranges: SourcePorts when set, otherwise the single SourcePort, otherwise nil.
func (r *Rule) SourcePortSpecs() []PortRange {
	return portSpecsFor(r.SourcePort, r.SourcePorts)
}

// HasPorts reports whether the rule matches on any destination port.
func (r *Rule) HasPorts() bool {
	return r.Port != 0 || len(r.Ports) > 0
}

// HasSourcePorts reports whether the rule matches on any source port.
func (r *Rule) HasSourcePorts() bool {
	return r.SourcePort != 0 || len(r.SourcePorts) > 0
}

// perSourceLimited reports whether the rule carries a per-source connection
// limit, the form whose count is keyed on the source address.
func (r *Rule) perSourceLimited() bool {
	return r.ConnLimit != nil && r.ConnLimit.PerSource
}

// HasPortSet reports whether the rule matches more than a single discrete port
// (a list, or a range spanning more than one port). Backends limited to a single
// port use this to reject rules they cannot represent.
func (r *Rule) HasPortSet() bool {
	specs := r.PortSpecs()
	if len(specs) > 1 {
		return true
	}
	if len(specs) == 1 && specs[0].Start != specs[0].End {
		return true
	}
	return false
}

// HasSourcePortSet reports whether the rule matches more than a single discrete
// source port.
func (r *Rule) HasSourcePortSet() bool {
	specs := r.SourcePortSpecs()
	if len(specs) > 1 {
		return true
	}
	if len(specs) == 1 && specs[0].Start != specs[0].End {
		return true
	}
	return false
}

// portNeedsConcreteProtocol reports whether a (Port, Ports) pair specifies a
// port without a concrete port-carrying protocol (tcp/udp/sctp).
func portNeedsConcreteProtocol(port uint16, ports []PortRange, proto Protocol) bool {
	return (port != 0 || len(ports) > 0) && !proto.HasPorts()
}

// PortNeedsConcreteProtocol reports whether the rule specifies a destination or
// source port without a concrete port-carrying protocol (TCP/UDP/SCTP). Most
// firewall backends cannot express a port match without such a protocol, so they
// use this to reject such a rule rather than silently widening it (matching every
// protocol) or emitting an invalid rule. A ported `any` in a ufw tuple is not this
// shape: it means tcp+udp and is modeled as TCPUDP.
func (r *Rule) PortNeedsConcreteProtocol() bool {
	return portNeedsConcreteProtocol(r.Port, r.Ports, r.Proto) || portNeedsConcreteProtocol(r.SourcePort, r.SourcePorts, r.Proto)
}

// impliedFamily returns the family a rule effectively targets, resolving
// FamilyAny from an ICMP protocol (ICMP => IPv4, ICMPv6 => IPv6) or, failing
// that, from a concrete source/destination address. A rule that names an IPv4
// address is an IPv4 rule even when its Family was left unset, so inferring it
// keeps the rule out of the wrong-family save file (an IPv4 address in an
// ip6tables ruleset is rejected on load).
func (r *Rule) impliedFamily() Family {
	if r.Family != FamilyAny {
		return r.Family
	}
	switch r.Proto {
	case ICMP:
		return IPv4
	case ICMPv6:
		return IPv6
	}
	for _, a := range []string{r.Source, r.Destination} {
		if fam := familyOfAddr(a); fam != FamilyAny {
			return fam
		}
	}
	return FamilyAny
}

// directionSwapped returns a copy of r with its source and destination roles
// swapped: the transform between a rule's inbound and outbound materialization.
// A rule that matches inbound traffic from a host (Source=X, dport=P, in-iface)
// matches the same flow outbound as traffic to that host (Destination=X, sport=P,
// out-iface), so the source/destination address, the source/destination ports and
// the in/out interface all swap sides. Everything protocol- or policy-bound (Proto,
// ICMPType, State, Action, Log, rate/conn limits, Family, Priority, Comment,
// counters, Number, table) is direction-independent and is left untouched. It backs
// the DirAny write-side fan-out (expandDirections), the direction split on removal,
// and the inbound-frame comparison rule identity uses. The Ports/SourcePorts slice
// headers are swapped, not their elements; callers do not mutate them, matching
// splitDualRow's shallow-copy style.
func (r *Rule) directionSwapped() *Rule {
	s := *r
	s.Source, s.Destination = r.Destination, r.Source
	s.Port, s.SourcePort = r.SourcePort, r.Port
	s.Ports, s.SourcePorts = r.SourcePorts, r.Ports
	s.InInterface, s.OutInterface = r.OutInterface, r.InInterface
	return &s
}

// canonicalMatch expresses a rule's match fields in the inbound (input-chain)
// frame so two rules stored in opposite directions can be compared like-for-like.
// An output rule is role-swapped into the inbound frame; input, forward and DirAny
// rules are already inbound-framed (a DirAny rule is authored inbound). It does not
// change Direction — direction coverage is decided separately by coversDirection.
func (r *Rule) canonicalMatch() *Rule {
	if r.Direction == DirOutput {
		return r.directionSwapped()
	}
	return r
}

// portRangeInSpecs reports whether pr equals any range in specs (normalized).
func portRangeInSpecs(pr PortRange, specs []PortRange) bool {
	pr = pr.normalized()
	for _, sp := range specs {
		if sp.normalized() == pr {
			return true
		}
	}
	return false
}

// coalescePortRanges normalizes a port-range list to its minimal canonical form:
// each range is normalized, the list is sorted, and overlapping or directly
// contiguous ranges are merged. It exists because several backends re-spell a
// port set on read — nft in particular lists an anonymous set back with adjacent
// and overlapping ranges merged, so "{22,23,24-30}" comes back as "{22-30}". Rule
// identity compares port sets through this canonical form (see portRangesEqual)
// so such a rule still matches its own read-back and Sync does not churn.
func coalescePortRanges(prs []PortRange) []PortRange {
	if len(prs) == 0 {
		return nil
	}
	cp := make([]PortRange, len(prs))
	for i, pr := range prs {
		cp[i] = pr.normalized()
	}
	sort.Slice(cp, func(i, j int) bool {
		if cp[i].Start != cp[j].Start {
			return cp[i].Start < cp[j].Start
		}
		return cp[i].End < cp[j].End
	})
	out := []PortRange{cp[0]}
	for _, pr := range cp[1:] {
		last := &out[len(out)-1]
		// Merge when the next range overlaps the current one or begins exactly one
		// past its end (a contiguous span). The End<65535 guard avoids a uint16
		// wrap when the current range already reaches the maximum port.
		if pr.Start <= last.End || (last.End < 65535 && pr.Start == last.End+1) {
			if pr.End > last.End {
				last.End = pr.End
			}
			continue
		}
		out = append(out, pr)
	}
	return out
}

// portRangesEqual compares two port-range lists as sets, treating overlapping or
// contiguous ranges that cover the same ports as equal (see coalescePortRanges).
func portRangesEqual(a, b []PortRange) bool {
	ac := coalescePortRanges(a)
	bc := coalescePortRanges(b)
	if len(ac) != len(bc) {
		return false
	}
	for i := range ac {
		if ac[i] != bc[i] {
			return false
		}
	}
	return true
}

// eqU8Ptr reports whether two optional uint8 values are equal, treating nil as a
// distinct "unset" value.
func eqU8Ptr(a, b *uint8) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

// matchFields reports whether the non-family match fields of two rules are
// equal. It is the shared core of Equal and EqualBase. outputSupported is false
// on a backend with no output concept (Capabilities().Output), where the
// input/output distinction is dropped so those two directions never tell two
// rules apart. The coverage callers (covers, EqualForRemoval) pass false here
// only after coversDirection has already decided direction — including keeping a
// forward rule distinct — so the exact-direction gate is theirs to skip.
func (r *Rule) matchFields(rule *Rule, outputSupported bool) bool {
	if r.Direction != rule.Direction && outputSupported {
		return false
	}
	// Priority orders a rule relative to the others (firewalld rich rules), so two
	// rules that differ only in priority are distinct — otherwise a reconcile could
	// never change a rule's priority. Backends without per-rule priority leave it 0,
	// so this never affects them.
	if r.Priority != rule.Priority {
		return false
	}
	if !addrEqual(r.Source, rule.Source) || !addrEqual(r.Destination, rule.Destination) {
		return false
	}
	if !portRangesEqual(r.PortSpecs(), rule.PortSpecs()) {
		return false
	}
	if !portRangesEqual(r.SourcePortSpecs(), rule.SourcePortSpecs()) {
		return false
	}
	if r.Proto != rule.Proto {
		return false
	}
	if !eqU8Ptr(r.ICMPType, rule.ICMPType) {
		return false
	}
	if r.State != rule.State {
		return false
	}
	if r.InInterface != rule.InInterface || r.OutInterface != rule.OutInterface {
		return false
	}
	if r.Action != rule.Action {
		return false
	}
	// Logging and rate/connection limits change the rule's effect, so two rules
	// that differ only in these are distinct (they are not deduplicated, and a
	// removal must name the same modifiers it was added with).
	if r.Log != rule.Log || r.LogPrefix != rule.LogPrefix {
		return false
	}
	if !eqRateLimit(r.RateLimit, rule.RateLimit) {
		return false
	}
	if !eqConnLimit(r.ConnLimit, rule.ConnLimit) {
		return false
	}
	return true
}

// Equal reports whether two rules are the same. Family is compared through
// impliedFamily so a FamilyAny rule matches the concrete family its own content
// forces (an ICMP rule is IPv4, an ICMPv6 rule IPv6, an addressed rule its
// address's family). outputSupported is false on a backend with no output concept
// (Capabilities().Output), where direction does not distinguish two rules.
func (r *Rule) Equal(rule *Rule, outputSupported bool) bool {
	if r.impliedFamily() != rule.impliedFamily() {
		return false
	}
	return r.matchFields(rule, outputSupported)
}

// EqualBase reports whether two rules are the same, ignoring family.
// outputSupported has Equal's meaning.
func (r *Rule) EqualBase(rule *Rule, outputSupported bool) bool {
	return r.matchFields(rule, outputSupported)
}

// coversDirection reports whether an existing rule's direction (have) already
// covers a caller rule's direction (want) — the asymmetric add/dedup form. DirAny
// spans input and output, so it covers either; it never covers DirForward (a
// routed rule has no in/out twin). When outputSupported is false the backend has no
// output concept, so input and output never distinguish two rules — but a
// forward rule is still its own chain and only covered by another forward rule.
func coversDirection(have, want Direction, outputSupported bool) bool {
	if !outputSupported {
		return (have == DirForward) == (want == DirForward)
	}
	if have == want {
		return true
	}
	return have == DirAny && (want == DirInput || want == DirOutput)
}

// coversDirectionRemoval reports whether two rules touch a common direction (the
// symmetric remove/move form): a DirAny on either side spans input and output, so
// it touches any concrete direction and vice versa. DirForward stands alone.
func coversDirectionRemoval(a, b Direction, outputSupported bool) bool {
	if !outputSupported {
		return (a == DirForward) == (b == DirForward)
	}
	if a == b {
		return true
	}
	if a == DirAny && (b == DirInput || b == DirOutput) {
		return true
	}
	if b == DirAny && (a == DirInput || a == DirOutput) {
		return true
	}
	return false
}

// EqualForDedup reports whether the receiver (an existing rule) already makes o
// redundant on add: the same base rule, with the receiver's family, direction
// and transport (a TCPUDP row covers its tcp/udp halves) all covering o's. It is the family- and direction-aware add guard the container
// backends need because EqualBase ignores Family — without the coverage check,
// adding an IPv6 rule whose IPv4 twin already exists would be dropped as a false
// duplicate, leaving that family unprotected. Family and direction are checked
// first so a non-covering row skips the field compare. Coverage: a FamilyAny
// receiver covers either family, a DirAny receiver covers either direction; a
// concrete value covers only its own. The match fields are compared in the inbound
// frame (canonicalMatch) so a DirAny row and a concrete DirOutput target line up,
// with direction excluded from the field compare since coversDirection already
// gated it.
func (r *Rule) EqualForDedup(o *Rule, outputSupported bool) bool {
	return r.covers(o, outputSupported)
}

// coversFamily reports whether an existing rule's family (have) already covers a caller
// rule's family want. FamilyAny spans both IP families, so it covers either; a
// concrete family covers only itself. Both sides are implied families, so an
// address- or ICMP-pinned rule is compared by the family it actually targets.
func coversFamily(have, want Family) bool {
	return have == FamilyAny || have == want
}

// covers is the coverage relation behind Covers and EqualForDedup: r's match is the
// same as o's in every ordinary field, and r's family, transport, direction and
// port axes each span o's. outputSupported is false on a backend with no output
// concept, where direction never distinguishes two rules.
func (r *Rule) covers(o *Rule, outputSupported bool) bool {
	if !coversFamily(r.impliedFamily(), o.impliedFamily()) {
		return false
	}
	if !coversDirection(r.Direction, o.Direction, outputSupported) {
		return false
	}
	if !coversProtocol(r.Proto, o.Proto) {
		return false
	}
	// The port axes compare in the inbound frame, as matchFields does below: an
	// output rule's source and destination ports swap roles.
	rc, oc := r.canonicalMatch(), o.canonicalMatch()
	if !coversPorts(rc.PortSpecs(), oc.PortSpecs()) || !coversPorts(rc.SourcePortSpecs(), oc.SourcePortSpecs()) {
		return false
	}
	// Protocol and ports are gated above, so neutralize them on their axes rather
	// than let matchFields re-test them exactly — a TCPUDP row must absorb a
	// concrete TCP add, and a port-list row its single-port cells.
	return rc.protoNeutralized().portsNeutralized().EqualBase(oc.protoNeutralized().portsNeutralized(), false)
}

// Covers reports whether the receiver's coverage contains o's: the same match in
// every ordinary field, with the receiver's family, transport, direction and port
// axes each spanning o's. FamilyAny spans both IP families, TCPUDP spans TCP and
// UDP, DirAny spans input and output, and a port list or range spans the ports it
// contains; a concrete value spans only itself. ProtocolAny is
// not a multi-state value — it matches every IP protocol — so it covers only
// ProtocolAny.
//
// It is the exported form of the coverage relation the library reasons with. A caller
// holding a rule read back from GetRules uses it to tell whether that rule already
// contains one it is about to add, rather than re-deriving the per-axis rules. It is
// asymmetric: a TCPUDP rule covers its TCP half, never the reverse. Direction is
// always honored; a backend that has no output concept reports Capabilities().Output
// false and folds a DirAny rule to its input half on write.
func (r *Rule) Covers(o *Rule) bool {
	return r.covers(o, true)
}

// EqualForRemoval reports whether the receiver (an existing row) should be acted
// on when the caller targets o: the same base rule, and o's family, transport and
// direction each touch the row's. It is the overlap relation a removal walks the
// stored rows with: a target removes every row it covers, and also matches a row
// that covers more than the target, which the backend then deletes and re-adds
// minus the targeted cell (splitMergedRow). A FamilyAny/TCPUDP/DirAny target
// matches every row on that axis, such a row matches any target, and otherwise
// the values must match so acting on one twin never disturbs the other. The
// field compare runs in the inbound frame (canonicalMatch) with direction
// excluded, since the axis gates above already decided it.
func (r *Rule) EqualForRemoval(o *Rule, outputSupported bool) bool {
	ft, fr := o.impliedFamily(), r.impliedFamily()
	if ft != FamilyAny && fr != FamilyAny && ft != fr {
		return false
	}
	if !coversDirectionRemoval(r.Direction, o.Direction, outputSupported) {
		return false
	}
	if !coversProtocolRemoval(r.Proto, o.Proto) {
		return false
	}
	// Protocol is gated above; neutralize it on the tcp/udp axis so a TCPUDP row
	// matches a concrete-transport target (the caller then splits it) and a TCPUDP
	// target matches each concrete row it covers.
	return r.canonicalMatch().protoNeutralized().EqualBase(o.canonicalMatch().protoNeutralized(), false)
}

// oppositeFamily returns the other concrete IP family: IPv4 for IPv6 and vice
// versa. FamilyAny has no opposite and returns FamilyAny. It supports the
// dual-row split on removal, where deleting a single dual-family row to satisfy a
// concrete-family target must re-add the family the caller did not target.
func oppositeFamily(f Family) Family {
	switch f {
	case IPv4:
		return IPv6
	case IPv6:
		return IPv4
	default:
		return FamilyAny
	}
}

// splitDualRow returns the rule a backend must re-add after deleting a genuine
// dual-family row — a single stored object with no family pin that covers both
// families — to satisfy a concrete-family removal: a copy of the stored row
// pinned to the family the caller did NOT target, so that family's coverage
// survives the delete. It returns nil when no split applies: the target is
// family-agnostic (the whole rule is meant to go), or the matched row is itself
// concrete-family (it removes only its own family and never a twin). Backends
// whose model cannot express the surviving single-family rule reject the removal
// with ErrUnsupported instead of calling this.
func splitDualRow(matched, target *Rule) *Rule {
	tf := target.impliedFamily()
	if tf == FamilyAny || matched.impliedFamily() != FamilyAny {
		return nil
	}
	opp := *matched
	opp.Family = oppositeFamily(tf)
	return &opp
}

// expandDirections returns the concrete-direction rows a rule materializes into on
// write: itself for a concrete direction, or an inbound (DirInput) row plus its
// role-swapped outbound (DirOutput) twin for a DirAny rule. Backends call it before
// their existing per-family fan-out so per-chain marshalling never has to reason
// about DirAny. The returned rows are copies; the caller's rule is untouched.
func expandDirections(r *Rule) []*Rule {
	if r.Direction != DirAny {
		return []*Rule{r}
	}
	in := *r
	in.Direction = DirInput
	out := r.directionSwapped()
	out.Direction = DirOutput
	return []*Rule{&in, out}
}

// expandProtocols returns the concrete-transport rows a rule materializes into on
// write: itself for a single protocol, or a TCP row plus a UDP row for a TCPUDP
// rule. Backends whose native config has no both-transports form call it before
// marshalling so per-row emission never has to reason about TCPUDP. The returned
// rows are copies; the caller's rule is untouched. It is the protocol analog of
// expandDirections.
func expandProtocols(r *Rule) []*Rule {
	if r.Proto != TCPUDP {
		return []*Rule{r}
	}
	tcp, udp := *r, *r
	tcp.Proto, udp.Proto = TCP, UDP
	return []*Rule{&tcp, &udp}
}

// expandFamilies returns the concrete-family rows a rule materializes into: itself
// when it already targets one family, or an IPv4 row plus an IPv6 row when it targets
// both. It reads the implied family, so a rule pinned by an address or an ICMP
// protocol is never split. Backends fan families out in their own way (a save file
// per family, a family-less inet row, a dual-stack config list), so this backs the
// coverage math in cells/CoveredBy, the filterFamiliesIPv6 narrowing, and the
// per-family fan-outs that work on rows (nftables sets, the csf/apf hook's
// per-family command lines).
func expandFamilies(r *Rule) []*Rule {
	if r.impliedFamily() != FamilyAny {
		return []*Rule{r}
	}
	v4, v6 := *r, *r
	v4.Family, v6.Family = IPv4, IPv6
	return []*Rule{&v4, &v6}
}

// filterFamiliesIPv6 returns the expandFamilies rows narrowed to the families the
// backend enforces: with ipv6Enabled false, the IPv6 row of a family-agnostic rule
// is dropped rather than written as a line the backend would never enforce. A row
// already pinned to a concrete family keeps it, IPv6 included, so Restore can
// reproduce a snapshot verbatim.
func filterFamiliesIPv6(ipv6Enabled bool, r *Rule) []*Rule {
	rows := expandFamilies(r)
	if ipv6Enabled || len(rows) == 1 {
		return rows
	}
	kept := make([]*Rule, 0, 1)
	for _, row := range rows {
		if row.Family != IPv6 {
			kept = append(kept, row)
		}
	}
	return kept
}

// expandPorts returns the single-port-spec rows a port-list rule materializes
// into on write: itself when each port axis carries at most one spec, otherwise
// the cross product of one row per destination-port spec and source-port spec.
// Backends whose rule form carries a single port element (a firewalld rich rule
// or zone port, a pf row — pfctl expands a list on load) call it before
// marshalling so per-row emission never has to reason about a list; the stored
// rows cover the list rule through coversPorts. The returned rows are copies;
// the caller's rule is untouched. It is the port analog of expandProtocols.
func expandPorts(r *Rule) []*Rule {
	dest, src := r.PortSpecs(), r.SourcePortSpecs()
	if len(dest) <= 1 && len(src) <= 1 {
		return []*Rule{r}
	}
	// An unset axis stays unset in every row; a set axis contributes one row per
	// spec, written back through portSpecsToRule so a single discrete port takes
	// the Port field, matching how a backend spells a parsed row.
	var dests, srcs [][]PortRange
	for _, pr := range dest {
		dests = append(dests, []PortRange{pr})
	}
	if len(dests) == 0 {
		dests = [][]PortRange{nil}
	}
	for _, pr := range src {
		srcs = append(srcs, []PortRange{pr})
	}
	if len(srcs) == 0 {
		srcs = [][]PortRange{nil}
	}
	var out []*Rule
	for _, d := range dests {
		for _, s := range srcs {
			c := *r
			c.Port, c.Ports, c.SourcePort, c.SourcePorts = 0, nil, 0, nil
			portSpecsToRule(&c, d)
			sourcePortSpecsToRule(&c, s)
			out = append(out, &c)
		}
	}
	return out
}

// expandNATPorts is expandPorts for NAT rules: it fans a match-port list into
// one rule per spec so a backend whose NAT form carries a single port (a
// firewalld forward-port, a pf rdr row) stores each spec as its own row, every
// row translating to the same target.
func expandNATPorts(r *NATRule) []*NATRule {
	specs := r.PortSpecs()
	if len(specs) <= 1 {
		return []*NATRule{r}
	}
	out := make([]*NATRule, 0, len(specs))
	for _, pr := range specs {
		c := *r
		c.Port, c.Ports = 0, nil
		natPortSpecsToRule(&c, []PortRange{pr})
		out = append(out, &c)
	}
	return out
}

// cells returns the concrete rules r covers: the cross product of its merged
// axes, each expanded to the values it spans. A FamilyAny + TCPUDP + DirAny rule
// yields eight cells; a fully concrete rule yields itself. The direction expansion
// role-swaps the outbound half, so each cell is stated in its own natural frame —
// covers compares in the inbound frame, so that swap round-trips. On a backend with
// no output concept (outputSupported false) the direction axis does not distinguish
// two rules, so it is not expanded. On a backend that does not manage IPv6
// (ipv6Supported false) a family-agnostic rule spans only its IPv4 cell, since that
// is all the backend can store for it; a rule pinned to IPv6 keeps its cell. The
// port axis expands a list to one cell per spec, keeping each range whole, so a
// stored set of single-port rows covers a list rule on a backend that fans lists
// out (firewalld, pf).
func (r *Rule) cells(outputSupported, ipv6Supported bool) []*Rule {
	dirs := []*Rule{r}
	if outputSupported {
		dirs = expandDirections(r)
	}
	var out []*Rule
	for _, d := range dirs {
		for _, p := range expandProtocols(d) {
			for _, fam := range filterFamiliesIPv6(ipv6Supported, p) {
				out = append(out, expandPorts(fam)...)
			}
		}
	}
	return out
}

// coveredBy is the coverage relation behind CoveredBy, with the direction axis
// gated on whether the backend distinguishes output rules at all and the family
// axis on whether it manages IPv6 (see cells).
func (r *Rule) coveredBy(rules []*Rule, outputSupported, ipv6Supported bool) bool {
	for _, cell := range r.cells(outputSupported, ipv6Supported) {
		covered := false
		for _, have := range rules {
			if have.covers(cell, outputSupported) {
				covered = true
				break
			}
		}
		if !covered {
			return false
		}
	}
	return true
}

// CoveredBy reports whether every concrete rule the receiver spans is covered by at
// least one rule in rules. It is the set form of Covers, and its inverse: where
// a.Covers(b) asks whether one rule contains another, b.CoveredBy([]*Rule{a}) asks
// whether a set contains one.
//
// A rule that spans several axes is rarely stored as one object: GetRules reports the
// firewall's actual rows, so a rule the caller authored as FamilyAny may read back as
// an IPv4 row and an IPv6 row on a backend that cannot store one family-agnostic row.
// Such a rule is fully present in the set even though no single member Covers it, so
// coverage is decided cell by cell rather than rule by rule. A caller uses it to
// decide whether a rule is already installed before adding it.
//
// It expands the receiver across family, transport, direction and ports and
// requires every resulting cell to be covered, so a rule spanning both transports
// is not reported present when only its TCP half is, and a port-list rule is not
// reported present when only some of its ports are. The receiver is not modified.
func (r *Rule) CoveredBy(rules []*Rule) bool {
	return r.coveredBy(rules, true, true)
}

// MatchesAny reports whether the receiver is the same underlying rule as any of
// targets, honoring direction but ignoring the comment, which is not part of rule
// identity. It is the set form of Equal, and unlike CoveredBy it demands identity
// rather than coverage: a TCPUDP target does not match its TCP half. It backs
// comment-agnostic removal, where a stored row is acted on when it means the same
// rule as one the caller named, however that row was spelled or commented.
func (r *Rule) MatchesAny(targets []*Rule) bool {
	for _, t := range targets {
		if r.Equal(t, true) {
			return true
		}
	}
	return false
}

// OrphanLogMatchesAny reports whether the receiver is a log-only row — a LOG rule
// whose action partner is gone, carried as Log with no action — belonging to a
// logged rule named by one of targets. A logged rule is stored as a LOG row plus
// the action row under it; when the action row is edited away by hand the stray
// LOG row no longer reads back as a rule, and this is how a removal still claims
// it. It reports false for any receiver that carries an action, so a complete
// rule is matched by MatchesAny alone.
func (r *Rule) OrphanLogMatchesAny(targets []*Rule) bool {
	if r.Action != ActionInvalid || !r.Log {
		return false
	}
	for _, t := range targets {
		if !t.Log {
			continue
		}
		// Compare against the target stripped of its action, which is the shape the
		// surviving LOG row encodes.
		tl := *t
		tl.Action = ActionInvalid
		if r.Equal(&tl, true) {
			return true
		}
	}
	return false
}

// splitDualRowProtocol returns the rule a backend must re-add after deleting one
// transport of a genuine TCPUDP row — a single stored rule covering both TCP and
// UDP — to satisfy a concrete-protocol removal: the surviving opposite transport.
// It mirrors splitDualRow for the protocol axis. It returns nil when no split
// applies: the matched row is not a merged TCPUDP row, or the target names no
// single transport (so the whole row goes).
func splitDualRowProtocol(matched, target *Rule) *Rule {
	if matched.Proto != TCPUDP {
		return nil
	}
	opp := oppositeProtocol(target.Proto)
	if opp == ProtocolAny {
		return nil
	}
	s := *matched
	s.Proto = opp
	return &s
}

// splitMergedRow returns the rows a backend must re-add after deleting a single
// stored row that covered more than the caller targeted. A row may be merged on two
// axes at once — nftables' inet table holds a FamilyAny rule as one unpinned row,
// and a TCPUDP rule as one `meta l4proto { tcp, udp }` row — so removing one cell of
// that family×transport grid can leave a remainder that needs two rows to express.
// It composes the per-axis splits: the untargeted family keeps the row's full
// transport coverage, and the untargeted transport is then scoped to the family the
// target named, so the two rows never overlap. It returns nil when the target covers
// the whole row.
func splitMergedRow(matched, target *Rule) []*Rule {
	var out []*Rule
	if s := splitDualRow(matched, target); s != nil {
		out = append(out, s)
	}
	if s := splitDualRowProtocol(matched, target); s != nil {
		// A family split above already re-added the untargeted family across both
		// transports, so this row must not repeat it: pin it to the targeted family.
		if len(out) > 0 {
			s.Family = target.impliedFamily()
		}
		out = append(out, s)
	}
	return out
}

// coversProtocol reports whether an existing rule's protocol (have) already covers a
// caller rule's protocol want (the asymmetric add/dedup form). TCPUDP spans TCP and
// UDP, so it covers either; every other protocol covers only itself. ProtocolAny is
// not a merged value — it matches every IP protocol — so it covers only ProtocolAny.
func coversProtocol(have, want Protocol) bool {
	if have == want {
		return true
	}
	return have == TCPUDP && (want == TCP || want == UDP)
}

// coversPorts reports whether an existing rule's port specs (have) cover a caller
// rule's (want) — the port-axis analog of coversProtocol: every port want spans
// lies inside a range have carries, so a list covers its elements and a range its
// interior, never the reverse. Both sides are compared in coalesced canonical
// form, so contiguous have ranges merge over a want range while a discrete have
// set covers only the ports it names, never the gaps between them. An empty want
// is always covered; an empty have covers only an empty want.
func coversPorts(have, want []PortRange) bool {
	hc := coalescePortRanges(have)
	for _, w := range coalescePortRanges(want) {
		covered := false
		for _, h := range hc {
			if h.Start <= w.Start && w.End <= h.End {
				covered = true
				break
			}
		}
		if !covered {
			return false
		}
	}
	return true
}

// coversProtocolRemoval reports whether two rules touch a common transport (the
// symmetric remove/move form): a TCPUDP on either side spans TCP and UDP, so it
// touches either concrete transport and vice versa.
func coversProtocolRemoval(a, b Protocol) bool {
	if a == b {
		return true
	}
	if a == TCPUDP && (b == TCP || b == UDP) {
		return true
	}
	if b == TCPUDP && (a == TCP || a == UDP) {
		return true
	}
	return false
}

// protoNeutralized returns a copy of r with its protocol cleared to TCPUDP when it
// sits on the merged tcp/udp axis, so the field compare in EqualForDedup and
// EqualForRemoval does not re-test a protocol coversProtocol has already gated.
// Every other protocol is returned unchanged, keeping matchFields' exact protocol
// equality for rules that never merge.
func (r *Rule) protoNeutralized() *Rule {
	if !onProtocolAxis(r.Proto) {
		return r
	}
	c := *r
	c.Proto = TCPUDP
	return &c
}

// portsNeutralized returns a copy of r with both port axes cleared, so the field
// compare in covers does not re-test an axis coversPorts has already gated — a
// port-list row must absorb its single-port cells. It mirrors protoNeutralized
// for the port axes.
func (r *Rule) portsNeutralized() *Rule {
	c := *r
	c.Port, c.Ports, c.SourcePort, c.SourcePorts = 0, nil, 0, nil
	return &c
}

// onProtocolAxis reports whether a protocol participates in the tcp/udp merge:
// the two concrete transports and their merged TCPUDP form.
func onProtocolAxis(p Protocol) bool {
	return p == TCP || p == UDP || p == TCPUDP
}

// splitDualRowDirection returns the rule a backend must re-add after deleting one
// direction of a genuine DirAny row — a single stored object covering both the
// input and output directions — to satisfy a concrete-direction removal: the
// surviving opposite-direction rule, materialized in its natural frame. It mirrors
// splitDualRow for the direction axis. It returns nil when no split applies: the
// matched row is itself a concrete direction (it removes only itself, its twin
// living in a separate physical row), or the target is direction-agnostic
// (DirAny/DirForward, so the whole rule is meant to go). Backends whose model
// cannot express the surviving single-direction rule reject the removal with
// ErrUnsupported instead of calling this.
func splitDualRowDirection(matched, target *Rule) *Rule {
	if matched.Direction != DirAny {
		return nil
	}
	switch target.Direction {
	case DirInput:
		// The input cell is removed; the output cell survives, in its natural
		// outbound frame (the stored DirAny row is inbound-framed).
		s := matched.directionSwapped()
		s.Direction = DirOutput
		return s
	case DirOutput:
		// The output cell is removed; the input cell survives unchanged in frame.
		s := *matched
		s.Direction = DirInput
		return &s
	default:
		return nil
	}
}

// dirAnyInputFallback maps a DirAny rule to its input half on a backend that has no
// output concept (Capabilities().Output is false), where the two directions cannot
// be distinguished: a both-directions rule degrades to an input rule rather than
// being rejected. Such a backend applies it at the top of AddRule/RemoveRule. The
// input half keeps every field (DirAny is authored in the inbound frame), only the
// direction changes. On an output-capable backend DirAny is fanned out via
// expandDirections instead, so a non-DirAny rule — or a rule on a backend that does
// distinguish output — is returned unchanged.
func dirAnyInputFallback(r *Rule, outputSupported bool) *Rule {
	if r.Direction == DirAny && !outputSupported {
		in := *r
		in.Direction = DirInput
		return &in
	}
	return r
}

// checkICMPType reports an ICMP type set on a non-ICMP rule, which is
// meaningless. Backends that honor ICMPType call it to reject such a rule.
func (r *Rule) checkICMPType() error {
	if r.ICMPType != nil && !r.Proto.IsICMP() {
		return fmt.Errorf("an icmp type requires the icmp or icmpv6 protocol")
	}
	return nil
}

// CheckExpandedProtocol reports a TCPUDP rule reaching a row-level marshaller.
// TCPUDP is a merged, logical protocol: a backend with no both-transports form fans
// it into a tcp row and a udp row with expandProtocols before marshalling, so a
// TCPUDP rule arriving here means that fan-out was skipped. Backends whose native
// syntax does carry both transports in one row (nftables' `meta l4proto { tcp, udp }`)
// do not call it.
func (r *Rule) CheckExpandedProtocol() error {
	if r.Proto == TCPUDP {
		return fmt.Errorf("the tcpudp protocol matches two transports and must be expanded to a tcp and a udp rule")
	}
	return nil
}

// validate reports whether the filter rule is well formed independent of any
// backend, mirroring NATRule.validate. Every backend's entry points call it first
// so a fundamentally malformed rule fails uniformly: an ICMP type set on a
// non-ICMP protocol, a port match with no port-carrying transport, or an
// interface bound to the side its direction cannot see. It holds only checks
// every backend shares; a backend-specific limit lives in that backend's
// validateRule.
func (r *Rule) validate() error {
	if err := r.checkICMPType(); err != nil {
		return err
	}
	// A port match requires a concrete port-carrying transport (tcp/udp/sctp); the
	// allowed set narrows per backend, but no backend can match a port with none.
	if r.PortNeedsConcreteProtocol() {
		return fmt.Errorf("a port requires a concrete transport protocol")
	}
	// An interface match must sit on the side the rule's direction can observe: a
	// packet an input rule matches has not yet been routed to an outgoing
	// interface, and one an output rule matches never arrived on an incoming one.
	// The forward direction sees both, so it accepts either, and the check is
	// strict on IsInput/IsOutput so a DirAny rule — authored in the inbound frame
	// and swapped per direction by expandDirections — is judged on its concrete
	// halves. Backends that cannot express an interface at all reject any
	// interface match separately.
	if r.IsOutput() && r.InInterface != "" {
		return fmt.Errorf("an input interface cannot be matched on an output rule")
	}
	if r.IsInput() && r.OutInterface != "" {
		return fmt.Errorf("an output interface cannot be matched on an input rule")
	}
	return nil
}

// numberByDirection assigns each rule a 1-based Number within its direction
// (input, output or forward), in slice order. Backends whose input, output and
// forward chains are ordered independently (iptables, nftables) number rules
// this way so a rule's Number matches the InsertRule/MoveRule position for its
// chain. A DirAny rule counts in the input bucket — its Number reflects the input
// chain, as a FamilyAny rule's Number reflects the IPv4 chain. It is derived on
// read and, like HasPrefix, ignored on add and not part of rule identity.
func numberByDirection(rules []*Rule) {
	var in, out, fwd int
	for _, r := range rules {
		switch r.Direction {
		case DirOutput:
			out++
			r.Number = out
		case DirForward:
			fwd++
			r.Number = fwd
		default:
			// DirInput and DirAny both number in the input chain.
			in++
			r.Number = in
		}
	}
}

// numberSequential assigns each rule a 1-based Number in slice order, for a backend
// that evaluates all its filter rules as one ordered list whose position spans
// directions (pf's anchor, ufw's numbered list).
func numberSequential(rules []*Rule) {
	for i, r := range rules {
		r.Number = i + 1
	}
}

// NATKind is the kind of network address translation a NATRule performs.
type NATKind uint8

const (
	// NATInvalid is the zero value of NATKind, meaning no translation; it is
	// rejected when authoring a NAT rule.
	NATInvalid NATKind = iota
	// DNAT rewrites the destination of matching inbound packets to ToAddress
	// (and ToPort when set) — a classic port-forward to another host.
	DNAT
	// Redirect sends matching inbound packets to a port on the local host
	// (ToPort). It is destination NAT to this machine and takes no ToAddress.
	Redirect
	// SNAT rewrites the source of matching outbound packets to the fixed
	// ToAddress.
	SNAT
	// Masquerade rewrites the source of matching outbound packets to the
	// address of the outgoing interface, chosen dynamically at send time.
	Masquerade
)

// String returns the canonical lower-case name of the NAT kind.
func (k NATKind) String() string {
	switch k {
	case DNAT:
		return "dnat"
	case Redirect:
		return "redirect"
	case SNAT:
		return "snat"
	case Masquerade:
		return "masquerade"
	}
	return "invalid"
}

// ParseNATKind parses a NAT-kind token (case-insensitive), accepting only the
// concrete kinds NATKind.String emits. The sentinel "invalid" (NATInvalid) is
// rejected, mirroring ParseAction, so callers cannot author a NAT rule with no
// real kind; backup decoding round-trips it separately in NATKind.UnmarshalJSON.
func ParseNATKind(s string) (NATKind, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "dnat":
		return DNAT, nil
	case "redirect":
		return Redirect, nil
	case "snat":
		return SNAT, nil
	case "masquerade":
		return Masquerade, nil
	}
	return 0, fmt.Errorf("unknown nat kind %q", s)
}

// isSource reports whether the kind performs source NAT (applied to outbound
// traffic in the postrouting stage) as opposed to destination NAT (inbound,
// prerouting).
func (k NATKind) isSource() bool {
	return k == SNAT || k == Masquerade
}

// A NATRule describes a network-address-translation rule: a port-forward
// (DNAT/Redirect) applied to inbound traffic, or source NAT (SNAT/Masquerade)
// applied to outbound traffic. NAT rules are managed separately from filter
// Rules through the Manager's NAT methods.
type NATRule struct {
	// Kind is the translation to perform.
	Kind NATKind
	// Family is the IP family the rule targets. FamilyAny is resolved from the
	// translation target or a matched address when left unset.
	Family Family
	// Proto is the network protocol the rule matches.
	Proto Protocol
	// Interface matches the inbound interface for DNAT/Redirect and the
	// outbound interface for SNAT/Masquerade. Empty means any interface.
	Interface string
	// Source matches the packet's source address or CIDR, with the same
	// semantics as Rule.Source. Empty matches any source.
	Source string
	// Destination matches the packet's destination address or CIDR, with the
	// same semantics as Rule.Destination. Empty matches any destination.
	Destination string
	// Port is the single destination port the rule matches; Ports takes
	// precedence when non-empty.
	Port uint16
	// Ports is a list of destination port ranges the rule matches.
	Ports []PortRange
	// ToAddress is the translation target: the new destination for DNAT, the
	// new source for SNAT. It is empty for Redirect and Masquerade.
	ToAddress string
	// ToPort is the translation target port for DNAT/Redirect (0 leaves the
	// port unchanged). It is unused for SNAT/Masquerade.
	ToPort uint16
	// HasPrefix reports whether the rule carries the library's configured
	// prefix, mirroring Rule.HasPrefix. It is derived on read and purely
	// informational.
	HasPrefix bool
	// Number is the rule's 1-based position within its nat chain, populated by
	// GetNATRules on backends that advertise Capabilities().RuleOrdering. It
	// mirrors the position argument of InsertNATRule and MoveNATRule.
	Number int
	// table records the container a container backend read this NAT rule from;
	// it backs HasPrefix.
	table string
}

// PortSpecs returns the rule's matched destination ports as a normalized list.
func (r *NATRule) PortSpecs() []PortRange {
	return portSpecsFor(r.Port, r.Ports)
}

// HasPorts reports whether the rule matches on any destination port.
func (r *NATRule) HasPorts() bool {
	return r.Port != 0 || len(r.Ports) > 0
}

// HasPortSet reports whether the rule matches more than a single discrete port.
func (r *NATRule) HasPortSet() bool {
	specs := r.PortSpecs()
	if len(specs) > 1 {
		return true
	}
	return len(specs) == 1 && specs[0].Start != specs[0].End
}

// impliedFamily returns the family the rule effectively targets, inferring it
// from the translation, destination or source address when unspecified.
func (r *NATRule) impliedFamily() Family {
	if r.Family != FamilyAny {
		return r.Family
	}
	for _, a := range []string{r.ToAddress, r.Destination, r.Source} {
		if f := familyOfAddr(a); f != FamilyAny {
			return f
		}
	}
	return FamilyAny
}

// expandNATFamilies returns the concrete-family rows a NAT rule materializes
// into: itself when it already targets one family, or an IPv4 row plus an IPv6
// row when it targets both. It is the NAT analog of expandFamilies.
func expandNATFamilies(r *NATRule) []*NATRule {
	if r.impliedFamily() != FamilyAny {
		return []*NATRule{r}
	}
	v4, v6 := *r, *r
	v4.Family, v6.Family = IPv4, IPv6
	return []*NATRule{&v4, &v6}
}

// filterNATFamiliesIPv6 returns the expandNATFamilies rows narrowed to the
// families the backend enforces, the NAT analog of filterFamiliesIPv6: with
// ipv6Enabled false, the IPv6 row of a family-agnostic rule is dropped rather
// than written as a line the backend would never enforce. A row already pinned
// to a concrete family keeps it, IPv6 included, so Restore can reproduce a
// snapshot verbatim.
func filterNATFamiliesIPv6(ipv6Enabled bool, r *NATRule) []*NATRule {
	rows := expandNATFamilies(r)
	if ipv6Enabled || len(rows) == 1 {
		return rows
	}
	kept := make([]*NATRule, 0, 1)
	for _, row := range rows {
		if row.Family != IPv6 {
			kept = append(kept, row)
		}
	}
	return kept
}

// validate reports whether the rule is well formed for its kind. It is called
// by every backend before marshaling so an ill-formed rule fails uniformly.
func (r *NATRule) validate() error {
	switch r.Kind {
	case DNAT:
		if r.ToAddress == "" {
			return fmt.Errorf("dnat requires a translation address")
		}
	case Redirect:
		if r.ToAddress != "" {
			return fmt.Errorf("redirect translates to a local port, not an address")
		}
		if r.ToPort == 0 {
			return fmt.Errorf("redirect requires a translation port")
		}
	case SNAT:
		if r.ToAddress == "" {
			return fmt.Errorf("snat requires a translation address")
		}
	case Masquerade:
		if r.ToAddress != "" || r.ToPort != 0 {
			return fmt.Errorf("masquerade takes no translation target")
		}
	default:
		return fmt.Errorf("invalid nat kind")
	}
	// TCPUDP is a multi-state, logical protocol with no NAT form: a translation is applied
	// per transport, and no backend's NAT syntax carries both in one rule. The filter
	// path fans TCPUDP out with expandProtocols; NAT has no such fan-out, so reject it
	// here rather than let a backend emit a `tcpudp` protocol token. A caller wanting
	// both transports translated adds a tcp rule and a udp rule.
	if r.Proto == TCPUDP {
		return fmt.Errorf("nat rules take a single transport; add a tcp rule and a udp rule: %w", ErrUnsupportedNAT)
	}
	if portNeedsConcreteProtocol(r.Port, r.Ports, r.Proto) {
		return fmt.Errorf("a port requires a tcp or udp protocol")
	}
	// A translation port (DNAT/Redirect ToPort) is only valid when the rule
	// carries a port-bearing protocol: iptables' DNAT/REDIRECT/SNAT targets and
	// nft's dnat/redirect reject a target port without tcp/udp/sctp. Redirect
	// always sets ToPort, so this also guards a bare Redirect left ProtocolAny.
	if r.ToPort != 0 && !r.Proto.HasPorts() {
		return fmt.Errorf("a translation port requires a tcp or udp protocol")
	}
	return nil
}

// EqualBase reports whether two NAT rules describe the same translation and
// match, ignoring the IP family (mirroring Rule.EqualBase). Backends use it to
// deduplicate and remove rules regardless of a FamilyAny/concrete distinction.
func (r *NATRule) EqualBase(o *NATRule) bool {
	if r.Kind != o.Kind || r.Proto != o.Proto {
		return false
	}
	if r.Interface != o.Interface || !addrEqual(r.Source, o.Source) || !addrEqual(r.Destination, o.Destination) {
		return false
	}
	if !portRangesEqual(r.PortSpecs(), o.PortSpecs()) {
		return false
	}
	// ToAddress is compared through addrEqual, like Source/Destination: a backend
	// re-spells the translation target on read (IPv6 zero-compression/case, a /32
	// host prefix), so a byte-for-byte compare would fail to dedup an existing NAT
	// rule and RemoveNATRule would fail to find it.
	return addrEqual(r.ToAddress, o.ToAddress) && r.ToPort == o.ToPort
}

// Equal reports whether two NAT rules are the same, including the IP family.
// Family is compared through impliedFamily so a FamilyAny rule matches the
// concrete family a backend stores it under (mirroring Rule.Equal).
func (r *NATRule) Equal(o *NATRule) bool {
	return r.impliedFamily() == o.impliedFamily() && r.EqualBase(o)
}

// EqualForDedup is the NAT-rule add guard mirroring Rule.EqualForDedup: the same
// base translation, and the receiver's family covers o's.
func (r *NATRule) EqualForDedup(o *NATRule) bool {
	return r.Covers(o)
}

// Covers reports whether the receiver's coverage contains o's, mirroring Rule.Covers
// for NAT rules. A FamilyAny rule covers either family and a concrete one covers
// only itself; a match-port list or range covers the ports it contains. NAT has no
// direction axis and a translation applies per transport, so family and ports are
// the only axes a NAT rule spans.
func (r *NATRule) Covers(o *NATRule) bool {
	return coversFamily(r.impliedFamily(), o.impliedFamily()) &&
		coversPorts(r.PortSpecs(), o.PortSpecs()) &&
		r.portsNeutralized().EqualBase(o.portsNeutralized())
}

// portsNeutralized returns a copy of r with its match ports cleared, so the field
// compare in Covers does not re-test an axis coversPorts has already gated. It
// mirrors Rule.portsNeutralized.
func (r *NATRule) portsNeutralized() *NATRule {
	c := *r
	c.Port, c.Ports = 0, nil
	return &c
}

// CoveredBy reports whether every concrete NAT rule the receiver spans is covered by
// at least one rule in rules, mirroring Rule.CoveredBy. A FamilyAny receiver requires
// both families to be covered, whether by one FamilyAny rule or by an IPv4 rule and
// an IPv6 rule; a match-port list requires every port to be covered, whether by one
// list rule or by a row per port on a backend that fans lists out.
func (r *NATRule) CoveredBy(rules []*NATRule) bool {
	for _, cell := range r.cells() {
		covered := false
		for _, have := range rules {
			if have.Covers(cell) {
				covered = true
				break
			}
		}
		if !covered {
			return false
		}
	}
	return true
}

// cells returns the concrete NAT rules the receiver spans: the cross product of
// its family and match-port expansions, the NAT analog of Rule.cells.
func (r *NATRule) cells() []*NATRule {
	fams := []*NATRule{r}
	if r.impliedFamily() == FamilyAny {
		v4, v6 := *r, *r
		v4.Family, v6.Family = IPv4, IPv6
		fams = []*NATRule{&v4, &v6}
	}
	var out []*NATRule
	for _, fam := range fams {
		out = append(out, expandNATPorts(fam)...)
	}
	return out
}

// EqualForRemoval is the NAT-rule remove guard mirroring Rule.EqualForRemoval:
// the same base translation, and o's family may touch the receiver row's.
func (r *NATRule) EqualForRemoval(o *NATRule) bool {
	ft, fr := o.impliedFamily(), r.impliedFamily()
	return (ft == FamilyAny || fr == FamilyAny || ft == fr) && r.EqualBase(o)
}

// numberNATByChain assigns each NAT rule a 1-based Number within its nat chain —
// prerouting for destination NAT, postrouting for source NAT — matching the
// InsertNATRule/MoveNATRule position on chain-ordered backends (iptables, nftables).
func numberNATByChain(rules []*NATRule) {
	var pre, post int
	for _, r := range rules {
		if r.Kind.isSource() {
			post++
			r.Number = post
		} else {
			pre++
			r.Number = pre
		}
	}
}

// numberNATSequential assigns each NAT rule a 1-based Number in slice order, for a
// backend that evaluates its translation rules as one ordered list (pf).
//
//nolint:unused // only the pf backend needs it, and the authoritative `unused` run is GOOS=linux.
func numberNATSequential(rules []*NATRule) {
	for i, r := range rules {
		r.Number = i + 1
	}
}

// splitNATDualRow is splitDualRow's NAT analog: the copy of a genuine
// dual-family NAT row (a single stored translation with no family pin) that a
// backend re-adds after deleting it for a concrete-family removal, pinned to
// the family the caller did NOT target. It returns nil when no split applies.
// Family is the only axis a NAT rule spans.
func splitNATDualRow(matched, target *NATRule) *NATRule {
	tf := target.impliedFamily()
	if tf == FamilyAny || matched.impliedFamily() != FamilyAny {
		return nil
	}
	opp := *matched
	opp.Family = oppositeFamily(tf)
	return &opp
}

// Backup is a portable snapshot of the state a backend manages. It can be used
// to restore that state later via Manager.Restore.
type Backup struct {
	// Filter rules saved in the order they were returned by GetRules.
	Rules []*Rule
	// NAT rules saved in the order they were returned by GetNATRules.
	NATRules []*NATRule
	// DefaultPolicy is the per-direction default action captured at backup time,
	// on backends that advertise Capabilities().DefaultPolicy; nil otherwise. A
	// direction the backend does not expose is ActionInvalid and is left unchanged
	// on Restore. Capturing it lets Restore re-assert a restrictive policy (e.g. a
	// default DROP) rather than silently inherit the restore host's current one.
	DefaultPolicy *DefaultPolicy
	// AddressSets are the named address sets (ipsets, nftables sets, pf tables) the
	// backend manages, captured on backends that advertise
	// Capabilities().AddressSets; nil otherwise. Restore recreates them before the
	// filter rules so a set-referencing rule (@set) resolves on a host that does
	// not yet have the set.
	AddressSets []*AddressSet
}

// Capabilities advertises which features a backend can express. It lets a
// caller detect support before trial-and-error: a false field means the
// corresponding operation returns an unsupported error (or, for RuleCounters,
// simply reports zero).
type Capabilities struct {
	// Output is true when the backend distinguishes input from output rules.
	Output bool
	// Forward is true when the backend can express a rule in the forward (routing)
	// chain. A false Forward means a rule with Direction DirForward is rejected
	// with ErrUnsupportedForward.
	Forward bool
	// Zones is true when the backend maps interfaces to zones.
	Zones bool
	// Priority is true when per-rule priority is honored.
	Priority bool
	// IPv6 is true when the backend manages IPv6 rules at all. It is host-resolved
	// on the backends whose own configuration can disable IPv6 (csf, apf) or whose
	// packaging can omit it (iptables); a false IPv6 means every IPv6 rule shape,
	// ICMPv6 included, is unmanageable, not merely rejected on one axis. (IPv4 is
	// managed by every backend, so it is not advertised as a capability.)
	IPv6 bool
	// PortPair is true when a source-port match can be combined with a
	// destination-port match in one rule. A false PortPair means such a rule is
	// rejected with ErrUnsupportedSourcePort (a firewalld rich rule carries a
	// single port element).
	PortPair bool
	// ConnState is true when connection-tracking state can be matched.
	ConnState bool
	// InterfaceMatch is true when a rule can bind to a per-rule interface (as
	// opposed to a zone).
	InterfaceMatch bool
	// Logging is true when per-rule packet logging is honored.
	Logging bool
	// RateLimit is true when per-rule rate limiting is honored.
	RateLimit bool
	// ConnLimit is true when per-rule connection limiting is honored.
	ConnLimit bool
	// NAT is true when AddNATRule/RemoveNATRule/GetNATRules are supported.
	NAT bool
	// RuleOrdering is true when InsertRule/MoveRule are supported, and when NAT is
	// also true, InsertNATRule/MoveNATRule.
	RuleOrdering bool
	// DefaultPolicy is true when GetDefaultPolicy/SetDefaultPolicy are supported.
	DefaultPolicy bool
	// RuleCounters is true when GetRules populates the Packets/Bytes fields.
	RuleCounters bool
	// AddressSets is true when the address-set methods are supported.
	AddressSets bool
	// Comments is true when a rule's Comment field round-trips: it is stored on
	// AddRule and populated by GetRules. A false Comments means the backend
	// silently ignores the Comment field.
	Comments bool
	// Negation is true when a "!"-negated Source/Destination match is honored.
	// A false Negation means such a rule is rejected with ErrUnsupported (WFP
	// has no negated address condition).
	Negation bool
	// RejectAction is true when the Reject action — refuse with an error
	// response, as opposed to a silent Drop — is expressible. A false
	// RejectAction means a Reject rule is rejected with ErrUnsupported (WFP
	// only permits or blocks).
	RejectAction bool
	// FamilyWithoutAddress is true when a rule with a concrete Family but no
	// Source/Destination is expressible. A false value means family scoping
	// rides on addresses alone and such a rule is rejected with ErrUnsupported
	// (a WFP filter scopes family through its address conditions).
	FamilyWithoutAddress bool
	// DenyActionFromConfig is true when the backend's native deny store carries
	// no per-entry action — the firewall tool applies the deny action its own
	// config names (csf.conf DROP, conf.apf ALL_STOP). A deny added with the
	// config's action is stored natively and reads back with it; one with a
	// differing action is expressed elsewhere (the raw-iptables hook). Because
	// the native entry encodes no action, RemoveRule clears it whatever action
	// the removal target names.
	DenyActionFromConfig bool
}

// The backend type strings Manager.Type reports, one per backend. They are declared
// here beside the interface rather than beside each implementation because every
// backend lives behind a build tag for its own platform: a caller — or a test — that
// branches on mgr.Type() must be able to name any backend on any platform, not only
// the ones that compile for the host.
const (
	IPTablesType  = "iptables"
	NFTType       = "nftables"
	UFWType       = "ufw"
	FirewallDType = "firewalld"
	CSFType       = "csf"
	APFType       = "apf"
	PFType        = "pf"
	WFType        = "windows-firewall"
)

// Manager is the standard firewall manager interface.
//
// Every method that performs I/O (shelling out, D-Bus, or the Windows API)
// takes a context.Context as its first argument so callers can apply timeouts
// and cancellation. Type and Capabilities are pure and take none.
type Manager interface {
	// Type returns the manager type.
	Type() string

	// Capabilities returns the set of features this backend can express.
	Capabilities() Capabilities

	// GetZone returns the zone for the specified interface.
	GetZone(ctx context.Context, iface string) (string, error)

	// GetRules returns the existing filter rules from the zone.
	GetRules(ctx context.Context, zoneName string) ([]*Rule, error)

	// AddRule adds a rule to the zone.
	AddRule(ctx context.Context, zoneName string, rule *Rule) error

	// InsertRule adds rule at the given position. position uses 1-based indexing
	// (1 = first rule); a non-positive position is treated as 1, and a position
	// larger than the current rule count appends the rule. Backends that do not
	// support ordered rules return an error.
	InsertRule(ctx context.Context, zoneName string, position int, rule *Rule) error

	// MoveRule moves an existing rule to the given position. position uses 1-based
	// indexing; a non-positive position is treated as 1, and a position larger
	// than the current rule count moves the rule to the end. Backends that do not
	// support ordered rules return an error.
	MoveRule(ctx context.Context, zoneName string, rule *Rule, position int) error

	// RemoveRule removes a rule from the zone.
	RemoveRule(ctx context.Context, zoneName string, rule *Rule) error

	// GetNATRules returns the existing NAT rules from the zone. Backends without
	// NAT support return an unsupported error.
	GetNATRules(ctx context.Context, zoneName string) ([]*NATRule, error)

	// AddNATRule adds a NAT rule to the zone.
	AddNATRule(ctx context.Context, zoneName string, rule *NATRule) error

	// InsertNATRule adds a NAT rule at the given position within its nat chain.
	// position uses 1-based indexing (1 = first rule in that chain); a non-positive
	// position is treated as 1, and a position larger than the chain's current rule
	// count appends the rule. Backends that do not support ordered rules return an
	// error; backends without NAT support return the NAT sentinel.
	InsertNATRule(ctx context.Context, zoneName string, position int, rule *NATRule) error

	// MoveNATRule moves an existing NAT rule to the given position within its nat
	// chain. position uses 1-based indexing; a non-positive position is treated as
	// 1, and a position larger than the chain's current rule count moves the rule
	// to the end. Backends that do not support ordered rules return an error;
	// backends without NAT support return the NAT sentinel.
	MoveNATRule(ctx context.Context, zoneName string, rule *NATRule, position int) error

	// RemoveNATRule removes a NAT rule from the zone.
	RemoveNATRule(ctx context.Context, zoneName string, rule *NATRule) error

	// GetDefaultPolicy returns the default action applied to packets that match
	// no rule. A direction the backend cannot express is returned as
	// ActionInvalid. Backends that cannot manage a default policy at all return
	// an unsupported error.
	GetDefaultPolicy(ctx context.Context, zoneName string) (*DefaultPolicy, error)

	// SetDefaultPolicy sets the default action for the directions named in
	// policy. A direction left as ActionInvalid is left unchanged. Backends that
	// cannot manage a default policy return an unsupported error.
	SetDefaultPolicy(ctx context.Context, zoneName string, policy *DefaultPolicy) error

	// GetAddressSets returns the address sets managed by this backend. Backends
	// that cannot manage address sets return an unsupported error.
	GetAddressSets(ctx context.Context) ([]*AddressSet, error)

	// GetAddressSet returns a single address set by name, or an error if it does
	// not exist. Backends that cannot manage address sets return an unsupported
	// error.
	GetAddressSet(ctx context.Context, name string) (*AddressSet, error)

	// AddAddressSet creates an address set. Adding a set that already exists (by
	// name) is a no-op. Backends that cannot manage address sets return an
	// unsupported error.
	AddAddressSet(ctx context.Context, set *AddressSet) error

	// RemoveAddressSet removes an address set by name. Backends that cannot
	// manage address sets return an unsupported error.
	RemoveAddressSet(ctx context.Context, name string) error

	// AddAddressSetEntry adds an entry to the named set. Backends that cannot
	// manage address sets return an unsupported error.
	AddAddressSetEntry(ctx context.Context, name, entry string) error

	// RemoveAddressSetEntry removes an entry from the named set. Backends that
	// cannot manage address sets return an unsupported error.
	RemoveAddressSetEntry(ctx context.Context, name, entry string) error

	// Backup captures the current filter and NAT rules the manager reports, plus —
	// on backends that advertise them — the default policy and the managed address
	// sets. On container backends (nftables table, pf anchor, firewalld zone) this
	// is scoped to the library's container by construction; on tag/comment backends
	// it is the whole chain, foreign rules included. It does not filter on the
	// HasPrefix flag.
	Backup(ctx context.Context, zoneName string) (*Backup, error)

	// Restore reconciles the firewall to the contents of a Backup. The captured
	// address sets are recreated first (so a set-referencing rule resolves), then
	// existing filter and NAT rules the backend acts on are removed and the backup
	// rules added, and finally the captured default policy is re-asserted. Like Sync
	// it reconciles the actual state and does not filter on HasPrefix.
	Restore(ctx context.Context, zoneName string, backup *Backup) error

	// Reload reloads the manager to activate new rules.
	Reload(ctx context.Context) error

	// Close closes the connection to the manager.
	Close(ctx context.Context) error
}

// Sync reconciles the zone's filter rules toward desired: it removes any rule
// the backend reports that desired does not cover and adds desired rules that are
// not yet present, leaving rules already in place untouched. It reconciles the
// actual firewall state and does not filter on HasPrefix — a rule without the
// configured prefix (HasPrefix=false) is reconciled like any other, so a foreign
// rule not in desired is removed. A rule unchanged between existing and desired is
// never removed and re-added, but removal still runs as its own pass before
// additions, so a desired set that shares nothing with the existing rules is not
// applied atomically. Sync reports how many rules were added and removed.
//
// The diff is a coverage relation, not rule-for-rule equality, because GetRules
// reports the firewall's actual rows and a backend stores a rule the way its model
// allows: iptables holds a FamilyAny rule as an IPv4 row plus an IPv6 row, pf holds
// a DirAny rule as an inbound row plus an outbound row, while nftables holds either
// as one row. An existing rule is kept when every concrete cell it spans is wanted
// (Rule.CoveredBy over desired), and a desired rule is added when some cell it spans
// is not yet present (its CoveredBy over existing). On a backend that does not
// manage IPv6 (Capabilities.IPv6 false) a family-agnostic rule is compared on its
// IPv4 half alone, since that is all such a backend stores for it. Comparing this
// way keeps Sync a no-op against its own output whichever representation the
// backend chose, where plain equality would remove-and-re-add every fanned-out
// rule on each run. A rule only partially covered by desired is removed whole and
// the wanted part re-added.
// The Comment, HasPrefix and Packets/Bytes fields never affect the diff.
func Sync(ctx context.Context, mgr Manager, zoneName string, desired []*Rule) (added, removed int, err error) {
	existing, err := mgr.GetRules(ctx, zoneName)
	if err != nil {
		return 0, 0, err
	}
	caps := mgr.Capabilities()

	// Remove any existing rule desired does not fully cover. Sync reconciles the
	// actual firewall state toward desired, so any rule the backend reports and can
	// act on is fair game; backends whose mutations are scoped to a private
	// table/anchor simply no-op on rules outside it. A rule whose cells are spread
	// across several desired rules is still fully wanted and is kept.
	kept := make([]*Rule, 0, len(existing))
	for _, e := range existing {
		if e.coveredBy(desired, caps.Output, caps.IPv6) {
			kept = append(kept, e)
			continue
		}
		if err := mgr.RemoveRule(ctx, zoneName, e); err != nil {
			return added, removed, err
		}
		removed++
	}

	// Add any wanted rule that is not already present. A rule already in the
	// firewall — whoever created it — counts as present, so Sync does not add a
	// duplicate of a rule the surviving rows already cover. Queued additions count
	// as present too: adding a covered duplicate would over-count added.
	var toAdd []*Rule
	for _, d := range desired {
		if d.coveredBy(kept, caps.Output, caps.IPv6) || d.coveredBy(toAdd, caps.Output, caps.IPv6) {
			continue
		}
		toAdd = append(toAdd, d)
	}
	// Count additions as they land so the reported added stays accurate when a
	// later add errors after several have already been applied.
	for _, r := range toAdd {
		if err := mgr.AddRule(ctx, zoneName, r); err != nil {
			return added, removed, err
		}
		added++
	}
	return added, removed, nil
}
