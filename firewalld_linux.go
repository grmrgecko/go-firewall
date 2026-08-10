package firewall

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	firewalld "github.com/grmrgecko/go-firewalld"
)

// FirewallD manages a firewalld instance over D-Bus, mapping the Manager
// interface onto firewalld's zones, rich rules, and ipsets.
type FirewallD struct {
	Conn *firewalld.Conn
	// rulePrefix is accepted for a consistent constructor signature across
	// backends. firewalld organizes rules into zones rather than a private
	// namespace, so the prefix is not applied to individual rules.
	rulePrefix string
}

// fwICMPv4Types maps firewalld's IPv4 icmp-type names to their numeric ICMP type,
// covering the stock firewalld icmptype set. A rich rule's icmp-type element
// carries the name; the model carries the number, so these tables translate
// between the two. Only types firewalld names as a plain type match are listed —
// a number absent here cannot be expressed and marshalling reports it.
var fwICMPv4Types = map[string]uint8{
	"echo-reply":              0,
	"destination-unreachable": 3,
	"source-quench":           4,
	"redirect":                5,
	"echo-request":            8,
	"router-advertisement":    9,
	"router-solicitation":     10,
	"time-exceeded":           11,
	"parameter-problem":       12,
	"timestamp-request":       13,
	"timestamp-reply":         14,
}

// fwICMPv6Types maps firewalld's ICMPv6 icmp-type names to their numeric type.
// The same name (e.g. echo-request) resolves to a different number than IPv4, so
// the family selects the table.
var fwICMPv6Types = map[string]uint8{
	"destination-unreachable": 1,
	"packet-too-big":          2,
	"time-exceeded":           3,
	"parameter-problem":       4,
	"echo-request":            128,
	"echo-reply":              129,
	"router-solicitation":     133,
	"router-advertisement":    134,
	"neighbour-solicitation":  135,
	"neighbour-advertisement": 136,
	"redirect":                137,
}

// NewFirewallD connects to firewalld and returns a manager, or an error when
// firewalld cannot be reached.
func NewFirewallD(ctx context.Context, rulePrefix string) (*FirewallD, error) {
	// Attempt to connect, and failure means no firewalld.
	conn, err := firewalld.Connect(ctx)
	if err != nil {
		return nil, err
	}
	_, err = conn.DefaultZone(ctx)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("firewalld cannot be reached: %s", err)
	}
	return &FirewallD{Conn: conn, rulePrefix: rulePrefix}, nil
}

// Type returns the backend identifier for firewalld.
func (f *FirewallD) Type() string {
	return FirewallDType
}

// Capabilities reports which optional features this backend supports.
func (f *FirewallD) Capabilities() Capabilities {
	return Capabilities{
		Output:   false,
		Zones:    true,
		Priority: true,
		IPv6:     true,
		// A rich rule carries a single port element, so a source-port match
		// cannot be combined with a destination-port match in one rule.
		PortPair:             false,
		ConnState:            false,
		InterfaceMatch:       false,
		Logging:              true,
		RateLimit:            true,
		ConnLimit:            false,
		NAT:                  true,
		RuleOrdering:         false,
		DefaultPolicy:        true,
		RuleCounters:         false,
		AddressSets:          true,
		Negation:             true,
		RejectAction:         true,
		FamilyWithoutAddress: true,
	}
}

// GetZone returns the firewalld zone bound to the interface, falling back to the
// default zone when the interface is unbound.
func (f *FirewallD) GetZone(ctx context.Context, iface string) (zoneName string, err error) {
	// Ask firewalld directly which permanent zone the interface is bound to.
	// This returns the zone id (e.g. "public"), which is what the other backend
	// methods expect to pass back into Permanent().Zone. An empty result or an
	// error means the interface is not bound to a zone, leaving the default
	// zone below.
	zoneName, err = f.Conn.Permanent().ZoneOfInterface(ctx, iface)
	if err == nil && zoneName != "" {
		return zoneName, nil
	}

	// An unbound interface belongs to the default zone.
	defaultZone, derr := f.Conn.DefaultZone(ctx)
	if derr == nil && defaultZone != "" {
		return defaultZone, nil
	}

	return "", fmt.Errorf("unable to find zone")
}

// icmpTypeTable selects the IPv4 or IPv6 name/number table by family.
func (f *FirewallD) icmpTypeTable(isV6 bool) map[string]uint8 {
	if isV6 {
		return fwICMPv6Types
	}
	return fwICMPv4Types
}

// icmpTypeNumber returns the numeric ICMP type for a firewalld icmp-type name in
// the given family, and whether the name is known.
func (f *FirewallD) icmpTypeNumber(isV6 bool, name string) (uint8, bool) {
	n, ok := f.icmpTypeTable(isV6)[strings.ToLower(name)]
	return n, ok
}

// splitRichRuleFields tokenizes a firewalld rich rule on whitespace while
// keeping a double-quoted value as a single token, quotes included (so the
// existing trimQuotes callers still work). firewalld quotes rich-rule attribute
// values, and some — a log prefix, an address — legitimately contain spaces;
// plain strings.Fields would split those and break the parse.
func (f *FirewallD) splitRichRuleFields(s string) []string {
	var tokens []string
	var b strings.Builder
	inQuote := false
	flush := func() {
		if b.Len() > 0 {
			tokens = append(tokens, b.String())
			b.Reset()
		}
	}
	for _, r := range s {
		switch {
		case r == '"':
			inQuote = !inQuote
			b.WriteRune(r)
		case (r == ' ' || r == '\t') && !inQuote:
			flush()
		default:
			b.WriteRune(r)
		}
	}
	flush()
	return tokens
}

// UnmarshalRichRule takes a rich-rule string and returns a parsed rule for supported rules.
func (f *FirewallD) UnmarshalRichRule(richRule string) (r *Rule, err error) {
	// Setup new rule.
	r = new(Rule)

	// Get tokens for rule. splitRichRuleFields keeps a quoted value with spaces
	// as a single token (see its doc).
	tokens := f.splitRichRuleFields(richRule)
	if len(tokens) == 0 {
		return nil, fmt.Errorf("empty rule")
	}

	// Confirm this is a rich rule.
	if tokens[0] != "rule" {
		return nil, fmt.Errorf("invalid rule format")
	}

	// Process the rule.
	for i := 1; i < len(tokens); i++ {
		// Check the token type and parse.
		if strings.HasPrefix(tokens[i], "family=") {
			// Family can only be IPv4 or IPv6.
			family := trimQuotes(strings.TrimPrefix(tokens[i], "family="))
			if strings.EqualFold(family, "ipv4") {
				r.Family = IPv4
			} else if strings.EqualFold(family, "ipv6") {
				r.Family = IPv6
			} else {
				return nil, fmt.Errorf("invalid family value")
			}
		} else if strings.HasPrefix(tokens[i], "priority=") {
			// Parse the priority int.
			priority := trimQuotes(strings.TrimPrefix(tokens[i], "priority="))
			p, err := strconv.Atoi(priority)
			if err != nil {
				return nil, err
			}
			r.Priority = p
		} else if tokens[i] == "source" {
			// The source must contain at least one value after.
			i++
			if i >= len(tokens) {
				return nil, fmt.Errorf("missing source value")
			}

			// It is possible to define as a NOT match by adding NOT.
			not := false
			if strings.EqualFold(tokens[i], "NOT") {
				not = true

				// Check that there is a source defined after the not.
				i++
				if i >= len(tokens) {
					return nil, fmt.Errorf("missing source value")
				}
			}

			// Check the source value, to parse out the type.
			source := tokens[i]
			if strings.HasPrefix(source, "address=") {
				address := trimQuotes(strings.TrimPrefix(source, "address="))
				if not {
					r.Source = "!" + address
				} else {
					r.Source = address
				}
			} else if strings.HasPrefix(source, "mac=") {
				mac := trimQuotes(strings.TrimPrefix(source, "mac="))
				if not {
					r.Source = "!" + mac
				} else {
					r.Source = mac
				}
			} else if strings.HasPrefix(source, "ipset=") {
				ipset := trimQuotes(strings.TrimPrefix(source, "ipset="))
				if not {
					r.Source = "!" + ipset
				} else {
					r.Source = ipset
				}
			} else { // If the source is not defined on a none key=value, source is invalid.
				return nil, fmt.Errorf("the source argument has no type defined")
			}
		} else if tokens[i] == "destination" {
			// The destination must contain at least one value after.
			i++
			if i >= len(tokens) {
				return nil, fmt.Errorf("missing destination value")
			}

			// It is possible to define as a NOT match by adding NOT.
			not := false
			if strings.EqualFold(tokens[i], "NOT") {
				not = true

				// Check that there is a destination defined after the not.
				i++
				if i >= len(tokens) {
					return nil, fmt.Errorf("missing destination value")
				}
			}

			// Parse the destination, which firewalld expresses as either an address
			// or an ipset (mirroring the source grammar). firewalld has no output
			// chain, so a destination element is an inbound-frame destination match,
			// not a direction signal — the write side stores every rule in the
			// inbound frame (see AddRule).
			if strings.HasPrefix(tokens[i], "address=") {
				address := trimQuotes(strings.TrimPrefix(tokens[i], "address="))
				if not {
					r.Destination = "!" + address
				} else {
					r.Destination = address
				}
			} else if strings.HasPrefix(tokens[i], "ipset=") {
				ipset := trimQuotes(strings.TrimPrefix(tokens[i], "ipset="))
				if not {
					r.Destination = "!" + ipset
				} else {
					r.Destination = ipset
				}
			} else {
				return nil, fmt.Errorf("the destination argument has no address or ipset defined")
			}
		} else if tokens[i] == "log" {
			// Record that the rule logs, and capture the optional prefix. Any
			// key=value qualifiers that follow (prefix="...", level="...") are
			// consumed here; only the prefix is stored, the rest are ignored.
			r.Log = true
			for i+1 < len(tokens) && strings.Contains(tokens[i+1], "=") {
				q := tokens[i+1]
				if strings.HasPrefix(q, "prefix=") {
					r.LogPrefix = trimQuotes(strings.TrimPrefix(q, "prefix="))
				}
				i++
			}
			// A limit element directly after log throttles only the logging, which
			// RateLimit cannot hold — it models a traffic limit. Reading it as one
			// would let a rewrite turn a log throttle into a traffic throttle, so
			// the rule stays unmodeled.
			if i+1 < len(tokens) && tokens[i+1] == "limit" {
				return nil, fmt.Errorf("a log-scoped limit is unsupported")
			}
		} else if tokens[i] == "limit" {
			// A rule-level rate limit: limit value="N/unit" where unit is one of
			// s/m/h/d. Parse it into the rule's RateLimit.
			i++
			if i >= len(tokens) {
				return nil, fmt.Errorf("missing limit value")
			}
			if !strings.HasPrefix(tokens[i], "value=") {
				return nil, fmt.Errorf("the limit element has no value")
			}
			val := trimQuotes(strings.TrimPrefix(tokens[i], "value="))
			num, unitStr, ok := strings.Cut(val, "/")
			if !ok {
				return nil, fmt.Errorf("invalid limit value %q", val)
			}
			n, err := strconv.ParseUint(strings.TrimSpace(num), 10, 32)
			if err != nil {
				return nil, fmt.Errorf("invalid limit value %q", val)
			}
			unit, err := ParseRateUnit(unitStr)
			if err != nil {
				return nil, err
			}
			r.RateLimit = &RateLimit{Rate: uint(n), Unit: unit}
		} else if tokens[i] == "audit" {
			// Ignore audit element.
		} else if tokens[i] == "port" {
			// The port must contain the port and protocol definitions.
			if i+2 >= len(tokens) {
				return nil, fmt.Errorf("missing port parameters")
			}
			i++

			// Parse the port parameter, which may be a single port or a dash
			// range such as "1000-2000".
			if strings.HasPrefix(tokens[i], "port=") {
				port := trimQuotes(strings.TrimPrefix(tokens[i], "port="))
				pr, err := ParsePortRange(port)
				if err != nil {
					return nil, fmt.Errorf("the port argument %s is invalid", tokens[i])
				}
				if pr.Start == pr.End {
					r.Port = pr.Start
				} else {
					r.Ports = []PortRange{pr}
				}
			} else {
				return nil, fmt.Errorf("the port element has no defined port")
			}
			i++

			// Parse the protocol.
			if strings.HasPrefix(tokens[i], "protocol=") {
				proto := trimQuotes(strings.TrimPrefix(tokens[i], "protocol="))
				r.Proto = GetProtocol(proto)
			} else {
				return nil, fmt.Errorf("the port element has no defined protocol")
			}
			// firewalld allows a port on a protocol this library cannot model
			// (e.g. dccp, which GetProtocol widens to ProtocolAny) or on a modeled
			// but portless protocol. Such a rule cannot round-trip — MarshalRichRule
			// rejects a port without a concrete tcp/udp/sctp protocol — so reject it
			// here, matching the zone-port path, so GetRules skips it rather than
			// surfacing a rule Restore could never re-add.
			if !r.Proto.HasPorts() {
				return nil, fmt.Errorf("the port element uses a protocol that cannot carry a port")
			}
		} else if tokens[i] == "source-port" {
			// A source-port element mirrors the port element but matches the
			// packet's source port: source-port port="1024" protocol="tcp".
			if i+2 >= len(tokens) {
				return nil, fmt.Errorf("missing source-port parameters")
			}
			i++

			// Parse the source port, which may be a single port or a dash range.
			if strings.HasPrefix(tokens[i], "port=") {
				port := trimQuotes(strings.TrimPrefix(tokens[i], "port="))
				pr, err := ParsePortRange(port)
				if err != nil {
					return nil, fmt.Errorf("the source-port argument %s is invalid", tokens[i])
				}
				if pr.Start == pr.End {
					r.SourcePort = pr.Start
				} else {
					r.SourcePorts = []PortRange{pr}
				}
			} else {
				return nil, fmt.Errorf("the source-port element has no defined port")
			}
			i++

			// Parse the protocol.
			if strings.HasPrefix(tokens[i], "protocol=") {
				proto := trimQuotes(strings.TrimPrefix(tokens[i], "protocol="))
				r.Proto = GetProtocol(proto)
			} else {
				return nil, fmt.Errorf("the source-port element has no defined protocol")
			}
			// See the port element above: a source-port on a protocol that cannot
			// carry a port cannot round-trip, so reject rather than surface it.
			if !r.Proto.HasPorts() {
				return nil, fmt.Errorf("the source-port element uses a protocol that cannot carry a port")
			}
		} else if tokens[i] == "protocol" {
			// A bare protocol element (no port), e.g. an ICMP match:
			// protocol value="icmp" / value="ipv6-icmp".
			i++
			if i >= len(tokens) {
				return nil, fmt.Errorf("missing protocol value")
			}
			if !strings.HasPrefix(tokens[i], "value=") {
				return nil, fmt.Errorf("the protocol element has no defined value")
			}
			proto := GetProtocol(trimQuotes(strings.TrimPrefix(tokens[i], "value=")))
			if proto == ProtocolAny {
				return nil, fmt.Errorf("unsupported protocol value")
			}
			r.Proto = proto
		} else if tokens[i] == "icmp-type" {
			// An icmp-type element restricts to a single ICMP message type by
			// firewalld name, e.g. icmp-type name="echo-request". The numeric type
			// and the ICMP protocol both depend on the rule's family, which appears
			// earlier in the rule string, so r.Family is already set here. A
			// familyless icmp-type rule (foreign; firewalld applies it to both
			// families) has no single ICMP/ICMPv6 form, so it stays unmodeled
			// rather than reading back as its IPv4 half.
			i++
			if i >= len(tokens) || !strings.HasPrefix(tokens[i], "name=") {
				return nil, fmt.Errorf("the icmp-type element has no defined name")
			}
			if r.Family == FamilyAny {
				return nil, fmt.Errorf("an icmp-type element without a family is unsupported")
			}
			isV6 := r.Family == IPv6
			num, ok := f.icmpTypeNumber(isV6, trimQuotes(strings.TrimPrefix(tokens[i], "name=")))
			if !ok {
				return nil, fmt.Errorf("unsupported icmp-type name")
			}
			r.ICMPType = Ptr(num)
			if isV6 {
				r.Proto = ICMPv6
			} else {
				r.Proto = ICMP
			}
		} else if tokens[i] == "accept" {
			r.Action = Accept
		} else if tokens[i] == "reject" {
			r.Action = Reject

			// Ignore type definition for reject.
			if i+1 < len(tokens) && strings.HasPrefix(tokens[i+1], "type=") {
				i++
			}
		} else if tokens[i] == "drop" {
			r.Action = Drop
		} else {
			return nil, fmt.Errorf("the element %s is unsupported", tokens[i])
		}
	}

	// If no action provided, error.
	if r.Action == ActionInvalid {
		return nil, fmt.Errorf("no valid action was provided")
	}

	// Return the parsed rule.
	return
}

// resolveZoneName substitutes the default zone when zoneName is empty. The rest
// of go-firewall treats an empty zone as "the default" (zoneless backends ignore
// it entirely), but firewalld's permanent config interface rejects an empty zone
// name with INVALID_ZONE, so every zone-scoped method resolves it here first.
func (f *FirewallD) resolveZoneName(ctx context.Context, zoneName string) (string, error) {
	if zoneName != "" {
		return zoneName, nil
	}
	return f.Conn.DefaultZone(ctx)
}

// zonePortRules maps a firewalld zone port list (settings.Ports or SourcePorts)
// to allow rules, one per entry. source selects whether the range binds to the
// source-port or destination-port fields. A port on an unmodeled protocol (e.g.
// dccp, which GetProtocol maps to ProtocolAny) is skipped: it has no expressible
// Rule, so surfacing it would leave a rule RemoveRule and MarshalRichRule reject.
// This mirrors the protocols loop's guard.
func (f *FirewallD) zonePortRules(ports []firewalld.Port, source bool) []*Rule {
	var rules []*Rule
	for _, port := range ports {
		pr, perr := ParsePortRange(port.Port)
		if perr != nil {
			continue
		}
		proto := GetProtocol(port.Protocol)
		if !proto.HasPorts() {
			continue
		}
		rule := &Rule{Proto: proto, Action: Accept}
		switch {
		case source && pr.Start == pr.End:
			rule.SourcePort = pr.Start
		case source:
			rule.SourcePorts = []PortRange{pr}
		case pr.Start == pr.End:
			rule.Port = pr.Start
		default:
			rule.Ports = []PortRange{pr}
		}
		rules = append(rules, rule)
	}
	return rules
}

// GetRules returns the filter rules for a zone, resolving an empty zone to the default.
func (f *FirewallD) GetRules(ctx context.Context, zoneName string) (rules []*Rule, err error) {
	zoneName, err = f.resolveZoneName(ctx, zoneName)
	if err != nil {
		return
	}

	// Get the zone settings.
	settings, err := f.Conn.Permanent().Zone(zoneName).Settings(ctx)
	if err != nil {
		return
	}

	// Named services (settings.Services) have no Rule representation and are
	// intentionally not surfaced here; only ports, source ports, sources and
	// rich rules map to managed rules.

	// Add port allows to rule list. A zone port entry may be a single port or a
	// contiguous range (e.g. "49152-49215"), so parse it as a range and collapse
	// a single-port range back onto the scalar Port field.
	rules = append(rules, f.zonePortRules(settings.Ports, false)...)

	// Add bare-protocol allows (firewall-cmd --add-protocol) to the rule list.
	// firewalld stores these as a zone protocol entry rather than a rich rule, so
	// surface each recognized one as a portless-protocol rule; otherwise it is
	// invisible to Sync/Restore and can never be reconciled. An unrecognized
	// protocol has no Rule representation and is left unmanaged.
	for _, proto := range settings.Protocols {
		if p := GetProtocol(proto); p != ProtocolAny {
			rules = append(rules, &Rule{Proto: p, Action: Accept})
		}
	}

	// Add source-port allows to rule list, likewise reading a single port or a
	// contiguous range.
	rules = append(rules, f.zonePortRules(settings.SourcePorts, true)...)

	// Add source allows to rule list.
	for _, source := range settings.Sources {
		rule := &Rule{
			Source: source,
			Action: Accept,
		}
		rules = append(rules, rule)
	}

	// Parse and add rich rules.
	for _, richRule := range settings.RichRules {
		rule, err := f.UnmarshalRichRule(richRule)
		if err != nil {
			continue
		}
		rules = append(rules, rule)
	}

	// Every entry above is reported as firewalld stores it. A rich rule with no
	// `family=` attribute, and a zone port or source, cover both IP families as one
	// object and read back as FamilyAny on their own; a rich rule's port element
	// carries exactly one protocol, so a both-transports rule is two entries and is
	// reported as two rules.

	// firewalld isolates rules by zone; this read is already scoped to a single
	// zone, so every rule read here lives in zoneName — record the zone and flag it
	// as carrying the prefix.
	for _, r := range rules {
		r.table = zoneName
		r.HasPrefix = true
	}
	return
}

// icmpTypeName returns the firewalld icmp-type name for a numeric ICMP type in
// the given family, and whether the type is expressible as a rich rule element.
func (f *FirewallD) icmpTypeName(isV6 bool, typ uint8) (string, bool) {
	for name, n := range f.icmpTypeTable(isV6) {
		if n == typ {
			return name, true
		}
	}
	return "", false
}

// protoValue returns the protocol name firewalld's `protocol value=` element
// expects. ICMPv6 is named `ipv6-icmp` in /etc/protocols.
func (f *FirewallD) protoValue(p Protocol) string {
	if p == ICMPv6 {
		return "ipv6-icmp"
	}
	return p.String()
}

// rateUnit maps a RateUnit to the single-letter time unit a firewalld rich
// rule's `limit value="N/unit"` expects (s/m/h/d).
func (f *FirewallD) rateUnit(u RateUnit) string {
	switch u {
	case PerMinute:
		return "m"
	case PerHour:
		return "h"
	case PerDay:
		return "d"
	}
	return "s"
}

// MarshalRichRule encodes a rule into a firewalld rich-rule string.
func (f *FirewallD) MarshalRichRule(r *Rule) (richRule string, err error) {
	// firewalld's zone/rich-rule model has no forward chain, so a forward rule
	// cannot be expressed.
	if r.IsForward() {
		return "", unsupportedForward("firewalld")
	}
	// A port in a rich rule requires a concrete protocol; `protocol="any"` is
	// not valid, so reject rather than emit a rule firewalld will refuse.
	if r.PortNeedsConcreteProtocol() {
		return "", fmt.Errorf("a port requires a tcp, udp or sctp protocol")
	}

	// Features a rich rule cannot express are rejected rather than dropped. A
	// rich rule has no conntrack-state or per-rule interface match (interfaces
	// bind to zones instead). A port list has no single rich-rule form, but
	// AddRule/RemoveRule fan one into a row per spec with expandPorts before this
	// row-level marshaller runs, so only a single spec per axis ever reaches here.
	if r.State != 0 {
		return "", fmt.Errorf("firewalld does not support connection-state matching in a rich rule: %w", ErrUnsupportedState)
	}
	if r.InInterface != "" || r.OutInterface != "" {
		return "", fmt.Errorf("firewalld binds interfaces to zones, not individual rules: %w", ErrUnsupportedInterface)
	}
	// A rich rule carries only one port element, so a destination port and a
	// source port cannot be matched by the same rule.
	if len(r.PortSpecs()) == 1 && len(r.SourcePortSpecs()) == 1 {
		return "", fmt.Errorf("firewalld rich rules cannot match a destination and source port together: %w", ErrUnsupportedSourcePort)
	}
	// An ICMP type only applies to an ICMP/ICMPv6 protocol; reject it paired with
	// anything else before rendering an icmp-type element.
	if err := r.checkICMPType(); err != nil {
		return "", err
	}
	// A rich rule can log and rate-limit, but has no way to express a
	// connection-count limit.
	if r.ConnLimit != nil {
		return "", fmt.Errorf("firewalld does not support connection limiting: %w", ErrUnsupportedConnLimit)
	}
	// A rich rule limit is a bare rate (value="N/unit") with no burst allowance,
	// so a specific non-zero burst cannot be expressed and is rejected rather than
	// silently dropped. The netfilter default burst (5) is treated as "unset"
	// everywhere else in the library (normBurst/eqRateLimit), so a rule carrying
	// Burst=5 normalizes to 0 and round-trips cleanly here — it must be accepted,
	// keeping a desired set portable across backends.
	if r.RateLimit != nil && normBurst(r.RateLimit.Burst) != 0 {
		return "", fmt.Errorf("firewalld does not support a rate-limit burst in a rich rule: %w", ErrUnsupportedRateLimit)
	}

	// Start with the base rule.
	parts := []string{"rule"}

	// Add priority.
	if r.Priority != 0 {
		parts = append(parts, fmt.Sprintf(`priority="%d"`, r.Priority))
	}

	// Add family. firewalld requires a family whenever a rich rule matches an IP
	// address, and stores the rule under that concrete family, so a FamilyAny rule
	// carrying a source or destination is qualified with that address's family
	// rather than emitting a familyless — and, with an address, invalid — rule. A
	// bare (untyped) ICMP/ICMPv6 protocol match needs no such qualification:
	// firewalld accepts a familyless `protocol value="ipv6-icmp"` rule just like
	// any other protocol (it only requires a family for a source/destination
	// address, never for a protocol), and this library's own read path recovers
	// ICMP vs ICMPv6 directly from the protocol value string regardless of
	// family. A *typed*
	// ICMP match (icmp-type name=...) is different: firewalld resolves the type
	// name without a protocol element (see the icmp-type element emitted below), so the emitted
	// family is this library's own disambiguator on read — ICMPv4 and ICMPv6
	// reuse several of the same type names for different numbers — not something
	// firewalld itself requires.
	fam := r.Family
	if fam == FamilyAny {
		switch {
		case r.Proto.IsICMP() && r.ICMPType != nil:
			if r.Proto == ICMPv6 {
				fam = IPv6
			} else {
				fam = IPv4
			}
		default:
			if af := familyOfAddr(r.Source); af != FamilyAny {
				fam = af
			} else if af := familyOfAddr(r.Destination); af != FamilyAny {
				fam = af
			}
		}
	}
	if fam != FamilyAny {
		parts = append(parts, fmt.Sprintf(`family="%s"`, fam.String()))
	} else if dst := strings.TrimPrefix(r.Destination, "!"); dst != "" {
		// firewalld requires an explicit family for `destination ipset="..."`
		// (unlike `source ipset="..."`, which it accepts familyless) since an
		// ipset's members could be either family. familyOfAddr above already
		// resolves a destination CIDR/IP; this only fires when the destination
		// is an ipset name and the caller left Family unset, in which case there
		// is no address to infer a family from — reject rather than emit a rule
		// firewalld refuses with MISSING_FAMILY.
		if _, _, err := net.ParseCIDR(dst); err != nil && net.ParseIP(dst) == nil {
			return "", fmt.Errorf("firewalld requires an explicit Family for a destination ipset match: %w", ErrUnsupportedSet)
		}
	}

	// Add source.
	if r.Source != "" {
		parts = append(parts, "source")

		// If not defined, append NOT.
		src := r.Source
		if src[0] == '!' {
			parts = append(parts, "NOT")
			src = src[1:]
		}

		// Check if CIDR.
		_, _, err := net.ParseCIDR(src)
		ip := net.ParseIP(src)
		if err == nil || ip != nil {
			parts = append(parts, fmt.Sprintf(`address="%s"`, src))
		} else {
			// Check if MAC.
			_, err := net.ParseMAC(src)
			if err == nil {
				parts = append(parts, fmt.Sprintf(`mac="%s"`, src))
			} else {
				parts = append(parts, fmt.Sprintf(`ipset="%s"`, src))
			}
		}
	}

	// Add destination.
	if r.Destination != "" {
		parts = append(parts, "destination")

		// If not defined, append NOT.
		dst := r.Destination
		if dst[0] == '!' {
			parts = append(parts, "NOT")
			dst = dst[1:]
		}

		// Check if CIDR or IP; otherwise it is an ipset name, which firewalld's
		// destination grammar accepts (`destination ipset="..."`) like the source.
		_, _, err := net.ParseCIDR(dst)
		ip := net.ParseIP(dst)
		if err == nil || ip != nil {
			parts = append(parts, fmt.Sprintf(`address="%s"`, dst))
		} else {
			parts = append(parts, fmt.Sprintf(`ipset="%s"`, dst))
		}
	}

	// An ICMP/ICMPv6 rule matches by protocol value, or — when a specific type is
	// requested — by an icmp-type element. firewalld resolves the type name against
	// the rule's family; the ICMP protocol pins it (ICMP => IPv4, ICMPv6 => IPv6),
	// so the variant is derived from the protocol rather than requiring the caller
	// to set Family (the rule is already qualified with that family above).
	if r.Proto.IsICMP() {
		if r.ICMPType != nil {
			isV6 := r.Proto == ICMPv6
			name, ok := f.icmpTypeName(isV6, *r.ICMPType)
			if !ok {
				return "", fmt.Errorf("firewalld cannot express icmp type %d for %s: %w", *r.ICMPType, fam.String(), ErrUnsupported)
			}
			parts = append(parts, "icmp-type", fmt.Sprintf(`name="%s"`, name))
		} else {
			parts = append(parts, "protocol", fmt.Sprintf(`value="%s"`, f.protoValue(r.Proto)))
		}
	} else if specs := r.PortSpecs(); len(specs) == 1 {
		// A single port or dash range, e.g. port="23" or port="1000-2000".
		parts = append(parts, "port", fmt.Sprintf(`port="%s"`, specs[0].String()), fmt.Sprintf(`protocol="%s"`, r.Proto.String()))
	} else if specs := r.SourcePortSpecs(); len(specs) == 1 {
		// A source-port match, e.g. source-port port="1024" protocol="tcp".
		// Emitted only when there is no destination port, since a rich rule
		// carries a single port element.
		parts = append(parts, "source-port", fmt.Sprintf(`port="%s"`, specs[0].String()), fmt.Sprintf(`protocol="%s"`, r.Proto.String()))
	} else if r.Proto != ProtocolAny {
		// A bare protocol match with no port, such as GRE, ESP or AH (or a
		// portless tcp/udp/sctp rule): protocol value="gre".
		parts = append(parts, "protocol", fmt.Sprintf(`value="%s"`, f.protoValue(r.Proto)))
	}

	// A log element attaches to the whole rule, immediately before the action:
	// rule ... [log] action.
	if r.Log {
		if r.LogPrefix != "" {
			parts = append(parts, "log", fmt.Sprintf(`prefix="%s"`, r.LogPrefix), `level="info"`)
		} else {
			parts = append(parts, "log", `level="info"`)
		}
	}

	// Add the action, then any rate limit. In firewalld's rich-rule grammar a
	// limit is not a standalone element: it is a trailing attribute of the
	// action (or of log/audit). Emitting it before the action produces a rule
	// firewalld rejects, or — after a log element — one that rate-limits the
	// logging rather than the packet. Attaching it to the action rate-limits the
	// action, matching the RateLimit semantics on the other backends.
	parts = append(parts, r.Action.String())
	if r.RateLimit != nil {
		parts = append(parts, "limit", fmt.Sprintf(`value="%d/%s"`, r.RateLimit.Rate, f.rateUnit(r.RateLimit.Unit)))
	}

	// Return the built parts joined with spaces.
	return strings.Join(parts, " "), nil
}

// ignoreAlreadyEnabled treats firewalld's ALREADY_ENABLED as success, making an
// add idempotent: re-adding an element that is already present is a no-op.
func (f *FirewallD) ignoreAlreadyEnabled(err error) error {
	if errors.Is(err, firewalld.ErrAlreadyEnabled) {
		return nil
	}
	return err
}

// sourceZoneShape reports whether a rule's non-address shape lets a plain source
// map to a firewalld zone source: no protocol match, no destination port, no
// source port, and a non-negated source. A source combined with a concrete
// protocol or a port is a rich rule (firewalld encodes those as
// `source address="..." protocol value="..."`/`port ...`), so it is excluded here
// — encoding such a rule as a bare zone source would silently drop the protocol or
// port match and widen it. AddRule and RemoveRule share this so their zone-source
// routing stays symmetric; they differ only in which source *forms* they accept (a
// MAC source is added as a rich rule but removed via the zone-source path).
func (f *FirewallD) sourceZoneShape(r *Rule) bool {
	return r.Source != "" && r.Source[0] != '!' && r.Proto == ProtocolAny &&
		!r.HasPorts() && !r.HasSourcePorts()
}

// zoneEntryEligible reports whether a rule can be expressed as a firewalld
// zone-level entry (a zone port, source port, or source) rather than a rich
// rule. firewalld stores a zone port/source-port as a single port OR a single
// contiguous range, so a lone range is eligible; only a genuine multi-element
// port list (or any of the rich-only features — a concrete family/priority, a
// destination, state/interface/ICMP matching, logging or rate limiting) forces
// the rich-rule path. Eligibility keys on the port-list length rather than
// HasPortSet, which is also true for a single range and would misroute a
// zone-port range onto the rich-rule path.
func (f *FirewallD) zoneEntryEligible(r *Rule) bool {
	return r.Action == Accept && r.Family == FamilyAny && r.Priority == 0 && r.Destination == "" &&
		r.State == 0 && r.InInterface == "" && r.OutInterface == "" && !r.Proto.IsICMP() &&
		len(r.PortSpecs()) <= 1 && len(r.SourcePortSpecs()) <= 1 &&
		!r.Log && r.RateLimit == nil
}

// resolveDestSetFamily pins a family-agnostic rule whose destination names an
// ipset to the set's own family: firewalld requires an explicit family for a
// destination ipset match (unlike a source one, which it accepts familyless),
// and an ipset is family-typed, so the rule could only ever match that family.
// Rules pinned already, or carrying an address that implies a family, pass
// through unchanged.
func (f *FirewallD) resolveDestSetFamily(ctx context.Context, r *Rule) (*Rule, error) {
	if r.Family != FamilyAny || !isSetRef(r.Destination) {
		return r, nil
	}
	if familyOfAddr(r.Source) != FamilyAny {
		return r, nil
	}
	fam, err := setRefFamilyFrom(func(name string) (Family, bool, error) {
		set, gerr := f.getAddressSet(ctx, name)
		if gerr != nil {
			return FamilyAny, false, gerr
		}
		if set == nil {
			return FamilyAny, false, nil
		}
		return set.Family, true, nil
	}, "", r.Destination)
	if err != nil {
		return nil, err
	}
	rc := *r
	rc.Family = fam
	return &rc, nil
}

// AddRule adds a filter rule to a zone, using a zone-level entry when the rule
// fits one and a rich rule otherwise.
func (f *FirewallD) AddRule(ctx context.Context, zoneName string, r *Rule) error {
	if err := r.validate(); err != nil {
		return err
	}

	// firewalld has no output chain (Capabilities().Output is false); it models a
	// "destination" match rather than a true outbound direction. A both-directions
	// DirAny rule cannot be expressed, so it degrades to its input half, and a
	// DirOutput rule is stored in the inbound frame (role-swapped) so both
	// authorings of the same match converge on one stored form and read back
	// identically — otherwise Sync would remove and re-add it forever.
	r = dirAnyInputFallback(r, f.Capabilities().Output)
	if r.Direction == DirOutput {
		r = r.canonicalMatch()
	}

	// A firewalld zone port and rich rule each carry a single protocol, so a
	// TCPUDP rule has no single form; fan it into a tcp add and a udp add, each of
	// which routes through the zone-port or rich-rule path below on its own.
	if subs := expandProtocols(r); len(subs) > 1 {
		for _, sub := range subs {
			if err := f.AddRule(ctx, zoneName, sub); err != nil {
				return err
			}
		}
		return nil
	}

	// A zone port and a rich-rule port element each carry a single port or range,
	// never a list, so a multi-port rule fans into one add per port spec — the
	// port analog of the transport fan-out above. A rule carrying a list on both
	// port axes fans into source+destination pairs, which the rich-rule path then
	// rejects (PortPair is false).
	if subs := expandPorts(r); len(subs) > 1 {
		for _, sub := range subs {
			if err := f.AddRule(ctx, zoneName, sub); err != nil {
				return err
			}
		}
		return nil
	}

	// A connection-count limit cannot be expressed in a firewalld rich rule.
	if r.ConnLimit != nil {
		return fmt.Errorf("firewalld does not support connection limiting: %w", ErrUnsupportedConnLimit)
	}

	// A family-agnostic destination set reference is pinned to the set's own family.
	r, err := f.resolveDestSetFamily(ctx, r)
	if err != nil {
		return err
	}

	// Get the zone.
	zoneName, err = f.resolveZoneName(ctx, zoneName)
	if err != nil {
		return err
	}
	zone := f.Conn.Permanent().Zone(zoneName)

	// Check if rule may be a non-rich rule. Basically only accept actions. Any
	// of the newer match features force the rich-rule path so they are handled
	// (ICMP) or rejected there rather than silently dropped by the port/source
	// shortcuts below. Logging and rate limiting also force the rich-rule path
	// because the AddPort/AddSource shortcuts cannot carry them. A single
	// destination port, a single source port, or a source address each map to a
	// zone-level entry; anything more (a set, or both port dimensions together)
	// falls through to the rich-rule path.
	if f.zoneEntryEligible(r) {
		// A single destination port (or contiguous range) with no source match maps
		// to a zone port. Test HasPorts (not r.Port), so a single port carried in the
		// Ports slice takes this path too rather than falling through to the source
		// shortcut and losing the port match. A concrete tcp/udp/sctp protocol is
		// required; otherwise fall through to the rich-rule path for its clean
		// rejection instead of asking firewalld for a protocol="any" port.
		if r.HasPorts() && r.Proto.HasPorts() && r.Source == "" && !r.HasSourcePorts() {
			return f.ignoreAlreadyEnabled(zone.AddPort(ctx, firewalld.Port{Port: r.PortSpecs()[0].String(), Protocol: r.Proto.String()}))
		}
		// A single source port with no destination port and no source address
		// maps to a zone source port.
		if r.HasSourcePorts() && r.Proto.HasPorts() && !r.HasPorts() && r.Source == "" {
			return f.ignoreAlreadyEnabled(zone.AddSourcePort(ctx, firewalld.Port{Port: r.SourcePortSpecs()[0].String(), Protocol: r.Proto.String()}))
		}
		// A bare source address maps to a zone source: an IP, a subnet, or an ipset
		// reference (ipset:<name>). GetRules reports a zone ipset source in that exact
		// `ipset:<name>` form and RemoveRule clears it via isZoneSource, so AddRule
		// must add it the same way — otherwise it falls through to the rich-rule path,
		// which bakes the `ipset:` prefix into the ipset name (source ipset="ipset:name")
		// and references a nonexistent ipset. (A MAC source stays on the rich-rule path,
		// where it round-trips as source mac="...".)
		// A zone source encodes only the address, so it must not carry a concrete
		// protocol: a source+protocol rule (e.g. tcp from 1.2.3.4) belongs on the
		// rich-rule path (see sourceZoneShape). Taking AddSource here would silently
		// drop the protocol and widen the rule to every protocol, and GetRules would
		// read it back as ProtocolAny.
		if f.sourceZoneShape(r) {
			_, _, cidrErr := net.ParseCIDR(r.Source)
			ip := net.ParseIP(r.Source)
			if cidrErr == nil || ip != nil || strings.HasPrefix(r.Source, "ipset:") {
				return f.ignoreAlreadyEnabled(zone.AddSource(ctx, r.Source))
			}
		}
	}

	// Encode the rich rule and add it.
	richRule, err := f.MarshalRichRule(r)
	if err != nil {
		return err
	}
	return f.ignoreAlreadyEnabled(zone.AddRichRule(ctx, richRule))
}

// InsertRule is unsupported: firewalld rich rules and port/source shortcuts are
// not positionally ordered.
func (f *FirewallD) InsertRule(ctx context.Context, zoneName string, position int, r *Rule) error {
	return unsupportedOrdering(f.Type())
}

// MoveRule is unsupported for the same reason as InsertRule.
func (f *FirewallD) MoveRule(ctx context.Context, zoneName string, r *Rule, position int) error {
	return unsupportedOrdering(f.Type())
}

// removeZoneEntry removes the zone-level entry — a zone port, source port, or
// protocol — that a zone-entry-shaped rule maps to, reporting whether the rule's
// shape matched one of those forms. The firewalld error (including NOT_ENABLED)
// is returned uninterpreted; RemoveRule's zone-entry shortcut and its dual-stack
// split share this so their form routing cannot drift apart.
func (f *FirewallD) removeZoneEntry(ctx context.Context, zone *firewalld.PermZone, r *Rule) (bool, error) {
	switch {
	case r.HasPorts() && r.Proto.HasPorts() && r.Source == "" && !r.HasSourcePorts():
		return true, zone.RemovePort(ctx, firewalld.Port{Port: r.PortSpecs()[0].String(), Protocol: r.Proto.String()})
	case r.HasSourcePorts() && r.Proto.HasPorts() && !r.HasPorts() && r.Source == "":
		return true, zone.RemoveSourcePort(ctx, firewalld.Port{Port: r.SourcePortSpecs()[0].String(), Protocol: r.Proto.String()})
	case r.Proto != ProtocolAny && r.Source == "" && !r.HasPorts() && !r.HasSourcePorts():
		return true, zone.RemoveProtocol(ctx, r.Proto.String())
	}
	return false, nil
}

// isZoneSource reports whether a source string is a form firewalld stores as a
// zone source: an IP, a CIDR, a MAC address, or an ipset reference (ipset:<name>).
// RemoveRule uses it to decide whether a bare source can be cleared with
// RemoveSource rather than falling through to the rich-rule path.
func (f *FirewallD) isZoneSource(s string) bool {
	if _, _, err := net.ParseCIDR(s); err == nil {
		return true
	}
	if net.ParseIP(s) != nil {
		return true
	}
	if strings.HasPrefix(s, "ipset:") {
		return true
	}
	if _, err := net.ParseMAC(s); err == nil {
		return true
	}
	return false
}

// ignoreNotEnabled treats firewalld's NOT_ENABLED as success, making a remove
// idempotent: removing an element that is not present is a no-op.
func (f *FirewallD) ignoreNotEnabled(err error) error {
	if errors.Is(err, firewalld.ErrNotEnabled) {
		return nil
	}
	return err
}

// RemoveRule removes a filter rule from a zone, clearing every form it may be
// stored in: the zone-level entry AddRule would have used and any rich rule
// whose parsed form matches the target.
func (f *FirewallD) RemoveRule(ctx context.Context, zoneName string, r *Rule) error {
	if err := r.validate(); err != nil {
		return err
	}

	// A DirAny rule degrades to its input half on firewalld (no output concept),
	// and a DirOutput target is role-swapped into the inbound frame, mirroring
	// AddRule so a rule is found and removed as stored.
	r = dirAnyInputFallback(r, f.Capabilities().Output)
	if r.Direction == DirOutput {
		r = r.canonicalMatch()
	}

	// firewalld stores a TCPUDP rule as two concrete rows (a tcp entry and a udp
	// entry), never one shared row, so such a removal fans into a tcp remove and a
	// udp remove — the exact inverse of AddRule's fan-out. Removing a concrete
	// transport still deletes only its own row, so no protocol-axis split is needed.
	if subs := expandProtocols(r); len(subs) > 1 {
		for _, sub := range subs {
			if err := f.RemoveRule(ctx, zoneName, sub); err != nil {
				return err
			}
		}
		return nil
	}

	// A multi-port rule is stored as one row per port spec (AddRule's fan-out),
	// never one shared row, so such a removal fans into a single-port remove per
	// spec — the inverse of the add fan-out. Removing one port of a list still
	// deletes only its own row, so no port-axis split is needed.
	if subs := expandPorts(r); len(subs) > 1 {
		for _, sub := range subs {
			if err := f.RemoveRule(ctx, zoneName, sub); err != nil {
				return err
			}
		}
		return nil
	}

	// Get the zone.
	zoneName, err := f.resolveZoneName(ctx, zoneName)
	if err != nil {
		return err
	}
	zone := f.Conn.Permanent().Zone(zoneName)

	// Check if rule maps to a zone element rather than a rich rule, mirroring how
	// AddRule stores it. Any of the newer match features force the rich-rule path
	// so they are handled (ICMP) or rejected there rather than silently dropped by
	// the port/source shortcuts below. Logging and rate limiting also force the
	// rich-rule path. Each shortcut removes the element directly and relies on
	// firewalld's typed errors: a real error is returned, while success and
	// NOT_ENABLED both continue to the rich-rule sweep — a rule present in both
	// storage forms (a zone entry plus an equivalent rich rule added out of band)
	// must be cleared from both in one call.
	if f.zoneEntryEligible(r) {
		if matched, rerr := f.removeZoneEntry(ctx, zone, r); matched {
			if rerr != nil && !errors.Is(rerr, firewalld.ErrNotEnabled) {
				return rerr
			}
		} else if f.sourceZoneShape(r) && f.isZoneSource(r.Source) {
			// A bare source maps to a zone source. firewalld stores an IP/CIDR, a MAC
			// address, or an ipset reference (ipset:<name>) as a zone source, and
			// GetRules reports each verbatim, so removal must try RemoveSource for all
			// of them. A value that is not a zone source form is left to the rich-rule
			// path below; sourceZoneShape mirrors AddRule's ProtocolAny guard, since a
			// source+protocol rule is stored as a rich rule.
			if err := zone.RemoveSource(ctx, r.Source); err != nil && !errors.Is(err, firewalld.ErrNotEnabled) {
				return err
			}
		}
	}

	// Split a dual-stack zone entry on a concrete-family removal. firewalld zone
	// ports, source ports, and protocols carry no family, so a FamilyAny rule of
	// those shapes is stored as one shared entry; zoneEntryEligible (and the
	// shortcuts above) require FamilyAny, so a concrete-family target skips them and
	// would otherwise no-op — leaving both families in place. Remove the shared
	// entry, then re-add the untargeted family, which — being concrete — becomes a
	// rich rule, so its coverage survives. A NOT_ENABLED result means the rule was
	// not stored as that zone entry, so fall through to the rich-rule path (which
	// runs its own split). A bare zone source is excluded: an address carries its own
	// family, so there is no dual-stack entry to split.
	if fam := r.impliedFamily(); fam != FamilyAny {
		rAny := *r
		rAny.Family = FamilyAny
		if f.zoneEntryEligible(&rAny) && r.Source == "" {
			if matched, removeErr := f.removeZoneEntry(ctx, zone, r); matched {
				if removeErr == nil {
					if s := splitDualRow(&rAny, r); s != nil {
						return f.AddRule(ctx, zoneName, s)
					}
					return nil
				}
				if !errors.Is(removeErr, firewalld.ErrNotEnabled) {
					return removeErr
				}
			}
		}
	}

	// A foreign bare ICMP/ICMPv6 protocol allow (firewall-cmd --add-protocol=icmp)
	// is surfaced by GetRules as a portless ICMP-protocol rule, but ICMP is excluded
	// from zoneEntryEligible (the library writes its own ICMP matches as rich
	// rules), so the zone-protocol shortcut above never runs for it. Attempt the
	// zone-protocol removal here for exactly that bare shape; a NOT_ENABLED result
	// falls through to the rich-rule path for an ICMP match the library stored as a
	// rich rule instead.
	if r.Proto.IsICMP() && r.ICMPType == nil && r.Action == Accept && r.Source == "" &&
		r.Destination == "" && !r.HasPorts() && !r.HasSourcePorts() && r.State == 0 &&
		r.InInterface == "" && r.OutInterface == "" && !r.Log && r.RateLimit == nil && r.Priority == 0 {
		proto := "icmp"
		if r.Proto == ICMPv6 {
			proto = "ipv6-icmp"
		}
		if err := zone.RemoveProtocol(ctx, proto); err != nil && !errors.Is(err, firewalld.ErrNotEnabled) {
			return err
		}
	}

	// Rich-rule path: read the zone settings and remove every stored rich rule
	// whose parsed form matches the target, so a rule firewalld stored with
	// different formatting than our marshaller produces is still matched. Match with
	// EqualForRemoval rather than the family-strict Equal: a FamilyAny target must
	// clear both the familyless rich rule it names and any family-pinned rich rules
	// it covers, while a concrete-family target still removes only its own family
	// (splitting a familyless rich rule when it matches one).
	settings, err := zone.Settings(ctx)
	if err != nil {
		return err
	}
	removedRich := false
	var reAdd *Rule
	for _, richRule := range settings.RichRules {
		rule, err := f.UnmarshalRichRule(richRule)
		if err != nil {
			continue
		}
		if rule.EqualForRemoval(r, false) {
			if err := f.ignoreNotEnabled(zone.RemoveRichRule(ctx, richRule)); err != nil {
				return err
			}
			removedRich = true
			// A concrete-family target that matched a genuine dual-family rich rule
			// (one stored with no family= attribute) would drop both families; re-add
			// the untargeted family below so its coverage survives.
			if s := splitDualRow(rule, r); s != nil {
				reAdd = s
			}
		}
	}
	if removedRich {
		if reAdd != nil {
			return f.AddRule(ctx, zoneName, reAdd)
		}
		return nil
	}

	// If no stored rule matched, encode the rule and remove it directly; an absent
	// rule is treated as already removed.
	richRule, err := f.MarshalRichRule(r)
	if err != nil {
		return err
	}
	return f.ignoreNotEnabled(zone.RemoveRichRule(ctx, richRule))
}

// modeledForwardPort decodes a zone forward-port entry into the NATRule
// GetNATRules reports, or nil for an entry the model cannot hold: an
// unparseable port, a protocol the write side rejects (sctp/dccp — forwardPort
// takes tcp/udp only, so such a rule could never be removed or re-added), or a
// target-port range. An unmodeled entry stays unmanaged, and Restore leaves it
// in place for the same reason.
func (f *FirewallD) modeledForwardPort(fp firewalld.ForwardPort) *NATRule {
	pr, perr := ParsePortRange(fp.Port)
	if perr != nil {
		return nil
	}
	proto := GetProtocol(fp.Protocol)
	if proto != TCP && proto != UDP {
		return nil
	}
	rule := &NATRule{Proto: proto}
	if pr.Start == pr.End {
		rule.Port = pr.Start
	} else {
		rule.Ports = []PortRange{pr}
	}
	if fp.ToPort != "" {
		tp, terr := strconv.ParseUint(fp.ToPort, 10, 16)
		if terr != nil {
			return nil
		}
		rule.ToPort = uint16(tp)
	}
	rule.ToAddress = fp.ToAddr
	if fp.ToAddr != "" {
		rule.Kind = DNAT
	} else {
		rule.Kind = Redirect
	}
	return rule
}

// GetNATRules returns the NAT rules for a zone, mapping forward ports and masquerade.
func (f *FirewallD) GetNATRules(ctx context.Context, zoneName string) (rules []*NATRule, err error) {
	zoneName, err = f.resolveZoneName(ctx, zoneName)
	if err != nil {
		return nil, err
	}

	// Read the zone settings for forward ports and masquerade.
	settings, err := f.Conn.Permanent().Zone(zoneName).Settings(ctx)
	if err != nil {
		return nil, err
	}

	// Each forward port maps to a DNAT (when it targets another address) or a
	// Redirect (same host, port only). firewalld's model carries no family, so
	// these are returned as FamilyAny. An entry the model cannot hold stays
	// unmanaged (see modeledForwardPort).
	for _, fp := range settings.ForwardPorts {
		if rule := f.modeledForwardPort(fp); rule != nil {
			rules = append(rules, rule)
		}
	}

	// Zone masquerade maps to a single Masquerade rule.
	if settings.Masquerade {
		rules = append(rules, &NATRule{Kind: Masquerade})
	}

	// firewalld isolates NAT by zone; this read is scoped to one zone, so every
	// rule lives in zoneName — record the zone and flag it as carrying the prefix.
	for _, r := range rules {
		r.table = zoneName
		r.HasPrefix = true
	}
	return rules, nil
}

// forwardPort renders a DNAT/Redirect NAT rule as the arguments firewalld's
// per-zone port-forward API expects (port, protocol, toport, toaddr). That API
// carries only these four fields, so any source, destination or interface match
// cannot be expressed through it and is rejected. A port list has no single
// forward-port form either; AddNATRule/RemoveNATRule fan one into a forward-port
// per spec with expandNATPorts before this row-level renderer runs, so a list
// reaching here means that fan-out was skipped. (firewalld can
// express a source-scoped forward-port in a rich rule, but this backend manages
// NAT through the zone API, which GetNATRules reads back; a rich-rule forward-port
// would not round-trip, so it is intentionally not emitted here.)
func (f *FirewallD) forwardPort(r *NATRule) (firewalld.ForwardPort, error) {
	if r.Proto != TCP && r.Proto != UDP {
		return firewalld.ForwardPort{}, fmt.Errorf("firewalld port forwarding requires a tcp or udp protocol: %w", ErrUnsupportedNAT)
	}
	if !r.HasPorts() {
		return firewalld.ForwardPort{}, fmt.Errorf("firewalld port forwarding requires a matched port: %w", ErrUnsupportedNAT)
	}
	// A forward-port carries a single port or range; AddNATRule/RemoveNATRule fan a
	// port list into one forward-port per spec with expandNATPorts before this
	// helper runs, so only a single spec ever reaches here.
	specs := r.PortSpecs()
	if r.Interface != "" {
		return firewalld.ForwardPort{}, fmt.Errorf("firewalld does not bind a port forward to an interface: %w", ErrUnsupportedNAT)
	}
	if r.Source != "" || r.Destination != "" {
		return firewalld.ForwardPort{}, fmt.Errorf("firewalld port forwarding does not support source or destination matching: %w", ErrUnsupportedNAT)
	}
	fp := firewalld.ForwardPort{
		Port:     specs[0].String(),
		Protocol: r.Proto.String(),
		// ToAddr is empty for a Redirect (same-host) and set for a DNAT.
		ToAddr: r.ToAddress,
	}
	if r.ToPort != 0 {
		fp.ToPort = strconv.FormatUint(uint64(r.ToPort), 10)
	}
	return fp, nil
}

// AddNATRule adds a NAT rule to a zone via firewalld's forward-port or masquerade API.
func (f *FirewallD) AddNATRule(ctx context.Context, zoneName string, r *NATRule) error {
	if err := r.validate(); err != nil {
		return err
	}

	// Get the zone.
	zoneName, err := f.resolveZoneName(ctx, zoneName)
	if err != nil {
		return err
	}
	zone := f.Conn.Permanent().Zone(zoneName)

	switch r.Kind {
	case DNAT, Redirect:
		// A forward-port carries a single port or range, never a list, so a
		// multi-port match fans into one forward-port add per spec, each
		// translating to the same target.
		if subs := expandNATPorts(r); len(subs) > 1 {
			for _, sub := range subs {
				if err := f.AddNATRule(ctx, zoneName, sub); err != nil {
					return err
				}
			}
			return nil
		}
		fp, err := f.forwardPort(r)
		if err != nil {
			return err
		}
		return f.ignoreAlreadyEnabled(zone.AddForwardPort(ctx, fp))
	case Masquerade:
		// This backend manages masquerade through firewalld's per-zone toggle, which
		// carries no match, so reject a rule that asks for one. (firewalld can scope a
		// masquerade to a source in a rich rule, but the zone toggle is what
		// GetNATRules reads back; a rich-rule masquerade would not round-trip.)
		if r.Interface != "" || r.Source != "" || r.Destination != "" || r.Proto != ProtocolAny || r.HasPorts() {
			return fmt.Errorf("this backend's zone masquerade cannot match on interface, address, protocol or port: %w", ErrUnsupportedNAT)
		}
		return f.ignoreAlreadyEnabled(zone.AddMasquerade(ctx))
	case SNAT:
		return fmt.Errorf("firewalld does not support snat in this model: %w", ErrUnsupportedNAT)
	}
	return fmt.Errorf("invalid nat kind")
}

// InsertNATRule is unsupported: firewalld models NAT through zone toggles and rich
// rules, which carry no explicit ordering.
func (f *FirewallD) InsertNATRule(ctx context.Context, zoneName string, position int, r *NATRule) error {
	return unsupportedOrdering(f.Type())
}

// MoveNATRule is unsupported for the same reason as InsertNATRule.
func (f *FirewallD) MoveNATRule(ctx context.Context, zoneName string, r *NATRule, position int) error {
	return unsupportedOrdering(f.Type())
}

// RemoveNATRule removes a NAT rule from a zone via firewalld's forward-port or masquerade API.
func (f *FirewallD) RemoveNATRule(ctx context.Context, zoneName string, r *NATRule) error {
	if err := r.validate(); err != nil {
		return err
	}

	// Get the zone.
	zoneName, err := f.resolveZoneName(ctx, zoneName)
	if err != nil {
		return err
	}
	zone := f.Conn.Permanent().Zone(zoneName)

	switch r.Kind {
	case DNAT, Redirect:
		// The inverse of AddNATRule's fan-out: a multi-port match is stored as
		// one forward-port per spec, so its removal fans into one remove per spec.
		if subs := expandNATPorts(r); len(subs) > 1 {
			for _, sub := range subs {
				if err := f.RemoveNATRule(ctx, zoneName, sub); err != nil {
					return err
				}
			}
			return nil
		}
		fp, err := f.forwardPort(r)
		if err != nil {
			return err
		}
		return f.ignoreNotEnabled(zone.RemoveForwardPort(ctx, fp))
	case Masquerade:
		return f.ignoreNotEnabled(zone.RemoveMasquerade(ctx))
	case SNAT:
		return fmt.Errorf("firewalld does not support snat in this model: %w", ErrUnsupportedNAT)
	}
	return fmt.Errorf("invalid nat kind")
}

// policyFromTarget maps a firewalld zone target to a default action. The
// "default"/"%%REJECT%%"/empty targets behave as a reject, the only ones a zone
// accepts explicitly being ACCEPT and DROP.
func (f *FirewallD) policyFromTarget(target string) Action {
	switch strings.ToUpper(target) {
	case "ACCEPT":
		return Accept
	case "DROP":
		return Drop
	case "", "DEFAULT", "%%REJECT%%", "REJECT":
		return Reject
	}
	return Reject
}

// GetDefaultPolicy returns the zone's default input policy, derived from its target.
func (f *FirewallD) GetDefaultPolicy(ctx context.Context, zoneName string) (*DefaultPolicy, error) {
	zoneName, err := f.resolveZoneName(ctx, zoneName)
	if err != nil {
		return nil, err
	}
	settings, err := f.Conn.Permanent().Zone(zoneName).Settings(ctx)
	if err != nil {
		return nil, err
	}
	// firewalld zones only model the input side; a packet that matches no rule
	// is handled by the zone target.
	return &DefaultPolicy{Input: f.policyFromTarget(string(settings.Target))}, nil
}

// SetDefaultPolicy sets the zone's default input policy via its target; firewalld
// zones only expose the input direction.
func (f *FirewallD) SetDefaultPolicy(ctx context.Context, zoneName string, policy *DefaultPolicy) error {
	if policy == nil {
		return fmt.Errorf("policy cannot be nil")
	}
	// firewalld zones only expose the input direction.
	if policy.Output != ActionInvalid || policy.Forward != ActionInvalid {
		return fmt.Errorf("firewalld only manages the input default policy: %w", ErrUnsupportedPolicy)
	}
	if policy.Input == ActionInvalid {
		return nil
	}
	var target firewalld.Target
	switch policy.Input {
	case Accept:
		target = firewalld.TargetACCEPT
	case Drop:
		target = firewalld.TargetDROP
	case Reject:
		target = firewalld.TargetReject
	default:
		return fmt.Errorf("invalid default policy action")
	}
	zoneName, err := f.resolveZoneName(ctx, zoneName)
	if err != nil {
		return err
	}
	return f.Conn.Permanent().Zone(zoneName).SetTarget(ctx, target)
}

// --- address sets (firewalld ipsets) ----------------------------------------

// getAddressSet reads a single firewalld ipset, or nil if it does not exist or
// has a type the model cannot hold. Only hash:ip and hash:net map onto SetType;
// coercing another type (hash:mac, hash:ip,port, ...) would let a Backup/Restore
// rewrite the set as a bare hash:ip and break it, so those stay unmanaged.
func (f *FirewallD) getAddressSet(ctx context.Context, name string) (*AddressSet, error) {
	settings, err := f.Conn.Permanent().IPSet(name).Settings(ctx)
	if errors.Is(err, firewalld.ErrInvalidIPSet) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	set := &AddressSet{Name: name, Entries: settings.Entries}
	switch settings.Type {
	case "hash:ip":
		set.Type = SetHashIP
	case "hash:net":
		set.Type = SetHashNet
	default:
		return nil, nil
	}
	switch settings.Options["family"] {
	case "inet6":
		set.Family = IPv6
	case "inet", "":
		set.Family = IPv4
	}
	return set, nil
}

// GetAddressSets returns all permanent firewalld ipsets as address sets.
func (f *FirewallD) GetAddressSets(ctx context.Context) ([]*AddressSet, error) {
	names, err := f.Conn.Permanent().IPSetNames(ctx)
	if err != nil {
		return nil, err
	}
	result := make([]*AddressSet, 0, len(names))
	for _, name := range names {
		set, err := f.getAddressSet(ctx, name)
		if err != nil {
			return nil, err
		}
		if set == nil {
			continue
		}
		result = append(result, set)
	}
	return result, nil
}

// GetAddressSet returns the named permanent ipset, or an error if it does not exist.
func (f *FirewallD) GetAddressSet(ctx context.Context, name string) (*AddressSet, error) {
	set, err := f.getAddressSet(ctx, name)
	if err != nil {
		return nil, err
	}
	if set == nil {
		return nil, fmt.Errorf("address set %q not found", name)
	}
	return set, nil
}

// ipSetType maps an AddressSet type to a firewalld ipset type string.
func (f *FirewallD) ipSetType(t SetType) string {
	if t == SetHashNet {
		return "hash:net"
	}
	return "hash:ip"
}

// AddAddressSet creates the permanent ipset, or updates it in place when it already exists.
func (f *FirewallD) AddAddressSet(ctx context.Context, set *AddressSet) error {
	if set == nil || set.Name == "" {
		return fmt.Errorf("an address set requires a name")
	}
	settings := firewalld.IPSetSettings{
		Name:    set.Name,
		Type:    f.ipSetType(set.Type),
		Entries: set.Entries,
		Options: map[string]string{"family": "inet"},
	}
	if set.Family == IPv6 {
		settings.Options["family"] = "inet6"
	}

	// If the set already exists, update it in place; otherwise create it.
	names, err := f.Conn.Permanent().IPSetNames(ctx)
	if err != nil {
		return err
	}
	for _, n := range names {
		if n == set.Name {
			return f.Conn.Permanent().IPSet(set.Name).Update(ctx, settings)
		}
	}
	if _, err := f.Conn.Permanent().AddIPSet(ctx, set.Name, settings); err != nil {
		return err
	}
	return nil
}

// RemoveAddressSet removes the named permanent ipset. Remove resolves the ipset
// by name itself and returns firewalld.ErrInvalidIPSet if it does not exist, so a
// separate existence pre-check would just double the D-Bus round trips.
func (f *FirewallD) RemoveAddressSet(ctx context.Context, name string) error {
	err := f.Conn.Permanent().IPSet(name).Remove(ctx)
	// A missing set is a no-op; any other error (D-Bus disconnect, permission
	// denial, ...) must surface.
	if errors.Is(err, firewalld.ErrInvalidIPSet) {
		return nil
	}
	return err
}

// AddAddressSetEntry adds entry to the named permanent ipset. AddEntry resolves
// the ipset by name itself and returns firewalld.ErrInvalidIPSet if it does not
// exist, so a separate existence pre-check would just double the D-Bus round trips.
func (f *FirewallD) AddAddressSetEntry(ctx context.Context, name, entry string) error {
	err := f.Conn.Permanent().IPSet(name).AddEntry(ctx, entry)
	if errors.Is(err, firewalld.ErrInvalidIPSet) {
		return fmt.Errorf("address set %q not found", name)
	}
	return err
}

// RemoveAddressSetEntry removes entry from the named permanent ipset. RemoveEntry
// resolves the ipset by name itself and returns firewalld.ErrInvalidIPSet if it
// does not exist, so a separate existence pre-check would just double the D-Bus
// round trips.
func (f *FirewallD) RemoveAddressSetEntry(ctx context.Context, name, entry string) error {
	err := f.Conn.Permanent().IPSet(name).RemoveEntry(ctx, entry)
	if errors.Is(err, firewalld.ErrInvalidIPSet) {
		return fmt.Errorf("address set %q not found", name)
	}
	return err
}

// Backup captures the current filter and NAT rules managed by this backend.
func (f *FirewallD) Backup(ctx context.Context, zoneName string) (*Backup, error) {
	rules, err := f.GetRules(ctx, zoneName)
	if err != nil {
		return nil, err
	}
	natRules, err := f.GetNATRules(ctx, zoneName)
	if err != nil {
		return nil, err
	}
	// GetRules/GetNATRules are already scoped to this zone, so the backup captures
	// exactly the zone's rules; captureBackupState adds the zone's default policy
	// (its target) and the managed ipsets.
	backup := &Backup{Rules: rules, NATRules: natRules}
	if err := captureBackupState(ctx, f, zoneName, backup); err != nil {
		return nil, err
	}
	return backup, nil
}

// Restore replaces the managed rules with the contents of a Backup.
func (f *FirewallD) Restore(ctx context.Context, zoneName string, backup *Backup) error {
	if backup == nil {
		return fmt.Errorf("backup cannot be nil")
	}

	// Get the zone.
	zoneName, err := f.resolveZoneName(ctx, zoneName)
	if err != nil {
		return err
	}
	zone := f.Conn.Permanent().Zone(zoneName)

	settings, err := zone.Settings(ctx)
	if err != nil {
		return err
	}

	// Remove the zone entries and rich rules the model manages. Each removal
	// mirrors the guard its read side applies, so an entry GetRules skips as
	// unmodeled (a dccp port, an unrecognized protocol, an unparseable rich rule)
	// is preserved rather than destroyed by a Backup that never captured it.
	for _, port := range settings.Ports {
		if len(f.zonePortRules([]firewalld.Port{port}, false)) == 0 {
			continue
		}
		if err := zone.RemovePort(ctx, port); err != nil {
			return err
		}
	}
	for _, sp := range settings.SourcePorts {
		if len(f.zonePortRules([]firewalld.Port{sp}, true)) == 0 {
			continue
		}
		if err := zone.RemoveSourcePort(ctx, sp); err != nil {
			return err
		}
	}
	for _, source := range settings.Sources {
		if err := zone.RemoveSource(ctx, source); err != nil {
			return err
		}
	}
	for _, proto := range settings.Protocols {
		if GetProtocol(proto) == ProtocolAny {
			continue
		}
		if err := zone.RemoveProtocol(ctx, proto); err != nil {
			return err
		}
	}
	for _, richRule := range settings.RichRules {
		if _, perr := f.UnmarshalRichRule(richRule); perr != nil {
			continue
		}
		if err := zone.RemoveRichRule(ctx, richRule); err != nil {
			return err
		}
	}

	// Remove the modeled NAT entries, preserving forward ports the model cannot
	// hold for the same reason.
	for _, fp := range settings.ForwardPorts {
		if f.modeledForwardPort(fp) == nil {
			continue
		}
		if err := zone.RemoveForwardPort(ctx, fp); err != nil {
			return err
		}
	}
	if settings.Masquerade {
		if err := zone.RemoveMasquerade(ctx); err != nil {
			return err
		}
	}

	// Recreate the ipsets before the rules that reference them (the managed rich
	// rules were removed above, so nothing holds a set reference).
	if err := restoreBackupSets(ctx, f, backup, false); err != nil {
		return err
	}

	// Re-add rules from backup.
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
	// Re-assert the zone's captured default policy (its target).
	return applyBackupPolicy(ctx, f, zoneName, backup)
}

// Reload reloads firewalld's permanent configuration into the runtime.
func (f *FirewallD) Reload(ctx context.Context) error {
	return f.Conn.Reload(ctx)
}

// Close releases the D-Bus connection to firewalld.
func (f *FirewallD) Close(ctx context.Context) error {
	return f.Conn.Close()
}
