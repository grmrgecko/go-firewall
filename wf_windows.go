package firewall

import (
	"context"
	"fmt"
	"net"
	"strings"

	wapi "github.com/iamacarpet/go-win64api"
	"go4.org/netipx"
)

const (
	// The IP protocol numbers for the transport/tunnel protocols the model adds.
	// Windows filters by raw protocol number, so these map directly.
	wfProtocolGRE  = 47
	wfProtocolESP  = 50
	wfProtocolAH   = 51
	wfProtocolSCTP = 132
	// wfManagedDescription is the default filter description for rules this
	// library creates that carry no user comment. It is treated as "no comment"
	// on read so it does not surface as a Rule.Comment.
	wfManagedDescription = "Managed by go-firewall"
)

// WF manages firewall rules through the Windows Filtering Platform via the
// go-win64api binding, tagging its rules with the configured name prefix.
type WF struct {
	rulePrefix string
}

// NewWF constructs a WF backend using rulePrefix as its rule-name namespace,
// confirming the Windows firewall interface is reachable.
func NewWF(ctx context.Context, rulePrefix string) (*WF, error) {
	// Honor an already-cancelled context before touching the Windows API, whose
	// calls are synchronous and cannot be cancelled mid-flight.
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	wf := &WF{
		rulePrefix: rulePrefix,
	}

	// Confirm the firewall interface works.
	_, err := wapi.FirewallCurrentProfiles()
	if err != nil {
		return nil, err
	}

	// Return the firewall pointer.
	return wf, nil
}

// Type returns the backend type string for the Windows firewall.
func (f *WF) Type() string {
	return WFType
}

// Capabilities returns the set of features the Windows firewall backend can express.
func (f *WF) Capabilities() Capabilities {
	return Capabilities{
		Output:   true,
		IPv6:     true,
		PortPair: true,
		// WFP has no negated address condition, no reject action (permit or
		// block only), and scopes a filter's family through its address
		// conditions, so an address-less rule cannot pin one family.
		Negation:             false,
		RejectAction:         false,
		FamilyWithoutAddress: false,
		ConnState:            false,
		InterfaceMatch:       false,
		Logging:              false,
		RateLimit:            false,
		ConnLimit:            false,
		NAT:                  false,
		RuleOrdering:         false,
		DefaultPolicy:        false,
		RuleCounters:         false,
		AddressSets:          false,
		Comments:             true,
	}
}

// GetZone reports no zone; Windows Firewall is profile-based, so an interface maps to no single zone.
func (f *WF) GetZone(ctx context.Context, iface string) (zoneName string, err error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}

	// Windows Firewall is profile-based (Domain, Private, Public), and an interface
	// can carry multiple profiles, so an interface name maps to no single zone.
	// Return empty to fall back to profile-wide rules.
	return "", nil
}

// decodeAddress normalizes a Windows Firewall address string to a single CIDR/IP.
func (f *WF) decodeAddress(addr string) (newAddr string, err error) {
	addr = strings.TrimSpace(addr)

	// If wildcard or empty, return empty string.
	if addr == "*" || addr == "" {
		return
	}

	// WFP built-in rules frequently carry a comma-separated address list, which the
	// single-valued Rule model cannot hold. Decoding only the first entry would
	// misrepresent the rule — it would compare equal to a rule scoped to that one
	// address, so a rewrite would silently narrow it and a Backup/Restore round trip
	// would drop the remaining addresses. Reject it so UnmarshallFWRule keeps the
	// rule out of the view entirely, as it does for the other unmodeled shapes.
	if strings.IndexByte(addr, ',') >= 0 {
		return "", fmt.Errorf("multi-address list cannot be represented")
	}

	// Parse IP range to single prefix if possible.
	if strings.Contains(addr, "-") {
		// Make IP range from parts.
		r, err := netipx.ParseIPRange(addr)
		if err != nil {
			return "", err
		}

		// Get prefixes from the range.
		prefixes := r.Prefixes()
		if len(prefixes) != 1 {
			return "", fmt.Errorf("unable to parse range into single prefix")
		}

		// Return the found prefix.
		return prefixes[0].String(), nil
	}

	// Parse prefix from cidr or ip/netmask.
	// Example: 192.168.1.0/24 OR 192.168.1.0/255.255.255.0
	if strings.Contains(addr, "/") {
		// Parse CIDR or IP/netmask.
		var ipNet *net.IPNet
		var ip net.IP

		// Split into parts and confirm the length.
		parts := strings.Split(addr, "/")
		if len(parts) != 2 {
			err = fmt.Errorf("invalid prefix length")
			return
		}

		// The length side is a dotted-quad (IPv4) or colon-form (IPv6) netmask
		// rather than a plain prefix length. A plain prefix is all digits, so any
		// "." or ":" marks the ip/netmask form.
		if strings.ContainsAny(parts[1], ".:") {
			// Parse the netmask.
			netmask := net.ParseIP(parts[1])
			if netmask == nil {
				err = fmt.Errorf("invalid netmask")
				return
			}

			// Parse the network address.
			ip = net.ParseIP(parts[0])
			if ip == nil {
				err = fmt.Errorf("invalid ip")
				return
			}

			// Normalize an IPv4 pair to 4-byte form so the mask width matches the
			// address width; leave IPv6 in 16-byte form. A family mismatch between
			// the address and the netmask is invalid.
			if m4 := netmask.To4(); m4 != nil {
				ip4 := ip.To4()
				if ip4 == nil {
					err = fmt.Errorf("ip/netmask family mismatch")
					return
				}
				netmask, ip = m4, ip4
			} else if ip.To4() != nil {
				err = fmt.Errorf("ip/netmask family mismatch")
				return
			}
			mask := net.IPMask(netmask)

			// Make the IP network, masking host bits so the ip/netmask form
			// normalizes identically to the equivalent CIDR (net.ParseCIDR masks
			// the network address; "192.168.1.5/255.255.255.0" and
			// "192.168.1.5/24" must both decode to "192.168.1.0/24" or the two
			// spellings would compare unequal in Rule.Equal).
			ipNet = &net.IPNet{
				IP:   ip.Mask(mask),
				Mask: mask,
			}
		} else {
			// For standard CIDRs try and parse normally.
			ip, ipNet, err = net.ParseCIDR(addr)
			if err != nil {
				return
			}
		}

		// Get CIDR string.
		newAddr = ipNet.String()

		// See if this is an individual IP and update new address.
		ones, bits := ipNet.Mask.Size()
		if ones == bits {
			newAddr = ip.String()
		}

		// Return the parsed address.
		return
	}

	// Handle a single IP.
	ip := net.ParseIP(addr)
	if ip == nil {
		err = fmt.Errorf("invalid IP")
		return
	}
	newAddr = ip.String()

	return
}

// UnmarshallFWRule decodes a Windows FWRule into a Rule, returning nil for a rule the model cannot represent.
func (f *WF) UnmarshallFWRule(fr wapi.FWRule) *Rule {
	r := &Rule{}

	// A rule scoped by an attribute this model cannot represent — an application
	// path, a Windows service, or a specific interface-type category (LAN,
	// Wireless, RemoteAccess) — would decode into a bare, unscoped rule, silently
	// widening a narrow foreign rule ("allow inbound TCP for program X") into a
	// match-all one ("allow all inbound TCP"). Windows ships many such built-in
	// rules; surfacing them misrepresented would let them compare equal to a
	// genuinely bare rule and be reconciled or removed as if identical. Drop them
	// from the view instead, as the ICMP-code and multi-pair cases below do. Our
	// own rules never set these fields (MarshallFWRule cannot express an interface
	// match and never sets an application or service), so this hides only foreign
	// rules the model cannot faithfully hold.
	if fr.ApplicationName != "" || fr.ServiceName != "" {
		return nil
	}
	if it := strings.TrimSpace(fr.InterfaceTypes); it != "" && !strings.EqualFold(it, "All") {
		return nil
	}
	// A disabled rule enforces nothing: decoding it as live would let AddRule's
	// idempotency check treat a disabled twin as satisfying the add (the rule is
	// then never enforced) and a Backup capture a rule Restore re-adds enabled.
	if !fr.Enabled {
		return nil
	}
	// The model has no edge-traversal field; decoding such a rule identically to
	// its non-edge twin would let a rewrite silently narrow it.
	if fr.EdgeTraversal {
		return nil
	}

	// Map direction.
	if fr.Direction == wapi.NET_FW_RULE_DIR_OUT {
		r.Direction = DirOutput
	} else {
		r.Direction = DirInput
	}

	// Map action.
	switch fr.Action {
	case wapi.NET_FW_ACTION_ALLOW:
		r.Action = Accept
	case wapi.NET_FW_ACTION_BLOCK:
		r.Action = Drop
	default:
		return nil
	}

	// Map protocol.
	switch fr.Protocol {
	case wapi.NET_FW_IP_PROTOCOL_TCP:
		r.Proto = TCP
	case wapi.NET_FW_IP_PROTOCOL_UDP:
		r.Proto = UDP
	case wapi.NET_FW_IP_PROTOCOL_ANY:
		r.Proto = ProtocolAny
	case wapi.NET_FW_IP_PROTOCOL_ICMPv6:
		r.Proto = ICMPv6
	case wapi.NET_FW_IP_PROTOCOL_ICMPv4:
		r.Proto = ICMP
	case wfProtocolSCTP:
		r.Proto = SCTP
	case wfProtocolGRE:
		r.Proto = GRE
	case wfProtocolESP:
		r.Proto = ESP
	case wfProtocolAH:
		r.Proto = AH
	default:
		return nil
	}

	// Decode an ICMP type from the "type:code" field. Only a single type is
	// modeled; a "*" (or empty) type matches every type.
	if r.Proto.IsICMP() {
		raw := strings.TrimSpace(fr.ICMPTypesAndCodes)
		if raw != "" && raw != "*" {
			// Multiple type:code pairs cannot be represented by a single rule.
			if strings.Contains(raw, ",") {
				return nil
			}
			typePart, codePart, hasCode := strings.Cut(raw, ":")
			typePart = strings.TrimSpace(typePart)
			codePart = strings.TrimSpace(codePart)
			// The Rule model carries an ICMP type but no code. A rule scoped to a
			// specific code (e.g. "3:4") cannot be represented, and re-adding it would
			// emit "3:*" — silently widening it to every code of that type. Drop it
			// from the view (like the multi-pair case above) rather than misrepresent
			// and then widen it.
			if hasCode && codePart != "" && codePart != "*" {
				return nil
			}
			if typePart != "" && typePart != "*" {
				// Resolve a named type through the family-appropriate table: ICMPv6
				// reuses several ICMPv4 names for different numbers. Windows stores
				// types numerically, where both tables agree, so this only matters if
				// a rule carries a named type.
				n, ok := parseICMPTypeFamily(typePart, r.Proto == ICMPv6)
				if !ok {
					return nil
				}
				r.ICMPType = Ptr(n)
			}
		}
	}

	// Windows uses local/remote ports; map them by direction. For an input rule the
	// destination is the local port and the source is the remote port; for an output
	// rule it is reversed. Windows expresses each as a string that may hold a list
	// and dash ranges (e.g. "80,443,1000-2000").
	destPortsRaw, srcPortsRaw := fr.LocalPorts, fr.RemotePorts
	if r.IsOutput() {
		destPortsRaw, srcPortsRaw = fr.RemotePorts, fr.LocalPorts
	}
	if r.Proto == TCP || r.Proto == UDP {
		if destPortsRaw != "" && destPortsRaw != "*" {
			specs, err := ParsePortRanges(destPortsRaw, ",")
			if err != nil {
				return nil
			}
			if len(specs) == 1 && specs[0].Start == specs[0].End {
				r.Port = specs[0].Start
			} else {
				r.Ports = specs
			}
		}
		if srcPortsRaw != "" && srcPortsRaw != "*" {
			specs, err := ParsePortRanges(srcPortsRaw, ",")
			if err != nil {
				return nil
			}
			if len(specs) == 1 && specs[0].Start == specs[0].End {
				r.SourcePort = specs[0].Start
			} else {
				r.SourcePorts = specs
			}
		}
	}

	// Based on direction, map the source and destination address: the rule model
	// uses source/destination, whereas Windows uses local/remote.
	var srcRaw, dstRaw string
	if r.IsOutput() {
		srcRaw = fr.LocalAddresses
		dstRaw = fr.RemoteAddresses
	} else {
		srcRaw = fr.RemoteAddresses
		dstRaw = fr.LocalAddresses
	}

	// Parse addresses.
	var err error
	r.Source, err = f.decodeAddress(srcRaw)
	if err != nil {
		return nil
	}
	r.Destination, err = f.decodeAddress(dstRaw)
	if err != nil {
		return nil
	}

	// Map family.
	r.Family = FamilyAny
	if strings.Contains(r.Source, ":") || strings.Contains(r.Destination, ":") {
		r.Family = IPv6
	} else if strings.Contains(r.Source, ".") || strings.Contains(r.Destination, ".") {
		r.Family = IPv4
	}

	// A description other than our managed default is a user comment.
	if fr.Description != "" && fr.Description != wfManagedDescription {
		r.Comment = fr.Description
	}

	return r
}

// hasPrefix reports whether a listed rule's name carries the configured prefix
// (see MarshallFWRule), marking it as one this manager tagged. Everything else —
// notably Windows' many built-in rules — reports false. With no prefix the
// manager has no namespace of its own, so no rule reports HasPrefix.
func (f *WF) hasPrefix(fr wapi.FWRule) bool {
	return f.rulePrefix != "" && strings.HasPrefix(fr.Name, f.rulePrefix+" ")
}

// profileFilter maps a zone name to the single Windows profile bit that GetRules
// and RemoveRule filter on, so both scope to the same rules. ok is false when the
// zone names no specific profile, meaning every profile is in scope.
func (f *WF) profileFilter(zoneName string) (profile int32, ok bool) {
	switch {
	case strings.EqualFold(zoneName, "public"):
		return wapi.NET_FW_PROFILE2_PUBLIC, true
	case strings.EqualFold(zoneName, "private"):
		return wapi.NET_FW_PROFILE2_PRIVATE, true
	case strings.EqualFold(zoneName, "domain"):
		return wapi.NET_FW_PROFILE2_DOMAIN, true
	}
	return 0, false
}

// profileMatches reports whether a rule's Profiles bitmask is in scope for a
// zone's profile filter (every rule is, when the zone named no profile). A rule
// matches only when its Profiles exactly equals the single filter bit: AddRule
// always stores a named zone's rule under exactly one profile bit or the
// all-profiles default (never a combination), so an exact-equality test is what
// keeps a specific zone's rules disjoint from another zone's and from an
// all-profiles rule. Testing overlap instead (fr.Profiles&profile != 0) would
// let a single-zone query and, worse, a single-zone RemoveRule/Sync match and
// delete an all-profiles rule — silently affecting every other zone too.
func (f *WF) profileMatches(rulesProfiles, filterProfile int32, useFilter bool) bool {
	if !useFilter {
		return true
	}
	return rulesProfiles == filterProfile
}

// GetRules returns the existing filter rules from the zone.
func (f *WF) GetRules(ctx context.Context, zoneName string) (rules []*Rule, err error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	fwRules, err := wapi.FirewallRulesGet()
	if err != nil {
		return nil, fmt.Errorf("failed to fetch firewall rules: %w", err)
	}

	// Filter by profile if a zone names one.
	filterProfile, useFilter := f.profileFilter(zoneName)

	// Parse all rules. Windows ships hundreds of built-in rules; rather than hide
	// them, every rule is surfaced with HasPrefix reporting whether this manager
	// tagged it (identified by the configured name prefix), so callers can tell
	// them apart.
	for _, fr := range fwRules {
		// If filtered by profile, skip rules not scoped to exactly this profile.
		if !f.profileMatches(fr.Profiles, filterProfile, useFilter) {
			continue
		}

		// Decode the rule and skip it if it cannot be decoded.
		r := f.UnmarshallFWRule(fr)
		if r == nil {
			continue
		}
		r.HasPrefix = f.hasPrefix(fr)

		// Add decoded rule to list.
		rules = append(rules, r)
	}

	// Every filter above is reported as WFP stores it. WFP has no per-rule family
	// selector, so a FamilyAny rule is one dual-family filter and reads back as
	// FamilyAny on its own. Its protocol field carries a single protocol number and
	// its direction field a single direction, so a TCPUDP rule is a tcp filter plus a
	// udp filter and a DirAny rule an inbound plus an outbound filter — each reported
	// as its own rule.
	return rules, nil
}

// validateRule reports whether the Windows Filtering Platform can express the
// filter rule, applying the universal Rule.validate and then the WFP-specific
// shape constraints, so MarshallFWRule builds a rule already known to be
// expressible. The per-rule logging/limit gate stays in AddRule/RemoveRule
// (rejectLogAndLimit), which is where those requests are rejected today.
func (f *WF) validateRule(r *Rule) error {
	if err := r.validate(); err != nil {
		return err
	}
	// A WFP filter carries one protocol number, so the TCPUDP protocol has no
	// single-filter form; AddRule/RemoveRule fan it into a tcp filter and a udp
	// filter with expandProtocols first, so a TCPUDP rule here means that fan-out
	// was skipped.
	if err := r.CheckExpandedProtocol(); err != nil {
		return err
	}
	// The Windows Firewall rule model has only inbound and outbound directions;
	// forwarded (routed) traffic is handled out of band (RRAS/portproxy).
	if r.IsForward() {
		return unsupportedForward("windows firewall")
	}
	// A WFP filter likewise carries one direction; AddRule/RemoveRule fan a DirAny
	// rule out first, so a DirAny rule here means that fan-out was skipped.
	if r.Direction == DirAny {
		return fmt.Errorf("a both-directions rule must be expanded before marshalling")
	}
	// Windows only matches ports for TCP and UDP; a port on any other protocol
	// (e.g. SCTP) has no representation, so reject rather than silently drop it.
	if (r.HasPorts() || r.HasSourcePorts()) && r.Proto != TCP && r.Proto != UDP {
		return fmt.Errorf("windows firewall only matches ports for tcp or udp: %w", ErrUnsupported)
	}
	// Features this backend cannot express are rejected up front rather than
	// silently dropped. Windows firewall rules are stateful by default, and the
	// go-win64api binding cannot set the interface fields, so neither a
	// connection-state nor a per-rule interface match is expressible here.
	if r.State != 0 {
		return fmt.Errorf("windows firewall does not support connection-state matching in this model: %w", ErrUnsupportedState)
	}
	if r.InInterface != "" || r.OutInterface != "" {
		return fmt.Errorf("windows firewall does not support per-rule interface matching in this model: %w", ErrUnsupportedInterface)
	}
	// WFP has no reject action; mapping Reject to Drop would make a rule added as
	// Reject unreadable as Reject and impossible to reconcile.
	if r.Action == Reject {
		return fmt.Errorf("windows firewall has no reject action: %w", ErrUnsupported)
	}
	// WFP cannot express address negation (decodeAddress rejects a '!'-prefixed
	// token on read), so reject it rather than passing an invalid address string to
	// Windows and producing a rule that can never be read back or removed.
	if strings.HasPrefix(strings.TrimSpace(r.Source), "!") || strings.HasPrefix(strings.TrimSpace(r.Destination), "!") {
		return fmt.Errorf("windows firewall does not support address negation in this model: %w", ErrUnsupported)
	}
	// A WFP rule carries an IP family only through an address or an ICMP protocol.
	// An explicit Family with neither cannot be honored: applying the rule to both
	// families widens it, and it reads back as FamilyAny so it can never reconcile.
	if r.Family != FamilyAny && !r.Proto.IsICMP() &&
		familyOfAddr(r.Source) == FamilyAny && familyOfAddr(r.Destination) == FamilyAny {
		return fmt.Errorf("windows firewall cannot scope a rule to an IP family without an address; use family any or add an address: %w", ErrUnsupported)
	}
	return nil
}

// MarshallFWRule encodes a Rule as a Windows FWRule for the given zone. It is a
// pure encoder: callers run validateRule on the fanned-out rule first.
func (f *WF) MarshallFWRule(zoneName string, r *Rule) (*wapi.FWRule, error) {
	// Setup base rule. A user comment is carried in the filter description;
	// otherwise the managed default marks the rule as ours.
	fwRule := &wapi.FWRule{
		Description: wfManagedDescription,
		Enabled:     true,
	}
	if r.Comment != "" {
		fwRule.Description = r.Comment
	}

	// Base rule name.
	// Format: [prefix] [dir] [proto] [port X] [from S] [to D] [allow/block]
	var nameParts []string
	if f.rulePrefix != "" {
		nameParts = append(nameParts, f.rulePrefix)
	}

	// Set the profile based on provided zone, and fold the profile into the rule
	// name. RemoveRule deletes by name, so two otherwise-identical rules added to
	// different profiles must get distinct names — otherwise removing one deletes
	// the other. An all-profiles (default) rule keeps the plain name.
	switch strings.ToLower(zoneName) {
	case "private":
		fwRule.Profiles = wapi.NET_FW_PROFILE2_PRIVATE
		nameParts = append(nameParts, "private")
	case "public":
		fwRule.Profiles = wapi.NET_FW_PROFILE2_PUBLIC
		nameParts = append(nameParts, "public")
	case "domain":
		fwRule.Profiles = wapi.NET_FW_PROFILE2_DOMAIN
		nameParts = append(nameParts, "domain")
	default:
		fwRule.Profiles = wapi.NET_FW_PROFILE2_ALL
	}

	// Based on the rule direction.
	if r.IsOutput() {
		nameParts = append(nameParts, "out")
		fwRule.Direction = wapi.NET_FW_RULE_DIR_OUT
	} else {
		nameParts = append(nameParts, "in")
		fwRule.Direction = wapi.NET_FW_RULE_DIR_IN
	}

	// Set the protocol.
	fwRule.Protocol = wapi.NET_FW_IP_PROTOCOL_ANY
	switch r.Proto {
	case TCP:
		fwRule.Protocol = wapi.NET_FW_IP_PROTOCOL_TCP
		nameParts = append(nameParts, "tcp")
	case UDP:
		fwRule.Protocol = wapi.NET_FW_IP_PROTOCOL_UDP
		nameParts = append(nameParts, "udp")
	case ICMP:
		fwRule.Protocol = wapi.NET_FW_IP_PROTOCOL_ICMPv4
		nameParts = append(nameParts, "icmp")
	case ICMPv6:
		fwRule.Protocol = wapi.NET_FW_IP_PROTOCOL_ICMPv6
		nameParts = append(nameParts, "icmpv6")
	case SCTP:
		fwRule.Protocol = wfProtocolSCTP
		nameParts = append(nameParts, "sctp")
	case GRE:
		fwRule.Protocol = wfProtocolGRE
		nameParts = append(nameParts, "gre")
	case ESP:
		fwRule.Protocol = wfProtocolESP
		nameParts = append(nameParts, "esp")
	case AH:
		fwRule.Protocol = wfProtocolAH
		nameParts = append(nameParts, "ah")
	}

	// An ICMP type match is expressed via the ICMPTypesAndCodes field as
	// "type:code"; a "*" code matches every code of that type.
	if r.Proto.IsICMP() && r.ICMPType != nil {
		fwRule.ICMPTypesAndCodes = fmt.Sprintf("%d:*", *r.ICMPType)
		nameParts = append(nameParts, "type", fmt.Sprintf("%d", *r.ICMPType))
	}

	// If TCP/UDP, and a port set is defined, add the ports. Windows firewall
	// accepts a comma list with dash ranges (e.g. "80,443,1000-2000").
	dstSpecs := r.PortSpecs()
	if (r.Proto == TCP || r.Proto == UDP) && len(dstSpecs) > 0 {
		portS := FormatPortRanges(dstSpecs, ",")
		nameParts = append(nameParts, "port", portS)

		// Set remote/local based on direction.
		if r.IsOutput() {
			fwRule.RemotePorts = portS
		} else {
			fwRule.LocalPorts = portS
		}
	}

	// Source ports are mapped to the opposite side of direction.
	srcSpecs := r.SourcePortSpecs()
	if (r.Proto == TCP || r.Proto == UDP) && len(srcSpecs) > 0 {
		portS := FormatPortRanges(srcSpecs, ",")
		nameParts = append(nameParts, "sport", portS)

		if r.IsOutput() {
			fwRule.LocalPorts = portS
		} else {
			fwRule.RemotePorts = portS
		}
	}

	// Add addresses according to direction due to difference in local/remote vs source/dest.
	if r.IsOutput() {
		fwRule.LocalAddresses = r.Source
		fwRule.RemoteAddresses = r.Destination
	} else {
		fwRule.RemoteAddresses = r.Source
		fwRule.LocalAddresses = r.Destination
	}

	// Append addresses to name if present.
	if r.Source != "" {
		nameParts = append(nameParts, "from", r.Source)
	}
	if r.Destination != "" {
		nameParts = append(nameParts, "to", r.Destination)
	}

	// Set the rule action.
	if r.Action == Accept {
		nameParts = append(nameParts, "allow")
		fwRule.Action = wapi.NET_FW_ACTION_ALLOW
	} else {
		nameParts = append(nameParts, "block")
		fwRule.Action = wapi.NET_FW_ACTION_BLOCK
	}

	fwRule.Name = strings.Join(nameParts, " ")

	// Set the grouping.
	fwRule.Grouping = f.rulePrefix

	return fwRule, nil
}

// rejectLogAndLimit reports a logging or rate/connection-limit request on a
// backend whose per-rule model cannot express it. Such a rule is rejected
// rather than applied without the modifier. It returns nil when the rule asks
// for none of these. backend names the backend for the error message. WFP is
// the only such backend, so the helper lives here beside its caller.
func (r *Rule) rejectLogAndLimit(backend string) error {
	switch {
	case r.Log:
		return fmt.Errorf("%s does not support per-rule logging in this model: %w", backend, ErrUnsupportedLog)
	case r.RateLimit != nil:
		return fmt.Errorf("%s does not support rate limiting in this model: %w", backend, ErrUnsupportedRateLimit)
	case r.ConnLimit != nil:
		return fmt.Errorf("%s does not support connection limiting in this model: %w", backend, ErrUnsupportedConnLimit)
	}
	return nil
}

// AddRule adds a filter rule scoped to the zone's Windows profile (or the
// all-profiles default for an unnamed zone). It is idempotent: an equivalent
// existing rule makes it a no-op.
func (f *WF) AddRule(ctx context.Context, zoneName string, r *Rule) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	if r == nil {
		return fmt.Errorf("rule cannot be nil")
	}

	// A TCPUDP rule fans out into a tcp filter plus a udp filter; a WFP filter
	// carries one protocol number, so it has no single-filter form.
	if r.Proto == TCPUDP {
		for _, sub := range expandProtocols(r) {
			if err := f.AddRule(ctx, zoneName, sub); err != nil {
				return err
			}
		}
		return nil
	}

	// A DirAny rule fans out into an inbound filter plus its role-swapped outbound
	// filter; WFP stores each direction as its own rule object.
	if r.Direction == DirAny {
		for _, sub := range expandDirections(r) {
			if err := f.AddRule(ctx, zoneName, sub); err != nil {
				return err
			}
		}
		return nil
	}

	if err := r.rejectLogAndLimit(f.Type()); err != nil {
		return err
	}

	// Verify the rule is valid for WFP. The fan-outs above run first: validateRule
	// asserts the TCPUDP split has already happened.
	if err := f.validateRule(r); err != nil {
		return err
	}

	// Encode the rule.
	fwRule, err := f.MarshallFWRule(zoneName, r)
	if err != nil {
		return fmt.Errorf("failed to marshall rule: %w", err)
	}

	// Skip if an equivalent rule already exists: Windows rejects a duplicate rule
	// name, and AddRule is expected to be idempotent like the other backends.
	if existing, gerr := f.GetRules(ctx, zoneName); gerr == nil {
		for _, e := range existing {
			// Any equivalent rule already in the firewall counts as a duplicate
			// (Windows rejects a duplicate rule name), so the add stays idempotent.
			if e.EqualBase(r, true) {
				return nil
			}
		}
	}

	// Attempt to add the rule. FirewallRuleAddAdvanced reports success=false with a
	// nil error in exactly one case: a rule already exists under this exact Name;
	// every other failure carries a non-nil error. That is a benign duplicate (a
	// name collision the EqualBase check above missed, e.g. a concurrent or foreign
	// add), so treat it as a no-op rather than a failure.
	success, err := wapi.FirewallRuleAddAdvanced(*fwRule)
	if err != nil {
		return fmt.Errorf("failed to add firewall rule %q: %w", fwRule.Name, err)
	}
	if !success {
		return nil
	}

	return nil
}

// InsertRule is unsupported: Windows Filtering Platform rules are not
// positionally ordered in the same way as iptables/nftables.
func (f *WF) InsertRule(ctx context.Context, zoneName string, position int, r *Rule) error {
	return unsupportedOrdering(f.Type())
}

// MoveRule is unsupported for the same reason as InsertRule.
func (f *WF) MoveRule(ctx context.Context, zoneName string, r *Rule, position int) error {
	return unsupportedOrdering(f.Type())
}

// RemoveRule removes a rule from the zone.
func (f *WF) RemoveRule(ctx context.Context, zoneName string, r *Rule) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	// A TCPUDP target removes both its tcp filter and its udp filter; WFP stores only
	// concrete-protocol filters, so removing the tcp half leaves the udp filter and
	// vice versa (the surviving transport re-adds nothing, unlike a container backend).
	if r.Proto == TCPUDP {
		for _, sub := range expandProtocols(r) {
			if err := f.RemoveRule(ctx, zoneName, sub); err != nil {
				return err
			}
		}
		return nil
	}

	// A DirAny target removes both its inbound and its role-swapped outbound filter.
	if r.Direction == DirAny {
		for _, sub := range expandDirections(r) {
			if err := f.RemoveRule(ctx, zoneName, sub); err != nil {
				return err
			}
		}
		return nil
	}

	// A WFP rule carries an IP family only through an address or an ICMP protocol,
	// so a concrete-family rule with neither is unexpressible (see AddRule) — and a
	// FamilyAny bare rule is stored as one dual-family filter. A concrete-family
	// removal of that shape could only be honored by dropping the dual filter, which
	// takes the untargeted family with it; the surviving single-family rule cannot
	// be re-added without an address. Reject it rather than over-remove.
	if r.Family != FamilyAny && !r.Proto.IsICMP() &&
		familyOfAddr(r.Source) == FamilyAny && familyOfAddr(r.Destination) == FamilyAny {
		return fmt.Errorf("windows firewall cannot scope a removal to an IP family without an address; use family any or add an address: %w", ErrUnsupported)
	}

	// Get a list of existing rules.
	fwRules, err := wapi.FirewallRulesGet()
	if err != nil {
		return fmt.Errorf("failed to list rules for deletion: %w", err)
	}

	// Scope the deletion to the same profile GetRules/AddRule use for this zone, so
	// each zone stays isolated: the manager adds and lists rules per profile, so it
	// must also remove them per profile. profileMatches' exact-equality match (not
	// overlap) is what keeps this from also deleting an all-profiles rule when
	// zoneName names a single zone.
	filterProfile, useFilter := f.profileFilter(zoneName)

	// Windows deletes by name and removes the FIRST rule bearing it, so a name
	// shared with a rule this removal did not match (a per-profile twin of a
	// built-in rule, say) could destroy the wrong rule. Count each name's holders
	// and how many of them this removal matches: when every holder matches,
	// repeated by-name deletes are safe; otherwise the delete is ambiguous and is
	// refused rather than risked.
	nameTotal := map[string]int{}
	nameMatched := map[string]int{}
	type target struct{ name string }
	var targets []target
	for _, fr := range fwRules {
		nameTotal[fr.Name]++

		// Skip rules outside the target profile, matching GetRules' filter.
		if !f.profileMatches(fr.Profiles, filterProfile, useFilter) {
			continue
		}

		// Decode the rule, and skip if it can't be decoded.
		rule := f.UnmarshallFWRule(fr)
		if rule == nil {
			continue
		}

		// EqualBase ignores the IP family because Windows records a concrete
		// family on the rule it lists back even when the added rule left it unset
		// (mirroring GetRules). Removal is idempotent, matching the other
		// backends: a rule that is not present is not an error.
		if r.EqualBase(rule, true) {
			nameMatched[fr.Name]++
			targets = append(targets, target{fr.Name})
		}
	}
	for _, t := range targets {
		if nameTotal[t.name] != nameMatched[t.name] {
			return fmt.Errorf("cannot delete rule %q: another rule shares the name and windows deletes by name", t.name)
		}
		ok, err := wapi.FirewallRuleDelete(t.name)
		if err != nil {
			return fmt.Errorf("failed to delete rule %q: %w", t.name, err)
		}
		if !ok {
			return fmt.Errorf("failed to delete rule %q: reported failure", t.name)
		}
	}

	return nil
}

// GetNATRules is unsupported; WFP is a stateful packet filter only and NAT on
// Windows is handled out of band (netsh portproxy or RRAS).
func (f *WF) GetNATRules(ctx context.Context, zoneName string) ([]*NATRule, error) {
	return nil, unsupportedNAT(f.Type())
}

// AddNATRule is unsupported; the Windows firewall backend has no NAT (see GetNATRules).
func (f *WF) AddNATRule(ctx context.Context, zoneName string, r *NATRule) error {
	return unsupportedNAT(f.Type())
}

// InsertNATRule is unsupported; the Windows firewall backend has no NAT (see GetNATRules).
func (f *WF) InsertNATRule(ctx context.Context, zoneName string, position int, r *NATRule) error {
	return unsupportedNAT(f.Type())
}

// MoveNATRule is unsupported; the Windows firewall backend has no NAT (see GetNATRules).
func (f *WF) MoveNATRule(ctx context.Context, zoneName string, r *NATRule, position int) error {
	return unsupportedNAT(f.Type())
}

// RemoveNATRule is unsupported; the Windows firewall backend has no NAT (see GetNATRules).
func (f *WF) RemoveNATRule(ctx context.Context, zoneName string, r *NATRule) error {
	return unsupportedNAT(f.Type())
}

// GetDefaultPolicy is unsupported; the Windows firewall exposes no default policy in this model.
func (f *WF) GetDefaultPolicy(ctx context.Context, zoneName string) (*DefaultPolicy, error) {
	return nil, unsupportedPolicy(f.Type())
}

// SetDefaultPolicy is unsupported; the Windows firewall exposes no default policy in this model.
func (f *WF) SetDefaultPolicy(ctx context.Context, zoneName string, policy *DefaultPolicy) error {
	return unsupportedPolicy(f.Type())
}

// GetAddressSets is unsupported; the Windows firewall backend has no address sets.
func (f *WF) GetAddressSets(ctx context.Context) ([]*AddressSet, error) {
	return nil, unsupportedSet(f.Type())
}

// GetAddressSet is unsupported; the Windows firewall backend has no address sets.
func (f *WF) GetAddressSet(ctx context.Context, name string) (*AddressSet, error) {
	return nil, unsupportedSet(f.Type())
}

// AddAddressSet is unsupported; the Windows firewall backend has no address sets.
func (f *WF) AddAddressSet(ctx context.Context, set *AddressSet) error {
	return unsupportedSet(f.Type())
}

// RemoveAddressSet is unsupported; the Windows firewall backend has no address sets.
func (f *WF) RemoveAddressSet(ctx context.Context, name string) error {
	return unsupportedSet(f.Type())
}

// AddAddressSetEntry is unsupported; the Windows firewall backend has no address sets.
func (f *WF) AddAddressSetEntry(ctx context.Context, name, entry string) error {
	return unsupportedSet(f.Type())
}

// RemoveAddressSetEntry is unsupported; the Windows firewall backend has no address sets.
func (f *WF) RemoveAddressSetEntry(ctx context.Context, name, entry string) error {
	return unsupportedSet(f.Type())
}

// Backup captures every decodable filter rule in the zone, foreign rules
// included; the library manages the actual firewall state.
func (f *WF) Backup(ctx context.Context, zoneName string) (*Backup, error) {
	rules, err := f.GetRules(ctx, zoneName)
	if err != nil {
		return nil, err
	}
	// Backup captures the full filter rule state; Restore reconciles the live rules
	// to this set, so every rule read is preserved.
	return &Backup{Rules: rules}, nil
}

// Restore replaces the managed rules with the contents of a Backup.
func (f *WF) Restore(ctx context.Context, zoneName string, backup *Backup) error {
	if backup == nil {
		return fmt.Errorf("backup cannot be nil")
	}

	// Reconcile the live rule set to the backup with a minimal add/remove diff
	// rather than removing every rule and re-adding it. Removing all rules first
	// leaves a window with no matching filter, and WFP drops in-flight connections
	// that no longer match one — including a foreign inbound-allow rule the backup
	// itself captured (e.g. the rule keeping this host reachable over SSH while a
	// remote restore runs). Sync leaves a rule present in both the firewall and the
	// backup untouched, so such a rule is never briefly removed. WFP has no NAT, so
	// backup.NATRules is not applied here.
	_, _, err := Sync(ctx, f, zoneName, backup.Rules)
	return err
}

// Reload is a no-op; Windows Firewall applies rule changes immediately.
func (f *WF) Reload(ctx context.Context) error {
	return nil
}

// Close releases any resources held by the backend; the Windows firewall holds none.
func (f *WF) Close(ctx context.Context) error {
	return nil
}
