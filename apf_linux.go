package firewall

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
)

const (
	APFConf  = "/etc/apf/conf.apf"
	APFAllow = "/etc/apf/allow_hosts.rules"
	APFDeny  = "/etc/apf/deny_hosts.rules"
	// APFPreroute and APFPostroute are apf's user routing-rule files, sourced as
	// shell during a (re)start. Like the pre-hook below, this backend uses them as a
	// raw-iptables fallback for rules apf's native config and allow/deny files cannot
	// express — here the routing-stage cases, which in practice are NAT: destination
	// NAT (DNAT/Redirect) is written into preroute.rules and source NAT
	// (SNAT/Masquerade) into postroute.rules.
	APFPreroute  = "/etc/apf/preroute.rules"
	APFPostroute = "/etc/apf/postroute.rules"
	// APFHook is apf's pre-hook, run after the flush but before apf adds its own
	// rules. This library writes the iptables rules for features apf's native
	// config cannot express directly into this hook.
	APFHook = "/etc/apf/hook_pre.sh"
)

// APF manages the firewall through apf's config files and a managed pre-hook.
type APF struct {
	ConfigChanged bool
	// rulePrefix tags rules this library creates so they can be told apart
	// from foreign rules. In allow_hosts.rules/deny_hosts.rules it is
	// prepended to the comment written on the line above each rule;
	// conf.apf port/icmp-list rules carry no per-rule comment and so
	// cannot carry the tag.
	rulePrefix string
	// ipv6Enabled mirrors conf.apf's USE_IPV6. With it off (the shipped default) apf
	// enforces no IPv6 at all: its shell logic no-ops a bare IPv6 host in
	// allow_hosts.rules/deny_hosts.rules (apf_trust.sh trust_hosts()) and the native
	// IG_ICMPV6_TYPES/EG_ICMPV6_TYPES lists (cports.common), and ip6tables is never
	// flushed on (re)load (apf_ipt.sh ipt6()) — so a hook-injected ip6tables line
	// would be re-appended on every reload and outlive its own removal. AddRule
	// therefore rejects every concrete-IPv6 rule rather than write one apf will
	// never enforce.
	ipv6Enabled bool
	// stopActions caches conf.apf's STOP settings, loaded on first use:
	// deny_hosts commonly holds thousands of entries and each parsed line
	// consults a STOP action, so per-line conf reads are avoided. The library
	// never writes these keys.
	stopActions map[string]Action
}

// NewAPF verifies apf is installed and active, then returns a manager bound to rulePrefix.
func NewAPF(ctx context.Context, rulePrefix string) (*APF, error) {
	apf := new(APF)
	apf.rulePrefix = rulePrefix

	// Confirm apf is enabled under whatever init system the host uses
	// (systemd, chkconfig, update-rc.d, OpenRC, Slackware rc.d, or rc.local).
	if !serviceEnabled(ctx, "apf") {
		return nil, fmt.Errorf("the apf service is not active or enabled on this server")
	}

	// Confirm config files exist.
	files := []string{APFConf, APFAllow, APFDeny}
	for _, f := range files {
		if _, err := os.Stat(f); err != nil {
			return nil, fmt.Errorf("the config file %s is missing", f)
		}
	}

	// Read whether apf's own IPv6 handling is turned on.
	useIPv6, err := readConfValue(APFConf, "USE_IPV6")
	if err != nil {
		return nil, fmt.Errorf("error reading %s: %s", APFConf, err)
	}
	apf.ipv6Enabled = useIPv6 == "1"

	// Return the new apf object.
	return apf, nil
}

// Type returns the backend identifier for apf.
func (f *APF) Type() string {
	return APFType
}

// Capabilities reports the firewall features apf supports.
func (f *APF) Capabilities() Capabilities {
	return Capabilities{
		Output:  true,
		Forward: true,
		// IPv6 mirrors ipv6Enabled: with conf.apf's USE_IPV6 off, apf never
		// touches ip6tables — an IG_ICMPV6_TYPES entry yields no rule — so neither
		// its native config nor the raw-iptables hook yields a rule apf will keep
		// in sync across a reload (see ipv6Enabled).
		IPv6:                 f.ipv6Enabled,
		PortPair:             true,
		ConnState:            true,
		InterfaceMatch:       true,
		Logging:              true,
		RateLimit:            true,
		ConnLimit:            true,
		NAT:                  true,
		RuleOrdering:         false,
		DefaultPolicy:        false,
		RuleCounters:         true,
		AddressSets:          true,
		Comments:             true,
		Negation:             true,
		RejectAction:         true,
		FamilyWithoutAddress: true,
		// A deny_hosts.rules entry stores no action; apf applies conf.apf's
		// ALL_STOP action, so removal matches an entry whatever action is named.
		DenyActionFromConfig: true,
	}
}

// GetZone returns no zone; apf has no zone support.
func (f *APF) GetZone(ctx context.Context, iface string) (zoneName string, err error) {
	return "", nil
}

// parsePortToken parses a single apf port token: a port or an underscore
// range (e.g. "6000_7000").
func (f *APF) parsePortToken(tok string) (PortRange, error) {
	lo, hi, isRange := strings.Cut(strings.TrimSpace(tok), "_")
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
			return PortRange{}, fmt.Errorf("port range end below start")
		}
	}
	return pr, nil
}

// ParseConnLimit decodes a conf.apf IG_TCP_CLIMIT/IG_UDP_CLIMIT value
// ("port:limit,...", port may be an underscore range) into connection-limit
// rules: apf caps concurrent connections per source and rejects the excess, so
// each entry becomes an inbound reject rule carrying a per-source ConnLimit.
func (f *APF) ParseConnLimit(val string, proto Protocol) (rules []*Rule) {
	for _, entry := range strings.Split(val, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		portTok, limitTok, ok := strings.Cut(entry, ":")
		if !ok {
			continue
		}
		pr, err := f.parsePortToken(strings.TrimSpace(portTok))
		if err != nil {
			continue
		}
		limit, err := strconv.ParseUint(strings.TrimSpace(limitTok), 10, 32)
		if err != nil {
			continue
		}
		// Like the CPORTS lists, IG_TCP_CLIMIT/IG_UDP_CLIMIT are dual-stack, so a
		// connection-limit entry carries no family of its own. Report FamilyAny so a
		// FamilyAny desired connlimit rule reconciles with its read-back. (APF has no
		// egress connection-limit config; connlimit applies only on the input chain.)
		rule := &Rule{
			Family:    FamilyAny,
			Proto:     proto,
			Action:    Reject,
			ConnLimit: &ConnLimit{Count: uint(limit), PerSource: true},
		}
		portSpecsToRule(rule, []PortRange{pr})
		rules = append(rules, rule)
	}
	return
}

// ParseICMPTypes decodes an apf ICMP type list (IG_ICMP_TYPES/EG_ICMP_TYPES for
// proto ICMP, IG_ICMPV6_TYPES/EG_ICMPV6_TYPES for proto ICMPv6) into accept rules,
// one per type. The "all" wildcard (which apf applies as a typeless `-p icmp -j
// ACCEPT`) becomes a rule with a nil ICMPType, matching every type.
func (f *APF) ParseICMPTypes(val string, proto Protocol, dir Direction) (rules []*Rule) {
	fam := IPv4
	if proto == ICMPv6 {
		fam = IPv6
	}
	for _, tok := range strings.Split(val, ",") {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			continue
		}
		rule := &Rule{Family: fam, Proto: proto, Direction: dir, Action: Accept}
		if !strings.EqualFold(tok, "all") {
			n, ok := parseICMPTypeFamily(tok, proto == ICMPv6)
			if !ok {
				continue
			}
			rule.ICMPType = Ptr(n)
		}
		rules = append(rules, rule)
	}
	return
}

// parseAddr parses an apf address value, stripping the bracket notation used
// to protect IPv6 addresses, and normalizing a zero-network to the empty (any)
// address. It reports the family, or false when the value is not an address.
func (f *APF) parseAddr(v string) (addr string, fam Family, ok bool) {
	if strings.HasPrefix(v, "[") && strings.HasSuffix(v, "]") {
		v = v[1 : len(v)-1]
	}
	_, network, err := net.ParseCIDR(v)
	ip := net.ParseIP(v)
	if err != nil && ip == nil {
		return "", FamilyAny, false
	}
	family := IPv4
	if (network != nil && network.IP.To4() == nil) || (ip != nil && ip.To4() == nil) {
		family = IPv6
	}
	// A zero network (0.0.0.0/0 or ::/0) means "any", represented as empty.
	if network != nil {
		ones, _ := network.Mask.Size()
		if ones == 0 && network.IP.IsUnspecified() {
			return "", family, true
		}
	}
	return v, family, true
}

// parseStopAction maps a conf.apf ALL_STOP/TCP_STOP/UDP_STOP value to the
// action apf actually applies. "DROP", "REJECT" and "PROHIBIT" are valid;
// anything else (including empty) falls back to the stock default of DROP.
// PROHIBIT jumps to apf's own PROHIBIT chain, which rejects with an ICMP
// (un)reachable-prohibited response — the same reject-like semantics as
// REJECT, just a different ICMP code — so it maps to Reject rather than Drop;
// this model has no third action to give it.
func (f *APF) parseStopAction(val string) Action {
	switch strings.ToUpper(trimQuotes(strings.TrimSpace(val))) {
	case "REJECT", "PROHIBIT":
		return Reject
	default:
		return Drop
	}
}

// readStopAction reads the named STOP setting (ALL_STOP/TCP_STOP/UDP_STOP)
// from a conf.apf-format file, defaulting to the stock DROP when the key is
// absent or the file cannot be read.
func (f *APF) readStopAction(path, key string) Action {
	action := Drop
	fd, err := os.Open(path)
	if err != nil {
		return action
	}
	defer func() { _ = fd.Close() }()

	scanner := bufio.NewScanner(fd)
	for scanner.Scan() {
		line := scanner.Text()
		if ci := strings.IndexByte(line, '#'); ci >= 0 {
			line = line[:ci]
		}
		k, val, found := strings.Cut(strings.TrimSpace(line), "=")
		if !found {
			continue
		}
		if strings.TrimSpace(k) != key {
			continue
		}
		action = f.parseStopAction(val)
	}
	return action
}

// stopKey names the conf.apf setting apf actually applies to a deny of the
// given protocol. A bare-address deny_hosts entry (no protocol/port) is dropped
// by trust_hosts's own bare-host branch, which applies ALL_STOP directly. An
// advanced entry (proto:flow:s/d=port:s/d=ip) is instead routed through
// trust_entry_rule, which ignores ALL_STOP entirely and applies TCP_STOP for a
// tcp entry or UDP_STOP for a udp one (files/internals/apf_trust.sh). The three
// settings default to DROP and are otherwise fully independent, so an entry read
// or matched under the wrong key can report or accept the wrong action whenever
// an operator sets them differently.
func (f *APF) stopKey(proto Protocol) string {
	switch proto {
	case TCP:
		return "TCP_STOP"
	case UDP:
		return "UDP_STOP"
	default:
		return "ALL_STOP"
	}
}

// confStopActions returns conf.apf's three STOP settings, read once per manager
// and cached (see the stopActions field).
func (f *APF) confStopActions() map[string]Action {
	if f.stopActions == nil {
		f.stopActions = map[string]Action{
			"ALL_STOP": f.readStopAction(APFConf, "ALL_STOP"),
			"TCP_STOP": f.readStopAction(APFConf, "TCP_STOP"),
			"UDP_STOP": f.readStopAction(APFConf, "UDP_STOP"),
		}
	}
	return f.stopActions
}

// denyActionFor returns the action apf applies to a deny of the given protocol,
// from conf.apf's STOP settings (see stopKey).
func (f *APF) denyActionFor(proto Protocol) Action {
	stops := f.confStopActions()
	// A TCPUDP deny is one protocol-less advanced line, which apf applies with
	// TCP_STOP on the tcp rule it derives and UDP_STOP on the udp one. It therefore
	// has a single native action only when the two settings agree; when they differ
	// the rule cannot be one Rule with one Action, so report ActionInvalid and let
	// addRule route it to the hook, whose lines carry the action verbatim.
	if proto == TCPUDP {
		if stops["UDP_STOP"] != stops["TCP_STOP"] {
			return ActionInvalid
		}
		return stops["TCP_STOP"]
	}
	return stops[f.stopKey(proto)]
}

// resolveAction resolves the action to stamp on a rule parsed from — or
// matched against — allow_hosts/deny_hosts. base is Accept for allow_hosts
// (returned unchanged, since parseStopAction never yields Accept and
// allow_hosts has no per-protocol distinction) or the ALL_STOP-derived action
// for deny_hosts. A deny_hosts entry in apf's advanced syntax with a concrete
// tcp or udp protocol is not governed by ALL_STOP (see stopKey), so its
// action is re-derived from the matching TCP_STOP/UDP_STOP setting instead.
func (f *APF) resolveAction(base Action, proto Protocol) Action {
	if base == Accept {
		return base
	}
	switch proto {
	case TCP, UDP, TCPUDP:
		// denyActionFor reports ActionInvalid for a TCPUDP rule whose TCP_STOP and
		// UDP_STOP disagree — the signal addRule uses to route such a rule to the hook,
		// since no single native line carries two actions. A rule being read back still
		// needs a usable action, so fall back to the file's own (a foreign
		// protocol-less deny line written outside this library can hit this).
		if a := f.denyActionFor(proto); a != ActionInvalid {
			return a
		}
		return base
	default:
		return base
	}
}

// splitAdvFields splits an apf advanced rule on ':' while leaving colons inside
// bracketed IPv6 addresses (e.g. [2001:db8::1]) intact.
func (f *APF) splitAdvFields(s string) []string {
	var fields []string
	depth, start := 0, 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '[':
			depth++
		case ']':
			if depth > 0 {
				depth--
			}
		case ':':
			if depth == 0 {
				fields = append(fields, s[start:i])
				start = i + 1
			}
		}
	}
	return append(fields, s[start:])
}

// ParseAdvRule decodes an apf advanced allow/deny rule of the form
// proto:flow:s/d=port:s/d=ip. IPv6 addresses use bracket notation.
func (f *APF) ParseAdvRule(val string, action Action) (r *Rule) {
	r = &Rule{}

	for _, fld := range f.splitAdvFields(val) {
		switch {
		case strings.EqualFold(fld, "tcp"):
			r.Proto = TCP
		case strings.EqualFold(fld, "udp"):
			r.Proto = UDP
		case strings.EqualFold(fld, "in"):
			r.Direction = DirInput
		case strings.EqualFold(fld, "out"):
			r.Direction = DirOutput
		case strings.HasPrefix(fld, "s="):
			// The source field is either an address or, when it is not, a source
			// port (a single port or an underscore range; apf's port field takes
			// no comma list).
			v := strings.TrimPrefix(fld, "s=")
			if addr, fam, ok := f.parseAddr(v); ok {
				r.Family = fam
				r.Source = addr
				continue
			}
			pr, err := f.parsePortToken(v)
			if err != nil {
				return nil
			}
			sourcePortSpecsToRule(r, []PortRange{pr})
		case strings.HasPrefix(fld, "d="):
			// Mirror the s= branch: the destination field is either an address or a
			// single destination port (a single port or an underscore range; apf's
			// port field takes no comma list).
			v := strings.TrimPrefix(fld, "d=")
			if addr, fam, ok := f.parseAddr(v); ok {
				r.Family = fam
				r.Destination = addr
				continue
			}
			pr, err := f.parsePortToken(v)
			if err != nil {
				return nil
			}
			portSpecsToRule(r, []PortRange{pr})
		}
	}

	// An advanced line with no protocol field covers both transports: apf's trust
	// parser derives a `-p tcp` rule and a `-p udp` rule from it. Report that as
	// TCPUDP, not ProtocolAny, so the rule reads back as the one that was written and
	// is not mistaken for an every-protocol match.
	if r.Proto == ProtocolAny {
		r.Proto = TCPUDP
	}

	// The action depends on the protocol just parsed (see resolveAction), so
	// it is resolved last rather than stamped up front.
	r.Action = f.resolveAction(action, r.Proto)

	return
}

// ParseIPList reads an apf allow_hosts/deny_hosts file and returns the rules it
// holds, each carrying any full-line comment that precedes it (see
// scanCommentGroups for the comment-attachment convention).
func (f *APF) ParseIPList(filePath string, action Action) (rules []*Rule, err error) {
	// Read the allow_hosts/deny_hosts rule list.
	fd, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer func() { _ = fd.Close() }()

	err = scanCommentGroups(fd, f.rulePrefix, nil, func(g commentGroup) error {
		// Strip an inline trailing comment (not a rule comment).
		line := trimInlineComment(g.line)
		if line == "" {
			return nil
		}
		// parseListLine classifies an advanced (s=/d= option) line or a plain
		// address line — one bidirectional DirAny rule authored in the inbound
		// frame (Source=X) — and skips anything else.
		rule := f.parseListLine(line, action)
		if rule == nil {
			return nil
		}
		rule.Comment, rule.HasPrefix = prefixedComment(f.rulePrefix, g.comment)
		rules = append(rules, rule)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return
}

// ParsePorts decodes an apf comma-separated port list into accept rules, one per port entry.
func (f *APF) ParsePorts(val string, proto Protocol, dir Direction) (rules []*Rule) {
	for _, port := range strings.Split(val, ",") {
		port = strings.TrimSpace(port)
		if port == "" {
			continue
		}

		pr, err := f.parsePortToken(port)
		if err != nil {
			continue
		}
		// apf's IG_*_CPORTS/EG_*_CPORTS lists are dual-stack — a single list applied
		// to both the ip and ip6 tables — so a port entry carries no family of its
		// own. Report FamilyAny (not IPv4) so a FamilyAny desired rule, which a bare
		// tcp/udp port carries by default, reconciles with its own read-back.
		rule := &Rule{
			Family:    FamilyAny,
			Proto:     proto,
			Direction: dir,
			Action:    Accept,
		}
		portSpecsToRule(rule, []PortRange{pr})
		rules = append(rules, rule)
	}
	return
}

// hook returns the managed pre-hook script used to inject iptables rules for
// features apf's native config cannot express.
func (f *APF) hook() *hookScript {
	return newHookScript(f.rulePrefix, APFHook, 0750, f.ipv6Enabled)
}

// --- live counters -----------------------------------------------------------

// trustChainDirection reports the direction a row in one of apf's trust chains
// stands for. TALLOW/TDENY (and their global twins) are entered from both INPUT
// and OUTPUT, so the chain itself names no direction — apf writes the inbound
// half of an entry as a source match and the outbound half as a destination
// match, and that is the only signal the row carries. A row matching on neither
// side, or on both, keeps DirAny.
func (f *APF) trustChainDirection(fields []string) Direction {
	src, dst := false, false
	for _, tok := range fields {
		switch tok {
		case "-s", "--source":
			src = true
		case "-d", "--destination":
			dst = true
		}
	}
	switch {
	case src && !dst:
		return DirInput
	case dst && !src:
		return DirOutput
	}
	return DirAny
}

// liveChain reports the direction a live chain's rows stand for, and whether the
// chain is one apf's rules reach at all. The trust chains carry no direction of
// their own, so their rows are classified from the row itself.
func (f *APF) liveChain(chain string, fields []string) (Direction, bool) {
	switch chain {
	case "INPUT":
		return DirInput, true
	case "OUTPUT":
		return DirOutput, true
	case "FORWARD":
		return DirForward, true
	case "TALLOW", "TDENY", "TGALLOW", "TGDENY":
		return f.trustChainDirection(fields), true
	}
	// Every other chain is one of apf's internal sanity/policy chains, whose rows
	// stand for no rule this backend reports.
	return DirInput, false
}

// icmpLimit reads conf.apf's ICMP_LIM, the rate apf attaches to every ICMP type
// it accepts. The rate is apf's own framing rather than part of the rule — an
// IG_ICMP_TYPES entry decodes to a plain accept — so a live ICMP row carrying
// exactly this rate has it cleared before matching. A missing or malformed
// setting yields no rate, which leaves such rows unmatched rather than risking
// clearing a rate a rule genuinely carries.
func (f *APF) icmpLimit() *RateLimit {
	val, err := readConfValue(APFConf, "ICMP_LIM")
	if err != nil || val == "" {
		return nil
	}
	rate, unit, err := parseRateToken(val)
	if err != nil {
		return nil
	}
	return &RateLimit{Rate: rate, Unit: unit}
}

// parseLiveRules decodes counter-annotated `iptables-save -c` output into the
// rules apf's chains hold, reading the ICMP framing rate from conf.apf.
func (f *APF) parseLiveRules(out []string, fam Family) []*Rule {
	return f.decodeLiveRules(out, fam, f.icmpLimit())
}

// decodeLiveRules is parseLiveRules with the ICMP framing rate supplied. apf
// writes a rule much as this backend models it, so the only framing to undo is
// the rate it attaches to every accepted ICMP type, and the direction its trust
// chains leave to the row.
func (f *APF) decodeLiveRules(out []string, fam Family, icmpLim *RateLimit) []*Rule {
	return decodeLiveRows(out, func(row liveRow) (*Rule, bool) {
		dir, ok := f.liveChain(row.chain, row.fields)
		if !ok {
			return nil, false
		}
		rule, ok := parseLiveRow(row, dir, fam)
		if !ok {
			return nil, false
		}
		// Drop apf's ICMP rate framing so the row reads as the plain accept a
		// conf.apf ICMP-type entry decodes to.
		if icmpLim != nil && rule.Proto.IsICMP() && rule.Action == Accept &&
			rule.RateLimit != nil && *rule.RateLimit == *icmpLim {
			rule.RateLimit = nil
		}
		return rule, true
	})
}

// mergeLiveCounters copies the kernel's packet/byte counters onto the rules read
// from conf.apf, the trust lists and the pre-hook.
func (f *APF) mergeLiveCounters(ctx context.Context, rules []*Rule, fam Family) {
	targets := countableRules(rules, fam)
	if len(targets) == 0 {
		return
	}
	applyLiveCounters(targets, f.parseLiveRules(liveSaveLines(ctx, fam), fam))
}

// GetRules returns the current filter rules read from conf.apf, the allow/deny lists, and the pre-hook.
func (f *APF) GetRules(ctx context.Context, zoneName string) (rules []*Rule, err error) {
	// Read rules from conf.apf
	fd, err := os.Open(APFConf)
	if err != nil {
		return nil, err
	}

	// denyAction is the action apf applies to a bare-address deny (conf.apf
	// ALL_STOP, default DROP). Capture it in this same pass so the deny list can
	// be stamped without re-reading conf.apf for that common case; a tcp/udp
	// advanced deny_hosts entry is re-resolved from TCP_STOP/UDP_STOP instead (see
	// resolveAction, used by ParseAdvRule as ParseIPList parses each line).
	denyAction := Drop

	// Scan each line.
	scanner := bufio.NewScanner(fd)
	for scanner.Scan() {
		// Get the line.
		line := scanner.Text()

		// Remove comments.
		ci := strings.IndexByte(line, '#')
		if ci >= 0 {
			line = line[:ci]
		}

		// Trim spaces.
		line = strings.TrimSpace(line)

		// Ignore zero lines.
		if len(line) == 0 {
			continue
		}

		// Parse key/value.
		key, val, found := strings.Cut(line, "=")
		if !found {
			continue
		}
		key = strings.TrimSpace(key)
		val = trimQuotes(strings.TrimSpace(val))

		// Parse rules.
		switch key {
		case "ALL_STOP":
			denyAction = f.parseStopAction(val)
		case "IG_TCP_CPORTS":
			rules = append(rules, f.ParsePorts(val, TCP, DirInput)...)
		case "IG_UDP_CPORTS":
			rules = append(rules, f.ParsePorts(val, UDP, DirInput)...)
		case "EG_TCP_CPORTS":
			rules = append(rules, f.ParsePorts(val, TCP, DirOutput)...)
		case "EG_UDP_CPORTS":
			rules = append(rules, f.ParsePorts(val, UDP, DirOutput)...)
		case "IG_ICMP_TYPES":
			rules = append(rules, f.ParseICMPTypes(val, ICMP, DirInput)...)
		case "EG_ICMP_TYPES":
			rules = append(rules, f.ParseICMPTypes(val, ICMP, DirOutput)...)
		case "IG_ICMPV6_TYPES":
			rules = append(rules, f.ParseICMPTypes(val, ICMPv6, DirInput)...)
		case "EG_ICMPV6_TYPES":
			rules = append(rules, f.ParseICMPTypes(val, ICMPv6, DirOutput)...)
		case "IG_TCP_CLIMIT":
			rules = append(rules, f.ParseConnLimit(val, TCP)...)
		case "IG_UDP_CLIMIT":
			rules = append(rules, f.ParseConnLimit(val, UDP)...)
		}
	}

	_ = fd.Close()
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	// Read the allowed IP rule list.
	ipRules, err := f.ParseIPList(APFAllow, Accept)
	if err != nil {
		return nil, err
	}
	rules = append(rules, ipRules...)

	// Read the denied IP rule list, stamped with the action apf actually applies
	// (captured above from conf.apf ALL_STOP, default DROP) rather than a fixed
	// Reject, so a managed Drop rule reads back as Drop and reconciles without churn.
	ipRules, err = f.ParseIPList(APFDeny, denyAction)
	if err != nil {
		return nil, err
	}
	rules = append(rules, ipRules...)

	// Read the iptables rules injected through the apf pre-hook (state,
	// interface, logging, rate-limit, icmpv6).
	hookRules, err := f.hook().getRules()
	if err != nil {
		return nil, err
	}
	rules = append(rules, hookRules...)

	// apf's config files carry no packet/byte counters — the kernel does — so
	// merge them from the live ruleset (RuleCounters).
	f.mergeLiveCounters(ctx, rules, IPv4)
	f.mergeLiveCounters(ctx, rules, IPv6)

	// Every entry above is reported as apf stores it, and several apf entries cover
	// more than one axis on their own: a CPORTS or CLIMIT entry is dual-stack and
	// decodes to FamilyAny, a protocol-less advanced line decodes to TCPUDP, and a
	// bare allow_hosts/deny_hosts IP is one bidirectional line that decodes to DirAny.
	// What apf keys separately — the TCP and UDP CPORTS lists, the IG_ and EG_ prefixes,
	// the per-family hook lines — stays several rules.
	return
}

// portToken renders a port spec in apf notation: a port or an underscore
// range.
func (f *APF) portToken(pr PortRange) string {
	pr = pr.normalized()
	if pr.Start == pr.End {
		return strconv.FormatUint(uint64(pr.Start), 10)
	}
	return fmt.Sprintf("%d_%d", pr.Start, pr.End)
}

// editConnLimit renders a CLIMIT config line with a rule's "port:limit" entry
// added or removed, preserving the other entries, and records a config change.
func (f *APF) editConnLimit(key, val string, r *Rule, remove bool) string {
	portTok := f.portToken(r.PortSpecs()[0])
	var kept []string
	present := false
	for _, tok := range strings.Split(val, ",") {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			continue
		}
		p, _, ok := strings.Cut(tok, ":")
		if ok && strings.TrimSpace(p) == portTok {
			present = true
			if remove {
				f.ConfigChanged = true
				continue
			}
			// Replace the entry in place. Record a config change only when the
			// count actually differs so Reload runs apf --restart to apply the new
			// limit; an unchanged count must not trigger a spurious restart.
			newTok := fmt.Sprintf("%s:%d", portTok, r.ConnLimit.Count)
			if strings.TrimSpace(tok) != newTok {
				f.ConfigChanged = true
			}
			kept = append(kept, newTok)
			continue
		}
		kept = append(kept, tok)
	}
	if !remove && !present {
		kept = append(kept, fmt.Sprintf("%s:%d", portTok, r.ConnLimit.Count))
		f.ConfigChanged = true
	}
	return fmt.Sprintf(`%s="%s"`, key, strings.Join(kept, ","))
}

// icmpTokens returns the conf.apf type token(s) an icmp/icmpv6 accept rule
// contributes to its type list: the numeric type, or "all" when the rule matches
// every type (a nil ICMPType, which apf applies as a typeless `-p icmp -j ACCEPT`).
func (f *APF) icmpTokens(r *Rule) []string {
	if r.ICMPType == nil {
		return []string{"all"}
	}
	return []string{strconv.Itoa(int(*r.ICMPType))}
}

// isConnLimitRule reports whether a rule maps onto conf.apf's
// IG_TCP_CLIMIT/IG_UDP_CLIMIT: a per-source cap on concurrent inbound
// connections to a single tcp/udp port (or range) with no address, rejecting the
// excess.
func (f *APF) isConnLimitRule(r *Rule) bool {
	return r.ConnLimit != nil && r.ConnLimit.PerSource &&
		!r.IsOutput() && (r.Proto == TCP || r.Proto == UDP) &&
		r.Source == "" && r.Destination == "" &&
		len(r.PortSpecs()) == 1 && r.Action == Reject
}

// portTokens renders the rule's ports as apf config tokens.
func (f *APF) portTokens(r *Rule) []string {
	specs := r.PortSpecs()
	tokens := make([]string, len(specs))
	for i, sp := range specs {
		tokens[i] = f.portToken(sp)
	}
	return tokens
}

// EditRulePort returns the conf.apf line with the rule's tokens added to or removed from the list that key manages.
func (f *APF) EditRulePort(orig, key, val string, r *Rule, remove bool) string {
	// A connection-limit rule is expressed solely through the CLIMIT config; it
	// must never also add or remove its port from an accept port list, or
	// RemoveRule would close a port the caller never opened and a round-trip
	// would report a spurious accept rule alongside the connlimit.
	if r.ConnLimit != nil && key != "IG_TCP_CLIMIT" && key != "IG_UDP_CLIMIT" {
		return orig
	}

	// Determine which config list this key manages and the tokens the rule
	// contributes to it. Non-matching keys are returned untouched.
	// A CPORTS list is per-transport, so a TCPUDP rule contributes its ports to both
	// the TCP and the UDP list, and reads back as one rule per list. coversProtocol
	// gates each list: TCPUDP covers either, a concrete transport only its own.
	var wantTokens []string
	switch key {
	case "IG_TCP_CPORTS":
		if r.IsOutput() || !coversProtocol(r.Proto, TCP) {
			return orig
		}
		wantTokens = f.portTokens(r)
	case "IG_UDP_CPORTS":
		if r.IsOutput() || !coversProtocol(r.Proto, UDP) {
			return orig
		}
		wantTokens = f.portTokens(r)
	case "EG_TCP_CPORTS":
		if !r.IsOutput() || !coversProtocol(r.Proto, TCP) {
			return orig
		}
		wantTokens = f.portTokens(r)
	case "EG_UDP_CPORTS":
		if !r.IsOutput() || !coversProtocol(r.Proto, UDP) {
			return orig
		}
		wantTokens = f.portTokens(r)
	case "IG_ICMP_TYPES":
		if r.IsOutput() || r.Proto != ICMP {
			return orig
		}
		wantTokens = f.icmpTokens(r)
	case "EG_ICMP_TYPES":
		if !r.IsOutput() || r.Proto != ICMP {
			return orig
		}
		wantTokens = f.icmpTokens(r)
	case "IG_ICMPV6_TYPES":
		if r.IsOutput() || r.Proto != ICMPv6 {
			return orig
		}
		wantTokens = f.icmpTokens(r)
	case "EG_ICMPV6_TYPES":
		if !r.IsOutput() || r.Proto != ICMPv6 {
			return orig
		}
		wantTokens = f.icmpTokens(r)
	case "IG_TCP_CLIMIT":
		// CLIMIT tokens are "port:limit", edited independently of the port lists.
		if !f.isConnLimitRule(r) || r.Proto != TCP {
			return orig
		}
		return f.editConnLimit(key, val, r, remove)
	case "IG_UDP_CLIMIT":
		if !f.isConnLimitRule(r) || r.Proto != UDP {
			return orig
		}
		return f.editConnLimit(key, val, r, remove)
	default:
		return orig
	}

	// Canonicalize tokens for comparison. An ICMP-type list may hold either a
	// numeric type or a name (e.g. "echo-request"), and the read path resolves names
	// to numbers; comparing the list's raw token against the numeric token this code
	// emits would never match a name-based (foreign) entry, so a remove would keep it
	// and an add would append a numeric duplicate. Fold each token to its resolved
	// number, using the family the key implies; other keys
	// compare verbatim.
	canon := func(tok string) string { return tok }
	switch key {
	case "IG_ICMP_TYPES", "EG_ICMP_TYPES", "IG_ICMPV6_TYPES", "EG_ICMPV6_TYPES":
		v6 := key == "IG_ICMPV6_TYPES" || key == "EG_ICMPV6_TYPES"
		canon = func(tok string) string {
			if n, ok := parseICMPTypeFamily(tok, v6); ok {
				return strconv.Itoa(int(n))
			}
			return tok
		}
	}

	// Add or remove the rule's tokens from the comma list, preserving any others.
	// want holds the canonical form of every token the rule contributes and
	// present the canonical form of every kept token, so removal recognizes a
	// token however the file spells it and an add never appends a duplicate;
	// kept carries the surviving tokens in their original spelling.
	want := make(map[string]bool, len(wantTokens))
	for _, w := range wantTokens {
		want[canon(w)] = true
	}
	present := make(map[string]bool)
	var kept []string

	// Pass 1: walk the existing config list, dropping a token only on a remove
	// and only when it is one of the rule's own; surviving tokens keep their
	// original spelling and are tracked by canonical form for the add pass.
	for _, tok := range strings.Split(val, ",") {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			continue
		}
		c := canon(tok)
		// On a remove, an existing token that matches one of the rule's tokens is
		// the one we are deleting: skip it and flag the file as changed.
		if remove && want[c] {
			f.ConfigChanged = true
			continue
		}
		// Otherwise the token stays. Record its canonical form so the add pass
		// below treats it as already present.
		kept = append(kept, tok)
		present[c] = true
	}

	// Pass 2 (add only): append any of the rule's tokens that the existing list
	// did not already contain. present carries forward from pass 1, so a token
	// the file already had is skipped and we never write a duplicate.
	if !remove {
		for _, w := range wantTokens {
			if cw := canon(w); !present[cw] {
				kept = append(kept, w)
				present[cw] = true
				f.ConfigChanged = true
			}
		}
	}

	// Re-create the configuration with the new list.
	return fmt.Sprintf(`%s="%s"`, key, strings.Join(kept, ","))
}

// EditConf adds or removes a rule in conf.apf, rewriting the file in place.
// confKeyApplies reports whether a conf.apf key is one the rule's EditRulePort
// edit lands in, mirroring EditRulePort's own routing guards. EditConf uses it
// to detect a config missing the rule's key line (an operator-stripped or older
// conf.apf), where an add would otherwise report success with nothing written.
func (f *APF) confKeyApplies(key string, r *Rule) bool {
	switch key {
	case "IG_TCP_CPORTS":
		return r.ConnLimit == nil && !r.IsOutput() && coversProtocol(r.Proto, TCP)
	case "IG_UDP_CPORTS":
		return r.ConnLimit == nil && !r.IsOutput() && coversProtocol(r.Proto, UDP)
	case "EG_TCP_CPORTS":
		return r.ConnLimit == nil && r.IsOutput() && coversProtocol(r.Proto, TCP)
	case "EG_UDP_CPORTS":
		return r.ConnLimit == nil && r.IsOutput() && coversProtocol(r.Proto, UDP)
	case "IG_ICMP_TYPES":
		return r.ConnLimit == nil && !r.IsOutput() && r.Proto == ICMP
	case "EG_ICMP_TYPES":
		return r.ConnLimit == nil && r.IsOutput() && r.Proto == ICMP
	case "IG_ICMPV6_TYPES":
		return r.ConnLimit == nil && !r.IsOutput() && r.Proto == ICMPv6
	case "EG_ICMPV6_TYPES":
		return r.ConnLimit == nil && r.IsOutput() && r.Proto == ICMPv6
	case "IG_TCP_CLIMIT":
		return f.isConnLimitRule(r) && r.Proto == TCP
	case "IG_UDP_CLIMIT":
		return f.isConnLimitRule(r) && r.Proto == UDP
	}
	return false
}

func (f *APF) EditConf(ctx context.Context, r *Rule, remove bool) error {
	// Open the standard config file; EditRulePort rewrites the port, icmp-type
	// and CLIMIT list lines the rule applies to.
	fd, err := os.Open(APFConf)
	if err != nil {
		return err
	}

	// Stage the rewrite, preserving conf.apf's mode and ownership.
	af, err := newAtomicFile(APFConf, 0644)
	if err != nil {
		_ = fd.Close()
		return err
	}
	defer af.Abort()

	// Parse config one line at a time, adding the port rule.
	keyMatched := false
	scanner := bufio.NewScanner(fd)
	for scanner.Scan() {
		// Get the line.
		orig := scanner.Text()
		line := orig

		// Remove comments.
		ci := strings.IndexByte(line, '#')
		if ci >= 0 {
			line = line[:ci]
		}

		// Trim spaces.
		line = strings.TrimSpace(line)

		// Ignore zero lines.
		if len(line) == 0 {
			_, _ = fmt.Fprintln(af, orig)
			continue
		}

		// Parse key/value.
		key, val, found := strings.Cut(line, "=")
		if !found {
			_, _ = fmt.Fprintln(af, orig)
			continue
		}
		key = strings.TrimSpace(key)
		val = trimQuotes(strings.TrimSpace(val))

		// Parse rules.
		if f.confKeyApplies(key, r) {
			keyMatched = true
		}
		orig = f.EditRulePort(orig, key, val, r, remove)
		_, _ = fmt.Fprintln(af, orig)
	}

	_ = fd.Close()

	// A read error means the rewritten file is truncated; discard it.
	if serr := scanner.Err(); serr != nil {
		return serr
	}

	// An add against a config missing the rule's key line would write nothing
	// while reporting success — the rule's port or type would simply never
	// open. Removal of a rule whose key line is absent is a plain no-op.
	if !remove && !keyMatched {
		return fmt.Errorf("conf.apf carries no config list for this rule")
	}

	// Move new file into place, preserving mode and ownership.
	return af.Commit()
}

// addrField renders an address for an advanced rule, wrapping an IPv6 address
// in brackets so it survives the colon-separated field format.
func (f *APF) addrField(addr string) string {
	if strings.Contains(addr, ":") {
		return "[" + addr + "]"
	}
	return addr
}

// MarshalAdvRule encodes a rule as an apf advanced allow/deny line: an optional
// protocol field, a direction, one port-flow field (a source or a destination port)
// and one address field, joined by ":". It validates nothing; addRule/RemoveRule
// route every shape the line cannot carry elsewhere first (see needsHook).
func (f *APF) MarshalAdvRule(r *Rule) string {
	// apf's advanced rule carries an optional protocol field, and treats a line
	// without one as both transports: its trust parser emits a `-p tcp` rule and a
	// `-p udp` rule for it. So TCPUDP is written by omitting the field.
	var parts []string
	switch r.Proto {
	case TCP:
		parts = append(parts, "tcp")
	case UDP:
		parts = append(parts, "udp")
	case TCPUDP:
		// No protocol field: apf reads that as tcp plus udp.
	}
	if r.IsOutput() {
		parts = append(parts, "out")
	} else {
		parts = append(parts, "in")
	}
	// The port-flow field: a source port or a destination port. apf's field holds a
	// single port or one underscore range; needsHook routes a multi-port list to the
	// hook, so only one spec ever arrives.
	if specs := r.SourcePortSpecs(); len(specs) == 1 {
		parts = append(parts, "s="+f.portToken(specs[0]))
	} else if specs := r.PortSpecs(); len(specs) == 1 {
		parts = append(parts, "d="+f.portToken(specs[0]))
	}
	if r.Source != "" {
		parts = append(parts, "s="+f.addrField(r.Source))
	} else if r.Destination != "" {
		parts = append(parts, "d="+f.addrField(r.Destination))
	}
	return strings.Join(parts, ":")
}

// parseListLine parses one apf allow_hosts/deny_hosts rule line into the rule it
// holds: an advanced rule, or a plain address line, which is a single bidirectional
// DirAny rule matching every protocol. It returns nil for a line that is neither,
// which the caller passes through untouched. The action comes from the file
// (allow_hosts is accept, deny_hosts takes the drop/reject action conf.apf sets);
// the line encodes none of its own.
func (f *APF) parseListLine(line string, action Action) *Rule {
	if strings.Contains(line, "=") {
		return f.ParseAdvRule(line, action)
	}
	fam, ok := parseAddrFamily(line)
	if !ok {
		return nil
	}
	return &Rule{Direction: DirAny, Family: fam, Source: line, Action: action}
}

// listRows returns the allow_hosts/deny_hosts rows a rule materializes into, in write
// order, or none for a shape the trust files cannot hold. The rule must already carry
// the action its file implies (see EditIPList's match), since each row's read-back
// form is compared against lines stamped with it.
//
// A rule never fans out across transports: apf's trust parser reads a protocol-less
// advanced line as a `-p tcp` rule plus a `-p udp` rule, so MarshalAdvRule writes a
// TCPUDP rule as a single line. A port-only deny does fan out per family: apf requires
// an address in the advanced line's field position, and the "any" network placeholder
// it uses there is family-specific, so a family-neutral rule would otherwise silently
// become IPv4-only. The fan-out covers the families apf actually enforces (see
// filterFamiliesIPv6; with conf.apf's USE_IPV6 off that is IPv4 alone). parseAddr
// normalizes the placeholder back to an empty address, so each row reads back as the
// address-less rule it stands for.
func (f *APF) listRows(action Action, match *Rule) []ruleLine {
	hasIP := match.Source != "" || match.Destination != ""
	var rows []ruleLine
	switch {
	case hasIP && (match.HasPorts() || match.HasSourcePorts()):
		// A port rule with an address is an advanced rule.
		rows = append(rows, ruleLine{line: f.MarshalAdvRule(match), read: match})
	case hasIP:
		// A bare all-protocol host allow/deny: a single address matching every
		// protocol. apf's trust files hold no other portless address shape — a
		// concrete-protocol host or a source+destination pair — so AddRule diverts
		// those to the raw-iptables hook (shapeNeedsHook) and never reaches here with
		// one. A direct caller of this exported writer that supplies such a shape gets
		// a best-effort single-address write, not a guard.
		addr := match.Source
		if addr == "" {
			addr = match.Destination
		}
		// The plain line is bidirectional and names its address as the source, which is
		// the frame the scan reads it back in.
		read := *match
		read.Direction = DirAny
		read.Source, read.Destination = addr, ""
		rows = append(rows, ruleLine{line: addr, read: &read})
	case action != Accept && match.HasPorts():
		specs := match.PortSpecs()
		for _, fam := range filterFamiliesIPv6(f.ipv6Enabled, match) {
			placeholder := "0.0.0.0/0"
			if fam.impliedFamily() == IPv6 {
				// MarshalAdvRule brackets an IPv6 literal for the colon-separated format.
				placeholder = "::/0"
			}
			// Pin the row to the one shape apf's single port-flow field holds: one
			// destination port. needsHook routes a multi-port list and a source-port match
			// to the hook before AddRule reaches here, so this only bounds a direct caller
			// of this exported writer — without it MarshalAdvRule would emit a portless
			// line (denying the whole protocol) for a list, or prefer the source port over
			// the destination one.
			read := *fam
			read.Port, read.Ports = 0, specs[:1]
			read.SourcePort, read.SourcePorts = 0, nil
			// The row reads back address-less; only the line carries the placeholder.
			row := read
			if row.IsOutput() {
				row.Destination = placeholder
			} else {
				row.Source = placeholder
			}
			rows = append(rows, ruleLine{line: f.MarshalAdvRule(&row), read: &read})
		}
	}
	return rows
}

// EditIPList adds or removes a rule in an apf allow_hosts/deny_hosts file, rewriting
// it in place. An add expands the rule into the rows it materializes into (see
// listRows), notes which of them the file already holds, and appends only the rest,
// so a rule that fans out across families is completed rather than duplicated on
// every reconcile. A removal drops every line the target covers.
func (f *APF) EditIPList(ctx context.Context, filePath string, action Action, r *Rule, remove bool) error {
	// Read the allow_hosts/deny_hosts rule list.
	fd, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer func() { _ = fd.Close() }()

	// Stage the rewrite, preserving the list file's mode and ownership.
	af, err := newAtomicFile(filePath, 0644)
	if err != nil {
		return err
	}
	defer af.Abort()

	// A deny_hosts entry takes on the drop/reject action set in apf.conf (and
	// allow_hosts is accept), so a rule read back is stamped with the file's
	// action. Resolve the incoming rule's action the same way via resolveAction
	// before matching.
	match := *r
	match.Action = f.resolveAction(action, r.Proto)
	// The rows an add must end up with, and which of them the scan finds already in
	// the file. A removal wants no rows: it matches the target against each line
	// directly, since a line it must drop need not be one this library would write.
	var rows []ruleLine
	if !remove {
		rows = f.listRows(action, &match)
	}
	present := make([]bool, len(rows))

	// Stream the file's comment-attached groups so a removed rule takes its
	// comment with it and every kept line copies through verbatim.
	err = scanCommentGroups(fd, f.rulePrefix, nil, func(g commentGroup) error {
		keep := func() {
			for _, l := range g.raw {
				_, _ = fmt.Fprintln(af, l)
			}
		}
		// Strip an inline trailing comment for matching, but preserve the
		// original line (with its inline note) when copying it through.
		line := trimInlineComment(g.line)
		// A line neither form parses is not a rule; pass it — and any blank or
		// detached comment — through untouched.
		var cur *Rule
		if line != "" {
			cur = f.parseListLine(line, action)
		}
		if cur == nil {
			keep()
			return nil
		}

		// A removal drops every line the target covers, along with its comment. A
		// family-neutral target touches each of the concrete lines it was written as;
		// that coverage is folded into EqualForRemoval.
		if remove {
			if cur.EqualForRemoval(&match, true) {
				f.ConfigChanged = true
				return nil
			}
			keep()
			return nil
		}

		// An add keeps every line and only notes which wanted rows the file already
		// covers, so the tail writes the rest. Coverage rather than a text compare, so
		// a row is satisfied by an existing line that spans it (a protocol-less TCPUDP
		// line absorbing a tcp row) and by one spelled differently but meaning the same.
		for i := range rows {
			if !present[i] && cur.EqualForDedup(rows[i].read, true) {
				present[i] = true
			}
		}
		keep()
		return nil
	})
	// A read error means the rewritten file is truncated; discard it.
	if err != nil {
		return err
	}

	// Append the wanted rows the file does not already hold. A rule that fans out is
	// completed row by row: when only a subset is present (the IPv4 line but not its
	// IPv6 twin, from a prior single-family add or a manual edit) the missing rows
	// must still be written, or that family stays open while the library reports the
	// rule in force.
	writeComment := func() {
		if c := combineComment(f.rulePrefix, r.Comment); c != "" {
			_, _ = fmt.Fprintln(af, "# "+c)
		}
	}
	for i, row := range rows {
		if present[i] {
			continue
		}
		f.ConfigChanged = true
		writeComment()
		_, _ = fmt.Fprintln(af, row.line)
	}

	// Move new file into place, preserving mode and ownership.
	return af.Commit()
}

// isConfRule reports whether a rule is managed in conf.apf: an address-less
// accept rule of ports (TCP/UDP lists) or ICMP/ICMPv6 types (a nil type is the
// "all" wildcard).
func (f *APF) isConfRule(r *Rule) bool {
	if r.Source != "" || r.Destination != "" || r.Action != Accept {
		return false
	}
	return r.HasPorts() || r.Proto == ICMP || r.Proto == ICMPv6
}

// nativeICMPv6 reports whether an ICMPv6 rule can be carried by apf's native
// IG_ICMPV6_TYPES/EG_ICMPV6_TYPES lists (an address-less accept, optionally typed)
// and so belongs in conf.apf rather than the raw-iptables hook. The shared
// ruleNeedsHook diverts every ICMPv6 rule to the hook, since not every backend it
// serves has a native v6 type list; apf overrides that only for the rules its config
// can actually express, leaving an ICMPv6 rule that also needs state/interface/log/
// rate matching (which conf.apf cannot carry) on the hook path.
func (f *APF) nativeICMPv6(r *Rule) bool {
	return r.Proto == ICMPv6 && r.State == 0 && r.InInterface == "" && r.OutInterface == "" &&
		!r.Log && r.RateLimit == nil && f.isConfRule(r)
}

// barePortAccept reports whether a rule is an address-less tcp/udp port accept —
// the shape apf stores either in a dual-stack conf.apf CPORTS list (a FamilyAny
// port) or, per family, through the raw-iptables hook (a single-family port, or a
// FamilyAny added as a v4 hook rule plus a v6 hook rule). Both the add-time hook
// decision (dualStackPortNeedsHook) and the remove-time split/clear
// (removeDualStackPort) build on it.
func (f *APF) barePortAccept(r *Rule) bool {
	return onProtocolAxis(r.Proto) && r.HasPorts() &&
		r.Source == "" && r.Destination == "" && r.Action == Accept
}

// dualStackPortNeedsHook reports whether a bare tcp/udp port accept pinned to a
// single family must be injected through the hook. apf's IG_*_CPORTS/EG_*_CPORTS
// lists are dual-stack — one list applied to both the ip and ip6 tables — so they
// express only a FamilyAny port; the lists have no per-family form to pin one to.
// A single-family port accept is written per-family through the hook instead,
// whose iptables (or ip6tables) rule carries just that family; removing one family
// of a FamilyAny CPORTS entry splits it (see removeDualStackPort). ICMP keeps its
// concrete family (its type lists are per-family), so this gates on a port match.
func (f *APF) dualStackPortNeedsHook(r *Rule) bool {
	return f.barePortAccept(r) && r.impliedFamily() != FamilyAny
}

// needsHook reports whether a rule must be injected through the apf pre-hook as a
// raw iptables rule because apf's native config cannot express it. It is the single
// gate between the hook path and apf's config files: everything it rejects (returns
// true) is written to the hook, everything it accepts (returns false) maps onto
// conf.apf or the allow_hosts/deny_hosts trust files. The shared predicates
// (ruleNeedsHook, shapeNeedsHook, bareHostOneWay) and the two apf shapes RemoveRule
// reuses to route a split (dualStackPortNeedsHook, nativeICMPv6) stay standalone;
// the apf-only, single-use port/connlimit/icmp tests are inlined here as their sole
// caller.
func (f *APF) needsHook(r *Rule) bool {
	// Features apf's native config cannot model — connection state, per-rule
	// interface, logging, rate limiting, forward-chain routing, ICMPv6, or a
	// transport apf does not carry (see ruleNeedsHook) — go to the hook. An ICMPv6
	// type rule is the exception: apf carries it natively in IG_ICMPV6_TYPES/
	// EG_ICMPV6_TYPES (see nativeICMPv6), so it stays out.
	if ruleNeedsHook(r) && !f.nativeICMPv6(r) {
		return true
	}
	// A shape no native apf form holds — a one-way bare host, a source+destination
	// pair, a concrete-protocol portless host, an advanced-line address/port-flow
	// overflow, or a bare protocol match (see shapeNeedsHook) — goes to the hook. A
	// native address-less ICMP/ICMPv6 accept is excluded there and routed below.
	if shapeNeedsHook(r) {
		return true
	}
	// A multi-port tcp/udp list apf's config cannot carry as one rule: its advanced
	// rule holds a single port or one underscore range, and a conf.apf CPORTS comma
	// list stores each port as an independent token that reads back as its own rule,
	// so an address-less multi-port accept would never round-trip whole. Every list
	// goes to the hook's iptables multiport match instead, which keeps it on one line.
	if onProtocolAxis(r.Proto) &&
		(len(r.PortSpecs()) > 1 || len(r.SourcePortSpecs()) > 1) {
		return true
	}
	// A connection limit conf.apf's IG_*_CLIMIT cannot express — anything but a
	// per-source cap on a single address-less inbound tcp/udp port rejecting the
	// excess (isConnLimitRule) — goes to the hook's `-m connlimit` match.
	if r.ConnLimit != nil && !f.isConnLimitRule(r) {
		return true
	}
	// An ICMPv4 rule apf's IG_ICMP_TYPES/EG_ICMP_TYPES lists cannot express (they
	// match a type on the whole zone, so only an address-less accept is native, and
	// one carrying an address or a non-accept action is not) goes to the hook's
	// `iptables -p icmp` match. ICMPv6 is routed by ruleNeedsHook above, not here.
	if r.Proto == ICMP && !f.isConfRule(r) {
		return true
	}
	// A single-family bare tcp/udp port accept: apf's CPORTS lists are dual-stack, so
	// only a FamilyAny port is native; a single-family one is written per-family
	// through the hook (see dualStackPortNeedsHook, which RemoveRule also uses).
	return f.dualStackPortNeedsHook(r)
}

// addRule is AddRule's implementation, with the IPv6 gate optional. Restore
// passes enforceIPv6Gate false so it can reproduce a Backup snapshot's exact
// prior state, including inert entries the gate would reject as fresh no-op
// writes.
func (f *APF) addRule(ctx context.Context, zoneName string, r *Rule, enforceIPv6Gate bool) error {
	// Reject a concrete-IPv6 rule when apf's own IPv6 handling is off, ahead of every
	// routing decision below: neither conf.apf nor the pre-hook can carry one that apf
	// will keep in sync (see ipv6Enabled). Checking here rather than past the hook
	// branch also keeps a DirAny rule from writing its input half before its output
	// half is rejected.
	if enforceIPv6Gate && !f.ipv6Enabled && r.impliedFamily() == IPv6 {
		return fmt.Errorf("apf's IPv6 handling is disabled (conf.apf USE_IPV6 is not \"1\"): %w", ErrUnsupported)
	}

	// A DirAny rule maps to a single native construct only as a bare-host plain line;
	// every other DirAny shape fans out into a concrete input rule plus its swapped
	// output rule, each routed independently (a half may itself need the hook).
	if r.Direction == DirAny && !dirAnyPlainLine(r) {
		for _, sub := range expandDirections(r) {
			if err := f.addRule(ctx, zoneName, sub, enforceIPv6Gate); err != nil {
				return err
			}
		}
		return nil
	}

	// Verify the rule is valid with iptables.
	if err := r.validate(); err != nil {
		return fmt.Errorf("%v: %w", err, ErrUnsupported)
	}

	// Any shape apf's native config cannot express (a stateful/interface/logged/
	// rate-limited rule, a one-way or concrete-protocol host, a source+destination
	// pair, a source-and-destination port match, a multi-port list, an address-less
	// source-port match, a non-native connection limit, a non-native ICMPv4 rule, or
	// a single-family port accept) is
	// injected as a raw iptables rule through the apf pre-hook. See needsHook for
	// each clause; everything past this gate maps onto apf's own config files.
	if f.needsHook(r) {
		changed, err := f.hook().edit(r, false)
		f.ConfigChanged = f.ConfigChanged || changed
		return err
	}

	// A native connection-limit rule maps onto conf.apf's IG_*_CLIMIT lists (a
	// non-native one was diverted to the hook above by needsHook).
	if r.ConnLimit != nil {
		return f.EditConf(ctx, r, false)
	}

	// Address-less accept rules (dual-stack port lists, icmp types) live in conf.apf.
	if f.isConfRule(r) {
		return f.EditConf(ctx, r, false)
	}

	// Otherwise edit allow_hosts.rules for accepts, deny_hosts.rules for denies. A
	// bare protocol match (no address, no port) never reaches here — needsHook routed
	// it to the pre-hook above — so every rule at this point carries an address.
	if r.Action == Accept {
		return f.EditIPList(ctx, APFAllow, Accept, r, false)
	}
	// A deny_hosts entry carries no action of its own: apf applies conf.apf's ALL_STOP
	// action to a bare-address entry, or its TCP_STOP/UDP_STOP action to a tcp/udp
	// advanced one (see stopKey). A deny whose action matches that is written natively;
	// one that differs has no native form, so it is injected through the pre-hook
	// instead, whose iptables rule carries the exact action. A DirAny bare-host deny is
	// expanded to its two concrete directions first, since each hook line is one-way.
	denyAction := f.denyActionFor(r.Proto)
	if r.Action != denyAction {
		for _, sub := range expandDirections(r) {
			changed, err := f.hook().edit(sub, false)
			f.ConfigChanged = f.ConfigChanged || changed
			if err != nil {
				return err
			}
		}
		return nil
	}
	return f.EditIPList(ctx, APFDeny, denyAction, r, false)
}

// AddRule adds a rule to apf, routing it to conf.apf, the allow/deny lists, or the pre-hook.
func (f *APF) AddRule(ctx context.Context, zoneName string, r *Rule) error {
	return f.addRule(ctx, zoneName, r, true)
}

// InsertRule is unsupported: APF organizes rules in config files, not an ordered list.
func (f *APF) InsertRule(ctx context.Context, zoneName string, position int, r *Rule) error {
	return unsupportedOrdering(f.Type())
}

// MoveRule is unsupported for the same reason as InsertRule.
func (f *APF) MoveRule(ctx context.Context, zoneName string, r *Rule, position int) error {
	return unsupportedOrdering(f.Type())
}

// removePlainHost drops the bidirectional plain allow_hosts/deny_hosts line backing
// the DirAny rule e, choosing the list by the rule's action.
func (f *APF) removePlainHost(ctx context.Context, e *Rule) error {
	if e.Action == Accept {
		return f.EditIPList(ctx, APFAllow, Accept, e, true)
	}
	return f.EditIPList(ctx, APFDeny, f.denyActionFor(e.Proto), e, true)
}

// removeBareHostOneWay removes a one-way bare-address host rule. Such a rule is
// stored either as its own hook rule or as one direction of a bidirectional plain
// allow_hosts/deny_hosts line (a DirAny rule). When a matching plain line exists,
// split it: drop the line and re-add the surviving opposite direction as a hook rule
// so the untargeted direction keeps its coverage.
func (f *APF) removeBareHostOneWay(ctx context.Context, zoneName string, r *Rule) error {
	existing, err := f.GetRules(ctx, zoneName)
	if err != nil {
		return err
	}
	for _, e := range existing {
		if e.Direction != DirAny || !e.EqualForRemoval(r, true) {
			continue
		}
		// The host is stored as a bidirectional plain line; drop it, then re-add the
		// surviving direction as a hook rule.
		if err := f.removePlainHost(ctx, e); err != nil {
			return err
		}
		if s := splitDualRowDirection(e, r); s != nil {
			// An IPv6 plain line left over from when USE_IPV6 was on is not
			// enforced with it off, and a hook-injected ip6tables line would
			// outlive its own removal (see ipv6Enabled); there is no coverage
			// to preserve, so no v6 survivor is written.
			if !f.ipv6Enabled && s.impliedFamily() == IPv6 {
				return nil
			}
			changed, err := f.hook().edit(s, false)
			f.ConfigChanged = f.ConfigChanged || changed
			return err
		}
		return nil
	}
	// Not stored as a plain line; remove the one-way hook rule.
	changed, err := f.hook().edit(r, true)
	f.ConfigChanged = f.ConfigChanged || changed
	return err
}

// cPortsKey returns the conf.apf CPORTS list a tcp/udp port rule of the given
// direction lives in, or "" for a protocol with no such list.
func (f *APF) cPortsKey(proto Protocol, output bool) string {
	dir := "IG"
	if output {
		dir = "EG"
	}
	switch proto {
	case TCP:
		return dir + "_TCP_CPORTS"
	case UDP:
		return dir + "_UDP_CPORTS"
	}
	return ""
}

// portInCPorts reports whether a bare port accept is stored in conf.apf's CPORTS
// lists rather than as its own hook rule. A TCPUDP rule contributes to both the TCP
// and the UDP list, so it is CPORTS-backed only when every transport it covers is
// present — if one list is missing the port, that transport lives in the hook and
// the whole rule must be treated as hook-backed. cPortsKey is only ever asked about
// a concrete transport, since expandProtocols has split the rule first.
func (f *APF) portInCPorts(r *Rule) (bool, error) {
	for _, sub := range expandProtocols(r) {
		val, err := readConfValue(APFConf, f.cPortsKey(sub.Proto, sub.IsOutput()))
		if err != nil {
			return false, err
		}
		found := false
		for _, e := range f.ParsePorts(val, sub.Proto, sub.Direction) {
			if e.EqualForRemoval(sub, true) {
				found = true
				break
			}
		}
		if !found {
			return false, nil
		}
	}
	return true, nil
}

// removeDualStackPort removes a single-family bare tcp/udp port accept. Such a rule
// is stored either as its own per-family hook rule or as one family of a dual-stack
// conf.apf CPORTS entry (a FamilyAny port). Read the CPORTS list the port would live
// in — the rule view alone cannot tell a genuine CPORTS entry from a pair of
// single-family hook rules — and split it when present: drop the dual-stack
// entry and re-add the surviving opposite family as a hook rule, so the untargeted
// family keeps its coverage. Otherwise the rule is a per-family hook rule.
func (f *APF) removeDualStackPort(ctx context.Context, r *Rule) error {
	inCPorts, err := f.portInCPorts(r)
	if err != nil {
		return err
	}
	if inCPorts {
		// Drop the dual-stack CPORTS entry (family-agnostic), then re-add the
		// surviving opposite family through the hook.
		if err := f.EditConf(ctx, r, true); err != nil {
			return err
		}
		surviving := *r
		surviving.Family = oppositeFamily(r.impliedFamily())
		// With USE_IPV6 off apf never enforced the entry's IPv6 half, and a
		// hook-injected ip6tables line is re-appended on every reload and
		// outlives its own removal (see ipv6Enabled), so there is no
		// coverage to preserve and no v6 survivor to write.
		if !f.ipv6Enabled && surviving.Family == IPv6 {
			return nil
		}
		changed, err := f.hook().edit(&surviving, false)
		f.ConfigChanged = f.ConfigChanged || changed
		return err
	}
	// Not stored in CPORTS; remove the per-family hook rule.
	changed, err := f.hook().edit(r, true)
	f.ConfigChanged = f.ConfigChanged || changed
	return err
}

// removeFamilyAnyPort removes a FamilyAny address-less bare tcp/udp port accept. Its
// two families live in a dual-stack conf.apf CPORTS entry (a genuine FamilyAny add),
// in a v4+v6 pair in the hook (two separate concrete-family adds), or split across
// both. A read cannot tell which, so remove the rule from both backings — EditConf
// drops it from the CPORTS list and the hook edit drops both per-family rows, and
// each no-ops when the rule is absent — clearing every cell the target covers,
// wherever it lives. Unlike the single-family path there is no surviving family
// to re-express, so no split is needed.
func (f *APF) removeFamilyAnyPort(ctx context.Context, r *Rule) error {
	if err := f.EditConf(ctx, r, true); err != nil {
		return err
	}
	changed, err := f.hook().edit(r, true)
	f.ConfigChanged = f.ConfigChanged || changed
	return err
}

// RemoveRule removes a rule from apf, routing it to the config file or pre-hook that holds it.
func (f *APF) RemoveRule(ctx context.Context, zoneName string, r *Rule) error {
	// A non-plain-line DirAny target fans out into its two concrete-direction rules,
	// mirroring addRule, so each half is removed from wherever it was written.
	if r.Direction == DirAny && !dirAnyPlainLine(r) {
		for _, sub := range expandDirections(r) {
			if err := f.RemoveRule(ctx, zoneName, sub); err != nil {
				return err
			}
		}
		return nil
	}

	// Validate the shape before the hook sweep below: an iptables-inexpressible
	// rule (a port on ProtocolAny) exists nowhere apf can hold it, and letting it
	// fail inside the hook marshal would return the bare error without the
	// sentinel AddRule attaches to the same shape.
	if err := r.validate(); err != nil {
		return fmt.Errorf("%v: %w", err, ErrUnsupported)
	}

	// Clear any hook copy of the rule first, no matter how apf stores it. A rule apf
	// carries only in the hook (stateful/interface/logged/rate-limited/icmpv6/
	// hook-only-proto) lives nowhere else, so this is its entire removal; a natively-
	// expressible rule may still have a stray hook copy — the library's own
	// differing-action deny (see AddRule) or a hand-added duplicate for a shape apf can
	// also express natively — that must be cleared before the native entry below. DirAny
	// is expanded so both one-way hook lines are matched; a rule with no hook copy makes
	// this a harmless no-op.
	var err error
	for _, sub := range expandDirections(r) {
		changed, e := f.hook().edit(sub, true)
		f.ConfigChanged = f.ConfigChanged || changed
		if e != nil {
			err = e
			break
		}
	}
	// A rule apf carries only in the hook has no native entry to fall through to, so
	// return once its hook copy is cleared (or on any hook error). Returning here also
	// keeps such a rule out of the split scans below, whose plain-line/CPORTS checks
	// could wrongly split an unrelated coexisting native entry. A native ICMPv6 type
	// rule lives in conf.apf, not the hook, so it is excluded and routed there below.
	if (ruleNeedsHook(r) && !f.nativeICMPv6(r)) || err != nil {
		return err
	}
	// A one-way bare host rule is stored either as its own hook rule or as one
	// direction of a bidirectional plain line; removing it may need to split the
	// plain line (see removeBareHostOneWay).
	if bareHostOneWay(r) {
		return f.removeBareHostOneWay(ctx, zoneName, r)
	}
	// A single-family bare tcp/udp port accept is stored either as its own per-family
	// hook rule or as one family of a dual-stack CPORTS entry; removing it may need to
	// split that entry (see removeDualStackPort).
	if f.dualStackPortNeedsHook(r) {
		return f.removeDualStackPort(ctx, r)
	}
	// A FamilyAny bare tcp/udp port accept is stored in a dual-stack CPORTS entry, in a
	// v4+v6 hook pair (separate concrete-family adds), or split across both;
	// removeFamilyAnyPort clears it from every backing (see there).
	if f.barePortAccept(r) {
		return f.removeFamilyAnyPort(ctx, r)
	}
	// Every other shape apf's native config cannot express (see needsHook) has already
	// had its hook copy cleared above and has no native entry to split, so it is done.
	if f.needsHook(r) {
		return nil
	}

	// A native connection-limit rule maps onto conf.apf's IG_*_CLIMIT lists.
	if r.ConnLimit != nil {
		return f.EditConf(ctx, r, true)
	}

	// Address-less accept rules (dual-stack port lists, icmp types) live in conf.apf.
	if f.isConfRule(r) {
		return f.EditConf(ctx, r, true)
	}

	// Otherwise edit allow_hosts.rules for accepts, deny_hosts.rules for denies.
	if r.Action == Accept {
		return f.EditIPList(ctx, APFAllow, Accept, r, true)
	}
	return f.EditIPList(ctx, APFDeny, f.denyActionFor(r.Proto), r, true)
}

// natFile returns the routing file a NAT rule belongs in: source NAT is
// applied in POSTROUTING (postroute.rules), destination NAT in PREROUTING
// (preroute.rules).
func (f *APF) natFile(r *NATRule) string {
	if r.Kind.isSource() {
		return APFPostroute
	}
	return APFPreroute
}

// routeHook returns a hookScript bound to one of apf's routing-rule files. apf
// sources preroute.rules and postroute.rules as shell on every (re)start, exactly
// as it sources the pre-hook, so the same raw-iptables mechanism that carries
// csf's hook NAT lines carries apf's routing-file NAT lines: a NAT rule is written
// as an `iptables -t nat` command and read back the same way, reusing the iptables
// NAT marshaller/parser and its shell-safe quoting rather than a second rendering
// path. The two files stay distinct because apf applies preroute.rules at the
// PREROUTING stage and postroute.rules at the POSTROUTING stage (see natFile), so
// each is its own hookScript; only the hook's NAT methods are exercised here.
func (f *APF) routeHook(path string) *hookScript {
	return newHookScript(f.rulePrefix, path, 0600, f.ipv6Enabled)
}

// GetNATRules returns the NAT rules held in apf's preroute and postroute routing
// files, parsed through the shared hook mechanism.
func (f *APF) GetNATRules(ctx context.Context, zoneName string) ([]*NATRule, error) {
	var rules []*NATRule
	for _, path := range []string{APFPreroute, APFPostroute} {
		parsed, err := f.routeHook(path).getNATRules()
		if err != nil {
			return nil, err
		}
		rules = append(rules, parsed...)
	}
	// APF's routing files hold raw iptables nat commands, so a rule this library
	// added carries the configured prefix in its -m comment tag and UnmarshalNATRule
	// derives HasPrefix from it (an empty prefix writes no tag, so HasPrefix is
	// false; a rule hand-added without the tag likewise reports false).
	return rules, nil
}

// AddNATRule adds a NAT rule to apf's preroute or postroute routing file.
func (f *APF) AddNATRule(ctx context.Context, zoneName string, r *NATRule) error {
	if err := r.validate(); err != nil {
		return err
	}
	// A concrete-IPv6 translation cannot be kept in sync with USE_IPV6 off: apf
	// sources the routing files on every (re)load but never flushes the v6 nat
	// table, so the injected line re-appends each reload and outlives its own
	// removal.
	if !f.ipv6Enabled && r.impliedFamily() == IPv6 {
		return fmt.Errorf("apf cannot manage an IPv6 nat rule with USE_IPV6 disabled: %w", ErrUnsupportedNAT)
	}
	changed, err := f.routeHook(f.natFile(r)).editNAT(r, false)
	f.ConfigChanged = f.ConfigChanged || changed
	return err
}

// InsertNATRule is unsupported: APF stores NAT in a config file it applies as a
// whole, with no explicit ordering.
func (f *APF) InsertNATRule(ctx context.Context, zoneName string, position int, r *NATRule) error {
	return unsupportedOrdering(f.Type())
}

// MoveNATRule is unsupported for the same reason as InsertNATRule.
func (f *APF) MoveNATRule(ctx context.Context, zoneName string, r *NATRule, position int) error {
	return unsupportedOrdering(f.Type())
}

// RemoveNATRule removes a NAT rule from apf's preroute or postroute routing file.
func (f *APF) RemoveNATRule(ctx context.Context, zoneName string, r *NATRule) error {
	if err := r.validate(); err != nil {
		return err
	}
	changed, err := f.routeHook(f.natFile(r)).editNAT(r, true)
	f.ConfigChanged = f.ConfigChanged || changed
	return err
}

// GetDefaultPolicy is unsupported: apf has no managed default-policy control.
func (f *APF) GetDefaultPolicy(ctx context.Context, zoneName string) (*DefaultPolicy, error) {
	return nil, unsupportedPolicy(f.Type())
}

// SetDefaultPolicy is unsupported: apf has no managed default-policy control.
func (f *APF) SetDefaultPolicy(ctx context.Context, zoneName string, policy *DefaultPolicy) error {
	return unsupportedPolicy(f.Type())
}

// GetAddressSets returns the address sets carried by the apf pre-hook.
func (f *APF) GetAddressSets(ctx context.Context) ([]*AddressSet, error) {
	return f.hook().getAddressSets()
}

// GetAddressSet returns a single address set by name, or an error if absent.
func (f *APF) GetAddressSet(ctx context.Context, name string) (*AddressSet, error) {
	sets, err := f.hook().getAddressSets()
	if err != nil {
		return nil, err
	}
	for _, s := range sets {
		if s.Name == name {
			return s, nil
		}
	}
	return nil, fmt.Errorf("address set %q not found", name)
}

// AddAddressSet writes a set as ipset commands in the pre-hook; apf --restart
// (Reload) sources the hook to create the set. Re-adding a set is idempotent.
func (f *APF) AddAddressSet(ctx context.Context, set *AddressSet) error {
	if set == nil || set.Name == "" {
		return fmt.Errorf("an address set requires a name")
	}
	changed, err := f.hook().editAddressSet(set, false)
	f.ConfigChanged = f.ConfigChanged || changed
	return err
}

// RemoveAddressSet drops a set's ipset commands from the pre-hook. It fails if a
// hook rule still references the set; removing an absent set is a no-op.
func (f *APF) RemoveAddressSet(ctx context.Context, name string) error {
	changed, err := f.hook().editAddressSet(&AddressSet{Name: name}, true)
	f.ConfigChanged = f.ConfigChanged || changed
	return err
}

// AddAddressSetEntry adds an entry to an existing set in the pre-hook.
func (f *APF) AddAddressSetEntry(ctx context.Context, name, entry string) error {
	changed, err := f.hook().editAddressSetEntry(name, entry, false)
	f.ConfigChanged = f.ConfigChanged || changed
	return err
}

// RemoveAddressSetEntry removes an entry from an existing set in the pre-hook.
func (f *APF) RemoveAddressSetEntry(ctx context.Context, name, entry string) error {
	changed, err := f.hook().editAddressSetEntry(name, entry, true)
	f.ConfigChanged = f.ConfigChanged || changed
	return err
}

// Backup captures the current filter and NAT rules managed by this backend.
func (f *APF) Backup(ctx context.Context, zoneName string) (*Backup, error) {
	rules, err := f.GetRules(ctx, zoneName)
	if err != nil {
		return nil, err
	}
	natRules, err := f.GetNATRules(ctx, zoneName)
	if err != nil {
		return nil, err
	}
	// Backup captures the full filter and NAT rule state plus the hook's address
	// sets; Restore removes the current rules and re-adds these, so every rule read
	// is preserved.
	backup := &Backup{Rules: rules, NATRules: natRules}
	if err := captureBackupState(ctx, f, zoneName, backup); err != nil {
		return nil, err
	}
	return backup, nil
}

// Restore replaces the managed rules with the contents of a Backup.
func (f *APF) Restore(ctx context.Context, zoneName string, backup *Backup) error {
	if backup == nil {
		return fmt.Errorf("backup cannot be nil")
	}

	// Remove existing rules.
	existing, err := f.GetRules(ctx, zoneName)
	if err != nil {
		return err
	}
	for _, r := range existing {
		if err := f.RemoveRule(ctx, zoneName, r); err != nil {
			return err
		}
	}
	existingNAT, err := f.GetNATRules(ctx, zoneName)
	if err != nil {
		return err
	}
	for _, r := range existingNAT {
		if err := f.RemoveNATRule(ctx, zoneName, r); err != nil {
			return err
		}
	}

	// Recreate the address sets before the rules so a set-referencing rule resolves
	// when apf sources the hook. The old rules are already gone, and editAddressSet
	// rewrites each set's block idempotently, so cleanFirst is unnecessary.
	if err := restoreBackupSets(ctx, f, backup, false); err != nil {
		return err
	}

	// Re-add rules from backup.
	for _, r := range backup.Rules {
		if err := f.addRule(ctx, zoneName, r, false); err != nil {
			return err
		}
	}
	for _, r := range backup.NATRules {
		if err := f.AddNATRule(ctx, zoneName, r); err != nil {
			return err
		}
	}
	return nil
}

// Reload restarts apf to apply config changes, but only when a mutation changed its files.
func (f *APF) Reload(ctx context.Context) error {
	// apf --restart rewrites and reloads the whole ruleset, which is disruptive, so
	// only restart when a mutation actually changed apf's config files. A
	// successful restart consumes the flag; otherwise a second Reload with no
	// intervening mutation would restart apf again for nothing.
	if f.ConfigChanged {
		_, err := runCommand(ctx, "/etc/apf/apf", "--restart")
		if err != nil {
			return err
		}
		f.ConfigChanged = false
	}
	return nil
}

// Close releases resources held by the manager; apf holds none.
func (f *APF) Close(ctx context.Context) error {
	return nil
}
