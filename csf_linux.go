package firewall

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	CSFConf  = "/etc/csf/csf.conf"
	CSFAllow = "/etc/csf/csf.allow"
	CSFDeny  = "/etc/csf/csf.deny"
	// CSFRedirect holds csf's port-forwarding rules, one per line in the
	// pipe-delimited form "IPx|portA|IPy|portB|proto". A destination IP (IPy) of
	// "*" is a local port redirect; a concrete IPy is a forward to another host.
	CSFRedirect = "/etc/csf/csf.redirect"
	// CSFHook is the csf pre-hook, run after csf flushes and before it loads its
	// own rules, so injected rules land at the top of the chains and are re-added
	// on every reload. This library writes the iptables rules for features csf's
	// native config cannot express directly into this hook. (csf sources both
	// /usr/local/csf/bin/csfpre.sh and /etc/csf/csfpre.sh when present, so this
	// /etc/csf hook always runs.)
	CSFHook = "/etc/csf/csfpre.sh"
)

// CSF manages a ConfigServer Security & Firewall (csf) installation, mapping
// rules onto its config files (csf.conf, csf.allow, csf.deny, csf.redirect) and
// a managed pre-hook for features csf's native config cannot express.
type CSF struct {
	// rulePrefix tags rules this library creates so they can be told apart
	// from foreign rules. In csf.allow/csf.deny it is prepended to the
	// comment written on the line above each rule; csf.conf port-list rules
	// carry no per-rule comment and so cannot carry the tag.
	rulePrefix string
	// ipv6Enabled mirrors csf.conf's IPV6. With it off (the shipped default) csf
	// enforces no IPv6 at all: csf.pl's linefilter silently drops a csf.allow/
	// csf.deny line resolving to an IPv6 address, the TCP6_IN/UDP6_IN port lists
	// go unread, and ip6tables is never flushed on (re)load — so a hook-injected
	// ip6tables line would be re-appended on every reload and outlive its own
	// removal. AddRule therefore rejects every concrete-IPv6 rule rather than
	// write one csf will never enforce.
	ipv6Enabled bool
}

// NewCSF constructs a CSF manager, verifying the csf service is enabled and its
// config files are present, and reading whether csf's own IPv6 handling is on.
func NewCSF(ctx context.Context, rulePrefix string) (*CSF, error) {
	csf := new(CSF)
	csf.rulePrefix = rulePrefix

	// Confirm csf is enabled under whatever init system the host uses
	// (systemd, chkconfig, update-rc.d, OpenRC, Slackware rc.d, or rc.local).
	if !serviceEnabled(ctx, "csf") {
		return nil, fmt.Errorf("the csf service is not enabled on this server")
	}

	// Confirm config files exist.
	files := []string{CSFConf, CSFAllow, CSFDeny}
	for _, f := range files {
		if _, err := os.Stat(f); err != nil {
			return nil, fmt.Errorf("the config file %s is missing", f)
		}
	}

	// Confirm it is not disabled.
	if _, err := os.Stat("/etc/csf/csf.disable"); err == nil {
		return nil, fmt.Errorf("csf is currently disabled")
	}

	// Read whether csf's own IPv6 handling is turned on.
	useIPv6, err := readConfValue(CSFConf, "IPV6")
	if err != nil {
		return nil, fmt.Errorf("error reading %s: %s", CSFConf, err)
	}
	csf.ipv6Enabled = useIPv6 == "1"

	return csf, nil
}

// Type reports the backend identifier, "csf".
func (f *CSF) Type() string {
	return CSFType
}

// Capabilities reports the firewall features csf supports.
func (f *CSF) Capabilities() Capabilities {
	return Capabilities{
		Output:  true,
		Forward: true,
		// IPv6 mirrors ipv6Enabled: with csf.conf's IPV6 off, csf never touches
		// ip6tables, so neither its native config nor the raw-iptables hook yields a
		// rule csf will keep in sync across a reload (see ipv6Enabled).
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
		// A csf.deny entry stores no action; csf applies csf.conf's configured
		// deny action, so removal matches an entry whatever action is named.
		DenyActionFromConfig: true,
	}
}

// GetZone reports no zone; csf has no concept of zones.
func (f *CSF) GetZone(ctx context.Context, iface string) (zoneName string, err error) {
	return "", nil
}

// ParseConnLimit decodes a csf.conf CONNLIMIT value ("port;limit,...") into
// connection-limit rules: csf caps concurrent new TCP connections per source and
// rejects the excess with a TCP reset, so each entry becomes an inbound tcp
// reject rule carrying a per-source ConnLimit.
func (f *CSF) ParseConnLimit(val string) (rules []*Rule) {
	for _, entry := range strings.Split(val, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		portTok, limitTok, ok := strings.Cut(entry, ";")
		if !ok {
			continue
		}
		port, err := strconv.ParseUint(strings.TrimSpace(portTok), 10, 16)
		if err != nil {
			continue
		}
		limit, err := strconv.ParseUint(strings.TrimSpace(limitTok), 10, 32)
		if err != nil {
			continue
		}
		// CONNLIMIT is a single config key, but csf.pl only installs its IPv6
		// CONNLIMIT rule (ip6tables) when csf.conf's IPV6 is enabled (ConfigServer/
		// Config.pm, csf.pl); on the shipped default (IPV6="0") CONNLIMIT is IPv4
		// only. Report FamilyAny when IPv6 handling is on — so a FamilyAny desired
		// connlimit rule reconciles with its dual-stack read-back rather than
		// churning every Sync — and IPv4 otherwise, matching what csf actually
		// enforces.
		fam := IPv4
		if f.ipv6Enabled {
			fam = FamilyAny
		}
		rules = append(rules, &Rule{
			Family:    fam,
			Proto:     TCP,
			Port:      uint16(port),
			Action:    Reject,
			ConnLimit: &ConnLimit{Count: uint(limit), PerSource: true},
		})
	}
	return
}

// parseAddr classifies a csf advanced-rule address field. It returns the
// address, its family, and whether the value is an address at all (a non-address
// value is a port list or ICMP type). A zero "any" network (0.0.0.0/0 or ::/0)
// is normalized to an empty address so a port-only rule written with the "any"
// placeholder round-trips against a rule that carries no address.
func (f *CSF) parseAddr(v string) (addr string, fam Family, ok bool) {
	family, ok := parseAddrFamily(v)
	if !ok {
		return "", FamilyAny, false
	}
	if _, network, err := net.ParseCIDR(v); err == nil {
		if ones, _ := network.Mask.Size(); ones == 0 && network.IP.IsUnspecified() {
			return "", family, true
		}
	}
	return v, family, true
}

// parseAdvPorts parses a csf advanced-rule port value: a comma list whose
// entries are single ports or underscore ranges (e.g. "22,80,2000_3000").
func (f *CSF) parseAdvPorts(val string) ([]PortRange, error) {
	var specs []PortRange
	for _, tok := range strings.Split(val, ",") {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			continue
		}
		lo, hi, isRange := strings.Cut(tok, "_")
		start, err := strconv.ParseUint(strings.TrimSpace(lo), 10, 16)
		if err != nil {
			return nil, fmt.Errorf("invalid port %q", lo)
		}
		pr := PortRange{Start: uint16(start), End: uint16(start)}
		if isRange {
			end, err := strconv.ParseUint(strings.TrimSpace(hi), 10, 16)
			if err != nil {
				return nil, fmt.Errorf("invalid port %q", hi)
			}
			pr.End = uint16(end)
			if pr.End < pr.Start {
				return nil, fmt.Errorf("port range end below start")
			}
		}
		specs = append(specs, pr)
	}
	if len(specs) == 0 {
		return nil, fmt.Errorf("no ports")
	}
	return specs, nil
}

// ParseAdvRule decodes a csf advanced allow/deny rule of the form
// tcp/udp/icmp|in/out|s/d=port(s)|s/d=ip. The port field accepts a comma
// multiport list and underscore ranges; for icmp it holds the ICMP type.
func (f *CSF) ParseAdvRule(val string, action Action) (r *Rule) {
	r = &Rule{
		Action: action,
	}

	fields := strings.Split(val, "|")
	for _, fld := range fields {
		switch {
		case strings.EqualFold(fld, "tcp"):
			r.Proto = TCP
		case strings.EqualFold(fld, "udp"):
			r.Proto = UDP
		case strings.EqualFold(fld, "icmp"):
			r.Proto = ICMP
		case strings.EqualFold(fld, "in"):
			r.Direction = DirInput
		case strings.EqualFold(fld, "out"):
			r.Direction = DirOutput
		case strings.HasPrefix(fld, "s="):
			// The source field is either an address or, when it is not, an ICMP type
			// for icmp rules or a source port list/range otherwise. csf reuses the
			// port position for the ICMP type in both s= and d= (csf.pl maps
			// `s=<n>` to `--icmp-type <n>` for an icmp rule), so mirror the d= branch.
			v := strings.TrimPrefix(fld, "s=")
			if addr, fam, ok := f.parseAddr(v); ok {
				r.Family = fam
				r.Source = addr
				continue
			}
			if r.Proto == ICMP {
				n, ok := parseICMPType(v)
				if !ok {
					return nil
				}
				r.ICMPType = Ptr(n)
				continue
			}
			specs, err := f.parseAdvPorts(v)
			if err != nil {
				return nil
			}
			sourcePortSpecsToRule(r, specs)
		case strings.HasPrefix(fld, "d="):
			v := strings.TrimPrefix(fld, "d=")
			// A destination value is either an address, or (when it is not) an
			// ICMP type for icmp rules or a port list/range otherwise.
			if addr, fam, ok := f.parseAddr(v); ok {
				r.Family = fam
				r.Destination = addr
				continue
			}
			if r.Proto == ICMP {
				n, ok := parseICMPType(v)
				if !ok {
					return nil
				}
				r.ICMPType = Ptr(n)
				continue
			}
			specs, err := f.parseAdvPorts(v)
			if err != nil {
				return nil
			}
			portSpecsToRule(r, specs)
		case strings.HasPrefix(fld, "u=") || strings.HasPrefix(fld, "g="):
			return nil
		}
	}

	// csf.pl defaults a protocol-less advanced line to `-p tcp` (its $protocol
	// starts as "-p tcp"), so mirror it: reading the line back as ProtocolAny
	// would report an all-protocol rule csf does not enforce, and one whose
	// removal the iptables validity check rejects.
	if r.Proto == ProtocolAny {
		r.Proto = TCP
	}

	return
}

// ParseIPList reads a csf.allow/csf.deny file into rules, stamping each with the
// given action and any full-line comment that precedes it (see scanCommentGroups
// for the comment-attachment convention).
func (f *CSF) ParseIPList(filePath string, action Action) (rules []*Rule, err error) {
	// Read the allow/deny IP rule list.
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
		// parseListLine classifies an advanced line (pipe or colon delimited) or a
		// plain address line — one bidirectional DirAny rule authored in the
		// inbound frame (Source=X) — and skips anything else.
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

// ParsePorts decodes a csf.conf port-list value into one accept rule per port
// token for the given family, protocol, and direction.
func (f *CSF) ParsePorts(val string, family Family, proto Protocol, dir Direction) (rules []*Rule) {
	ports := strings.Split(val, ",")
	for _, port := range ports {
		port = strings.TrimSpace(port)
		if port == "" {
			continue
		}

		// A csf.conf port token is a single port or a colon range.
		pr, err := ParsePortRange(port)
		if err != nil {
			continue
		}
		rule := &Rule{
			Family:    family,
			Proto:     proto,
			Direction: dir,
			Action:    Accept,
		}
		portSpecsToRule(rule, []PortRange{pr})
		rules = append(rules, rule)
	}
	return
}

// dropActions reads csf.conf's DROP (inbound) and DROP_OUT (outbound)
// settings, which decide whether a csf.deny entry is dropped or rejected: csf
// builds its DENYIN chain with `-j $DROP` and its DENYOUT chain with
// `-j $DROP_OUT`, so a deny rule's effective action follows its direction.
// Only "DROP" and "REJECT" are valid values; anything else (or an unreadable
// file) falls back to stock csf defaults — DROP drops inbound, DROP_OUT rejects
// outbound.
func (f *CSF) dropActions() (dropIn, dropOut Action) {
	dropIn, dropOut = Drop, Reject
	fd, err := os.Open(CSFConf)
	if err != nil {
		return
	}
	defer func() { _ = fd.Close() }()

	scanner := bufio.NewScanner(fd)
	for scanner.Scan() {
		line := scanner.Text()
		if ci := strings.IndexByte(line, '#'); ci >= 0 {
			line = line[:ci]
		}
		key, val, found := strings.Cut(strings.TrimSpace(line), "=")
		if !found {
			continue
		}
		key = strings.TrimSpace(key)
		val = strings.ToUpper(trimQuotes(strings.TrimSpace(val)))
		switch key {
		case "DROP":
			if val == "REJECT" {
				dropIn = Reject
			} else {
				dropIn = Drop
			}
		case "DROP_OUT":
			if val == "DROP" {
				dropOut = Drop
			} else {
				dropOut = Reject
			}
		}
	}
	return
}

// hook returns the managed pre-hook script used to inject iptables rules for
// features csf's native config cannot express.
func (f *CSF) hook() *hookScript {
	return newHookScript(f.rulePrefix, CSFHook, 0700, f.ipv6Enabled)
}

// --- live counters -----------------------------------------------------------

// liveChain reports the direction a live chain's rows stand for, and whether the
// chain is one csf's rules reach at all. csf appends its config-driven rules
// straight onto INPUT/OUTPUT/FORWARD and keeps the allow and deny lists in
// per-direction chains of its own, so every chain here names its direction. The
// rest — csf's sanity, logging and rate-limit chains — hold rows that stand for
// no rule this backend reports.
func (f *CSF) liveChain(chain string) (Direction, bool) {
	switch chain {
	case "INPUT", "LOCALINPUT", "ALLOWIN", "DENYIN", "GALLOWIN", "GDENYIN":
		return DirInput, true
	case "OUTPUT", "LOCALOUTPUT", "ALLOWOUT", "DENYOUT", "GALLOWOUT", "GDENYOUT":
		return DirOutput, true
	case "FORWARD", "ALLOWFWD", "DENYFWD":
		return DirForward, true
	}
	return DirInput, false
}

// interfaceFrame returns the interface match csf stamps on every rule it
// generates: `! -i lo`/`! -o lo` by default, or `-i <dev>`/`-o <dev>` when
// csf.conf's ETH_DEVICE names one. The frame is csf's own — a TCP_IN entry
// decodes to a plain port accept, not an interface-bound one — so it is stripped
// off a live row before the row is parsed. Stripping it is also what separates a
// row csf generated from a raw one the pre-hook injected, which carries no frame
// and is reported exactly as written.
func (f *CSF) interfaceFrame() (in, out string) {
	dev, err := readConfValue(CSFConf, "ETH_DEVICE")
	if err != nil || dev == "" {
		return "! -i lo", "! -o lo"
	}
	return "-i " + dev, "-o " + dev
}

// logDropAction maps csf's logging drop chains onto the terminal action they end
// in. csf routes a blocked packet through LOGDROPIN/LOGDROPOUT when DROP_LOGGING
// is on, so the row that stands for a deny jumps to one of those rather than
// naming its action; the action is csf.conf's DROP (inbound) or DROP_OUT
// (outbound), which is what the deny list decodes to. Both are passed in, having
// been read once for the whole ruleset rather than per row.
func (f *CSF) logDropAction(target string, dropIn, dropOut Action) (Action, bool) {
	switch target {
	case "LOGDROPIN":
		return dropIn, true
	case "LOGDROPOUT":
		return dropOut, true
	}
	return ActionInvalid, false
}

// parseLiveRules decodes counter-annotated `iptables-save -c` output into the
// rules csf's chains hold. csf frames every rule it generates with an interface
// match, and a port-list rule with a NEW state match, neither of which is part of
// the rule the config decodes to; both are undone here so a row lines up with the
// entry that produced it. A row jumping into csf's logging drop chain is restored
// to the action that chain ends in.
func (f *CSF) parseLiveRules(out []string, fam Family) []*Rule {
	// The settings that decide how a row reads back come from csf.conf, so read
	// them once here rather than per row.
	frameIn, frameOut := f.interfaceFrame()
	dropIn, dropOut := f.dropActions()
	return decodeLiveRows(out, func(row liveRow) (*Rule, bool) {
		dir, ok := f.liveChain(row.chain)
		if !ok {
			return nil, false
		}

		// Strip csf's interface frame. The rulespec parser rejects a negated
		// interface outright, so this has to happen on the line rather than on the
		// parsed rule.
		framed := false
		for _, frame := range []string{frameIn, frameOut} {
			if strings.Contains(row.line, " "+frame+" ") {
				row.line = strings.Replace(row.line, " "+frame+" ", " ", 1)
				framed = true
			}
		}

		// Restore the action behind a jump into csf's logging drop chain.
		target := jumpTarget(row.fields)
		if action, isDrop := f.logDropAction(target, dropIn, dropOut); isDrop {
			row.line = strings.Replace(row.line, "-j "+target,
				"-j "+strings.ToUpper(action.String()), 1)
		}

		rule, ok := parseLiveRow(row, dir, fam)
		if !ok {
			return nil, false
		}
		// csf opens a port-list rule with a NEW state match. Clear it only on a row
		// csf framed, so a pre-hook rule that genuinely matches on state keeps it.
		if framed && rule.State == StateNew {
			rule.State = 0
		}
		return rule, true
	})
}

// claimDenyOutRows attributes the outbound half of a bidirectional deny. A
// csf.deny address is one line that csf implements as two rows carrying two
// different actions — csf.conf's DROP inbound, DROP_OUT outbound — while the
// line reads back as a single DirAny rule stamped with the inbound one (see
// GetRules). The outbound row therefore matches that rule on every field but
// action and is left unclaimed, so it is claimed here rather than dropped: its
// packets are the ones that entry blocked on the way out.
func (f *CSF) claimDenyOutRows(targets, leftover []*Rule) {
	dropIn, dropOut := f.dropActions()
	if dropIn == dropOut {
		return
	}
	for _, l := range leftover {
		if l == nil || l.Direction != DirOutput || l.Action != dropOut {
			continue
		}
		// Compare with the action the entry reads back as; every other field must
		// still line up, so an unrelated outbound deny is not absorbed.
		probe := *l
		probe.Action = dropIn
		for _, r := range targets {
			if r.Direction != DirAny || r.Action != dropIn || !r.Covers(&probe) {
				continue
			}
			r.Packets += l.Packets
			r.Bytes += l.Bytes
			break
		}
	}
}

// mergeLiveCounters copies the kernel's packet/byte counters onto the rules read
// from csf.conf, the allow/deny lists and the pre-hook.
func (f *CSF) mergeLiveCounters(ctx context.Context, rules []*Rule, fam Family) {
	targets := countableRules(rules, fam)
	if len(targets) == 0 {
		return
	}
	leftover := applyLiveCounters(targets, f.parseLiveRules(liveSaveLines(ctx, fam), fam))
	f.claimDenyOutRows(targets, leftover)
}

// GetRules reads all filter rules from csf's config files and the managed
// pre-hook, merging family and protocol fan-outs back to their written form.
func (f *CSF) GetRules(ctx context.Context, zoneName string) (rules []*Rule, err error) {
	// Read the standard configuration.
	fd, err := os.Open(CSFConf)
	if err != nil {
		return nil, err
	}

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
		case "TCP_IN":
			rules = append(rules, f.ParsePorts(val, IPv4, TCP, DirInput)...)
		case "TCP_OUT":
			rules = append(rules, f.ParsePorts(val, IPv4, TCP, DirOutput)...)
		case "UDP_IN":
			rules = append(rules, f.ParsePorts(val, IPv4, UDP, DirInput)...)
		case "UDP_OUT":
			rules = append(rules, f.ParsePorts(val, IPv4, UDP, DirOutput)...)
		case "TCP6_IN", "TCP6_OUT", "UDP6_IN", "UDP6_OUT":
			// With IPV6 off csf never applies the *6_* lists, so their entries
			// are inert; reporting them would claim IPv6 coverage the firewall
			// does not enforce.
			if !f.ipv6Enabled {
				continue
			}
			proto := TCP
			if strings.HasPrefix(key, "UDP") {
				proto = UDP
			}
			dir := DirInput
			if strings.HasSuffix(key, "_OUT") {
				dir = DirOutput
			}
			rules = append(rules, f.ParsePorts(val, IPv6, proto, dir)...)
		case "CONNLIMIT":
			rules = append(rules, f.ParseConnLimit(val)...)
		}
	}

	_ = fd.Close()
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	// Read the allowed IP rule list.
	ipRules, err := f.ParseIPList(CSFAllow, Accept)
	if err != nil {
		return nil, err
	}
	rules = append(rules, ipRules...)

	// Read the denied IP rule list. A csf.deny entry takes effect as the DROP
	// (inbound) or DROP_OUT (outbound) action from csf.conf, so stamp each rule
	// with the action its direction actually gets rather than a fixed Reject —
	// otherwise a Drop rule the caller manages reads back as Reject, never
	// compares equal to the desired rule, and churns on every Sync.
	// LF_BLOCKINONLY (off in stock csf.conf) is not modeled: with it set, csf
	// skips a deny line's outbound rule while the line still reads back DirAny.
	dropIn, dropOut := f.dropActions()
	ipRules, err = f.ParseIPList(CSFDeny, dropIn)
	if err != nil {
		return nil, err
	}
	for _, r := range ipRules {
		if r.IsOutput() {
			r.Action = dropOut
		}
	}
	rules = append(rules, ipRules...)

	// Read the iptables rules injected through the csf pre-hook (state,
	// interface, logging, rate-limit, icmpv6).
	hookRules, err := f.hook().getRules()
	if err != nil {
		return nil, err
	}
	rules = append(rules, hookRules...)

	// csf's config files carry no packet/byte counters — the kernel does — so
	// merge them from the live ruleset (RuleCounters).
	f.mergeLiveCounters(ctx, rules, IPv4)
	f.mergeLiveCounters(ctx, rules, IPv6)
	return
}

// confPortToken renders a port spec for a csf.conf port list, where a range
// is written with a colon (e.g. "30000:35000").
func (f *CSF) confPortToken(pr PortRange) string {
	pr = pr.normalized()
	if pr.Start == pr.End {
		return strconv.FormatUint(uint64(pr.Start), 10)
	}
	return fmt.Sprintf("%d:%d", pr.Start, pr.End)
}

// editConnLimit renders the csf.conf CONNLIMIT line with a port's per-source
// limit added or removed, preserving the other entries.
func (f *CSF) editConnLimit(val string, port uint16, limit uint, remove bool) string {
	portStr := strconv.Itoa(int(port))
	var kept []string
	present := false
	for _, tok := range strings.Split(val, ",") {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			continue
		}
		p, _, ok := strings.Cut(tok, ";")
		if ok && strings.TrimSpace(p) == portStr {
			present = true
			if remove {
				continue
			}
			kept = append(kept, fmt.Sprintf("%d;%d", port, limit))
			continue
		}
		kept = append(kept, tok)
	}
	if !remove && !present {
		kept = append(kept, fmt.Sprintf("%d;%d", port, limit))
	}
	return fmt.Sprintf(`CONNLIMIT = "%s"`, strings.Join(kept, ","))
}

// isConnLimitRule reports whether a rule maps onto csf.conf's CONNLIMIT: a
// per-source cap on concurrent new connections to a single inbound TCP port with
// no address. csf's CONNLIMIT chain rejects the excess with a TCP reset
// (`-j REJECT --reject-with tcp-reset`), so the excess action is Reject, not Drop.
func (f *CSF) isConnLimitRule(r *Rule) bool {
	return r.ConnLimit != nil && r.ConnLimit.PerSource &&
		!r.IsOutput() && r.Proto == TCP && r.Source == "" && r.Destination == "" &&
		r.HasPorts() && !r.HasPortSet() && r.Action == Reject
}

// EditRulePort returns the config line for key with the rule's port added or
// removed, leaving lines the rule does not apply to unchanged.
func (f *CSF) EditRulePort(orig, key, val string, r *Rule, remove bool) string {
	// A connection-limit rule is expressed solely through the CONNLIMIT config;
	// it must never also add or remove its port from an accept port list, or
	// RemoveRule would close a port the caller never opened and a round-trip
	// would report a spurious accept rule alongside the connlimit.
	if r.ConnLimit != nil && key != "CONNLIMIT" {
		return orig
	}

	// Determine if this key needs edits.
	switch key {
	case "TCP_IN":
		if r.IsOutput() || r.Family == IPv6 || r.Proto == UDP {
			return orig
		}
	case "TCP_OUT":
		if !r.IsOutput() || r.Family == IPv6 || r.Proto == UDP {
			return orig
		}
	case "UDP_IN":
		if r.IsOutput() || r.Family == IPv6 || r.Proto == TCP {
			return orig
		}
	case "UDP_OUT":
		if !r.IsOutput() || r.Family == IPv6 || r.Proto == TCP {
			return orig
		}
	case "TCP6_IN":
		if r.IsOutput() || r.Family == IPv4 || r.Proto == UDP {
			return orig
		}
		if !remove && !f.ipv6Enabled && r.Family != IPv6 {
			// With IPV6 off a family-agnostic add is written for IPv4 only (the
			// v6 entry would sit inert and read back as unenforced coverage);
			// removals still sweep, and a concrete-IPv6 row written by Restore
			// keeps its family. The list-file analog is filterFamiliesIPv6.
			return orig
		}
	case "TCP6_OUT":
		if !r.IsOutput() || r.Family == IPv4 || r.Proto == UDP {
			return orig
		}
		if !remove && !f.ipv6Enabled && r.Family != IPv6 {
			// With IPV6 off a family-agnostic add is written for IPv4 only (the
			// v6 entry would sit inert and read back as unenforced coverage);
			// removals still sweep, and a concrete-IPv6 row written by Restore
			// keeps its family. The list-file analog is filterFamiliesIPv6.
			return orig
		}
	case "UDP6_IN":
		if r.IsOutput() || r.Family == IPv4 || r.Proto == TCP {
			return orig
		}
		if !remove && !f.ipv6Enabled && r.Family != IPv6 {
			// With IPV6 off a family-agnostic add is written for IPv4 only (the
			// v6 entry would sit inert and read back as unenforced coverage);
			// removals still sweep, and a concrete-IPv6 row written by Restore
			// keeps its family. The list-file analog is filterFamiliesIPv6.
			return orig
		}
	case "UDP6_OUT":
		if !r.IsOutput() || r.Family == IPv4 || r.Proto == TCP {
			return orig
		}
		if !remove && !f.ipv6Enabled && r.Family != IPv6 {
			// With IPV6 off a family-agnostic add is written for IPv4 only (the
			// v6 entry would sit inert and read back as unenforced coverage);
			// removals still sweep, and a concrete-IPv6 row written by Restore
			// keeps its family. The list-file analog is filterFamiliesIPv6.
			return orig
		}
	case "CONNLIMIT":
		// CONNLIMIT tokens are "port;limit", edited independently of the port
		// lists above.
		if !f.isConnLimitRule(r) {
			return orig
		}
		// isConnLimitRule guarantees a single discrete port, which may be
		// carried in either Port or a one-element Ports; read it via PortSpecs so
		// a rule expressing its port through Ports is not written as port 0.
		return f.editConnLimit(val, r.PortSpecs()[0].Start, r.ConnLimit.Count, remove)
	default:
		return orig
	}

	// The rule may carry one or more ports (a single port, a range, or a list).
	// Add or remove each of the rule's port tokens from the config list,
	// preserving any existing tokens the rule does not touch.
	specs := r.PortSpecs()
	present := make(map[string]bool)
	var kept []string
	for _, tok := range strings.Split(val, ",") {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			continue
		}
		// Preserve tokens we cannot parse untouched.
		pr, err := ParsePortRange(tok)
		if err != nil {
			kept = append(kept, tok)
			continue
		}
		if remove && portRangeInSpecs(pr, specs) {
			continue
		}
		kept = append(kept, tok)
		present[f.confPortToken(pr)] = true
	}
	if !remove {
		for _, sp := range specs {
			tok := f.confPortToken(sp)
			if !present[tok] {
				kept = append(kept, tok)
				present[tok] = true
			}
		}
	}

	// Re-create the configuration with new port list.
	return fmt.Sprintf(`%s = "%s"`, key, strings.Join(kept, ","))
}

// EditConf rewrites csf.conf to add or remove a port-list or CONNLIMIT rule.
func (f *CSF) EditConf(ctx context.Context, r *Rule, remove bool) error {
	// Open the standard config file; EditRulePort rewrites the port-list and
	// CONNLIMIT lines the rule applies to.
	fd, err := os.Open(CSFConf)
	if err != nil {
		return err
	}

	// Stage the rewrite, preserving csf.conf's mode and ownership.
	af, err := newAtomicFile(CSFConf, 0644)
	if err != nil {
		_ = fd.Close()
		return err
	}
	defer af.Abort()

	// Parse config one line at a time, adding the port rule.
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
		orig = f.EditRulePort(orig, key, val, r, remove)
		_, _ = fmt.Fprintln(af, orig)
	}

	_ = fd.Close()

	// A read error means the rewritten file is truncated; discard it.
	if serr := scanner.Err(); serr != nil {
		return serr
	}

	// Move new file into place, preserving mode and ownership.
	return af.Commit()
}

// advPortValue renders port specs for a csf advanced rule, which uses a comma
// list and an underscore range (e.g. "22,80,2000_3000").
func (f *CSF) advPortValue(specs []PortRange) string {
	parts := make([]string, len(specs))
	for i, pr := range specs {
		pr = pr.normalized()
		if pr.Start == pr.End {
			parts[i] = strconv.FormatUint(uint64(pr.Start), 10)
		} else {
			parts[i] = fmt.Sprintf("%d_%d", pr.Start, pr.End)
		}
	}
	return strings.Join(parts, ",")
}

// MarshalAdvRule encodes a rule as a csf advanced allow/deny line: a protocol
// token, a direction, one port-flow field (an icmp type, a source port or a
// destination port) and one address field, joined by "|". It validates nothing;
// addRule/RemoveRule route every shape the line cannot carry elsewhere first.
func (f *CSF) MarshalAdvRule(r *Rule) string {
	var parts []string
	switch r.Proto {
	case TCP:
		parts = append(parts, "tcp")
	case UDP:
		parts = append(parts, "udp")
	case ICMP:
		parts = append(parts, "icmp")
	}
	if r.IsOutput() {
		parts = append(parts, "out")
	} else {
		parts = append(parts, "in")
	}

	// The port-flow field: an ICMP type, a source port, or a destination port.
	switch {
	case r.Proto == ICMP:
		if r.ICMPType != nil {
			parts = append(parts, fmt.Sprintf("d=%d", *r.ICMPType))
		}
	case r.HasSourcePorts():
		parts = append(parts, "s="+f.advPortValue(r.SourcePortSpecs()))
	case r.HasPorts():
		parts = append(parts, "d="+f.advPortValue(r.PortSpecs()))
	}

	// Address.
	if r.Source != "" {
		parts = append(parts, "s="+r.Source)
	} else if r.Destination != "" {
		parts = append(parts, "d="+r.Destination)
	}

	return strings.Join(parts, "|")
}

// parseListLine parses one csf.allow/csf.deny rule line into the rule it holds: an
// advanced rule, or a plain address line, which is a single bidirectional DirAny
// rule matching every protocol. It returns nil for a line that is neither, which the
// caller passes through untouched. The action comes from the file (csf.allow is
// accept, csf.deny is a deny); the line encodes none of its own.
func (f *CSF) parseListLine(line string, action Action) *Rule {
	if strings.Contains(line, "|") {
		return f.ParseAdvRule(line, action)
	}
	if family, ok := parseAddrFamily(line); ok {
		return &Rule{Direction: DirAny, Family: family, Source: line, Action: action}
	}
	// csf.pl accepts a colon-delimited advanced line, converting `:` to `|` when
	// the line carries no pipe; an address (IPv6 included) was classified above,
	// so the conversion never touches one. An advanced line always carries an s=
	// or d= field, which keeps other unparseable colon text opaque.
	if strings.Contains(line, ":") && strings.Contains(line, "=") {
		return f.ParseAdvRule(strings.ReplaceAll(line, ":", "|"), action)
	}
	return nil
}

// listRows returns the csf.allow/csf.deny rows a rule materializes into, in write
// order, or none for a shape the lists cannot hold. The rule must already carry the
// action its file implies (see EditIPList's match), since each row's read-back form
// is compared against lines stamped with it.
//
// csf has no both-transports line anywhere — csf.pl's linefilter silently reads a
// protocol-less advanced line as `-p tcp` — so a TCPUDP rule fans out into a tcp row
// and a udp row. A port-only deny additionally carries no address of its own, and
// csf's advanced-rule handler only emits an iptables rule for a line that has one, so
// each of its rows takes the "any" network as a placeholder address. That literal is
// family-specific, so a family-neutral rule fans out per family too rather than
// silently becoming IPv4-only — across the families csf actually enforces (see
// filterFamiliesIPv6; with csf.conf's IPV6 off that is IPv4 alone). parseAddr normalizes
// the placeholder back to an empty address, so each row reads back as the address-less
// rule it stands for.
func (f *CSF) listRows(action Action, match *Rule) []ruleLine {
	hasIP := match.Source != "" || match.Destination != ""
	var rows []ruleLine
	switch {
	case hasIP && (match.HasPorts() || match.HasSourcePorts() || match.Proto.IsICMP()):
		// A port/ICMP rule with an address is an advanced rule.
		for _, sub := range expandProtocols(match) {
			rows = append(rows, ruleLine{line: f.MarshalAdvRule(sub), read: sub})
		}
	case hasIP:
		// A bare all-protocol host allow/deny: a single address matching every
		// protocol. csf.allow/csf.deny hold no other portless address shape — a
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
		for _, fam := range filterFamiliesIPv6(f.ipv6Enabled, match) {
			placeholder := "0.0.0.0/0"
			if fam.impliedFamily() == IPv6 {
				placeholder = "::/0"
			}
			for _, sub := range expandProtocols(fam) {
				// The row reads back address-less; only the line carries the placeholder.
				// shapeNeedsHook has already routed an address-less source-port match to
				// the hook, so the address field being filled in here is free.
				row := *sub
				if row.IsOutput() {
					row.Destination = placeholder
				} else {
					row.Source = placeholder
				}
				rows = append(rows, ruleLine{line: f.MarshalAdvRule(&row), read: sub})
			}
		}
	}
	return rows
}

// EditIPList adds or removes a rule in a csf.allow/csf.deny list, rewriting it in
// place. An add expands the rule into the rows it materializes into (see listRows),
// notes which of them the file already holds, and appends only the rest, so a rule
// that fans out across families or transports is completed rather than duplicated on
// every reconcile. A removal drops every line the target covers.
func (f *CSF) EditIPList(ctx context.Context, filePath string, action Action, r *Rule, remove bool) error {
	// Read the allow/deny IP rule list.
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

	// csf.allow/csf.deny encode no action of their own — the file decides it
	// (csf.allow is accept, csf.deny is a deny). A rule read from a file is stamped
	// with that file's action, so match an incoming rule with its action coerced
	// the same way: otherwise a rule added as Drop (written to csf.deny, read back
	// as the deny action) could never be found and removed.
	match := *r
	match.Action = action
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
		// TCPUDP or family-neutral target touches each of the concrete lines it was
		// written as; that coverage is folded into EqualForRemoval.
		if remove {
			if cur.EqualForRemoval(&match, true) {
				return nil
			}
			keep()
			return nil
		}

		// An add keeps every line and only notes which wanted rows the file already
		// covers, so the tail writes the rest. Coverage rather than a text compare, so
		// a row is satisfied by an existing line that spans it (a TCPUDP line absorbing
		// a tcp row) and by one spelled differently but meaning the same.
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
		writeComment()
		_, _ = fmt.Fprintln(af, row.line)
	}

	// Move new file into place, preserving mode and ownership.
	return af.Commit()
}

// needsHook reports whether a rule must be injected through the csf pre-hook as a
// raw iptables rule because csf's native config cannot express it. It is the single
// gate between the hook path and csf's config files: everything it rejects (returns
// true) is written to the hook, everything it accepts (returns false) maps onto
// csf.conf or the csf.allow/csf.deny lists. The shared predicates (ruleNeedsHook,
// shapeNeedsHook, bareHostOneWay) stay standalone, since APF shares them and
// RemoveRule routes on ruleNeedsHook and bareHostOneWay directly.
func (f *CSF) needsHook(r *Rule) bool {
	// Features csf's native config cannot express (connection state, per-rule
	// interface, logging, rate limiting, forward-chain routing, icmpv6, a transport
	// csf does not carry, an address set) go to the hook.
	if ruleNeedsHook(r) {
		return true
	}
	// A shape no native csf form holds — a one-way bare host, a source+destination
	// pair, a concrete-protocol portless host, an advanced-line address/port-flow
	// overflow, or a bare protocol match (see shapeNeedsHook) — goes to the hook.
	if shapeNeedsHook(r) {
		return true
	}
	// An address-less multi-port accept goes to the hook's `-m multiport` match:
	// a csf.conf port list stores each port as an independent token that reads
	// back as its own rule, so the list shape has no single native form (see
	// multiPortConfAccept). An addressed multi-port rule stays native — an
	// advanced line's port field is a comma list.
	if f.multiPortConfAccept(r) {
		return true
	}
	// A connection limit csf.conf's CONNLIMIT cannot express — anything but a
	// per-source cap on a single address-less inbound tcp port rejecting the excess
	// (isConnLimitRule) — goes to the hook's `-m connlimit` match.
	if r.ConnLimit != nil && !f.isConnLimitRule(r) {
		return true
	}
	// An ICMPv4 rule csf's advanced-rule format cannot carry goes to the hook's
	// `iptables -p icmp` match, which needs neither an address nor a type. The only
	// native form is exactly one address with a concrete type: an advanced line
	// requires an address, its single port-flow field carries the icmp type, and
	// csf.pl's linefilter reads that field by position — an address with no type
	// would land the address there (`--icmp-type <ip>`), which csf fails to parse
	// and drops silently. A source+destination pair overflows the single address
	// field and is routed by shapeNeedsHook above; ICMPv6 never reaches this test —
	// ruleNeedsHook sends it to the hook, or the IPv6 gate rejects it.
	return r.Proto == ICMP && (r.ICMPType == nil || (r.Source != "") == (r.Destination != ""))
}

// multiPortConfAccept reports whether a rule is an address-less tcp/udp accept
// carrying a discrete multi-port list — the one port shape a csf.conf port list
// cannot hold as a single rule: TCP_IN="80,443" stores independent tokens that
// read back one rule per port, so the rule would never round-trip whole. AddRule
// injects it through the hook's `-m multiport` match, which keeps the list on
// one line; a single port or one range stays a native token. A connection-limited
// rule is excluded (CONNLIMIT routing owns it), as is a source-port match, which
// is not the port-list shape and is routed by shapeNeedsHook — the exclusions let
// RemoveRule sweep the csf.conf port lists for this shape without touching tokens
// other rules own.
func (f *CSF) multiPortConfAccept(r *Rule) bool {
	return onProtocolAxis(r.Proto) && r.Action == Accept && r.ConnLimit == nil &&
		r.Source == "" && r.Destination == "" && !r.HasSourcePorts() &&
		len(r.PortSpecs()) > 1
}

// denyAction returns the action a csf.deny entry takes in the given direction,
// following csf.conf's DROP (inbound) / DROP_OUT (outbound) settings. A deny
// rule this library writes must carry exactly this action: csf.deny encodes no
// action of its own, so a rule read back is stamped with what csf would apply,
// and a caller asking for the opposite action could never reconcile against it.
func (f *CSF) denyAction(output bool) Action {
	dropIn, dropOut := f.dropActions()
	if output {
		return dropOut
	}
	return dropIn
}

// addRule is AddRule's implementation, with the IPv6 gate optional so Restore
// can reproduce a prior snapshot's inert entries rather than be rejected by a
// gate meant to catch fresh no-op writes.
func (f *CSF) addRule(ctx context.Context, zoneName string, r *Rule, enforceIPv6Gate bool) error {
	// Reject a concrete-IPv6 rule when csf's own IPv6 handling is off, ahead of every
	// routing decision below: neither csf's config nor the pre-hook can carry one that
	// csf will keep in sync (see ipv6Enabled). Checking here rather than past the
	// hook branches also keeps a DirAny rule from writing its input half before its
	// output half is rejected.
	if enforceIPv6Gate && !f.ipv6Enabled && r.impliedFamily() == IPv6 {
		return fmt.Errorf("csf's IPv6 handling is disabled (csf.conf IPV6 is not \"1\"): %w", ErrUnsupported)
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

	// csf has no both-transports construct anywhere: its port lists are a TCP list and
	// a UDP list, and csf.pl's linefilter silently reads a protocol-less advanced line
	// as `-p tcp` rather than as both transports. So a TCPUDP rule fans out into a tcp
	// rule and a udp rule, each routed independently, and each reads back as its own
	// rule.
	if r.Proto == TCPUDP {
		for _, sub := range expandProtocols(r) {
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

	// Any shape csf's native config cannot express (a stateful/interface/logged/
	// rate-limited rule, a one-way or concrete-protocol host, a source+destination
	// pair, a source-and-destination port match, an address-less source-port match,
	// an address-less multi-port accept, a non-native connection limit, a non-native
	// ICMPv4 rule, or a bare protocol match) is injected as a raw iptables rule
	// through the csf pre-hook. See needsHook for each clause; everything past this
	// gate maps onto csf's own config files.
	if f.needsHook(r) {
		_, err := f.hook().edit(r, false)
		return err
	}
	// A native connection-limit rule maps onto the csf.conf CONNLIMIT list (a
	// non-native one was diverted to the hook above by needsHook).
	if r.ConnLimit != nil {
		return f.EditConf(ctx, r, false)
	}

	// A port-only accept maps to a csf.conf port list rather than csf.allow;
	// listRows has no row for it, so falling through to the csf.allow edit would
	// only rewrite that file byte-identically. Only a single port or one range
	// reaches here — needsHook diverted a multi-port list to the hook above.
	if r.Source == "" && r.Destination == "" && r.HasPorts() && r.Action == Accept {
		return f.EditConf(ctx, r, false)
	}

	// Edit csf.allow if accept is the action, otherwise edit csf.deny. A csf.deny
	// entry carries no action of its own — csf applies csf.conf's action by direction
	// (DROP inbound, DROP_OUT outbound) — so a deny whose action matches is written
	// natively, while one that differs has no native form and is injected through the
	// pre-hook instead, whose iptables rule carries the exact action. A DirAny bare-host
	// deny is expanded to its two concrete directions first, since each hook line is
	// one-way.
	if r.Action == Accept {
		err := f.EditIPList(ctx, CSFAllow, Accept, r, false)
		if err != nil {
			return err
		}
	} else {
		denyAction := f.denyAction(r.IsOutput())
		if r.Action != denyAction {
			for _, sub := range expandDirections(r) {
				if _, err := f.hook().edit(sub, false); err != nil {
					return err
				}
			}
			return nil
		}
		err := f.EditIPList(ctx, CSFDeny, denyAction, r, false)
		if err != nil {
			return err
		}
	}
	return nil
}

// AddRule adds a filter rule to the appropriate csf construct: a csf.conf port
// list, an advanced rule, a bare address list, CONNLIMIT, or the pre-hook.
func (f *CSF) AddRule(ctx context.Context, zoneName string, r *Rule) error {
	return f.addRule(ctx, zoneName, r, true)
}

// InsertRule is unsupported: CSF organizes rules in config files, not an ordered list.
func (f *CSF) InsertRule(ctx context.Context, zoneName string, position int, r *Rule) error {
	return unsupportedOrdering(f.Type())
}

// MoveRule is unsupported for the same reason as InsertRule.
func (f *CSF) MoveRule(ctx context.Context, zoneName string, r *Rule, position int) error {
	return unsupportedOrdering(f.Type())
}

// removePlainHost drops the bidirectional plain csf.allow/csf.deny line backing the
// DirAny rule e, choosing the list by the rule's action.
func (f *CSF) removePlainHost(ctx context.Context, e *Rule) error {
	if e.Action == Accept {
		return f.EditIPList(ctx, CSFAllow, Accept, e, true)
	}
	return f.EditIPList(ctx, CSFDeny, f.denyAction(false), e, true)
}

// removeBareHostOneWay removes a one-way bare-address host rule. Such a rule is
// stored either as its own hook rule or as one direction of a bidirectional plain
// csf.allow/csf.deny line (a DirAny rule). When a matching plain line exists, split
// it: drop the line and re-add the surviving opposite direction as a hook rule so
// the untargeted direction keeps its coverage.
func (f *CSF) removeBareHostOneWay(ctx context.Context, zoneName string, r *Rule) error {
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
			// A deny plain line's outbound half was enforced with csf.conf's
			// DROP_OUT action, while the DirAny row reads back with the inbound
			// action; re-express the survivor with the action csf actually applied
			// so the split does not silently change wire behavior.
			if s.Action != Accept && s.IsOutput() {
				_, s.Action = f.dropActions()
			}
			_, err := f.hook().edit(s, false)
			return err
		}
		return nil
	}
	// Not stored as a plain line; remove the one-way hook rule.
	_, err = f.hook().edit(r, true)
	return err
}

// RemoveRule removes a filter rule from whichever csf construct holds it.
func (f *CSF) RemoveRule(ctx context.Context, zoneName string, r *Rule) error {
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

	// A TCPUDP target fans out into its two concrete-transport rules, mirroring
	// addRule, so each is removed from whichever list or line it was written to. A
	// caller removing one transport targets that transport directly and leaves the
	// other in place.
	if r.Proto == TCPUDP {
		for _, sub := range expandProtocols(r) {
			if err := f.RemoveRule(ctx, zoneName, sub); err != nil {
				return err
			}
		}
		return nil
	}

	// Validate the shape before the hook sweep below: an iptables-inexpressible
	// rule (a port on ProtocolAny) exists nowhere csf can hold it, and letting it
	// fail inside the hook marshal would return the bare error without the
	// sentinel AddRule attaches to the same shape.
	if err := r.validate(); err != nil {
		return fmt.Errorf("%v: %w", err, ErrUnsupported)
	}

	// Clear any hook copy of the rule first, no matter how csf stores it. A rule csf
	// carries only in the hook (see needsHook) lives nowhere else, so this is its
	// entire removal; a natively-expressible rule may still have a stray hook copy —
	// the library's own (a deny whose action differs from csf.conf's is stored there,
	// see AddRule) or one a customer added by hand for a shape csf can also express
	// natively — that must be cleared before the native entry below. DirAny is expanded
	// so both one-way hook lines are matched; a rule with no hook copy makes this a
	// harmless no-op.
	var err error
	for _, sub := range expandDirections(r) {
		if _, e := f.hook().edit(sub, true); e != nil {
			err = e
			break
		}
	}
	// A rule csf carries only in the hook has no native entry to fall through to, so
	// return once its hook copy is cleared (or on any hook error). Returning here also
	// keeps such a rule out of the plain-line split scan below, which could wrongly
	// split an unrelated coexisting native entry.
	if ruleNeedsHook(r) || err != nil {
		return err
	}
	// A one-way bare host rule is stored either as its own hook rule (cleared above) or
	// as one direction of a bidirectional plain line; removing it may need to split the
	// plain line (see removeBareHostOneWay).
	if bareHostOneWay(r) {
		return f.removeBareHostOneWay(ctx, zoneName, r)
	}
	// Every other shape csf's native config cannot express (see needsHook) has already
	// had its hook copy cleared above and has no native entry to split, so it is done.
	// An address-less multi-port accept is the exception: it lives in the hook now,
	// but an earlier per-port add (or a manual edit) may also hold its ports as
	// csf.conf tokens, so it falls through to the port-list sweep below.
	if f.needsHook(r) && !f.multiPortConfAccept(r) {
		return nil
	}

	// A native connection-limit rule maps onto the csf.conf CONNLIMIT list.
	if r.ConnLimit != nil {
		return f.EditConf(ctx, r, true)
	}

	// A port-only accept maps to a csf.conf port list rather than csf.allow.
	if r.Source == "" && r.Destination == "" && r.HasPorts() && r.Action == Accept {
		err := f.EditConf(ctx, r, true)
		if err != nil {
			return err
		}
	}

	// Edit csf.allow if accept is the action, otherwise edit csf.deny. A csf.deny entry
	// carries no action of its own — csf applies csf.conf's action by direction — so the
	// deny of an address is a single entry there, and it is removed whatever action the
	// caller named: asking to stop denying something means the entry goes, or RemoveRule
	// would report success while csf kept enforcing it. EditIPList coerces the target's
	// action to the file's, so a differing-action deny still matches the line. The hook
	// copy such a deny was added as (see AddRule) was already cleared above, exactly as
	// the hook copy of a matching-action deny is, so both backings are swept either way.
	if r.Action == Accept {
		err := f.EditIPList(ctx, CSFAllow, Accept, r, true)
		if err != nil {
			return err
		}
	} else {
		err := f.EditIPList(ctx, CSFDeny, f.denyAction(r.IsOutput()), r, true)
		if err != nil {
			return err
		}
	}
	return nil
}

// UnmarshalNATRule decodes a csf.redirect line into a NATRule.
func (f *CSF) UnmarshalNATRule(line string) *NATRule {
	fields := strings.Split(line, "|")
	if len(fields) != 5 {
		return nil
	}
	ipx, porta, ipy, portb, proto := fields[0], fields[1], fields[2], fields[3], fields[4]

	parsePort := func(s string) (uint16, bool) {
		if s == "*" || s == "" {
			return 0, true
		}
		n, err := strconv.ParseUint(strings.TrimSpace(s), 10, 16)
		if err != nil {
			return 0, false
		}
		return uint16(n), true
	}

	r := &NATRule{Proto: GetProtocol(proto)}
	if r.Proto != TCP && r.Proto != UDP {
		return nil
	}
	if ipx != "*" && ipx != "" {
		if _, ok := parseAddrFamily(ipx); !ok {
			return nil
		}
		r.Destination = ipx
	}
	pa, ok := parsePort(porta)
	if !ok {
		return nil
	}
	r.Port = pa
	pb, ok := parsePort(portb)
	if !ok {
		return nil
	}
	r.ToPort = pb

	if ipy == "*" || ipy == "" {
		r.Kind = Redirect
		if r.ToPort == 0 || r.Port == 0 {
			return nil
		}
	} else {
		fam, ok := parseAddrFamily(ipy)
		if !ok {
			return nil
		}
		r.Kind = DNAT
		r.ToAddress = ipy
		r.Family = fam
	}
	if r.Family == FamilyAny {
		r.Family = r.impliedFamily()
	}
	return r
}

// natNeedsHook reports whether a NAT rule has no csf.redirect form and must be
// injected as a raw nat-table command through the pre-hook instead. csf.redirect
// encodes destination NAT only, in exactly two DNAT shapes plus the local
// redirect, always tcp/udp on a single concrete port, with no source or
// interface match (see MarshalNATRule). iptables expresses all of the excess —
// source NAT, an interface binding, a port range — directly, so those shapes are
// hooked rather than rejected.
func (f *CSF) natNeedsHook(r *NATRule) bool {
	if r.Kind.isSource() {
		return true
	}
	if r.Proto != TCP && r.Proto != UDP {
		return true
	}
	if r.HasPortSet() {
		return true
	}
	if r.Source != "" || r.Interface != "" {
		return true
	}
	// A csf.redirect line carries family only through its addresses, so a family
	// pinned by the Family field alone (an address-less redirect) has no native
	// form: it would read back family-agnostic and never reconcile.
	if r.Family != FamilyAny && familyOfAddr(r.Destination) == FamilyAny && familyOfAddr(r.ToAddress) == FamilyAny {
		return true
	}
	switch r.Kind {
	case Redirect:
		return r.Port == 0
	case DNAT:
		// csf.pl accepts a DNAT only as a full-IP forward (both ports "*") or a
		// port forward (both ports concrete); any other pairing aborts the load.
		return r.Destination == "" || (r.Port == 0) != (r.ToPort == 0)
	}
	return true
}

// GetNATRules reads the NAT rules from csf.redirect and the raw nat-table
// commands the pre-hook carries.
func (f *CSF) GetNATRules(ctx context.Context, zoneName string) ([]*NATRule, error) {
	var rules []*NATRule
	fd, err := os.Open(CSFRedirect)
	switch {
	case err == nil:
		defer func() { _ = fd.Close() }()
		scanner := bufio.NewScanner(fd)
		for scanner.Scan() {
			line := scanner.Text()
			if ci := strings.IndexByte(line, '#'); ci >= 0 {
				line = line[:ci]
			}
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			if r := f.UnmarshalNATRule(line); r != nil {
				rules = append(rules, r)
			}
		}
		if err := scanner.Err(); err != nil {
			return nil, err
		}
	case os.IsNotExist(err):
		// csf.redirect is optional; a missing file simply has no native rules.
	default:
		return nil, err
	}
	// csf.redirect is CSF's own NAT config with no per-rule prefix marker, so no
	// rule in it carries the configured prefix; HasPrefix stays false (mirroring
	// firewalld's zones). Hook NAT lines are raw iptables commands, so a rule this
	// library added there carries the prefix in its -m comment tag instead.
	hookNAT, err := f.hook().getNATRules()
	if err != nil {
		return nil, err
	}
	return append(rules, hookNAT...), nil
}

// redirectAddr renders an address for a csf.redirect field, using "*" for an
// empty (any) address.
func (f *CSF) redirectAddr(a string) string {
	if a == "" {
		return "*"
	}
	return a
}

// redirectPort renders a single port for a csf.redirect field, using "*" for
// an unset (0) port, which csf reads as "any/unchanged".
func (f *CSF) redirectPort(p uint16) string {
	if p == 0 {
		return "*"
	}
	return strconv.FormatUint(uint64(p), 10)
}

// MarshalNATRule encodes a NAT rule as a csf.redirect line
// ("IPx|portA|IPy|portB|proto"): a Redirect to a local port (IPy = "*") or a DNAT
// forward to another host (IPy = ToAddress). Like MarshalAdvRule it validates
// nothing and assumes a natively-expressible rule; AddNATRule/RemoveNATRule route
// every shape csf.redirect cannot hold — source NAT, a non-tcp/udp protocol, a port
// range or list, a source/interface match, an address-less family pin, and the DNAT
// pairings csf.pl aborts on — to the pre-hook first (natNeedsHook), exactly as
// addRule routes non-native filter rules before they reach MarshalAdvRule.
func (f *CSF) MarshalNATRule(r *NATRule) string {
	ipx := f.redirectAddr(r.Destination)
	porta := f.redirectPort(r.Port)
	if r.Kind == Redirect {
		// A local port redirect: IPy is "*", portB is the target local port.
		return strings.Join([]string{ipx, porta, "*", f.redirectPort(r.ToPort), r.Proto.String()}, "|")
	}
	// A DNAT forward to another host: IPy is the translation address.
	return strings.Join([]string{ipx, porta, r.ToAddress, f.redirectPort(r.ToPort), r.Proto.String()}, "|")
}

// editRedirect adds or removes a csf.redirect line, returning without change when
// an add is a duplicate or a remove finds no match.
func (f *CSF) editRedirect(r *NATRule, remove bool) error {
	line := f.MarshalNATRule(r)

	data, err := os.ReadFile(CSFRedirect)
	if err != nil {
		if os.IsNotExist(err) {
			if remove {
				return nil
			}
			data = nil
		} else {
			return err
		}
	}
	lines := strings.Split(string(data), "\n")
	// Drop the trailing empty element left by a final newline so repeated adds do
	// not accumulate blank lines.
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}

	out := make([]string, 0, len(lines)+1)
	found := false
	for _, raw := range lines {
		body := raw
		if ci := strings.IndexByte(body, '#'); ci >= 0 {
			body = body[:ci]
		}
		body = strings.TrimSpace(body)
		if body != "" {
			// Keep the match family-aware (EqualForRemoval): a family-scoped removal
			// must not drop an opposite-family twin sharing this file (mirrors the
			// filter-rule and pf/nft NAT family gates).
			if existing := f.UnmarshalNATRule(body); existing != nil && existing.EqualForRemoval(r) {
				found = true
				if remove {
					continue
				}
			}
		}
		out = append(out, raw)
	}

	if remove {
		if !found {
			return nil
		}
	} else {
		if found {
			return nil
		}
		out = append(out, line)
	}

	// Ensure the file ends with a single trailing newline.
	content := strings.Join(out, "\n")
	if !strings.HasSuffix(content, "\n") {
		content += "\n"
	}
	return writeConfigFile(CSFRedirect, []byte(content), 0600)
}

// AddNATRule adds a NAT rule to csf.redirect, or — for the shapes csf.redirect
// cannot hold (natNeedsHook) — as a raw nat-table command in the pre-hook.
func (f *CSF) AddNATRule(ctx context.Context, zoneName string, r *NATRule) error {
	if err := r.validate(); err != nil {
		return err
	}
	// A concrete-IPv6 translation cannot be kept in sync with IPV6 off: csf
	// sources the pre-hook on every (re)load but only flushes the v6 nat table
	// when IPV6 is on, so an injected ip6tables line would re-append each reload
	// and outlive its own removal, and a csf.redirect v6 entry is never applied
	// at all.
	if !f.ipv6Enabled && r.impliedFamily() == IPv6 {
		return fmt.Errorf("csf cannot manage an IPv6 nat rule with IPV6 disabled: %w", ErrUnsupportedNAT)
	}
	if f.natNeedsHook(r) {
		_, err := f.hook().editNAT(r, false)
		return err
	}
	return f.editRedirect(r, false)
}

// InsertNATRule is unsupported: CSF stores redirects in a config file it applies
// as a whole, with no explicit ordering.
func (f *CSF) InsertNATRule(ctx context.Context, zoneName string, position int, r *NATRule) error {
	return unsupportedOrdering(f.Type())
}

// MoveNATRule is unsupported for the same reason as InsertNATRule.
func (f *CSF) MoveNATRule(ctx context.Context, zoneName string, r *NATRule, position int) error {
	return unsupportedOrdering(f.Type())
}

// RemoveNATRule removes a NAT rule from csf.redirect and from the pre-hook.
// The hook is swept first whatever the rule's shape: a hook-only shape lives
// nowhere else, and a natively-expressible rule may still have a stray hook
// copy a customer added by hand, mirroring the filter-side RemoveRule.
func (f *CSF) RemoveNATRule(ctx context.Context, zoneName string, r *NATRule) error {
	if err := r.validate(); err != nil {
		return err
	}
	if _, err := f.hook().editNAT(r, true); err != nil {
		return err
	}
	if f.natNeedsHook(r) {
		return nil
	}
	return f.editRedirect(r, true)
}

// GetDefaultPolicy is unsupported: csf exposes no chain default policy.
func (f *CSF) GetDefaultPolicy(ctx context.Context, zoneName string) (*DefaultPolicy, error) {
	return nil, unsupportedPolicy(f.Type())
}

// SetDefaultPolicy is unsupported: csf exposes no chain default policy.
func (f *CSF) SetDefaultPolicy(ctx context.Context, zoneName string, policy *DefaultPolicy) error {
	return unsupportedPolicy(f.Type())
}

// GetAddressSets returns the address sets carried by the csf pre-hook.
func (f *CSF) GetAddressSets(ctx context.Context) ([]*AddressSet, error) {
	return f.hook().getAddressSets()
}

// GetAddressSet returns a single address set by name, or an error if absent.
func (f *CSF) GetAddressSet(ctx context.Context, name string) (*AddressSet, error) {
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

// AddAddressSet writes a set as ipset commands in the pre-hook; csf -r (Reload)
// sources the hook to create the set. Re-adding a set is idempotent.
func (f *CSF) AddAddressSet(ctx context.Context, set *AddressSet) error {
	if set == nil || set.Name == "" {
		return fmt.Errorf("an address set requires a name")
	}
	_, err := f.hook().editAddressSet(set, false)
	return err
}

// RemoveAddressSet drops a set's ipset commands from the pre-hook. It fails if a
// hook rule still references the set; removing an absent set is a no-op.
func (f *CSF) RemoveAddressSet(ctx context.Context, name string) error {
	_, err := f.hook().editAddressSet(&AddressSet{Name: name}, true)
	return err
}

// AddAddressSetEntry adds an entry to an existing set in the pre-hook.
func (f *CSF) AddAddressSetEntry(ctx context.Context, name, entry string) error {
	_, err := f.hook().editAddressSetEntry(name, entry, false)
	return err
}

// RemoveAddressSetEntry removes an entry from an existing set in the pre-hook.
func (f *CSF) RemoveAddressSetEntry(ctx context.Context, name, entry string) error {
	_, err := f.hook().editAddressSetEntry(name, entry, true)
	return err
}

// Backup captures the current filter and NAT rules managed by this backend.
func (f *CSF) Backup(ctx context.Context, zoneName string) (*Backup, error) {
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
func (f *CSF) Restore(ctx context.Context, zoneName string, backup *Backup) error {
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
	// when csf sources the hook. The old rules are already gone, and editAddressSet
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

// Reload restarts csf to apply config changes, retrying past csf's transient
// restart lock.
func (f *CSF) Reload(ctx context.Context) error {
	// csf serializes restarts behind a lock, so a reload issued while a previous
	// restart is still finishing fails transiently with "csf is being restarted, try
	// again in a moment" (Resource temporarily unavailable). Wait and retry rather
	// than surfacing that transient condition — the caller asked for a reload, not to
	// race csf's own in-flight restart.
	var err error
	for attempt := 0; attempt < 20; attempt++ {
		if _, err = runCommand(ctx, "csf", "-r"); err == nil {
			return nil
		}
		if !strings.Contains(err.Error(), "being restarted") && !strings.Contains(err.Error(), "temporarily unavailable") {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
	return err
}

// Close releases any resources held by the manager; csf holds none.
func (f *CSF) Close(ctx context.Context) error {
	return nil
}
