//go:build darwin || freebsd

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
	// PFDefaultAnchor is the pf anchor name used when no rule prefix is supplied.
	PFDefaultAnchor = "go_firewall"
	// PFConf is the main pf configuration file.
	PFConf = "/etc/pf.conf"
)

// PF manages firewall rules through OpenBSD's Packet Filter (pf), used on both
// macOS and FreeBSD. To avoid disturbing rules owned by the base system, this
// backend keeps every rule it creates inside a private anchor (named after the
// rule prefix). The anchor is referenced from the main pf.conf so its rules are
// evaluated, but the rules themselves are loaded and read through pfctl scoped
// to the anchor.
type PF struct {
	// anchor is the pf anchor this backend owns.
	anchor string
	// ensured records whether the anchor reference has been added to pf.conf
	// this session so we only check/patch it once. The flag is session state: if
	// something else rewrites pf.conf without our reference after we have latched
	// it, this process keeps loading rules into an anchor nothing evaluates until
	// it restarts.
	ensured bool
	// natEnsured records the same for the nat/rdr anchor references, added
	// lazily only when a NAT rule is first written, and carries the same
	// session-state caveat.
	natEnsured bool
}

// pfICMPTypeNames maps the icmp-type names pfctl prints (which differ from the
// hyphenated aliases in icmpNameToNum, e.g. `echoreq` vs `echo-request`) to their
// numeric type, so an icmp-type match round-trips whether pfctl emits a number or
// a name.
var pfICMPTypeNames = map[string]uint8{
	"echorep": 0, "unreach": 3, "squench": 4, "redir": 5, "althost": 6,
	"echoreq": 8, "routeradv": 9, "routersol": 10, "timex": 11,
	"paramprob": 12, "timereq": 13, "timerep": 14, "inforeq": 15,
	"inforep": 16, "maskreq": 17, "maskrep": 18, "trace": 30,
	"dataconv": 31, "mobredir": 32, "ipv6-where": 33, "ipv6-here": 34,
	"mobregreq": 35, "mobregrep": 36, "skip": 39, "photuris": 40,
}

// pfICMP6TypeNames maps the icmp6-type names pfctl prints to their numeric
// ICMPv6 type. Several spellings collide with the ICMPv4 names in
// pfICMPTypeNames but mean a different number (e.g. `unreach` is 3 for ICMPv4
// but 1 for ICMPv6, `echoreq` is 8 vs 128), so an icmp6-type match must be
// resolved through this table rather than the ICMPv4 one.
var pfICMP6TypeNames = map[string]uint8{
	"unreach": 1, "toobig": 2, "timex": 3, "paramprob": 4,
	"echoreq": 128, "echorep": 129,
	"groupqry": 130, "listqry": 130, "grouprep": 131, "listenrep": 131,
	"groupterm": 132, "listendone": 132,
	"routersol": 133, "routeradv": 134, "neighbrsol": 135, "neighbradv": 136,
	"redir": 137, "routrrenum": 138,
	"fqdnreq": 139, "niqry": 139, "fqdnrep": 140, "nirep": 140,
}

// sanitizePFName reduces an arbitrary prefix to a safe pf anchor name, falling
// back to the default when nothing usable remains.
func sanitizePFName(prefix string) string {
	var b strings.Builder
	for _, r := range prefix {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_', r == '-':
			b.WriteRune(r)
		case r == ' ' || r == '.':
			b.WriteRune('_')
		}
	}
	name := strings.Trim(b.String(), "_-")
	if name == "" {
		return PFDefaultAnchor
	}
	return name
}

// NewPF constructs a PF backend scoped to an anchor derived from rulePrefix,
// verifying pfctl is available and pf is enabled.
func NewPF(ctx context.Context, rulePrefix string) (*PF, error) {
	pf := &PF{anchor: sanitizePFName(rulePrefix)}

	// Confirm pfctl is available and pf is enabled; otherwise our rules would
	// never take effect and we should let another manager (or none) be chosen.
	out, err := runCommand(ctx, "pfctl", "-s", "info")
	if err != nil {
		return nil, fmt.Errorf("pfctl is not available: %s", err)
	}
	enabled := false
	for _, line := range out {
		if strings.HasPrefix(strings.TrimSpace(line), "Status: Enabled") {
			enabled = true
			break
		}
	}
	if !enabled {
		return nil, fmt.Errorf("pf is not enabled on this server")
	}

	return pf, nil
}

// Type returns the backend type string for pf.
func (f *PF) Type() string {
	return PFType
}

// Capabilities returns the set of features the pf backend can express.
func (f *PF) Capabilities() Capabilities {
	return Capabilities{
		Output:   true,
		IPv6:     true,
		PortPair: true,
		// pf keeps state on a pass rule automatically but exposes no equivalent of
		// the conntrack-state match the model carries, so a rule naming a state is
		// rejected rather than silently losing it (see validateRule).
		ConnState:      false,
		InterfaceMatch: true,
		Logging:        true,
		RateLimit:      true,
		ConnLimit:      true,
		NAT:            true,
		RuleOrdering:   true,
		// pf's block/pass policy is a property of the main ruleset (a leading
		// `block all`), not of the anchor this backend owns, so there is no default
		// policy it can report or set without rewriting rules it does not manage.
		DefaultPolicy:        false,
		RuleCounters:         true,
		AddressSets:          true,
		Comments:             true,
		Negation:             true,
		RejectAction:         true,
		FamilyWithoutAddress: true,
	}
}

// GetZone reports no zone; pf has no interface-to-zone mapping in the model we expose.
func (f *PF) GetZone(ctx context.Context, iface string) (zoneName string, err error) {
	return "", nil
}

// --- pf.conf anchor references and anchor loading -----------------------------

// readFileLines reads a file and returns its lines with trailing newlines
// stripped.
func (f *PF) readFileLines(path string) ([]string, error) {
	fd, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = fd.Close() }()

	var lines []string
	scanner := bufio.NewScanner(fd)
	// pf.conf can carry a very long single line (e.g. a large table macro); raise
	// the token cap well above the default 64 KB so such a line is not rejected.
	scanner.Buffer(make([]byte, 0, 64*1024), 64*1024*1024)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines, scanner.Err()
}

// writeFileLines atomically replaces path with the provided lines by writing to
// a uniquely-named temp file in the same directory and renaming it into place.
// The original file's mode and ownership are preserved (defaulting to 0600 for a
// new file) so a rewrite never loosens restrictive permissions.
func (f *PF) writeFileLines(path string, lines []string) error {
	af, err := newAtomicFile(path, 0600)
	if err != nil {
		return err
	}
	defer af.Abort()
	w := bufio.NewWriter(af)
	for _, line := range lines {
		_, _ = fmt.Fprintln(w, line)
	}
	if err := w.Flush(); err != nil {
		return err
	}
	return af.Commit()
}

// ensureAnchor makes sure pf.conf references our anchor so that rules loaded
// into it are evaluated. If the reference is missing it is appended and pf.conf
// is reloaded. Filter anchors are evaluated in place, so appending keeps our
// rules after the base ruleset.
func (f *PF) ensureAnchor(ctx context.Context) error {
	if f.ensured {
		return nil
	}

	data, err := f.readFileLines(PFConf)
	if err != nil {
		return err
	}

	anchorRef := fmt.Sprintf(`anchor "%s"`, f.anchor)
	for _, line := range data {
		if strings.TrimSpace(line) == anchorRef {
			f.ensured = true
			return nil
		}
	}

	// Append the anchor reference and reload the main ruleset.
	data = append(data, anchorRef)
	if err := f.writeFileLines(PFConf, data); err != nil {
		return err
	}
	if _, err := runCommand(ctx, "pfctl", "-f", PFConf); err != nil {
		return fmt.Errorf("failed to reload pf.conf after adding anchor: %s", err)
	}
	f.ensured = true
	return nil
}

// pfFilterKeywords are the tokens that begin a pf filtering-section statement.
// Translation anchors (nat/rdr) must be declared before the first of these, so
// ensureNATAnchors inserts them at that boundary. pf.conf sections are strictly
// ordered options → normalization → queueing → translation → filtering, so the
// queueing keywords (altq/queue) are deliberately NOT included: they precede the
// translation section, and treating one as the boundary would splice the nat/rdr
// anchors ahead of the queueing statements, which pfctl -f rejects.
var pfFilterKeywords = map[string]bool{
	"pass": true, "block": true, "match": true, "anchor": true,
	"antispoof": true,
}

// translationBoundary returns the index of the first filtering statement in a
// pf.conf, which is where the nat/rdr translation anchors must be inserted (see
// pfFilterKeywords for why queueing keywords are excluded). When there is no
// filtering statement the boundary is the end of the file, so anchors are appended.
func (f *PF) translationBoundary(data []string) int {
	for i, line := range data {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) > 0 && pfFilterKeywords[fields[0]] {
			return i
		}
	}
	return len(data)
}

// ensureNATAnchors makes sure pf.conf carries the nat-anchor and rdr-anchor
// references for our anchor, inserting any missing ones at the translation
// boundary (see translationBoundary), and ensures the filter anchor first via
// ensureAnchor.
func (f *PF) ensureNATAnchors(ctx context.Context) error {
	if f.natEnsured {
		return nil
	}
	if err := f.ensureAnchor(ctx); err != nil {
		return err
	}

	data, err := f.readFileLines(PFConf)
	if err != nil {
		return err
	}

	natRef := fmt.Sprintf(`nat-anchor "%s"`, f.anchor)
	rdrRef := fmt.Sprintf(`rdr-anchor "%s"`, f.anchor)
	haveNat, haveRdr := false, false
	for _, line := range data {
		trimmed := strings.TrimSpace(line)
		if trimmed == natRef {
			haveNat = true
		}
		if trimmed == rdrRef {
			haveRdr = true
		}
	}
	insertAt := f.translationBoundary(data)
	if haveNat && haveRdr {
		f.natEnsured = true
		return nil
	}

	var add []string
	if !haveRdr {
		add = append(add, rdrRef)
	}
	if !haveNat {
		add = append(add, natRef)
	}
	updated := make([]string, 0, len(data)+len(add))
	updated = append(updated, data[:insertAt]...)
	updated = append(updated, add...)
	updated = append(updated, data[insertAt:]...)

	if err := f.writeFileLines(PFConf, updated); err != nil {
		return err
	}
	if _, err := runCommand(ctx, "pfctl", "-f", PFConf); err != nil {
		return fmt.Errorf("failed to reload pf.conf after adding nat anchors: %s", err)
	}
	f.natEnsured = true
	return nil
}

// loadAnchor replaces the anchor's ruleset with the provided rules. pf requires
// nat/rdr (translation) rules to precede filter rules in the ruleset, so they
// are written first. An empty combined set flushes the anchor.
func (f *PF) loadAnchor(ctx context.Context, natLines, filterLines []string) error {
	all := make([]string, 0, len(natLines)+len(filterLines))
	all = append(all, natLines...)
	all = append(all, filterLines...)
	stdin := strings.Join(all, "\n")
	if stdin != "" {
		stdin += "\n"
	}
	_, err := runCommandStdin(ctx, stdin, "pfctl", "-a", f.anchor, "-f", "-")
	return err
}

// --- filter rule parsing -----------------------------------------------------
//
// The address, port and table token helpers here are shared with the NAT parser.

// parseAddr reads an address operand starting at index i, honoring an optional
// leading '!' negation (pf allows `! host` or `!host`). It returns the address,
// the negation prefix to prepend ("" or "!"), and the index of the last token
// consumed.
func (f *PF) parseAddr(tokens []string, i int) (val string, neg string, next int, err error) {
	if i >= len(tokens) {
		return "", "", 0, fmt.Errorf("missing address value")
	}
	tok := tokens[i]
	if tok == "!" {
		neg = "!"
		i++
		if i >= len(tokens) {
			return "", "", 0, fmt.Errorf("missing address value")
		}
		tok = tokens[i]
	} else if strings.HasPrefix(tok, "!") {
		neg = "!"
		// Strip the negation from a local copy; the caller's slice must not be
		// mutated in place.
		tok = strings.TrimPrefix(tok, "!")
	}
	return tok, neg, i, nil
}

// parseICMPType resolves a pf icmp-type token: a number, or a name known to
// the ICMP name tables. When v6 is true the token is an icmp6-type and is
// resolved through the ICMPv6 tables (standard names and pfctl's own spellings);
// otherwise the ICMPv4 tables are used. Numbers parse the same in either family.
func (f *PF) parseICMPType(tok string, v6 bool) (uint8, bool) {
	if n, ok := parseICMPTypeFamily(tok, v6); ok {
		return n, true
	}
	if v6 {
		n, ok := pfICMP6TypeNames[tok]
		return n, ok
	}
	n, ok := pfICMPTypeNames[tok]
	return n, ok
}

// lookupPort resolves a pf port token to its number. pfctl prints a well-known
// port by its /etc/services name (22 -> ssh, 80 -> http, ...), so a non-numeric
// token is looked up as a service name. pf does not record the protocol alongside
// the name, so both tcp and udp are tried.
func (f *PF) lookupPort(tok string) (uint16, error) {
	tok = strings.TrimSpace(tok)
	if n, err := strconv.ParseUint(tok, 10, 16); err == nil {
		return uint16(n), nil
	}
	for _, netw := range []string{"tcp", "udp"} {
		if p, err := net.LookupPort(netw, tok); err == nil {
			return uint16(p), nil
		}
	}
	return 0, fmt.Errorf("invalid port %q", tok)
}

// parsePortRange parses a pf port token that may be a service name, a number, or
// a "lo:hi" range with either endpoint named.
func (f *PF) parsePortRange(tok string) (PortRange, error) {
	lo, hi, isRange := strings.Cut(tok, ":")
	start, err := f.lookupPort(lo)
	if err != nil {
		return PortRange{}, err
	}
	pr := PortRange{Start: start, End: start}
	if isRange {
		end, err := f.lookupPort(hi)
		if err != nil {
			return PortRange{}, err
		}
		pr.End = end
	}
	return pr, nil
}

// parsePorts reads a pf port operand starting at index i: a single value, a
// range, or a `{ ... }` list. It returns the parsed specs and the index of the
// last token consumed.
func (f *PF) parsePorts(tokens []string, i int) (specs []PortRange, next int, err error) {
	if i >= len(tokens) {
		return nil, 0, fmt.Errorf("missing port value")
	}
	if tokens[i] == "{" {
		for i++; i < len(tokens); i++ {
			if tokens[i] == "}" {
				return specs, i, nil
			}
			m := strings.Trim(tokens[i], ",")
			if m == "" {
				continue
			}
			pr, perr := f.parsePortRange(m)
			if perr != nil {
				return nil, 0, perr
			}
			specs = append(specs, pr)
		}
		return nil, 0, fmt.Errorf("unterminated port set")
	}
	pr, perr := f.parsePortRange(tokens[i])
	if perr != nil {
		return nil, 0, perr
	}
	return []PortRange{pr}, i, nil
}

// rateUnitFromSeconds maps a pf rate window in seconds back to a RateUnit,
// falling back to PerSecond for a window that matches no named unit.
func (f *PF) rateUnitFromSeconds(s int) RateUnit {
	switch s {
	case 60:
		return PerMinute
	case 3600:
		return PerHour
	case 86400:
		return PerDay
	}
	return PerSecond
}

// parseStateOpts parses a pf state-option group `( ... )` starting at
// tokens[i] (strings.Fields has split it on spaces, so the members are
// reassembled) and records any rate/connection limits on r. It returns the
// index of the token that closed the group.
func (f *PF) parseStateOpts(tokens []string, i int, r *Rule) (int, error) {
	var b strings.Builder
	for ; i < len(tokens); i++ {
		if b.Len() > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(tokens[i])
		if strings.HasSuffix(tokens[i], ")") {
			break
		}
	}
	group := strings.TrimSpace(b.String())
	group = strings.TrimSuffix(strings.TrimPrefix(group, "("), ")")
	for _, opt := range strings.Split(group, ",") {
		fields := strings.Fields(strings.TrimSpace(opt))
		if len(fields) < 2 {
			continue
		}
		switch fields[0] {
		case "max-src-conn":
			n, err := strconv.ParseUint(fields[1], 10, 32)
			if err != nil {
				return 0, fmt.Errorf("invalid max-src-conn %q", fields[1])
			}
			r.ConnLimit = &ConnLimit{Count: uint(n), PerSource: true}
		case "max-src-conn-rate":
			cnt, secs, ok := strings.Cut(fields[1], "/")
			if !ok {
				return 0, fmt.Errorf("invalid max-src-conn-rate %q", fields[1])
			}
			n, err := strconv.ParseUint(cnt, 10, 32)
			if err != nil {
				return 0, fmt.Errorf("invalid rate %q", fields[1])
			}
			s, err := strconv.Atoi(secs)
			if err != nil {
				return 0, fmt.Errorf("invalid rate window %q", fields[1])
			}
			r.RateLimit = &RateLimit{Rate: uint(n), Unit: f.rateUnitFromSeconds(s)}
		}
	}
	return i, nil
}

// stripTable removes the angle brackets pf prints around a table reference,
// yielding the bare set name stored in Source/Destination.
func (f *PF) stripTable(v string) string {
	if strings.HasPrefix(v, "<") && strings.HasSuffix(v, ">") {
		return v[1 : len(v)-1]
	}
	return v
}

// UnmarshalRule decodes a single pf rule line as produced by `pfctl -sr`. pfctl
// normalizes rules (e.g. `port = 23`, trailing `flags S/SA keep state`), so the
// parser is tolerant of the extra tokens it emits.
func (f *PF) UnmarshalRule(line string) (*Rule, error) {
	r := new(Rule)
	tokens := strings.Fields(line)
	if len(tokens) == 0 {
		return nil, fmt.Errorf("empty rule")
	}

	i := 0

	// Action.
	switch tokens[i] {
	case "pass":
		r.Action = Accept
		i++
	case "block":
		i++
		// Optional block variant: drop / return / return-* .
		if i < len(tokens) {
			switch {
			case tokens[i] == "drop":
				r.Action = Drop
				i++
			case tokens[i] == "return" || strings.HasPrefix(tokens[i], "return-"):
				r.Action = Reject
				i++
			default:
				// A bare `block` defaults to drop in pf.
				r.Action = Drop
			}
		} else {
			r.Action = Drop
		}
	default:
		return nil, fmt.Errorf("unsupported action: %s", tokens[i])
	}

	// Direction.
	if i >= len(tokens) {
		return nil, fmt.Errorf("missing direction")
	}
	switch tokens[i] {
	case "in":
		r.Direction = DirInput
		i++
	case "out":
		r.Direction = DirOutput
		i++
	default:
		return nil, fmt.Errorf("unsupported direction: %s", tokens[i])
	}

	for ; i < len(tokens); i++ {
		switch tokens[i] {
		case "quick", "all", "flags":
			// Tokens with no bearing on our rule model. `flags S/SA` trails
			// stateful pass rules; skip the qualifier that follows flags.
			if tokens[i] == "flags" && i+1 < len(tokens) {
				i++
			}
		case "log":
			r.Log = true
			// pf may print a parenthesized option group (e.g. `log (all)`);
			// skip it.
			if i+1 < len(tokens) && strings.HasPrefix(tokens[i+1], "(") {
				i++
				for i < len(tokens) && !strings.HasSuffix(tokens[i], ")") {
					i++
				}
			}
		case "keep", "modulate", "synproxy":
			// State tracking: `keep state [(opts)]`. Consume the `state` keyword
			// and parse any parenthesized options for rate/connection limits.
			if i+1 < len(tokens) && tokens[i+1] == "state" {
				i++
			}
			if i+1 < len(tokens) && strings.HasPrefix(tokens[i+1], "(") {
				next, perr := f.parseStateOpts(tokens, i+1, r)
				if perr != nil {
					return nil, perr
				}
				i = next
			}
		case "label":
			// A user comment, carried as a pf label emitted last as
			// `label "<quoted>"`. Recover it from the original line rather than the
			// whitespace-collapsed tokens so a run of spaces inside the label is not
			// folded, slicing from the keyword's quote to end of line and reversing the
			// marshal-time strconv.Quote with strconv.Unquote (falling back to a plain
			// trim if the token is not a well-formed quoted string).
			var joined string
			if idx := strings.Index(line, `label "`); idx >= 0 {
				joined = line[idx+len("label "):]
			} else {
				joined = strings.Join(tokens[i+1:], " ")
			}
			if unq, uerr := strconv.Unquote(joined); uerr == nil {
				r.Comment = unq
			} else {
				r.Comment = trimQuotes(joined)
			}
			i = len(tokens)
		case "state":
			// A bare state keyword with no preceding `keep`; nothing to record.
		case "on":
			// Interface binding, tied to the rule direction.
			i++
			if i >= len(tokens) {
				return nil, fmt.Errorf("missing interface value")
			}
			if r.IsOutput() {
				r.OutInterface = tokens[i]
			} else {
				r.InInterface = tokens[i]
			}
		case "inet":
			r.Family = IPv4
		case "inet6":
			r.Family = IPv6
		case "proto":
			i++
			if i >= len(tokens) {
				return nil, fmt.Errorf("missing protocol value")
			}
			r.Proto = GetProtocol(tokens[i])
			if r.Proto == ProtocolAny {
				return nil, fmt.Errorf("unsupported protocol: %s", tokens[i])
			}
		case "icmp-type", "icmp6-type":
			v6 := tokens[i] == "icmp6-type"
			i++
			if i >= len(tokens) {
				return nil, fmt.Errorf("missing icmp type value")
			}
			n, ok := f.parseICMPType(tokens[i], v6)
			if !ok {
				return nil, fmt.Errorf("invalid icmp type %q", tokens[i])
			}
			r.ICMPType = Ptr(n)
		case "from":
			val, neg, next, err := f.parseAddr(tokens, i+1)
			if err != nil {
				return nil, err
			}
			i = next
			if val != "any" {
				r.Source = neg + f.stripTable(val)
			}
			// A source port may follow: `from any port 80` (pfctl normalizes it to
			// `from any port = 80`, so skip the operator as the destination case does).
			if i+1 < len(tokens) && tokens[i+1] == "port" {
				i += 2
				if i >= len(tokens) {
					return nil, fmt.Errorf("missing source port value")
				}
				if tokens[i] == "=" {
					i++
					if i >= len(tokens) {
						return nil, fmt.Errorf("missing source port value")
					}
				}
				specs, next, perr := f.parsePorts(tokens, i)
				if perr != nil {
					return nil, perr
				}
				i = next
				if len(specs) == 1 && specs[0].Start == specs[0].End {
					r.SourcePort = specs[0].Start
				} else {
					r.SourcePorts = specs
				}
			}
		case "to":
			val, neg, next, err := f.parseAddr(tokens, i+1)
			if err != nil {
				return nil, err
			}
			i = next
			if val != "any" {
				r.Destination = neg + f.stripTable(val)
			}
		case "port":
			// May be `port 23`, normalized `port = 23`, a range `port 1000:2000`
			// or a list `port { 80 443 }`. This appears after `to any` and refers
			// to the destination port.
			i++
			if i >= len(tokens) {
				return nil, fmt.Errorf("missing port value")
			}
			if tokens[i] == "=" {
				i++
				if i >= len(tokens) {
					return nil, fmt.Errorf("missing port value")
				}
			}
			specs, next, err := f.parsePorts(tokens, i)
			if err != nil {
				return nil, err
			}
			i = next
			if len(specs) == 1 && specs[0].Start == specs[0].End {
				r.Port = specs[0].Start
			} else {
				r.Ports = specs
			}
		default:
			return nil, fmt.Errorf("unsupported token: %s", tokens[i])
		}
	}

	// Infer the family from an address when pf did not print one.
	if r.Family == FamilyAny {
		addr := r.Source
		if addr == "" {
			addr = r.Destination
		}
		addr = strings.TrimPrefix(addr, "!")
		if addr != "" {
			ip, _, err := net.ParseCIDR(addr)
			if err != nil {
				ip = net.ParseIP(addr)
			}
			if ip != nil {
				if ip.To4() == nil {
					r.Family = IPv6
				} else {
					r.Family = IPv4
				}
			}
		}
	}

	if r.Action == ActionInvalid {
		return nil, fmt.Errorf("no valid action was provided")
	}
	return r, nil
}

// --- filter anchor reading ----------------------------------------------------

// parseRuleCounters extracts the Packets and Bytes counts from a pfctl -vsr
// statistics continuation line, e.g.
// "[ Evaluations: 5  Packets: 10  Bytes: 600  States: 0 ]". It returns ok=false
// for a continuation line that carries no counters, so a non-statistics line is
// ignored rather than mistaken for a zeroed counter.
func (f *PF) parseRuleCounters(line string) (packets, bytes uint64, ok bool) {
	fields := strings.Fields(strings.Trim(line, "[] "))
	var haveP, haveB bool
	for i := 0; i+1 < len(fields); i++ {
		switch fields[i] {
		case "Packets:":
			if v, err := strconv.ParseUint(fields[i+1], 10, 64); err == nil {
				packets, haveP = v, true
			}
		case "Bytes:":
			if v, err := strconv.ParseUint(fields[i+1], 10, 64); err == nil {
				bytes, haveB = v, true
			}
		}
	}
	return packets, bytes, haveP && haveB
}

// parseAnchorRules decodes the lines of a `pfctl -a <anchor> -vsr` listing into
// rules and their raw rule text. A rule spans one rule line plus one or more
// indented `[ ... ]` continuation lines; the `[ ... Packets: N  Bytes: N ... ]`
// line carries the rule's counters, which are attached to the rule it follows.
func (f *PF) parseAnchorRules(out []string) (rules []*Rule, raw []string) {
	for _, line := range out {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// A verbose listing prefixes each rule with its "@N" ruleset index (pfctl
		// prints it under -vv, and some pf versions under -v). It is not part of the
		// rule and is invalid in a rules file, so strip it before parsing and before
		// recording the raw line — loadAnchor feeds raw straight back to `pfctl -f`,
		// which would reject a stray "@N". Only strip when the token after '@' is a
		// number so a genuine rule never loses content.
		if strings.HasPrefix(line, "@") {
			if tok, rest, ok := strings.Cut(line, " "); ok {
				if _, perr := strconv.ParseUint(tok[1:], 10, 64); perr == nil {
					line = strings.TrimSpace(rest)
				}
			}
		}
		// A continuation line annotates the rule just parsed rather than starting a
		// new one; pull its Packets/Bytes into that rule when present. The verbose
		// listing prints counters under every rule, including an unmodeled one held
		// as an opaque nil row, whose counters have nowhere to go.
		if strings.HasPrefix(line, "[") {
			if len(rules) > 0 && rules[len(rules)-1] != nil {
				if p, b, ok := f.parseRuleCounters(line); ok {
					rules[len(rules)-1].Packets = p
					rules[len(rules)-1].Bytes = b
				}
			}
			continue
		}
		rule, perr := f.UnmarshalRule(line)
		if perr != nil {
			// A line we cannot model is preserved as an opaque row: a nil rule with
			// its raw text kept, so a read-modify-write rewrite of our anchor does
			// not silently drop a foreign rule loaded into it. The nil keeps rules
			// 1:1 with raw so the physical-row edits never misalign; GetRules, Backup
			// and the position math skip the nil entries.
			rules = append(rules, nil)
			raw = append(raw, line)
			continue
		}
		// Rules loaded in this backend's own anchor: membership in the library's
		// private anchor is what sets HasPrefix, so record the anchor and flag it
		// as carrying the prefix.
		rule.table = f.anchor
		rule.HasPrefix = true
		rules = append(rules, rule)
		raw = append(raw, line)
	}
	return rules, raw
}

// anchorRules returns the filter rules currently loaded in our anchor.
func (f *PF) anchorRules(ctx context.Context) (rules []*Rule, raw []string, err error) {
	// Read with -vsr so pfctl prints each rule's per-rule counters on a following
	// `[ Evaluations: N  Packets: N  Bytes: N  States: N ]` continuation line,
	// which parseAnchorRules attaches to the preceding rule (RuleCounters).
	out, err := runCommand(ctx, "pfctl", "-a", f.anchor, "-vsr")
	if err != nil {
		// Propagate a genuine pfctl failure rather than reporting an empty anchor: a
		// referenced anchor lists nothing with a zero exit when empty, so an error
		// here is a real read failure.
		return nil, nil, err
	}
	rules, raw = f.parseAnchorRules(out)
	return rules, raw, nil
}

// compactRules drops the opaque (nil) placeholder rows parseAnchorRules keeps
// for lines it cannot model, leaving only the rules the library represents. The
// read/number and backup paths use it, since those operate on the modeled rule set
// (a []*Rule cannot carry an unparseable line).
func (f *PF) compactRules(rules []*Rule) []*Rule {
	out := make([]*Rule, 0, len(rules))
	for _, r := range rules {
		if r != nil {
			out = append(out, r)
		}
	}
	return out
}

// listForeignRules returns best-effort filter rules loaded outside this backend's
// own anchor — the main ruleset and any other anchors. pf has no JSON mode and
// foreign rules may use constructs the library's Rule model cannot represent, so
// any line that fails to parse is skipped rather than erroring the read. Callers
// gain visibility of rules in other anchors alongside the library's own.
func (f *PF) listForeignRules(ctx context.Context) []*Rule {
	var rules []*Rule
	// table records where each foreign rule came from ("" for the main ruleset, the
	// anchor name otherwise); it is not ours, so HasPrefix stays false.
	parse := func(out []string, table string) {
		for _, line := range out {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			rule, perr := f.UnmarshalRule(line)
			if perr != nil || rule == nil {
				continue
			}
			rule.table = table
			rules = append(rules, rule)
		}
	}
	// The main ruleset (our anchor appears only as an `anchor "..."` placeholder
	// line here, which does not parse as a rule, so there is no overlap).
	if out, err := runCommand(ctx, "pfctl", "-sr"); err == nil {
		parse(out, "")
	}
	// Every other anchor; our own is already read precisely by anchorRules.
	if names, err := runCommand(ctx, "pfctl", "-s", "Anchors"); err == nil {
		for _, name := range names {
			name = strings.TrimSpace(name)
			if name == "" || name == f.anchor {
				continue
			}
			if out, err := runCommand(ctx, "pfctl", "-a", name, "-sr"); err == nil {
				parse(out, name)
			}
		}
	}
	return rules
}

// GetRules returns the existing filter rules from the zone.
func (f *PF) GetRules(ctx context.Context, zoneName string) (rules []*Rule, err error) {
	rules, _, err = f.anchorRules(ctx)
	if err != nil {
		return nil, err
	}
	// Drop the opaque placeholder rows kept for unmodeled anchor lines; GetRules
	// reports only the rules the library can represent.
	rules = f.compactRules(rules)
	// Report one rule per anchor row. A pf rule written without `inet`/`inet6` matches
	// both families, and UnmarshalRule reports it as FamilyAny from that single row;
	// the transport and direction axes have no both-states form in pf's grammar (this
	// backend fans TCPUDP and DirAny out on write), so those rows read back concrete.
	// Number the anchor's rules as one ordered list — pf evaluates a single filter
	// list, so its position spans directions. Foreign rules appended below live
	// outside this anchor and keep Number 0.
	numberSequential(rules)
	rules = append(rules, f.listForeignRules(ctx)...)
	return rules, nil
}

// --- filter rule encoding -----------------------------------------------------
//
// The address, port and protocol token helpers here are shared with the NAT
// marshaller.

// addrToken renders a source/destination value for a pf rule: a bare address, or
// a table reference `<name>` when the token names an address set. The caller emits
// any leading "!" negation separately.
func (f *PF) addrToken(bare string) string {
	if _, ok := canonAddr(bare); !ok {
		return "<" + bare + ">"
	}
	return bare
}

// portMember renders one port spec in pf syntax: "80" for a single port or
// "1000:2000" for a range.
func (f *PF) portMember(pr PortRange) string {
	pr = pr.normalized()
	if pr.Start == pr.End {
		return strconv.FormatUint(uint64(pr.Start), 10)
	}
	return fmt.Sprintf("%d:%d", pr.Start, pr.End)
}

// portExpr renders a destination port match: a bare value for a single spec or
// a pf list `{ 80 443 1000:2000 }` for several.
func (f *PF) portExpr(specs []PortRange) string {
	if len(specs) == 1 {
		return f.portMember(specs[0])
	}
	members := make([]string, len(specs))
	for i, pr := range specs {
		members[i] = f.portMember(pr)
	}
	return "{ " + strings.Join(members, " ") + " }"
}

// protoName returns the protocol keyword pf uses; pf spells ICMPv6 as
// `icmp6`.
func (f *PF) protoName(p Protocol) string {
	if p == ICMPv6 {
		return "icmp6"
	}
	return p.String()
}

// rateUnitSeconds converts a RateUnit to the number of seconds pf expresses a
// rate over (pf writes max-src-conn-rate as <count>/<seconds>).
func (f *PF) rateUnitSeconds(u RateUnit) int {
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

// MarshalRule encodes a rule as a pf rule line suitable for loading into our
// anchor. Rules are marked `quick` so the first match wins, matching the
// allow/deny-list semantics of the other backends. It is a pure encoder:
// callers run validateRule on the fanned-out row first.
func (f *PF) MarshalRule(r *Rule) (string, error) {
	var parts []string

	// Action.
	switch r.Action {
	case Accept:
		parts = append(parts, "pass")
	case Drop:
		parts = append(parts, "block", "drop")
	case Reject:
		parts = append(parts, "block", "return")
	}

	// Direction.
	if r.IsOutput() {
		parts = append(parts, "out")
	} else {
		parts = append(parts, "in")
	}

	// Logging, emitted right after the direction as pfctl normalizes it. Packet
	// capture requires a pflog interface; the rule syntax is valid regardless.
	if r.Log {
		parts = append(parts, "log")
	}

	// First match wins.
	parts = append(parts, "quick")

	// Interface, bound to the rule's direction.
	iface := r.InInterface
	if r.IsOutput() {
		iface = r.OutInterface
	}
	if iface != "" {
		parts = append(parts, "on", iface)
	}

	// Address family. pf requires an explicit family for an icmp-type/icmp6-type
	// match, and an ICMP protocol implies one (ICMP => inet, ICMPv6 => inet6), so
	// resolve it rather than emitting the family only when set explicitly.
	switch r.impliedFamily() {
	case IPv4:
		parts = append(parts, "inet")
	case IPv6:
		parts = append(parts, "inet6")
	}

	// Protocol.
	if r.Proto != ProtocolAny {
		parts = append(parts, "proto", f.protoName(r.Proto))
	}

	// Source and optional source port(s).
	srcSpecs := r.SourcePortSpecs()
	if r.Source != "" {
		// A non-address token names a pf table, referenced as `<name>`.
		neg, bare := splitAddrNeg(r.Source)
		if neg {
			parts = append(parts, "from", "!", f.addrToken(bare))
		} else {
			parts = append(parts, "from", f.addrToken(bare))
		}
		if len(srcSpecs) > 0 {
			parts = append(parts, "port", f.portExpr(srcSpecs))
		}
	} else if len(srcSpecs) > 0 {
		parts = append(parts, "from", "any", "port", f.portExpr(srcSpecs))
	} else {
		parts = append(parts, "from", "any")
	}

	// Destination and optional destination port(s).
	dstSpecs := r.PortSpecs()
	if r.Destination != "" {
		neg, bare := splitAddrNeg(r.Destination)
		if neg {
			parts = append(parts, "to", "!", f.addrToken(bare))
		} else {
			parts = append(parts, "to", f.addrToken(bare))
		}
		if len(dstSpecs) > 0 {
			parts = append(parts, "port", f.portExpr(dstSpecs))
		}
	} else if len(dstSpecs) > 0 {
		parts = append(parts, "to", "any", "port", f.portExpr(dstSpecs))
	} else {
		parts = append(parts, "to", "any")
	}

	// An ICMP type match. pf places it after the from/to addresses (and requires
	// the address family emitted above); it spells the ICMPv6 keyword icmp6-type.
	if r.Proto.IsICMP() && r.ICMPType != nil {
		kw := "icmp-type"
		if r.Proto == ICMPv6 {
			kw = "icmp6-type"
		}
		parts = append(parts, kw, strconv.FormatUint(uint64(*r.ICMPType), 10))
	}

	// Rate / connection limits. pf expresses these as per-source state-tracking
	// options; validateRule has confirmed the rule is a stateful accept rule with a
	// per-source connection limit and no rate-limit burst.
	if r.RateLimit != nil || r.ConnLimit != nil {
		var opts []string
		if r.ConnLimit != nil {
			opts = append(opts, fmt.Sprintf("max-src-conn %d", r.ConnLimit.Count))
		}
		if r.RateLimit != nil {
			opts = append(opts, fmt.Sprintf("max-src-conn-rate %d/%d", r.RateLimit.Rate, f.rateUnitSeconds(r.RateLimit.Unit)))
		}
		parts = append(parts, "keep", "state", "("+strings.Join(opts, ", ")+")")
	}

	// An optional user comment, carried as a pf rule label. It has no effect on
	// matching and is ignored when comparing rules.
	if r.Comment != "" {
		parts = append(parts, "label", strconv.Quote(r.Comment))
	}

	return strings.Join(parts, " "), nil
}

// --- filter rule operations ---------------------------------------------------

// validateRule reports whether pf can express the filter rule, applying the
// universal Rule.validate and then the pf-specific shape constraints, so
// MarshalRule renders a rule already known to be expressible.
func (f *PF) validateRule(r *Rule) error {
	if err := r.validate(); err != nil {
		return err
	}
	// pf filters by the interface a packet passes on (`pass in`/`pass out`) and has
	// no distinct forward chain, so a forward rule cannot be expressed in this model.
	if r.IsForward() {
		return unsupportedForward("pf")
	}
	// pf has no both-transports rule form; pfctl expands a `{ tcp udp }` list into
	// separate rows on load, so a TCPUDP rule must be fanned into a tcp row and a udp
	// row by expandProtocols before it reaches this row-level marshaller. Reaching
	// here with TCPUDP means that fan-out was skipped.
	if err := r.CheckExpandedProtocol(); err != nil {
		return err
	}
	// pfctl expands a discrete port list into one rule per port on load, so a list
	// has no single-row form; AddRule/RemoveRule fan one into a row per spec with
	// expandPorts before this row-level marshaller runs (a contiguous range is one
	// token and is allowed). A list reaching here means that fan-out was skipped.
	if len(r.SourcePortSpecs()) > 1 {
		return fmt.Errorf("pf cannot express a source-port list as a single rule: %w", ErrUnsupportedSourcePort)
	}
	if len(r.PortSpecs()) > 1 {
		return fmt.Errorf("pf cannot express a destination-port list as a single rule: %w", ErrUnsupported)
	}
	// pf keeps state on pass rules automatically; it has no equivalent of the
	// conntrack-state match the model exposes, so reject rather than drop it.
	if r.State != 0 {
		return fmt.Errorf("pf does not support connection-state matching: %w", ErrUnsupportedState)
	}
	// pf's `log` keyword carries no text prefix, so a LogPrefix cannot be represented.
	if r.LogPrefix != "" {
		return fmt.Errorf("pf does not support a log prefix: %w", ErrUnsupportedLog)
	}
	// A pf rule binds a single interface via `on`, tied to the rule direction; the
	// pairing that enforces is the shared one Rule.validate holds. Callers validate
	// the fanned-out cells, so each carries a concrete direction on arrival.

	// The rule must carry a valid verdict.
	switch r.Action {
	case Accept, Drop, Reject:
	default:
		return fmt.Errorf("no valid action was provided")
	}
	// pf expresses rate/connection limits as per-source state-tracking options,
	// valid only on stateful pass (accept) rules.
	if r.RateLimit != nil || r.ConnLimit != nil {
		if r.Action != Accept {
			return fmt.Errorf("pf rate/connection limiting is only supported on accept rules: %w", ErrUnsupported)
		}
		if r.ConnLimit != nil && !r.ConnLimit.PerSource {
			return fmt.Errorf("pf connection limiting is per-source only: %w", ErrUnsupportedConnLimit)
		}
		// pf's max-src-conn-rate has no burst term, so a requested burst cannot be
		// honored; a rule that dropped it would read back with Burst 0 and fail
		// rule-identity comparison.
		if r.RateLimit != nil && r.RateLimit.Burst != 0 {
			return fmt.Errorf("pf does not support a rate-limit burst: %w", ErrUnsupported)
		}
	}
	return nil
}

// ruleCells fans a logical rule out into the concrete anchor rows it occupies:
// the DirAny direction split times the TCPUDP transport split times the port-list
// split. pf stores each direction, transport and port spec as its own row —
// pfctl expands a `{ tcp udp }` or `port { 80 443 }` list into separate rows on
// load — so a merged rule has no single-row form. The stored rows cover the
// merged rule through Covers, so it round-trips at the set level.
func (f *PF) ruleCells(r *Rule) []*Rule {
	var cells []*Rule
	for _, dir := range expandDirections(r) {
		for _, proto := range expandProtocols(dir) {
			cells = append(cells, expandPorts(proto)...)
		}
	}
	return cells
}

// editAnchor applies one logical-rule edit to the anchor's filter ruleset. The
// rule is fanned out once into its concrete cells (ruleCells) and op rewrites the
// anchor's rows covering every cell in a single pass, so the whole edit lands in
// one `pfctl -f` load. Fanning out here rather than re-entering the public entry
// point per cell is what keeps a rule spanning directions, transports or ports
// from being left half-applied by a failure part-way through, and holds the anchor
// to one read-rewrite cycle instead of one per cell. The rows are 1:1 with raw,
// opaque (nil) rows included, so op can edit physical rows without misaligning
// them. The translation rows are read only when op reports a change, since
// loadAnchor rewrites the whole anchor and must preserve them.
func (f *PF) editAnchor(ctx context.Context, r *Rule, op func(rules []*Rule, raw []string, cells []*Rule) ([]string, bool, error)) error {
	if err := f.ensureAnchor(ctx); err != nil {
		return err
	}

	rules, filterRaw, err := f.anchorRules(ctx)
	if err != nil {
		return err
	}
	out, changed, err := op(rules, filterRaw, f.ruleCells(r))
	if err != nil {
		return err
	}
	if !changed {
		return nil
	}

	// Preserve any translation rules that share the anchor.
	_, natRaw, err := f.anchorNATRules(ctx)
	if err != nil {
		return err
	}
	return f.loadAnchor(ctx, natRaw, out)
}

// insertRows returns the anchor's filter rows with each cell's line spliced in
// ahead of the first row at reports true for, appending the cells no row selects.
// A cell an existing row already covers is left alone rather than duplicated,
// which also fills in a subset left by an earlier partial edit instead of
// re-adding the rule whole. It is the shared body of AddRule and InsertRule; each
// passes its own placement predicate over the physical row index.
func (f *PF) insertRows(rules []*Rule, raw []string, cells []*Rule, at func(idx int, cell *Rule) bool) ([]string, bool, error) {
	// Validate and encode every cell up front so a rejection or a marshalling
	// error changes nothing. The check runs per cell rather than on the caller's
	// rule because editAnchor has already fanned the merged axes out — a TCPUDP or
	// port-list rule is legitimate on the way in and only its concrete cells are
	// expressible.
	lines := make([]string, len(cells))
	for i, cell := range cells {
		if err := f.validateRule(cell); err != nil {
			return nil, false, err
		}
		line, err := f.MarshalRule(cell)
		if err != nil {
			return nil, false, err
		}
		lines[i] = line
	}

	// Note the cells the anchor already holds. Match with EqualForDedup, not the
	// exact Equal: an existing row whose family, direction, transport or port axis
	// spans the cell already covers it, and re-adding a covered cell would leave a
	// redundant row Sync then reports forever. The coverage is one-way, so an
	// opposite-family twin is never mistaken for a duplicate — adding an IPv6 rule
	// whose IPv4 twin exists must still write the IPv6 row. An opaque (nil) row
	// models nothing and so covers nothing.
	placed := make([]bool, len(cells))
	for _, e := range rules {
		if e == nil {
			continue
		}
		for i, cell := range cells {
			if !placed[i] && e.EqualForDedup(cell, true) {
				placed[i] = true
			}
		}
	}

	out := make([]string, 0, len(raw)+len(cells))
	changed := false
	for i, line := range raw {
		for j, cell := range cells {
			if !placed[j] && at(i, cell) {
				out = append(out, lines[j])
				placed[j] = true
				changed = true
			}
		}
		out = append(out, line)
	}
	// A cell no row selected lands at the end of the anchor: AddRule appends by
	// design, and an insert position past the last row appends too.
	for j := range cells {
		if !placed[j] {
			out = append(out, lines[j])
			changed = true
		}
	}
	return out, changed, nil
}

// AddRule adds a rule to the zone, appending it to the anchor's filter ruleset.
func (f *PF) AddRule(ctx context.Context, zoneName string, r *Rule) error {
	return f.editAnchor(ctx, r, func(rules []*Rule, raw []string, cells []*Rule) ([]string, bool, error) {
		// No row is a placement point, so every missing cell appends.
		return f.insertRows(rules, raw, cells, func(int, *Rule) bool { return false })
	})
}

// filterAnchors maps each logical filter rule to its physical row index in the
// anchor, skipping opaque (nil) rows so an unmodeled foreign line occupying a
// physical slot does not consume a logical position. Every modeled row is its own
// rule — GetRules reports the anchor row for row — so with no opaque rows this is
// the identity. It backs the logical-position insert/move mapping.
func (f *PF) filterAnchors(rules []*Rule) []int {
	anchors := make([]int, 0, len(rules))
	for i, r := range rules {
		if r == nil {
			continue
		}
		anchors = append(anchors, i)
	}
	return anchors
}

// logicalInsertIndex maps a 1-based logical position (a rule's Number, as GetRules
// reports it) to the 0-based physical anchor index to insert before, given the
// physical index of each logical rule (from filterAnchors/natAnchors) and the
// physical row count. A position past the last logical rule appends (returns
// physicalLen). It exists because the anchor may hold opaque (nil) rows for
// unmodeled foreign lines that occupy a physical slot without consuming a logical
// position, so a logical position counted over the reported rules lands at the
// wrong physical row unless mapped through the anchors. With no opaque rows this
// reduces to position-1, the plain physical index.
func (f *PF) logicalInsertIndex(anchors []int, physicalLen, position int) int {
	if position < 1 {
		position = 1
	}
	if position-1 >= len(anchors) {
		return physicalLen
	}
	return anchors[position-1]
}

// InsertRule inserts rule before the given 1-based position. position <= 0 is
// treated as 1; a position larger than the current rule count appends the rule.
// A merged rule occupies a row per cell, and its cells go in together at the
// requested position in the order ruleCells fans them out.
func (f *PF) InsertRule(ctx context.Context, zoneName string, position int, r *Rule) error {
	if position <= 0 {
		position = 1
	}
	return f.editAnchor(ctx, r, func(rules []*Rule, raw []string, cells []*Rule) ([]string, bool, error) {
		// position is a Number GetRules reported, which counts only the rules it can
		// model. rules is 1:1 with raw, and filterAnchors skips any opaque
		// (unmodeled) row so a foreign anchor line does not consume a logical
		// position. A position past the last rule maps past the last row, which
		// selects nothing and leaves insertRows to append.
		idx := f.logicalInsertIndex(f.filterAnchors(rules), len(raw), position)
		return f.insertRows(rules, raw, cells, func(i int, _ *Rule) bool { return i == idx })
	})
}

// reorderRows returns the anchor's filter rows with every physical row matching r
// relocated to the 1-based position, and whether any row moved. A FamilyAny or
// TCPUDP target spans rows the anchor may hold separately, so every matching row is
// relocated together. rules is 1:1 with filterRaw. The target position counts only
// modeled rules, so it is mapped to a physical index within the reduced row set.
func (f *PF) reorderRows(rules []*Rule, filterRaw []string, r *Rule, position int) ([]string, bool) {
	if position <= 0 {
		position = 1
	}
	// Split the rows into the ones being moved and the ones staying, keeping the
	// kept rules 1:1 with the kept rows for the anchor mapping. Match with
	// EqualForRemoval (as RemoveRule does), not the family-strict Equal, so a
	// FamilyAny target relocates the family-agnostic row it names; a concrete-family
	// target still moves only its own family row.
	moved := make([]string, 0, 2)
	kept := make([]string, 0, len(filterRaw))
	keptRules := make([]*Rule, 0, len(rules))
	for i, e := range rules {
		// An opaque (nil) row is never a match target, so it is always kept in place.
		if e != nil && e.EqualForRemoval(r, true) {
			moved = append(moved, filterRaw[i])
			continue
		}
		kept = append(kept, filterRaw[i])
		keptRules = append(keptRules, rules[i])
	}
	if len(moved) == 0 {
		return nil, false
	}
	newIdx := f.logicalInsertIndex(f.filterAnchors(keptRules), len(kept), position)
	out := make([]string, 0, len(filterRaw))
	out = append(out, kept[:newIdx]...)
	out = append(out, moved...)
	out = append(out, kept[newIdx:]...)
	return out, true
}

// MoveRule moves an existing rule to the given 1-based position.
func (f *PF) MoveRule(ctx context.Context, zoneName string, r *Rule, position int) error {
	// The cells go unused here, unlike the other edits: reorderRows matches with
	// EqualForRemoval, which already spans the merged axes, and pf evaluates a
	// single ordered filter list, so every row the rule occupies relocates together
	// as one block rather than cell by cell landing at the same position in turn.
	return f.editAnchor(ctx, r, func(rules []*Rule, raw []string, _ []*Rule) ([]string, bool, error) {
		out, moved := f.reorderRows(rules, raw, r, position)
		return out, moved, nil
	})
}

// removeRows returns the anchor's filter rows with every row matching one of the
// rule's cells dropped, reporting whether any matched. Match with EqualForRemoval
// rather than the family-strict Equal, so a FamilyAny cell clears every row it
// covers — an unpinned dual-family row and any family-pinned twins added one at a
// time — while a concrete-family cell still removes only its own family and never
// the twin's row. Every row a cell matches goes in the one pass, so an anchor
// holding the same rule twice comes back clean.
func (f *PF) removeRows(rules []*Rule, raw []string, cells []*Rule) ([]string, bool, error) {
	kept := make([]string, 0, len(raw))
	changed := false
	for i, e := range rules {
		// An opaque (nil) row models nothing, so it is never a match target and is
		// always preserved.
		matched := false
		var split *Rule
		if e != nil {
			for _, cell := range cells {
				if e.EqualForRemoval(cell, true) {
					matched = true
					// A concrete-family cell that matched a genuine dual-family row (an
					// anchor rule with no af, covering both) would drop both families;
					// the untargeted family is re-marshalled below.
					split = splitDualRow(e, cell)
					break
				}
			}
		}
		if !matched {
			kept = append(kept, raw[i])
			continue
		}
		changed = true
		if split == nil {
			continue
		}
		// The surviving family takes the dual row's own slot, so it keeps both its
		// coverage and its place in the anchor. It is synthesized by the split rather
		// than supplied by a caller, so it takes the check an entry point would run.
		if err := f.validateRule(split); err != nil {
			return nil, false, err
		}
		line, err := f.MarshalRule(split)
		if err != nil {
			return nil, false, err
		}
		kept = append(kept, line)
	}
	return kept, changed, nil
}

// RemoveRule removes a rule from the zone. The cells are the inverse of the add
// fan-out: EqualForRemoval matches ports exactly, so a port-list target clears the
// per-spec rows AddRule wrote for it.
func (f *PF) RemoveRule(ctx context.Context, zoneName string, r *Rule) error {
	return f.editAnchor(ctx, r, f.removeRows)
}

// --- NAT rule parsing and anchor reading --------------------------------------

// UnmarshalNATRule decodes a single pf nat/rdr rule line as produced by
// `pfctl -a <anchor> -sn`.
func (f *PF) UnmarshalNATRule(line string) (*NATRule, error) {
	tokens := strings.Fields(line)
	if len(tokens) == 0 {
		return nil, fmt.Errorf("empty rule")
	}

	r := new(NATRule)
	i := 0
	switch tokens[i] {
	case "rdr":
		r.Kind = DNAT
	case "nat":
		r.Kind = SNAT // Refined to Masquerade below if the target is dynamic.
	default:
		return nil, fmt.Errorf("unsupported nat action: %s", tokens[i])
	}
	i++

	// srcScope is true between `from` and `to`, where a `port` token is a
	// source-port match this model cannot hold; erroring keeps the line opaque
	// rather than mis-reading it as a destination-port rule.
	srcScope := false
	for ; i < len(tokens); i++ {
		switch tokens[i] {
		case "pass", "quick", "log":
			// Qualifiers with no bearing on our model.
		case "all":
			// pfctl prints `all` for `from any to any`.
		case "round-robin", "random", "source-hash", "bitmask", "static-port", "sticky-address":
			// Address-pool / port options pfctl appends to a nat rule; ignored.
		case "on":
			i++
			if i >= len(tokens) {
				return nil, fmt.Errorf("missing interface value")
			}
			r.Interface = tokens[i]
		case "inet":
			r.Family = IPv4
		case "inet6":
			r.Family = IPv6
		case "proto":
			i++
			if i >= len(tokens) {
				return nil, fmt.Errorf("missing protocol value")
			}
			r.Proto = GetProtocol(tokens[i])
			if r.Proto == ProtocolAny {
				return nil, fmt.Errorf("unsupported protocol: %s", tokens[i])
			}
		case "from":
			srcScope = true
			val, neg, next, err := f.parseAddr(tokens, i+1)
			if err != nil {
				return nil, err
			}
			i = next
			if val != "any" {
				r.Source = neg + f.stripTable(val)
			}
		case "to":
			srcScope = false
			val, neg, next, err := f.parseAddr(tokens, i+1)
			if err != nil {
				return nil, err
			}
			i = next
			if val != "any" {
				r.Destination = neg + f.stripTable(val)
			}
		case "port":
			if srcScope {
				return nil, fmt.Errorf("source port match is not modeled")
			}
			i++
			if i >= len(tokens) {
				return nil, fmt.Errorf("missing port value")
			}
			if tokens[i] == "=" {
				i++
				if i >= len(tokens) {
					return nil, fmt.Errorf("missing port value")
				}
			}
			specs, next, err := f.parsePorts(tokens, i)
			if err != nil {
				return nil, err
			}
			i = next
			if len(specs) == 1 && specs[0].Start == specs[0].End {
				r.Port = specs[0].Start
			} else {
				r.Ports = specs
			}
		case "->":
			i++
			if i >= len(tokens) {
				return nil, fmt.Errorf("missing nat target")
			}
			target := tokens[i]
			if strings.HasPrefix(target, "(") {
				// A dynamic interface address is masquerade. A port pool after it
				// (`port 1024:65535`) has no single ToPort to map onto, so the line
				// stays opaque.
				r.Kind = Masquerade
				if i+1 < len(tokens) && tokens[i+1] == "port" {
					return nil, fmt.Errorf("nat target port pool is not modeled")
				}
			} else {
				r.ToAddress = target
				// An optional `port N` gives the translation port. pfctl prints a
				// well-known target port by its /etc/services name (80 -> http), just
				// like a match port, so resolve it through lookupPort rather than a
				// number-only parse — otherwise a named target port fails to parse and
				// the whole rule is dropped from the snapshot.
				if i+2 < len(tokens) && tokens[i+1] == "port" {
					p, err := f.lookupPort(tokens[i+2])
					if err != nil {
						return nil, fmt.Errorf("invalid nat target port %q", tokens[i+2])
					}
					r.ToPort = p
					i += 2
				}
			}
		default:
			return nil, fmt.Errorf("unsupported token: %s", tokens[i])
		}
	}

	if r.Family == FamilyAny {
		r.Family = r.impliedFamily()
	}
	if r.Kind == NATInvalid {
		return nil, fmt.Errorf("no nat action was provided")
	}
	return r, nil
}

// anchorNATRules returns the nat/rdr rules currently loaded in our anchor.
func (f *PF) anchorNATRules(ctx context.Context) (rules []*NATRule, raw []string, err error) {
	out, err := runCommand(ctx, "pfctl", "-a", f.anchor, "-sn")
	if err != nil {
		// Propagate a genuine failure rather than a false-empty snapshot; see
		// anchorRules for why swallowing it risks silently dropping loaded rules.
		return nil, nil, err
	}
	for _, line := range out {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		rule, perr := f.UnmarshalNATRule(line)
		if perr != nil {
			// Preserve a line we cannot model as an opaque row; see parseAnchorRules
			// for why nil keeps rules 1:1 with raw so a rewrite does not drop it.
			rules = append(rules, nil)
			raw = append(raw, line)
			continue
		}
		// NAT rules loaded in this backend's own anchor: membership is what sets
		// HasPrefix, so record the anchor and flag it as carrying the prefix.
		rule.table = f.anchor
		rule.HasPrefix = true
		rules = append(rules, rule)
		raw = append(raw, line)
	}
	return rules, raw, nil
}

// compactNATRules is compactRules for NAT rules: it drops the opaque (nil)
// placeholder rows anchorNATRules keeps for unmodeled lines.
func (f *PF) compactNATRules(rules []*NATRule) []*NATRule {
	out := make([]*NATRule, 0, len(rules))
	for _, r := range rules {
		if r != nil {
			out = append(out, r)
		}
	}
	return out
}

// listForeignNATRules returns best-effort nat/rdr rules loaded outside this
// backend's own anchor — the main ruleset and any other anchors. Unparseable
// lines are skipped, as in listForeignRules.
func (f *PF) listForeignNATRules(ctx context.Context) []*NATRule {
	var rules []*NATRule
	// table records where each foreign NAT rule came from ("" for the main ruleset,
	// the anchor name otherwise); not ours, so HasPrefix stays false.
	parse := func(out []string, table string) {
		for _, line := range out {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			rule, perr := f.UnmarshalNATRule(line)
			if perr != nil || rule == nil {
				continue
			}
			rule.table = table
			rules = append(rules, rule)
		}
	}
	if out, err := runCommand(ctx, "pfctl", "-sn"); err == nil {
		parse(out, "")
	}
	if names, err := runCommand(ctx, "pfctl", "-s", "Anchors"); err == nil {
		for _, name := range names {
			name = strings.TrimSpace(name)
			if name == "" || name == f.anchor {
				continue
			}
			if out, err := runCommand(ctx, "pfctl", "-a", name, "-sn"); err == nil {
				parse(out, name)
			}
		}
	}
	return rules
}

// GetNATRules returns the existing NAT rules from the zone.
func (f *PF) GetNATRules(ctx context.Context, zoneName string) (rules []*NATRule, err error) {
	rules, _, err = f.anchorNATRules(ctx)
	if err != nil {
		return nil, err
	}
	// Drop the opaque placeholder rows kept for unmodeled anchor lines.
	rules = f.compactNATRules(rules)
	// Report one rule per anchor row: a nat/rdr line written without `inet`/`inet6`
	// matches both families and reads back as FamilyAny on its own. Number the
	// anchor's NAT rules as one ordered list; foreign NAT rules appended below keep
	// Number 0.
	numberNATSequential(rules)
	rules = append(rules, f.listForeignNATRules(ctx)...)
	return rules, nil
}

// --- NAT rule encoding --------------------------------------------------------

// MarshalNATRule encodes a NAT rule as a pf rdr/nat rule line for our anchor.
// It is a pure encoder: callers run validateNAT on the fanned-out row first.
func (f *PF) MarshalNATRule(r *NATRule) (string, error) {
	var parts []string
	switch r.Kind {
	case DNAT:
		parts = append(parts, "rdr")
	case SNAT, Masquerade:
		parts = append(parts, "nat")
	}

	// Interface, bound to the translation direction.
	if r.Interface != "" {
		parts = append(parts, "on", r.Interface)
	}

	switch r.impliedFamily() {
	case IPv4:
		parts = append(parts, "inet")
	case IPv6:
		parts = append(parts, "inet6")
	}

	if r.Proto != ProtocolAny {
		parts = append(parts, "proto", f.protoName(r.Proto))
	}

	if r.Source != "" {
		neg, bare := splitAddrNeg(r.Source)
		if neg {
			parts = append(parts, "from", "!", f.addrToken(bare))
		} else {
			parts = append(parts, "from", f.addrToken(bare))
		}
	} else {
		parts = append(parts, "from", "any")
	}
	if r.Destination != "" {
		neg, bare := splitAddrNeg(r.Destination)
		if neg {
			parts = append(parts, "to", "!", f.addrToken(bare))
		} else {
			parts = append(parts, "to", f.addrToken(bare))
		}
	} else {
		parts = append(parts, "to", "any")
	}

	if specs := r.PortSpecs(); len(specs) > 0 {
		parts = append(parts, "port", f.portExpr(specs))
	}

	// Translation target.
	switch r.Kind {
	case DNAT:
		parts = append(parts, "->", r.ToAddress)
		if r.ToPort != 0 {
			parts = append(parts, "port", strconv.FormatUint(uint64(r.ToPort), 10))
		}
	case SNAT:
		// validateNAT has rejected a source-port translation, which pf's nat rule
		// cannot carry (it maps to an address only).
		parts = append(parts, "->", r.ToAddress)
	case Masquerade:
		// validateNAT guarantees an interface, which pf renders as `-> (iface)`.
		parts = append(parts, "->", "("+r.Interface+")")
	}

	return strings.Join(parts, " "), nil
}

// --- NAT rule operations ------------------------------------------------------

// validateNAT reports whether pf can express the NAT rule, applying the universal
// NATRule.validate and then the pf-specific constraints, so MarshalNATRule renders
// a rule already known to be expressible.
func (f *PF) validateNAT(r *NATRule) error {
	if err := r.validate(); err != nil {
		return err
	}
	// pfctl expands a discrete match-port list into one rule per port on load, so
	// a list has no single-row form; AddNATRule/RemoveNATRule fan one into a row
	// per spec with expandNATPorts before this row-level validation runs (a
	// contiguous range is one token and is allowed). A list reaching here means
	// that fan-out was skipped.
	if len(r.PortSpecs()) > 1 {
		return fmt.Errorf("pf cannot express a NAT match-port list as a single rule: %w", ErrUnsupported)
	}
	switch r.Kind {
	case Redirect:
		// pf has no portless redirect target; a redirect is modeled as a dnat to a
		// local address.
		return fmt.Errorf("pf does not support a portless redirect; use dnat to a local address: %w", ErrUnsupportedNAT)
	case SNAT:
		// pf's nat rule maps to an address only; a source-port translation has no
		// representation here. (iptables emits it as --to-source addr:port.)
		if r.ToPort != 0 {
			return fmt.Errorf("pf does not support translating the source port in snat: %w", ErrUnsupportedNAT)
		}
	case Masquerade:
		// pf renders masquerade as `-> (iface)`, so it requires an interface.
		if r.Interface == "" {
			return fmt.Errorf("pf masquerade requires an interface")
		}
	}
	return nil
}

// editNATAnchor is editAnchor for NAT rules. The rule is fanned out once into
// the translation rows it occupies — one per match-port spec, since pfctl expands
// a `port { 80 443 }` list into separate rows on load — and op rewrites the
// anchor's rows covering every cell in a single pass, so the whole edit lands in
// one `pfctl -f` load and cannot be left half-applied. The rows are 1:1 with raw,
// opaque (nil) rows included. The filter rows are read only when op reports a
// change, since loadAnchor rewrites the whole anchor and must preserve them.
func (f *PF) editNATAnchor(ctx context.Context, r *NATRule, op func(rules []*NATRule, raw []string, cells []*NATRule) ([]string, bool, error)) error {
	if err := f.ensureNATAnchors(ctx); err != nil {
		return err
	}

	rules, natRaw, err := f.anchorNATRules(ctx)
	if err != nil {
		return err
	}
	out, changed, err := op(rules, natRaw, expandNATPorts(r))
	if err != nil {
		return err
	}
	if !changed {
		return nil
	}

	// Preserve the filter rules that share the anchor.
	_, filterRaw, err := f.anchorRules(ctx)
	if err != nil {
		return err
	}
	return f.loadAnchor(ctx, out, filterRaw)
}

// insertNATRows is insertRows for NAT rules: it returns the anchor's translation
// rows with each cell's line spliced in ahead of the first row at reports true
// for, appending the cells no row selects and leaving a cell an existing row
// already covers alone. It is the shared body of AddNATRule and InsertNATRule.
func (f *PF) insertNATRows(rules []*NATRule, raw []string, cells []*NATRule, at func(idx int, cell *NATRule) bool) ([]string, bool, error) {
	// Validate and encode every cell up front so a rejection changes nothing. The
	// check runs per cell because editNATAnchor has already split the match-port
	// list a caller may legitimately pass in.
	lines := make([]string, len(cells))
	for i, cell := range cells {
		if err := f.validateNAT(cell); err != nil {
			return nil, false, err
		}
		line, err := f.MarshalNATRule(cell)
		if err != nil {
			return nil, false, err
		}
		lines[i] = line
	}

	// Dedup only against a row that also covers this cell's family (EqualForDedup):
	// without the coverage gate, adding an IPv6 NAT rule whose otherwise-identical
	// IPv4 twin already exists (e.g. a per-interface masquerade) would be silently
	// dropped, leaving that family un-NATed.
	placed := make([]bool, len(cells))
	for _, e := range rules {
		if e == nil {
			continue
		}
		for i, cell := range cells {
			if !placed[i] && e.EqualForDedup(cell) {
				placed[i] = true
			}
		}
	}

	out := make([]string, 0, len(raw)+len(cells))
	changed := false
	for i, line := range raw {
		for j, cell := range cells {
			if !placed[j] && at(i, cell) {
				out = append(out, lines[j])
				placed[j] = true
				changed = true
			}
		}
		out = append(out, line)
	}
	// A cell no row selected lands at the end of the translation ruleset.
	for j := range cells {
		if !placed[j] {
			out = append(out, lines[j])
			changed = true
		}
	}
	return out, changed, nil
}

// AddNATRule adds a NAT rule to the zone, appending it to the anchor's
// translation ruleset.
func (f *PF) AddNATRule(ctx context.Context, zoneName string, r *NATRule) error {
	return f.editNATAnchor(ctx, r, func(rules []*NATRule, raw []string, cells []*NATRule) ([]string, bool, error) {
		// No row is a placement point, so every missing cell appends.
		return f.insertNATRows(rules, raw, cells, func(int, *NATRule) bool { return false })
	})
}

// natAnchors is filterAnchors for NAT rules: it maps each logical NAT rule to its
// physical row index, skipping opaque (nil) rows.
func (f *PF) natAnchors(rules []*NATRule) []int {
	anchors := make([]int, 0, len(rules))
	for i, r := range rules {
		if r == nil {
			continue
		}
		anchors = append(anchors, i)
	}
	return anchors
}

// InsertNATRule inserts a NAT rule at the given 1-based position within the
// anchor's NAT ruleset. position <= 0 is treated as 1; a position larger than the
// current NAT rule count appends the rule.
func (f *PF) InsertNATRule(ctx context.Context, zoneName string, position int, r *NATRule) error {
	if position <= 0 {
		position = 1
	}
	return f.editNATAnchor(ctx, r, func(rules []*NATRule, raw []string, cells []*NATRule) ([]string, bool, error) {
		// position is a Number GetNATRules reported, which counts only the rules it
		// can model. rules is 1:1 with raw, and natAnchors skips any opaque
		// (unmodeled) row so a foreign anchor line does not consume a logical
		// position. A position past the last rule selects no row, leaving
		// insertNATRows to append.
		idx := f.logicalInsertIndex(f.natAnchors(rules), len(raw), position)
		return f.insertNATRows(rules, raw, cells, func(i int, _ *NATRule) bool { return i == idx })
	})
}

// reorderNATRows is reorderRows for NAT rules: it returns the anchor's nat rows
// with every physical row matching r relocated to the 1-based position, and
// whether any row moved. A FamilyAny target spans rows the anchor may hold
// separately (an IPv4 row and an IPv6 row added one at a time), so every matching
// row is relocated together as a block. rules is 1:1 with natRaw. The target
// position counts only modeled rules, so it is mapped to a physical index within
// the reduced row set.
func (f *PF) reorderNATRows(rules []*NATRule, natRaw []string, r *NATRule, position int) ([]string, bool) {
	if position <= 0 {
		position = 1
	}
	// Split the rows into the ones being moved and the ones staying, keeping the
	// kept rules 1:1 with the kept rows for the anchor mapping. Match with
	// EqualForRemoval (as RemoveNATRule does) so a FamilyAny target relocates the
	// family-agnostic row it names; a concrete-family target still moves only its
	// own family row.
	moved := make([]string, 0, 2)
	kept := make([]string, 0, len(natRaw))
	keptRules := make([]*NATRule, 0, len(rules))
	for i, e := range rules {
		// An opaque (nil) row is never a match target, so it is always kept in place.
		if e != nil && e.EqualForRemoval(r) {
			moved = append(moved, natRaw[i])
			continue
		}
		kept = append(kept, natRaw[i])
		keptRules = append(keptRules, rules[i])
	}
	if len(moved) == 0 {
		return nil, false
	}
	newIdx := f.logicalInsertIndex(f.natAnchors(keptRules), len(kept), position)
	out := make([]string, 0, len(natRaw))
	out = append(out, kept[:newIdx]...)
	out = append(out, moved...)
	out = append(out, kept[newIdx:]...)
	return out, true
}

// MoveNATRule moves an existing NAT rule to the given 1-based position.
func (f *PF) MoveNATRule(ctx context.Context, zoneName string, r *NATRule, position int) error {
	// The cells go unused here, as in MoveRule: reorderNATRows matches with
	// EqualForRemoval, which already spans the rows a merged rule occupies, so they
	// relocate together as one block.
	return f.editNATAnchor(ctx, r, func(rules []*NATRule, raw []string, _ []*NATRule) ([]string, bool, error) {
		out, moved := f.reorderNATRows(rules, raw, r, position)
		return out, moved, nil
	})
}

// removeNATRows is removeRows for NAT rules: it returns the anchor's translation
// rows with every row matching one of the rule's cells dropped, reporting whether
// any matched. A FamilyAny cell spans rows the anchor may hold separately (an IPv4
// row and an IPv6 row added one at a time), so removing it clears all of them,
// while a concrete-family cell still removes only its own family and never the
// twin's row.
func (f *PF) removeNATRows(rules []*NATRule, raw []string, cells []*NATRule) ([]string, bool, error) {
	kept := make([]string, 0, len(raw))
	changed := false
	for i, e := range rules {
		// An opaque (nil) row models nothing, so it is never a match target and is
		// always preserved.
		matched := false
		if e != nil {
			for _, cell := range cells {
				if e.EqualForRemoval(cell) {
					matched = true
					break
				}
			}
		}
		if matched {
			changed = true
			continue
		}
		kept = append(kept, raw[i])
	}
	return kept, changed, nil
}

// RemoveNATRule removes a NAT rule from the zone. The cells are the inverse of the
// add fan-out: EqualForRemoval matches ports exactly, so a match-port list target
// clears the per-spec rows AddNATRule wrote for it.
func (f *PF) RemoveNATRule(ctx context.Context, zoneName string, r *NATRule) error {
	return f.editNATAnchor(ctx, r, f.removeNATRows)
}

// --- default policy -----------------------------------------------------------

// GetDefaultPolicy is unsupported; pf exposes no default policy in this model.
func (f *PF) GetDefaultPolicy(ctx context.Context, zoneName string) (*DefaultPolicy, error) {
	return nil, unsupportedPolicy(f.Type())
}

// SetDefaultPolicy is unsupported; pf exposes no default policy in this model.
func (f *PF) SetDefaultPolicy(ctx context.Context, zoneName string, policy *DefaultPolicy) error {
	return unsupportedPolicy(f.Type())
}

// --- address sets (pf tables) -------------------------------------------------

// isMissingTableErr reports whether a pfctl error means the table does not
// exist. pfctl prints "pfctl: Table does not exist." for a missing table across
// its -T subcommands (show/kill/delete), so every idempotent table operation keys
// on this same string rather than each guessing at the wording.
func (f *PF) isMissingTableErr(err error) bool {
	return err != nil && strings.Contains(err.Error(), "does not exist")
}

// tableFamily infers a table's family from its entries: IPv6 when every entry
// is IPv6, FamilyAny when the table mixes families (a pf table legitimately
// holds both), and IPv4 otherwise.
func (f *PF) tableFamily(entries []string) Family {
	v4, v6 := false, false
	for _, e := range entries {
		if strings.Contains(e, ":") {
			v6 = true
		} else {
			v4 = true
		}
	}
	switch {
	case v4 && v6:
		return FamilyAny
	case v6:
		return IPv6
	}
	return IPv4
}

// getAddressSet reads one pf table, returning (nil, nil) when no table of that
// name exists so the two exported readers can each report a miss their own way.
func (f *PF) getAddressSet(ctx context.Context, name string) (*AddressSet, error) {
	out, err := runCommand(ctx, "pfctl", "-t", name, "-T", "show")
	if err != nil {
		// pfctl reports an unknown table distinctly; only that is a genuine
		// "not found" (nil, nil). Any other failure (permission, pf disabled) is a
		// real error the caller must see rather than a silent miss.
		if f.isMissingTableErr(err) {
			return nil, nil
		}
		return nil, err
	}
	var entries []string
	for _, line := range out {
		e := strings.TrimSpace(line)
		if e != "" {
			entries = append(entries, e)
		}
	}
	return &AddressSet{Name: name, Family: f.tableFamily(entries), Entries: entries}, nil
}

// GetAddressSets returns the address sets (pf tables) managed by this backend.
func (f *PF) GetAddressSets(ctx context.Context) ([]*AddressSet, error) {
	out, err := runCommand(ctx, "pfctl", "-s", "Tables")
	if err != nil {
		// A failed listing must surface: reporting "no sets" would let a Backup
		// silently capture zero tables and a later Restore load rules whose
		// <table> references resolve to nothing.
		return nil, err
	}
	var result []*AddressSet
	for _, line := range out {
		name := strings.TrimSpace(line)
		if name == "" {
			continue
		}
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

// GetAddressSet returns a single address set by name, or an error if it does not exist.
func (f *PF) GetAddressSet(ctx context.Context, name string) (*AddressSet, error) {
	set, err := f.getAddressSet(ctx, name)
	if err != nil {
		return nil, err
	}
	if set == nil {
		return nil, fmt.Errorf("address set %q not found", name)
	}
	return set, nil
}

// AddAddressSet creates an address set (pf table), or empties an existing one.
func (f *PF) AddAddressSet(ctx context.Context, set *AddressSet) error {
	if set == nil || set.Name == "" {
		return fmt.Errorf("an address set requires a name")
	}
	if err := f.ensureAnchor(ctx); err != nil {
		return err
	}
	// `-T replace` reconciles an existing table to exactly the given entries
	// (where `-T add` would only union), and with none creates the table empty —
	// pf does not lazily create tables, so a later filter rule referencing
	// <name> would otherwise fail to load.
	args := []string{"-t", set.Name, "-T", "replace"}
	args = append(args, set.Entries...)
	_, err := runCommand(ctx, "pfctl", args...)
	return err
}

// RemoveAddressSet removes an address set (pf table) by name; an absent table is a no-op.
func (f *PF) RemoveAddressSet(ctx context.Context, name string) error {
	if err := f.ensureAnchor(ctx); err != nil {
		return err
	}
	_, err := runCommand(ctx, "pfctl", "-t", name, "-T", "kill")
	// Removing an absent table is a no-op success: pfctl fails with "Table does
	// not exist", which must not surface as an error (matching getAddressSet).
	if f.isMissingTableErr(err) {
		return nil
	}
	return err
}

// AddAddressSetEntry adds an entry to the named address set (pf table).
func (f *PF) AddAddressSetEntry(ctx context.Context, name, entry string) error {
	if err := f.ensureAnchor(ctx); err != nil {
		return err
	}
	_, err := runCommand(ctx, "pfctl", "-t", name, "-T", "add", entry)
	return err
}

// RemoveAddressSetEntry removes an entry from the named address set (pf table); an absent table is a no-op.
func (f *PF) RemoveAddressSetEntry(ctx context.Context, name, entry string) error {
	if err := f.ensureAnchor(ctx); err != nil {
		return err
	}
	_, err := runCommand(ctx, "pfctl", "-t", name, "-T", "delete", entry)
	// Deleting from an absent table is a no-op success (see RemoveAddressSet).
	if f.isMissingTableErr(err) {
		return nil
	}
	return err
}

// --- backup and restore -------------------------------------------------------

// Backup captures the current filter and NAT rules managed by this backend.
func (f *PF) Backup(ctx context.Context, zoneName string) (*Backup, error) {
	// Read the private anchor directly rather than GetRules: Restore refills only
	// this anchor, so the backup must not pull in rules from the main ruleset or
	// other anchors (they would be re-loaded into the wrong anchor on Restore).
	rules, _, err := f.anchorRules(ctx)
	if err != nil {
		return nil, err
	}
	natRules, _, err := f.anchorNATRules(ctx)
	if err != nil {
		return nil, err
	}
	// A Backup holds modeled rules ([]*Rule / []*NATRule), which cannot carry an
	// unparseable anchor line, so drop the opaque placeholder rows here.
	backup := &Backup{Rules: f.compactRules(rules), NATRules: f.compactNATRules(natRules)}
	// pf has no default policy to capture (DefaultPolicy is false), so this only
	// adds the pf tables a rule may reference.
	if err := captureBackupState(ctx, f, zoneName, backup); err != nil {
		return nil, err
	}
	return backup, nil
}

// marshalExpanded renders rules as anchor filter lines, fanning each into the
// rows it occupies through ruleCells. Restore uses it so a merged rule from a
// portable backup expands exactly as the add paths expand it.
func (f *PF) marshalExpanded(rules []*Rule) ([]string, error) {
	var lines []string
	for _, top := range rules {
		for _, cell := range f.ruleCells(top) {
			if err := f.validateRule(cell); err != nil {
				return nil, err
			}
			line, err := f.MarshalRule(cell)
			if err != nil {
				return nil, err
			}
			lines = append(lines, line)
		}
	}
	return lines, nil
}

// Restore replaces the managed rules with the contents of a Backup.
func (f *PF) Restore(ctx context.Context, zoneName string, backup *Backup) error {
	if backup == nil {
		return fmt.Errorf("backup cannot be nil")
	}
	// Ensure the pf.conf anchor references exist before loading. When the backup
	// carries NAT rules, the nat-anchor/rdr-anchor references must be present too
	// (ensureNATAnchors also ensures the filter anchor); without them pf loads the
	// translation rules into the anchor but never evaluates them, mirroring the
	// AddNATRule/InsertNATRule/MoveNATRule paths.
	if len(backup.NATRules) > 0 {
		if err := f.ensureNATAnchors(ctx); err != nil {
			return err
		}
	} else if err := f.ensureAnchor(ctx); err != nil {
		return err
	}

	// Recreate the pf tables a rule may reference (`<table>`) before loading the
	// anchor. pf tables are global and independent of the anchor ruleset, so this
	// creates or repopulates them (pfctl -T add) without disturbing the anchor.
	if err := restoreBackupSets(ctx, f, backup, false); err != nil {
		return err
	}

	// A portable backup may carry DirAny or TCPUDP rules captured from a backend
	// that stores them as one row; expand exactly as the add paths do.
	filterLines, err := f.marshalExpanded(backup.Rules)
	if err != nil {
		return err
	}

	// A match-port list expands exactly as the add paths fan it out: one
	// translation row per port spec.
	var natLines []string
	for _, r := range backup.NATRules {
		for _, sub := range expandNATPorts(r) {
			if err := f.validateNAT(sub); err != nil {
				return err
			}
			line, err := f.MarshalNATRule(sub)
			if err != nil {
				return err
			}
			natLines = append(natLines, line)
		}
	}

	return f.loadAnchor(ctx, natLines, filterLines)
}

// Reload is a no-op; pf applies anchor changes immediately.
func (f *PF) Reload(ctx context.Context) error {
	return nil
}

// Close releases any resources held by the backend; pf holds none.
func (f *PF) Close(ctx context.Context) error {
	return nil
}
