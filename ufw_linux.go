package firewall

import (
	"bufio"
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
)

const (
	// UFWIPv4 is ufw's IPv4 user-rules file.
	UFWIPv4 = "/etc/ufw/user.rules"
	// UFWIPv6 is ufw's IPv6 user-rules file.
	UFWIPv6 = "/etc/ufw/user6.rules"
	// UFWConf is ufw's main configuration file (ENABLED/LOGLEVEL).
	UFWConf = "/etc/ufw/ufw.conf"
	// UFWDefaults is ufw's defaults file, where the default-policy keys
	// (DEFAULT_INPUT_POLICY, ...) actually live — not ufw.conf.
	UFWDefaults = "/etc/default/ufw"
	// UFWBefore and its peers are the iptables rules files holding rules that run
	// before/after the user rules, in iptables-restore format with ufw's own
	// chains. They are the raw-iptables fallback for what ufw's tuple format
	// cannot express — ICMP, SCTP, state matches, custom log prefixes,
	// rate/connection limits, and NAT (written into before.rules' nat table via
	// natHelper).
	UFWBefore  = "/etc/ufw/before.rules"
	UFWBefore6 = "/etc/ufw/before6.rules"
	UFWAfter   = "/etc/ufw/after.rules"
	UFWAfter6  = "/etc/ufw/after6.rules"
)

// UFW manages a host firewall through the ufw command-line tool and its rules files.
type UFW struct {
	// rulePrefix, when set, is attached as a ufw comment on rules this library
	// creates so they can be told apart from pre-existing rules.
	rulePrefix string
	// iptablesRulesChanged records whether a before.rules/before6.rules file was
	// edited this session, so Reload knows to run `ufw reload`.
	iptablesRulesChanged bool
	// sets is the iptables backend ufw reaches its ipset-backed address sets
	// through. It is held for the session rather than built per call because it
	// carries the staging file the sets are written to and the queue of removals
	// Reload still owes the kernel.
	sets *IPTables
}

// NewUFW connects to ufw, verifies it is enabled, and returns a manager for it.
func NewUFW(ctx context.Context, rulePrefix string) (*UFW, error) {
	ufw := new(UFW)
	ufw.rulePrefix = rulePrefix

	// Confirm ufw is enabled under whatever init system the host uses
	// (systemd, chkconfig, update-rc.d, OpenRC, Slackware rc.d, or rc.local).
	if !serviceEnabled(ctx, "ufw") {
		return nil, fmt.Errorf("the ufw service is not enabled on this server")
	}

	// Try and read the ufw config file.
	fd, err := os.Open(UFWConf)
	if err != nil {
		return nil, fmt.Errorf("ufw config is not readable: %w", err)
	}

	// Scan file for the enabled state.
	scanner := bufio.NewScanner(fd)
	enabled := false
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

		// Check if enabled.
		if key == "ENABLED" && strings.EqualFold(val, "yes") {
			enabled = true
		}
	}

	// Close file.
	_ = fd.Close()

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	// If disabled, return error.
	if !enabled {
		return nil, fmt.Errorf("ufw is currently disabled")
	}

	// Confirm config files exist.
	files := []string{UFWIPv4, UFWIPv6}
	for _, f := range files {
		if _, err := os.Stat(f); err != nil {
			return nil, fmt.Errorf("the config file %s is missing", f)
		}
	}

	// Build the address-set helper, detecting the optional ipset persistence
	// mechanism independently of ufw's own rules files. A missing mechanism is not
	// fatal; it leaves sets live-only, as it does for the iptables backend.
	ufw.sets = &IPTables{rulePrefix: rulePrefix}
	ufw.sets.IPSetPath, ufw.sets.IPSetService = detectIPSetPersistence(ctx)

	// Return the new ufw object.
	return ufw, nil
}

// Type returns the backend identifier for ufw.
func (f *UFW) Type() string {
	return UFWType
}

// Capabilities reports the features this backend supports.
func (f *UFW) Capabilities() Capabilities {
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

// --- default policy ---------------------------------------------------------

// GetZone reports no zone; ufw has no zone support.
func (f *UFW) GetZone(ctx context.Context, iface string) (zoneName string, err error) {
	return "", nil
}

// ipTablesChain maps a ufw iptables chain to a rule direction, reporting
// whether it is one this backend surfaces. Internal chains (logging, not-local,
// skip-to-policy) are not represented and return ok=false. Both the IPv4 (`ufw-*`)
// and IPv6 (`ufw6-*`) chain names are accepted, since before6.rules declares its
// chains with the `ufw6-` prefix.
func (f *UFW) ipTablesChain(chain string) (dir Direction, ok bool) {
	switch chain {
	case "ufw-before-input", "ufw-after-input", "ufw-user-input",
		"ufw6-before-input", "ufw6-after-input", "ufw6-user-input":
		return DirInput, true
	case "ufw-before-output", "ufw-after-output", "ufw-user-output",
		"ufw6-before-output", "ufw6-after-output", "ufw6-user-output":
		return DirOutput, true
	case "ufw-before-forward", "ufw-after-forward", "ufw-user-forward",
		"ufw6-before-forward", "ufw6-after-forward", "ufw6-user-forward":
		return DirForward, true
	}
	return DirInput, false
}

// parseIPTablesLine parses a raw before.rules line into the rule it represents
// (one line, so a LOG line yields a rule with Log set and no action), reporting
// whether the line is an input/output/forward iptables rule this model surfaces.
// The ufw chain is rewritten to its INPUT/OUTPUT/FORWARD equivalent so the
// iptables rulespec parser can be reused, and the configured prefix is split off
// the comment so only the user-facing text surfaces.
func (f *UFW) parseIPTablesLine(line string, family Family) (*Rule, bool) {
	fields := strings.Fields(line)
	if len(fields) < 3 || (fields[0] != "-A" && fields[0] != "--append") {
		return nil, false
	}
	dir, ok := f.ipTablesChain(fields[1])
	if !ok {
		return nil, false
	}
	rule, err := unmarshalIPTablesRule("-A "+iptChainForDirection(dir)+" "+strings.Join(fields[2:], " "), family)
	if err != nil {
		return nil, false
	}
	rule.Comment, rule.HasPrefix = prefixedComment(f.rulePrefix, rule.Comment)
	return rule, true
}

// ufwGroup is one physical span of a before.rules file: an iptables rule line —
// with a LOG line and the action line directly under it counting as the one
// logged rule they encode — or any other line on its own. It is the ufw
// counterpart of the iptables backend's iptGroup, and both the read path and the
// file rewrites stream through it, so table scoping and LOG-pair coalescing are
// each defined in exactly one place.
type ufwGroup struct {
	// raw preserves the original lines verbatim, so a rewrite copies user
	// formatting through and a removal drops a logged rule's two lines together.
	raw []string
	// table is the table the group's lines sit in ("filter", "nat", ...), or ""
	// outside any table. A table header belongs to the table it opens and a
	// COMMIT to the table it closes.
	table string
	// rule is the filter rule the group encodes, nil when it encodes none: a line
	// outside *filter, one on a chain this backend does not surface, one the model
	// cannot hold, an orphan LOG line, or a line that is not a rule at all.
	rule *Rule
	// commit marks the group as its table's COMMIT line.
	commit bool
}

// scanBeforeGroups streams a before.rules file to fn as logical groups in file
// order, emitting every line exactly once so a caller can rewrite the file in a
// single pass. A rule line is parsed only inside *filter, so an input rule
// sitting in the nat table is never read as a filter rule.
//
// A LOG line pairs with the action line PHYSICALLY under it and nothing else, as
// in the iptables backend: iptables writes a logged rule as two lines, and a
// pair separated by any other line is not one rule. Pairing across such a line
// would report a logged rule no removal could ever locate. An orphan LOG line
// begins no logical rule; its group still streams through with rule left nil.
//
// A nil fd scans as an empty file. An error from fn stops the scan.
func (f *UFW) scanBeforeGroups(fd *os.File, family Family, fn func(g ufwGroup) error) error {
	if fd == nil {
		return nil
	}
	table := ""
	// held buffers a parsed LOG line until the following line decides whether it
	// is that line's action partner; emitHeld flushes it as the orphan it turned
	// out to be, with its rule cleared.
	var held *ufwGroup
	emitHeld := func() error {
		if held == nil {
			return nil
		}
		g := *held
		held = nil
		g.rule = nil
		return fn(g)
	}

	scanner := bufio.NewScanner(fd)
	for scanner.Scan() {
		raw := scanner.Text()
		line := strings.TrimSpace(raw)

		// A table header opens its table and a COMMIT closes it. Both end any
		// pending LOG pairing, since a partner must sit on the very next line.
		if strings.HasPrefix(line, "*") || line == "COMMIT" {
			if err := emitHeld(); err != nil {
				return err
			}
			g := ufwGroup{raw: []string{raw}, table: table}
			if line == "COMMIT" {
				g.commit = true
				table = ""
			} else {
				table = strings.TrimPrefix(line, "*")
				g.table = table
			}
			if err := fn(g); err != nil {
				return err
			}
			continue
		}

		g := ufwGroup{raw: []string{raw}, table: table}
		// Only the filter table models a rule; every other line passes through and
		// breaks any pending pairing.
		if rule, ok := f.parseIPTablesLine(line, family); ok && table == "filter" {
			// Fold a held LOG line together with the action line directly under it
			// into the one logged rule they encode.
			if held != nil && logPartner(held.rule, rule) {
				pair := *held
				held = nil
				pair.raw = append(pair.raw, raw)
				pair.rule = mergeLogPair(pair.rule, rule)
				if err := fn(pair); err != nil {
					return err
				}
				continue
			}
			// Not a partner, so any held LOG line is an orphan; flush it before this
			// line.
			if err := emitHeld(); err != nil {
				return err
			}
			// Buffer a bare LOG line (Log set, no terminal action) against the next
			// line; every other rule is complete on its own.
			if rule.Action == ActionInvalid && rule.Log {
				g.rule = rule
				held = &g
				continue
			}
			g.rule = rule
		}

		if err := emitHeld(); err != nil {
			return err
		}
		if err := fn(g); err != nil {
			return err
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	return emitHeld()
}

// ParseIPTablesRules parses a ufw before/after rules file, which is in
// iptables-restore format using ufw's own chains. Each `-A <chain> ...` line in
// the filter table on an input/output/forward chain is reparsed with the
// iptables rulespec parser, a logged rule's LOG and action lines folding back
// into one rule; lines whose match or action this model cannot represent are
// skipped by the scan.
func (f *UFW) ParseIPTablesRules(filePath string, family Family) (rules []*Rule, err error) {
	fd, err := os.Open(filePath)
	if err != nil {
		// A missing iptables rules file simply contributes no rules.
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer func() { _ = fd.Close() }()

	err = f.scanBeforeGroups(fd, family, func(g ufwGroup) error {
		if g.rule != nil {
			rules = append(rules, g.rule)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return rules, nil
}

// parseAddr validates a ufw tuple address token (an IP or CIDR) and returns
// it, blanking a zero-network ("0.0.0.0/0" or "::/0") to the empty "any"
// address.
func (f *UFW) parseAddr(tok string) (string, error) {
	_, network, err := net.ParseCIDR(tok)
	ip := net.ParseIP(tok)
	if err != nil && ip == nil {
		return "", fmt.Errorf("invalid address parameter %q", tok)
	}
	if network != nil {
		if ones, _ := network.Mask.Size(); ones == 0 {
			return "", nil
		}
	}
	return tok, nil
}

// UnmarshalRule decodes a ufw tuple into a firewall rule. A ufw tuple carries six core fields
// (action, proto, dport, dst, sport, src), an optional pair of application-name
// fields (dapp, sapp), and a trailing direction/interface field, so a tuple ufw
// itself writes has 7 tokens, or 9 for the application-profile form; a bare
// 6-token tuple (direction/interface omitted, defaulting to inbound) is also
// accepted here for tolerance, though ufw does not generate one. An
// application-profile rule's six core fields already carry the concrete
// proto/port the profile expands to (e.g. `allow tcp 80 ... Apache - in`) — dapp
// and sapp are just the profile's name, informational labels this library has no
// field for, so they are parsed to locate the trailing direction field and then
// discarded; the rule decodes exactly like an ordinary 7-token tuple otherwise.
// An 8-token tuple is ufw's old storage format (six core fields plus dapp/sapp
// with no direction field), which this library does not model; it is rejected so
// the row stays opaque and is preserved verbatim.
func (f *UFW) UnmarshalRule(tuple string, family Family) (r *Rule, err error) {
	r = &Rule{
		Family: family,
	}
	tokens := strings.Split(tuple, " ")

	// A `route:` prefix on the action marks a forward-chain (routed) rule. Strip it
	// and flag the direction; a route rule's interfaces are read from the trailing
	// field(s) below rather than fixing a single in/out direction.
	forward := false
	if strings.HasPrefix(tokens[0], "route:") {
		forward = true
		tokens[0] = strings.TrimPrefix(tokens[0], "route:")
		r.Direction = DirForward
	}

	n := len(tokens)
	// A dual-interface route rule stays at seven tokens — ufw joins both
	// interfaces into one trailing "!"-separated token (`in_eth0!out_eth1`) — so
	// eight tokens only occurs in ufw's unmodeled old format.
	if n < 6 || n > 9 || n == 8 {
		return nil, fmt.Errorf("invalid rule length")
	}

	// Check action. ufw encodes the action field as a base action with an optional
	// `_<logtype>` suffix (`log` or `log-all`) — e.g. `allow_log`, `limit_log`.
	// Split that off so a logged or rate-limited tuple is read rather than dropped
	// as an "unsupported action".
	action := tokens[0]
	if base, logtype, hasLog := strings.Cut(action, "_"); hasLog {
		if logtype != "log" && logtype != "log-all" {
			return nil, fmt.Errorf("unsupported action: %s", tokens[0])
		}
		action = base
		r.Log = true
	}
	switch action {
	case "allow":
		r.Action = Accept
	case "deny":
		r.Action = Drop
	case "reject":
		r.Action = Reject
	case "limit":
		// ufw's `limit` is an accept that rate-limits new connections (its
		// built-in policy blocks a source with 6 or more connections in 30
		// seconds, i.e. 6 per 30s). Represent it as an accept carrying that rate
		// so the rule is reported by GetRules and stays distinct from a plain
		// allow; the window is expressed per-minute (12/minute == 6/30s) as the
		// model has no sub-minute unit.
		r.Action = Accept
		rate := f.nativeLimit()
		r.RateLimit = &rate
	default:
		return nil, fmt.Errorf("unsupported action: %s", tokens[0])
	}

	// The trailing token after the six core fields carries the direction and any
	// interface binding: `in`, `out`, an interface-bound `in_eth0`/`out_eth0`, or
	// — on a route rule binding both interfaces — ufw's "!"-joined pair
	// `in_eth0!out_eth1`, still one token. An application-profile tuple (n==9)
	// carries the dapp/sapp labels in tokens 6-7 and the direction in token 8. A
	// 6-token tuple omits the field and defaults to inbound. For a route rule the
	// direction stays forward and the interfaces populate InInterface/
	// OutInterface; for an ordinary rule the token fixes the in/out direction and
	// its interface.
	var dirTok string
	switch n {
	case 7:
		dirTok = tokens[6]
	case 9:
		dirTok = tokens[8]
	}
	if dirTok != "" {
		parts := strings.SplitN(dirTok, "!", 2)
		if len(parts) == 2 && !forward {
			// Only a route rule carries both interfaces in one token.
			return nil, fmt.Errorf("unsupported direction: %s", dirTok)
		}
		for _, part := range parts {
			name, iface, hasIface := strings.Cut(part, "_")
			switch name {
			case "in":
				if !forward {
					r.Direction = DirInput
				}
				if hasIface {
					r.InInterface = iface
				}
			case "out":
				if !forward {
					r.Direction = DirOutput
				}
				if hasIface {
					r.OutInterface = iface
				}
			default:
				return nil, fmt.Errorf("unsupported direction: %s", dirTok)
			}
		}
	}

	// Resolve the protocol token. ufw's `any` is deferred: on a ported tuple it means
	// tcp+udp together (TCPUDP), on a portless tuple it means every IP protocol
	// (ProtocolAny), so the ports must be parsed first to tell them apart. A non-`any`
	// token must name a known protocol; GetProtocol returns ProtocolAny for an unknown
	// value, so an unknown token that is not literally `any` is rejected.
	isAny := strings.EqualFold(tokens[1], "any")
	r.Proto = GetProtocol(tokens[1])
	if r.Proto == ProtocolAny && !isAny {
		return nil, fmt.Errorf("invalid protocol parameter")
	}

	// Parse destination port(s): a single port, a colon range, or a comma list.
	if !strings.EqualFold(tokens[2], "any") {
		specs, perr := ParsePortRanges(tokens[2], ",")
		if perr != nil {
			return nil, fmt.Errorf("the port argument %s is invalid", tokens[2])
		}
		portSpecsToRule(r, specs)
	}

	// Parse destination address.
	r.Destination, err = f.parseAddr(tokens[3])
	if err != nil {
		return nil, err
	}

	// Parse source port(s).
	if !strings.EqualFold(tokens[4], "any") {
		specs, perr := ParsePortRanges(tokens[4], ",")
		if perr != nil {
			return nil, fmt.Errorf("the source port argument %s is invalid", tokens[4])
		}
		sourcePortSpecsToRule(r, specs)
	}

	// Parse source address.
	r.Source, err = f.parseAddr(tokens[5])
	if err != nil {
		return nil, err
	}

	// Resolve ufw's `any` protocol now that the ports are known: a ported `any` tuple
	// matches tcp+udp together (TCPUDP), a portless one matches every IP protocol
	// (ProtocolAny, the value GetProtocol already assigned). TCPUDP carries ports,
	// ProtocolAny does not, so this keeps the two ufw meanings of `any` distinct.
	if isAny && (r.HasPorts() || r.HasSourcePorts()) {
		r.Proto = TCPUDP
	}
	return
}

// parseTupleRows scans a ufw rules file and returns one entry per `### tuple ###`
// line, in file order: the parsed rule, or nil for a non-empty tuple this backend
// does not model (one that fails to parse). ufw counts every tuple in its own
// numbered list, so keeping such rows as nil lets callers map a representable rule
// to its true physical position. Only a tuple whose body is empty after stripping
// the comment is dropped without occupying a slot.
func (f *UFW) parseTupleRows(filePath string, family Family) ([]*Rule, error) {
	fd, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer func() { _ = fd.Close() }()

	var rows []*Rule
	scanner := bufio.NewScanner(fd)
	for scanner.Scan() {
		// Get the line.
		line := scanner.Text()

		// Ignore non-tuple lines.
		tuplePrefix := "### tuple ### "
		if !strings.HasPrefix(line, tuplePrefix) {
			continue
		}
		line = strings.TrimPrefix(line, tuplePrefix)

		// Remove comments.
		ci := strings.IndexByte(line, '#')
		if ci >= 0 {
			line = line[:ci]
		}
		// A trailing ` comment=<hex>` carries the ufw rule comment, hex-encoded
		// UTF-8. Capture and decode it, then strip it before parsing the tuple.
		var comment string
		if ci = strings.LastIndex(line, " comment="); ci >= 0 {
			hexVal := strings.TrimSpace(line[ci+len(" comment="):])
			if b, derr := hex.DecodeString(hexVal); derr == nil {
				comment = string(b)
			}
			line = line[:ci]
		}

		// Trim spaces.
		line = strings.TrimSpace(line)

		// Ignore zero lines.
		if len(line) == 0 {
			continue
		}

		// Parse rule. A tuple this backend cannot model (ufw's old 8-field
		// format, an application profile it cannot resolve, a malformed line) is
		// kept as a nil row so it still occupies a physical position.
		rule, err := f.UnmarshalRule(line, family)
		if err != nil {
			rows = append(rows, nil)
			continue
		}
		// Strip the prefix so only the user-facing comment surfaces, and flag
		// whether the prefix marked this as one of our rules.
		text, hasPrefix := prefixedComment(f.rulePrefix, comment)
		rule.Comment = text
		rule.HasPrefix = hasPrefix
		rows = append(rows, rule)
	}
	if serr := scanner.Err(); serr != nil {
		return nil, serr
	}
	return rows, nil
}

// ParseRules reads a ufw rules file and returns the rules it models, in file order.
func (f *UFW) ParseRules(filePath string, family Family) (rules []*Rule, err error) {
	rows, err := f.parseTupleRows(filePath, family)
	if err != nil {
		return nil, err
	}
	for _, r := range rows {
		if r != nil {
			rules = append(rules, r)
		}
	}
	return rules, nil
}

// --- live counters -----------------------------------------------------------

// nativeLimit returns the rate ufw's built-in `limit` action enforces: 6 new
// connections per 30s, expressed per minute because the model has no sub-minute
// unit. It is the signature UnmarshalRule decodes a `limit` tuple into, and the
// one liveRules restores onto a row that jumps to ufw's limit-accept chain.
func (f *UFW) nativeLimit() RateLimit {
	return RateLimit{Rate: 12, Unit: PerMinute, Burst: 6}
}

// internalJump classifies a jump target that names one of ufw's own internal
// chains, so a live row can be read back as the rule that produced it. ufw
// expands a logged rule into a jump into its logging chain followed by the
// action line, and its built-in `limit` action into a three-line sequence
// ending in a jump to the limit-accept chain. Both the IPv4 (`ufw-`) and IPv6
// (`ufw6-`) chain names are accepted. An empty string means the target is not
// one of ufw's internal chains.
func (f *UFW) internalJump(target string) string {
	rest, ok := strings.CutPrefix(target, "ufw-")
	if !ok {
		if rest, ok = strings.CutPrefix(target, "ufw6-"); !ok {
			return ""
		}
	}
	switch rest {
	case "user-logging-input", "user-logging-output", "user-logging-forward":
		return "logging"
	case "user-limit":
		return "limit"
	case "user-limit-accept":
		return "limit-accept"
	}
	return ""
}

// parseLiveRules decodes counter-annotated `iptables-save -c` output into the
// rules ufw's own chains hold. A live row is the expansion ufw writes for a rule
// rather than the rule itself, so this reverses the two expansions its rules
// files apply — the jump into the logging chain that precedes a logged rule's
// action line, and the three-line sequence its `limit` action becomes — leaving
// a row that lines up with the tuple or before.rules line that produced it.
func (f *UFW) parseLiveRules(out []string, fam Family) []*Rule {
	// A pending logging jump only carries into the row directly beneath it,
	// within the same chain.
	logged := false
	return decodeLiveRows(out, func(row liveRow) (*Rule, bool) {
		if row.newChain {
			logged = false
		}
		dir, ok := f.ipTablesChain(row.chain)
		if !ok {
			return nil, false
		}

		// Undo ufw's expansions, so what is left is the row carrying the rule.
		target := jumpTarget(row.fields)
		if target == "" {
			// A row with no jump models nothing: it is the `-m recent --set`
			// accounting row opening a `limit` rule. Skipping it here rather than
			// letting the parse reject it keeps a pending logging jump alive, since
			// a `limit_log` rule's log half sits above this row.
			return nil, false
		}
		kind := f.internalJump(target)
		switch kind {
		case "logging":
			// The log half of a logged rule; the row beneath it holds the action.
			logged = true
			return nil, false
		case "limit":
			// The over-limit path of a `limit` rule, which stands for no rule of
			// its own; the accept row below it is the one the tuple models.
			return nil, false
		case "limit-accept":
			// ufw accepts a rate-limited rule through its own chain. Restore the
			// plain accept here and the rate below, which together are what the
			// tuple carries.
			row.line = strings.Replace(row.line, "-j "+target, "-j ACCEPT", 1)
		}

		rule, ok := parseLiveRow(row, dir, fam)
		wasLogged := logged
		logged = false
		if !ok {
			return nil, false
		}
		if kind == "limit-accept" {
			rate := f.nativeLimit()
			rule.RateLimit = &rate
		}
		rule.Log = rule.Log || wasLogged
		return rule, true
	})
}

// mergeLiveCounters copies the kernel's packet/byte counters onto the rules read
// from ufw's rules files, matching by rule identity.
func (f *UFW) mergeLiveCounters(ctx context.Context, rules []*Rule, fam Family) {
	// ufw keys each family into its own files, so a rule always names one; only
	// this family's rules can match this family's ruleset.
	targets := countableRules(rules, fam)
	if len(targets) == 0 {
		return
	}
	applyLiveCounters(targets, f.parseLiveRules(liveSaveLines(ctx, fam), fam))
}

// GetRules returns the existing filter rules from the zone: ufw's own numbered
// tuples from user.rules and user6.rules, then the raw iptables rules from the
// before.rules files, which carry the matches the tuple format cannot express.
func (f *UFW) GetRules(ctx context.Context, zoneName string) (rules []*Rule, err error) {
	// Parse IPv4 user rules.
	tupleRules, err := f.ParseRules(UFWIPv4, IPv4)
	if err != nil {
		return nil, err
	}

	// Parse IPv6 user rules.
	v6Rules, err := f.ParseRules(UFWIPv6, IPv6)
	if err != nil {
		return nil, err
	}
	tupleRules = append(tupleRules, v6Rules...)

	// Number the tuple rules as one ordered list: `ufw insert` positions within a
	// single numbered list spanning both families. The raw before.rules entries read
	// below sit outside that list, so they keep Number 0.
	numberSequential(tupleRules)
	rules = append(rules, tupleRules...)

	// Parse the before.rules iptables files, which carry ICMP and other rules the
	// user-rule tuple format cannot express. Only the before.rules files are read:
	// this backend writes and removes raw rules exclusively there (see
	// iptablesFilesFor), so reading after.rules too would surface rules it cannot
	// remove — Restore then re-added them into before.rules, duplicating them.
	iptablesRules, ferr := f.ParseIPTablesRules(UFWBefore, IPv4)
	if ferr != nil {
		return nil, ferr
	}
	rules = append(rules, iptablesRules...)
	ip6tablesRules, ferr := f.ParseIPTablesRules(UFWBefore6, IPv6)
	if ferr != nil {
		return nil, ferr
	}
	rules = append(rules, ip6tablesRules...)

	// ufw's rules files carry no packet/byte counters — the kernel does — so merge
	// them from the live ruleset (RuleCounters).
	f.mergeLiveCounters(ctx, rules, IPv4)
	f.mergeLiveCounters(ctx, rules, IPv6)
	return
}

// zeroNet returns the zero-network ("any") CIDR for a family, defaulting to
// the IPv4 form when the family is unspecified.
func (f *UFW) zeroNet(fam Family) string {
	if fam == IPv6 {
		return "::/0"
	}
	return "0.0.0.0/0"
}

// anyAddr returns the address literal used to stand in for an unspecified
// endpoint when ufw's grammar forces one. A concrete family uses its
// zero-network CIDR; a family-agnostic rule uses the literal "any" so ufw
// installs both the IPv4 and IPv6 rule — a zero-network CIDR (which is
// family-specific) would silently pin the rule to a single family and break the
// round-trip back to FamilyAny.
func (f *UFW) anyAddr(fam Family) string {
	if fam == FamilyAny {
		return "any"
	}
	return f.zeroNet(fam)
}

// isNativeLimit reports whether r is expressible as ufw's built-in `limit`
// action: an accept carrying exactly ufw's fixed rate (6 connections per 30s,
// modeled as 12/minute burst 6) and no other modifier the tuple form cannot
// hold. UnmarshalRule decodes a `limit` tuple into this exact shape, so it is the
// signature that round-trips through the CLI rather than the before.rules files.
func (f *UFW) isNativeLimit(r *Rule) bool {
	// Logging is allowed: `ufw limit log ...` writes a `limit_log` tuple, which
	// UnmarshalRule decodes back into this same shape with Log set. Excluding
	// logged limits would route such a rule to the before.rules files even though
	// it lives in user.rules, leaving it unremovable there and duplicating it on
	// Restore. A custom LogPrefix still cannot be expressed in a tuple, so a limit
	// carrying one stays false here and is routed to before.rules (which can).
	return r.Action == Accept && r.ConnLimit == nil && r.State == 0 && r.LogPrefix == "" &&
		r.RateLimit != nil && *r.RateLimit == f.nativeLimit()
}

// protoNeedsRaw reports whether a protocol cannot be expressed through ufw's
// CLI/tuple format and must instead be written as a raw before.rules rule. ufw's
// supported_protocols list (src/util.py) carries tcp, udp, esp, ah and gre
// natively, so only ICMP/ICMPv6 and SCTP — which ufw does not accept — go through
// the iptables rules files.
func (f *UFW) protoNeedsRaw(p Protocol) bool {
	return p.IsICMP() || p == SCTP
}

// MarshalRule encodes a firewall rule into a ufw rulespec. It validates nothing:
// the entry points run Rule.validate and then route every shape the tuple cannot
// carry elsewhere — ICMP/SCTP, a state match, a custom log prefix, a connection
// limit, a non-native rate limit and a negated or ipset address go to the
// before.rules files (needsIPTablesRules), while a portless or multiport tcp+udp
// match fans out into concrete tcp and udp rules (tcpudpNeedsExpand).
func (f *UFW) MarshalRule(r *Rule) string {
	// Start out with the action. ufw's built-in rate limit is its own `limit` verb
	// (an accept), so a native-limit rule emits that rather than `allow`;
	// UnmarshalRule reads it back into the same rate.
	action := "allow"
	if f.isNativeLimit(r) {
		action = "limit"
	} else if r.Action == Drop {
		action = "deny"
	} else if r.Action == Reject {
		action = "reject"
	}
	parts := []string{action}

	// Direction and interface binding. A forward rule is emitted as a route rule
	// carrying an `in on <in>` and/or `out on <out>` clause (the `route` keyword and
	// the command verb are prepended by the caller in ruleArgs); ufw rejects a
	// bare direction on a route rule, so none is emitted. An ordinary rule carries
	// its single direction and, when set, its interface.
	hasIface := r.InInterface != "" || r.OutInterface != ""
	if r.IsForward() {
		if r.InInterface != "" {
			parts = append(parts, "in", "on", r.InInterface)
		}
		if r.OutInterface != "" {
			parts = append(parts, "out", "on", r.OutInterface)
		}
	} else {
		dir := "in"
		iface := r.InInterface
		if r.IsOutput() {
			dir = "out"
			iface = r.OutInterface
		}
		parts = append(parts, dir)
		if iface != "" {
			parts = append(parts, "on", iface)
		}
	}

	// Per-rule logging: ufw's `log` keyword follows the direction and any interface
	// clause (a non-interface rule has its direction stripped by ufw before the
	// keyword is read, so `allow in log ...` and `allow in on eth0 log ...` are both
	// valid). ufw uses its own log prefixes; a rule carrying a custom LogPrefix is
	// routed to before.rules and never reaches here.
	if r.Log {
		parts = append(parts, "log")
	}

	// If family is not defined, but a source or destination address is, find out the
	// family. It is held in a local rather than written back so the caller's rule is
	// never mutated. An address ufw itself will reject leaves the rule
	// family-agnostic rather than failing here; ufw's own validation is the arbiter
	// of the address.
	family := r.impliedFamily()

	// A source port needs a `from ... port` clause, and a destination port that
	// follows a from clause cannot use the bare short form, so synthesize
	// zero-network addresses where needed to keep the grammar well formed.
	srcAddr := r.Source
	if r.HasSourcePorts() && srcAddr == "" {
		srcAddr = f.anyAddr(family)
	}
	// Ensure the destination for family-specific rules has a zero IP address to
	// allow using the `to/from` definition.
	dstAddr := r.Destination
	if dstAddr == "" && family != FamilyAny {
		dstAddr = f.zeroNet(family)
	}
	if r.HasPorts() && dstAddr == "" && srcAddr != "" {
		dstAddr = f.anyAddr(family)
	}
	// ufw's short port form (`22/tcp`) is rejected when the rule also binds an
	// interface (`on eth0`); that combination needs the full `to <any> port ...
	// proto ...` grammar. Synthesize a destination so the full form is emitted,
	// using the literal `any` for a family-agnostic rule so ufw still covers both
	// IPv4 and IPv6.
	if r.HasPorts() && dstAddr == "" && hasIface {
		dstAddr = f.anyAddr(family)
	}
	// A portless, address-less rule has no short form to hold its protocol, so give
	// it an `any` destination and let the `proto` clause below carry the protocol.
	// This covers a portless native protocol (gre, esp, ah) and, crucially, a bare
	// tcp/udp match ("allow all TCP inbound"): without the synthesized destination
	// the proto clause never fires and ufw is handed a bare `allow in`, which it
	// rejects ("Invalid interface clause"). A true match-all rule (ProtocolAny, no
	// match at all) likewise becomes `... to any`, the only form ufw accepts for it.
	if !r.HasPorts() && !r.HasSourcePorts() && dstAddr == "" && srcAddr == "" {
		dstAddr = f.anyAddr(family)
	}

	// Add protocol only when an IP address (or a source port, which forces a
	// from clause) is present; a bare destination-port rule carries its protocol
	// in the short form below. A proto clause is emitted only for a concrete
	// protocol: ufw's tuple has no `tcpudp` keyword — it expresses tcp+udp by OMITTING
	// the protocol (its `any` protocol on a ported rule) — so TCPUDP emits no proto
	// clause, exactly as ProtocolAny does.
	if r.Proto != ProtocolAny && r.Proto != TCPUDP && (dstAddr != "" || srcAddr != "") {
		parts = append(parts, "proto", r.Proto.String())
	}

	// Add source and its port(s).
	if srcAddr != "" {
		parts = append(parts, "from", srcAddr)
		if r.HasSourcePorts() {
			parts = append(parts, "port", iptMultiportValue(r.SourcePortSpecs()))
		}
	}

	// Add destination and its port(s). ufw accepts a comma list and colon ranges,
	// the same form as iptables multiport.
	if dstAddr != "" {
		parts = append(parts, "to", dstAddr)
		if r.HasPorts() {
			parts = append(parts, "port", iptMultiportValue(r.PortSpecs()))
		}
	}

	// If destination port(s) defined and no address on either side, add them in
	// ufw's short form. The protocol rides along as `port/proto` for a concrete
	// transport, or bare `port` for ufw's `any` protocol — which on a ported rule
	// means tcp+udp, i.e. TCPUDP. A ProtocolAny port has no port-carrying transport
	// and is rejected by Rule.validate, so the bare form here is reached only by TCPUDP.
	if r.HasPorts() && dstAddr == "" && srcAddr == "" {
		val := iptMultiportValue(r.PortSpecs())
		if r.Proto == TCPUDP {
			parts = append(parts, val)
		} else {
			parts = append(parts, fmt.Sprintf("%s/%s", val, r.Proto.String()))
		}
	}

	// Return the built parts joined with spaces.
	return strings.Join(parts, " ")
}

// commentFor returns the comment text ufw should tag a rule with: the configured
// prefix carried alongside the user-supplied comment (prefix + " " + comment), so
// rules this library creates stay identifiable.
func (f *UFW) commentFor(r *Rule) string {
	return combineComment(f.rulePrefix, r.Comment)
}

// rewriteToChain rewrites an iptables `-A INPUT/OUTPUT ...` line to use ufw's
// own before-chain names. The IPv6 rules file (before6.rules) declares its chains
// with the `ufw6-` prefix, so a rule bound there must use those names or
// ip6tables-restore rejects the file on `ufw reload`.
func (f *UFW) rewriteToChain(line string, family Family) (string, error) {
	prefix := "ufw"
	if family == IPv6 {
		prefix = "ufw6"
	}
	if rest, ok := strings.CutPrefix(line, "-A INPUT "); ok {
		return "-A " + prefix + "-before-input " + rest, nil
	}
	if rest, ok := strings.CutPrefix(line, "-A OUTPUT "); ok {
		return "-A " + prefix + "-before-output " + rest, nil
	}
	if rest, ok := strings.CutPrefix(line, "-A FORWARD "); ok {
		return "-A " + prefix + "-before-forward " + rest, nil
	}
	return "", fmt.Errorf("unexpected iptables rule form: %s", line)
}

// marshalIPTablesLines encodes a rule as the before.rules line(s) for the given
// family, reusing the iptables marshaller and rewriting the chain to ufw's own
// input/output/forward chain. A logged rule yields a LOG line followed by its
// action line.
func (f *UFW) marshalIPTablesLines(r *Rule, family Family) ([]string, error) {
	ipt := &IPTables{rulePrefix: f.rulePrefix}
	// The borrowed encoder takes its own check: this rule reached here through
	// ufw's entry points, not iptables'.
	if err := ipt.validateRule(r); err != nil {
		return nil, err
	}
	lines, err := ipt.marshalRuleLines(r)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		rewritten, rerr := f.rewriteToChain(line, family)
		if rerr != nil {
			return nil, rerr
		}
		out = append(out, rewritten)
	}
	return out, nil
}

// editIPTablesRulesFile inserts (or removes) a rule's line(s) in a before.rules
// file, streaming the original through a staged rewrite so every line the edit
// does not touch — comments, user formatting, other tables — is copied through
// verbatim and the file is replaced atomically with its mode and ownership
// intact. An add splices the rule in just above the *filter section's COMMIT; a
// removal drops every line the rule covers, a logged rule's LOG and action lines
// together. It reports whether the file was changed.
func (f *UFW) editIPTablesRulesFile(path string, r *Rule, family Family, remove bool) (bool, error) {
	fd, err := os.Open(path)
	if err != nil {
		// Nothing to remove from a file that is not there.
		if os.IsNotExist(err) && remove {
			return false, nil
		}
		return false, err
	}
	defer func() { _ = fd.Close() }()

	// An add resolves its line(s) and the already-present check before anything is
	// staged: a duplicate add must leave the file untouched, and the rewrite pass
	// below cannot look past the COMMIT it splices at.
	var specs []string
	if !remove {
		present := false
		if err := f.scanBeforeGroups(fd, family, func(g ufwGroup) error {
			if g.rule != nil && g.rule.EqualBase(r, true) {
				present = true
			}
			return nil
		}); err != nil {
			return false, err
		}
		if present {
			return false, nil
		}
		if specs, err = f.marshalIPTablesLines(r, family); err != nil {
			return false, err
		}
		if _, err := fd.Seek(0, io.SeekStart); err != nil {
			return false, err
		}
	}

	af, err := newAtomicFile(path, 0640)
	if err != nil {
		return false, err
	}
	defer af.Abort()
	write := func(g ufwGroup) error {
		for _, l := range g.raw {
			_, _ = fmt.Fprintln(af, l)
		}
		return nil
	}

	changed := false
	err = f.scanBeforeGroups(fd, family, func(g ufwGroup) error {
		if remove {
			// Drop every group the target covers, not only the first, so a
			// before.rules file holding the rule twice comes back clean in one pass.
			// The target is already one concrete family/transport/direction cell —
			// RemoveRule fanned out the merged axes — and the file itself pins the
			// family. A foreign LOG line adjacent to the target is its own group and
			// so survives.
			if g.rule != nil && g.rule.EqualBase(r, true) {
				changed = true
				return nil
			}
			return write(g)
		}
		// Anchor the add on the *filter section's COMMIT, not the file's first one:
		// the canonical ufw NAT setup adds a *nat block above *filter, and a filter
		// rule spliced into that block references an undeclared chain, failing the
		// whole reload at iptables-restore.
		if !changed && g.commit && g.table == "filter" {
			for _, l := range specs {
				_, _ = fmt.Fprintln(af, l)
			}
			changed = true
		}
		return write(g)
	})
	if err != nil {
		return false, err
	}
	if !remove && !changed {
		return false, fmt.Errorf("no *filter COMMIT line found in %s", path)
	}
	if !changed {
		return false, nil
	}
	if err := af.Commit(); err != nil {
		return false, fmt.Errorf("failed to move new firewall rules into place: %s", err)
	}
	return true, nil
}

// iptablesFilesFor returns the before.rules file(s) a rule applies to. An ICMP
// protocol pins the family; a family-agnostic rule (e.g. a bare state match)
// touches both the IPv4 and IPv6 files.
func (f *UFW) iptablesFilesFor(r *Rule) []string {
	switch r.impliedFamily() {
	case IPv4:
		return []string{UFWBefore}
	case IPv6:
		return []string{UFWBefore6}
	default:
		return []string{UFWBefore, UFWBefore6}
	}
}

// editIPTablesRules applies an add/remove across every before.rules file the rule
// touches, recording whether a reload is needed.
func (f *UFW) editIPTablesRules(r *Rule, remove bool) error {
	for _, path := range f.iptablesFilesFor(r) {
		family := IPv4
		if path == UFWBefore6 {
			family = IPv6
		}
		changed, err := f.editIPTablesRulesFile(path, r, family, remove)
		if err != nil {
			return err
		}
		if changed {
			f.iptablesRulesChanged = true
		}
	}
	return nil
}

// needsIPTablesRules reports whether a rule must be written as raw iptables
// rules rather than through ufw's command line. The ufw CLI and its user.rules
// tuple format cannot express ICMP/SCTP, a connection-state match, a custom log
// prefix or a rate/connection limit, but the before.rules files can. Plain
// logging (no custom prefix) is expressed natively with ufw's `log` keyword, so
// it stays on the CLI path.
func (f *UFW) needsIPTablesRules(r *Rule) bool {
	if f.protoNeedsRaw(r.Proto) || r.State != 0 || (r.Log && r.LogPrefix != "") || r.ConnLimit != nil {
		return true
	}
	// ufw's tuple format takes only addresses in from/to; an ipset reference is
	// written as a raw before.rules rule (`-m set --match-set`) instead.
	if isSetRef(r.Source) || isSetRef(r.Destination) {
		return true
	}
	// ufw's tuple grammar has no address negation, but before.rules can express it
	// as `iptables ! -s/-d`, so a negated plain address routes there rather than
	// being rejected. (A negated ipset reference is already covered above.)
	if neg, _ := splitAddrNeg(r.Source); neg {
		return true
	}
	if neg, _ := splitAddrNeg(r.Destination); neg {
		return true
	}
	// ufw's built-in `limit` action is expressed through the CLI/user.rules, so a
	// rule carrying exactly that rate stays on the tuple path; any other rate
	// limit can only be written as raw iptables in the before.rules files.
	if r.RateLimit != nil && !f.isNativeLimit(r) {
		return true
	}
	return false
}

// ruleArgs builds the argument list for a ufw rule command: the optional
// command verb tokens (e.g. {"prepend"}, {"insert", "3"}, {"delete"}, or none for
// a plain tail append) followed by the marshaled rule spec split into tokens. A
// forward rule is a ufw route rule, so the `route` keyword precedes the verb
// (`ufw route prepend allow in on eth0 ...`).
func (f *UFW) ruleArgs(r *Rule, verb []string, spec string) []string {
	tokens := strings.Split(spec, " ")
	args := make([]string, 0, 1+len(verb)+len(tokens))
	if r.IsForward() {
		args = append(args, "route")
	}
	args = append(args, verb...)
	args = append(args, tokens...)
	return args
}

// tcpudpNeedsExpand reports whether a TCPUDP rule cannot be written as a single
// native ufw tuple and must be fanned out into concrete tcp+udp rows. ufw carries
// tcp+udp in one tuple only through its `any` protocol on a ported CLI rule: a
// portless TCPUDP would become ufw's every-protocol match, a multiport TCPUDP is
// rejected by ufw itself ("Must specify 'tcp' or 'udp' with multiple ports"), and a
// TCPUDP rule routed to the before.rules raw path (state, icmp, a non-native limit,
// a negated/ipset address) must reach the iptables marshaller as a concrete
// transport since that path has no both-transports form either. Any of those splits
// into a tcp row and a udp row before the rule is written or removed, mirroring the
// DirAny fan-out.
func (f *UFW) tcpudpNeedsExpand(r *Rule) bool {
	if r.Proto != TCPUDP {
		return false
	}
	if f.needsIPTablesRules(r) {
		return true
	}
	// Native only for a single-port `any` tuple: it must carry a port (a portless
	// `any` matches every protocol) and match single ports only.
	if !r.HasPorts() && !r.HasSourcePorts() {
		return true
	}
	return r.HasPortSet() || r.HasSourcePortSet()
}

// AddRule adds a filter rule to the zone.
func (f *UFW) AddRule(ctx context.Context, zoneName string, r *Rule) error {
	// A DirAny rule fans out into an inbound tuple plus its role-swapped outbound
	// tuple; add each concrete-direction half (either may route to before.rules).
	if r.Direction == DirAny {
		for _, sub := range expandDirections(r) {
			if err := f.AddRule(ctx, zoneName, sub); err != nil {
				return err
			}
		}
		return nil
	}

	// A TCPUDP rule ufw cannot hold in a single native `any`-proto tuple is fanned out
	// into a concrete tcp tuple and a udp tuple, the same way a DirAny rule fans out by
	// direction. A native single-port TCPUDP falls through to the CLI path below, where
	// MarshalRule emits ufw's bare/`any` short form for it.
	if f.tcpudpNeedsExpand(r) {
		for _, sub := range expandProtocols(r) {
			if err := f.AddRule(ctx, zoneName, sub); err != nil {
				return err
			}
		}
		return nil
	}

	// Verify the rule is valid for ufw before routing it: the tuple path and the
	// before.rules path marshal through different encoders, so neither sees every
	// rule.
	if err := r.validate(); err != nil {
		return err
	}

	// ICMP, connection-state, logging and rate/connection-limit rules are not
	// expressible through the ufw CLI, so they are written to the iptables-based
	// before.rules files instead, with a set-referencing rule pinned to its
	// set's family first.
	if f.needsIPTablesRules(r) {
		r, err := resolveSetRefRule(r, f.setHelper().setRefFamily)
		if err != nil {
			return err
		}
		return f.editIPTablesRules(r, false)
	}

	args := f.ruleArgs(r, []string{"prepend"}, f.MarshalRule(r))
	// Attach a comment: the prefix tag and any user-supplied Comment are combined
	// (prefix first, see combineComment) so the rule is identifiable as ours and
	// the user text still surfaces. The comment is only added on insert; ufw
	// matches deletes on the rule without it.
	if c := f.commentFor(r); c != "" {
		args = append(args, "comment", c)
	}
	_, err := runCommand(ctx, "ufw", args...)
	return err
}

// appendRule adds a rule at the end of ufw's numbered list with a plain
// `ufw <rule>` (ufw appends a non-inserted rule). It mirrors AddRule but does not
// use `ufw prepend`, so callers that need a tail append — InsertRule past the end,
// and MoveRule to the end — get end placement rather than front placement. Its
// only caller, InsertRule, already diverts raw rules to editIPTablesRules before
// reaching here, so r is always a native ufw rule at this point.
func (f *UFW) appendRule(ctx context.Context, r *Rule) error {
	args := f.ruleArgs(r, nil, f.MarshalRule(r))
	if c := f.commentFor(r); c != "" {
		args = append(args, "comment", c)
	}
	_, err := runCommand(ctx, "ufw", args...)
	return err
}

// nativeInsertPositionFromRows maps a 1-based logical position to ufw's 1-based
// native insert position, given the physical tuple rows in ufw's own order. A nil
// row is a tuple ufw counts in its numbered list but this backend does not model
// (an old-format or otherwise unparseable tuple); it still occupies a physical
// slot, so such a row preceding the anchor shifts the native position instead of
// being ignored — which would place the rule one slot too early per preceding
// unmodeled row and, for a first-match firewall, change enforcement. Every modeled tuple is its own rule, so with no
// un-representable rows this reduces to the plain physical position.
func (f *UFW) nativeInsertPositionFromRows(rows []*Rule, position int) int {
	var physPos []int
	for i, r := range rows {
		if r != nil {
			physPos = append(physPos, i+1)
		}
	}
	if position < 1 {
		position = 1
	}
	if position-1 >= len(physPos) {
		// Past the last logical rule: point past the last physical tuple so ufw
		// rejects the position and InsertRule falls back to a plain append.
		return len(rows) + 1
	}
	return physPos[position-1]
}

// nativeInsertPosition maps a 1-based logical position (a rule's Number, as GetRules
// reports it) to the 1-based position ufw's own numbered list uses for `ufw insert`.
// The two index spaces differ because ufw's list also counts tuples this backend
// does not model. The tuple order (IPv4 user.rules then IPv6 user6.rules) is exactly ufw's
// native order, so the logical position's row in that list is its native position. A
// position past the last logical rule maps past the native count, which ufw rejects
// and InsertRule then handles as a plain append.
func (f *UFW) nativeInsertPosition(position int) (int, error) {
	v4, err := f.parseTupleRows(UFWIPv4, IPv4)
	if err != nil {
		return 0, err
	}
	v6, err := f.parseTupleRows(UFWIPv6, IPv6)
	if err != nil {
		return 0, err
	}
	// Physical order is every IPv4 tuple then every IPv6 tuple — ufw's own numbered
	// order.
	return f.nativeInsertPositionFromRows(append(v4, v6...), position), nil
}

// InsertRule inserts rule before the given 1-based position using `ufw insert`.
// position <= 0 is treated as 1; a position larger than the current rule count
// appends the rule (ufw itself rejects an out-of-range position, so that case
// falls back to a plain add).
func (f *UFW) InsertRule(ctx context.Context, zoneName string, position int, r *Rule) error {
	// A DirAny rule occupies a tuple in each direction; insert each half at the
	// requested position.
	if r.Direction == DirAny {
		for _, sub := range expandDirections(r) {
			if err := f.InsertRule(ctx, zoneName, position, sub); err != nil {
				return err
			}
		}
		return nil
	}

	// A TCPUDP rule with no single native tuple form is inserted as its concrete
	// tcp+udp rows at the same position, mirroring AddRule's fan-out.
	if f.tcpudpNeedsExpand(r) {
		for _, sub := range expandProtocols(r) {
			if err := f.InsertRule(ctx, zoneName, position, sub); err != nil {
				return err
			}
		}
		return nil
	}

	// Verify the rule is valid for ufw before routing it, as in AddRule.
	if err := r.validate(); err != nil {
		return err
	}

	if f.needsIPTablesRules(r) {
		r, err := resolveSetRefRule(r, f.setHelper().setRefFamily)
		if err != nil {
			return err
		}
		return f.editIPTablesRules(r, false)
	}
	if position <= 0 {
		position = 1
	}

	rule := f.MarshalRule(r)

	// position is a Number GetRules reported, which counts only the tuples this
	// backend models, while `ufw insert` counts ufw's own numbered list — which
	// also counts tuples it does not model. Map to that native position so an
	// unmodeled tuple earlier in the list does not skew the insert.
	native, err := f.nativeInsertPosition(position)
	if err != nil {
		return err
	}
	position = native

	args := f.ruleArgs(r, []string{"insert", strconv.Itoa(position)}, rule)
	if c := f.commentFor(r); c != "" {
		args = append(args, "comment", c)
	}
	_, err = runCommand(ctx, "ufw", args...)
	// ufw rejects a position past the end of its (per-family) numbered rule list.
	// The interface contract asks to append there, and ufw's own validation is the
	// only reliable measure of that list's length. Append with a plain `ufw <rule>`
	// (which adds at the tail); AddRule instead uses `ufw prepend`, which would put
	// the rule at the front rather than the end.
	if err != nil && strings.Contains(err.Error(), "Invalid position") {
		return f.appendRule(ctx, r)
	}
	return err
}

// deleteNative marshals r into a ufw rulespec and removes it with `ufw delete`,
// treating an already-absent rule as a no-op (matching every other backend). It is
// the single-tuple removal primitive RemoveRule builds its protocol-axis handling on.
func (f *UFW) deleteNative(ctx context.Context, r *Rule) error {
	args := f.ruleArgs(r, []string{"delete"}, f.MarshalRule(r))
	if _, err := runCommand(ctx, "ufw", args...); err != nil {
		// ufw reports a missing rule as "Could not delete non-existent rule".
		if strings.Contains(strings.ToLower(err.Error()), "could not delete") {
			return nil
		}
		return err
	}
	return nil
}

// storedNativeTCPUDP returns the single native `any`-proto tuple ufw currently holds
// that backs r — one stored tuple UnmarshalRule read back as TCPUDP (ufw's ported
// `any`) — or nil when none does. A TCPUDP target may instead be backed by a
// separately-added tcp tuple and udp tuple, which delete individually, so the actual
// backing has to be resolved before deleting. It matches on everything but the
// transport (EqualForRemoval). It backs RemoveRule's choice between deleting one
// native tuple (splitting it for a concrete-transport target) and deleting a
// concrete tcp/udp pair, the analog of apf reading its CPORTS list before removal.
func (f *UFW) storedNativeTCPUDP(r *Rule) (*Rule, error) {
	v4, err := f.ParseRules(UFWIPv4, IPv4)
	if err != nil {
		return nil, err
	}
	v6, err := f.ParseRules(UFWIPv6, IPv6)
	if err != nil {
		return nil, err
	}
	for _, e := range append(v4, v6...) {
		if e.Proto == TCPUDP && e.EqualForRemoval(r, true) {
			return e, nil
		}
	}
	return nil, nil
}

// removeIPTablesRules sweeps the before.rules files for a removal target. The raw
// files carry one transport per line, so a both-transports target sweeps its
// concrete tcp and udp rows (expandProtocols is a no-op for anything else).
func (f *UFW) removeIPTablesRules(r *Rule) error {
	for _, sub := range expandProtocols(r) {
		if err := f.editIPTablesRules(sub, true); err != nil {
			return err
		}
	}
	return nil
}

// RemoveRule removes a filter rule from the zone.
func (f *UFW) RemoveRule(ctx context.Context, zoneName string, r *Rule) error {
	// A DirAny target removes both its inbound and outbound tuple.
	if r.Direction == DirAny {
		for _, sub := range expandDirections(r) {
			if err := f.RemoveRule(ctx, zoneName, sub); err != nil {
				return err
			}
		}
		return nil
	}

	// A TCPUDP rule with no single native tuple form (a raw-path, portless or multiport
	// both-transports match) is removed as its concrete tcp+udp rows, mirroring
	// AddRule's fan-out. A native single-port TCPUDP falls through to the tuple-backing
	// resolution below.
	if f.tcpudpNeedsExpand(r) {
		for _, sub := range expandProtocols(r) {
			if err := f.RemoveRule(ctx, zoneName, sub); err != nil {
				return err
			}
		}
		return nil
	}

	// Verify the rule is valid for ufw before routing it, as in AddRule.
	if err := r.validate(); err != nil {
		return err
	}

	// Sweep the before.rules files on every removal, not only for a rule that has
	// to live there: a rule ufw could hold natively may still have been written by
	// hand into before.rules, GetRules reads both stores, so skipping the raw files
	// for a native target would leave a matching line behind and still reported.
	if err := f.removeIPTablesRules(r); err != nil {
		return err
	}
	if f.needsIPTablesRules(r) {
		return nil
	}

	// Protocol-axis removal. A TCPUDP rule may be backed by a single native
	// `any`-proto tuple, by a separately-added tcp tuple + udp tuple, or — since
	// ufw treats a differing protocol as a distinct rule — by both at once, so a
	// removal sweeps every backing rather than stopping at the first.
	if onProtocolAxis(r.Proto) {
		native, err := f.storedNativeTCPUDP(r)
		if err != nil {
			return err
		}
		if native != nil {
			// Delete the native `any` tuple via its bare/`any` form (a TCPUDP
			// marshal of the target).
			del := *r
			del.Proto = TCPUDP
			if err := f.deleteNative(ctx, &del); err != nil {
				return err
			}
		}
		// Delete the concrete-transport tuples: a TCPUDP target expands into
		// tcp+udp, a concrete target deletes itself. deleteNative is a no-op for a
		// tuple ufw does not hold.
		for _, sub := range expandProtocols(r) {
			if err := f.deleteNative(ctx, sub); err != nil {
				return err
			}
		}
		// When a concrete-transport target consumed a native both-transports
		// tuple, re-add the surviving opposite transport so its coverage is kept —
		// the protocol analog of splitting a dual-family row on removal. AddRule
		// dedups, so an already-present concrete twin is not doubled.
		if native != nil {
			if s := splitDualRowProtocol(native, r); s != nil {
				return f.AddRule(ctx, zoneName, s)
			}
		}
		return nil
	}

	return f.deleteNative(ctx, r)
}

// MoveRule repositions an existing rule. ufw has no native move verb, so a move
// is a positional delete-then-insert: the rule is removed and re-inserted at the
// requested slot. It is therefore not atomic — if the re-insert fails the rule is
// left removed. A position larger than the rule count moves the rule to the end
// (via InsertRule's append fallback).
func (f *UFW) MoveRule(ctx context.Context, zoneName string, r *Rule, position int) error {
	if err := f.RemoveRule(ctx, zoneName, r); err != nil {
		return err
	}
	return f.InsertRule(ctx, zoneName, position, r)
}

// natHelper returns an iptables backend scoped to ufw's before.rules files, so
// the iptables nat-table machinery (marshal/parse/edit) can be reused: ufw's
// before.rules is loaded through iptables-restore and takes a standard `*nat`
// table. Edits set iptablesRulesChanged so Reload runs `ufw reload`.
func (f *UFW) natHelper() *IPTables {
	return &IPTables{rulePrefix: f.rulePrefix, IP4Path: UFWBefore, IP6Path: UFWBefore6}
}

// GetNATRules returns the current NAT rules for the zone.
func (f *UFW) GetNATRules(ctx context.Context, zoneName string) ([]*NATRule, error) {
	return f.natHelper().GetNATRules(ctx, zoneName)
}

// AddNATRule adds a NAT rule to the zone.
func (f *UFW) AddNATRule(ctx context.Context, zoneName string, r *NATRule) error {
	if err := f.natHelper().AddNATRule(ctx, zoneName, r); err != nil {
		return err
	}
	f.iptablesRulesChanged = true
	return nil
}

// InsertNATRule positions a NAT rule within ufw's before.rules nat table, reusing
// the iptables helper's insert machinery.
func (f *UFW) InsertNATRule(ctx context.Context, zoneName string, position int, r *NATRule) error {
	if err := f.natHelper().InsertNATRule(ctx, zoneName, position, r); err != nil {
		return err
	}
	f.iptablesRulesChanged = true
	return nil
}

// MoveNATRule repositions a NAT rule within ufw's before.rules nat table, reusing
// the iptables helper's move machinery.
func (f *UFW) MoveNATRule(ctx context.Context, zoneName string, r *NATRule, position int) error {
	if err := f.natHelper().MoveNATRule(ctx, zoneName, r, position); err != nil {
		return err
	}
	f.iptablesRulesChanged = true
	return nil
}

// RemoveNATRule removes a NAT rule from the zone.
func (f *UFW) RemoveNATRule(ctx context.Context, zoneName string, r *NATRule) error {
	if err := f.natHelper().RemoveNATRule(ctx, zoneName, r); err != nil {
		return err
	}
	f.iptablesRulesChanged = true
	return nil
}

// policyKey is the /etc/default/ufw key for a direction's default policy.
func (f *UFW) policyKey(d Direction) string {
	switch d {
	case DirOutput:
		return "DEFAULT_OUTPUT_POLICY"
	case DirForward:
		return "DEFAULT_FORWARD_POLICY"
	}
	return "DEFAULT_INPUT_POLICY"
}

// readPolicy reads /etc/default/ufw and returns the default policy for each
// direction. A direction whose key is absent is reported as ActionInvalid.
func (f *UFW) readPolicy() (*DefaultPolicy, error) {
	fd, err := os.Open(UFWDefaults)
	if err != nil {
		return nil, err
	}
	defer func() { _ = fd.Close() }()
	vals := map[string]string{}
	scanner := bufio.NewScanner(fd)
	for scanner.Scan() {
		line := scanner.Text()
		if ci := strings.IndexByte(line, '#'); ci >= 0 {
			line = line[:ci]
		}
		line = strings.TrimSpace(line)
		key, val, found := strings.Cut(line, "=")
		if !found {
			continue
		}
		vals[strings.TrimSpace(key)] = trimQuotes(strings.TrimSpace(val))
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	policy := &DefaultPolicy{}
	for _, d := range []Direction{DirInput, DirOutput, DirForward} {
		v, ok := vals[f.policyKey(d)]
		if !ok {
			continue
		}
		// ufw stores the policy as a quoted ACCEPT/DROP/REJECT token.
		if a, err := ParseAction(v); err == nil && a != ActionInvalid {
			policy.set(d, a)
		}
	}
	return policy, nil
}

// GetDefaultPolicy returns the default filter policy for each direction.
func (f *UFW) GetDefaultPolicy(ctx context.Context, zoneName string) (*DefaultPolicy, error) {
	return f.readPolicy()
}

// policyValue renders an action as ufw's quoted policy token
// (DEFAULT_*_POLICY="ACCEPT"), matching how ufw itself writes the file.
func (f *UFW) policyValue(a Action) string {
	switch a {
	case Accept:
		return `"ACCEPT"`
	case Drop:
		return `"DROP"`
	case Reject:
		return `"REJECT"`
	}
	return ""
}

// writePolicy writes the default policy for each direction into
// /etc/default/ufw, updating an existing key in place and appending any that is
// absent.
func (f *UFW) writePolicy(policy *DefaultPolicy) error {
	existing, err := os.ReadFile(UFWDefaults)
	if err != nil {
		return err
	}
	lines := strings.Split(string(existing), "\n")
	written := map[Direction]bool{}
	for i, line := range lines {
		body := line
		if ci := strings.IndexByte(body, '#'); ci >= 0 {
			body = body[:ci]
		}
		key, _, found := strings.Cut(strings.TrimSpace(body), "=")
		if !found {
			continue
		}
		for _, d := range []Direction{DirInput, DirOutput, DirForward} {
			if key != f.policyKey(d) || policy.get(d) == ActionInvalid {
				continue
			}
			lines[i] = fmt.Sprintf("%s=%s", f.policyKey(d), f.policyValue(policy.get(d)))
			written[d] = true
		}
	}
	for _, d := range []Direction{DirInput, DirOutput, DirForward} {
		if written[d] || policy.get(d) == ActionInvalid {
			continue
		}
		lines = append(lines, fmt.Sprintf("%s=%s", f.policyKey(d), f.policyValue(policy.get(d))))
	}
	return writeConfigFile(UFWDefaults, []byte(strings.Join(lines, "\n")), 0640)
}

// SetDefaultPolicy sets the default filter policy for each direction.
func (f *UFW) SetDefaultPolicy(ctx context.Context, zoneName string, policy *DefaultPolicy) error {
	if policy == nil {
		return fmt.Errorf("policy cannot be nil")
	}
	// ufw supports accept, drop and reject as a default policy; a direction left
	// ActionInvalid is skipped by writePolicy and left unchanged.
	if err := f.writePolicy(policy); err != nil {
		return err
	}
	f.iptablesRulesChanged = true
	return nil
}

// --- address sets (ipset) ---------------------------------------------------

// setHelper returns the session's iptables backend, used to reach the
// ipset-backed address-set implementation. A manager built as a bare struct
// rather than through NewUFW gets one on first use, with no staging file
// detected, which leaves its sets live-only.
func (f *UFW) setHelper() *IPTables {
	if f.sets == nil {
		f.sets = &IPTables{rulePrefix: f.rulePrefix}
	}
	return f.sets
}

// GetAddressSets returns all managed address sets.
func (f *UFW) GetAddressSets(ctx context.Context) ([]*AddressSet, error) {
	return f.setHelper().GetAddressSets(ctx)
}

// GetAddressSet returns the named address set.
func (f *UFW) GetAddressSet(ctx context.Context, name string) (*AddressSet, error) {
	return f.setHelper().GetAddressSet(ctx, name)
}

// AddAddressSet creates an address set.
func (f *UFW) AddAddressSet(ctx context.Context, set *AddressSet) error {
	return f.setHelper().AddAddressSet(ctx, set)
}

// RemoveAddressSet removes the named address set.
func (f *UFW) RemoveAddressSet(ctx context.Context, name string) error {
	return f.setHelper().RemoveAddressSet(ctx, name)
}

// AddAddressSetEntry adds an entry to an address set.
func (f *UFW) AddAddressSetEntry(ctx context.Context, name, entry string) error {
	return f.setHelper().AddAddressSetEntry(ctx, name, entry)
}

// RemoveAddressSetEntry removes an entry from an address set.
func (f *UFW) RemoveAddressSetEntry(ctx context.Context, name, entry string) error {
	return f.setHelper().RemoveAddressSetEntry(ctx, name, entry)
}

// Backup captures the current filter and NAT rules managed by this backend.
func (f *UFW) Backup(ctx context.Context, zoneName string) (*Backup, error) {
	rules, err := f.GetRules(ctx, zoneName)
	if err != nil {
		return nil, err
	}
	natRules, err := f.GetNATRules(ctx, zoneName)
	if err != nil {
		return nil, err
	}
	// Backup captures the full filter and NAT rule state plus the default policy and
	// managed ipsets; Restore rebuilds them, so every rule read is preserved and
	// re-applied.
	backup := &Backup{Rules: rules, NATRules: natRules}
	if err := captureBackupState(ctx, f, zoneName, backup); err != nil {
		return nil, err
	}
	return backup, nil
}

// Restore replaces the managed rules with the contents of a Backup.
func (f *UFW) Restore(ctx context.Context, zoneName string, backup *Backup) error {
	if backup == nil {
		return fmt.Errorf("backup cannot be nil")
	}

	// Snapshot the actual current state and remove it, so Restore reconciles the
	// live firewall to the backup rather than only re-touching the backup's own
	// rules: a rule present now but absent from the backup must be removed. Removal
	// of an already-absent rule is tolerated as a no-op (RemoveRule/RemoveNATRule
	// are idempotent), so a partially-applied backup can be re-restored cleanly.
	current, err := f.GetRules(ctx, zoneName)
	if err != nil {
		return err
	}
	currentNAT, err := f.GetNATRules(ctx, zoneName)
	if err != nil {
		return err
	}
	for _, r := range current {
		// RemoveRule itself dispatches an iptables-file rule to editIPTablesRules, so
		// every current rule — whichever form it takes — goes through the same call.
		if err := f.RemoveRule(ctx, zoneName, r); err != nil {
			return err
		}
	}
	for _, r := range currentNAT {
		if err := f.RemoveNATRule(ctx, zoneName, r); err != nil {
			return err
		}
	}

	// Recreate the ipsets now that the current rules are gone (so nothing holds a
	// set reference) and before the backup rules that reference them are re-added.
	if err := restoreBackupSets(ctx, f, backup, false); err != nil {
		return err
	}

	// Re-add rules from backup, reproducing their backed-up order. AddRule appends
	// an iptables-based rule (inserted before COMMIT in before.rules) but prepends a
	// CLI rule (`ufw prepend`, always position 1), so the two groups need opposite
	// iteration: append the iptables rules front-to-back, then prepend the CLI rules
	// back-to-front so each prepend pushes the earlier rules down and rebuilds the
	// original top-to-bottom order. Re-adding CLI rules front-to-back would reverse
	// them, inverting first-match evaluation (a specific deny above a broad allow
	// would land below it and never fire).
	for _, r := range backup.Rules {
		if f.needsIPTablesRules(r) {
			if err := f.AddRule(ctx, zoneName, r); err != nil {
				return err
			}
		}
	}
	for i := len(backup.Rules) - 1; i >= 0; i-- {
		r := backup.Rules[i]
		if f.needsIPTablesRules(r) {
			continue
		}
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

// Reload re-applies edits to the iptables rules files; rules added through the
// ufw CLI apply immediately, but edits to those files only take effect after a
// reload. Address sets are staged the same way this backend's raw iptables rules
// are, so they are loaded here too: the sets first, so a rule matching on one
// resolves when ufw reloads, and the destroys owed for removed sets last, once
// the rules that referenced them are gone.
func (f *UFW) Reload(ctx context.Context) error {
	sets := f.setHelper()
	if err := sets.applyStagedSets(ctx); err != nil {
		return err
	}

	if f.iptablesRulesChanged {
		if _, err := runCommand(ctx, "ufw", "reload"); err != nil {
			return err
		}
		f.iptablesRulesChanged = false
	}

	return sets.applyPendingSetRemovals(ctx)
}

// Close releases any resources held by the backend.
func (f *UFW) Close(ctx context.Context) error {
	return nil
}
