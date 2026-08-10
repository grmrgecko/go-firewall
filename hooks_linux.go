package firewall

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/anmitsu/go-shlex"
)

// hookScript injects raw iptables/ip6tables commands into a CSF or APF hook that
// the firewall sources at (re)load time. It lets those backends express filter
// rules their native config cannot — connection-state, per-rule interface,
// logging, rate limiting, ICMPv6, and the transport protocols SCTP, GRE, ESP and
// AH — by reusing the iptables rule marshaller/parser and writing the resulting
// commands directly into the firewall's documented hook. It also parses the
// iptables/ip6tables commands in the hook back into rules.
//
// A rule's comment is carried as a full-line `#` script comment directly above
// its command line(s), the same convention the csf.allow/apf trust files use, so
// the command lines themselves stay free of shell-quoted comment text. An
// iptables `-m comment` embedded in a line — hand-added, or written by an older
// library version — takes precedence on read, and the prefix tag from either
// source marks the rule as HasPrefix (see resolveComment).
type hookScript struct {
	// rulePrefix tags each injected rule through the script comment written
	// above its lines so it can be told apart from other rules.
	rulePrefix string
	// hookPath is the firewall hook this library writes its command lines into. It
	// runs before the firewall adds its own rules, so injected rules sit at the top
	// of the INPUT/OUTPUT chains.
	hookPath string
	// hookPerm is the mode a newly created hook file is given (0700 for CSF, 0750
	// for APF); an existing hook keeps its own mode, except for the execute bit
	// (see commit).
	hookPerm os.FileMode
	// ipv6Enabled mirrors the backend's own IPv6 handling (csf.conf IPV6, conf.apf
	// USE_IPV6). With it off, a family-agnostic rule is written for IPv4 only (see
	// ruleLines).
	ipv6Enabled bool
	// ip4Cmd, ip6Cmd and ipsetCmd are the commands the written lines invoke. The
	// backends fill them with absolute paths (newHookScript) so the hook does not
	// depend on the PATH it is sourced with; an empty field falls back to the bare
	// command name and leaves resolution to the shell.
	ip4Cmd   string
	ip6Cmd   string
	ipsetCmd string
}

// newHookScript binds a hookScript to a firewall's hook file, resolving the
// commands its lines invoke to absolute paths.
func newHookScript(rulePrefix, hookPath string, hookPerm os.FileMode, ipv6Enabled bool) *hookScript {
	return &hookScript{
		rulePrefix:  rulePrefix,
		hookPath:    hookPath,
		hookPerm:    hookPerm,
		ipv6Enabled: ipv6Enabled,
		ip4Cmd:      resolveHookBinary("iptables"),
		ip6Cmd:      resolveHookBinary("ip6tables"),
		ipsetCmd:    resolveHookBinary("ipset"),
	}
}

// commit installs a staged hook file and makes sure it is left executable.
//
// The execute bit is the hook's activation switch, not a mode the operator
// chose: apf runs hook_pre.sh only when it is executable and ships it 0640, and
// csf's csfpre.sh works the same way. An atomic write preserves an existing
// file's mode, so without this the library's lines land in a file the firewall
// never runs — they read back from the file correctly while never reaching the
// kernel. Only the owner-execute bit is forced; the rest of the mode and the
// ownership stay as they were.
func (h *hookScript) commit(af *atomicFile) error {
	if err := af.Commit(); err != nil {
		return err
	}
	fi, err := os.Stat(h.hookPath)
	if err != nil {
		return err
	}
	if fi.Mode().Perm()&0100 != 0 {
		return nil
	}
	return os.Chmod(h.hookPath, fi.Mode().Perm()|0100)
}

// resolveHookBinary returns the absolute path of a command the hook invokes, so
// an injected line does not depend on the PATH the firewall happens to source the
// hook with. csf.pl and apf both prepend the standard sbin directories before
// sourcing, but neither guarantees them across versions, and a hook run by hand
// or from a service unit inherits whatever environment its caller had — an
// unresolved `iptables` there fails the line silently at load time. Falls back to
// the bare name when the tool cannot be found, leaving resolution to the shell.
func resolveHookBinary(name string) string {
	bin, _ := resolveBinary(name)
	return bin
}

// --- hook routing (rule shapes the native configs cannot express) ------------

// hookOnlyProto reports whether a protocol has no representation in CSF's or
// APF's native config and so can only be applied through the raw-iptables hook.
func hookOnlyProto(p Protocol) bool {
	switch p {
	case SCTP, GRE, ESP, AH:
		return true
	}
	return false
}

// ruleNeedsHook reports whether a rule requires a feature that CSF/APF cannot
// express in their native config and so must be injected as a raw iptables rule
// through the hook: a forward-chain (routed) rule, connection-state matching,
// per-rule interface matching, logging, rate limiting, ICMPv6, a transport
// protocol their native config does not model (SCTP and the portless IP protocols
// GRE, ESP and AH), an address-set reference (@set), or a negated address.
// csf.allow/apf trust files take literal addresses only, so a `-m set
// --match-set` match lives in the hook beside the ipset commands that create the
// set, and a negated address lives there as iptables' native `! -s`/`! -d` —
// csf.pl passes an advanced line's s=/d= value verbatim to iptables (where a
// joined "!" is not a reliable negation) and skips a plain "!"-prefixed line as
// not an address, so neither native form can carry one.
func ruleNeedsHook(r *Rule) bool {
	return r.IsForward() || r.State != 0 || r.InInterface != "" || r.OutInterface != "" ||
		r.Log || r.RateLimit != nil || r.Proto == ICMPv6 || hookOnlyProto(r.Proto) ||
		isSetRef(r.Source) || isSetRef(r.Destination) ||
		strings.HasPrefix(r.Source, "!") || strings.HasPrefix(r.Destination, "!")
}

// bareHostShape reports whether a rule has the shape a plain csf.allow/apf
// allow_hosts line expresses: exactly one source or destination address, no ports,
// and the any-protocol match. Its direction is not considered — a DirAny bare host
// is the single bidirectional plain line, while a concrete-direction one is one-way
// (see bareHostOneWay). Shared by CSF and APF.
func bareHostShape(r *Rule) bool {
	if r.HasPorts() || r.HasSourcePorts() || r.Proto != ProtocolAny {
		return false
	}
	// A set reference (@set) is not a literal host: it matches through the hook's
	// `-m set` clause (ruleNeedsHook routes it there), never a plain trust-file line.
	if isSetRef(r.Source) || isSetRef(r.Destination) {
		return false
	}
	return (r.Source != "") != (r.Destination != "")
}

// bareHostOneWay reports whether a rule is a ONE-WAY bare-address host allow/deny:
// the bare host shape with a concrete input or output direction. A plain line matches
// a host in BOTH directions, and neither backend's advanced-rule format can carry an
// address without a port, so a one-way bare host rule is expressed through the
// raw-iptables hook instead.
func bareHostOneWay(r *Rule) bool {
	return bareHostShape(r) && (r.Direction == DirInput || r.Direction == DirOutput)
}

// dirAnyPlainLine reports whether a DirAny rule maps to a single bidirectional plain
// csf.allow/apf line: a bare host carrying no feature that would force the
// raw-iptables hook (connection state, interface, logging, etc.). Every other DirAny
// rule fans out into a concrete input rule plus its role-swapped output rule on
// add/remove, since csf/apf have no single native both-directions construct for it.
func dirAnyPlainLine(r *Rule) bool {
	return r.Direction == DirAny && bareHostShape(r) && !ruleNeedsHook(r)
}

// shapeNeedsHook reports whether a rule's shape overflows every native CSF/APF
// config form and must be injected through the raw-iptables hook. The native forms
// are narrow — a plain trust-file line holds one address, matches both directions,
// and is all-protocol; an advanced line holds exactly one address field and one
// port-flow field and requires both; the conf lists key on a port or an icmp type —
// while iptables expresses every overflow directly (`-s` with `-d`, `--sport` with
// `--dport`, a bare `-p tcp -j ACCEPT`), so these shapes are hooked rather than
// rejected: the alternative is failing on a rule the firewall can enforce.
//
// Feature-based routing (state, interface, logging, rate limiting, ICMPv6,
// hook-only transports, set references, negation) is ruleNeedsHook's job, and the
// backend-specific connlimit, ICMP and port-list shapes stay in each backend's
// needsHook; ICMP is excluded from every test here because both backends route it
// there (CSF's typed advanced rule, APF.isConfRule). Shared by CSF and APF.
func shapeNeedsHook(r *Rule) bool {
	// A one-way bare host: a plain line is bidirectional and an advanced rule
	// requires a port, so a concrete-direction bare host has no native form.
	if bareHostOneWay(r) {
		return true
	}
	// Portless address shapes no trust file expresses.
	if !r.Proto.IsICMP() && !r.HasPorts() && !r.HasSourcePorts() {
		// A source+destination pair has no single-address advanced/plain form.
		if r.Source != "" && r.Destination != "" {
			return true
		}
		// A single-address host pinned to a transport has no portless form: the plain
		// line is all-protocol and the advanced rule requires a port. TCPUDP counts —
		// it names transports, so it is not the all-protocol plain line either.
		if (r.Source != "" || r.Destination != "") && onProtocolAxis(r.Proto) {
			return true
		}
	}
	// Advanced-line overflows, on the protocols an iptables port or icmp match
	// accepts: a port on ProtocolAny is inexpressible in iptables too, so it stays
	// on the native path and is rejected there by Rule.validate rather than
	// reaching the hook and failing there.
	if onProtocolAxis(r.Proto) || r.Proto.IsICMP() {
		// One port-flow field: a source port and a destination port cannot share it.
		if r.HasPorts() && r.HasSourcePorts() {
			return true
		}
		// An advanced rule requires an address, so a bare source-port match has no
		// advanced form at all; iptables matches --sport on its own.
		if r.HasSourcePorts() && r.Source == "" && r.Destination == "" {
			return true
		}
		// One address field: a ported or icmp-matching source+destination pair cannot
		// share it (its portless non-ICMP counterpart is routed above).
		if r.Source != "" && r.Destination != "" &&
			(r.HasPorts() || r.HasSourcePorts() || r.Proto.IsICMP()) {
			return true
		}
	}
	// A bare protocol match — a non-ICMP transport with no address and no port — has
	// no native construct (the trust files key on an address, the conf lists on a
	// port or icmp type) but iptables applies it directly.
	return r.Source == "" && r.Destination == "" && !r.HasPorts() && !r.HasSourcePorts() && !r.Proto.IsICMP()
}

// --- hook file primitives ----------------------------------------------------

// command returns the iptables command a written line invokes for a family: the
// resolved absolute path when the hook has one, otherwise the bare name.
func (h *hookScript) command(fam Family) string {
	if fam == IPv6 {
		if h.ip6Cmd != "" {
			return h.ip6Cmd
		}
		return "ip6tables"
	}
	if h.ip4Cmd != "" {
		return h.ip4Cmd
	}
	return "iptables"
}

// ipsetCommand returns the ipset command an address-set line invokes, resolved as
// with command.
func (h *hookScript) ipsetCommand() string {
	if h.ipsetCmd != "" {
		return h.ipsetCmd
	}
	return "ipset"
}

// hookCmdIs reports whether a hook line's command token invokes name. Only the
// command's base name is compared, so every spelling of the same tool matches:
// the bare name a hand-written line uses, the resolved path this library writes,
// and any other path an operator wrote by hand (`/sbin/ipset` read by a manager
// that resolved `/usr/sbin/ipset`). Quotes are stripped, since the hook is shell.
func hookCmdIs(tok, name string) bool {
	tok = trimQuotes(tok)
	if tok == "" {
		return false
	}
	return filepath.Base(tok) == name
}

// hookRuleCommands maps the base name of a rule command to the family it selects.
// Alongside the plain names it covers the update-alternatives variants a
// hand-written line may invoke directly (Debian's iptables-nft/-legacy). The
// save/restore front-ends are deliberately absent: they are not rule commands.
var hookRuleCommands = map[string]Family{
	"iptables":         IPv4,
	"iptables-legacy":  IPv4,
	"iptables-nft":     IPv4,
	"ip6tables":        IPv6,
	"ip6tables-legacy": IPv6,
	"ip6tables-nft":    IPv6,
}

// hookCmdFamily splits a hook command line into the family its command selects
// and the arguments that follow, reporting whether the line invokes a rule
// command at all. The command is matched on its base name (see hookCmdIs), so a
// line spelled with any path — or none — reads back the same. A command with no
// arguments is not a rule line.
func hookCmdFamily(line string) (fam Family, rest string, ok bool) {
	cmd, rest, _ := strings.Cut(strings.TrimSpace(line), " ")
	rest = strings.TrimSpace(rest)
	cmd = trimQuotes(cmd)
	if rest == "" || cmd == "" {
		return FamilyAny, "", false
	}
	if fam, ok := hookRuleCommands[filepath.Base(cmd)]; ok {
		return fam, rest, true
	}
	return FamilyAny, "", false
}

// resolveComment derives a parsed hook rule's user-facing comment and prefix
// flag from the iptables comment embedded in its line and the script comment
// above it. An embedded comment's text wins — foreign lines and lines written
// by an older library version carry one — while the script comment is the form
// this library writes; the prefix tag counts from either source.
func (h *hookScript) resolveComment(embedded, script string) (text string, hasPrefix bool) {
	et, eh := prefixedComment(h.rulePrefix, embedded)
	st, sh := prefixedComment(h.rulePrefix, script)
	if embedded != "" {
		return et, eh || sh
	}
	return st, sh
}

// hookGroup is one physical span of the hook: an iptables/ip6tables command
// line together with the script comment lines attached above it (a LOG line and
// its adjacent action line count as one logical group), or any other line on
// its own. raw preserves the original lines so a rewrite copies user formatting
// through verbatim; rule/nat hold the parsed logical rule when the group
// encodes one, and cmds marks a group whose line is a command even when neither
// parser models it.
type hookGroup struct {
	raw  []string
	cmds []string
	rule *Rule
	nat  *NATRule
}

// scanGroups streams the hook's groups to fn in file order, built on the shared
// comment-group scanner (scanCommentGroups): each full-line script comment
// attaches to the command line below it, and a LOG line pairs with the action
// line under it into the one logged rule they encode. An error from fn stops
// the scan.
func (h *hookScript) scanGroups(fd *os.File, fn func(g hookGroup) error) error {
	// held is a parsed LOG-only group waiting to see whether the next command
	// line is its action partner. iptables writes a logged rule as two lines (a
	// non-terminal LOG line then the action line), so we buffer the LOG line here
	// rather than emit it, resolving its comment only once its fate is decided.
	type heldGroup struct {
		g        hookGroup
		rule     *Rule
		embedded string
		script   string
	}
	var held *heldGroup
	// emitHeld flushes any buffered LOG group, whether it merged with a partner
	// or stayed an orphan LOG-only rule. resolveComment folds the embedded
	// comment (from a paired action line) over the script comment.
	emitHeld := func() error {
		if held == nil {
			return nil
		}
		hg := held
		held = nil
		hg.rule.Comment, hg.rule.HasPrefix = h.resolveComment(hg.embedded, hg.script)
		hg.g.rule = hg.rule
		return fn(hg.g)
	}
	isCommand := func(trimmed string) bool {
		_, _, ok := hookCmdFamily(trimmed)
		return ok
	}
	err := scanCommentGroups(fd, h.rulePrefix, isCommand, func(cg commentGroup) error {
		// A passthrough line sits between a held LOG line and any later action
		// line, so it ends the pairing.
		if cg.line == "" {
			if err := emitHeld(); err != nil {
				return err
			}
			return fn(hookGroup{raw: cg.raw})
		}
		g := hookGroup{raw: cg.raw, cmds: []string{cg.line}}
		if nat, ok := h.parseNATLine(cg.line); ok {
			if err := emitHeld(); err != nil {
				return err
			}
			_, sp := prefixedComment(h.rulePrefix, cg.comment)
			nat.HasPrefix = nat.HasPrefix || sp
			g.nat = nat
			return fn(g)
		}
		rule, ok := h.parseLine(cg.line)
		if !ok {
			// A command line neither parser models still counts as a command
			// (cmds set), so set removal refuses to strand a referencing rule.
			if err := emitHeld(); err != nil {
				return err
			}
			return fn(g)
		}
		// Pair a held LOG line with the action line directly under it. The
		// len(cg.raw) == 1 guard enforces physical adjacency: a raw slice longer
		// than one line means a comment attached to this action, so the LOG and
		// action are not consecutive and must stay separate — pairing them would
		// synthesize a rule no removal could locate. On a match, fold the two
		// lines into the one logged rule they encode and emit it.
		if held != nil && len(cg.raw) == 1 && logPartner(held.rule, rule) {
			if rule.Comment != "" {
				held.embedded = rule.Comment
			}
			held.rule = mergeLogPair(held.rule, rule)
			held.g.raw = append(held.g.raw, cg.raw[0])
			held.g.cmds = append(held.g.cmds, cg.line)
			return emitHeld()
		}
		// This line is not a partner, so any held LOG line is now an orphan;
		// flush it before handling this line.
		if err := emitHeld(); err != nil {
			return err
		}
		// Buffer a bare LOG line (Log set, no terminal action) to pair against the
		// next command line; every other rule is complete on its own and emitted
		// at once.
		if rule.Action == ActionInvalid && rule.Log {
			held = &heldGroup{g: g, rule: rule, embedded: rule.Comment, script: cg.comment}
			return nil
		}
		rule.Comment, rule.HasPrefix = h.resolveComment(rule.Comment, cg.comment)
		g.rule = rule
		return fn(g)
	})
	if err != nil {
		return err
	}
	return emitHeld()
}

// shellSafeToken quotes a token so /bin/sh passes it through verbatim. The
// iptables marshaller quotes free-text fields (a log prefix) for an
// iptables-restore file, where double quotes are literal — but the hook is
// sourced by /bin/sh, which expands $var, $(...) and backticks inside double
// quotes. A token made of ordinary argument characters is returned bare for
// readability; anything else is wrapped in single quotes (with any embedded
// single quote escaped), which the shell treats as a literal. shlex.Split
// reverses either form on read-back.
func shellSafeToken(tok string) string {
	safe := tok != ""
	for _, r := range tok {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' ||
			strings.ContainsRune("_./:=,+-@%", r) {
			continue
		}
		safe = false
		break
	}
	if safe {
		return tok
	}
	return "'" + strings.ReplaceAll(tok, "'", `'\''`) + "'"
}

// --- filter rules (raw iptables commands in the hook) ------------------------

// linesForRows encodes family-concrete rule rows (an expandFamilies fan-out) as
// the raw command line(s) to inject: one iptables (or ip6tables) command per
// underlying iptables line and per row. A logged rule yields a LOG line followed
// by its action line, as with the iptables backend. The comment is not
// marshalled into the line — it rides as the script comment edit writes above
// the lines instead. Each marshalled line is re-tokenized and re-quoted
// shell-safely, because the hook script is sourced by /bin/sh rather than exec'd
// argv-style.
func (h *hookScript) linesForRows(rows []*Rule) ([]string, error) {
	var out []string
	for _, row := range rows {
		fam := row.impliedFamily()
		cmd := h.command(fam)
		// iptables has no both-transports match, so a TCPUDP rule fans out into a tcp
		// line and a udp line; a portless ProtocolAny rule is a valid protocol-agnostic
		// match (a bare `-j ACCEPT`) and is not fanned.
		for _, sub := range expandProtocols(row) {
			rc := *sub
			rc.Family = fam
			rc.Comment = ""
			ipt := &IPTables{}
			// The hook borrows the iptables encoder, so it also runs its checks:
			// the rule reached here through a routing backend's entry point, not
			// iptables', and expandProtocols above supplied the concrete cell.
			if err := ipt.validateRule(&rc); err != nil {
				return nil, err
			}
			base, err := ipt.marshalRuleLines(&rc)
			if err != nil {
				return nil, err
			}
			for _, line := range base {
				tokens, terr := shlex.Split(line, true)
				if terr != nil {
					return nil, terr
				}
				for i, t := range tokens {
					tokens[i] = shellSafeToken(t)
				}
				out = append(out, cmd+" "+strings.Join(tokens, " "))
			}
		}
	}
	return out, nil
}

// ruleLines encodes a rule as the raw command line(s) an edit acts on. An add
// writes only the family rows the backend enforces (filterFamiliesIPv6): the
// hook runs on every (re)load regardless, but neither csf nor apf flushes
// ip6tables — filter or nat table — while IPv6 is disabled (csf.pl guards the
// v6 flush behind IPV6; apf's ipt6() is a no-op unless USE_IPV6=1), so an
// injected ip6tables line would be re-appended on each reload and would outlive
// its own removal from the hook. A family-agnostic rule that references an
// address set is pinned to the set's family instead: an ipset is single-family,
// so the opposite-family line would fail every time the firewall sources the
// hook. A removal sweeps every family row the rule could occupy
// (expandFamilies) regardless of the IPv6 setting, so an ip6tables line written
// while IPv6 was enabled — or added by hand — is still cleared once it is
// switched off, rather than stranded in the hook.
func (h *hookScript) ruleLines(r *Rule, remove bool) ([]string, error) {
	if remove {
		return h.linesForRows(expandFamilies(r))
	}
	if r.impliedFamily() == FamilyAny && (isSetRef(r.Source) || isSetRef(r.Destination)) {
		// Resolved live-first, then from the hook's own ipset lines for a set
		// just written but not loaded by the firewall yet.
		fam, err := ipsetRefFamily(r.Source, r.Destination, h.getAddressSets)
		if err != nil {
			return nil, err
		}
		if fam == IPv6 && !h.ipv6Enabled {
			return nil, fmt.Errorf("rule references an IPv6 address set while IPv6 is disabled: %w", ErrUnsupported)
		}
		rc := *r
		rc.Family = fam
		return h.linesForRows([]*Rule{&rc})
	}
	return h.linesForRows(filterFamiliesIPv6(h.ipv6Enabled, r))
}

// parseLine decodes an injected command line back into the rule it represents
// (one line, so a LOG line yields a rule with Log set and no action), reporting
// whether the line is one this backend recognizes. Any embedded iptables comment
// is left as its raw text; scanGroups resolves it against the script
// comment above the line (see resolveComment).
func (h *hookScript) parseLine(line string) (*Rule, bool) {
	fam, rest, ok := hookCmdFamily(line)
	if !ok {
		return nil, false
	}
	r, err := unmarshalIPTablesRule(rest, fam)
	if err != nil {
		return nil, false
	}
	return r, true
}

// getRules parses the hook into logical rules, each LOG line coalesced with the
// action line that follows it and each rule carrying the comment resolved from
// its script or embedded comment. Every command line is read, including any a
// user authored by hand, so the library reconciles the hook's real state. Family
// merging is left to the caller, which unions these with the backend's native
// rules.
func (h *hookScript) getRules() ([]*Rule, error) {
	fd, err := os.Open(h.hookPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer func() { _ = fd.Close() }()
	var rules []*Rule
	err = h.scanGroups(fd, func(g hookGroup) error {
		// An orphan LOG line (its action partner hand-edited away) is not a
		// reportable rule; removal still sweeps it (see Rule.OrphanLogMatchesAny).
		if g.rule != nil && g.rule.Action != ActionInvalid {
			rules = append(rules, g.rule)
		}
		return nil
	})
	return rules, err
}

// hookUnit is one logical rule as its hook line(s) — a LOG pair is two lines,
// every other rule one — with the rule those lines encode.
type hookUnit struct {
	lines []string
	rule  *Rule
}

// lineUnits parses marshalled command lines back into the logical units they
// encode, pairing each LOG line with its action line. The round trip normalizes
// field spellings, which edit's matching depends on, so a line that fails to
// parse is an error rather than a silent no-op.
func (h *hookScript) lineUnits(lines []string) ([]hookUnit, error) {
	var units []hookUnit
	for i := 0; i < len(lines); i++ {
		r, ok := h.parseLine(lines[i])
		if !ok {
			return nil, fmt.Errorf("hook line does not round-trip: %q", lines[i])
		}
		if i+1 < len(lines) {
			if p, pok := h.parseLine(lines[i+1]); pok && logPartner(r, p) {
				units = append(units, hookUnit{lines: []string{lines[i], lines[i+1]}, rule: mergeLogPair(r, p)})
				i++
				continue
			}
		}
		units = append(units, hookUnit{lines: []string{lines[i]}, rule: r})
	}
	return units, nil
}

// edit adds or removes a rule's command line(s) directly in the hook, rewriting
// the file in a single streamed pass. Both directions match on the underlying
// rule, never the comment, which is not part of rule identity: an add
// is satisfied by an existing line meaning the same rule even when it is spelled
// or commented differently, and a removal drops a copy of the rule a customer
// added under a different comment (or none) too. An added unit is appended with
// its script comment written above it; a dropped one takes its attached comment
// lines with it. A LOG line and the action line under it are matched as the one
// logged rule they encode, never independently: a logged rule and its unlogged
// twin are distinct rules, and removing one must not strip the other's lines.
// Every other hook line — user-authored shell and rules alike — streams through
// to the staged rewrite untouched; it reports whether the hook changed. Adding
// to an absent hook creates it; removing from one is a no-op.
func (h *hookScript) edit(r *Rule, remove bool) (bool, error) {
	desired, err := h.ruleLines(r, remove)
	if err != nil {
		return false, err
	}
	units, err := h.lineUnits(desired)
	if err != nil {
		return false, err
	}

	// A missing hook scans as empty: an add creates it, a removal is a no-op.
	fd, err := os.Open(h.hookPath)
	if err != nil {
		if !os.IsNotExist(err) {
			return false, err
		}
		if remove {
			return false, nil
		}
	} else {
		defer func() { _ = fd.Close() }()
	}

	af, err := newAtomicFile(h.hookPath, h.hookPerm)
	if err != nil {
		return false, err
	}
	defer af.Abort()
	// A freshly created hook gets a shebang; the firewall sources it as shell.
	if fd == nil {
		_, _ = fmt.Fprintln(af, "#!/bin/sh")
	}

	if remove {
		targets := make([]*Rule, 0, len(units))
		for _, u := range units {
			targets = append(targets, u.rule)
		}
		changed := false
		err = h.scanGroups(fd, func(g hookGroup) error {
			// An orphan LOG line whose action partner was hand-edited away still
			// belongs to the logged rule named by the removal.
			if g.rule != nil && (g.rule.MatchesAny(targets) || g.rule.OrphanLogMatchesAny(targets)) {
				changed = true
				return nil
			}
			for _, l := range g.raw {
				_, _ = fmt.Fprintln(af, l)
			}
			return nil
		})
		if err != nil {
			return false, err
		}
		if !changed {
			return false, nil
		}
		return true, h.commit(af)
	}

	// Copy the hook through, noting which wanted units it already holds.
	present := make([]bool, len(units))
	err = h.scanGroups(fd, func(g hookGroup) error {
		if g.rule != nil {
			for i, u := range units {
				if !present[i] && g.rule.Equal(u.rule, true) {
					present[i] = true
				}
			}
		}
		for _, l := range g.raw {
			_, _ = fmt.Fprintln(af, l)
		}
		return nil
	})
	if err != nil {
		return false, err
	}

	// Append the units the hook does not already hold, each under its script
	// comment. A rule that fans out is completed unit by unit, so a subset left
	// by a prior single-family add or a manual edit is filled in rather than
	// duplicated on every reconcile.
	changed := false
	comment := combineComment(h.rulePrefix, r.Comment)
	for i, u := range units {
		if present[i] {
			continue
		}
		if comment != "" {
			_, _ = fmt.Fprintln(af, "# "+comment)
		}
		for _, l := range u.lines {
			_, _ = fmt.Fprintln(af, l)
		}
		changed = true
	}
	if !changed {
		return false, nil
	}
	return true, h.commit(af)
}

// --- address sets (ipset commands in the hook) -----------------------------
//
// CSF and APF have no native address-set construct, so the library persists a
// set as `ipset` commands in the same hook that carries its raw iptables rules.
// The firewall sources the hook on every (re)start, so the ipset commands
// recreate the set before the `-m set --match-set` rule lines that follow can
// reference it — the set survives a reboot exactly as the hook's rules do. Every
// ipset line is kept ahead of every iptables/ip6tables line to preserve that
// ordering. Reading foreign, user-authored ipset lines is intended, as with
// rules: the library manages the actual hook state.

// ipsetLinesFor renders the hook lines that (re)create a set and load its
// entries: an idempotent create (-exist, so a reload does not fail on the
// existing set), a flush (so a reload drops entries removed since the last
// write, making the entry list declarative), then one add per entry.
func (h *hookScript) ipsetLinesFor(set *AddressSet) []string {
	fam := "inet"
	if set.Family == IPv6 {
		fam = "inet6"
	}
	cmd := h.ipsetCommand()
	lines := []string{
		fmt.Sprintf("%s create %s %s family %s -exist", cmd, set.Name, set.Type.String(), fam),
		fmt.Sprintf("%s flush %s", cmd, set.Name),
	}
	for _, e := range set.Entries {
		lines = append(lines, fmt.Sprintf("%s add %s %s", cmd, set.Name, e))
	}
	return lines
}

// hookIPSetName returns the set a hook ipset line operates on, or "" when the
// line is not one of the library's ipset commands. Every such line names the set
// in its third field (`ipset <verb> <name> ...`), whether the command is spelled
// bare or as a resolved path.
func hookIPSetName(line string) string {
	f := strings.Fields(line)
	if len(f) >= 3 && hookCmdIs(f[0], "ipset") {
		return f[2]
	}
	return ""
}

// cmdRefsSet reports whether a command line references name through an
// `-m set --match-set <name>` match, so a set is not removed out from under a
// rule that still uses it (the kernel enforces the same on a live destroy).
func cmdRefsSet(cmd, name string) bool {
	f := strings.Fields(cmd)
	for i := 0; i+1 < len(f); i++ {
		if f[i] == "--match-set" && f[i+1] == name {
			return true
		}
	}
	return false
}

// getAddressSets parses the sets the hook carries, in the order their create
// lines appear. An ipset is pinned to a single family, so each create yields one
// set and its add lines supply the entries; flush lines carry no state and are
// ignored. Add lines are applied after the scan so a hand-authored add above
// its create still counts.
func (h *hookScript) getAddressSets() ([]*AddressSet, error) {
	fd, err := os.Open(h.hookPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer func() { _ = fd.Close() }()
	// ipsetParseType is an IPTables method that ignores its receiver; a zero value
	// reuses the same create-line parser the iptables backend uses.
	ipt := &IPTables{}
	sets := map[string]*AddressSet{}
	var order []string
	var adds [][2]string
	scanner := bufio.NewScanner(fd)
	for scanner.Scan() {
		f := strings.Fields(scanner.Text())
		if len(f) < 4 || !hookCmdIs(f[0], "ipset") {
			continue
		}
		switch f[1] {
		case "create":
			// ipsetParseType scans a `create NAME <type> family <fam> ...` slice from
			// its third element, so drop the leading `ipset` word to line it up.
			fam, typ := ipt.ipsetParseType(f[1:])
			sets[f[2]] = &AddressSet{Name: f[2], Family: fam, Type: typ}
			order = append(order, f[2])
		case "add":
			// A hand-authored add may carry trailing options (`timeout 300`, `-exist`);
			// the entry itself is still the fourth field. Options are not modeled, so a
			// rewrite of the set's block re-emits the entry without them.
			adds = append(adds, [2]string{f[2], f[3]})
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	for _, a := range adds {
		if s, ok := sets[a[0]]; ok {
			s.Entries = append(s.Entries, a[1])
		}
	}
	out := make([]*AddressSet, 0, len(order))
	for _, n := range order {
		out = append(out, sets[n])
	}
	return out, nil
}

// editAddressSet writes or removes a set's ipset lines in the hook. Adding drops
// any prior lines for the set and reinserts its block ahead of the first
// iptables/ip6tables line, so the set exists before any rule matches it; the
// write is idempotent. Removing drops the set's lines but refuses when a hook
// rule still references it. Every other hook line — user shell, rules, other
// sets — streams through to the staged rewrite untouched; it reports whether
// the hook changed.
func (h *hookScript) editAddressSet(set *AddressSet, remove bool) (bool, error) {
	// hookIPSetName reports "" for every non-ipset line, so an unnamed set would
	// match — and the drop filter below would strip — every rule and user line in
	// the hook.
	if set.Name == "" {
		return false, fmt.Errorf("an address set requires a name")
	}
	// A missing hook scans as empty: an add creates it, a removal is a no-op.
	fd, err := os.Open(h.hookPath)
	if err != nil {
		if !os.IsNotExist(err) {
			return false, err
		}
		if remove {
			return false, nil
		}
	} else {
		defer func() { _ = fd.Close() }()
	}

	af, err := newAtomicFile(h.hookPath, h.hookPerm)
	if err != nil {
		return false, err
	}
	defer af.Abort()

	block := h.ipsetLinesFor(set)
	// pos counts the lines written so a no-op re-add can be recognized: the hook
	// is unchanged only when the dropped block was contiguous (every drop saw
	// the same pos), sat exactly at the reinsertion point, and matches the fresh
	// block line for line.
	pos := 0
	write := func(ls ...string) {
		for _, l := range ls {
			_, _ = fmt.Fprintln(af, l)
			pos++
		}
	}
	// A freshly created hook gets a shebang; the firewall sources it as shell.
	if fd == nil {
		write("#!/bin/sh")
	}
	var droppedLines []string
	firstDrop, contiguous := 0, true
	inserted := false
	insertPos := 0
	err = h.scanGroups(fd, func(g hookGroup) error {
		// Drop any existing lines for this set (idempotent re-add; also the
		// removal path). ipset lines are single-line groups, so every rule's
		// attached comment stays with its rule.
		if len(g.cmds) == 0 && hookIPSetName(g.raw[0]) == set.Name {
			if droppedLines == nil {
				firstDrop = pos
			} else if pos != firstDrop {
				contiguous = false
			}
			droppedLines = append(droppedLines, g.raw[0])
			return nil
		}
		if remove {
			for _, cmd := range g.cmds {
				if cmdRefsSet(cmd, set.Name) {
					return fmt.Errorf("address set %q is in use by a rule", set.Name)
				}
			}
		}
		// Insert the set's block ahead of the first command-line group — the
		// rule's attached comment included — keeping every ipset line before
		// every rule line.
		if !remove && !inserted && len(g.cmds) > 0 {
			insertPos = pos
			write(block...)
			inserted = true
		}
		write(g.raw...)
		return nil
	})
	if err != nil {
		return false, err
	}

	if remove {
		if droppedLines == nil {
			return false, nil
		}
		return true, h.commit(af)
	}
	// Append the block when the hook holds no command line to insert it ahead of.
	if !inserted {
		insertPos = pos
		write(block...)
	}
	if contiguous && insertPos == firstDrop && slices.Equal(droppedLines, block) {
		return false, nil
	}
	return true, h.commit(af)
}

// editAddressSetEntry adds or removes a single entry in an existing set by
// rewriting the set's block. The set must already exist in the hook.
func (h *hookScript) editAddressSetEntry(name, entry string, remove bool) (bool, error) {
	sets, err := h.getAddressSets()
	if err != nil {
		return false, err
	}
	var target *AddressSet
	for _, s := range sets {
		if s.Name == name {
			target = s
			break
		}
	}
	if target == nil {
		return false, fmt.Errorf("address set %q not found", name)
	}
	if remove {
		next := target.Entries[:0]
		found := false
		for _, e := range target.Entries {
			if e == entry {
				found = true
				continue
			}
			next = append(next, e)
		}
		if !found {
			return false, nil
		}
		target.Entries = next
	} else {
		for _, e := range target.Entries {
			if e == entry {
				return false, nil
			}
		}
		target.Entries = append(target.Entries, entry)
	}
	return h.editAddressSet(target, false)
}

// --- NAT rules (raw nat-table commands in the hook) --------------------------
//
// csf.redirect holds exactly two destination-NAT shapes, so every other NAT rule
// — source NAT, an interface-bound or source-matched translation, a port
// range/list — is injected as a raw `iptables -t nat` command through the same
// hook that carries the filter rules. csf flushes the v4 nat table on every
// (re)start whenever the kernel provides one (its Config.pm probes `-t nat -L
// POSTROUTING` and sets NAT=1) and sources the pre-hook afterwards, so the
// injected lines are applied exactly once per load; the v6 nat flush is guarded
// by IPV6, the same hazard the filterNATFamiliesIPv6 narrowing guards. APF
// reuses these same NAT methods, binding a hookScript to each of its shell-sourced
// routing files (preroute.rules for destination NAT, postroute.rules for source
// NAT) instead of a single pre-hook — the file differs, the mechanism does not.

// natLine encodes a family-concrete NAT rule row (an expandNATFamilies fan-out)
// as one raw nat-table command line. The prefix tag is not marshalled into the
// line — it rides as the script comment editNAT writes above it. Each
// marshalled line is re-tokenized and re-quoted shell-safely, as with
// linesForRows, because the hook is sourced by /bin/sh.
func (h *hookScript) natLine(r *NATRule) (string, error) {
	fam := r.impliedFamily()
	rc := *r
	rc.Family = fam
	ipt := &IPTables{}
	// As in linesForRows, the borrowed encoder takes its own check here.
	if err := rc.validate(); err != nil {
		return "", err
	}
	spec, err := ipt.MarshalNATRule(&rc)
	if err != nil {
		return "", err
	}
	tokens, err := shlex.Split(spec, true)
	if err != nil {
		return "", err
	}
	for i, t := range tokens {
		tokens[i] = shellSafeToken(t)
	}
	return h.command(fam) + " -t nat " + strings.Join(tokens, " "), nil
}

// parseNATLine decodes a raw nat command line back into the NATRule it
// represents, reporting whether the line is one this backend recognizes. The
// iptables NAT parser derives HasPrefix from a comment tag embedded in the line
// (a line written by an older library version); scanGroups additionally
// marks it from the script comment above the line, which is the form this
// library writes. A `-t nat` line never doubles as a filter rule: parseLine's
// chain check (INPUT/OUTPUT/FORWARD) rejects it, so the two line kinds stay
// disjoint in the same hook.
func (h *hookScript) parseNATLine(line string) (*NATRule, bool) {
	fam, args, ok := hookCmdFamily(line)
	if !ok {
		return nil, false
	}
	rest, ok := strings.CutPrefix(args, "-t nat ")
	if !ok {
		return nil, false
	}
	ipt := &IPTables{rulePrefix: h.rulePrefix}
	r, err := ipt.UnmarshalNATRule(rest, fam)
	if err != nil {
		return nil, false
	}
	return r, true
}

// getNATRules parses the raw nat-table rules the hook carries, each with its
// prefix flag resolved from the script comment above it or a tag embedded in
// the line. Every such line is returned, including any a user authored by hand,
// so the library reconciles the hook's real state.
func (h *hookScript) getNATRules() ([]*NATRule, error) {
	fd, err := os.Open(h.hookPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer func() { _ = fd.Close() }()
	var rules []*NATRule
	err = h.scanGroups(fd, func(g hookGroup) error {
		if g.nat != nil {
			rules = append(rules, g.nat)
		}
		return nil
	})
	return rules, err
}

// editNAT adds or removes a NAT rule's raw nat command line(s) in the hook,
// mirroring edit for filter rules: an add writes only the families the backend
// enforces and is satisfied by an equivalent existing line — the same
// translation under EqualForRemoval, which stays family-aware so a
// family-scoped edit leaves an opposite-family twin alone — while a removal
// sweeps both families, taking each dropped line's attached comment with it.
// Every other hook line is preserved; it reports whether the hook changed.
func (h *hookScript) editNAT(r *NATRule, remove bool) (bool, error) {
	// An add writes only the family rows the backend enforces; encode their lines
	// up front so a marshalling error stages nothing. A removal marshals nothing:
	// it matches scanned lines through EqualForRemoval, whose family-covering
	// check already sweeps both families' lines for a family-agnostic rule.
	var rows []*NATRule
	var famLines []string
	if !remove {
		rows = filterNATFamiliesIPv6(h.ipv6Enabled, r)
		famLines = make([]string, len(rows))
		for i, row := range rows {
			line, err := h.natLine(row)
			if err != nil {
				return false, err
			}
			famLines[i] = line
		}
	}

	// A missing hook scans as empty: an add creates it, a removal is a no-op.
	fd, err := os.Open(h.hookPath)
	if err != nil {
		if !os.IsNotExist(err) {
			return false, err
		}
		if remove {
			return false, nil
		}
	} else {
		defer func() { _ = fd.Close() }()
	}

	af, err := newAtomicFile(h.hookPath, h.hookPerm)
	if err != nil {
		return false, err
	}
	defer af.Abort()
	// A freshly created hook gets a shebang; the firewall sources it as shell.
	if fd == nil {
		_, _ = fmt.Fprintln(af, "#!/bin/sh")
	}

	if remove {
		changed := false
		err = h.scanGroups(fd, func(g hookGroup) error {
			if g.nat != nil && g.nat.EqualForRemoval(r) {
				changed = true
				return nil
			}
			for _, l := range g.raw {
				_, _ = fmt.Fprintln(af, l)
			}
			return nil
		})
		if err != nil {
			return false, err
		}
		if !changed {
			return false, nil
		}
		return true, h.commit(af)
	}

	// Copy the hook through, noting which family rows it already holds.
	present := make([]bool, len(rows))
	err = h.scanGroups(fd, func(g hookGroup) error {
		if g.nat != nil && g.nat.EqualForRemoval(r) {
			for i, row := range rows {
				if g.nat.impliedFamily() == row.impliedFamily() {
					present[i] = true
				}
			}
		}
		for _, l := range g.raw {
			_, _ = fmt.Fprintln(af, l)
		}
		return nil
	})
	if err != nil {
		return false, err
	}

	// Append the family lines the hook does not already hold, each under the
	// prefix-tag script comment (a NAT rule carries no user comment of its own).
	changed := false
	for i := range rows {
		if present[i] {
			continue
		}
		if h.rulePrefix != "" {
			_, _ = fmt.Fprintln(af, "# "+h.rulePrefix)
		}
		_, _ = fmt.Fprintln(af, famLines[i])
		changed = true
	}
	if !changed {
		return false, nil
	}
	return true, h.commit(af)
}
