package main

import (
	"fmt"
	"io"
	"strconv"
	"strings"

	fw "github.com/grmrgecko/go-firewall"
)

// This file holds the human-readable renderers for the library's data types.
// They have no side effects, which keeps them easy to unit-test and reuse
// across the list subcommands. The --json path serializes the structs directly
// (they already carry stable JSON via backup.go), so only the text path needs
// bespoke formatting.

// describeRule renders a *fw.Rule as a compact, single-line summary suitable
// for a table cell. The order is deliberately familiar: direction, action,
// proto, addresses, ports, then the optional modifiers (state, interface,
// limits, counters, comment).
func describeRule(r *fw.Rule) string {
	var b strings.Builder

	// Direction.
	switch r.Direction {
	case fw.DirOutput:
		b.WriteString("out")
	case fw.DirForward:
		b.WriteString("fwd")
	case fw.DirAny:
		b.WriteString("any")
	default:
		b.WriteString("in")
	}
	// Action.
	b.WriteByte(' ')
	b.WriteString(r.Action.String())
	// Family (skip "any" to reduce noise; a concrete family still prints).
	if r.Family != fw.FamilyAny {
		b.WriteByte(' ')
		b.WriteString(r.Family.String())
	}
	// Protocol.
	b.WriteByte(' ')
	if r.Proto == fw.ProtocolAny {
		b.WriteString("any")
	} else {
		b.WriteString(r.Proto.String())
	}
	// Source/destination.
	if r.Source != "" {
		b.WriteString(" from ")
		b.WriteString(r.Source)
	}
	if r.Destination != "" {
		b.WriteString(" to ")
		b.WriteString(r.Destination)
	}
	// Ports.
	if ports := r.PortSpecs(); len(ports) > 0 {
		b.WriteString(" port ")
		b.WriteString(fw.FormatPortRanges(ports, ","))
	}
	if sports := r.SourcePortSpecs(); len(sports) > 0 {
		b.WriteString(" sport ")
		b.WriteString(fw.FormatPortRanges(sports, ","))
	}
	// ICMP type (only meaningful for ICMP/ICMPv6).
	if r.ICMPType != nil && r.Proto.IsICMP() {
		b.WriteString(" type ")
		b.WriteString(strconv.FormatUint(uint64(*r.ICMPType), 10))
	}
	// Connection-tracking state.
	if r.State != 0 {
		b.WriteString(" state=")
		b.WriteString(r.State.String())
	}
	// Interface(s): an input rule carries only an in-interface, an output rule only
	// an out-interface, a forward rule may carry both — print whichever are set.
	if r.InInterface != "" {
		b.WriteString(" iif=")
		b.WriteString(r.InInterface)
	}
	if r.OutInterface != "" {
		b.WriteString(" oif=")
		b.WriteString(r.OutInterface)
	}
	// Logging.
	if r.Log {
		b.WriteString(" log")
		if r.LogPrefix != "" {
			b.WriteByte('=')
			b.WriteString(r.LogPrefix)
		}
	}
	// Rate / connection limits.
	if r.RateLimit != nil {
		b.WriteString(" rate=")
		b.WriteString(r.RateLimit.String())
		if r.RateLimit.Burst != 0 {
			b.WriteString("/burst=")
			b.WriteString(strconv.FormatUint(uint64(r.RateLimit.Burst), 10))
		}
	}
	if r.ConnLimit != nil {
		b.WriteString(" conn=")
		b.WriteString(strconv.FormatUint(uint64(r.ConnLimit.Count), 10))
		if r.ConnLimit.PerSource {
			b.WriteString("/src")
		}
	}
	// Priority (only when nonzero and thus meaningful).
	if r.Priority != 0 {
		b.WriteString(" prio=")
		b.WriteString(strconv.Itoa(r.Priority))
	}
	// Comment (informational).
	if r.Comment != "" {
		b.WriteString(" # ")
		b.WriteString(r.Comment)
	}
	return b.String()
}

// describeNATRule renders a NAT rule as a compact single-line summary.
func describeNATRule(r *fw.NATRule) string {
	var b strings.Builder
	b.WriteString(r.Kind.String())
	if r.Family != fw.FamilyAny {
		b.WriteByte(' ')
		b.WriteString(r.Family.String())
	}
	b.WriteByte(' ')
	if r.Proto == fw.ProtocolAny {
		b.WriteString("any")
	} else {
		b.WriteString(r.Proto.String())
	}
	if r.Interface != "" {
		b.WriteString(" if=")
		b.WriteString(r.Interface)
	}
	if r.Source != "" {
		b.WriteString(" from ")
		b.WriteString(r.Source)
	}
	if r.Destination != "" {
		b.WriteString(" to ")
		b.WriteString(r.Destination)
	}
	if ports := r.PortSpecs(); len(ports) > 0 {
		b.WriteString(" port ")
		b.WriteString(fw.FormatPortRanges(ports, ","))
	}
	// Translation target.
	switch r.Kind {
	case fw.DNAT:
		b.WriteString(" -> ")
		b.WriteString(r.ToAddress)
		if r.ToPort != 0 {
			b.WriteByte(':')
			b.WriteString(strconv.FormatUint(uint64(r.ToPort), 10))
		}
	case fw.Redirect:
		b.WriteString(" -> ")
		b.WriteString(strconv.FormatUint(uint64(r.ToPort), 10))
	case fw.SNAT:
		b.WriteString(" -> ")
		b.WriteString(r.ToAddress)
	case fw.Masquerade:
		b.WriteString(" (dynamic)")
	}
	return b.String()
}

// printRules writes a rule list to w as a numbered table. The index is the
// 1-based position returned by GetRules, which is what RemoveRule/MoveRule
// refer to (since those methods match by rule identity, not index, the index is
// informational — it just helps the user pick the right line).
func printRules(w io.Writer, rules []*fw.Rule) {
	tw := newTable(w)
	defer func() { _ = tw.Flush() }()
	_, _ = fmt.Fprintln(tw, "#\tPREFIX\tACTION\tDESCRIPTION")
	for i, r := range rules {
		_, _ = fmt.Fprintf(tw, "%d\t%s\t%s\t%s\n", i+1, hasPrefixFlag(r.HasPrefix), r.Action.String(), describeRule(r))
	}
}

// printNATRules writes a NAT rule list to w as a numbered table.
func printNATRules(w io.Writer, rules []*fw.NATRule) {
	tw := newTable(w)
	defer func() { _ = tw.Flush() }()
	_, _ = fmt.Fprintln(tw, "#\tPREFIX\tKIND\tDESCRIPTION")
	for i, r := range rules {
		_, _ = fmt.Fprintf(tw, "%d\t%s\t%s\t%s\n", i+1, hasPrefixFlag(r.HasPrefix), r.Kind.String(), describeNATRule(r))
	}
}

// hasPrefixFlag renders whether a rule carries the configured prefix, for the
// PREFIX column of a rule listing.
func hasPrefixFlag(hasPrefix bool) string {
	if hasPrefix {
		return "yes"
	}
	return "no"
}

// setType renders an address set's type, defaulting the zero value to hash:ip
// the way the library does when a set is created without an explicit type.
func setType(s *fw.AddressSet) string {
	if s.Type == 0 {
		return fw.SetHashIP.String()
	}
	return s.Type.String()
}

// printSet writes one address set's header line followed by its entries, one per
// line. An empty set prints "(no entries)" so the output is never ambiguous.
func printSet(w io.Writer, s *fw.AddressSet) {
	_, _ = fmt.Fprintf(w, "%s  family=%s  type=%s  entries=%d\n", s.Name, s.Family.String(), setType(s), len(s.Entries))
	if len(s.Entries) == 0 {
		_, _ = fmt.Fprintln(w, "  (no entries)")
		return
	}
	for _, e := range s.Entries {
		_, _ = fmt.Fprintf(w, "  %s\n", e)
	}
}

// printSets writes an address-set list to w as a table.
func printSets(w io.Writer, sets []*fw.AddressSet) {
	tw := newTable(w)
	defer func() { _ = tw.Flush() }()
	_, _ = fmt.Fprintln(tw, "NAME\tFAMILY\tTYPE\tENTRIES")
	for _, s := range sets {
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%d\n", s.Name, s.Family.String(), setType(s), len(s.Entries))
	}
}
