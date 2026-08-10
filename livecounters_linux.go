package firewall

import (
	"context"
	"strings"
)

// Live packet/byte counters for the backends that store their rules in files but
// enforce them through iptables — iptables itself, ufw, csf and apf. The files
// carry no counts, so the counts have to come from the running ruleset, and the
// rows there are whatever the product generates for a rule rather than the rule
// itself. Each backend supplies the decode step that turns one of its rows back
// into the rule it stands for — for iptables that is the identity, for the others
// it undoes the product's own framing; the reading, the run handling and the
// matching below are the same for all four.
//
// Counters are informational (Capabilities().RuleCounters) and never part of
// rule identity, so everything here is best-effort: a missing save binary, a row
// this model cannot hold, or a rule the running ruleset does not carry simply
// leaves that rule's counters zero.

// liveRow is one counter-annotated `iptables-save -c` rule line, split into the
// parts a backend needs to decide what rule it stands for.
type liveRow struct {
	// chain is the chain the line appends to.
	chain string
	// fields is the whole line split on whitespace, counter token first. It is
	// for inspection only: a quoted log prefix does not survive the split, so
	// rewrites operate on line.
	fields []string
	// line is the line verbatim, counter token included.
	line string
	// newChain reports whether this row opens a chain, so a decoder holding
	// state across adjacent rows knows to drop it.
	newChain bool
}

// liveSaveLines reads the live filter table for a family with counters attached.
// A missing or failing save binary yields no lines rather than an error, since a
// backend that cannot read counters still reports its rules.
func liveSaveLines(ctx context.Context, fam Family) []string {
	cmd := "iptables-save"
	if fam == IPv6 {
		cmd = "ip6tables-save"
	}
	out, err := runCommand(ctx, cmd, "-c", "-t", "filter")
	if err != nil {
		return nil
	}
	return out
}

// jumpTarget returns the target of a rulespec's `-j`/`--jump` option, or the
// empty string when the line carries none.
func jumpTarget(fields []string) string {
	for i, tok := range fields {
		if tok == "-j" || tok == "--jump" {
			if i+1 < len(fields) {
				return fields[i+1]
			}
			return ""
		}
	}
	return ""
}

// parseLiveRow reparses a live row as a rule in the direction its chain stands
// for. It rewrites the product's chain to the INPUT/OUTPUT/FORWARD equivalent
// and reuses the iptables rulespec parser, which also lifts the [pkts:bytes]
// prefix onto the rule. A row the model cannot hold is rejected.
func parseLiveRow(row liveRow, dir Direction, fam Family) (*Rule, bool) {
	spec := strings.Replace(row.line, row.fields[1]+" "+row.chain,
		row.fields[1]+" "+iptChainForDirection(dir), 1)
	r, err := unmarshalIPTablesRule(spec, fam)
	if err != nil {
		return nil, false
	}
	return r, true
}

// decodeLiveRows decodes counter-annotated `iptables-save -c` output into the
// rules a backend's chains hold. decode turns one row into the rule it stands
// for and reports false for a row that stands for no rule of its own — a chain
// the backend does not surface, or one line of a multi-line expansion.
//
// A LOG line and the action line beneath it are one logical rule, but only while
// they stay physically adjacent, so a row decode rejects ends the current run
// and that run is coalesced on its own.
func decodeLiveRows(out []string, decode func(row liveRow) (*Rule, bool)) []*Rule {
	var rules, run []*Rule
	flush := func() {
		if len(run) > 0 {
			rules = append(rules, coalesceLoggedRules(run)...)
			run = nil
		}
	}

	chain := ""
	for _, line := range out {
		line = strings.TrimSpace(line)
		// Only the counter-annotated rule lines carry a rule; the table and chain
		// headers do not.
		if !strings.HasPrefix(line, "[") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 4 || (fields[1] != "-A" && fields[1] != "--append") {
			continue
		}

		row := liveRow{chain: fields[2], fields: fields, line: line}
		if row.chain != chain {
			flush()
			chain, row.newChain = row.chain, true
		}
		r, ok := decode(row)
		if !ok {
			flush()
			continue
		}
		run = append(run, r)
	}
	flush()
	return rules
}

// applyLiveCounters attaches each live row's counters to the rule it belongs to
// and returns the rows no rule claimed. Every live row is consumed at most once,
// so duplicate rules keep distinct counts, and a rule with no live counterpart —
// an edit not yet activated by Reload, or one the backend stores but has not
// loaded — keeps zero counters. The leftovers are for a backend that has to
// claim a row on something other than rule identity (see CSF.claimDenyOutRows).
func applyLiveCounters(targets, live []*Rule) []*Rule {
	if len(targets) == 0 || len(live) == 0 {
		return live
	}

	// Match on identity first, so a rule that has a row of its own never absorbs a
	// wider neighbour's count.
	used := make([]bool, len(live))
	matched := make([]bool, len(targets))
	for ri, r := range targets {
		for i, l := range live {
			if used[i] || !l.Equal(r, true) {
				continue
			}
			r.Packets, r.Bytes = l.Packets, l.Bytes
			used[i], matched[ri] = true, true
			break
		}
	}

	// Then sum the rows a wider rule spans: a rule that covers more than one
	// family, transport or direction is written as one row per cell, so its count
	// is their total.
	for ri, r := range targets {
		if matched[ri] {
			continue
		}
		for i, l := range live {
			if used[i] || !r.Covers(l) {
				continue
			}
			r.Packets += l.Packets
			r.Bytes += l.Bytes
			used[i] = true
		}
	}

	var leftover []*Rule
	for i, l := range live {
		if !used[i] {
			leftover = append(leftover, l)
		}
	}
	return leftover
}

// countableRules returns the rules a family's live ruleset can account for: the
// ones pinned to that family, plus the family-agnostic ones. A backend that
// stores a rule dual-stack (apf's port lists, a family-agnostic hook line)
// reports it as one FamilyAny rule that both families' rulesets hold a row for,
// so it is offered to each and its counters accumulate across the two.
func countableRules(rules []*Rule, fam Family) []*Rule {
	var out []*Rule
	for _, r := range rules {
		if r != nil && (r.Family == fam || r.Family == FamilyAny) {
			out = append(out, r)
		}
	}
	return out
}
