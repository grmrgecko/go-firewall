package main

import (
	"context"
	"fmt"
	"os"

	fw "github.com/grmrgecko/go-firewall"
)

// This file holds the rule command group: list, add, remove, insert, move.
// ruleFlags is a shared struct embedded by add/remove/insert/move so that the
// Rule field set is described once and stays in sync with the library's Rule.

// RuleCmd is the top-level "rule" command group. It only has subcommands of its
// own; running it bare prints help.
type RuleCmd struct {
	List   RuleListCmd   `cmd:"" help:"List filter rules (default)."`
	Add    RuleAddCmd    `cmd:"" help:"Add a filter rule."`
	Remove RuleRemoveCmd `cmd:"" help:"Remove a filter rule matching the given fields."`
	Insert RuleInsertCmd `cmd:"" help:"Insert a filter rule at a 1-based position."`
	Move   RuleMoveCmd   `cmd:"" help:"Move an existing filter rule to a 1-based position."`
}

// RuleListCmd lists every filter rule in a zone. The PREFIX column reports which
// rules carry the configured prefix (HasPrefix); filtering is left to the caller
// rather than hidden here.
type RuleListCmd struct {
	zoneMixin
}

// Run lists the filter rules in the resolved zone.
func (c *RuleListCmd) Run(g *Globals) error {
	mgr, cleanup, err := g.manager()
	if err != nil {
		return err
	}
	defer cleanup()

	zone, err := resolveZone(mgr, c.Zone, c.Interface)
	if err != nil {
		return err
	}
	rules, err := mgr.GetRules(context.Background(), zone)
	if err != nil {
		return fmt.Errorf("listing rules: %w", err)
	}
	return g.emit(rules, func() error {
		if len(rules) == 0 {
			fmt.Println("(no rules)")
			return nil
		}
		printRules(os.Stdout, rules)
		return nil
	})
}

// ruleFlags carries every fw.Rule field that add/remove/insert/move accept. It
// is embedded by each so the flag surface is identical across them (the match
// key for remove equals the spec for add). Field-for-field mapping of the
// library's Rule struct, minus the read-only counters.
type ruleFlags struct {
	// Direction.
	Output  bool `name:"out" help:"Outbound (output) rule. Default is inbound (input)."`
	Forward bool `name:"forward" help:"Forward (routing) rule, for traffic routed through the host. Mutually exclusive with --out."`
	Both    bool `name:"both" help:"Both directions (input and output). The address/port roles swap on the outbound half. Mutually exclusive with --out/--forward."`

	// Match: addresses, protocol, ports.
	Action      string `name:"action" short:"a" help:"accept|reject|drop (default accept)." default:"accept"`
	Family      string `name:"family" short:"f" help:"any|ipv4|ipv6 (default any)." default:"any"`
	Proto       string `name:"proto" help:"any|tcp|udp|icmp|icmpv6|sctp|gre|esp|ah (default any)." default:"any"`
	Source      string `name:"source" short:"s" help:"Source address/CIDR. Prefix '!' to negate where supported."`
	Destination string `name:"destination" short:"d" help:"Destination address/CIDR. Prefix '!' to negate where supported."`
	Port        uint16 `name:"port" short:"p" help:"Destination port (single). Requires tcp/udp/sctp."`
	Ports       string `name:"ports" help:"Destination port list/ranges, e.g. \"80,443,1000-2000\". Overrides --port."`
	SourcePort  uint16 `name:"source-port" help:"Source port (single). Requires tcp/udp/sctp."`
	SourcePorts string `name:"source-ports" help:"Source port list/ranges. Overrides --source-port."`
	ICMPType    string `name:"icmp-type" help:"ICMP type (number or name like echo-request). Requires icmp/icmpv6."`

	// Modifiers.
	State        string `name:"state" help:"Connection states to match, comma-joined: new,established,related,invalid."`
	InInterface  string `name:"in-interface" help:"Inbound interface to match (input rules)."`
	OutInterface string `name:"out-interface" help:"Outbound interface to match (output rules)."`
	Log          bool   `name:"log" help:"Log matched packets before the action."`
	LogPrefix    string `name:"log-prefix" help:"Label attached to log lines (where supported)."`
	RateLimit    string `name:"rate-limit" help:"Rate cap as <rate>/<unit> (e.g. 10/minute). Implies a logged drop on overflow."`
	RateBurst    uint   `name:"rate-burst" help:"Burst allowance for --rate-limit."`
	ConnLimit    uint   `name:"conn-limit" help:"Cap concurrent connections."`
	ConnPerSrc   bool   `name:"conn-per-source" help:"Apply --conn-limit per source address."`
	Priority     int    `name:"priority" help:"Rule priority (where the backend supports it, e.g. firewalld rich rules)."`
	Comment      string `name:"comment" short:"c" help:"Human-readable label carried where supported (see 'status')."`
}

// btoi returns 1 for true and 0 for false, so exclusive boolean flags can be
// counted.
func btoi(b bool) int {
	if b {
		return 1
	}
	return 0
}

// toRule assembles the ruleFlags into a *fw.Rule, parsing and validating the
// string-typed flags via the library's own Parse* helpers so the CLI never
// reinvents rule semantics. Returns an error for a malformed flag rather than a
// silent default.
func (f *ruleFlags) toRule() (*fw.Rule, error) {
	action, err := fw.ParseAction(f.Action)
	if err != nil {
		return nil, err
	}
	family, err := fw.ParseFamily(f.Family)
	if err != nil {
		return nil, err
	}
	proto, err := parseProto(f.Proto)
	if err != nil {
		return nil, err
	}
	if btoi(f.Output)+btoi(f.Forward)+btoi(f.Both) > 1 {
		return nil, fmt.Errorf("--out, --forward and --both are mutually exclusive")
	}
	direction := fw.DirInput
	switch {
	case f.Forward:
		direction = fw.DirForward
	case f.Both:
		direction = fw.DirAny
	case f.Output:
		direction = fw.DirOutput
	}
	// Interface matches are direction-specific: an inbound interface is invalid on
	// an output rule and an outbound interface on an input rule; a forward or
	// both-directions rule may match either (a DirAny rule's interfaces swap sides
	// on its outbound half).
	if direction == fw.DirOutput && f.InInterface != "" {
		return nil, fmt.Errorf("--in-interface is only valid on an inbound, forward or both-directions rule (omit --out)")
	}
	if direction == fw.DirInput && f.OutInterface != "" {
		return nil, fmt.Errorf("--out-interface is only valid on an outbound, forward or both-directions rule (--out, --forward or --both)")
	}
	rule := &fw.Rule{
		Direction:    direction,
		Priority:     f.Priority,
		Action:       action,
		Family:       family,
		Source:       f.Source,
		Destination:  f.Destination,
		Port:         f.Port,
		SourcePort:   f.SourcePort,
		Proto:        proto,
		InInterface:  f.InInterface,
		OutInterface: f.OutInterface,
		Log:          f.Log,
		LogPrefix:    f.LogPrefix,
		Comment:      f.Comment,
	}
	if f.Ports != "" {
		ranges, err := fw.ParsePortRanges(f.Ports, ",")
		if err != nil {
			return nil, err
		}
		rule.Ports = ranges
	}
	if f.SourcePorts != "" {
		ranges, err := fw.ParsePortRanges(f.SourcePorts, ",")
		if err != nil {
			return nil, err
		}
		rule.SourcePorts = ranges
	}
	if f.ICMPType != "" {
		t, ok := fw.ParseICMPType(f.ICMPType, rule.Proto == fw.ICMPv6)
		if !ok {
			return nil, fmt.Errorf("unknown icmp type %q", f.ICMPType)
		}
		rule.ICMPType = fw.Ptr[uint8](t)
	}
	if f.State != "" {
		state, err := fw.ParseConnState(f.State)
		if err != nil {
			return nil, err
		}
		rule.State = state
	}
	if f.RateLimit != "" {
		rate, unit, err := parseRateToken(f.RateLimit)
		if err != nil {
			return nil, err
		}
		rule.RateLimit = &fw.RateLimit{Rate: rate, Unit: unit, Burst: f.RateBurst}
	}
	if f.ConnLimit != 0 {
		rule.ConnLimit = &fw.ConnLimit{Count: f.ConnLimit, PerSource: f.ConnPerSrc}
	}
	return rule, nil
}

// zoneMixin is shared by list/add/remove/insert/move: they all optionally target
// a zone, defaulting to the backend's default zone when neither is given. An
// explicit --zone wins; --interface is resolved only when --zone is empty.
type zoneMixin struct {
	Zone      string `name:"zone" short:"z" help:"Zone name (firewalld) or empty for the default. Takes precedence over --interface."`
	Interface string `name:"interface" short:"i" help:"Resolve the zone for this interface. Used only when --zone is empty."`
}

// RuleAddCmd adds a filter rule.
type RuleAddCmd struct {
	zoneMixin
	ruleFlags
}

// Run validates the flags and adds the filter rule.
func (c *RuleAddCmd) Run(g *Globals) error {
	// Validate the rule spec before touching the firewall: a malformed flag
	// (bad action, family, port range, ...) should fail fast here rather
	// than after a backend connection has been opened.
	rule, err := c.toRule()
	if err != nil {
		return err
	}
	mgr, cleanup, err := g.manager()
	if err != nil {
		return err
	}
	defer cleanup()

	zone, err := resolveZone(mgr, c.Zone, c.Interface)
	if err != nil {
		return err
	}
	if err := mgr.AddRule(context.Background(), zone, rule); err != nil {
		return fmt.Errorf("add rule: %w", err)
	}
	if err := g.reload(mgr); err != nil {
		return fmt.Errorf("reload: %w", err)
	}
	return g.emitStatus("added")
}

// RuleRemoveCmd removes a filter rule. The flags describe the rule to match
// (identity is rule.Equal, so counters and comment are ignored).
type RuleRemoveCmd struct {
	zoneMixin
	ruleFlags
}

// Run removes the filter rule matching the given flags.
func (c *RuleRemoveCmd) Run(g *Globals) error {
	rule, err := c.toRule()
	if err != nil {
		return err
	}
	mgr, cleanup, err := g.manager()
	if err != nil {
		return err
	}
	defer cleanup()

	zone, err := resolveZone(mgr, c.Zone, c.Interface)
	if err != nil {
		return err
	}
	if err := mgr.RemoveRule(context.Background(), zone, rule); err != nil {
		return fmt.Errorf("remove rule: %w", err)
	}
	if err := g.reload(mgr); err != nil {
		return fmt.Errorf("reload: %w", err)
	}
	return g.emitStatus("removed")
}

// RuleInsertCmd inserts a filter rule at a 1-based position (1 = first; a
// position past the end appends). Only ordered backends support this.
type RuleInsertCmd struct {
	zoneMixin
	Position int `arg:"" name:"position" help:"1-based position to insert at (1 = first; past the end appends)."`
	ruleFlags
}

// Run inserts the filter rule at the requested 1-based position.
func (c *RuleInsertCmd) Run(g *Globals) error {
	rule, err := c.toRule()
	if err != nil {
		return err
	}
	mgr, cleanup, err := g.manager()
	if err != nil {
		return err
	}
	defer cleanup()

	zone, err := resolveZone(mgr, c.Zone, c.Interface)
	if err != nil {
		return err
	}
	if err := mgr.InsertRule(context.Background(), zone, c.Position, rule); err != nil {
		return fmt.Errorf("insert rule: %w", err)
	}
	if err := g.reload(mgr); err != nil {
		return fmt.Errorf("reload: %w", err)
	}
	return g.emitStatus("inserted")
}

// RuleMoveCmd moves an existing rule to a new 1-based position. The flags
// describe the rule to move (matched by identity).
type RuleMoveCmd struct {
	zoneMixin
	Position int `arg:"" name:"position" help:"1-based position to move the rule to."`
	ruleFlags
}

// Run moves the matched filter rule to the requested 1-based position.
func (c *RuleMoveCmd) Run(g *Globals) error {
	rule, err := c.toRule()
	if err != nil {
		return err
	}
	mgr, cleanup, err := g.manager()
	if err != nil {
		return err
	}
	defer cleanup()

	zone, err := resolveZone(mgr, c.Zone, c.Interface)
	if err != nil {
		return err
	}
	if err := mgr.MoveRule(context.Background(), zone, rule, c.Position); err != nil {
		return fmt.Errorf("move rule: %w", err)
	}
	if err := g.reload(mgr); err != nil {
		return fmt.Errorf("reload: %w", err)
	}
	return g.emitStatus("moved")
}

// resolveZone picks the zone to operate on: an explicit --zone wins, otherwise
// the zone for --interface is resolved (which is empty on zoneless backends,
// which is correct), otherwise the empty default.
func resolveZone(mgr fw.Manager, zone, iface string) (string, error) {
	if zone != "" {
		return zone, nil
	}
	if iface != "" {
		return mgr.GetZone(context.Background(), iface)
	}
	return "", nil
}
