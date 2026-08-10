package main

import (
	"context"
	"fmt"
	"os"

	fw "github.com/grmrgecko/go-firewall"
)

// This file holds the NAT command group: list, add, insert, move, remove. NAT
// rules are managed separately from filter rules in the library, so they get
// their own subcommand group here too.

// NATCmd is the top-level "nat" command group.
type NATCmd struct {
	List   NATListCmd   `cmd:"" help:"List NAT rules (default)."`
	Add    NATAddCmd    `cmd:"" help:"Add a NAT rule (port-forward/masquerade)."`
	Insert NATInsertCmd `cmd:"" help:"Insert a NAT rule at a 1-based position within its nat chain."`
	Move   NATMoveCmd   `cmd:"" help:"Move a NAT rule to a new 1-based position within its nat chain."`
	Remove NATRemoveCmd `cmd:"" help:"Remove a NAT rule matching the given fields."`
}

// NATListCmd lists every NAT rule in a zone. The PREFIX column reports which rules
// carry the configured prefix (HasPrefix); filtering is left to the caller rather
// than hidden here.
type NATListCmd struct {
	Zone      string `name:"zone" short:"z" help:"Zone name or empty for the default."`
	Interface string `name:"interface" short:"i" help:"Resolve the zone for this interface."`
}

// Run lists the NAT rules in the resolved zone.
func (c *NATListCmd) Run(g *Globals) error {
	mgr, cleanup, err := g.manager()
	if err != nil {
		return err
	}
	defer cleanup()

	zone, err := resolveZone(mgr, c.Zone, c.Interface)
	if err != nil {
		return err
	}
	rules, err := mgr.GetNATRules(context.Background(), zone)
	if err != nil {
		return fmt.Errorf("listing NAT rules: %w", err)
	}
	return g.emit(rules, func() error {
		if len(rules) == 0 {
			fmt.Println("(no NAT rules)")
			return nil
		}
		printNATRules(os.Stdout, rules)
		return nil
	})
}

// natFlags carries every fw.NATRule field that add/remove accept.
type natFlags struct {
	Kind   string `name:"kind" short:"k" help:"dnat|redirect|snat|masquerade." default:"dnat"`
	Family string `name:"family" short:"f" help:"any|ipv4|ipv6 (default any)." default:"any"`
	Proto  string `name:"proto" help:"any|tcp|udp|icmp|icmpv6|sctp|gre|esp|ah (default any)." default:"any"`
	If     string `name:"nat-interface" help:"Inbound interface for dnat/redirect; outbound for snat/masquerade."`
	Source string `name:"source" short:"s" help:"Source address/CIDR."`
	Dest   string `name:"destination" short:"d" help:"Destination address/CIDR."`
	Port   uint16 `name:"port" short:"p" help:"Matched destination port. Requires tcp/udp."`
	Ports  string `name:"ports" help:"Matched port list/ranges. Overrides --port."`
	ToAddr string `name:"to-address" help:"Translation address (dnat/snat). Empty for redirect/masquerade."`
	ToPort uint16 `name:"to-port" help:"Translation port (dnat/redirect). Unused for snat/masquerade."`
}

// toNATRule assembles natFlags into a *fw.NATRule using the library's Parse*
// helpers. Validation (e.g. dnat requires an address) is delegated to the
// library's NATRule.validate, called by each backend before marshaling.
func (f *natFlags) toNATRule() (*fw.NATRule, error) {
	kind, err := fw.ParseNATKind(f.Kind)
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
	r := &fw.NATRule{
		Kind:        kind,
		Family:      family,
		Proto:       proto,
		Interface:   f.If,
		Source:      f.Source,
		Destination: f.Dest,
		Port:        f.Port,
		ToAddress:   f.ToAddr,
		ToPort:      f.ToPort,
	}
	if f.Ports != "" {
		ranges, err := fw.ParsePortRanges(f.Ports, ",")
		if err != nil {
			return nil, err
		}
		r.Ports = ranges
	}
	// A redirect sends matched traffic to a local port, so it needs a port-bearing
	// protocol and a concrete destination port. Reject the ambiguous defaults here
	// rather than deferring to the backend.
	if kind == fw.Redirect {
		if !proto.HasPorts() {
			return nil, fmt.Errorf("redirect requires a port-bearing protocol (tcp, udp or sctp)")
		}
		if r.ToPort == 0 {
			return nil, fmt.Errorf("redirect requires --to-port")
		}
	}
	return r, nil
}

// NATAddCmd adds a NAT rule.
type NATAddCmd struct {
	Zone      string `name:"zone" short:"z" help:"Zone name or empty for the default."`
	Interface string `name:"interface" short:"i" help:"Resolve the zone for this interface."`
	natFlags
}

// Run validates the flags and adds the NAT rule.
func (c *NATAddCmd) Run(g *Globals) error {
	rule, err := c.toNATRule()
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
	if err := mgr.AddNATRule(context.Background(), zone, rule); err != nil {
		return fmt.Errorf("add NAT rule: %w", err)
	}
	if err := g.reload(mgr); err != nil {
		return fmt.Errorf("reload: %w", err)
	}
	return g.emitStatus("added")
}

// NATInsertCmd inserts a NAT rule at a 1-based position within its nat chain
// (1 = first; a position past the end appends). Only ordered backends support
// this; others return an unsupported-ordering error.
type NATInsertCmd struct {
	Zone      string `name:"zone" short:"z" help:"Zone name or empty for the default."`
	Interface string `name:"interface" short:"i" help:"Resolve the zone for this interface."`
	Position  int    `arg:"" name:"position" help:"1-based position to insert at (1 = first; past the end appends)."`
	natFlags
}

// Run inserts the NAT rule at the requested 1-based position.
func (c *NATInsertCmd) Run(g *Globals) error {
	rule, err := c.toNATRule()
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
	if err := mgr.InsertNATRule(context.Background(), zone, c.Position, rule); err != nil {
		return fmt.Errorf("insert NAT rule: %w", err)
	}
	if err := g.reload(mgr); err != nil {
		return fmt.Errorf("reload: %w", err)
	}
	return g.emitStatus("inserted")
}

// NATMoveCmd moves an existing NAT rule to a new 1-based position within its nat
// chain (1 = first; a position past the end moves the rule to the end). The
// flags describe the rule to move (matched by identity). Only ordered backends
// support this; others return an unsupported-ordering error.
type NATMoveCmd struct {
	Zone      string `name:"zone" short:"z" help:"Zone name or empty for the default."`
	Interface string `name:"interface" short:"i" help:"Resolve the zone for this interface."`
	Position  int    `arg:"" name:"position" help:"1-based position to move the rule to."`
	natFlags
}

// Run moves the matched NAT rule to the requested 1-based position.
func (c *NATMoveCmd) Run(g *Globals) error {
	rule, err := c.toNATRule()
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
	if err := mgr.MoveNATRule(context.Background(), zone, rule, c.Position); err != nil {
		return fmt.Errorf("move NAT rule: %w", err)
	}
	if err := g.reload(mgr); err != nil {
		return fmt.Errorf("reload: %w", err)
	}
	return g.emitStatus("moved")
}

// NATRemoveCmd removes a NAT rule matched by identity.
type NATRemoveCmd struct {
	Zone      string `name:"zone" short:"z" help:"Zone name or empty for the default."`
	Interface string `name:"interface" short:"i" help:"Resolve the zone for this interface."`
	natFlags
}

// Run removes the NAT rule matching the given flags.
func (c *NATRemoveCmd) Run(g *Globals) error {
	rule, err := c.toNATRule()
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
	if err := mgr.RemoveNATRule(context.Background(), zone, rule); err != nil {
		return fmt.Errorf("remove NAT rule: %w", err)
	}
	if err := g.reload(mgr); err != nil {
		return fmt.Errorf("reload: %w", err)
	}
	return g.emitStatus("removed")
}
