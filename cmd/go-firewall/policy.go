package main

import (
	"context"
	"fmt"

	fw "github.com/grmrgecko/go-firewall"
)

// This file holds the default-policy command group: get and set. A default
// policy is the action applied to packets that match no rule, per direction
// (input/output/forward). Not every backend exposes every direction, and some
// expose none at all (they return ErrUnsupportedPolicy).

// PolicyCmd is the top-level "policy" command group.
type PolicyCmd struct {
	Get PolicyGetCmd `cmd:"" help:"Show the default policy (default)."`
	Set PolicySetCmd `cmd:"" help:"Set the default policy for one or more directions."`
}

// PolicyGetCmd prints the default policy. Directions the backend cannot express
// are shown as "-" (the library returns ActionInvalid for those).
type PolicyGetCmd struct {
	Zone      string `name:"zone" short:"z" help:"Zone name or empty for the default."`
	Interface string `name:"interface" short:"i" help:"Resolve the zone for this interface."`
}

// Run prints the default policy for each direction.
func (c *PolicyGetCmd) Run(g *Globals) error {
	mgr, cleanup, err := g.manager()
	if err != nil {
		return err
	}
	defer cleanup()

	zone, err := resolveZone(mgr, c.Zone, c.Interface)
	if err != nil {
		return err
	}
	pol, err := mgr.GetDefaultPolicy(context.Background(), zone)
	if err != nil {
		return fmt.Errorf("get default policy: %w", err)
	}
	return g.emit(pol, func() error {
		printPolicy("input", pol.Input)
		printPolicy("output", pol.Output)
		printPolicy("forward", pol.Forward)
		return nil
	})
}

// printPolicy renders one direction's action, collapsing ActionInvalid to "-"
// so a get on a backend that doesn't expose a direction reads cleanly.
func printPolicy(dir string, a fw.Action) {
	s := a.String()
	if a == fw.ActionInvalid {
		s = "-"
	}
	fmt.Printf("%-8s %s\n", dir, s)
}

// PolicySetCmd sets the default policy. Each direction is optional: an unset
// flag leaves that direction unchanged (the library treats ActionInvalid that
// way on Set), so `policy set --input drop` changes only the input direction.
type PolicySetCmd struct {
	Zone      string `name:"zone" short:"z" help:"Zone name or empty for the default."`
	Interface string `name:"interface" short:"i" help:"Resolve the zone for this interface."`
	Input     string `name:"input" help:"accept|reject|drop for the input direction. Unset leaves it unchanged."`
	Output    string `name:"output" help:"accept|reject|drop for the output direction. Unset leaves it unchanged."`
	Forward   string `name:"forward" help:"accept|reject|drop for the forward direction. Unset leaves it unchanged."`
}

// Run sets the default policy for the directions whose flags were given.
func (c *PolicySetCmd) Run(g *Globals) error {
	// Parse each direction up front; an empty flag stays ActionInvalid, which
	// the library interprets as "leave unchanged" on Set. Doing this before
	// opening the manager means a bad action token fails fast.
	pol := &fw.DefaultPolicy{}
	if c.Input != "" {
		a, err := fw.ParseAction(c.Input)
		if err != nil {
			return err
		}
		pol.Input = a
	}
	if c.Output != "" {
		a, err := fw.ParseAction(c.Output)
		if err != nil {
			return err
		}
		pol.Output = a
	}
	if c.Forward != "" {
		a, err := fw.ParseAction(c.Forward)
		if err != nil {
			return err
		}
		pol.Forward = a
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
	if err := mgr.SetDefaultPolicy(context.Background(), zone, pol); err != nil {
		return fmt.Errorf("set default policy: %w", err)
	}
	if err := g.reload(mgr); err != nil {
		return fmt.Errorf("reload: %w", err)
	}
	return g.emitStatus("ok")
}
