package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"reflect"
	"sort"

	fw "github.com/grmrgecko/go-firewall"
)

// This file holds the read-only/info subcommands: status (backend + caps),
// zone (resolve an interface's zone), and reload (force a backend reload).

// StatusCmd reports the detected backend and its capabilities. It is the
// default thing to run when orienting on an unfamiliar host.
type StatusCmd struct{}

// Run reports the detected backend and its capabilities.
func (c *StatusCmd) Run(g *Globals) error {
	mgr, cleanup, err := g.manager()
	if err != nil {
		return err
	}
	defer cleanup()

	caps := mgr.Capabilities()
	type statusOut struct {
		Backend      string          `json:"backend"`
		Prefix       string          `json:"prefix"`
		Capabilities fw.Capabilities `json:"capabilities"`
	}
	out := statusOut{
		Backend:      mgr.Type(),
		Prefix:       g.Prefix,
		Capabilities: caps,
	}
	return g.emit(out, func() error {
		fmt.Printf("backend:        %s\n", out.Backend)
		fmt.Printf("prefix:         %s\n", out.Prefix)
		fmt.Println()
		fmt.Println("capabilities:")
		printCapabilities(os.Stdout, caps)
		return nil
	})
}

// printCapabilities lists the capability booleans in a stable, readable order.
// It walks the struct via reflection so a new bool field in fw.Capabilities is
// surfaced automatically without a parallel slice here. Non-bool fields are
// skipped so a future non-bool capability cannot panic the reflection walk.
func printCapabilities(w io.Writer, caps fw.Capabilities) {
	v := reflect.ValueOf(caps)
	t := v.Type()
	type field struct {
		name string
		ok   bool
	}
	fields := make([]field, 0, t.NumField())
	for i := 0; i < t.NumField(); i++ {
		if v.Field(i).Kind() != reflect.Bool {
			continue
		}
		fields = append(fields, field{
			name: t.Field(i).Name,
			ok:   v.Field(i).Bool(),
		})
	}
	sort.Slice(fields, func(i, j int) bool { return fields[i].name < fields[j].name })
	maxLen := 0
	for _, f := range fields {
		if len(f.name) > maxLen {
			maxLen = len(f.name)
		}
	}
	for _, f := range fields {
		mark := "-"
		if f.ok {
			mark = "yes"
		}
		_, _ = fmt.Fprintf(w, "  %-*s  %s\n", maxLen, f.name, mark)
	}
}

// ZoneCmd resolves the zone an interface belongs to. On backends without zones
// (iptables, nftables, pf, WFP) the returned zone is empty and that is the
// correct answer — it just means the backend has no zone abstraction.
type ZoneCmd struct {
	Interface string `arg:"" name:"interface" help:"Network interface to resolve (e.g. eth0)."`
}

// Run resolves and prints the zone the interface belongs to.
func (c *ZoneCmd) Run(g *Globals) error {
	mgr, cleanup, err := g.manager()
	if err != nil {
		return err
	}
	defer cleanup()

	zone, err := mgr.GetZone(context.Background(), c.Interface)
	if err != nil {
		return fmt.Errorf("resolving zone for %q: %w", c.Interface, err)
	}
	type zoneOut struct {
		Interface string `json:"interface"`
		Zone      string `json:"zone"`
	}
	out := zoneOut{Interface: c.Interface, Zone: zone}
	return g.emit(out, func() error {
		// A zoneless backend returns an empty zone; show a human placeholder here
		// only, so the JSON form keeps the honest empty string.
		display := out.Zone
		if display == "" {
			display = "(none)"
		}
		fmt.Printf("%s -> %s\n", out.Interface, display)
		return nil
	})
}

// ReloadCmd forces a backend reload, activating any staged rules. Useful after
// a series of --no-reload mutations, or to pick up changes made out of band.
type ReloadCmd struct{}

// Run forces a backend reload, activating any staged rules.
func (c *ReloadCmd) Run(g *Globals) error {
	mgr, cleanup, err := g.manager()
	if err != nil {
		return err
	}
	defer cleanup()
	if err := mgr.Reload(context.Background()); err != nil {
		return fmt.Errorf("reload: %w", err)
	}
	return g.emitStatus("reloaded")
}
