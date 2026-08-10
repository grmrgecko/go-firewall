package main

import (
	"context"
	"fmt"
	"os"

	fw "github.com/grmrgecko/go-firewall"
)

// This file holds the address-set command group: list, create, remove,
// add-entry, remove-entry. Address sets are named collections of addresses
// (ipset / nftables set / pf table) that rules can match against; they are
// managed separately from filter and NAT rules.

// SetCmd is the top-level "set" command group.
type SetCmd struct {
	List        SetListCmd        `cmd:"" help:"List address sets (default)."`
	Show        SetShowCmd        `cmd:"" help:"Show a single address set and its entries."`
	Create      SetCreateCmd      `cmd:"" help:"Create an address set."`
	Remove      SetRemoveCmd      `cmd:"" help:"Remove an address set."`
	AddEntry    SetAddEntryCmd    `cmd:"" help:"Add an entry to an address set."`
	RemoveEntry SetRemoveEntryCmd `cmd:"" help:"Remove an entry from an address set."`
}

// SetShowCmd prints one address set's metadata and every entry it holds. The
// list command shows only an entry count; this is how the actual addresses are
// inspected in text mode (the --json list already carries them). The library
// has no get-by-name method, so it filters GetAddressSets by name.
type SetShowCmd struct {
	Name string `arg:"" name:"name" help:"Set name to show."`
}

// Run prints one address set's metadata and every entry it holds.
func (c *SetShowCmd) Run(g *Globals) error {
	mgr, cleanup, err := g.manager()
	if err != nil {
		return err
	}
	defer cleanup()

	sets, err := mgr.GetAddressSets(context.Background())
	if err != nil {
		return fmt.Errorf("listing address sets: %w", err)
	}
	var set *fw.AddressSet
	for _, s := range sets {
		if s.Name == c.Name {
			set = s
			break
		}
	}
	if set == nil {
		return fmt.Errorf("address set %q not found", c.Name)
	}
	return g.emit(set, func() error {
		printSet(os.Stdout, set)
		return nil
	})
}

// SetListCmd lists every address set the backend manages.
type SetListCmd struct{}

// Run lists every address set the backend manages.
func (c *SetListCmd) Run(g *Globals) error {
	mgr, cleanup, err := g.manager()
	if err != nil {
		return err
	}
	defer cleanup()

	sets, err := mgr.GetAddressSets(context.Background())
	if err != nil {
		return fmt.Errorf("listing address sets: %w", err)
	}
	return g.emit(sets, func() error {
		if len(sets) == 0 {
			fmt.Println("(no address sets)")
			return nil
		}
		printSets(os.Stdout, sets)
		return nil
	})
}

// SetCreateCmd creates an address set. Adding a set that already exists by name
// is a no-op in the library.
type SetCreateCmd struct {
	Name   string `arg:"" name:"name" help:"Set name."`
	Family string `name:"family" short:"f" help:"any|ipv4|ipv6 (default any; some backends resolve 'any' to ipv4)." default:"any"`
	Type   string `name:"type" short:"t" help:"hash:ip|hash:net (default hash:ip)." default:"hash:ip"`
}

// Run creates an address set from the parsed flags.
func (c *SetCreateCmd) Run(g *Globals) error {
	// Parse the enum flags before opening the manager so a bad token fails
	// fast instead of after a backend connection.
	family, err := fw.ParseFamily(c.Family)
	if err != nil {
		return err
	}
	typ, err := fw.ParseSetType(c.Type)
	if err != nil {
		return err
	}
	mgr, cleanup, err := g.manager()
	if err != nil {
		return err
	}
	defer cleanup()

	set := &fw.AddressSet{Name: c.Name, Family: family, Type: typ}
	if err := mgr.AddAddressSet(context.Background(), set); err != nil {
		return fmt.Errorf("create address set: %w", err)
	}
	if err := g.reload(mgr); err != nil {
		return fmt.Errorf("reload: %w", err)
	}
	return g.emitStatus("created")
}

// SetRemoveCmd removes an address set by name.
type SetRemoveCmd struct {
	Name string `arg:"" name:"name" help:"Set name to remove."`
}

// Run removes an address set by name.
func (c *SetRemoveCmd) Run(g *Globals) error {
	mgr, cleanup, err := g.manager()
	if err != nil {
		return err
	}
	defer cleanup()

	if err := mgr.RemoveAddressSet(context.Background(), c.Name); err != nil {
		return fmt.Errorf("remove address set: %w", err)
	}
	if err := g.reload(mgr); err != nil {
		return fmt.Errorf("reload: %w", err)
	}
	return g.emitStatus("removed")
}

// SetAddEntryCmd adds an entry (IP or CIDR) to a set.
type SetAddEntryCmd struct {
	Name  string `arg:"" name:"name" help:"Set name."`
	Entry string `arg:"" name:"entry" help:"Address or CIDR to add."`
}

// Run adds an entry (IP or CIDR) to a set.
func (c *SetAddEntryCmd) Run(g *Globals) error {
	mgr, cleanup, err := g.manager()
	if err != nil {
		return err
	}
	defer cleanup()

	if err := mgr.AddAddressSetEntry(context.Background(), c.Name, c.Entry); err != nil {
		return fmt.Errorf("add entry: %w", err)
	}
	if err := g.reload(mgr); err != nil {
		return fmt.Errorf("reload: %w", err)
	}
	return g.emitStatus("added")
}

// SetRemoveEntryCmd removes an entry from a set.
type SetRemoveEntryCmd struct {
	Name  string `arg:"" name:"name" help:"Set name."`
	Entry string `arg:"" name:"entry" help:"Address or CIDR to remove."`
}

// Run removes an entry from a set.
func (c *SetRemoveEntryCmd) Run(g *Globals) error {
	mgr, cleanup, err := g.manager()
	if err != nil {
		return err
	}
	defer cleanup()

	if err := mgr.RemoveAddressSetEntry(context.Background(), c.Name, c.Entry); err != nil {
		return fmt.Errorf("remove entry: %w", err)
	}
	if err := g.reload(mgr); err != nil {
		return fmt.Errorf("reload: %w", err)
	}
	return g.emitStatus("removed")
}
