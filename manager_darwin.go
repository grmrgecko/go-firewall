package firewall

import (
	"context"
	"fmt"
)

// NewManager gets a firewall manager for this macOS host.
func NewManager(ctx context.Context, rulePrefix string) (Manager, error) {
	// macOS uses pf (Packet Filter) for its network firewall.
	pf, err := NewPF(ctx, rulePrefix)
	if err == nil {
		return pf, nil
	}

	return nil, fmt.Errorf("no firewall manager found")
}
