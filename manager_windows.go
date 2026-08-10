package firewall

import (
	"context"
	"fmt"
)

// NewManager gets a firewall manager for this server; Windows has a single
// backend, the Windows Filtering Platform. The context bounds the probe.
func NewManager(ctx context.Context, rulePrefix string) (Manager, error) {
	wf, err := NewWF(ctx, rulePrefix)
	if err == nil {
		return wf, nil
	}
	return nil, fmt.Errorf("no firewall manager found: %w", err)
}
