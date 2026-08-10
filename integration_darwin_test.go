//go:build integration

package firewall

import (
	"context"
	"testing"
)

// TestIntegration runs the capability-driven suite against macOS's pf backend.
// macOS cannot be automated in a general VM (it needs Apple hardware), so this is
// run manually on a Mac: `sudo go test -tags integration -run TestIntegration`.
// The pf backend is shared with FreeBSD, which the VM runner covers automatically.
// See integration_test.go for the shared suite and runIntegration.
func TestIntegration(t *testing.T) {
	runIntegration(t, []backendFactory{
		{"pf", func(ctx context.Context, p string) (Manager, error) { return NewPF(ctx, p) }},
	})
}
