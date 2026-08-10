//go:build integration

package firewall

import (
	"context"
	"testing"
)

// TestIntegration runs the capability-driven suite against FreeBSD's pf backend.
// See integration_test.go for the shared suite and runIntegration.
func TestIntegration(t *testing.T) {
	runIntegration(t, []backendFactory{
		{"pf", func(ctx context.Context, p string) (Manager, error) { return NewPF(ctx, p) }},
	})
}
