//go:build integration

package firewall

import (
	"context"
	"testing"
)

// TestIntegration runs the capability-driven suite against the Windows Firewall
// (WFP) backend. It needs Administrator privileges and the Windows API, so it runs
// inside a Windows VM (see test/integration/host-windows-vm.sh) or manually on a
// Windows host: `go test -tags integration -run TestIntegration` from an elevated
// prompt. See integration_test.go for the shared suite and runIntegration.
func TestIntegration(t *testing.T) {
	runIntegration(t, []backendFactory{
		{"wf", func(ctx context.Context, p string) (Manager, error) { return NewWF(ctx, p) }},
	})
}
