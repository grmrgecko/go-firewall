// Command go-firewall is a unified firewall management CLI built on the
// github.com/grmrgecko/go-firewall library. It auto-detects the host's active
// firewall backend and exposes a single command set across every backend the
// library supports (firewalld, ufw, CSF, APF, iptables, nftables, pf, WFP).
//
// It doubles as runnable example code for the library: every subcommand maps
// one-to-one onto a Manager method.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"text/tabwriter"
	"time"

	"github.com/alecthomas/kong"
	"github.com/willabides/kongplete"

	fw "github.com/grmrgecko/go-firewall"
)

// managerDetectTimeout bounds backend detection so a hung probe (pfctl, D-Bus)
// fails fast instead of hanging the CLI process indefinitely.
const managerDetectTimeout = 30 * time.Second

// version is the CLI version, overridden at build time with:
//
//	go build -ldflags "-X main.version=1.2.3"
var version = "dev"

// VersionFlag is a kong flag type that prints the version and exits before any
// command runs (mirrors the pattern in kong's own examples).
type VersionFlag bool

// Decode satisfies kong's flag decoder; the value itself carries no data.
func (v VersionFlag) Decode(ctx *kong.DecodeContext) error { return nil }

// IsBool marks the flag as boolean so it takes no argument.
func (v VersionFlag) IsBool() bool { return true }

// BeforeApply prints the version and exits before any command runs.
func (v VersionFlag) BeforeApply(app *kong.Kong, vars kong.Vars) error {
	fmt.Println(vars["version"])
	app.Exit(0)
	return nil
}

// Globals are the top-level flags shared by every subcommand. Kong passes a
// pointer to each command's Run method, so every subcommand opens the firewall
// manager the same way regardless of which one ran.
type Globals struct {
	// Prefix namespaces the rules this CLI creates, mirroring
	// firewall.NewManager's rulePrefix argument. Backends that need a name
	// (WFP rule group, nftables table, pf anchor) fall back to "go_firewall"
	// when empty.
	Prefix string `name:"prefix" env:"GOFIREWALL_PREFIX" help:"Rule prefix used to namespace managed rules." default:"go_firewall"`
	// NoReload disables the automatic Reload after a mutating command on
	// backends that stage changes (ufw, CSF, APF). Off by default so changes
	// take effect immediately.
	NoReload bool `name:"no-reload" env:"GOFIREWALL_NO_RELOAD" help:"Do not reload the backend after a mutation."`
	// JSON switches list/status output to machine-readable JSON.
	JSON bool `short:"j" name:"json" env:"GOFIREWALL_JSON" help:"Emit list/status output as JSON."`
	// Version prints the CLI version and exits.
	Version VersionFlag `name:"version" help:"Print version information and quit."`

	Rule    RuleCmd       `cmd:"" help:"Manage filter rules." group:"rules"`
	NAT     NATCmd        `cmd:"" help:"Manage NAT (port-forward/masquerade) rules." group:"rules"`
	Policy  PolicyCmd     `cmd:"" help:"Manage the default policy." group:"rules"`
	Set     SetCmd        `cmd:"" help:"Manage address sets (ipset/nftset/pf tables)." group:"management"`
	Backup  BackupSubcmd  `cmd:"" help:"Snapshot managed rules to a file (or stdout)." group:"management"`
	Restore RestoreSubcmd `cmd:"" help:"Replay a backup file (or stdin)." group:"management"`
	Status  StatusCmd     `cmd:"" help:"Show the detected firewall backend and its capabilities." group:"info"`
	Zone    ZoneCmd       `cmd:"" help:"Resolve the zone for an interface." group:"info"`
	Reload  ReloadCmd     `cmd:"" help:"Reload the firewall backend (activate staged rules)." group:"info"`

	// InstallCompletions registers shell completion for bash/zsh/fish. Running
	// it emits (or installs) the completion script; the actual completion
	// requests are served by kongplete.Complete in main before Parse.
	InstallCompletions kongplete.InstallCompletions `cmd:"" help:"Install shell completion for go-firewall." group:"info"`
}

func main() {
	var cli Globals
	parser := kong.Must(&cli,
		kong.Name("go-firewall"),
		kong.Description("A unified firewall management CLI across firewalld, ufw, CSF, APF, iptables, nftables, pf and WFP."),
		kong.UsageOnError(),
		kong.ConfigureHelp(kong.HelpOptions{
			Compact: true,
			Tree:    true,
		}),
		kong.Vars{"version": version},
	)
	// Serve shell-completion requests (COMP_LINE-driven) before parsing, so a
	// completion invocation returns candidates and exits without running a
	// command. It is a no-op for a normal invocation.
	kongplete.Complete(parser)

	ctx, err := parser.Parse(os.Args[1:])
	parser.FatalIfErrorf(err)
	err = ctx.Run(&cli)
	ctx.FatalIfErrorf(err)
}

// manager opens the detected firewall manager, scoped to g.Prefix. The returned
// closer must be invoked by the caller. It is the single entry point every
// subcommand uses, so detection and teardown are defined once.
func (g *Globals) manager() (fw.Manager, func(), error) {
	// Bound only detection: the returned closer and each command's operations run
	// on their own contexts, so this deadline cannot cancel in-flight work.
	ctx, cancel := context.WithTimeout(context.Background(), managerDetectTimeout)
	defer cancel()
	mgr, err := fw.NewManager(ctx, g.Prefix)
	if err != nil {
		return nil, nil, fmt.Errorf("detecting firewall backend: %w", err)
	}
	cleanup := func() { _ = mgr.Close(context.Background()) }
	return mgr, cleanup, nil
}

// reload conditionally activates staged rules. NoReload skips it (useful when a
// caller batches several mutations and reloads once at the end).
func (g *Globals) reload(mgr fw.Manager) error {
	if g.NoReload {
		return nil
	}
	return mgr.Reload(context.Background())
}

// emit prints either JSON (when g.JSON is set) or the human-readable rendering
// produced by human. It is the single output path for list/status commands so
// every subcommand honors --json the same way.
func (g *Globals) emit(v any, human func() error) error {
	if g.JSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(v)
	}
	return human()
}

// emitStatus reports the outcome of a mutating command. In text mode it prints
// the bare word (e.g. "added"); under --json it emits a small status object so
// a scripted caller passing -j still gets parseable output instead of empty
// stdout. It is the single success path for every mutation so they stay in sync.
func (g *Globals) emitStatus(status string) error {
	if g.JSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(struct {
			Status string `json:"status"`
		}{status})
	}
	fmt.Println(status)
	return nil
}

// newTable returns a tabwriter that flushes to w, configured for the
// human-readable tables used by the list commands. All columns are left-aligned
// for readability.
func newTable(w io.Writer) *tabwriter.Writer {
	return tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
}
