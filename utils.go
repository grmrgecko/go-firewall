package firewall

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
)

func trimQuotes(s string) string {
	return strings.Trim(s, "\"'")
}

// stripUnquotedComment removes a trailing '#' comment from a config line,
// ignoring a '#' inside a quoted value so `KEY = "pre#fix"` is not truncated.
func stripUnquotedComment(line string) string {
	var inQuote byte
	for i := 0; i < len(line); i++ {
		switch c := line[i]; {
		case inQuote != 0:
			if c == inQuote {
				inQuote = 0
			}
		case c == '"' || c == '\'':
			inQuote = c
		case c == '#':
			return line[:i]
		}
	}
	return line
}

// readConfValue scans a shell-style "KEY = \"VALUE\"" config file (conf.apf,
// csf.conf) for key and returns its value, or "" if key is not set. The last
// assignment wins, matching how the shell sources these files. Used for
// one-shot flags read at construction time, not the per-rule list edits (which
// each backend's own EditConf/EditRulePort scan handles in place).
func readConfValue(path, key string) (string, error) {
	fd, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = fd.Close() }()
	value := ""
	scanner := bufio.NewScanner(fd)
	for scanner.Scan() {
		line := strings.TrimSpace(stripUnquotedComment(scanner.Text()))
		if line == "" {
			continue
		}
		k, v, found := strings.Cut(line, "=")
		if !found {
			continue
		}
		if strings.TrimSpace(k) == key {
			value = trimQuotes(strings.TrimSpace(v))
		}
	}
	return value, scanner.Err()
}

// binSearchDirs are the directories searched for a firewall tool when PATH does
// not resolve it, covering the standard locations iptables, ip6tables, ipset, nft
// and the backend front-ends install into. The tools live in the sbin
// directories, and a process started from a service unit, a cron job or a login
// shell for an unprivileged user routinely gets a PATH without them.
var binSearchDirs = []string{"/usr/sbin", "/sbin", "/usr/local/sbin", "/usr/bin", "/bin", "/usr/local/bin"}

// resolvedBins memoizes successful lookups: every command run resolves its tool
// and an installed tool does not move while the process runs. A failed lookup is
// deliberately not cached, so a tool installed under a long-lived process is
// picked up on its next use.
var resolvedBins sync.Map

// resolveBinary returns the absolute path of a firewall tool and reports whether
// it was found. PATH wins; failing that the standard install directories are
// searched (binSearchDirs). A name that already carries a path separator is taken
// as given. An unresolved name is returned unchanged, leaving the caller to hand
// it to exec (for its own error) or to a shell.
func resolveBinary(name string) (string, bool) {
	if name == "" {
		return name, false
	}
	if strings.ContainsRune(name, os.PathSeparator) {
		return name, true
	}
	if cached, ok := resolvedBins.Load(name); ok {
		return cached.(string), true
	}
	if p, err := exec.LookPath(name); err == nil {
		if abs, err := filepath.Abs(p); err == nil {
			p = abs
		}
		resolvedBins.Store(name, p)
		return p, true
	}
	// PATH missed it — the tool may still be installed where the tools live.
	for _, dir := range binSearchDirs {
		cand := filepath.Join(dir, name)
		if fi, err := os.Stat(cand); err == nil && fi.Mode().IsRegular() && fi.Mode()&0111 != 0 {
			resolvedBins.Store(name, cand)
			return cand, true
		}
	}
	return name, false
}

// runCommand runs command and returns its stdout and any error. The context
// bounds the command's lifetime: cancelling it kills the process.
func runCommand(ctx context.Context, command string, args ...string) (out []string, err error) {
	return runCommandStdin(ctx, "", command, args...)
}

// runCommandStdin runs command with the provided string fed to stdin, returning its stdout and any error.
func runCommandStdin(ctx context.Context, stdin string, command string, args ...string) (out []string, err error) {
	// Resolve the tool up front so a PATH without the sbin directories does not
	// turn every backend call into an executable-not-found error.
	bin, _ := resolveBinary(command)
	cmd := exec.CommandContext(ctx, bin, args...)

	// Force the C locale so the backend tools emit their canonical, English output.
	// Several backends match tool output to drive control flow — ufw's "Invalid
	// position"/"Could not delete non-existent rule" fallbacks, CSF/APF restart
	// messages — and those strings are gettext-translated. Without a pinned locale a
	// non-English host would break the idempotent-remove and insert-append fallbacks
	// (leaving a rule removed-and-not-re-added, or a no-op remove turned into an
	// error). LC_ALL wins over LANG/LC_* so appending it last is sufficient.
	cmd.Env = append(os.Environ(), "LC_ALL=C")

	// Feed stdin when provided.
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}

	// Get output pipes.
	var stdout, stderr io.ReadCloser
	stdout, err = cmd.StdoutPipe()
	if err != nil {
		return
	}
	stderr, err = cmd.StderrPipe()
	if err != nil {
		_ = stdout.Close()
		return
	}

	// Start the command. Close the pipes on failure so their file descriptors do
	// not leak; a started command's pipes are closed by Wait below.
	err = cmd.Start()
	if err != nil {
		_ = stdout.Close()
		_ = stderr.Close()
		return
	}

	// Setup wait group to wait for buffers to fully read.
	var wg sync.WaitGroup
	wg.Add(2)

	// The default bufio.Scanner token cap is 64 KB, but some backends emit a
	// single very long line — notably `nft -j list sets`, whose entire JSON
	// result is one line and can far exceed 64 KB for a large blocklist. Give
	// each scanner a generous max so such a line is not silently truncated, and
	// surface scanner.Err() so a line that still overflows fails loudly rather
	// than returning partial output as success.
	const maxLine = 64 * 1024 * 1024
	var scanErr error
	var scanMu sync.Mutex
	recordScanErr := func(e error) {
		if e == nil {
			return
		}
		scanMu.Lock()
		if scanErr == nil {
			scanErr = e
		}
		scanMu.Unlock()
	}

	// Read stdout.
	stdoutScanner := bufio.NewScanner(stdout)
	stdoutScanner.Buffer(make([]byte, 0, 64*1024), maxLine)
	go func() {
		for stdoutScanner.Scan() {
			out = append(out, stdoutScanner.Text())
		}
		recordScanErr(stdoutScanner.Err())
		wg.Done()
	}()

	// Read stderr.
	var stderrData strings.Builder
	stderrScanner := bufio.NewScanner(stderr)
	stderrScanner.Buffer(make([]byte, 0, 64*1024), maxLine)
	go func() {
		for stderrScanner.Scan() {
			line := stderrScanner.Text()
			stderrData.WriteString(line)
			stderrData.WriteByte('\n')
		}
		recordScanErr(stderrScanner.Err())
		wg.Done()
	}()

	// Wait for the stdout and stderr reader goroutines to drain before calling cmd.Wait.
	wg.Wait()

	// Wait for the command to finish.
	err = cmd.Wait()
	if err != nil {
		// Keep the underlying error wrapped so its exit code stays reachable
		// through errors.As, and only mention stdout when there is any.
		stderrText := strings.TrimSpace(stderrData.String())
		switch {
		case stderrText != "" && len(out) > 0:
			err = fmt.Errorf("%s (stdout %s): %w", stderrText, strings.Join(out, "\n"), err)
		case stderrText != "":
			err = fmt.Errorf("%s: %w", stderrText, err)
		}
		// A command can fail and also produce truncated output; surface both so a
		// read error is never hidden behind the command's own failure.
		if scanErr != nil {
			err = fmt.Errorf("%v; scanner: %w", err, scanErr)
		}
		return
	}
	// The process succeeded; report a read/truncation error if one occurred so a
	// caller never mistakes truncated output for a complete result.
	if scanErr != nil {
		err = scanErr
	}
	return
}
