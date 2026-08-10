package firewall

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
)

// NewManager gets a firewall manager for this server, probing the higher-level
// managers first: firewalld, then ufw/csf/apf, then plain iptables, and
// nftables last, so a manager that is itself backed by iptables or nftables is
// preferred over managing its tables behind its back. The context bounds the
// detection probes (each shells out or opens a D-Bus/systemd connection).
func NewManager(ctx context.Context, rulePrefix string) (Manager, error) {
	// A probe error usually means "not installed", but it can also be a
	// transient failure on a host whose firewall IS that manager (a D-Bus
	// hiccup with firewalld running); every probe's reason is carried in the
	// final error so a mis-detection is diagnosable.
	var errs []error
	probes := []struct {
		name string
		try  func() (Manager, error)
	}{
		{"firewalld", func() (Manager, error) { return NewFirewallD(ctx, rulePrefix) }},
		{"ufw", func() (Manager, error) { return NewUFW(ctx, rulePrefix) }},
		{"csf", func() (Manager, error) { return NewCSF(ctx, rulePrefix) }},
		{"apf", func() (Manager, error) { return NewAPF(ctx, rulePrefix) }},
		{"iptables", func() (Manager, error) { return NewIPTables(ctx, rulePrefix) }},
		{"nftables", func() (Manager, error) { return NewNFT(ctx, rulePrefix) }},
	}
	for _, p := range probes {
		mgr, err := p.try()
		if err == nil {
			return mgr, nil
		}
		errs = append(errs, fmt.Errorf("%s: %w", p.name, err))
	}
	return nil, fmt.Errorf("no firewall manager found: %w", errors.Join(errs...))
}

// combineComment joins the configured prefix and an optional user comment into the
// single comment string stored on a rule. The prefix is always carried so rules
// this library creates stay identifiable: when both are present the prefix is
// followed by a space and the user text; when only one is present it is used
// alone; when neither is present the result is empty. Shared by the tag-based
// Linux backends (iptables, ufw, csf, apf, and the csf/apf hook).
func combineComment(prefix, comment string) string {
	if prefix == "" {
		return comment
	}
	if comment == "" {
		return prefix
	}
	return prefix + " " + comment
}

// commentGroup is one span of a scanned list file: a content line together with
// the full-line comment lines attached directly above it, or a single
// passthrough line — a blank, a detached comment, or a line the file's
// convention does not attach comments to — on its own.
type commentGroup struct {
	// raw preserves the original lines, attached comments first and the content
	// line last, so a rewrite copies user formatting through verbatim and a
	// removal drops a rule's comment together with its line.
	raw []string
	// line is the trimmed content line, or "" for a passthrough group.
	line string
	// comment is the space-joined text of the attached comment lines.
	comment string
}

// scanCommentGroups streams a list file to fn as comment-attached groups, the
// convention shared by the csf.allow/csf.deny lists, the apf trust files, and
// the raw-iptables hook: consecutive full-line `#` comments attach to the
// content line directly below them as its comment. A blank line detaches a
// pending comment block into passthrough groups, and a rulePrefix tag starts a
// fresh block, so header comments above a tagged rule survive the rule's
// removal. A `#!` line is never a comment: a shebang must not attach to a rule
// and be dropped with it. attach reports whether a content line takes the
// pending comments (nil attaches to every non-blank, non-comment line); a line
// it declines — user shell or ipset lines in the hook — detaches them and
// passes through on its own. A nil fd scans as an empty file. An error from fn
// stops the scan.
func scanCommentGroups(fd *os.File, rulePrefix string, attach func(trimmed string) bool, fn func(g commentGroup) error) error {
	if fd == nil {
		return nil
	}
	scanner := bufio.NewScanner(fd)
	// pending holds the raw held-back comment lines (a rewrite needs them
	// verbatim); pendingText accumulates their space-joined comment text (the
	// parse needs it).
	var pending []string
	var pendingText string
	flush := func() error {
		for _, c := range pending {
			if err := fn(commentGroup{raw: []string{c}}); err != nil {
				return err
			}
		}
		pending, pendingText = nil, ""
		return nil
	}
	for scanner.Scan() {
		raw := scanner.Text()
		trimmed := strings.TrimSpace(raw)

		// A full-line comment is held as a candidate rule comment.
		if strings.HasPrefix(trimmed, "#") && !strings.HasPrefix(trimmed, "#!") {
			text := strings.TrimSpace(strings.TrimPrefix(trimmed, "#"))
			if rulePrefix != "" && (text == rulePrefix || strings.HasPrefix(text, rulePrefix+" ")) {
				if err := flush(); err != nil {
					return err
				}
			}
			if text != "" {
				if pendingText != "" {
					pendingText += " " + text
				} else {
					pendingText = text
				}
			}
			pending = append(pending, raw)
			continue
		}

		// A blank line or a line the file's convention does not attach comments
		// to detaches the pending block and passes through untouched.
		if trimmed == "" || (attach != nil && !attach(trimmed)) {
			if err := flush(); err != nil {
				return err
			}
			if err := fn(commentGroup{raw: []string{raw}}); err != nil {
				return err
			}
			continue
		}

		g := commentGroup{raw: append(pending, raw), line: trimmed, comment: pendingText}
		pending, pendingText = nil, ""
		if err := fn(g); err != nil {
			return err
		}
	}
	if err := flush(); err != nil {
		return err
	}
	return scanner.Err()
}

// trimInlineComment strips a trailing inline `#` comment from a list line —
// a note on the line itself, not a rule comment — returning the trimmed rule
// text that remains.
func trimInlineComment(line string) string {
	if ci := strings.IndexByte(line, '#'); ci >= 0 {
		line = line[:ci]
	}
	return strings.TrimSpace(line)
}

// prefixedComment splits a stored comment into its user-facing text and whether
// the comment carried the configured prefix (marking a rule tagged with this
// library's namespace). A comment equal to the prefix (a prefix-only tag) has the
// prefix with empty text; a comment carrying the prefix followed by a space has
// the prefix with the remainder as text; any other comment lacks the prefix and
// is returned unchanged. An empty prefix gives the library no namespace of its
// own, so the prefix cannot be derived from the comment — hasPrefix is reported
// false and the caller decides (backends treat an empty prefix as covering
// everything, see GetRules). It is the read-side inverse of combineComment.
func prefixedComment(prefix, comment string) (text string, hasPrefix bool) {
	if prefix == "" {
		return comment, false
	}
	if comment == prefix {
		return "", true
	}
	if rest, ok := strings.CutPrefix(comment, prefix+" "); ok {
		return rest, true
	}
	return comment, false
}
