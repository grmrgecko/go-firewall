package firewall

import (
	"bufio"
	"errors"
	"os"
	"path/filepath"
)

// atomicFile stages an atomic replacement of a config file. It creates a temp
// file in the destination's directory and captures the destination's ownership
// and permission mode up front; Commit restores that metadata onto the temp
// file before renaming it into place. A destination that does not yet exist
// falls back to defaultMode with the temp file's default ownership.
//
// The struct embeds *os.File so callers stream into it with the usual Write and
// fmt.Fprintln calls, whether they buffer the whole file or scan the original
// and rewrite line by line. Writes pass through an internal bufio.Writer that
// Commit flushes, so a line-by-line rewrite of a large save file does not issue
// a syscall per line; the embedded fd remains reachable for the metadata calls
// Commit makes.
type atomicFile struct {
	*os.File
	w        *bufio.Writer
	dst      string
	tmp      string
	mode     os.FileMode
	uid, gid int
	chown    bool // True only when the destination already existed.
	done     bool
}

// newAtomicFile opens a temp file next to dst for streaming. The caller writes
// to the returned handle, then calls Commit to install it or Abort to discard
// it. Capturing the destination's mode and ownership here means a later
// scan-and-rewrite of the original still commits with the original's metadata.
// A symlinked destination is resolved so the rename replaces the link's target
// rather than turning the link itself into a regular file.
func newAtomicFile(dst string, defaultMode os.FileMode) (*atomicFile, error) {
	if resolved, err := filepath.EvalSymlinks(dst); err == nil {
		dst = resolved
	}
	mode := defaultMode
	var uid, gid int
	var chown bool
	if fi, err := os.Stat(dst); err == nil {
		mode = fi.Mode().Perm()
		uid, gid, chown = statOwner(fi)
	}
	fd, err := os.CreateTemp(filepath.Dir(dst), filepath.Base(dst)+".tmp.*")
	if err != nil {
		return nil, err
	}
	return &atomicFile{
		File:  fd,
		w:     bufio.NewWriter(fd),
		dst:   dst,
		tmp:   fd.Name(),
		mode:  mode,
		uid:   uid,
		gid:   gid,
		chown: chown,
	}, nil
}

// Write buffers p into the staged file. It shadows the embedded fd's own Write
// so every caller — the line-by-line rewrites and the whole-buffer writers
// alike — shares one bufio.Writer; Commit flushes it before installing the
// file, and Abort discards it with the temp file.
func (a *atomicFile) Write(p []byte) (int, error) {
	return a.w.Write(p)
}

// Commit flushes, applies the captured mode and ownership to the temp file, and
// renames it over the destination. Ownership is best-effort: a caller that can
// write the file but cannot chown it keeps the temp file's owner and still gets
// the original mode.
func (a *atomicFile) Commit() error {
	if a.done {
		return nil
	}
	// Flush the buffered writes down to the fd before any of the metadata and
	// durability steps below act on it.
	if err := a.w.Flush(); err != nil {
		return a.fail(err)
	}
	// Apply mode and ownership through the fd so the staged file is never
	// briefly installed with the wrong permissions.
	if err := a.Chmod(a.mode); err != nil {
		return a.fail(err)
	}
	if a.chown {
		if err := a.Chown(a.uid, a.gid); err != nil && !errors.Is(err, os.ErrPermission) {
			return a.fail(err)
		}
	}
	// Sync before the rename: these files are reboot-persistence-critical
	// (csf.conf, iptables save files), and a crash could otherwise reorder the
	// rename ahead of the data reaching disk, installing a truncated config.
	if err := a.Sync(); err != nil {
		return a.fail(err)
	}
	if err := a.Close(); err != nil {
		return a.fail(err)
	}
	// Install the staged file.
	if err := os.Rename(a.tmp, a.dst); err != nil {
		_ = os.Remove(a.tmp)
		a.done = true
		return err
	}
	a.done = true
	return nil
}

// Abort discards the temp file. It is a no-op after a successful Commit, so a
// caller may defer Abort immediately after opening.
func (a *atomicFile) Abort() {
	if a.done {
		return
	}
	_ = a.Close()
	_ = os.Remove(a.tmp)
	a.done = true
}

// fail closes and removes the temp file, then returns the triggering error.
func (a *atomicFile) fail(err error) error {
	_ = a.Close()
	_ = os.Remove(a.tmp)
	a.done = true
	return err
}

// writeConfigFile atomically replaces path with data for callers that already
// hold the whole file in memory, preserving the existing file's mode and
// ownership (falling back to defaultMode for a file that does not yet exist).
func writeConfigFile(path string, data []byte, defaultMode os.FileMode) error {
	af, err := newAtomicFile(path, defaultMode)
	if err != nil {
		return err
	}
	defer af.Abort()
	if _, err := af.Write(data); err != nil {
		return err
	}
	return af.Commit()
}
