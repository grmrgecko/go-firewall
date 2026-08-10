//go:build unix

package firewall

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"
)

// noTempLeftover asserts the staging directory holds no uncommitted temp files.
func noTempLeftover(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	for _, e := range entries {
		require.NotContains(t, e.Name(), ".tmp.", "a staged temp file was left behind")
	}
}

// TestAtomicFilePreservesMode confirms a rewrite of an existing file keeps its
// non-default permission mode rather than resetting to the caller's default.
func TestAtomicFilePreservesMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "conf")
	require.NoError(t, os.WriteFile(path, []byte("old\n"), 0600))
	require.NoError(t, os.Chmod(path, 0640))

	af, err := newAtomicFile(path, 0644)
	require.NoError(t, err)
	_, err = af.Write([]byte("new\n"))
	require.NoError(t, err)
	require.NoError(t, af.Commit())

	fi, err := os.Stat(path)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0640), fi.Mode().Perm(), "existing mode must be preserved")

	got, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, "new\n", string(got))
	noTempLeftover(t, dir)
}

// TestAtomicFileNewFileUsesDefaultMode confirms a file that does not yet exist
// is created with the supplied default mode.
func TestAtomicFileNewFileUsesDefaultMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "new-conf")

	af, err := newAtomicFile(path, 0600)
	require.NoError(t, err)
	_, err = af.Write([]byte("content\n"))
	require.NoError(t, err)
	require.NoError(t, af.Commit())

	fi, err := os.Stat(path)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0600), fi.Mode().Perm())
	noTempLeftover(t, dir)
}

// TestAtomicFileAbortLeavesOriginal confirms Abort discards the staged rewrite
// and leaves the original file and its content untouched.
func TestAtomicFileAbortLeavesOriginal(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "conf")
	require.NoError(t, os.WriteFile(path, []byte("original\n"), 0644))

	af, err := newAtomicFile(path, 0644)
	require.NoError(t, err)
	_, err = af.Write([]byte("discarded\n"))
	require.NoError(t, err)
	af.Abort()

	got, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, "original\n", string(got), "Abort must not modify the original")
	noTempLeftover(t, dir)
}

// TestAtomicFileAbortAfterCommitIsNoOp confirms a deferred Abort after a
// successful Commit does not remove the installed file.
func TestAtomicFileAbortAfterCommitIsNoOp(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "conf")

	af, err := newAtomicFile(path, 0644)
	require.NoError(t, err)
	_, err = af.Write([]byte("kept\n"))
	require.NoError(t, err)
	require.NoError(t, af.Commit())
	af.Abort() // Must be inert.

	got, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, "kept\n", string(got))
}

// TestWriteConfigFilePreservesMode confirms the buffer-all convenience wrapper
// preserves an existing file's mode.
func TestWriteConfigFilePreservesMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "conf")
	require.NoError(t, os.WriteFile(path, []byte("x"), 0600))
	require.NoError(t, os.Chmod(path, 0640))

	require.NoError(t, writeConfigFile(path, []byte("y\n"), 0644))

	fi, err := os.Stat(path)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0640), fi.Mode().Perm())
	got, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, "y\n", string(got))
	noTempLeftover(t, dir)
}

// TestAtomicFilePreservesOwner confirms a rewrite restores the original file's
// ownership. It requires root to assign a foreign owner, so it is skipped for an
// unprivileged run.
func TestAtomicFilePreservesOwner(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root to chown to a foreign owner")
	}
	const uid, gid = 65534, 65534 // nobody/nogroup on most systems.
	dir := t.TempDir()
	path := filepath.Join(dir, "conf")
	require.NoError(t, os.WriteFile(path, []byte("old\n"), 0644))
	require.NoError(t, os.Chown(path, uid, gid))

	require.NoError(t, writeConfigFile(path, []byte("new\n"), 0644))

	fi, err := os.Stat(path)
	require.NoError(t, err)
	st, ok := fi.Sys().(*syscall.Stat_t)
	require.True(t, ok)
	require.Equal(t, uint32(uid), st.Uid, "owner uid must be preserved")
	require.Equal(t, uint32(gid), st.Gid, "owner gid must be preserved")
}

// TestAtomicFileStagesInDestinationDir confirms the temp file is created next to
// the destination so the final rename is atomic within one filesystem.
func TestAtomicFileStagesInDestinationDir(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "conf")

	af, err := newAtomicFile(path, 0644)
	require.NoError(t, err)
	require.Equal(t, dir, filepath.Dir(af.tmp))
	require.True(t, strings.HasPrefix(filepath.Base(af.tmp), "conf.tmp."))
	af.Abort()
}

// readConfValue must not truncate a quoted value containing '#', and the last
// assignment of a key wins, matching the shell that sources these files.
func TestReadConfValueQuotingAndLastAssignment(t *testing.T) {
	path := filepath.Join(t.TempDir(), "conf")
	body := `
# A comment line.
PREFIX = "pre#fix"  # trailing comment
USE_IPV6 = "0"
USE_IPV6 = "1"
`
	require.NoError(t, os.WriteFile(path, []byte(body), 0644))

	v, err := readConfValue(path, "PREFIX")
	require.NoError(t, err)
	require.Equal(t, "pre#fix", v, "a '#' inside quotes is part of the value")

	v, err = readConfValue(path, "USE_IPV6")
	require.NoError(t, err)
	require.Equal(t, "1", v, "the last assignment wins")

	v, err = readConfValue(path, "MISSING")
	require.NoError(t, err)
	require.Equal(t, "", v)
}
