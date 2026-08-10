//go:build unix

package firewall

import (
	"os"
	"syscall"
)

// statOwner extracts the uid and gid from a Unix FileInfo. The final return is
// false when the underlying stat data is unavailable, leaving ownership
// unchanged on Commit.
func statOwner(fi os.FileInfo) (uid, gid int, ok bool) {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return int(st.Uid), int(st.Gid), true
	}
	return 0, 0, false
}
