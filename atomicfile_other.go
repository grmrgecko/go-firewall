//go:build !unix

package firewall

import "os"

// statOwner reports no ownership on platforms without Unix stat data, so Commit
// leaves the temp file's ownership unchanged.
func statOwner(fi os.FileInfo) (uid, gid int, ok bool) {
	return 0, 0, false
}
