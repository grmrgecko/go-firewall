package firewall

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// prefixedComment splits a stored comment into user text and a prefix signal: a
// prefix-only tag has the prefix with empty text, a "prefix text" comment has the
// prefix with the remainder, anything else lacks the prefix and is unchanged, and
// an empty prefix yields no prefix signal (callers treat that as covering
// everything).
func TestPrefixedComment(t *testing.T) {
	cases := []struct {
		prefix, stored string
		wantText       string
		wantHasPrefix  bool
	}{
		{"myapp", "myapp", "", true},
		{"myapp", "myapp https", "https", true},
		{"myapp", "someone else's note", "someone else's note", false},
		{"myapp", "", "", false},
		{"", "anything at all", "anything at all", false},
	}
	for _, c := range cases {
		text, hasPrefix := prefixedComment(c.prefix, c.stored)
		require.Equal(t, c.wantText, text, "text for (%q,%q)", c.prefix, c.stored)
		require.Equal(t, c.wantHasPrefix, hasPrefix, "hasPrefix for (%q,%q)", c.prefix, c.stored)
	}
}
