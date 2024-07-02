package gomagiclink

import (
	"strings"

	"github.com/oklog/ulid/v2"
)

var zeroULID ulid.ULID

func IsZeroULID(u ulid.ULID) bool {
	return u.Compare(zeroULID) == 0
}

func NormalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}
