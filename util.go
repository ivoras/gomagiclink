package gomagiclink

import (
	"strings"
)

func NormalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}
