package useragent

import (
	"fmt"

	"github.com/google/uuid"
)

// Has to be in a separate package to avoid circular dependencies

// Default user agent prefix
var StratusUserAgentPrefix = "stratus-red-team"

// SetUserAgentPrefix allows overriding the default user agent prefix
func SetUserAgentPrefix(prefix string) {
	StratusUserAgentPrefix = prefix
}

// GetUserAgentPrefix returns the current user agent prefix
func GetUserAgentPrefix() string {
	return StratusUserAgentPrefix
}

func GetStratusUserAgentForUUID(uuid uuid.UUID) string {
	return fmt.Sprintf("%s_%s", StratusUserAgentPrefix, uuid.String())
}
