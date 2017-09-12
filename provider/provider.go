package provider

import (
	"errors"

	"github.com/homebot/core/urn"
	"github.com/homebot/idam"
)

var (
	// ErrIdentityNotFound is returned when no identity matching the criteria can be found
	ErrIdentityNotFound = errors.New("unknown identitiy")

	// ErrDuplicateIdentity is returned if an identity with the same URN is already stored
	// in the provider
	ErrDuplicateIdentity = errors.New("duplicated itentity")

	Err2FANotEnabled = errors.New("2FA not enabled")
)

// Provider for identities
type Provider interface {
	// Identities returns all identities the provider knows about
	Identities() []*idam.Identity

	// Get returns the identity for the URN and
	// a boolean indicating if the user has 2FA enabled or not
	Get(urn.URN) (*idam.Identity, bool, error)

	// GetByName returns the identity with the given name and
	// a boolean indicating if the user has 2FA enabled or not
	GetByName(string) (*idam.Identity, bool, error)
}
