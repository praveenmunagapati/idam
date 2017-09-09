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

	ErrAuthenticationFailed = errors.New("authentication failed")
)

// Provider for identities
type Provider interface {
	// Identities returns all identities the provider knows about
	Identities() []*idam.Identity

	// Get returns the identity for the URN
	Get(urn.URN) (*idam.Identity, error)

	// GetByName returns the identity with the given name
	GetByName(string) (*idam.Identity, error)

	// Save adds a new identity
	Save(*idam.Identity) error
}
