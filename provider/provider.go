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

	// Err2FANotEnabled is returned when two-factor-authentication is disabled
	Err2FANotEnabled = errors.New("2FA not enabled")
)

type IdentityManager interface {
	Authenticator

	// Create creates a new identity with the given password and
	// optionally enables OTP for the identity
	Create(identity idam.Identity, password string, opt bool) (optSecret string, err error)

	// Delete deletes `identity`
	Delete(identity urn.URN) error

	// ChangePassword changes the identities password
	ChangePassword(identity urn.URN, newPassword string) error

	// Enable2FA enables two factor authentication
	Enable2FA(identity urn.URN) (string, error)

	// Disable2FA disables two factor authentication
	Disable2FA(identity urn.URN) error

	// Update updates the identity with new data
	Update(identity urn.URN, update idam.Identity) error

	// Identities returns all identities the provider knows about
	Identities() []*idam.Identity

	// Get returns the identity for the URN and
	// a boolean indicating if the user has 2FA enabled or not
	Get(urn.URN) (*idam.Identity, bool, error)

	// GetByName returns the identity with the given name and
	// a boolean indicating if the user has 2FA enabled or not
	GetByName(string) (*idam.Identity, bool, error)
}
