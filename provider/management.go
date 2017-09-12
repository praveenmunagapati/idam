package provider

import (
	"github.com/homebot/core/urn"
	"github.com/homebot/idam"
)

type IdentityManager interface {
	Authenticator

	Provider

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
}
