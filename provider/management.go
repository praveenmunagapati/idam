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
}
