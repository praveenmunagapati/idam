package provider

import "github.com/homebot/core/urn"

// Authenticator authenticates a client using a password
type Authenticator interface {
	// Verify verifies if `password` is valid for `client`
	// If authenticating `client` requires a one-time-password, `otp` should
	// be specified as well
	Verify(client urn.URN, password string, otp string) (bool, error)
}
