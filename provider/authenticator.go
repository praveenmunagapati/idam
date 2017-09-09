package provider

import "github.com/homebot/core/urn"

// Authenticator authenticates a client using a password
type Authenticator interface {
	// Verify verifies if `password` is valid for `client`
	Verify(client urn.URN, password string) (bool, error)
}
