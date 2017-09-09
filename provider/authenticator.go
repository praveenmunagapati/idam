package provider

// Authenticator authenticates a client using a password
type Authenticator interface {
	// Has returns true if the authenticator has a secret for `client`
	Has(client string) bool

	// Verify verifies if `password` is valid for `client`
	Verify(client string, password string) (bool, error)
}
