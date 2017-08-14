package idam

import "context"

// Authenticator authenticates an identity
type Authenticator interface {
	From(context.Context) (*Identity, error)
}
