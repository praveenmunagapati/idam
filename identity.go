package idam

import (
	"github.com/homebot/core/urn"
)

// Identity is an identity in the homebot
type Identity struct {
	urn.Resource

	accountID string
}

// Authenticated returns true if the identity is authenticated
// against Idam
func (i *Identity) Authenticated() bool {
	return false
}

// URN returns the URN for the identiy
func (i *Identity) URN() urn.URN {
	return urn.IdamIdentityResource.BuildURN("", i.accountID, i.accountID)
}

// DummyIdentity is a dummy identity to be used by services
// not yet supporting Idam based authentication
var DummyIdentity = Identity{
	accountID: "dummy",
}
