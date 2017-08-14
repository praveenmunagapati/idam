package idam

import "github.com/homebot/core/urn"

type Action string

var (
	ActionRead  = Action("read")
	ActionWrite = Action("write")
)

// Authorizer is used to verify a given subject has permissions to operate on an object
type Authorizer interface {
	// Allowed checks if `subject` is allowed to perform `action` on `object`
	Allowed(Identity, Action, urn.URN) bool
}
