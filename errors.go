package idam

import "errors"

// Error definitions for identity and access management errors
var (
	ErrNotAuthenticated = errors.New("not authenticated")
	ErrNotAllowed       = errors.New("not allowed")
)
