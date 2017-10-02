package server

import (
	"errors"
	"time"

	"github.com/homebot/core/log"
	"github.com/homebot/idam"
)

// Manager implements the gRPC Identity Manager Server interface
type Manager struct {
	identities  idam.IdentityProvider
	roles       idam.RoleProvider
	permissions idam.PermissionProvider

	alg           string
	signingKey    []byte
	signingCert   []byte
	issuer        string
	tokenDuration time.Duration
	log           log.Logger
}

// New creates a new manager server
func New(p provider.IdentityManager, opts ...Option) (*Manager, error) {
	m := &Manager{
		idam: p,
	}

	for _, fn := range opts {
		if err := fn(m); err != nil {
			return nil, err
		}
	}

	if len(m.signingCert) == 0 || len(m.signingKey) == 0 {
		return nil, errors.New("no secret provided")
	}

	if m.issuer == "" {
		m.issuer = "idam"
	}

	if m.tokenDuration == time.Duration(0) {
		m.tokenDuration = time.Hour
	}

	if m.log == nil {
		m.log = log.SimpleLogger{}
	}

	return m, nil
}

// VerificationKey returns the JWT token verification key and implements policy.JWTKeyVerifier
func (m *Manager) VerificationKey(issuer string, alg string) (interface{}, error) {
	return m.signingCert, nil
}
