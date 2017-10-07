package server

import (
	"time"

	"github.com/homebot/insight/logger"
)

// Option configures a new manager
type Option func(m *Manager) error

// WithSharedKey configures a shared key for siging and verifying JWTs
func WithSharedKey(key string) Option {
	return func(m *Manager) error {
		m.signingCert = []byte(key)
		m.signingKey = []byte(key)
		m.alg = "HS256"
		return nil
	}
}

// WithLogger configures the logger to use
func WithLogger(l logger.Logger) Option {
	return func(m *Manager) error {
		m.log = l
		return nil
	}
}

// WithIssuer configures the name of the issuer for new JWTs
func WithIssuer(s string) Option {
	return func(m *Manager) error {
		m.issuer = s
		return nil
	}
}

// WithTokenDuration configures how long a JWT is valid until it is marked
// as expired
func WithTokenDuration(d time.Duration) Option {
	return func(m *Manager) error {
		m.tokenDuration = d
		return nil
	}
}
