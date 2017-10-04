package server

import (
	"errors"
	"strings"
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
func New(i idam.IdentityProvider, r idam.RoleProvider, p idam.PermissionProvider, opts ...Option) (*Manager, error) {
	m := &Manager{
		roles:       r,
		identities:  i,
		permissions: p,
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

func (m *Manager) IsResourceOwner(resource, identity string, permissions []string) (bool, error) {
	if resource == identity {
		return true, nil
	}

	if strings.HasPrefix(resource, idam.IdentityPrefixUser) || strings.HasPrefix(resource, idam.IdentityPrefixGroup) || strings.HasPrefix(resource, idam.IdentityPrefixSerivce) {
		ident, err := m.identities.Get(resource)
		if err != nil {
			return false, err
		}

		if ident.Metadata().Creator == identity {
			return true, nil
		}
	}

	if strings.HasPrefix(resource, "role") {
		role, err := m.roles.Get(resource)
		if err != nil {
			return false, err
		}

		if role.Creator == identity {
			return true, nil
		}
	}

	if strings.HasPrefix(resource, "permission") {
		perm, err := m.permissions.Get(resource)
		if err != nil {
			return false, err
		}

		if perm.Creator == identity {
			return true, nil
		}
	}

	return false, nil
}

func (m *Manager) getPermissions(i string) ([]idam.Permission, error) {
	var res []idam.Permission

	identity, err := m.identities.Get(i)
	if err != nil {
		return nil, err
	}

	for _, r := range identity.Roles() {
		role, err := m.roles.Get(r)
		if err != nil {
			return nil, err
		}

		for _, p := range role.Permissions {
			perm, err := m.permissions.Get(p)
			if err != nil {
				return nil, err
			}

			res = append(res, *perm)
		}
	}

	// now collect group permissions
	for _, g := range identity.Groups() {
		groupPermissions, err := m.getPermissions(g)
		if err != nil {
			return nil, err
		}

		res = append(res, groupPermissions...)
	}

	var distinct []idam.Permission

L:
	for _, p := range res {
		for _, c := range distinct {
			if p.Name == c.Name {
				continue L
			}
		}

		distinct = append(distinct, p)
	}

	return res, nil
}

func (m *Manager) getPermissionNames(i string) ([]string, error) {
	perms, err := m.getPermissions(i)
	if err != nil {
		return nil, err
	}

	var res []string
	for _, p := range perms {
		res = append(res, p.Name)
	}

	return res, nil
}
