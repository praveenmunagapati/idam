package memory

import (
	"sync"

	"golang.org/x/crypto/bcrypt"

	"github.com/homebot/core/urn"
	"github.com/homebot/idam"
	"github.com/homebot/idam/provider"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

// Memory is an in-memory IdentityManager for Homebot
// It is mainly used during testing and should not be used
// in production
type Memory struct {
	rw sync.RWMutex

	identities map[urn.URN]*idam.Identity
	otpSecrets map[urn.URN]string
	passwords  map[urn.URN][]byte
}

// Verify authenticates `u` using `password` and, if used, `currentOTP`
// It implements provider.Authenticator
func (m *Memory) Verify(u urn.URN, password, currentOTP string) (bool, error) {
	m.rw.RLock()
	defer m.rw.RUnlock()

	if _, ok := m.identities[u]; !ok {
		return false, provider.ErrIdentityNotFound
	}

	if p, ok := m.passwords[u]; ok {
		if bcrypt.CompareHashAndPassword(p, []byte(password)) != nil {
			return false, nil
		}
	}

	if o, ok := m.otpSecrets[u]; ok {
		if !totp.Validate(currentOTP, o) {
			return false, nil
		}
	}

	return true, nil
}

// Identities returns all identities stored in the
// memory provider. It implements the Provider interface
func (m *Memory) Identities() []*idam.Identity {
	var res []*idam.Identity

	m.rw.RLock()
	defer m.rw.RUnlock()

	for _, i := range m.identities {
		identity := *i
		res = append(res, &identity)
	}
	return res
}

// Get returns the identity with the given URN
func (m *Memory) Get(u urn.URN) (*idam.Identity, error) {
	m.rw.RLock()
	defer m.rw.RUnlock()

	if i, ok := m.identities[u]; ok {
		return &(*i), nil
	}

	return nil, provider.ErrIdentityNotFound
}

// GetByName returns the identity with the given name
func (m *Memory) GetByName(n string) (*idam.Identity, error) {
	u := urn.IdamIdentityResource.BuildURN("", n, n)
	return m.Get(u)
}

// Create a new identity in the memory provider
func (m *Memory) Create(i *idam.Identity, password string, enableOTP bool) (string, error) {
	m.rw.Lock()
	defer m.rw.Unlock()

	if _, ok := m.identities[i.URN()]; ok {
		return "", provider.ErrDuplicateIdentity
	}

	var key *otp.Key

	if enableOTP {
		var err error
		key, err = totp.Generate(totp.GenerateOpts{
			Issuer:      "idam",
			AccountName: i.Name,
		})
		if err != nil {
			return "", err
		}
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}

	m.identities[i.URN()] = &(*i)
	m.passwords[i.URN()] = hash

	if key != nil {
		m.otpSecrets[i.URN()] = key.Secret()
		return key.Secret(), nil
	}

	return "", nil
}

// Delete deletes the identity with URN `u`
func (m *Memory) Delete(u urn.URN) error {
	m.rw.Lock()
	defer m.rw.Unlock()

	if _, ok := m.identities[u]; !ok {
		return provider.ErrIdentityNotFound
	}

	delete(m.identities, u)
	delete(m.passwords, u)
	delete(m.otpSecrets, u)

	return nil
}
