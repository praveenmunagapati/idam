package provider

import (
	"errors"
	"sync"

	"github.com/homebot/core/urn"
	"github.com/homebot/idam"
)

var (
	// ErrIdentityNotFound is returned when no identity matching the criteria can be found
	ErrIdentityNotFound = errors.New("unknown identitiy")

	// ErrDuplicateIdentity is returned if an identity with the same URN is already stored
	// in the provider
	ErrDuplicateIdentity = errors.New("duplicated itentity")
)

// Provider for identities
type Provider interface {
	// Identities returns all identities the provider knows about
	Identities() []*idam.Identity

	// Get returns the identity for the URN
	Get(urn.URN) (*idam.Identity, error)

	// GetByName returns the identity with the given name
	GetByName(string) (*idam.Identity, error)

	// Save adds a new identity
	Save(*idam.Identity) error
}

// Memory is an in-memory identity provider
type Memory struct {
	rw sync.RWMutex

	identities map[urn.URN]*idam.Identity
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

	return nil, ErrIdentityNotFound
}

// GetByName returns the identity with the given name
func (m *Memory) GetByName(n string) (*idam.Identity, error) {
	u := urn.IdamIdentityResource.BuildURN("", n, n)
	return m.Get(u)
}

// Save a new identity in the memory provider
func (m *Memory) Save(i *idam.Identity) error {
	m.rw.Lock()
	defer m.rw.Unlock()

	if _, ok := m.identities[i.URN()]; ok {
		return ErrDuplicateIdentity
	}

	m.identities[i.URN()] = &(*i)

	return nil
}
