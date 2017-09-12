package memory

import (
	"errors"
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

// New creates a new in-memory IdentityManager
func New() *Memory {
	return &Memory{
		identities: make(map[urn.URN]*idam.Identity),
		otpSecrets: make(map[urn.URN]string),
		passwords:  make(map[urn.URN][]byte),
	}
}

// Verify authenticates `u` using `password` and, if OTP is used, `currentOTP`
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
func (m *Memory) Get(u urn.URN) (*idam.Identity, bool, error) {
	m.rw.RLock()
	defer m.rw.RUnlock()

	i, ok := m.identities[u]
	if !ok {
		return nil, false, provider.ErrIdentityNotFound
	}

	_, hasOTP := m.otpSecrets[u]

	return &(*i), hasOTP, nil
}

// GetByName returns the identity with the given name
func (m *Memory) GetByName(n string) (*idam.Identity, bool, error) {
	u := urn.IdamIdentityResource.BuildURN("", n, n)
	return m.Get(u)
}

// Create a new identity in the memory provider
func (m *Memory) Create(i idam.Identity, password string, enableOTP bool) (string, error) {
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

	m.identities[i.URN()] = &i
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

// ChangePassword changes an identities password
func (m *Memory) ChangePassword(u urn.URN, newPassword string) error {
	m.rw.Lock()
	defer m.rw.Unlock()

	if _, ok := m.identities[u]; !ok {
		return provider.ErrIdentityNotFound
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	m.passwords[u] = hash
	return nil
}

// Disable2FA disables two-factor authentication
func (m *Memory) Disable2FA(u urn.URN) error {
	m.rw.Lock()
	defer m.rw.Unlock()

	if _, ok := m.identities[u]; !ok {
		return provider.ErrIdentityNotFound
	}

	if _, ok := m.otpSecrets[u]; !ok {
		return provider.Err2FANotEnabled
	}

	delete(m.otpSecrets, u)
	return nil
}

// Enable2FA enables two-factor-authentication
func (m *Memory) Enable2FA(u urn.URN) (string, error) {
	m.rw.Lock()
	defer m.rw.Unlock()

	if _, ok := m.identities[u]; !ok {
		return "", provider.ErrIdentityNotFound
	}

	if _, ok := m.otpSecrets[u]; !ok {
		// Already enabled, return the OTP secret
		return m.otpSecrets[u], nil
	}

	var err error
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "idam",
		AccountName: u.AccountID(),
	})
	if err != nil {
		return "", err
	}

	m.otpSecrets[u] = key.Secret()
	return key.Secret(), nil
}

// Update updates the identity
func (m *Memory) Update(u urn.URN, ident idam.Identity) error {
	m.rw.Lock()
	defer m.rw.Unlock()

	original, ok := m.identities[u]
	if !ok {
		return provider.ErrIdentityNotFound
	}

	if original.Name != ident.Name {
		return errors.New("cannot change identitiy name")
	}

	if original.Type != ident.Type {
		return errors.New("cannot change identity type")
	}

	original.Groups = make([]urn.URN, len(ident.Groups))
	for i, g := range ident.Groups {
		original.Groups[i] = g
	}

	original.Labels = make(map[string]string)
	for k, l := range ident.Labels {
		original.Labels[k] = l
	}

	if original.IsUser() {
		if ident.UserData != nil {
			mails := make([]string, len(ident.UserData.SecondaryMails))
			for i, m := range ident.UserData.SecondaryMails {
				mails[i] = m
			}

			original.UserData = &idam.UserData{
				PrimaryMail:    ident.UserData.PrimaryMail,
				FirstName:      ident.UserData.FirstName,
				LastName:       ident.UserData.LastName,
				SecondaryMails: mails,
			}
		} else {
			original.UserData = nil
		}
	}

	return nil
}
