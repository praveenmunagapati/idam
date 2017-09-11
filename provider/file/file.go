package file

import (
	"encoding/json"
	"os"
	"sync"

	"golang.org/x/crypto/bcrypt"

	"github.com/homebot/core/urn"
	"github.com/homebot/idam"
	"github.com/homebot/idam/provider"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

// FileProvider is an file based IdentityManager for Homebot
// It is mainly used during testing and should not be used
// in production
type FileProvider struct {
	rw sync.RWMutex

	path string

	identities map[urn.URN]*idam.Identity
	otpSecrets map[urn.URN]string
	passwords  map[urn.URN][]byte
}

type Data struct {
	Identities map[urn.URN]*idam.Identity `json:"identities"`
	OtpSecrets map[urn.URN]string         `json:"otps"`
	Passwords  map[urn.URN][]byte         `json:"passwords"`
}

// New creates a new file based IdentityManager
func New(path string) *FileProvider {
	file := &FileProvider{
		path:       path,
		identities: make(map[urn.URN]*idam.Identity),
		otpSecrets: make(map[urn.URN]string),
		passwords:  make(map[urn.URN][]byte),
	}

	file.read()

	return file
}

func (m *FileProvider) read() error {
	f, err := os.Open(m.path)
	if err != nil {
		return err
	}
	defer f.Close()

	decoder := json.NewDecoder(f)
	var d Data

	if err := decoder.Decode(&d); err != nil {
		return err
	}

	m.passwords = d.Passwords
	m.identities = d.Identities
	m.otpSecrets = d.OtpSecrets

	return nil
}

func (m *FileProvider) write() error {
	os.Remove(m.path)

	f, err := os.Create(m.path)
	if err != nil {
		return err
	}
	defer f.Close()

	d := Data{
		Passwords:  m.passwords,
		Identities: m.identities,
		OtpSecrets: m.otpSecrets,
	}

	encoder := json.NewEncoder(f)
	if err := encoder.Encode(d); err != nil {
		return err
	}

	return nil
}

// Verify authenticates `u` using `password` and, if OTP is used, `currentOTP`
// It implements provider.Authenticator
func (m *FileProvider) Verify(u urn.URN, password, currentOTP string) (bool, error) {
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
// FileProvider provider. It implements the Provider interface
func (m *FileProvider) Identities() []*idam.Identity {
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
func (m *FileProvider) Get(u urn.URN) (*idam.Identity, bool, error) {
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
func (m *FileProvider) GetByName(n string) (*idam.Identity, bool, error) {
	u := urn.IdamIdentityResource.BuildURN("", n, n)
	return m.Get(u)
}

// Create a new identity in the file provider
func (m *FileProvider) Create(i idam.Identity, password string, enableOTP bool) (string, error) {
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
	}

	err = m.write()

	if key != nil {
		return key.Secret(), err
	}

	return "", err
}

// Delete deletes the identity with URN `u`
func (m *FileProvider) Delete(u urn.URN) error {
	m.rw.Lock()
	defer m.rw.Unlock()

	if _, ok := m.identities[u]; !ok {
		return provider.ErrIdentityNotFound
	}

	delete(m.identities, u)
	delete(m.passwords, u)
	delete(m.otpSecrets, u)

	return m.write()
}
