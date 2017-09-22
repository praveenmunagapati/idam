package file

import (
	"encoding/json"
	"errors"
	"io/ioutil"
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

	roles []string
}

type Data struct {
	Identities map[urn.URN]*idam.Identity `json:"identities"`
	OtpSecrets map[urn.URN]string         `json:"otps"`
	Passwords  map[urn.URN][]byte         `json:"passwords"`
	Roles      []string                   `json:"roles"`
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
	m.roles = d.Roles

	return nil
}

func (m *FileProvider) write() error {
	os.Remove(m.path)

	d := Data{
		Passwords:  m.passwords,
		Identities: m.identities,
		OtpSecrets: m.otpSecrets,
		Roles:      m.roles,
	}

	blob, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return err
	}

	return ioutil.WriteFile(m.path, blob, 0600)
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

// VerifyPassword verifies the identities password
func (m *FileProvider) VerifyPassword(u urn.URN, pass string) (bool, error) {
	m.rw.RLock()
	defer m.rw.RUnlock()

	if _, ok := m.identities[u]; !ok {
		return false, provider.ErrIdentityNotFound
	}

	if p, ok := m.passwords[u]; ok {
		if bcrypt.CompareHashAndPassword(p, []byte(pass)) != nil {
			return false, nil
		}
	}

	return true, nil
}

// VerifyOTP verifies the identities one-time-password
func (m *FileProvider) VerifyOTP(u urn.URN, pass string) (bool, error) {
	m.rw.RLock()
	defer m.rw.RUnlock()

	if _, ok := m.identities[u]; !ok {
		return false, provider.ErrIdentityNotFound
	}

	if o, ok := m.otpSecrets[u]; ok {
		if !totp.Validate(pass, o) {
			return false, nil
		}

		return true, nil
	}

	return false, provider.Err2FANotEnabled
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

// ChangePassword changes an identities password
func (m *FileProvider) ChangePassword(u urn.URN, newPassword string) error {
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
	return m.write()
}

// Disable2FA disables two-factor authentication
func (m *FileProvider) Disable2FA(u urn.URN) error {
	m.rw.Lock()
	defer m.rw.Unlock()

	if _, ok := m.identities[u]; !ok {
		return provider.ErrIdentityNotFound
	}

	if _, ok := m.otpSecrets[u]; !ok {
		return provider.Err2FANotEnabled
	}

	delete(m.otpSecrets, u)
	return m.write()
}

// Enable2FA enables two-factor-authentication
func (m *FileProvider) Enable2FA(u urn.URN) (string, error) {
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
	return key.Secret(), m.write()
}

// Update updates the identity
func (m *FileProvider) Update(u urn.URN, ident idam.Identity) error {
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

	original.Roles = make([]string, len(ident.Roles))
	for i, g := range ident.Roles {
		original.Roles[i] = g
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

	return m.write()
}

func (m *FileProvider) containsRole(r string) bool {
	return contains(m.roles, r)
}

func contains(arr []string, needle string) bool {
	for _, v := range arr {
		if v == needle {
			return true
		}
	}
	return false
}

// CreateRole creates a new role
func (m *FileProvider) CreateRole(r string) error {
	m.rw.Lock()
	defer m.rw.Unlock()

	if m.containsRole(r) {
		return nil
	}

	m.roles = append(m.roles, r)

	return m.write()
}

func (m *FileProvider) IdentitiesByRole(r string) []idam.Identity {
	m.rw.RLock()
	defer m.rw.RUnlock()

	var identities []idam.Identity

	for _, v := range m.identities {
		if contains(v.Roles, r) {
			identities = append(identities, *v)
		}
	}

	return identities
}

// DeleteRole deletes a role
func (m *FileProvider) DeleteRole(r string) error {
	m.rw.RLock()
	has := m.containsRole(r)
	m.rw.RUnlock()

	if !has {
		return nil
	}

	m.rw.Lock()
	defer m.rw.Unlock()

	var roles []string
	for _, role := range m.roles {
		if role != r {
			roles = append(roles, role)
		}
	}

	m.roles = roles
	return m.write()
}

// GetRoles returns a list of roles
func (m *FileProvider) GetRoles() []string {
	m.rw.RLock()
	defer m.rw.RUnlock()

	var roles []string
	for _, role := range m.roles {
		roles = append(roles, role)
	}

	return roles
}

// HasRole checks if the provider has a given role
func (m *FileProvider) HasRole(r string) bool {
	for _, role := range m.GetRoles() {
		if r == role {
			return true
		}
	}

	return false
}
