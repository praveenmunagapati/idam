package file

import (
	"errors"
	"sync"

	"github.com/homebot/idam"
)

// TODO(ppacher): really save the identities to a file

// IdentityProvider is a idam.IdentityProvider that persists identities to
// files
type IdentityProvider struct {
	filename   string
	lock       sync.RWMutex
	identities []idam.Identity
	passwords  map[string][]byte
	secrets    map[string]string
}

// NewIdentityProvider creates a new identity provider that perisists identities to
// files
func NewIdentityProvider(name string) idam.IdentityProvider {
	return &IdentityProvider{
		filename: name,
	}
}

// New creates a new identity and implements idam.IdentityProvider
func (provider *IdentityProvider) New(i idam.Identity, pass []byte) (idam.Identity, error) {
	provider.lock.Lock()
	defer provider.lock.Unlock()

	if has, ok := provider.getIdentity(i.AccountName()); ok {
		copy, err := copyIdentiy(has)
		if err != nil {
			return nil, err
		}

		return copy, idam.ErrIdentityExists
	}

	// make sure that we have a group identity for each group the
	// new identity belongs to
	for _, g := range i.Groups() {
		if _, ok := provider.getGroup(g); !ok {
			return nil, idam.ErrUnknownIdentity
		}
	}

	newIdentity, err := copyIdentiy(i)
	if err != nil {
		return nil, err
	}

	// Save new identity
	provider.identities = append(provider.identities, newIdentity)

	// Add password hash if given
	if pass != nil {
		if provider.passwords == nil {
			provider.passwords = make(map[string][]byte)
		}

		provider.passwords[newIdentity.AccountName()] = pass
	}

	// now add the identity to all group identities
	for _, name := range newIdentity.Groups() {
		g, ok := provider.getGroup(name)
		if !ok {
			return nil, errors.New("unexpected error: group does not exist")
		}

		if err := g.AddMember(newIdentity.AccountName()); err != nil {
			return nil, err
		}
	}

	return copyIdentiy(newIdentity)
}

// Delete deletes an identity and implements idam.IdentityProvider
func (provider *IdentityProvider) Delete(name string) error {
	provider.lock.Lock()
	defer provider.lock.Unlock()

	del, ok := provider.getIdentity(name)
	if !ok {
		return idam.ErrUnknownIdentity
	}

	var newIdentities []idam.Identity

	for _, i := range provider.identities {
		if i.AccountName() != del.AccountName() {
			newIdentities = append(newIdentities, i)
		}
	}

	provider.identities = newIdentities

	if provider.secrets != nil {
		delete(provider.secrets, del.AccountName())
	}

	if provider.passwords != nil {
		delete(provider.passwords, del.AccountName())
	}

	// Remove the account from all group identities
	for _, g := range del.Groups() {
		if grp, ok := provider.getGroup(g); ok {
			grp.DeleteMember(del.AccountName())
		}
	}

	if idam.IsGroup(del) {
		for _, i := range provider.identities {
			if idam.HasGroup(i, del.AccountName()) {
				idam.DeleteGroup(i, del.AccountName())
				if _, err := provider.update(i); err != nil {
					return err
				}
			}
		}
	}

	return nil
}

// Update updates an existing identity and implements idam.IdentityProvider
func (provider *IdentityProvider) Update(i idam.Identity) (idam.Identity, error) {
	provider.lock.Lock()
	defer provider.lock.Unlock()

	return provider.update(i)
}

func (provider *IdentityProvider) update(i idam.Identity) (idam.Identity, error) {
	original, ok := provider.getIdentity(i.AccountName())
	if !ok {
		return nil, idam.ErrUnknownIdentity
	}

	switch original.(type) {
	case *idam.User:
		if !idam.IsUser(i) {
			return nil, errors.New("cannot change identity type")
		}
	case *idam.Group:
		if !idam.IsGroup(i) {
			return nil, errors.New("cannot change identity type")
		}
	default:
		return nil, errors.New("unsupported identity type")
	}

	updatedIdentity, err := copyIdentiy(i)
	if err != nil {
		return nil, err
	}

	newGroups, deletedGroups := diffSlice(original.Groups(), i.Groups())

	hasAllGroups := func(grps []string) bool {
		for _, g := range grps {
			if _, ok := provider.getGroup(g); !ok {
				return false
			}
		}

		return true
	}

	if !hasAllGroups(newGroups) {
		return nil, idam.ErrUnknownIdentity
	}

	if !hasAllGroups(deletedGroups) {
		return nil, idam.ErrUnknownIdentity
	}

	for _, g := range newGroups {
		grp, ok := provider.getGroup(g)
		if !ok {
			// This shouldn't happen
			continue
		}

		grp.AddMember(i.AccountName())
	}

	for _, g := range deletedGroups {
		grp, ok := provider.getGroup(g)
		if !ok {
			// This shouldn't happen as well
			continue
		}

		grp.DeleteMember(i.AccountName())
	}

	for idx, o := range provider.identities {
		if o.AccountName() == i.AccountName() {
			provider.identities[idx] = updatedIdentity
			break
		}
	}

	return copyIdentiy(updatedIdentity)
}

// Get returns the identity with the given name and implements idam.IdentityProvider
func (provider *IdentityProvider) Get(name string) (idam.Identity, error) {
	provider.lock.RLock()
	defer provider.lock.RUnlock()

	i, ok := provider.getIdentity(name)
	if !ok {
		return nil, idam.ErrUnknownIdentity
	}

	return copyIdentiy(i)
}

// List lists all identities stored by the provider and implements idam.IdentityProvider
func (provider *IdentityProvider) List() ([]idam.Identity, error) {
	provider.lock.RLock()
	defer provider.lock.RUnlock()

	var copy []idam.Identity

	for _, i := range provider.identities {
		c, err := copyIdentiy(i)
		if err == nil {
			copy = append(copy, c)
		}
	}

	return copy, nil
}

// ChangePasswordHash changes the identities password hash and implements idam.IdentityProvider
func (provider *IdentityProvider) ChangePasswordHash(name string, password []byte) error {
	provider.lock.Lock()
	defer provider.lock.Unlock()

	i, ok := provider.getIdentity(name)
	if !ok {
		return idam.ErrUnknownIdentity
	}

	if provider.passwords == nil {
		provider.passwords = make(map[string][]byte)
	}

	provider.passwords[i.AccountName()] = password

	return nil
}

// GetPasswordHash returns the password hash for the identity and implements idam.IdentityProvider
func (provider *IdentityProvider) GetPasswordHash(name string) ([]byte, error) {
	provider.lock.RLock()
	defer provider.lock.RUnlock()

	i, ok := provider.getIdentity(name)
	if !ok {
		return nil, idam.ErrUnknownIdentity
	}

	if provider.passwords == nil {
		return nil, nil
	}

	return provider.passwords[i.AccountName()], nil
}

// Get2FASecret returns the secret use for two-factor-authentication
// of the identity and implements idam.IdentityProvider
func (provider *IdentityProvider) Get2FASecret(name string) (string, error) {
	provider.lock.RLock()
	defer provider.lock.RUnlock()

	i, ok := provider.getIdentity(name)
	if !ok {
		return "", idam.ErrUnknownIdentity
	}

	if provider.secrets == nil {
		return "", nil
	}

	return provider.secrets[i.AccountName()], nil
}

// Set2FASecret sets the secret used for two-factor-authentication
// of the identity and implements idam.IdentityProvider
func (provider *IdentityProvider) Set2FASecret(name, secret string) error {
	provider.lock.Lock()
	defer provider.lock.Unlock()

	i, ok := provider.getIdentity(name)
	if !ok {
		return idam.ErrUnknownIdentity
	}

	if provider.secrets == nil {
		provider.secrets = make(map[string]string)
	}

	provider.secrets[i.AccountName()] = secret

	return nil
}

func (provider *IdentityProvider) getIdentity(name string) (idam.Identity, bool) {
	for _, i := range provider.identities {
		if i.AccountName() == name {
			return i, true
		}
	}

	return nil, false
}

func (provider *IdentityProvider) getGroup(name string) (*idam.Group, bool) {
	i, ok := provider.getIdentity(name)
	if !ok {
		return nil, false
	}

	grp, ok := i.(*idam.Group)
	return grp, ok
}

func copyIdentiy(i idam.Identity) (idam.Identity, error) {
	roles := copyStringSlice(i.Roles())
	groups := copyStringSlice(i.Groups())
	meta := i.Metadata()

	switch v := i.(type) {
	case *idam.User:
		u := idam.NewUserIdentityWithMetadata(i.AccountName(), roles, groups, meta)
		u.FirstName = v.FirstName
		u.LastName = v.LastName
		u.MailAddresses = copyStringSlice(v.MailAddresses)

		if i.Disabled() {
			idam.DisableIdentity(u)
		}

		return u, nil

	case *idam.Group:
		members := copyStringSlice(v.Members())
		g := idam.NewGroupWithMetadata(i.AccountName(), roles, groups, members, meta)

		if i.Disabled() {
			idam.DisableIdentity(g)
		}

		return g, nil

	default:
		return nil, errors.New("unsupported identity type")
	}
}

func diffSlice(original []string, updated []string) (added, deleted []string) {
	// TODO(ppacher) make this more efficient
Added:
	for _, u := range updated {
		for _, o := range original {
			if o == u {
				continue Added
			}

		}

		added = append(added, u)
	}

Deleted:
	for _, o := range original {
		for _, u := range updated {
			if o == u {
				continue Deleted
			}
		}

		deleted = append(deleted, o)
	}

	return
}

func copyStringSlice(s []string) []string {
	var copy []string

	for _, v := range s {
		copy = append(copy, v)
	}

	return copy
}
