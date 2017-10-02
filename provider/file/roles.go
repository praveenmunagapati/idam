package file

import (
	"sync"
	"time"

	"github.com/homebot/idam"
)

// TODO(ppacher): actually store roles to files

// RoleProvider is a idam.RoleProvider persisting roles to files
type RoleProvider struct {
	filename string

	lock  sync.RWMutex
	roles []*idam.Role
}

// NewRoleProvider returns a new file-based role provider
func NewRoleProvider(name string) idam.RoleProvider {
	return &RoleProvider{
		filename: name,
	}
}

// New creates a new role and implements idam.RoleProvider
func (roles *RoleProvider) New(r *idam.Role) (*idam.Role, error) {
	roles.lock.Lock()
	defer roles.lock.Unlock()

	if r, ok := roles.getRole(r.Name); ok {
		return copyRole(r), nil
	}

	newRole := idam.NewRole(r.Name, r.Permissions, r.Creator)

	roles.roles = append(roles.roles, newRole)

	return copyRole(newRole), nil
}

// Update updates a role and implements idam.RoleProvider
func (roles *RoleProvider) Update(r *idam.Role) (*idam.Role, error) {
	roles.lock.Lock()
	defer roles.lock.Unlock()

	role, ok := roles.getRole(r.Name)
	if !ok {
		return nil, idam.ErrUnknownRole
	}

	role.Permissions = []string{}

	for _, p := range r.Permissions {
		role.Permissions = append(role.Permissions, p)
	}

	role.Updated = time.Now()
	// TODO(ppacher): should we also allow to update the creator of the role?

	return copyRole(role), nil
}

// Delete deletes a role and implements idam.RoleProvider
func (roles *RoleProvider) Delete(name string) error {
	roles.lock.Lock()
	defer roles.lock.Unlock()

	var newRoles []*idam.Role

	found := false

	for _, r := range roles.roles {
		if r.Name != name {
			newRoles = append(newRoles, r)
		} else {
			found = true
		}
	}

	roles.roles = newRoles

	if !found {
		return idam.ErrUnknownRole
	}

	return nil
}

// Get returns the role with the given name and implements idam.RoleProvider
func (roles *RoleProvider) Get(name string) (*idam.Role, error) {
	roles.lock.RLock()
	defer roles.lock.RUnlock()

	r, ok := roles.getRole(name)
	if !ok {
		return nil, idam.ErrUnknownRole
	}

	return copyRole(r), nil
}

// List returns a list of available roles and implements idam.RoleProvider
func (roles *RoleProvider) List() ([]*idam.Role, error) {
	roles.lock.RLock()
	defer roles.lock.RUnlock()

	var copy []*idam.Role
	for _, r := range roles.roles {
		copy = append(copy, copyRole(r))
	}

	return copy, nil
}

func (roles *RoleProvider) getRole(n string) (*idam.Role, bool) {
	for _, r := range roles.roles {
		if r.Name == n {
			return r, true
		}
	}

	return nil, false
}

func copyRole(r *idam.Role) *idam.Role {
	copy := &idam.Role{
		Name:    r.Name,
		Created: r.Created,
		Creator: r.Creator,
		Updated: r.Updated,
	}

	for _, p := range r.Permissions {
		copy.Permissions = append(copy.Permissions, p)
	}

	return copy
}
