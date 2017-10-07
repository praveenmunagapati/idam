package file

import (
	"sync"
	"time"

	"github.com/gogo/protobuf/proto"
	"github.com/homebot/idam"
	idamV1 "github.com/homebot/protobuf/pkg/api/idam/v1"
)

// PermissionProvider is a idam.PermissionProvider persisting permissions to a file
type PermissionProvider struct {
	filename string
	lock     sync.RWMutex

	permissions []*idam.Permission
}

// NewPermissionProvider returns a new permission provder that persists permissions
// to `file`
func NewPermissionProvider(file string) idam.PermissionProvider {
	p := &PermissionProvider{
		filename: file,
	}

	if err := p.readFromFile(); err != nil {
		// TODO(ppacher) return error instead of panicing
		panic(err)
	}

	return p
}

// New creates a new permission and implements idam.PermissionProvider
func (perm *PermissionProvider) New(spec, creator string) (*idam.Permission, error) {
	perm.lock.Lock()
	defer perm.lock.Unlock()

	if p, ok := perm.getPermission(spec); ok {
		return copyPermission(p), nil
	}

	p := &idam.Permission{
		Name:    spec,
		Creator: creator,
		Created: time.Now(),
	}

	perm.permissions = append(perm.permissions, p)

	return copyPermission(p), perm.saveToFile()
}

// Delete deletes a permission and implements idam.PermissionProvider
func (perm *PermissionProvider) Delete(spec string) error {
	perm.lock.Lock()
	defer perm.lock.Unlock()

	if _, ok := perm.getPermission(spec); !ok {
		return idam.ErrUnknownPermission
	}

	var newPermissions []*idam.Permission

	for _, p := range perm.permissions {
		if p.Name != spec {
			newPermissions = append(newPermissions, p)
		}
	}

	perm.permissions = newPermissions

	return perm.saveToFile()
}

// List lista all permissions stored at the provider and implements
// idam.PermissionProvider
func (perm *PermissionProvider) List() ([]*idam.Permission, error) {
	perm.lock.RLock()
	defer perm.lock.RUnlock()

	var copy []*idam.Permission

	for _, p := range perm.permissions {
		copy = append(copy, copyPermission(p))
	}

	return copy, nil
}

// Get returns the permission with the given name and implements
// idam.PermissionProvider
func (perm *PermissionProvider) Get(spec string) (*idam.Permission, error) {
	perm.lock.RLock()
	defer perm.lock.RUnlock()

	p, ok := perm.getPermission(spec)
	if !ok {
		return nil, idam.ErrUnknownPermission
	}

	return copyPermission(p), nil
}

func (perm *PermissionProvider) getPermission(spec string) (*idam.Permission, bool) {
	for _, p := range perm.permissions {
		if p.Name == spec {
			return p, true
		}
	}

	return nil, false
}

func (perm *PermissionProvider) readFromFile() error {
	var data [][]byte

	if err := readFile(perm.filename, &data); err != nil {
		return err
	}

	var permissions []*idam.Permission

	for _, blob := range data {
		var pb idamV1.Permission

		if err := proto.Unmarshal(blob, &pb); err != nil {
			return err
		}

		p, err := idam.PermissionFromProto(&pb)
		if err != nil {
			return err
		}

		permissions = append(permissions, p)
	}

	perm.permissions = permissions
	return nil
}

func (perm *PermissionProvider) saveToFile() error {
	var data [][]byte

	for _, d := range perm.permissions {
		pb, err := idam.PermissionProto(*d)
		if err != nil {
			return err
		}

		blob, err := proto.Marshal(pb)
		if err != nil {
			return err
		}

		data = append(data, blob)
	}

	return writeFile(perm.filename, data)
}

func copyPermission(p *idam.Permission) *idam.Permission {
	return &idam.Permission{
		Name:    p.Name,
		Created: p.Created,
		Creator: p.Creator,
	}
}
