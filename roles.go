package idam

import (
	"errors"
	"time"

	"github.com/golang/protobuf/ptypes"

	idamV1 "github.com/homebot/protobuf/pkg/api/idam/v1"
)

var (
	ErrUnknownRole = errors.New("unknown role")
)

// Role represents a set of permissions and can be granted to identities
type Role struct {
	// Name is the name of the role
	Name string

	// Permissions is a set of permissions granted to the role
	Permissions []string

	// Created holds the time the role has been created
	Created time.Time

	// Updated holds the time the role has been updated last
	Updated time.Time

	// Creator is the name of the identity that created the role
	Creator string
}

// NewRole creates a new role
func NewRole(n string, perms []string, parent string) *Role {
	return &Role{
		Name:        n,
		Permissions: perms,
		Created:     time.Now(),
		Updated:     time.Now(),
		Creator:     parent,
	}
}

// HasPermission checks if the role has a given permission
func (r *Role) HasPermission(p string) bool {
	for _, perm := range r.Permissions {
		if perm == p {
			return true
		}
	}

	return false
}

// AddPermission adds a new permission to the role
func (r *Role) AddPermission(p string) {
	if r.HasPermission(p) {
		return
	}

	r.Permissions = append(r.Permissions, p)
}

// DeletePermission deletes a permission from the role
func (r *Role) DeletePermission(p string) {
	if !r.HasPermission(p) {
		return
	}

	var newPermissions []string
	for _, perm := range r.Permissions {
		if perm != p {
			newPermissions = append(newPermissions, perm)
		}
	}

	r.Permissions = newPermissions
}

// RoleProto converts a role to it's protocol buffer representation
func RoleProto(r *Role) (*idamV1.Role, error) {
	created, err := ptypes.TimestampProto(r.Created)
	if err != nil {
		return nil, err
	}
	updated, err := ptypes.TimestampProto(r.Updated)
	if err != nil {
		return nil, err
	}

	role := &idamV1.Role{
		Name:        r.Name,
		Permissions: r.Permissions,
		CreatedTime: created,
		UpdatedTime: updated,
		Creator:     r.Creator,
	}

	return role, nil
}

// RoleFromProto creates a role from it's protocol buffer representation
func RoleFromProto(p *idamV1.Role) (*Role, error) {
	// We ignore errors for the timestamps as they MUST be ignored
	// in requests (and thus should be missing)
	created, _ := ptypes.Timestamp(p.GetCreatedTime())
	updated, _ := ptypes.Timestamp(p.GetUpdatedTime())

	return &Role{
		Name:        p.GetName(),
		Permissions: p.GetPermissions(),
		Updated:     updated,
		Created:     created,
		Creator:     p.GetCreator(),
	}, nil
}
