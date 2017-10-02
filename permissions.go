package idam

import (
	"errors"
	"time"

	"github.com/golang/protobuf/ptypes"
	idamV1 "github.com/homebot/protobuf/pkg/api/idam/v1"
)

var (
	ErrUnknownPermission = errors.New("unknown permission")
)

// Permission is a single permission to perform a dedicated action
type Permission struct {
	// Name is the name of the permission and
	// should always follow the <service>.<resource>.<action> format
	Name string

	// Created holds the time the permission has been created
	Created time.Time

	// Creator is the name of the identity that created the permission
	Creator string
}

// PermissionProto converts a permission to it's protocol buffer representation
func PermissionProto(p Permission) (*idamV1.Permission, error) {
	created, err := ptypes.TimestampProto(p.Created)
	if err != nil {
		return nil, err
	}

	return &idamV1.Permission{
		Permission:  p.Name,
		CreatedTime: created,
		Creator:     p.Creator,
	}, nil
}

// PermissionFromProto creates a permission object from it's protocol buffer
// representation
func PermissionFromProto(p *idamV1.Permission) (*Permission, error) {
	created, _ := ptypes.Timestamp(p.GetCreatedTime())

	return &Permission{
		Name:    p.GetPermission(),
		Created: created,
		Creator: p.GetCreator(),
	}, nil
}

// Standard permissions
const (
	//
	// Role management permissions
	//

	AllowWriteRole  = "idam.role.write"
	AllowReadRole   = "idam.role.read"
	AllowDeleteRole = "idam.role.delete"

	//
	// Permission management permissions
	//

	AllowWritePermission  = "idam.permission.write"
	AllowReadPermission   = "idam.permission.read"
	AllowDeletePermission = "idam.permission.delete"
	AllowAssignPermission = "idam.permission.assign"
	AllowTestPermissions  = "idam.permission.test"

	//
	// Identity management permissions
	//

	AllowReadIdentity       = "idam.identity.read"
	AllowReadIdentityAuth   = "idam.identity.readAuth"
	AllowWriteIdentity      = "idam.identity.write"
	AllowWriteIdentityAuth  = "idam.identity.writeAuth"
	AllowDeleteIdentity     = "idam.identity.delete"
	AllowAssignRoleIdentity = "idam.identity.assignRole"
)

// AllBuiltInPermissions holds all permission strings built into IDAM
var AllBuiltInPermissions = []string{
	AllowWriteRole,
	AllowReadRole,
	AllowDeleteRole,
	AllowWritePermission,
	AllowReadPermission,
	AllowDeletePermission,
	AllowAssignPermission,
	AllowTestPermissions,
	AllowReadIdentity,
	AllowReadIdentityAuth,
	AllowWriteIdentity,
	AllowWriteIdentityAuth,
	AllowDeleteIdentity,
	AllowAssignRoleIdentity,
}
