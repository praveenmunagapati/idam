package server

import (
	"context"
	"errors"

	"github.com/golang/protobuf/ptypes/empty"
	"github.com/homebot/idam"
	idamV1 "github.com/homebot/protobuf/pkg/api/idam/v1"
)

// GetPermission implements homebot/api/idam/v1/permission.proto:Permission
func (m *Manager) GetPermission(ctx context.Context, in *idamV1.GetPermissionRequest) (*idamV1.Permission, error) {
	p, err := m.permissions.Get(in.GetName())
	if err != nil {
		return nil, err
	}

	pb, err := idam.PermissionProto(*p)
	if err != nil {
		return nil, err
	}

	return pb, nil
}

// CreatePermission implements homebot/api/idam/v1/permissions.proto:Permission
func (m *Manager) CreatePermission(ctx context.Context, in *idamV1.CreatePermissionRequest) (*idamV1.Permission, error) {
	i, _, err := m.identityFromCtx(ctx)
	if err != nil {
		return nil, err
	}

	logger := m.log.WithIdentity(i.AccountName()).WithResource(in.GetPermission())

	if _, err := m.permissions.Get(in.GetPermission()); err == nil {
		logger.Errorf("permission already created")
		return nil, errors.New("permission exists")
	}

	p, err := m.permissions.New(in.GetPermission(), i.AccountName())
	if err != nil {
		logger.Errorf("failed to create permission: %s", err)
		return nil, err
	}

	pb, err := idam.PermissionProto(*p)
	if err != nil {
		logger.Errorf("failed to convert permission: %s", err)
		return nil, err
	}

	logger.Infof("permission created")

	return pb, nil
}

// DeletePermission implements homebot/api/idam/v1/permissions.proto:Permission
func (m *Manager) DeletePermission(ctx context.Context, in *idamV1.DeletePermissionRequest) (*empty.Empty, error) {
	logger := m.getLogger(ctx).WithResource(in.GetName())

	if _, err := m.permissions.Get(in.GetName()); err != nil {
		logger.Errorf("permission error: %s", err)
		return nil, err
	}

	roles, err := m.roles.List()
	if err != nil {
		logger.Errorf("failed to get roles: %s", err)
		return nil, err
	}

	for _, r := range roles {
		if r.HasPermission(in.GetName()) {
			r.DeletePermission(in.GetName())
			if _, err := m.roles.Update(r); err != nil {
				logger.Errorf("failed to delete permission from role %q: %s", r.Name, err)
				return nil, err
			}

			logger.Infof("removed permission from role %q", r.Name)
		}
	}

	if err := m.permissions.Delete(in.GetName()); err != nil {
		logger.Errorf("failed to delete permission: %s", err)
		return nil, err
	}

	logger.Infof("permission deleted")

	return &empty.Empty{}, nil
}

// ListPermissions implements homebot/api/idam/v1/permissions.proto:Permission
func (m *Manager) ListPermissions(ctx context.Context, in *idamV1.ListPermissionRequest) (*idamV1.ListPermissionResponse, error) {

	permissions, err := m.permissions.List()
	if err != nil {
		return nil, err
	}

	var res []*idamV1.Permission

	for _, p := range permissions {
		pb, err := idam.PermissionProto(*p)
		if err != nil {
			return nil, err
		}

		res = append(res, pb)
	}

	return &idamV1.ListPermissionResponse{
		Permissions: res,
	}, nil
}

// TestAccessPermissions implements homebot/api/idam/v1/permissions.proto:Permission
func (m *Manager) TestAccessPermissions(ctx context.Context, in *idamV1.TestAccessRequest) (*idamV1.TestAccessResponse, error) {
	i, _, err := m.identityFromCtx(ctx)
	if err != nil {
		return nil, err
	}

	_ = i

	return nil, nil
}

func (m *Manager) GetRole(ctx context.Context, in *idamV1.GetRoleRequest) (*idamV1.Role, error) {
	r, err := m.roles.Get(in.GetName())
	if err != nil {
		return nil, err
	}

	pb, err := idam.RoleProto(r)
	if err != nil {
		return nil, err
	}

	return pb, err
}

// CreateRole implements homebot/api/idam/v1/permissions.proto:Permission
func (m *Manager) CreateRole(ctx context.Context, in *idamV1.CreateRoleRequest) (*idamV1.Role, error) {
	i, _, err := m.identityFromCtx(ctx)
	if err != nil {
		m.log.Errorf("failed to get identity: %s", err)
		return nil, err
	}

	if in.GetRole() == nil {
		m.log.Errorf("invalid request")
		return nil, errors.New("invalid request")
	}

	logger := m.log.WithIdentity(i.AccountName()).WithResource(in.GetRole().GetName())

	name := in.GetRole().GetName()
	permissions := in.GetRole().GetPermissions()

	if _, err := m.roles.Get(name); err == nil {
		logger.Errorf("role already created")
		return nil, errors.New("role exists")
	}

	role, err := m.roles.New(&idam.Role{
		Name:        name,
		Permissions: permissions,
		Creator:     i.AccountName(),
	})
	if err != nil {
		logger.Errorf("failed to create role: %s", err)
		return nil, err
	}

	pb, err := idam.RoleProto(role)
	if err != nil {
		logger.Errorf("failed to convert role: %s", err)
		return nil, err
	}

	logger.Infof("role created")

	return pb, nil
}

// DeleteRole implements homebot/api/idam/v1/permissions.proto:Permission
func (m *Manager) DeleteRole(ctx context.Context, in *idamV1.DeleteRoleRequest) (*empty.Empty, error) {
	logger := m.getLogger(ctx).WithResource(in.GetName())

	if _, err := m.roles.Get(in.GetName()); err != nil {
		logger.Errorf("role error: %s", err)
		return nil, err
	}

	identities, err := m.identities.List()
	if err != nil {
		logger.Errorf("failed to get identities: %s", err)
		return nil, err
	}

	for _, i := range identities {
		if idam.HasRole(i, in.GetName()) {
			idam.DeleteRole(i, in.GetName())
			if _, err := m.identities.Update(i); err != nil {
				logger.Errorf("failed to delete role from identity %q: %s", i.AccountName(), err)
				return nil, err
			}

			logger.Infof("deleted role from identity %q", i.AccountName())
		}
	}

	if err := m.roles.Delete(in.GetName()); err != nil {
		logger.Errorf("failed to delete role: %s", err)
		return nil, err
	}

	logger.Infof("role deleted")

	return &empty.Empty{}, nil
}

// UpdateRole implements homebot/api/idam/v1/permissions.proto:Permission
func (m *Manager) UpdateRole(ctx context.Context, in *idamV1.UpdateRoleRequest) (*idamV1.Role, error) {
	pb := in.GetRole()
	if pb == nil {
		m.log.Errorf("invalid request")
		return nil, errors.New("invalid request")
	}

	logger := m.getLogger(ctx).WithResource(in.GetRole().Name)

	role, err := idam.RoleFromProto(pb)
	if err != nil {
		logger.Errorf("failed to convert request: %s", err)
		return nil, err
	}

	upd, err := m.roles.Update(role)
	if err != nil {
		logger.Errorf("failed to update role: %s", err)
		return nil, err
	}

	updpb, err := idam.RoleProto(upd)
	if err != nil {
		logger.Errorf("failed to convert role: %s", err)
		return nil, err
	}

	logger.Infof("role updated")

	return updpb, nil
}

// ListRole implements homebot/api/idam/v1/permissions.proto:Permission
func (m *Manager) ListRole(ctx context.Context, in *idamV1.ListRoleRequest) (*idamV1.ListRoleResponse, error) {
	roles, err := m.roles.List()
	if err != nil {
		return nil, err
	}

	var res []*idamV1.Role
	for _, r := range roles {
		pb, err := idam.RoleProto(r)
		if err != nil {
			return nil, err
		}

		res = append(res, pb)
	}
	return &idamV1.ListRoleResponse{
		Roles: res,
	}, nil
}

// AssignPermission implements homebot/api/idam/v1/permissions.proto:Permission
func (m *Manager) AssignPermission(ctx context.Context, in *idamV1.AssignPermissionRequest) (*idamV1.Role, error) {
	logger := m.getLogger(ctx).WithResource(in.GetRole())

	role, err := m.roles.Get(in.GetRole())
	if err != nil {
		logger.Errorf("role error: %s", err)
		return nil, err
	}

	perm, err := m.permissions.Get(in.GetPermission())
	if err != nil {
		logger.Errorf("permission error: %q: %s", in.GetPermission(), err)
		return nil, err
	}

	role.AddPermission(perm.Name)

	upd, err := m.roles.Update(role)
	if err != nil {
		logger.Errorf("failed to update role: %s", err)
		return nil, err
	}

	pb, err := idam.RoleProto(upd)
	if err != nil {
		logger.Errorf("failed to convert role: %s", err)
		return nil, err
	}

	logger.Infof("permission %q added", in.GetPermission())

	return pb, nil
}

// RemoveGrantedPermission implements homebot/api/idam/v1/permissions.proto:Permission
func (m *Manager) RemoveGrantedPermission(ctx context.Context, in *idamV1.RemoveGrantedPermissionRequest) (*idamV1.Role, error) {
	logger := m.getLogger(ctx).WithResource(in.GetRole())

	role, err := m.roles.Get(in.GetRole())
	if err != nil {
		logger.Errorf("role error: %s", err)
		return nil, err
	}

	perm, err := m.permissions.Get(in.GetPermission())
	if err != nil {
		logger.Errorf("permission error: %q: %s", in.GetPermission(), err)
		return nil, err
	}

	role.DeletePermission(perm.Name)

	upd, err := m.roles.Update(role)
	if err != nil {
		logger.Errorf("failed to update role: %s", err)
		return nil, err
	}

	pb, err := idam.RoleProto(upd)
	if err != nil {
		logger.Errorf("failed to convert role: %s", err)
		return nil, err
	}

	logger.Infof("permission %q deleted", in.GetPermission())

	return pb, nil
}
