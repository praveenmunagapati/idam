package server

import (
	"context"
	"errors"

	"github.com/pquerna/otp/totp"

	"golang.org/x/crypto/bcrypt"

	"github.com/golang/protobuf/ptypes/empty"
	"github.com/homebot/core/utils"
	"github.com/homebot/idam"
	idamV1 "github.com/homebot/protobuf/pkg/api/idam/v1"
)

// CreateIdentity implements homebot/api/idam/v1/identity.proto:IdentityService
func (m *Manager) CreateIdentity(ctx context.Context, in *idamV1.CreateIdentityRequest) (*idamV1.CreateIdentityResponse, error) {
	i, _, err := m.identityFromCtx(ctx)
	if err != nil {
		return nil, err
	}

	logger := m.log.WithIdentity(i.AccountName())

	if in.GetIdentity() == nil {
		logger.Warnf("invalid request")
		return nil, errors.New("invalid request")
	}

	identity, err := idam.IdentityFromProto(in.GetIdentity())
	if err != nil {
		logger.Warnf("invalid request: %s", err)
		return nil, err
	}

	// TODO: set creator
	_ = i

	var hash []byte
	if !idam.IsGroup(identity) {
		hash, err = bcrypt.GenerateFromPassword([]byte(in.GetPassword()), bcrypt.DefaultCost)
		if err != nil {
			logger.Warnf("invalid request: %s", err)
			return nil, err
		}
	}

	res, err := m.identities.New(identity, hash)
	if err != nil {
		logger.Errorf("failed to create identity: %s", err)
		return nil, err
	}

	var totpSecret string
	if in.Enable2FA {
		key, err := totp.Generate(totp.GenerateOpts{
			Issuer:      m.issuer,
			AccountName: res.AccountName(),
		})
		if err != nil {
			logger.Errorf("failed to create identity: %s", err)
			m.identities.Delete(res.AccountName())
			return nil, err
		}

		if err := m.identities.Set2FASecret(res.AccountName(), key.Secret()); err != nil {
			logger.Errorf("failed to create identity: %s", err)
			m.identities.Delete(res.AccountName())
			return nil, err
		}

		totpSecret = key.String()
	}

	pb, err := idam.IdentityProto(res)
	if err != nil {
		logger.Errorf("failed to create identity: %s", err)
		return nil, err
	}

	logger.WithResource(res.AccountName()).Infof("identity created")

	return &idamV1.CreateIdentityResponse{
		Identity:   pb,
		TotpSecret: totpSecret,
	}, nil
}

func (m *Manager) GetIdentityPermissions(ctx context.Context, in *idamV1.GetIdentityRequest) (*idamV1.GetIdentityPermissionsResponse, error) {
	i, err := m.identities.Get(in.GetName())
	if err != nil {
		return nil, err
	}

	permissions, err := m.getPermissions(i.AccountName())
	if err != nil {
		return nil, err
	}

	ipb, err := idam.IdentityProto(i)
	if err != nil {
		return nil, err
	}

	res := &idamV1.GetIdentityPermissionsResponse{
		Identity: ipb,
	}

	for _, p := range permissions {
		ppb, err := idam.PermissionProto(p)
		if err != nil {
			return nil, err
		}

		res.Permissions = append(res.Permissions, ppb)
	}

	return res, nil
}

// DeleteIdentity implements homebot/api/idam/v1/identity.proto:IdentityService
func (m *Manager) DeleteIdentity(ctx context.Context, in *idamV1.DeleteIdentityRequest) (*empty.Empty, error) {
	logger := m.getLogger(ctx).WithResource(in.GetName())

	if err := m.identities.Delete(in.GetName()); err != nil {
		logger.Errorf("failed to delete identity: %s", err)
		return nil, err
	}

	logger.Infof("identity deleted")

	return &empty.Empty{}, nil
}

// UpdateIdentity implements homebot/api/idam/v1/identity.proto:IdentityService
func (m *Manager) UpdateIdentity(ctx context.Context, in *idamV1.UpdateIdentityRequest) (*idamV1.UpdateIdentityResponse, error) {
	pb := in.GetIdentity()
	if pb == nil {
		m.log.Errorf("invalid request")
		return nil, errors.New("invalid request")
	}

	logger := m.getLogger(ctx).WithResource(in.GetIdentity().GetName())

	i, err := idam.IdentityFromProto(pb)
	if err != nil {
		logger.Errorf("%s", err)
		return nil, err
	}

	original, err := m.identities.Get(i.AccountName())
	if err != nil {
		logger.Errorf("%s", err)
		return nil, err
	}

	// Make sure that all new roles actually exist
	newRoles, _ := diffSlice(original.Roles(), i.Roles())
	for _, n := range newRoles {
		if _, err := m.roles.Get(n); err != nil {
			logger.Errorf("role %s: %s", n, err)
			return nil, err
		}
	}

	// IdentityProvider is responsible for updating group memberships as well
	res, err := m.identities.Update(i)
	if err != nil {
		logger.Errorf("identity update failed: %s", err)
		return nil, err
	}

	_, token, err := m.identityFromCtx(ctx)
	if token.HasPermission(idam.AllowWriteIdentityAuth) && in.GetNewPassword() != "" {
		hash, err := bcrypt.GenerateFromPassword([]byte(in.GetNewPassword()), bcrypt.DefaultCost)
		if err != nil {
			logger.Errorf("password update failed: %s", err)
			return nil, err
		}

		if err := m.identities.ChangePasswordHash(i.AccountName(), hash); err != nil {
			logger.Errorf("password update failed: %s", err)
			return nil, err
		}
	}

	resPb, err := idam.IdentityProto(res)
	if err != nil {
		logger.Errorf("%s", err)
		return nil, err
	}

	logger.Infof("identity updated")
	return &idamV1.UpdateIdentityResponse{
		Identity: resPb,
	}, nil
}

// LookupIdentities implements homebot/api/idam/v1/identity.proto:IdentityService
func (m *Manager) LookupIdentities(ctx context.Context, in *idamV1.LookupRequest) (*idamV1.LookupResponse, error) {
	list, err := m.identities.List()
	if err != nil {
		return nil, err
	}

	start, end, token, err := utils.Paginate(in.GetPageToken(), len(list), in.GetPageSize())
	list = list[start:end]

	var res []*idamV1.Identity
	for _, i := range list {
		pb, err := idam.IdentityProto(i)
		if err != nil {
			return nil, err
		}

		res = append(res, pb)
	}
	return &idamV1.LookupResponse{
		Identities:    res,
		NextPageToken: token,
	}, nil
}

func (m *Manager) GetIdentity(ctx context.Context, in *idamV1.GetIdentityRequest) (*idamV1.Identity, error) {
	i, err := m.identities.Get(in.GetName())
	if err != nil {
		return nil, err
	}

	pb, err := idam.IdentityProto(i)
	if err != nil {
		return nil, err
	}

	return pb, nil
}

func (m *Manager) ListIdentityGroups(ctx context.Context, in *idamV1.ListIdentityGroupsRequest) (*idamV1.ListIdentityGroupResponse, error) {
	i, err := m.identities.Get(in.GetName())
	if err != nil {
		return nil, err
	}

	var groups []*idamV1.Identity

	for _, g := range i.Groups() {
		gi, err := m.identities.Get(g)
		if err != nil {
			return nil, err
		}

		pb, err := idam.IdentityProto(gi)
		if err != nil {
			return nil, err
		}

		groups = append(groups, pb)
	}

	return &idamV1.ListIdentityGroupResponse{
		Groups: groups,
	}, nil
}

func (m *Manager) AddIdentityToGroup(ctx context.Context, in *idamV1.AddIdentityToGroupRequest) (*idamV1.Identity, error) {
	i, err := m.identities.Get(in.GetName())
	if err != nil {
		m.log.Errorf("failed to add identity to group: %s", err)
		return nil, err
	}

	logger := m.getLogger(ctx).WithResource(i.AccountName())

	if _, err := m.identities.Get(in.GetGroup()); err != nil {
		logger.Errorf("group error: %s", err)
		return nil, err
	}

	idam.AddGroup(i, in.GetGroup())

	upd, err := m.identities.Update(i)
	if err != nil {
		logger.Errorf("failed to update identity: %s", err)
		return nil, err
	}

	pb, err := idam.IdentityProto(upd)
	if err != nil {
		logger.Errorf("failed to update identity: %s", err)
		return nil, err
	}

	logger.Infof("group %s added", in.GetGroup())

	return pb, nil
}

func (m *Manager) DeleteIdentityFromGroup(ctx context.Context, in *idamV1.DeleteIdentityFromGroupRequest) (*idamV1.Identity, error) {
	i, err := m.identities.Get(in.GetName())
	if err != nil {
		m.log.Errorf("failed to delete identity from group: %s", err)
		return nil, err
	}

	logger := m.getLogger(ctx).WithResource(i.AccountName())

	if _, err := m.identities.Get(in.GetGroup()); err != nil {
		logger.Errorf("group error: %s", err)
		return nil, err
	}

	idam.DeleteGroup(i, in.GetGroup())

	upd, err := m.identities.Update(i)
	if err != nil {
		logger.Errorf("identity update failed: %s", err)
		return nil, err
	}

	pb, err := idam.IdentityProto(upd)
	if err != nil {
		logger.Errorf("identity update failed: %s", err)
		return nil, err
	}

	logger.Infof("group %q deleted", in.GetGroup())

	return pb, nil
}

// AssignRole implements homebot/api/idam/v1/identity.proto:IdentityService
func (m *Manager) AssignRole(ctx context.Context, in *idamV1.AssignRoleRequest) (*idamV1.AssignRoleResponse, error) {
	i, err := m.identities.Get(in.GetName())
	if err != nil {
		m.log.Errorf("failed to assign role to identity: %s", err)
		return nil, err
	}

	logger := m.getLogger(ctx).WithResource(i.AccountName())

	if _, err := m.roles.Get(in.GetRole()); err != nil {
		logger.Errorf("role error: %s", err)
		return nil, err
	}

	if idam.HasRole(i, in.GetRole()) {
		pb, err := idam.IdentityProto(i)
		if err != nil {
			logger.Errorf("failed to convert identity: %s", err)
			return nil, err
		}

		return &idamV1.AssignRoleResponse{
			Identity: pb,
		}, nil
	}

	idam.AddRole(i, in.GetRole())

	upd, err := m.identities.Update(i)
	if err != nil {
		logger.Errorf("identity update failed: %s", err)
		return nil, err
	}

	pb, err := idam.IdentityProto(upd)
	if err != nil {
		logger.Errorf("failed to convert identity: %s", err)
		return nil, err
	}

	logger.Infof("role %q added", in.GetRole())

	return &idamV1.AssignRoleResponse{
		Identity: pb,
	}, nil
}

// RemoveRole implements homebot/api/idam/v1/identity.proto:IdentityService
func (m *Manager) RemoveRole(ctx context.Context, in *idamV1.UnassignRoleRequest) (*idamV1.UnassignRoleResponse, error) {
	i, err := m.identities.Get(in.GetName())
	if err != nil {
		m.log.Errorf("failed to remove role from identity: %s", err)
		return nil, err
	}

	logger := m.getLogger(ctx).WithResource(i.AccountName())

	if _, err := m.roles.Get(in.GetRole()); err != nil {
		logger.Errorf("role error: %s", err)
		return nil, err
	}

	if !idam.HasRole(i, in.GetRole()) {
		pb, err := idam.IdentityProto(i)
		if err != nil {
			logger.Errorf("failed to convert identity: %s", err)
			return nil, err
		}

		return &idamV1.UnassignRoleResponse{
			Identity: pb,
		}, nil
	}

	idam.DeleteRole(i, in.GetRole())

	upd, err := m.identities.Update(i)
	if err != nil {
		logger.Errorf("identity update failed: %s", err)
		return nil, err
	}

	pb, err := idam.IdentityProto(upd)
	if err != nil {
		logger.Errorf("failed to convert identity: %s", err)
		return nil, err
	}

	logger.Infof("role %q deleted", in.GetRole())

	return &idamV1.UnassignRoleResponse{
		Identity: pb,
	}, nil
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
