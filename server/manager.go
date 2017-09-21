package server

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/homebot/core/urn"

	"github.com/homebot/core/log"
	"github.com/homebot/idam"
	"github.com/homebot/idam/policy"
	"github.com/homebot/idam/provider"
	homebotApi "github.com/homebot/protobuf/pkg/api"
	idamV1 "github.com/homebot/protobuf/pkg/api/idam/v1"
)

// Manager implements the gRPC Identity Manager Server interface
type Manager struct {
	idam          provider.IdentityManager
	alg           string
	signingKey    []byte
	signingCert   []byte
	issuer        string
	tokenDuration time.Duration
	log           log.Logger
}

// New creates a new manager server
func New(p provider.IdentityManager, opts ...Option) (*Manager, error) {
	m := &Manager{
		idam: p,
	}

	for _, fn := range opts {
		if err := fn(m); err != nil {
			return nil, err
		}
	}

	if len(m.signingCert) == 0 || len(m.signingKey) == 0 {
		return nil, errors.New("no secret provided")
	}

	if m.issuer == "" {
		m.issuer = "idam"
	}

	if m.tokenDuration == time.Duration(0) {
		m.tokenDuration = time.Hour
	}

	if m.log == nil {
		m.log = log.SimpleLogger{}
	}

	return m, nil
}

// VerificationKey returns the JWT token verification key and implements policy.JWTKeyVerifier
func (m *Manager) VerificationKey(issuer string, alg string) (interface{}, error) {
	return m.signingCert, nil
}

// CreateIdentity creates a new identity
func (m *Manager) CreateIdentity(ctx context.Context, in *idamV1.CreateIdentityRequest) (*idamV1.CreateIdentityResponse, error) {
	token, ok := policy.TokenFromContext(ctx)
	if !ok || token.Valid() != nil {
		return nil, idam.ErrNotAuthenticated
	}

	logger := log.WithURN(token.URN)

	if in == nil || in.Identity == nil {
		return nil, errors.New("invalid message")
	}

	if in.GetPassword() == "" {
		return nil, errors.New("password required")
	}

	identity := idam.IdentityFromProto(in.GetIdentity())
	if identity == nil {
		return nil, errors.New("invalid message")
	}

	if err := identity.Valid(); err != nil {
		return nil, err
	}

	otpSecret, err := m.idam.Create(*identity, in.GetPassword(), in.GetEnable2FA())
	if err != nil {
		return nil, err
	}

	logFA := "without"
	if in.GetEnable2FA() {
		logFA = "with"
	}
	logger.Infof("created new identity %q %s 2FA", identity.URN().String(), logFA)

	resp := &idamV1.CreateIdentityResponse{}

	if in.GetEnable2FA() {
		resp.TotpSecret = otpSecret
	}

	return resp, nil
}

// DeleteIdentity deletes an identity
func (m *Manager) DeleteIdentity(ctx context.Context, in *idamV1.DeleteIdentityRequest) (*idamV1.DeleteIdentityResponse, error) {
	token, ok := policy.TokenFromContext(ctx)
	if !ok || token.Valid() != nil {
		return nil, idam.ErrNotAuthenticated
	}

	logger := log.WithURN(token.URN)

	if in == nil {
		return nil, errors.New("invald message")
	}

	target := urn.URN(in.GetUrn())
	if !target.Valid() {
		return nil, urn.ErrInvalidURN
	}

	if err := m.idam.Delete(target); err != nil {
		return nil, err
	}

	logger.Warnf("identity %q deleted", target.String())

	return &idamV1.DeleteIdentityResponse{
		Urn: in.GetUrn(),
	}, nil
}

// UpdateIdentity updates a given identity
func (m *Manager) UpdateIdentity(ctx context.Context, in *idamV1.UpdateIdentityRequest) (*idamV1.UpdateIdentityResponse, error) {
	return nil, nil
}

// LookupIdentities searches for identities matching the lookup request
func (m *Manager) LookupIdentities(ctx context.Context, in *idamV1.LookupRequest) (*idamV1.LookupResponse, error) {
	auth, ok := policy.TokenFromContext(ctx)
	if !ok || auth.Valid() != nil {
		return nil, fmt.Errorf("invalid token: %s", auth.Valid())
	}

	identities := m.idam.Identities()

	var res []*idamV1.Identity

	for _, i := range identities {
		if auth.HasGroup(urn.IdamAdminGroup) || auth.OwnsURN(i.URN()) {
			res = append(res, i.ToProtobuf())
		}
	}

	return &idamV1.LookupResponse{
		Identities: res,
	}, nil
}

// CreateRole creates a new role
func (m *Manager) CreateRole(ctx context.Context, in *idamV1.CreateRoleRequest) (*idamV1.CreateRoleResponse, error) {
	auth, ok := policy.TokenFromContext(ctx)
	if !ok || auth.Valid() != nil {
		return nil, idam.ErrNotAuthenticated
	}

	if err := m.idam.CreateRole(in.GetRoleName()); err != nil {
		return nil, err
	}

	log.WithURN(auth.URN).Infof("created role %s", in.GetRoleName())

	return &idamV1.CreateRoleResponse{RoleName: in.GetRoleName()}, nil
}

// ListRoles returns all roles matching the lookup filter
func (m *Manager) ListRoles(ctx context.Context, in *idamV1.RoleLookupRequest) (*idamV1.RoleLookupResponse, error) {
	auth, ok := policy.TokenFromContext(ctx)
	if ok || auth.Valid() != nil {
		return nil, idam.ErrNotAuthenticated
	}

	roles := m.idam.GetRoles()

	return &idamV1.RoleLookupResponse{
		RoleNames: roles,
	}, nil
}

// DeleteRole deletes a role
func (m *Manager) DeleteRole(ctx context.Context, in *idamV1.DeleteRoleRequest) (*homebotApi.Empty, error) {
	auth, ok := policy.TokenFromContext(ctx)
	if ok || auth.Valid() != nil {
		return nil, idam.ErrNotAuthenticated
	}

	if err := m.idam.DeleteRole(in.GetRoleName()); err != nil {
		return nil, err
	}

	identities := m.idam.IdentitiesByRole(in.GetRoleName())

	for _, i := range identities {
		var roles []urn.URN

		for _, r := range i.Roles {
			if r.String() != in.GetRoleName() {
				roles = append(roles, r)
			}
		}

		i.Roles = roles

		if err := m.idam.Update(i.URN(), i); err != nil {
			log.WithURN(auth.URN).Warnf("failed to remove role %s from identity: %s", in.GetRoleName(), i.URN().String())
		}
	}

	log.WithURN(auth.URN).Infof("deleted role: %s", in.GetRoleName())
	return &homebotApi.Empty{}, nil
}

// AssignRole assigns a role to an identity
func (m *Manager) AssignRole(ctx context.Context, in *idamV1.AssignRoleRequest) (*idamV1.AssignRoleResponse, error) {
	auth, ok := policy.TokenFromContext(ctx)
	if !ok || auth.Valid() != nil {
		return nil, idam.ErrNotAuthenticated
	}

	i, _, err := m.idam.Get(urn.URN(in.GetIdentity()))
	if err != nil {
		return nil, err
	}

	var rolesToAssign []string

L:
	for _, r := range in.GetRoleName() {
		for _, n := range i.Roles {
			if n.String() == r {
				continue L
			}
		}

		rolesToAssign = append(rolesToAssign, r)
	}

	for _, r := range rolesToAssign {
		i.Roles = append(i.Roles, urn.URN(r))
	}

	if err := m.idam.Update(i.URN(), *i); err != nil {
		return nil, err
	}

	return &idamV1.AssignRoleResponse{
		Identity: i.ToProtobuf(),
	}, nil
}

// UnassignRole removes a role from an identity
func (m *Manager) UnassignRole(ctx context.Context, in *idamV1.UnassignRoleRequest) (*idamV1.UnassignRoleResponse, error) {
	auth, ok := policy.TokenFromContext(ctx)
	if !ok || auth.Valid() != nil {
		return nil, idam.ErrNotAuthenticated
	}

	i, _, err := m.idam.Get(urn.URN(in.GetIdentity()))
	if err != nil {
		return nil, err
	}

	var newRoles []urn.URN
L:
	for _, r := range i.Roles {
		for _, remove := range in.GetRoleName() {
			if r.String() == remove {
				continue L
			}
		}

		newRoles = append(newRoles, urn.URN(r))
	}
	i.Roles = newRoles

	if err := m.idam.Update(i.URN(), *i); err != nil {
		return nil, err
	}

	return &idamV1.UnassignRoleResponse{
		Identity: i.ToProtobuf(),
	}, nil
}

var _ idamV1.AdminServer = &Manager{}
var _ policy.JWTKeyVerifier = &Manager{}
