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

	if in.GetIdentity() == nil {
		return nil, errors.New("invalid request")
	}

	identity, err := idam.IdentityFromProto(in.GetIdentity())
	if err != nil {
		return nil, err
	}

	// TODO: set creator
	_ = i

	var hash []byte
	if !idam.IsGroup(identity) {
		hash, err = bcrypt.GenerateFromPassword([]byte(in.GetPassword()), bcrypt.DefaultCost)
		if err != nil {
			return nil, err
		}
	}

	res, err := m.identities.New(identity, hash)
	if err != nil {
		return nil, err
	}

	var totpSecret string
	if in.Enable2FA {
		key, err := totp.Generate(totp.GenerateOpts{
			Issuer:      m.issuer,
			AccountName: res.AccountName(),
		})
		if err != nil {
			m.identities.Delete(res.AccountName())
			return nil, err
		}

		if err := m.identities.Set2FASecret(res.AccountName(), key.Secret()); err != nil {
			m.identities.Delete(res.AccountName())
			return nil, err
		}

		totpSecret = key.String()
	}

	pb, err := idam.IdentityProto(res)
	if err != nil {
		return nil, err
	}

	return &idamV1.CreateIdentityResponse{
		Identity:   pb,
		TotpSecret: totpSecret,
	}, nil
}

// DeleteIdentity implements homebot/api/idam/v1/identity.proto:IdentityService
func (m *Manager) DeleteIdentity(ctx context.Context, in *idamV1.DeleteIdentityRequest) (*empty.Empty, error) {
	if err := m.identities.Delete(in.GetName()); err != nil {
		return nil, err
	}

	return &empty.Empty{}, nil
}

// UpdateIdentity implements homebot/api/idam/v1/identity.proto:IdentityService
func (m *Manager) UpdateIdentity(ctx context.Context, in *idamV1.UpdateIdentityRequest) (*idamV1.UpdateIdentityResponse, error) {
	return nil, errors.New("not yet implemented")
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

// AssignRole implements homebot/api/idam/v1/identity.proto:IdentityService
func (m *Manager) AssignRole(ctx context.Context, in *idamV1.AssignRoleRequest) (*idamV1.AssignRoleResponse, error) {
	return nil, nil
}

// RemoveRole implements homebot/api/idam/v1/identity.proto:IdentityService
func (m *Manager) RemoveRole(ctx context.Context, in *idamV1.UnassignRoleRequest) (*idamV1.UnassignRoleResponse, error) {
	return nil, nil
}
