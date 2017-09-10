package server

import (
	"context"
	"errors"

	"github.com/homebot/core/urn"

	"github.com/homebot/idam"
	"github.com/homebot/idam/provider"
	"github.com/homebot/idam/token"
	homebot_api "github.com/homebot/protobuf/pkg/api"
	idam_api "github.com/homebot/protobuf/pkg/api/idam"
)

// Manager implements the gRPC Identity Manager Server interface
type Manager struct {
	idam  provider.IdentityManager
	keyFn KeyProviderFunc
}

// CreateIdentity creates a new identity
func (m *Manager) CreateIdentity(ctx context.Context, in *idam_api.CreateIdentityRequest) (*idam_api.CreateIdentityResponse, error) {
	token, err := m.getToken(ctx)
	if err != nil {
		return nil, err
	}

	if !token.HasGroup(urn.IdamAdminGroup) {
		return nil, idam.ErrNotAuthorized
	}

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

	resp := &idam_api.CreateIdentityResponse{}

	if in.GetEnable2FA() {
		resp.Settings2FA = &idam_api.Settings2FA{
			Secret: otpSecret,
			Type:   idam_api.Settings2FA_TOTP,
		}
	}

	return resp, nil
}

// DeleteIdentity deletes an identity
func (m *Manager) DeleteIdentity(ctx context.Context, in *homebot_api.URN) (*homebot_api.Empty, error) {
	token, err := m.getToken(ctx)
	if err != nil {
		return nil, err
	}

	if in == nil {
		return nil, errors.New("invald message")
	}

	u := urn.FromProtobuf(in)
	if !u.Valid() {
		return nil, errors.New("invalid URN")
	}

	// Only admin and the identity itself can delete it
	if !token.HasGroup(urn.IdamAdminGroup) && token.URN.String() == u.String() {
		return nil, idam.ErrNotAuthorized
	}

	if err := m.idam.Delete(u); err != nil {
		return nil, err
	}

	return &homebot_api.Empty{}, nil
}

func (m *Manager) getToken(ctx context.Context) (*token.Token, error) {
	return token.FromMetadata(ctx, m.keyFn)
}
