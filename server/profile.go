package server

import (
	"context"
	"errors"

	"github.com/homebot/core/urn"
	"github.com/homebot/idam"

	iotc_api "github.com/homebot/protobuf/pkg/api"
	idamV1 "github.com/homebot/protobuf/pkg/api/idam/v1"
)

// GetProfile returns the identitiy profile
func (m *Manager) GetProfile(ctx context.Context, in *iotc_api.URN) (*idamV1.Profile, error) {
	auth, err := m.getToken(ctx)
	if err != nil {
		return nil, err
	}

	u := urn.FromProtobuf(in)
	if !u.Valid() {
		return nil, urn.ErrInvalidURN
	}

	if !auth.HasGroup(urn.IdamAdminGroup) || !auth.OwnsURN(u) {
		return nil, idam.ErrNotAuthorized
	}

	identity, has2FA, err := m.idam.Get(u)
	if err != nil {
		return nil, err
	}

	return &idamV1.Profile{
		Identity: identity.ToProtobuf(),
		Has2FA:   has2FA,
	}, nil
}

// ChangePassword changes the identities password
func (m *Manager) ChangePassword(ctx context.Context, in *idamV1.ChangePasswordRequest) (*iotc_api.Empty, error) {
	auth, err := m.getToken(ctx)
	if err != nil {
		return nil, err
	}

	if in == nil || in.Urn == nil || in.NewPassword == "" {
		return nil, errors.New("invalid request")
	}

	u := urn.FromProtobuf(in.Urn)
	if !u.Valid() {
		return nil, urn.ErrInvalidURN
	}

	if !auth.HasGroup(urn.IdamAdminGroup) || !auth.OwnsURN(u) {
		return nil, idam.ErrNotAuthorized
	}

	// if the identitiy is not an IDAM admin, we need to verify the "old" password
	if !auth.HasGroup(urn.IdamAdminGroup) {
		ok, err := m.idam.VerifyPassword(u, in.GetOldPassword())
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, idam.ErrNotAuthenticated
		}
	}

	err = m.idam.ChangePassword(u, in.GetNewPassword())
	if err != nil {
		return nil, err
	}

	return &iotc_api.Empty{}, nil
}

// Change2FA changes two-factor-authentication settings
func (m *Manager) Change2FA(ctx context.Context, in *idamV1.Change2FARequest) (*idamV1.Change2FAResult, error) {
	auth, err := m.getToken(ctx)
	if err != nil {
		return nil, err
	}

	if in == nil || in.Urn == nil || in.GetChange() == nil {
		return nil, errors.New("invalid request")
	}

	u := urn.FromProtobuf(in.Urn)

	if !u.Valid() {
		return nil, urn.ErrInvalidURN
	}

	if !auth.HasGroup(urn.IdamAdminGroup) || !auth.OwnsURN(u) {
		return nil, idam.ErrNotAuthorized
	}

	_, has2FA, err := m.idam.Get(u)
	if err != nil {
		return nil, err
	}

	if has2FA && in.GetEnable() {
		return nil, errors.New("already enabled")
	}

	if !has2FA && in.GetEnable() {
		secret, err := m.idam.Enable2FA(u)
		if err != nil {
			return nil, err
		}

		return &idamV1.Change2FAResult{
			Urn: urn.ToProtobuf(u),
			Result: &idamV1.Change2FAResult_Settings{
				Settings: &idamV1.Settings2FA{
					Secret: secret,
					Type:   idamV1.Settings2FA_TOTP,
				},
			},
		}, nil
	}

	if !has2FA && in.GetDisable() {
		return nil, errors.New("not enabled")
	}

	if has2FA && in.GetDisable() {
		if !auth.HasGroup(urn.IdamAdminGroup) {
			ok, err := m.idam.VerifyOTP(u, in.GetCurrentOTP())
			if err != nil || !ok {
				return nil, idam.ErrNotAuthorized
			}
		}

		if err := m.idam.Disable2FA(u); err != nil {
			return nil, err
		}

		return &idamV1.Change2FAResult{
			Urn: urn.ToProtobuf(u),
			Result: &idamV1.Change2FAResult_Disabled{
				Disabled: true,
			},
		}, nil
	}

	return nil, errors.New("unknown error")
}

// UpdateProfile updates the user profile
func (m *Manager) UpdateProfile(ctx context.Context, in *idamV1.Identity) (*idamV1.Profile, error) {
	auth, err := m.getToken(ctx)
	if err != nil {
		return nil, err
	}

	if in == nil || in.Urn == nil {
		return nil, errors.New("invalid message")
	}

	u := urn.FromProtobuf(in.Urn)
	if !u.Valid() {
		return nil, urn.ErrInvalidURN
	}

	if !auth.HasGroup(urn.IdamAdminGroup) || auth.OwnsURN(u) {
		return nil, idam.ErrNotAuthorized
	}

	identity := idam.IdentityFromProto(in)
	if err := identity.Valid(); err != nil {
		return nil, err
	}

	if err := m.idam.Update(u, *identity); err != nil {
		return nil, err
	}

	ident, has2FA, err := m.idam.Get(u)
	if err != nil {
		return nil, err
	}

	return &idamV1.Profile{
		Identity: ident.ToProtobuf(),
		Has2FA:   has2FA,
	}, nil
}

var _ idamV1.ProfileManagerServer = &Manager{}
