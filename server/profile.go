package server

import (
	"context"
	"errors"

	"github.com/homebot/idam"
	"github.com/homebot/idam/policy"

	homebotApi "github.com/homebot/protobuf/pkg/api"
	idamV1 "github.com/homebot/protobuf/pkg/api/idam/v1"
)

// GetProfile returns the identitiy profile
func (m *Manager) GetProfile(ctx context.Context, _ *homebotApi.Empty) (*idamV1.Identity, error) {
	auth, ok := policy.TokenFromContext(ctx)
	if !ok || auth.Valid() != nil {
		return nil, idam.ErrNotAuthenticated
	}

	identity, _, err := m.idam.Get(auth.URN)
	if err != nil {
		return nil, err
	}

	return identity.ToProtobuf(), nil
}

// ChangePassword changes the identities password
func (m *Manager) ChangePassword(ctx context.Context, in *idamV1.ChangePasswordRequest) (*homebotApi.Empty, error) {
	auth, ok := policy.TokenFromContext(ctx)
	if !ok || auth.Valid() != nil {
		return nil, idam.ErrNotAuthenticated
	}

	if in == nil || in.NewPassword == "" {
		return nil, errors.New("invalid request")
	}

	// if the identitiy is not an IDAM admin, we need to verify the "old" password
	ok, err := m.idam.VerifyPassword(auth.URN, in.GetCurrentPassword())
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, idam.ErrNotAuthorized
	}

	err = m.idam.ChangePassword(auth.URN, in.GetNewPassword())
	if err != nil {
		return nil, err
	}

	return &homebotApi.Empty{}, nil
}

// Change2FA changes two-factor-authentication settings
func (m *Manager) Change2FA(ctx context.Context, in *idamV1.Change2FARequest) (*idamV1.Change2FAResponse, error) {
	auth, ok := policy.TokenFromContext(ctx)
	if !ok || auth.Valid() != nil {
		return nil, idam.ErrNotAuthenticated
	}

	_, has2FA, err := m.idam.Get(auth.URN)
	if err != nil {
		return nil, err
	}

	shouldEnable := in.GetEnabled()

	if has2FA && shouldEnable {
		return nil, errors.New("already enabled")
	}

	if !has2FA && shouldEnable {
		secret, err := m.idam.Enable2FA(auth.URN)
		if err != nil {
			return nil, err
		}

		return &idamV1.Change2FAResponse{
			Enabled: true,
			Secret:  secret,
		}, nil
	}

	if !has2FA && !shouldEnable {
		return nil, errors.New("not enabled")
	}

	if has2FA && !shouldEnable {
		// Before allowing to identity to disable 2FA, we need to verify it
		// once more
		ok, err := m.idam.VerifyOTP(auth.URN, in.GetCurrentOneTimeSecret())
		if err != nil || !ok {
			return nil, idam.ErrNotAuthorized
		}

		if err := m.idam.Disable2FA(auth.URN); err != nil {
			return nil, err
		}

		return &idamV1.Change2FAResponse{
			Enabled: false,
		}, nil
	}

	return nil, errors.New("unknown error")
}

// SetUserData updates the user profile of an identity
func (m *Manager) SetUserData(ctx context.Context, in *idamV1.UserData) (*idamV1.Identity, error) {
	auth, ok := policy.TokenFromContext(ctx)
	if !ok || auth.Valid() != nil {
		return nil, idam.ErrNotAuthenticated
	}

	i, _, err := m.idam.Get(auth.URN)

	if !i.IsUser() {
		return nil, errors.New("not a user identity")
	}

	userData := idam.UserData{
		PrimaryMail:    in.GetEmailAddress(),
		SecondaryMails: in.GetSecondaryMailAddresses(),
		FirstName:      in.GetFirstName(),
		LastName:       in.GetLastName(),
	}

	i.UserData = &userData

	if err := m.idam.Update(auth.URN, *i); err != nil {
		return nil, err
	}

	i, _, err = m.idam.Get(auth.URN)
	if err != nil {
		return nil, err
	}

	return i.ToProtobuf(), nil
}

var _ idamV1.ProfileServer = &Manager{}
