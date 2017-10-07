package server

import (
	"context"
	"errors"

	"github.com/pquerna/otp/totp"

	"golang.org/x/crypto/bcrypt"

	"github.com/golang/protobuf/ptypes/empty"
	"github.com/homebot/idam"
	"github.com/homebot/idam/policy"
	"github.com/homebot/idam/token"
	"github.com/homebot/insight/logger"
	idamV1 "github.com/homebot/protobuf/pkg/api/idam/v1"
)

// GetProfile implements homebot/api/idam/v1/profile.proto:Profile
func (m *Manager) GetProfile(ctx context.Context, in *empty.Empty) (*idamV1.Identity, error) {
	i, _, err := m.identityFromCtx(ctx)
	if err != nil {
		return nil, err
	}

	pb, err := idam.IdentityProto(i)
	if err != nil {
		return nil, err
	}

	return pb, nil
}

// ChangePassword implements homebot/api/idam/v1/profile.proto:Profile
func (m *Manager) ChangePassword(ctx context.Context, in *idamV1.ChangePasswordRequest) (*empty.Empty, error) {
	i, _, err := m.identityFromCtx(ctx)
	if err != nil {
		return nil, err
	}

	pwd, err := m.identities.GetPasswordHash(i.AccountName())
	if err != nil {
		return nil, err
	}

	if err := idam.CheckPassword(pwd, in.GetCurrentPassword()); err != nil {
		return nil, err
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(in.GetNewPassword()), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}

	if err := m.identities.ChangePasswordHash(i.AccountName(), hash); err != nil {
		return nil, err
	}

	return &empty.Empty{}, nil
}

// Change2FA implements homebot/api/idam/v1/profile.proto:Profile
func (m *Manager) Change2FA(ctx context.Context, in *idamV1.Change2FARequest) (*idamV1.Change2FAResponse, error) {
	i, _, err := m.identityFromCtx(ctx)
	if err != nil {
		return nil, err
	}

	otpSecret, err := m.identities.Get2FASecret(i.AccountName())
	if err != nil {
		return nil, err
	}

	if in.GetEnabled() {
		if otpSecret != "" {
			return &idamV1.Change2FAResponse{Enabled: true}, nil
		}

		key, err := totp.Generate(totp.GenerateOpts{
			Issuer:      m.issuer,
			AccountName: i.AccountName(),
		})
		if err != nil {
			return nil, err
		}

		if err := m.identities.Set2FASecret(i.AccountName(), key.Secret()); err != nil {
			return nil, err
		}

		return &idamV1.Change2FAResponse{Enabled: true, Secret: key.String()}, nil
	}

	if otpSecret == "" {
		return &idamV1.Change2FAResponse{Enabled: false}, nil
	}

	if err := idam.Check2FA(otpSecret, in.GetCurrentOneTimeSecret()); err != nil {
		return nil, err
	}

	if err := m.identities.Set2FASecret(i.AccountName(), ""); err != nil {
		return nil, err
	}

	return &idamV1.Change2FAResponse{Enabled: false}, nil
}

// SetUserData implements homebot/api/idam/v1/profile.proto:Profile
func (m *Manager) SetUserData(ctx context.Context, in *idamV1.UserData) (*idamV1.Identity, error) {
	i, _, err := m.identityFromCtx(ctx)
	if err != nil {
		return nil, err
	}

	if !idam.IsUser(i) {
		return nil, errors.New("invalid account type")
	}

	user := i.(*idam.User)

	user.FirstName = in.GetFirstName()
	user.LastName = in.GetLastName()
	user.MailAddresses = in.GetAdditionalMails()

	u, err := m.identities.Update(user)
	if err != nil {
		return nil, err
	}

	pb, err := idam.IdentityProto(u)
	if err != nil {
		return nil, err
	}

	return pb, nil
}

func (m *Manager) identityFromCtx(ctx context.Context) (idam.Identity, *token.Token, error) {
	t, ok := policy.TokenFromContext(ctx)
	if !ok {
		return nil, nil, errors.New("missing token")
	}

	i, err := m.identities.Get(t.Name)
	if err != nil {
		return nil, nil, err
	}

	return i, t, nil
}

func (m *Manager) getLogger(ctx context.Context) logger.Logger {
	i, _, err := m.identityFromCtx(ctx)
	if err != nil {
		return m.log
	}

	return m.log.WithIdentity(i.AccountName())
}
