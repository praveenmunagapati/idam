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
	keyFn token.KeyProviderFunc
}

// Authenticate authenticates an identity and issues a new JWT
func (m *Manager) Authenticate(stream idam_api.Authenticator_AuthenticateServer) error {
	issue := false

	ctx := stream.Context()
	token, err := m.getToken(ctx)

	var identity *idam.Identity

	if err == nil {
		// Already authenticated, issue a new token
		i, _, err := m.idam.Get(token.URN)
		if err != nil {
			return err
		}

		identity = i
		issue = true
	} else {
		// wait for the first "Answer" containing the username
		ans, err := stream.Recv()
		if err != nil {
			return err
		}

		if ans.GetType() != idam_api.QuestionType_USERNAME || ans.GetUsername() == nil {
			return errors.New("invalid type")
		}

		u := urn.FromProtobuf(ans.GetUsername().GetUrn())
		if !u.Valid() {
			return urn.ErrInvalidURN
		}

		i, has2FA, err := m.idam.Get(u)
		if err != nil {
			return err
		}

		identity = i

		ok2FA := !has2FA
		okPass := false

		pass := ""
		otp := ""

		stream.Send(&idam_api.AuthRequest{
			Data: &idam_api.AuthRequest_Question{
				Question: &idam_api.Question{
					Type: idam_api.QuestionType_PASSWORD,
				},
			},
		})

		if has2FA {
			stream.Send(&idam_api.AuthRequest{
				Data: &idam_api.AuthRequest_Question{
					Question: &idam_api.Question{
						Type: idam_api.QuestionType_OTP,
					},
				},
			})
		}

		for {
			msg, err := stream.Recv()
			if err != nil {
				return err
			}

			switch msg.GetType() {
			case idam_api.QuestionType_OTP:
				if ok2FA {
					return errors.New("unexpected message")
				}

				otp = msg.GetSecret()
				ok2FA = true

			case idam_api.QuestionType_PASSWORD:
				if okPass {
					return errors.New("unexpected message")
				}

				pass = msg.GetSecret()
				okPass = true
			default:
				return errors.New("unexpected message")
			}

			if okPass && ok2FA {
				break
			}
		}

		ok, err := m.idam.Verify(u, pass, otp)
		if err != nil {
			return err
		}

		if !ok {
			return idam.ErrNotAuthenticated
		}

		issue = true
	}

	if issue && identity != nil {
		// TODO(ppacher): issue new token
		return nil
	}

	return idam.ErrNotAuthenticated
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

var _ idam_api.IdentityManagerServer = &Manager{}
var _ idam_api.AuthenticatorServer = &Manager{}
