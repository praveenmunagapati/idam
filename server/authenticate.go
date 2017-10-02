package server

import (
	"bytes"
	"context"
	"errors"
	"time"

	"github.com/homebot/core/log"
	"github.com/homebot/idam"
	"github.com/homebot/idam/policy"
	"github.com/homebot/idam/token"
	idamV1 "github.com/homebot/protobuf/pkg/api/idam/v1"
)

// Login authenticates an identity and issues a new JWT
func (m *Manager) Login(ctx context.Context, in *idamV1.LoginRequest) (*idamV1.LoginResponse, error) {
	if in.GetUrn() == "" {
		return nil, errors.New("missing identity principal")
	}

	principal := in.GetUrn()

	identity, err := m.identities.Get(principal)
	if err != nil {
		return nil, err
	}

	hash, err := m.identities.GetPasswordHash(principal)
	if err != nil {
		return nil, err
	}

	secret, err := m.identities.Get2FASecret(principal)
	if err != nil {
		return nil, err
	}

	if err := idam.CheckPassword(hash, in.GetPassword()); err != nil {
		return nil, err
	}

	if secret != "" {
		if err := idam.Check2FA(secret, in.GetOneTimeSecret()); err != nil {
			return nil, err
		}
	}

	permissions, err := m.getPermissionNames(principal)
	if err != nil {
		return nil, err
	}

	newToken, err := token.New(identity.AccountName(), permissions, m.issuer, time.Now().Add(m.tokenDuration), m.alg, bytes.NewReader(m.signingKey))
	if err != nil {
		return nil, err
	}

	return &idamV1.LoginResponse{
		Token: newToken,
	}, nil
}

// Renew an authentication token when it is still valid
func (m *Manager) Renew(ctx context.Context, in *idamV1.RenewTokenRequest) (*idamV1.RenewTokenResponse, error) {
	auth, ok := policy.TokenFromContext(ctx)
	if !ok || auth.Valid() != nil {
		return nil, errors.New("token not valid")
	}

	identity, err := m.identities.Get(auth.Name)
	if err != nil {
		return nil, err
	}

	permissions, err := m.getPermissionNames(auth.Name)
	if err != nil {
		return nil, err
	}

	newToken, err := token.New(identity.AccountName(), permissions, m.issuer, time.Now().Add(m.tokenDuration), m.alg, bytes.NewReader(m.signingKey))
	if err != nil {
		return nil, err
	}

	return &idamV1.RenewTokenResponse{
		Token: newToken,
	}, nil
}

// StartConversation authenticates an identity and issues a new JWT
func (m *Manager) StartConversation(stream idamV1.Authenticator_StartConversationServer) error {
	issue := false

	auth, ok := policy.TokenFromContext(stream.Context())

	var identity idam.Identity

	if ok && auth.Valid() == nil {
		// Already authenticated, issue a new token
		i, err := m.identities.Get(auth.Name)
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

		if ans.GetType() != idamV1.ConversationChallengeType_USERNAME || ans.GetUsername() == "" {
			return errors.New("invalid type")
		}

		i, err := m.identities.Get(ans.GetUsername())
		if err != nil {
			return err
		}

		secret, err := m.identities.Get2FASecret(ans.GetUsername())
		if err != nil {
			return err
		}

		hash, err := m.identities.GetPasswordHash(ans.GetUsername())
		if err != nil {
			return err
		}

		logFA := "without"
		if secret != "" {
			logFA = "with"
		}

		log.Debugf("started authentication %s 2FA", logFA)

		identity = i

		ok2FA := !(secret == "")
		okPass := false

		pass := ""
		otp := ""

		stream.Send(&idamV1.ConversationRequest{
			Request: &idamV1.ConversationRequest_Question{
				Question: &idamV1.ConversationQuestion{
					Type: idamV1.ConversationChallengeType_PASSWORD,
				},
			},
		})

		if secret != "" {
			stream.Send(&idamV1.ConversationRequest{
				Request: &idamV1.ConversationRequest_Question{
					Question: &idamV1.ConversationQuestion{
						Type: idamV1.ConversationChallengeType_TOTP,
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
			case idamV1.ConversationChallengeType_TOTP:
				if ok2FA {
					return errors.New("unexpected message")
				}

				otp = msg.GetOneTimeSecret()
				ok2FA = true

			case idamV1.ConversationChallengeType_PASSWORD:
				if okPass {
					return errors.New("unexpected message")
				}

				pass = msg.GetPassword()
				okPass = true
			default:
				return errors.New("unexpected message")
			}

			if okPass && ok2FA {
				break
			}
		}

		if err := idam.CheckPassword(hash, pass); err != nil {
			log.Infof("authentication failed")
			return err
		}

		if secret != "" {
			if err := idam.Check2FA(secret, otp); err != nil {
				log.Infof("authentication failed")
				return err
			}
		}

		log.Infof("authentication successfull")

		issue = true
	}

	if issue && identity != nil {
		permissions, err := m.getPermissionNames(identity.AccountName())
		if err != nil {
			return err
		}

		newToken, err := token.New(identity.AccountName(), permissions, m.issuer, time.Now().Add(m.tokenDuration), m.alg, bytes.NewReader(m.signingKey))
		if err != nil {
			return err
		}

		resp := &idamV1.ConversationRequest{
			Request: &idamV1.ConversationRequest_LoginSuccess{
				LoginSuccess: &idamV1.LoginResponse{
					Token: newToken,
				},
			},
		}

		log.Infof("issuing new JWT")

		if err := stream.Send(resp); err != nil {
			return err
		}

		return nil
	}

	return errors.New("not authenticated")
}

var _ idamV1.AuthenticatorServer = &Manager{}
