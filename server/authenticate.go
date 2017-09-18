package server

import (
	"bytes"
	"context"
	"errors"
	"time"

	"github.com/homebot/core/log"
	"github.com/homebot/core/urn"
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

	principal := urn.URN(in.GetUrn())
	if !principal.Valid() {
		return nil, urn.ErrInvalidURN
	}

	ok, err := m.idam.Verify(principal, string(in.GetPassword()), string(in.GetOneTimeSecret()))

	if err != nil || !ok {
		return nil, idam.ErrNotAuthenticated
	}

	identity, _, err := m.idam.Get(principal)
	if err != nil {
		return nil, err
	}

	newToken, err := token.New(identity.URN(), identity.Roles, m.issuer, time.Now().Add(m.tokenDuration), m.alg, bytes.NewReader(m.signingKey))
	if err != nil {
		return nil, err
	}

	log.WithURN(identity.URN()).Infof("issuing new JWT")

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

	identity, _, err := m.idam.Get(auth.URN)
	if err != nil {
		return nil, err
	}

	newToken, err := token.New(identity.URN(), identity.Roles, m.issuer, time.Now().Add(m.tokenDuration), m.alg, bytes.NewReader(m.signingKey))
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

	var identity *idam.Identity

	if ok && auth.Valid() == nil {
		// Already authenticated, issue a new token
		i, _, err := m.idam.Get(auth.URN)
		if err != nil {
			return err
		}

		identity = i
		issue = true

		log.WithURN(auth.URN).Debugf("re-authenticated")
	} else {
		// wait for the first "Answer" containing the username
		ans, err := stream.Recv()
		if err != nil {
			return err
		}

		if ans.GetType() != idamV1.ConversationChallengeType_USERNAME || ans.GetUsername() == "" {
			return errors.New("invalid type")
		}

		u := urn.URN(ans.GetUsername())
		if !u.Valid() {
			return urn.ErrInvalidURN
		}

		i, has2FA, err := m.idam.Get(u)
		if err != nil {
			return err
		}

		logFA := "without"
		if has2FA {
			logFA = "with"
		}

		log.WithURN(u).Debugf("started authentication %s 2FA", logFA)

		identity = i

		ok2FA := !has2FA
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

		if has2FA {
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

		ok, err := m.idam.Verify(u, pass, otp)
		if err != nil {
			log.WithURN(u).Infof("authentication failed")
			return err
		}

		if !ok {
			return idam.ErrNotAuthenticated
		}

		log.WithURN(u).Infof("authentication successfull")

		issue = true
	}

	if issue && identity != nil {
		newToken, err := token.New(identity.URN(), identity.Roles, m.issuer, time.Now().Add(m.tokenDuration), m.alg, bytes.NewReader(m.signingKey))
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

		log.WithURN(identity.URN()).Infof("issuing new JWT")

		if err := stream.Send(resp); err != nil {
			return err
		}

		return nil
	}

	return idam.ErrNotAuthenticated
}

var _ idamV1.AuthenticatorServer = &Manager{}
