package server

import (
	"bytes"
	"errors"
	"time"

	"github.com/homebot/core/log"
	"github.com/homebot/core/urn"
	"github.com/homebot/idam"
	"github.com/homebot/idam/token"
	idam_api "github.com/homebot/protobuf/pkg/api/idam"
)

// Authenticate authenticates an identity and issues a new JWT
func (m *Manager) Authenticate(stream idam_api.Authenticator_AuthenticateServer) error {
	issue := false

	ctx := stream.Context()
	auth, err := m.getToken(ctx)

	var identity *idam.Identity

	if err == nil {
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
		newToken, err := token.New(identity.URN(), identity.Groups, m.issuer, time.Now().Add(m.tokenDuration), m.alg, bytes.NewReader(m.signingKey))
		if err != nil {
			return err
		}

		resp := &idam_api.AuthRequest{
			Data: &idam_api.AuthRequest_Token{
				Token: newToken,
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

var _ idam_api.AuthenticatorServer = &Manager{}
