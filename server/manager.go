package server

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"time"

	"github.com/homebot/core/urn"

	"github.com/homebot/core/log"
	"github.com/homebot/idam"
	"github.com/homebot/idam/provider"
	"github.com/homebot/idam/token"
	homebot_api "github.com/homebot/protobuf/pkg/api"
	idam_api "github.com/homebot/protobuf/pkg/api/idam"
)

// Option configures a new manager
type Option func(m *Manager) error

// WithSharedKey configures a shared key for siging and verifying JWTs
func WithSharedKey(key string) Option {
	return func(m *Manager) error {
		m.signingCert = []byte(key)
		m.signingKey = []byte(key)
		m.alg = "HS256"
		return nil
	}
}

// WithLogger configures the logger to use
func WithLogger(l log.Logger) Option {
	return func(m *Manager) error {
		m.log = l
		return nil
	}
}

// WithIssuer configures the name of the issuer for new JWTs
func WithIssuer(s string) Option {
	return func(m *Manager) error {
		m.issuer = s
		return nil
	}
}

// WithTokenDuration configures how long a JWT is valid until it is marked
// as expired
func WithTokenDuration(d time.Duration) Option {
	return func(m *Manager) error {
		m.tokenDuration = d
		return nil
	}
}

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
		// TODO make issuer and expire-at confgurable
		newToken, err := token.New(identity.URN(), identity.Groups, "idam", time.Now().Add(time.Hour), m.alg, bytes.NewReader(m.signingKey))
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

// CreateIdentity creates a new identity
func (m *Manager) CreateIdentity(ctx context.Context, in *idam_api.CreateIdentityRequest) (*idam_api.CreateIdentityResponse, error) {
	token, err := m.getToken(ctx)
	if err != nil {
		return nil, err
	}

	logger := log.WithURN(token.URN)

	if !token.HasGroup(urn.IdamAdminGroup) {
		logger.Warnf("not allowed to create a new identity")
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

	logFA := "without"
	if in.GetEnable2FA() {
		logFA = "with"
	}
	logger.Infof("created new identity %q %s 2FA", identity.URN().String(), logFA)

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

	logger := log.WithURN(token.URN)

	if in == nil {
		return nil, errors.New("invald message")
	}

	u := urn.FromProtobuf(in)
	if !u.Valid() {
		return nil, errors.New("invalid URN")
	}

	// Only admin and the identity itself can delete it
	if !token.HasGroup(urn.IdamAdminGroup) && token.URN.String() == u.String() {
		logger.Warnf("not allowed to delete identity %q", u.String())
		return nil, idam.ErrNotAuthorized
	}

	if err := m.idam.Delete(u); err != nil {
		return nil, err
	}

	logger.Warnf("identity %q deleted", u.String())
	return &homebot_api.Empty{}, nil
}

func (m *Manager) getToken(ctx context.Context) (*token.Token, error) {
	return token.FromMetadata(ctx, func(issuer string, alg string) (interface{}, error) {
		if strings.ToUpper(alg) != strings.ToUpper(m.alg) {
			return nil, errors.New("unexpected token algorithim")
		}

		return m.signingCert, nil
	})
}

var _ idam_api.IdentityManagerServer = &Manager{}
var _ idam_api.AuthenticatorServer = &Manager{}
