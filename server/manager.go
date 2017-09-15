package server

import (
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

// List returns a list of identities
func (m *Manager) List(in *homebot_api.Empty, stream idam_api.IdentityManager_ListServer) error {
	token, err := m.getToken(stream.Context())
	if err != nil {
		return err
	}

	identities := m.idam.Identities()

	for _, i := range identities {
		if token.HasGroup(urn.IdamAdminGroup) || token.Owns(i) {
			stream.Send(i.ToProtobuf())
		}
	}

	return nil
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
