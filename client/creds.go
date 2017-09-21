package client

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/homebot/idam/token"
	idamV1 "github.com/homebot/protobuf/pkg/api/idam/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

// CredentialsFunc returns the username, password and optionally otp token
type CredentialsFunc func() (username, password, otp string, err error)

// OnAuthenticatedFunc is invoked by IdamCredentials when a new token has been acquired
type OnAuthenticatedFunc func(t *token.Token)

// IdamCredentials are grpc.PerRPCCredentials that automatically renew the authentication
// token
type IdamCredentials struct {
	rw sync.RWMutex

	endpoints []string
	dialOpts  []grpc.DialOption

	creds CredentialsFunc

	t *token.Token

	onAuthenticated OnAuthenticatedFunc
}

func NewIdamCredentials(endpoint string, t string, fn CredentialsFunc, opts ...grpc.DialOption) (*IdamCredentials, error) {
	creds := &IdamCredentials{
		endpoints: []string{endpoint},
		dialOpts:  opts,
		creds:     fn,
	}

	if t != "" {
		parsed, err := token.FromJWT(t, nil)
		if err != nil {
			return nil, err
		}

		creds.t = parsed
	}

	if _, err := creds.authenticate(context.Background()); err != nil {
		return nil, err
	}
	return creds, nil
}

func (cred *IdamCredentials) OnAuthenticated(fn OnAuthenticatedFunc) error {
	cred.rw.Lock()
	defer cred.rw.Unlock()

	if cred.onAuthenticated != nil {
		return errors.New("OnAuthenticatedFunc already set")
	}

	cred.onAuthenticated = fn
	return nil
}

// RequireTransportSecurity implements the grpc.PerRPCCredentials interface
func (cred *IdamCredentials) RequireTransportSecurity() bool {
	return false
}

// GetRequestMetadata adds authentication tokens for the new request and renews the current token if
// required. It implements the grpc.PerRPCCredentials interface
func (cred *IdamCredentials) GetRequestMetadata(ctx context.Context, uri ...string) (map[string]string, error) {
	t, err := cred.authenticate(ctx)
	if err != nil {
		return nil, err
	}

	return map[string]string{
		"authorization": t.JWT,
	}, nil
}

func (cred *IdamCredentials) Token() *token.Token {
	cred.rw.RLock()
	defer cred.rw.RUnlock()

	return cred.t
}

func (cred *IdamCredentials) authenticate(ctx context.Context) (*token.Token, error) {
	cred.rw.Lock()
	defer cred.rw.Unlock()

	if cred.t == nil || cred.t.Valid() != nil {
		user, pass, otp, err := cred.creds()
		if err != nil {
			return nil, err
		}

		conn, err := grpc.Dial(cred.endpoints[0], cred.dialOpts...)
		if err != nil {
			return nil, err
		}
		defer conn.Close()

		cli := idamV1.NewAuthenticatorClient(conn)
		res, err := cli.Login(ctx, &idamV1.LoginRequest{
			Principal: &idamV1.LoginRequest_Urn{
				Urn: user,
			},
			Password:      pass,
			OneTimeSecret: otp,
		})
		if err != nil {
			return nil, err
		}

		t, err := token.FromJWT(res.GetToken(), nil)
		if err != nil {
			return nil, err
		}

		cred.t = t

		if cred.onAuthenticated != nil {
			cred.onAuthenticated(t)
		}
	}

	if cred.t != nil && cred.t.Expire.After(time.Now().Add(time.Minute*5)) {
		conn, err := grpc.Dial(cred.endpoints[0], cred.dialOpts...)
		if err != nil {
			return nil, err
		}
		defer conn.Close()

		md := metadata.New(map[string]string{
			"authorization": cred.t.JWT,
		})
		ctx = metadata.NewOutgoingContext(ctx, md)

		cli := idamV1.NewAuthenticatorClient(conn)
		res, err := cli.Renew(ctx, &idamV1.RenewTokenRequest{})
		if err != nil {
			return nil, err
		}

		t, err := token.FromJWT(res.GetToken(), nil)
		if err != nil {
			return nil, err
		}

		if cred.onAuthenticated != nil {
			cred.onAuthenticated(t)
		}

		cred.t = t
	}

	return cred.t, nil
}
