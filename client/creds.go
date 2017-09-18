package client

import (
	"context"
	"time"

	"github.com/homebot/idam/token"
	idamV1 "github.com/homebot/protobuf/pkg/api/idam/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

// CredentialsFunc returns the username, password and optionally otp token
type CredentialsFunc func() (username, password, otp string, err error)

// IdamCredentials are grpc.PerRPCCredentials that automatically renew the authentication
// token
type IdamCredentials struct {
	endpoints []string
	dialOpts  []grpc.DialOption

	creds CredentialsFunc

	t *token.Token
}

func NewIdamCredentials(endpoint string, token string, fn CredentialsFunc, opts ...grpc.DialOption) (*IdamCredentials, error) {
	creds := &IdamCredentials{
		endpoints: []string{endpoint},
		dialOpts:  opts,
		creds:     fn,
	}

	if err := creds.authenticate(context.Background()); err != nil {
		return nil, err
	}
	return creds, nil
}

// RequireTransportSecurity implements the grpc.PerRPCCredentials interface
func (cred *IdamCredentials) RequireTransportSecurity() bool {
	return false
}

// GetRequestMetadata adds authentication tokens for the new request and renews the current token if
// required. It implements the grpc.PerRPCCredentials interface
func (cred *IdamCredentials) GetRequestMetadata(ctx context.Context, uri ...string) (map[string]string, error) {
	if err := cred.authenticate(ctx); err != nil {
		return nil, err
	}

	return map[string]string{
		"authorization": cred.t.JWT,
	}, nil
}

func (cred *IdamCredentials) authenticate(ctx context.Context) error {
	if cred.t == nil || cred.t.Valid() != nil {
		user, pass, otp, err := cred.creds()
		if err != nil {
			return err
		}

		conn, err := grpc.Dial(cred.endpoints[0], cred.dialOpts...)
		if err != nil {
			return err
		}
		defer conn.Close()

		cli := idamV1.NewAuthenticatorClient(conn)
		res, err := cli.Login(ctx, &idamV1.LoginRequest{
			Principal: &idamV1.LoginRequest_Urn{
				Urn: user,
			},
			Password:      []byte(pass),
			OneTimeSecret: []byte(otp),
		})
		if err != nil {
			return err
		}

		t, err := token.FromJWT(res.GetToken(), nil)
		if err != nil {
			return err
		}

		cred.t = t
	}

	if cred.t != nil && cred.t.Expire.After(time.Now().Add(time.Minute*5)) {
		conn, err := grpc.Dial(cred.endpoints[0], cred.dialOpts...)
		if err != nil {
			return err
		}
		defer conn.Close()

		md := metadata.New(map[string]string{
			"authorization": cred.t.JWT,
		})
		ctx = metadata.NewOutgoingContext(ctx, md)

		cli := idamV1.NewAuthenticatorClient(conn)
		res, err := cli.Renew(ctx, &idamV1.RenewTokenRequest{})
		if err != nil {
			return err
		}

		t, err := token.FromJWT(res.GetToken(), nil)
		if err != nil {
			return err
		}

		cred.t = t
	}

	return nil
}
