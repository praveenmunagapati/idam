package client

import (
	"context"
	"errors"

	"github.com/homebot/idam"
	"github.com/homebot/idam/token"
	"google.golang.org/grpc"
)

// AuthClient supports authentication at an IDAM based authentication server
type AuthClient interface {
	// Login performs a login request against IDAM and returns the signed JSON
	// Web token. The token will also be stored within the client itself so further
	// requests to IDAM are authenticated
	Login(ctx context.Context, username, password, otp string) (string, error)

	// Renew tries to renew the clients token and will return the new token
	// issued by the authority
	Renew(ctx context.Context) (string, error)

	// Authenticated returns true if the client is still authenticated (e.g. has a valid
	// JWT)
	Authenticated() bool

	// Conn returns the underlying grpc.ClientConn
	Conn() *grpc.ClientConn

	// Close closes the unerlying gRPC connection
	Close() error
}

// Client is a gRPC client wrapper for communicating with IDAM
type Client interface {
	AuthClient

	// ChangePassword changes the password for the current identity
	ChangePassword(ctx context.Context, current, new string) error

	// GetProfile returns the identity profile for the currently authenticated
	// identity
	GetProfile(ctx context.Context) (*idam.Identity, error)

	// Change2FA changes the identities two-factor-authentication settings
	// If 2FA should be disabled, the current OTP needs to be passed. If 2FA
	// becomes enabled, the returned string is the new TOTP secret
	Change2FA(ctx context.Context, enabled bool, currentOTP string) (string, error)

	// SetUserData updates the current user settings
	SetUserData(ctx context.Context, userData idam.UserData) error
}

// AdminClient is an IDAM administration client
type AdminClient interface {
	AuthClient

	// CreateIdentity creates a new identity
	CreateIdentity(ctx context.Context, identity idam.Identity) error

	// DeleteIdentity deletes the given identity
	DeleteIdentity(ctx context.Context, identity string) error

	// UpdateIdentity updates the identity
	UpdateIdentity(ctx context.Context, identitiy idam.Identity) error

	// LookupIdentities searches for all identities on the server
	LookupIdentities(ctx context.Context) ([]idam.Identity, error)

	// CreateRole creates a new role
	CreateRole(ctx context.Context, role string) error

	// ListRoles lists available roles
	ListRoles(ctx context.Context) ([]string, error)

	// DeleteRole deletes a role from the server
	DeleteRole(ctx context.Context, role string) error

	// AssignRole assings a role to an identity
	AssignRole(ctx context.Context, role, identity string) error

	// UnassignRole removes a role from an identity
	UnassignRole(ctx context.Context, role, identity string) error
}

type authClient struct {
	conn *grpc.ClientConn

	creds *token.JWTCredentials

	dialOpt []grpc.DialOption
}

// ClientOption is an option for AuthClient
type ClientOption func(c *authClient) error

// WithDialOption sets a gRPC.DialOption for the connection
func WithDialOption(opts ...grpc.DialOption) ClientOption {
	return func(c *authClient) error {
		c.dialOpt = append(c.dialOpt, opts...)
		return nil
	}
}

// WithToken sets the authentication token to use
func WithToken(t string) ClientOption {
	return func(c *authClient) error {
		if c.creds != nil {
			return errors.New("token already set")
		}

		c.creds = token.NewRPCCredentials(t)
		return nil
	}
}

// NewAuthClient connects the an IDAM gRPC server and returns an AuthClient
func NewAuthClient(address string, opts ...ClientOption) (AuthClient, error) {
	cli := &authClient{}
	for _, fn := range opts {
		if err := fn(cli); err != nil {
			return nil, err
		}
	}

	if cli.creds == nil {
		cli.creds = token.NewRPCCredentials("")
	}

	conn, err := grpc.Dial(address, cli.dialOpt...)
	if err != nil {
		return nil, err
	}

	cli.conn = conn

	return cli, nil
}

func (cli *authClient) Conn() *grpc.ClientConn {
	return cli.conn
}

func (cli *authClient) Close() error {
	return cli.conn.Close()
}

func (cli *authClient) Authenticated() bool {
	if cli.creds.Token == "" {
		return false
	}

	return false
}
