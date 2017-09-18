package client

import (
	"context"

	"github.com/homebot/idam"
	homebotApi "github.com/homebot/protobuf/pkg/api"
	idamV1 "github.com/homebot/protobuf/pkg/api/idam/v1"
	"google.golang.org/grpc"
)

// Client is a gRPC client wrapper for communicating with IDAM
type Client interface {
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

type client struct {
	conn *grpc.ClientConn
}

// NewClient creates a new IDAM client for the given endpoint and credential functions
func NewClient(endpoint string, cred CredentialsFunc, opts ...grpc.DialOption) (Client, error) {
	return NewAuthenticatedClient(endpoint, "", cred, opts...)
}

// NewAuthenticatedClient returns a new client using the given `creds` and the authentication
// `token`
func NewAuthenticatedClient(endpoint, token string, cred CredentialsFunc, opts ...grpc.DialOption) (Client, error) {
	rpcCred, err := NewIdamCredentials(endpoint, token, cred, opts...)
	if err != nil {
		return nil, err
	}
	opts = append(opts, grpc.WithPerRPCCredentials(rpcCred))

	conn, err := grpc.Dial(endpoint, opts...)
	if err != nil {
		return nil, err
	}

	return &client{
		conn: conn,
	}, nil
}

// ChangePassword changes the password of the currently authenticated identity
func (cli *client) ChangePassword(ctx context.Context, oldPwd, newPwd string) error {
	client := idamV1.NewProfileClient(cli.conn)

	_, err := client.ChangePassword(ctx, &idamV1.ChangePasswordRequest{
		CurrentPassword: oldPwd,
		NewPassword:     newPwd,
	})

	if err != nil {
		return err
	}

	return nil
}

// GetProfile returns the profile for the currently authenticated identity
func (cli *client) GetProfile(ctx context.Context) (*idam.Identity, error) {
	client := idamV1.NewProfileClient(cli.conn)

	res, err := client.GetProfile(ctx, &homebotApi.Empty{})
	if err != nil {
		return nil, err
	}

	identity := idam.IdentityFromProto(res)
	if err := identity.Valid(); err != nil {
		return identity, err
	}

	return identity, nil
}

// SetUserData updates the users profile
func (cli *client) SetUserData(ctx context.Context, data idam.UserData) error {
	client := idamV1.NewProfileClient(cli.conn)

	_, err := client.SetUserData(ctx, &idamV1.UserData{
		EmailAddress:           data.PrimaryMail,
		SecondaryMailAddresses: data.SecondaryMails,
		FirstName:              data.FirstName,
		LastName:               data.LastName,
	})
	if err != nil {
		return err
	}

	return nil
}

// Change2FA changes two-factor-authentication settings for the current idenity.
// If 2FA should be disable, the current TOTP must be passed
func (cli *client) Change2FA(ctx context.Context, enabled bool, currentOTP string) (string, error) {
	client := idamV1.NewProfileClient(cli.conn)

	res, err := client.Change2FA(ctx, &idamV1.Change2FARequest{
		CurrentOneTimeSecret: currentOTP,
		Enabled:              enabled,
	})
	if err != nil {
		return "", err
	}

	return res.GetSecret(), nil
}
