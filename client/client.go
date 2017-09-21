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

	// Conn returns the underlying grpc client connection
	Conn() *grpc.ClientConn

	// Creds returns the idam credentials used
	Creds() *IdamCredentials

	// Close closes the underlying gRPC connection
	Close() error
}

// AdminClient is an IDAM administration client
type AdminClient interface {
	// CreateIdentity creates a new identity
	CreateIdentity(ctx context.Context, identity idam.Identity, password string, with2FA bool) (string, error)

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
	AssignRole(ctx context.Context, identity string, roles ...string) error

	// UnassignRole removes a role from an identity
	UnassignRole(ctx context.Context, identity string, roles ...string) error

	// Conn returns the underlying gRPC client connection
	Conn() *grpc.ClientConn

	// Creds returns the IDAM credentials used
	Creds() *IdamCredentials

	// Close closes the underlying gRPC connection
	Close() error
}

type client struct {
	conn  *grpc.ClientConn
	creds *IdamCredentials
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
		conn:  conn,
		creds: rpcCred,
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

// Conn returns the underlying gRPC connection
func (cli *client) Conn() *grpc.ClientConn {
	return cli.conn
}

// Creds returns the IDAM credentials of the connection
func (cli *client) Creds() *IdamCredentials {
	return cli.creds
}

// Close closes the gRPC connection
func (cli *client) Close() error {
	return cli.conn.Close()
}

type adminClient struct {
	conn  *grpc.ClientConn
	creds *IdamCredentials
}

// NewAuthenticatedAdminClient returns a new authenticated admin client using `token`
// If `token` is invalid or has been expired a new one will be requested using `cred`
func NewAuthenticatedAdminClient(endpoint, token string, cred CredentialsFunc, opts ...grpc.DialOption) (AdminClient, error) {
	cli, err := NewAuthenticatedClient(endpoint, token, cred, opts...)
	if err != nil {
		return nil, err
	}

	return &adminClient{
		conn:  cli.Conn(),
		creds: cli.Creds(),
	}, nil
}

// NewAdminClient returns a new authenticated admin client by requesting a new
// authentication token
func NewAdminClient(endpoint string, cred CredentialsFunc, opts ...grpc.DialOption) (AdminClient, error) {
	return NewAuthenticatedAdminClient(endpoint, "", cred, opts...)
}

func (cli *adminClient) CreateIdentity(ctx context.Context, identity idam.Identity, password string, with2FA bool) (string, error) {
	client := idamV1.NewAdminClient(cli.conn)

	res, err := client.CreateIdentity(ctx, &idamV1.CreateIdentityRequest{
		Identity:  identity.ToProtobuf(),
		Password:  password,
		Enable2FA: with2FA,
	})
	if err != nil {
		return "", err
	}

	return res.GetTotpSecret(), nil
}

func (cli *adminClient) DeleteIdentity(ctx context.Context, name string) error {
	client := idamV1.NewAdminClient(cli.conn)

	if _, err := client.DeleteIdentity(ctx, &idamV1.DeleteIdentityRequest{
		Urn: name,
	}); err != nil {
		return err
	}

	return nil
}

func (cli *adminClient) UpdateIdentity(ctx context.Context, identity idam.Identity) error {
	client := idamV1.NewAdminClient(cli.conn)

	if _, err := client.UpdateIdentity(ctx, &idamV1.UpdateIdentityRequest{
		Identity: identity.ToProtobuf(),
	}); err != nil {
		return err
	}

	return nil
}

func (cli *adminClient) LookupIdentities(ctx context.Context) ([]idam.Identity, error) {
	client := idamV1.NewAdminClient(cli.conn)

	res, err := client.LookupIdentities(ctx, &idamV1.LookupRequest{})
	if err != nil {
		return nil, err
	}

	var identities []idam.Identity

	for _, ri := range res.GetIdentities() {
		i := idam.IdentityFromProto(ri)
		if i.Valid() != nil {
			// TODO(ppacher): skip but log
			continue
		}

		identities = append(identities, *i)
	}

	return identities, nil
}

// CreateRole creates a new role at the identitiy server
func (cli *adminClient) CreateRole(ctx context.Context, role string) error {
	client := idamV1.NewAdminClient(cli.conn)

	if _, err := client.CreateRole(ctx, &idamV1.CreateRoleRequest{
		RoleName: role,
	}); err != nil {
		return err
	}

	return nil
}

// DeleteRole deletes a role from the IDAM server. It will also unassign the role
// from all identities
func (cli *adminClient) DeleteRole(ctx context.Context, role string) error {
	client := idamV1.NewAdminClient(cli.conn)

	if _, err := client.DeleteRole(ctx, &idamV1.DeleteRoleRequest{
		RoleName: role,
	}); err != nil {
		return err
	}

	return nil
}

// ListRoles returns a list of roles registered at the IDAM server
func (cli *adminClient) ListRoles(ctx context.Context) ([]string, error) {
	client := idamV1.NewAdminClient(cli.conn)

	res, err := client.ListRoles(ctx, &idamV1.RoleLookupRequest{})
	if err != nil {
		return nil, err
	}

	return res.GetRoleNames(), nil
}

// AssignRole assigns one or more roles to an idenity
func (cli *adminClient) AssignRole(ctx context.Context, identity string, roles ...string) error {
	client := idamV1.NewAdminClient(cli.conn)

	if _, err := client.AssignRole(ctx, &idamV1.AssignRoleRequest{
		Identity: identity,
		RoleName: roles,
	}); err != nil {
		return err
	}

	return nil
}

// UnassignRole removes one ore more roles from an identity
func (cli *adminClient) UnassignRole(ctx context.Context, identity string, roles ...string) error {
	client := idamV1.NewAdminClient(cli.conn)

	if _, err := client.UnassignRole(ctx, &idamV1.UnassignRoleRequest{
		Identity: identity,
		RoleName: roles,
	}); err != nil {
		return err
	}

	return nil
}

// Conn returns the underlying gRPC client connection
func (cli *adminClient) Conn() *grpc.ClientConn {
	return cli.conn
}

// Creds returns the IDAM credentials used by the connection
func (cli *adminClient) Creds() *IdamCredentials {
	return cli.creds
}

// Close closes the gRPC connection
func (cli *adminClient) Close() error {
	return cli.conn.Close()
}
