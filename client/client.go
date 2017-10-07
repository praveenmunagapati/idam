package client

import (
	"context"
	"errors"
	"strings"

	"github.com/golang/protobuf/ptypes/empty"
	"github.com/homebot/idam"
	idamV1 "github.com/homebot/protobuf/pkg/api/idam/v1"
	"google.golang.org/grpc"
)

// Client is a gRPC client wrapper for communicating with IDAM
type Client interface {
	// ChangePassword changes the password for the current identity
	ChangePassword(ctx context.Context, current, new string) error

	// GetProfile returns the identity profile for the currently authenticated
	// identity
	GetProfile(ctx context.Context) (idam.Identity, error)

	// Change2FA changes the identities two-factor-authentication settings
	// If 2FA should be disabled, the current OTP needs to be passed. If 2FA
	// becomes enabled, the returned string is the new TOTP secret
	Change2FA(ctx context.Context, enabled bool, currentOTP string) (string, error)

	// SetUserData updates the current user settings
	SetUserData(ctx context.Context, first, last, mail string, mails []string) error

	// Conn returns the underlying grpc client connection
	Conn() *grpc.ClientConn

	// Creds returns the idam credentials used
	Creds() *IdamCredentials

	// Close closes the underlying gRPC connection
	Close() error
}

// AdminClient is an IDAM administration client
type AdminClient interface {
	GetIdentity(ctx context.Context, name string) (idam.Identity, error)

	// CreateIdentity creates a new identity
	CreateIdentity(ctx context.Context, identity idam.Identity, password string, with2FA bool) (string, error)

	// DeleteIdentity deletes the given identity
	DeleteIdentity(ctx context.Context, identity string) error

	// UpdateIdentity updates the identity
	UpdateIdentity(ctx context.Context, identitiy idam.Identity) error

	// LookupIdentities searches for all identities on the server
	LookupIdentities(ctx context.Context) ([]idam.Identity, error)

	GetIdentityPermission(ctx context.Context, i string) (idam.Identity, []*idam.Permission, error)

	GetRole(ctx context.Context, role string) (*idam.Role, error)

	// CreateRole creates a new role
	CreateRole(ctx context.Context, role string, permissions []string) error

	// ListRoles lists available roles
	ListRoles(ctx context.Context) ([]idam.Role, error)

	// DeleteRole deletes a role from the server
	DeleteRole(ctx context.Context, role string) error

	// AssignRole assings a role to an identity
	AssignRole(ctx context.Context, identity string, roles string) error

	// UnassignRole removes a role from an identity
	UnassignRole(ctx context.Context, identity string, roles string) error

	GetPermission(ctx context.Context, p string) (*idam.Permission, error)

	// CreatePermission creates a new permission at the IDAM server
	CreatePermission(ctx context.Context, p string) (*idam.Permission, error)

	// DeletePermission deletes a permission
	DeletePermission(ctx context.Context, p string) error

	// ListPermissions lists all permissions
	ListPermissions(ctx context.Context) ([]*idam.Permission, error)

	// ListRolePermissions lists all permissions
	ListRolePermissions(ctx context.Context, role string) ([]*idam.Permission, error)

	AssignPermission(ctx context.Context, permission, role string) error

	UnassignPermission(ctx context.Context, permission, role string) error

	AddIdentityToGroup(ctx context.Context, identity, group string) error

	DeleteIdentityFromGroup(ctx context.Context, identity, group string) error

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
func (cli *client) GetProfile(ctx context.Context) (idam.Identity, error) {
	client := idamV1.NewProfileClient(cli.conn)

	res, err := client.GetProfile(ctx, &empty.Empty{})
	if err != nil {
		return nil, err
	}

	identity, err := idam.IdentityFromProto(res)
	if err != nil {
		return identity, err
	}

	return identity, nil
}

// SetUserData updates the users profile
func (cli *client) SetUserData(ctx context.Context, first, last, mail string, mails []string) error {
	client := idamV1.NewProfileClient(cli.conn)

	_, err := client.SetUserData(ctx, &idamV1.UserData{
		PrimaryMail:     mail,
		AdditionalMails: mails,
		FirstName:       first,
		LastName:        last,
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
	client := idamV1.NewIdentityServiceClient(cli.conn)
	ipb, err := idam.IdentityProto(identity)
	if err != nil {
		return "", err
	}

	res, err := client.CreateIdentity(ctx, &idamV1.CreateIdentityRequest{
		Identity:  ipb,
		Password:  password,
		Enable2FA: with2FA,
	})
	if err != nil {
		return "", err
	}

	return res.GetTotpSecret(), nil
}

func (cli *adminClient) DeleteIdentity(ctx context.Context, name string) error {
	client := idamV1.NewIdentityServiceClient(cli.conn)

	if _, err := client.DeleteIdentity(ctx, &idamV1.DeleteIdentityRequest{
		Name: name,
	}); err != nil {
		return err
	}

	return nil
}

func (cli *adminClient) UpdateIdentity(ctx context.Context, identity idam.Identity) error {
	client := idamV1.NewIdentityServiceClient(cli.conn)

	ipb, err := idam.IdentityProto(identity)
	if err != nil {
		return err
	}
	if _, err := client.UpdateIdentity(ctx, &idamV1.UpdateIdentityRequest{
		Identity: ipb,
	}); err != nil {
		return err
	}

	return nil
}

func (cli *adminClient) LookupIdentities(ctx context.Context) ([]idam.Identity, error) {
	client := idamV1.NewIdentityServiceClient(cli.conn)

	res, err := client.LookupIdentities(ctx, &idamV1.LookupRequest{})
	if err != nil {
		return nil, err
	}

	var identities []idam.Identity

	for _, ri := range res.GetIdentities() {
		i, err := idam.IdentityFromProto(ri)
		if err != nil {
			continue
		}
		// TODO(ppacher): re-add Valid() check
		identities = append(identities, i)
	}

	return identities, nil
}

func (cli *adminClient) GetRole(ctx context.Context, role string) (*idam.Role, error) {
	client := idamV1.NewPermissionsClient(cli.conn)

	res, err := client.GetRole(ctx, &idamV1.GetRoleRequest{
		Name: role,
	})
	if err != nil {
		return nil, err
	}

	r, err := idam.RoleFromProto(res)
	if err != nil {
		return nil, err
	}

	return r, nil
}

// CreateRole creates a new role at the identitiy server
func (cli *adminClient) CreateRole(ctx context.Context, role string, perms []string) error {
	client := idamV1.NewPermissionsClient(cli.conn)

	_, err := client.CreateRole(ctx, &idamV1.CreateRoleRequest{
		Role: &idamV1.Role{
			Name:        role,
			Permissions: perms,
		},
	})
	return err
}

// DeleteRole deletes a role from the IDAM server. It will also unassign the role
// from all identities
func (cli *adminClient) DeleteRole(ctx context.Context, role string) error {
	client := idamV1.NewPermissionsClient(cli.conn)

	_, err := client.DeleteRole(ctx, &idamV1.DeleteRoleRequest{
		Name: role,
	})
	return err
}

// ListRoles returns a list of roles registered at the IDAM server
func (cli *adminClient) ListRoles(ctx context.Context) ([]idam.Role, error) {
	client := idamV1.NewPermissionsClient(cli.conn)

	res, err := client.ListRole(ctx, &idamV1.ListRoleRequest{})
	if err != nil {
		return nil, err
	}

	var roles []idam.Role
	for _, r := range res.GetRoles() {
		rn, err := idam.RoleFromProto(r)
		if err != nil {
			return nil, err
		}

		roles = append(roles, *rn)
	}
	return roles, nil
}

// AssignRole assigns one or more roles to an idenity
func (cli *adminClient) AssignRole(ctx context.Context, identity string, role string) error {
	client := idamV1.NewIdentityServiceClient(cli.conn)

	if _, err := client.AssignRole(ctx, &idamV1.AssignRoleRequest{
		Name: identity,
		Role: role,
	}); err != nil {
		return err
	}

	return nil
}

// UnassignRole removes one ore more roles from an identity
func (cli *adminClient) UnassignRole(ctx context.Context, identity string, role string) error {
	client := idamV1.NewIdentityServiceClient(cli.conn)

	if _, err := client.RemoveRole(ctx, &idamV1.UnassignRoleRequest{
		Name: identity,
		Role: role,
	}); err != nil {
		return err
	}

	return nil
}

func (cli *adminClient) GetPermission(ctx context.Context, p string) (*idam.Permission, error) {
	client := idamV1.NewPermissionsClient(cli.conn)

	res, err := client.GetPermission(ctx, &idamV1.GetPermissionRequest{
		Name: p,
	})
	if err != nil {
		return nil, err
	}

	r, err := idam.PermissionFromProto(res)
	if err != nil {
		return nil, err
	}

	return r, nil
}

func (cli *adminClient) CreatePermission(ctx context.Context, p string) (*idam.Permission, error) {
	client := idamV1.NewPermissionsClient(cli.conn)

	res, err := client.CreatePermission(ctx, &idamV1.CreatePermissionRequest{
		Permission: p,
	})
	if err != nil {
		return nil, err
	}

	ret, err := idam.PermissionFromProto(res)
	if err != nil {
		return nil, err
	}

	return ret, nil
}

func (cli *adminClient) DeletePermission(ctx context.Context, p string) error {
	client := idamV1.NewPermissionsClient(cli.conn)

	if _, err := client.DeletePermission(ctx, &idamV1.DeletePermissionRequest{
		Name: p,
	}); err != nil {
		return err
	}

	return nil
}

func (cli *adminClient) ListPermissions(ctx context.Context) ([]*idam.Permission, error) {
	client := idamV1.NewPermissionsClient(cli.conn)

	res, err := client.ListPermissions(ctx, &idamV1.ListPermissionRequest{})
	if err != nil {
		return nil, err
	}

	var ret []*idam.Permission

	for _, pb := range res.GetPermissions() {
		r, err := idam.PermissionFromProto(pb)
		if err != nil {
			return nil, err
		}

		ret = append(ret, r)
	}

	return ret, nil
}

func (cli *adminClient) ListRolePermissions(ctx context.Context, role string) ([]*idam.Permission, error) {
	client := idamV1.NewPermissionsClient(cli.conn)

	res, err := client.ListPermissions(ctx, &idamV1.ListPermissionRequest{
		Role: role,
	})
	if err != nil {
		return nil, err
	}

	var ret []*idam.Permission

	for _, pb := range res.GetPermissions() {
		r, err := idam.PermissionFromProto(pb)
		if err != nil {
			return nil, err
		}

		ret = append(ret, r)
	}

	return ret, nil
}

func (cli *adminClient) AssignPermission(ctx context.Context, permission string, role string) error {
	client := idamV1.NewPermissionsClient(cli.conn)

	if _, err := client.AssignPermission(ctx, &idamV1.AssignPermissionRequest{
		Permission: permission,
		Role:       role,
	}); err != nil {
		return err
	}

	return nil
}

func (cli *adminClient) UnassignPermission(ctx context.Context, permission string, role string) error {
	client := idamV1.NewPermissionsClient(cli.conn)

	if _, err := client.RemoveGrantedPermission(ctx, &idamV1.RemoveGrantedPermissionRequest{
		Permission: permission,
		Role:       role,
	}); err != nil {
		return err
	}

	return nil
}

func (cli *adminClient) GetIdentity(ctx context.Context, name string) (idam.Identity, error) {
	client := idamV1.NewIdentityServiceClient(cli.conn)

	i, err := client.GetIdentity(ctx, &idamV1.GetIdentityRequest{
		Name: name,
	})

	if err != nil {
		return nil, err
	}

	identity, err := idam.IdentityFromProto(i)
	if err != nil {
		return nil, err
	}

	return identity, nil
}

func (cli *adminClient) GetIdentityPermission(ctx context.Context, name string) (idam.Identity, []*idam.Permission, error) {
	client := idamV1.NewIdentityServiceClient(cli.conn)

	res, err := client.GetIdentityPermissions(ctx, &idamV1.GetIdentityRequest{
		Name: name,
	})

	if err != nil {
		return nil, nil, err
	}

	identity, err := idam.IdentityFromProto(res.GetIdentity())
	if err != nil {
		return nil, nil, err
	}

	var p []*idam.Permission

	for _, pb := range res.GetPermissions() {
		perm, err := idam.PermissionFromProto(pb)
		if err != nil {
			return nil, nil, err
		}

		p = append(p, perm)
	}

	return identity, p, nil
}

func (cli *adminClient) AddIdentityToGroup(ctx context.Context, identity, group string) error {
	if !strings.HasPrefix(group, idam.IdentityPrefixGroup) {
		return errors.New("can only add an identity to a group")
	}

	client := idamV1.NewIdentityServiceClient(cli.conn)

	if _, err := client.AddIdentityToGroup(ctx, &idamV1.AddIdentityToGroupRequest{
		Name:  identity,
		Group: group,
	}); err != nil {
		return err
	}

	return nil
}

func (cli *adminClient) DeleteIdentityFromGroup(ctx context.Context, identity, group string) error {
	if !strings.HasPrefix(group, idam.IdentityPrefixGroup) {
		return errors.New("can only delete an identity from a group")
	}

	client := idamV1.NewIdentityServiceClient(cli.conn)

	if _, err := client.DeleteIdentityFromGroup(ctx, &idamV1.DeleteIdentityFromGroupRequest{
		Name:  identity,
		Group: group,
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
