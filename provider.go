package idam

// IdentityProvider provides identity management for IDAM
type IdentityProvider interface {
	// New creates a new identity
	New(Identity, []byte) (Identity, error)

	// Delete the identity with the given name
	Delete(name string) error

	// Update update the identity
	Update(Identity) (Identity, error)

	// Get returns the identity for the given name
	Get(name string) (Identity, error)

	// List returns a list of identities
	List() ([]Identity, error)

	// ChangePasswordHash sets a new password for the identity
	ChangePasswordHash(name string, password []byte) error

	// GetPasswordHash returns the password has for the identity
	GetPasswordHash(name string) ([]byte, error)

	// Set2FASecret sets the two-factor-authentication secret
	Set2FASecret(name string, secret string) error

	// Get2FASecret returns the secret used for the two-factor-authentication
	Get2FASecret(name string) (string, error)
}

// RoleProvider provides role management for IDAM
type RoleProvider interface {
	// New creates a new role
	New(*Role) (*Role, error)

	// Update updates the given role
	Update(*Role) (*Role, error)

	// Delete deletes a role
	Delete(string) error

	// Get returns the role with the given name
	Get(string) (*Role, error)

	// List lists all roles stored at the provider
	List() ([]*Role, error)
}

// PermissionProvider provides permission management for IDAM
type PermissionProvider interface {
	// New creates a new permission
	New(permission string, creator string) (*Permission, error)

	// Delete deletes a permission
	Delete(permission string) error

	// List lists permissions stored at the provider
	List() ([]*Permission, error)

	// Get returns a permission
	Get(permission string) (*Permission, error)
}
