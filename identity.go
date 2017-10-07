package idam

import (
	"errors"
	"strings"
	"time"

	"github.com/pquerna/otp/totp"

	"golang.org/x/crypto/bcrypt"

	"github.com/golang/protobuf/ptypes"

	idamV1 "github.com/homebot/protobuf/pkg/api/idam/v1"
)

var (
	// ErrMissingName indicates that the identity does not have a name
	ErrMissingName = errors.New("identity does not have a name")

	// ErrInvalidType indicates that the identity has an invalid type
	ErrInvalidType = errors.New("invalid identity type")

	// ErrInvalidPrefix is returned if an identity has an invalid name prefix
	ErrInvalidPrefix = errors.New("invalid or unexpected prefix")

	// ErrMissingUserData indicates that the USER identity does not have user data assigned
	ErrMissingUserData = errors.New("missing user data")

	// ErrInvalidData indicates that a identity has the wront type of data assigned
	ErrInvalidData = errors.New("invalid user or service data")

	// ErrUnknownIdentity indicates that one or more identities do not exist
	ErrUnknownIdentity = errors.New("unknown identity")

	// ErrIdentityExists is returned if the identity already exists and cannot be created
	ErrIdentityExists = errors.New("identity already exists")
)

// Constants for account name prefixes
const (
	IdentityPrefixGroup   = "group"
	IdentityPrefixUser    = "user"
	IdentityPrefixSerivce = "service"
)

// Metadata holds additional information for identities
type Metadata struct {
	// Labels holds additional labels for the identity
	Labels map[string]string

	// Created is the time the identity has been created
	Created time.Time

	// Update is the time the identity has been updated
	Updated time.Time

	// Creator is the name of the identity that created this one
	Creator string
}

// Identity is some kind of identity managed by the IDAM server
type Identity interface {
	// AccountName returns the name of the identity
	// which is always in the following format:
	// [user|service|group]:<email@address.com>
	AccountName() string

	// Roles returns a list of roles assigned to the identity
	Roles() []string

	// Groups returns a list of groups the identity belongs to
	Groups() []string

	// Disabled should return true if the identity is disabled
	Disabled() bool

	// Metadata returns the identitites metadata
	Metadata() Metadata
}

// User is a user identity
type User struct {
	name     string
	roles    []string
	groups   []string
	disabled bool
	meta     Metadata

	FirstName     string
	LastName      string
	MailAddresses []string
}

// NewUserIdentity returns a new user identity
func NewUserIdentity(name string, parent string, roles []string, groups []string) *User {
	return NewUserIdentityWithMetadata(name, roles, groups, Metadata{
		Creator: parent,
		Created: time.Now(),
		Updated: time.Now(),
	})
}

// NewUserIdentityWithMetadata creates a new user identity with the given metadata
func NewUserIdentityWithMetadata(name string, roles []string, groups []string, md Metadata) *User {
	return &User{
		name:   name,
		roles:  roles,
		groups: groups,
		meta:   md,
	}
}

// AccountName returns the account name of the user and
// implements Identity
func (u User) AccountName() string {
	return u.name
}

// Roles returns a list of roles assigned to the user and implements
// Identity
func (u User) Roles() []string {
	return u.roles
}

// Groups returns a list of groups the users belongs to
// and implements Identity
func (u User) Groups() []string {
	return u.groups
}

// Disabled returns true if the identity is disabled
func (u User) Disabled() bool {
	return u.disabled
}

// Metadata returns metadata for the user identity
func (u User) Metadata() Metadata {
	return u.meta
}

// Group is a group identity
type Group struct {
	name   string
	roles  []string
	groups []string
	md     Metadata

	members []string
}

// NewGroup creates a new group identity
func NewGroup(name string, parent string, roles []string, groups []string, members []string) *Group {
	return NewGroupWithMetadata(name, roles, groups, members, Metadata{
		Created: time.Now(),
		Updated: time.Now(),
		Creator: parent,
	})
}

// NewGroupWithMetadata creates a new group identity with the given metadata
func NewGroupWithMetadata(name string, roles []string, groups []string, members []string, md Metadata) *Group {
	return &Group{
		name:    name,
		roles:   roles,
		groups:  groups,
		members: members,
		md:      md,
	}
}

// Members returns a list of identities that belong to
// this group
func (g *Group) Members() []string {
	return g.members
}

// HasMember checks if the group has a given member
func (g *Group) HasMember(s string) bool {
	for _, m := range g.members {
		if m == s {
			return true
		}
	}

	return false
}

// AddMember adds a new member to the group
func (g *Group) AddMember(name string) error {
	if _, err := StripIdentityNamePrefix(name); err != nil {
		return err
	}

	if g.HasMember(name) {
		return nil
	}

	g.members = append(g.members, name)

	return nil
}

// DeleteMember deletes a member from the group
func (g *Group) DeleteMember(name string) error {
	if _, err := StripIdentityNamePrefix(name); err != nil {
		return err
	}

	if !g.HasMember(name) {
		return nil
	}

	var newMembers []string
	for _, m := range g.members {
		if m != name {
			newMembers = append(newMembers, m)
		}
	}

	g.members = newMembers

	return nil
}

// AccountName returns the name of the group
func (g Group) AccountName() string {
	return g.name
}

// Roles returns a list of roles assigned to the group
func (g Group) Roles() []string {
	return g.roles
}

// Groups returns a list of groups this group belongs to
func (g Group) Groups() []string {
	return g.groups
}

// Disabled always returns false for groups
func (g Group) Disabled() bool {
	return false
}

// Metadata returns the groups metadata
func (g Group) Metadata() Metadata {
	return g.md
}

// SetEnabled enables an identity
func SetEnabled(i Identity, enabled bool) error {
	if i.Disabled() == !enabled {
		return nil
	}

	switch v := i.(type) {
	case *User:
		v.disabled = !enabled
	case *Group:
		return errors.New("groups cannot be disabled/enabled")
	default:
		return ErrInvalidType
	}

	return nil
}

// EnableIdentity enables an identity
func EnableIdentity(i Identity) error {
	return SetEnabled(i, true)
}

// DisableIdentity disables an identity
func DisableIdentity(i Identity) error {
	return SetEnabled(i, false)
}

// HasRole checks whether the identity `i` has the role `s` assigned
func HasRole(i Identity, s string) bool {
	for _, r := range i.Roles() {
		if r == s {
			return true
		}
	}

	return false
}

// HasGroup checks if the identity `i` belongs to the group `g`
func HasGroup(i Identity, g string) bool {
	for _, s := range i.Groups() {
		if s == g {
			return true
		}
	}

	return false
}

// AddRole adds a role to an identity
func AddRole(i Identity, r string) {
	if HasRole(i, r) {
		return
	}

	switch v := i.(type) {
	case *User:
		v.roles = append(v.roles, r)
	case *Group:
		v.roles = append(v.roles, r)
	default:
		panic(ErrInvalidType)
	}
}

// AddGroup adds a group to an identity
func AddGroup(i Identity, g string) {
	if HasGroup(i, g) {
		return
	}

	switch v := i.(type) {
	case *User:
		v.groups = append(v.groups, g)
	case *Group:
		v.groups = append(v.groups, g)
	default:
		panic(ErrInvalidType)
	}
}

// DeleteRole deletes a role from an identity
func DeleteRole(i Identity, role string) {
	roles := i.Roles()

	var newRoles []string

	for _, r := range roles {
		if r != role {
			newRoles = append(newRoles, r)
		}
	}

	switch v := i.(type) {
	case *User:
		v.roles = newRoles
	case *Group:
		v.roles = newRoles
	default:
		panic(ErrInvalidType)
	}
}

// StripIdentityPrefix returns the real name of the identity by removing
// the identities type prefix from the account name
func StripIdentityPrefix(i Identity) (string, error) {
	return StripIdentityNamePrefix(i.AccountName())
}

// StripIdentityNamePrefix returns the real name of the identity by removing
// the identities type prefix from the account name
func StripIdentityNamePrefix(i string) (string, error) {
	parts := strings.Split(i, ":")

	if len(parts) < 2 {
		return "", ErrInvalidPrefix
	}

	if !(parts[0] == IdentityPrefixUser || parts[0] == IdentityPrefixGroup || parts[0] == IdentityPrefixSerivce) {
		return "", ErrInvalidPrefix
	}

	return strings.Join(parts[1:], ":"), nil
}

// DeleteGroup deletes a group from an identity
func DeleteGroup(i Identity, group string) {
	groups := i.Groups()

	var newGroups []string

	for _, g := range groups {
		if g != group {
			newGroups = append(newGroups, g)
		}
	}

	switch v := i.(type) {
	case *User:
		v.groups = newGroups
	case *Group:
		v.groups = newGroups
	default:
		panic(ErrInvalidType)
	}
}

// HasLabel checks if the identity has a given label
func HasLabel(i Identity, l string) bool {
	if i.Metadata().Labels == nil {
		return false
	}

	_, ok := i.Metadata().Labels[l]
	return ok
}

// GetLabel returns the value of the label assigned to the identity
func GetLabel(i Identity, l string) (string, bool) {
	if i.Metadata().Labels == nil {
		return "", false
	}

	v, ok := i.Metadata().Labels[l]
	return v, ok
}

// AddLabel adds a label to an identity
func AddLabel(i Identity, l string, v string) error {
	if HasLabel(i, l) {
		return errors.New("label already set")
	}

	md := i.Metadata()
	if md.Labels == nil {
		md.Labels = make(map[string]string)
	}

	md.Labels[l] = v
	return nil
}

// DeleteLabel deletes a label from an identity
func DeleteLabel(i Identity, l string) bool {
	if !HasLabel(i, l) {
		return false
	}

	md := i.Metadata()

	// This shouldn't happen anymore but re-check to be sure
	if md.Labels == nil {
		return false
	}

	delete(md.Labels, l)
	return true
}

// IsUser returns true if `i` is a user identity
func IsUser(i Identity) bool {
	_, ok := i.(*User)
	return ok
}

// IsGroup returns true if the identity is a group
func IsGroup(i Identity) bool {
	_, ok := i.(*Group)
	return ok
}

// IdentityProto converts a idam.Identity to it's protocol buffer
// representation
func IdentityProto(i Identity) (*idamV1.Identity, error) {
	created, err := ptypes.TimestampProto(i.Metadata().Created)
	if err != nil {
		return nil, err
	}

	updated, err := ptypes.TimestampProto(i.Metadata().Updated)
	if err != nil {
		return nil, err
	}

	identity := &idamV1.Identity{
		Name:        i.AccountName(),
		Groups:      i.Groups(),
		Roles:       i.Roles(),
		Disabled:    i.Disabled(),
		Labels:      i.Metadata().Labels,
		CreatedTime: created,
		UpdatedTime: updated,
		Creator:     i.Metadata().Creator,
	}

	switch v := i.(type) {
	case *User:
		identity.Type = idamV1.IdentityType_USER
		identity.Extra = &idamV1.Identity_User{
			User: &idamV1.UserData{
				FirstName:       v.FirstName,
				LastName:        v.LastName,
				AdditionalMails: v.MailAddresses,
			},
		}

	case *Group:
		identity.Type = idamV1.IdentityType_GROUP
		identity.Extra = &idamV1.Identity_Group{
			Group: &idamV1.GroupData{
				Members: v.Members(),
			},
		}

	default:
		return nil, ErrInvalidType
	}

	return identity, nil
}

// IdentityFromProto creates an idam.Identity from it's protocol buffer
// representation
func IdentityFromProto(p *idamV1.Identity) (Identity, error) {
	created, err := ptypes.Timestamp(p.GetCreatedTime())
	if err != nil {
		return nil, err
	}
	updated, err := ptypes.Timestamp(p.GetUpdatedTime())
	if err != nil {
		return nil, err
	}

	switch p.GetType() {
	case idamV1.IdentityType_GROUP:
		var members []string
		if p.GetGroup() != nil {
			members = p.GetGroup().GetMembers()
		}

		if !strings.HasPrefix(p.GetName(), IdentityPrefixGroup) {
			return nil, ErrInvalidPrefix
		}

		group := NewGroupWithMetadata(p.GetName(), p.GetRoles(), p.GetGroups(), members, Metadata{
			Creator: p.GetCreator(),
			Created: created,
			Updated: updated,
			Labels:  p.GetLabels(),
		})

		if p.GetDisabled() {
			DisableIdentity(group)
		}

		return group, nil

	case idamV1.IdentityType_USER:
		if !strings.HasPrefix(p.GetName(), IdentityPrefixUser) {
			return nil, ErrInvalidPrefix
		}

		user := NewUserIdentityWithMetadata(p.GetName(), p.GetRoles(), p.GetGroups(), Metadata{
			Created: created,
			Updated: updated,
			Creator: p.GetCreator(),
			Labels:  p.GetLabels(),
		})

		userData := p.GetUser()
		if userData != nil {
			user.FirstName = userData.GetFirstName()
			user.LastName = userData.GetLastName()
			user.MailAddresses = userData.GetAdditionalMails()
		}

		if p.GetDisabled() {
			DisableIdentity(user)
		}

		return user, nil

	default:
		return nil, ErrInvalidType
	}
}

// CheckPassword checks the identities password
func CheckPassword(hash []byte, pass string) error {
	return bcrypt.CompareHashAndPassword(hash, []byte(pass))
}

// Check2FA checks a one-time-token
func Check2FA(secret string, token string) error {
	if totp.Validate(token, secret) {
		return nil
	}

	return errors.New("invalid token")
}
