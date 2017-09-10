package idam

import (
	"errors"

	"github.com/homebot/core/urn"
	iotc_api "github.com/homebot/protobuf/pkg/api"
	idam_api "github.com/homebot/protobuf/pkg/api/idam"
)

var (
	// ErrMissingName indicates that the identity does not have a name
	ErrMissingName = errors.New("identity does not have a name")

	// ErrInvalidType indicates that the identity has an invalid type
	ErrInvalidType = errors.New("invalid identity type")

	// ErrMissingUserData indicates that the USER identity does not have user data assigned
	ErrMissingUserData = errors.New("missing user data")

	// ErrInvalidData indicates that a identity has the wront type of data assigned
	ErrInvalidData = errors.New("invalid user or service data")

	ErrNotAuthenticated = errors.New("not authenticated")

	ErrNotAuthorized = errors.New("not authorized")
)

// UserData holds additional information for USER identities
type UserData struct {
	// PrimaryMail is the users primary mail address
	PrimaryMail string `json:"primaryMail" yaml:"primaryMail"`

	// SecondaryMails is a list of secondary mail addresses
	SecondaryMails []string `json:"secondaryMails" yaml:"secondaryMails"`

	// FirstName (given name) of the user
	FirstName string `json:"firstName" yaml:"firstName"`

	// LastName of the user
	LastName string `json:"lastName" yaml:"lastName"`
}

// Identity is a Homebot identity that can be authenticated
// and authorized
type Identity struct {
	// Type is the type of the identity
	Type idam_api.IdentityType

	// Groups the identity belongs to
	Groups []urn.URN

	// Name of the identity
	Name string

	// Labels is a set of optional labels for the identity
	Labels map[string]string

	// UserData holds additional information for a USER identity
	UserData *UserData
}

// URN returns the URN of the identity
func (i *Identity) URN() urn.URN {
	return urn.IdamIdentityResource.BuildURN("", i.Name, i.Name)
}

// AccountID returns the AccountID of the identity
// to be used in URNs
func (i *Identity) AccountID() string {
	return i.Name
}

// IsUser returns true if the identity is a user identity
func (i *Identity) IsUser() bool {
	return i.Type == idam_api.IdentityType_USER
}

// IsService returns true if the identity is a service identity
func (i *Identity) IsService() bool {
	return i.Type == idam_api.IdentityType_SERVICE
}

// Valid checks if the identity is valid
func (i *Identity) Valid() error {
	if i.Name == "" {
		return ErrMissingName
	}

	if i.Type != idam_api.IdentityType_USER && i.Type != idam_api.IdentityType_SERVICE {
		return ErrInvalidType
	}

	if i.Type == idam_api.IdentityType_USER && i.UserData == nil {
		return ErrMissingUserData
	}

	if i.Type == idam_api.IdentityType_SERVICE && i.UserData != nil {
		return ErrInvalidData
	}

	return nil
}

// ToProtobuf creates the protocol buffer representation of the identity
func (i *Identity) ToProtobuf() *idam_api.Identity {
	var groups []*iotc_api.URN
	for _, g := range i.Groups {
		groups = append(groups, urn.ToProtobuf(g))
	}

	identity := &idam_api.Identity{
		Type:   i.Type,
		Urn:    urn.ToProtobuf(i.URN()),
		Groups: groups,
		Name:   i.Name,
		Labels: i.Labels,
	}

	if i.IsUser() && i.UserData != nil {
		identity.Extra = &idam_api.Identity_User{
			User: &idam_api.UserData{
				EmailAddress:           i.UserData.PrimaryMail,
				SecondaryMailAddresses: i.UserData.SecondaryMails,
				FirstName:              i.UserData.FirstName,
				LastName:               i.UserData.LastName,
			},
		}
	}

	return identity
}

// IdentityFromProto creates a Identity from it's protocol buffer
// representation
func IdentityFromProto(p *idam_api.Identity) *Identity {
	if p == nil {
		return nil
	}

	var groups []urn.URN

	for _, g := range p.GetGroups() {
		groups = append(groups, urn.FromProtobuf(g))
	}

	return &Identity{
		Type:   p.GetType(),
		Groups: groups,
		Name:   p.GetName(),
		Labels: p.GetLabels(),
	}
}
