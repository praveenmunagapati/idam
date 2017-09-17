package idam

import (
	"errors"

	"github.com/homebot/core/urn"
	idamV1 "github.com/homebot/protobuf/pkg/api/idam/v1"
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
	Type idamV1.IdentityType

	// Roles the identity belongs to
	Roles []urn.URN

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
	return i.Type == idamV1.IdentityType_USER
}

// IsService returns true if the identity is a service identity
func (i *Identity) IsService() bool {
	return i.Type == idamV1.IdentityType_SERVICE
}

// Valid checks if the identity is valid
func (i *Identity) Valid() error {
	if i.Name == "" {
		return ErrMissingName
	}

	if i.Type != idamV1.IdentityType_USER && i.Type != idamV1.IdentityType_SERVICE {
		return ErrInvalidType
	}

	if i.Type == idamV1.IdentityType_USER && i.UserData == nil {
		return ErrMissingUserData
	}

	if i.Type == idamV1.IdentityType_SERVICE && i.UserData != nil {
		return ErrInvalidData
	}

	return nil
}

// ToProtobuf creates the protocol buffer representation of the identity
func (i *Identity) ToProtobuf() *idamV1.Identity {
	var group []string
	for _, g := range i.Roles {
		group = append(group, g.String())
	}

	identity := &idamV1.Identity{
		Type:   i.Type,
		Urn:    i.URN().String(),
		Roles:  group,
		Name:   i.Name,
		Labels: i.Labels,
	}

	if i.IsUser() && i.UserData != nil {
		identity.Extra = &idamV1.Identity_User{
			User: &idamV1.UserData{
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
func IdentityFromProto(p *idamV1.Identity) *Identity {
	if p == nil {
		return nil
	}

	var groups []urn.URN

	for _, g := range p.GetRoles() {
		groups = append(groups, urn.URN(g))
	}

	var userData *UserData
	if p.GetType() == idamV1.IdentityType_USER && p.GetUser() != nil {
		userData = &UserData{
			PrimaryMail:    p.GetUser().GetEmailAddress(),
			SecondaryMails: p.GetUser().GetSecondaryMailAddresses(),
			FirstName:      p.GetUser().GetFirstName(),
			LastName:       p.GetUser().GetLastName(),
		}
	}

	return &Identity{
		Type:     p.GetType(),
		Roles:    groups,
		Name:     p.GetName(),
		Labels:   p.GetLabels(),
		UserData: userData,
	}
}
