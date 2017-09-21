package token

import (
	"context"
	"errors"
	"io"
	"io/ioutil"
	"strings"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/homebot/core/urn"
	"github.com/homebot/idam"
	homedir "github.com/mitchellh/go-homedir"
	"google.golang.org/grpc/metadata"
)

// DefaultTokenFile holds the location where the user's token
// is stored by default
var DefaultTokenFile = "~/.idam-token.jwt"

var (
	// ErrInvalidToken indicates an invalid or incorrectly signed
	// JSON Web Token (JWT)
	ErrInvalidToken = errors.New("invalid JWT")

	// ErrInvalidAlg is returned if an invalid JWT signing algorithm
	// has been specified
	ErrInvalidAlg = errors.New("invalid JWT algorithm")

	// ErrTokenExpired indicates that the JWT token has been expired
	ErrTokenExpired = errors.New("token expired")
)

// LoadToken checks `path` and returns the content and path of the
// first token file found
func LoadToken(paths []string) (string, string, error) {
	if len(paths) == 0 {
		paths = append(paths, DefaultTokenFile)
	}

	for _, p := range paths {
		path, err := homedir.Expand(p)
		if err != nil {
			continue
		}

		token, err := ioutil.ReadFile(path)
		if err != nil {
			continue
		}

		return string(token), p, nil
	}

	return "", "", errors.New("failed to find token file")
}

// SaveToken saves the JWT token to a file
func SaveToken(token, path string) error {
	if path == "" {
		path = DefaultTokenFile
	}

	var err error
	path, err = homedir.Expand(path)
	if err != nil {
		return err
	}

	return ioutil.WriteFile(path, []byte(token), 0600)
}

// Token is an authentication token for an identity and digitally
// signed by the issuer
type Token struct {
	// URN of the identity the token authenticates
	URN urn.URN

	// Groups it the list of groups the identity belongs to
	Groups []string

	// Issuer is the issuer of the authentication token
	Issuer string

	// IssuedAt holds the time the token has been issued
	IssuedAt time.Time

	// Expire holds the expiration date for the token
	Expire time.Time

	// JWT holds the JSON Web-Token the token has been parsed from
	JWT string
}

// ForIdentity checks if the given token is for `i`
func (t *Token) ForIdentity(i *idam.Identity) bool {
	return t.URN.String() == i.URN().String()
}

// HasGroup checks if the token has a given group
func (t *Token) HasGroup(grp string) bool {
	for _, g := range t.Groups {
		if g == grp {
			return true
		}
	}
	return false
}

// Owns checks if the identity of the token owns the resource `r`
func (t *Token) Owns(r urn.Resource) bool {
	return t.OwnsURN(r.URN())
}

// OwnsURN checks if the identity of the token owns a given URN
func (t *Token) OwnsURN(r urn.URN) bool {
	return t.URN.AccountID() == r.AccountID()
}

// Valid checks if the token is still valid
func (t *Token) Valid() error {
	if t == nil {
		return ErrInvalidToken
	}

	if !t.Expire.After(time.Now().UTC()) {
		return ErrTokenExpired
	}

	return nil
}

// FromJWT creates a idam.Token from the given JSON Web Token
func FromJWT(tokenData string, keyFn func(token *jwt.Token) (interface{}, error)) (*Token, error) {
	verify := true

	if keyFn == nil {
		verify = false
		keyFn = func(_ *jwt.Token) (interface{}, error) {
			return nil, errors.New("not verified")
		}
	}

	token, err := jwt.Parse(string(tokenData), keyFn)
	if err != nil && verify {
		return nil, err
	}

	if !token.Valid && verify {
		return nil, ErrInvalidToken
	}

	claim, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, ErrInvalidToken
	}

	u, ok := claim["sub"].(string)
	if !ok {
		return nil, ErrInvalidToken
	}

	var groups []string
	if _, ok := claim["groups"]; ok {
		grps, ok := claim["groups"].([]interface{})
		if ok {
			for _, gi := range grps {
				g, ok := gi.(string)
				if !ok {
					return nil, ErrInvalidToken
				}

				groups = append(groups, g)
			}
		}
	}

	exp, ok := claim["exp"].(float64)
	if !ok {
		return nil, ErrInvalidToken
	}
	expire := int64(exp)

	issuer, ok := claim["iss"].(string)
	if !ok {
		return nil, ErrInvalidToken
	}

	t := &Token{
		URN:    urn.URN(u),
		Groups: groups,
		Issuer: issuer,
		Expire: time.Unix(expire, 0),
		JWT:    tokenData,
	}

	issuedAt, ok := claim["iat"].(float64)
	if ok {
		t.IssuedAt = time.Unix(int64(issuedAt), 0)
	}

	return t, nil
}

// New creates a new signed JWT token
func New(sub urn.URN, groups []string, issuer string, expire time.Time, alg string, key io.Reader) (string, error) {
	claim := jwt.MapClaims{
		"sub":    sub.String(),
		"groups": groups,
		"exp":    expire.Unix(),
		"iss":    issuer,
		"iat":    time.Now().Unix(),
	}

	algorithm := jwt.GetSigningMethod(alg)
	if algorithm == nil {
		return "", ErrInvalidAlg
	}

	token := jwt.NewWithClaims(algorithm, claim)
	if token == nil {
		return "", errors.New("unknown error")
	}

	keyData, err := ioutil.ReadAll(key)
	if err != nil {
		return "", err
	}

	var signingKey interface{}

	if strings.HasPrefix(alg, "ES") {
		signingKey, err = jwt.ParseECPrivateKeyFromPEM(keyData)
	} else if strings.HasPrefix(alg, "RS") {
		signingKey, err = jwt.ParseRSAPrivateKeyFromPEM(keyData)
	} else {
		signingKey = keyData
	}

	signed, err := token.SignedString(signingKey)

	return signed, err
}

// KeyProviderFunc returns the signing key for the issuer
type KeyProviderFunc func(issuer string, alg string) (interface{}, error)

// FromMetadata reads and validates a token in gRPC metadata
func FromMetadata(ctx context.Context, keyFn KeyProviderFunc) (*Token, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, idam.ErrNotAuthenticated
	}

	header, ok := md["Authorization"]
	if !ok {
		header, ok = md["authorization"]
		if !ok {
			return nil, idam.ErrNotAuthenticated
		}
	}

	if len(header) != 1 {
		return nil, errors.New("invalid header")
	}

	// Check if we have the JWT Bearer prefix
	if strings.HasPrefix(header[0], "Bearer ") {
		header = header[6:]
	}

	key := func(t *jwt.Token) (interface{}, error) {
		claims, ok := t.Claims.(jwt.MapClaims)
		if !ok {
			return nil, errors.New("invalid claims")
		}

		issuer, ok := claims["iss"].(string)
		if !ok {
			return nil, errors.New("invalid claims")
		}

		return keyFn(issuer, t.Method.Alg())
	}

	if keyFn == nil {
		key = nil
	}

	t, err := FromJWT(header[0], key)
	if err != nil {
		return nil, err
	}

	if err := t.Valid(); err != nil {
		return nil, err
	}

	return t, nil
}

type JWTCredentials struct {
	Token string
}

func NewRPCCredentials(t string) *JWTCredentials {
	return &JWTCredentials{
		Token: t,
	}
}

func (j *JWTCredentials) GetRequestMetadata(ctx context.Context, uri ...string) (map[string]string, error) {
	return map[string]string{
		"authorization": j.Token,
	}, nil
}

func (j *JWTCredentials) RequireTransportSecurity() bool {
	return false // TODO(ppacher): make this true
}
