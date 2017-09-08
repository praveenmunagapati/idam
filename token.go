package idam

import (
	"errors"
	"io"
	"io/ioutil"
	"strings"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/homebot/core/urn"
)

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

// Token is an authentication token for an identity and digitally
// signed by the issuer
type Token struct {
	// URN of the identity the token authenticates
	URN urn.URN

	// Groups it the list of groups the identity belongs to
	Groups []urn.URN

	// Issuer is the issuer of the authentication token
	Issuer string

	// IssuedAt holds the time the token has been issued
	IssuedAt time.Time

	// Expire holds the expiration date for the token
	Expire time.Time

	// JWT holds the JSON Web-Token the token has been parsed from
	JWT string
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
	if !t.Expire.After(time.Now().UTC()) {
		return ErrTokenExpired
	}

	return nil
}

// TokenFromJWT creates a idam.Token from the given JSON Web Token
func TokenFromJWT(tokenData string, keyFn func(token *jwt.Token) (interface{}, error)) (*Token, error) {
	token, err := jwt.Parse(string(tokenData), keyFn)
	if err != nil {
		return nil, err
	}

	if !token.Valid {
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

	var groups []urn.URN
	if _, ok := claim["groups"]; ok {
		grps, ok := claim["groups"].([]interface{})
		if !ok {
			return nil, ErrInvalidToken
		}

		for _, gi := range grps {
			g, ok := gi.(string)
			if !ok {
				return nil, ErrInvalidToken
			}
			gu := urn.URN(g)
			if !gu.Valid() {
				return nil, urn.ErrInvalidURN
			}

			groups = append(groups, gu)
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

// NewToken creates a new signed JWT token
func NewToken(sub urn.URN, groups []urn.URN, issuer string, expire time.Time, alg string, key io.Reader) (string, error) {
	var grps []string
	for _, g := range groups {
		grps = append(grps, g.String())
	}

	claim := jwt.MapClaims{
		"sub":    sub.String(),
		"groups": grps,
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

	if strings.HasPrefix(alg, "RS") {
		signingKey, err = jwt.ParseECPrivateKeyFromPEM(keyData)
	} else if strings.HasPrefix(alg, "ES") {
		signingKey, err = jwt.ParseRSAPrivateKeyFromPEM(keyData)
	} else {
		signingKey = keyData
	}

	signed, err := token.SignedString(signingKey)

	return signed, err
}
