package token

import (
	"strings"
	"testing"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/homebot/core/urn"
	"github.com/stretchr/testify/assert"
)

func TestValidToken(t *testing.T) {
	key := "foobar"

	sub := urn.URN("urn:namespace:service:accountId:resourceType:resource")
	groups := []urn.URN{sub}
	issuer := "authority"

	token, err := NewToken(sub, groups, issuer, time.Now(), "HS256", strings.NewReader(key))
	assert.NoError(t, err)
	assert.NotEqual(t, "", token)

	parsed, err := TokenFromJWT(token, func(t *jwt.Token) (interface{}, error) {
		return []byte(key), nil
	})
	assert.NoError(t, err)
	assert.NotNil(t, parsed)

	assert.Error(t, parsed.Valid())
}

func TestTokenOwner(t *testing.T) {
	token := &Token{
		URN: urn.IdamIdentityResource.BuildURN("", "admin", "admin"),
	}

	u := urn.SigmaFunctionResource.BuildURN("foobar", "admin", "test-resource")
	assert.True(t, token.OwnsURN(u))

	u2 := urn.SigmaFunctionResource.BuildURN("foobar", "another-user", "test-resource")
	assert.False(t, token.OwnsURN(u2))
}
