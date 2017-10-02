package token

import (
	"strings"
	"testing"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/stretchr/testify/assert"
)

func TestValidToken(t *testing.T) {
	key := "foobar"

	sub := "user:admin@homebot.org"
	roles := []string{"role1"}
	issuer := "authority"

	token, err := New(sub, roles, issuer, time.Now(), "HS256", strings.NewReader(key))
	assert.NoError(t, err)
	assert.NotEqual(t, "", token)

	parsed, err := FromJWT(token, func(t *jwt.Token) (interface{}, error) {
		return []byte(key), nil
	})
	assert.NoError(t, err)
	assert.NotNil(t, parsed)

	assert.Error(t, parsed.Valid())
}
