package policy

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBuildPolicies(t *testing.T) {
	assert := assert.New(t)

	enforcer, err := NewEnforcer("homebot/api/idam/v1/identity.proto")

	assert.NoError(err)
	assert.NotNil(enforcer)

	assert.NotEmpty(enforcer.methods)

	// TODO(ppacher): finish test and create a dummy proto file for testing
}
