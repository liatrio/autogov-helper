package testutil

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSetupTestEnv(t *testing.T) {
	// save original values
	originalEnvVars := map[string]string{
		"GITHUB_TOKEN":      os.Getenv("GITHUB_TOKEN"),
		"POLICY_REPO_OWNER": os.Getenv("POLICY_REPO_OWNER"),
		"POLICY_REPO_NAME":  os.Getenv("POLICY_REPO_NAME"),
		"POLICY_VERSION":    os.Getenv("POLICY_VERSION"),
		"SCHEMAS_PATH":      os.Getenv("SCHEMAS_PATH"),
	}

	// run test env setup
	cleanup := SetupTestEnv(t)

	// verify test values are set
	assert.Equal(t, "test-token", os.Getenv("GITHUB_TOKEN"))
	assert.Equal(t, "test-owner", os.Getenv("POLICY_REPO_OWNER"))
	assert.Equal(t, "test-repo", os.Getenv("POLICY_REPO_NAME"))
	assert.Equal(t, "test-ref", os.Getenv("POLICY_VERSION"))
	assert.Equal(t, "schemas/", os.Getenv("SCHEMAS_PATH"))

	// run cleanup
	cleanup()

	// verify original values are restored
	for key, value := range originalEnvVars {
		assert.Equal(t, value, os.Getenv(key))
	}
}
