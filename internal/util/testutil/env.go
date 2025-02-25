package testutil

import (
	"os"
	"testing"
)

// SetupTestEnv sets up a test environment with common env vars and returns a cleanup function
func SetupTestEnv(t *testing.T) func() {
	// save original values
	originalEnvVars := map[string]string{
		"GITHUB_TOKEN":      os.Getenv("GITHUB_TOKEN"),
		"POLICY_REPO_OWNER": os.Getenv("POLICY_REPO_OWNER"),
		"POLICY_REPO_NAME":  os.Getenv("POLICY_REPO_NAME"),
		"POLICY_VERSION":    os.Getenv("POLICY_VERSION"),
		"SCHEMAS_PATH":      os.Getenv("SCHEMAS_PATH"),
	}

	// set up test environment
	os.Setenv("GITHUB_TOKEN", "test-token")
	os.Setenv("POLICY_REPO_OWNER", "test-owner")
	os.Setenv("POLICY_REPO_NAME", "test-repo")
	os.Setenv("POLICY_VERSION", "test-ref")
	os.Setenv("SCHEMAS_PATH", "schemas/")

	return func() {
		// restore original values
		for key, value := range originalEnvVars {
			if value == "" {
				os.Unsetenv(key)
			} else {
				os.Setenv(key, value)
			}
		}
	}
}
