package env

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetEnvOrDefault(t *testing.T) {
	t.Run("existing variable", func(t *testing.T) {
		os.Setenv("TEST_VAR", "test_value")
		defer os.Unsetenv("TEST_VAR")

		value := GetEnvOrDefault("TEST_VAR", "default")
		assert.Equal(t, "test_value", value)
	})

	t.Run("non-existent variable", func(t *testing.T) {
		value := GetEnvOrDefault("NON_EXISTENT_VAR", "default")
		assert.Equal(t, "default", value)
	})
}

func TestGetRequiredEnv(t *testing.T) {
	t.Run("existing variable", func(t *testing.T) {
		os.Setenv("TEST_VAR", "test_value")
		defer os.Unsetenv("TEST_VAR")

		value, err := GetRequiredEnv("TEST_VAR")
		assert.NoError(t, err)
		assert.Equal(t, "test_value", value)
	})

	t.Run("non-existent variable", func(t *testing.T) {
		_, err := GetRequiredEnv("NON_EXISTENT_VAR")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to get required environment variable")
	})
}

func TestGetGitHubToken(t *testing.T) {
	t.Run("GH_TOKEN exists", func(t *testing.T) {
		os.Setenv("GH_TOKEN", "gh_token")
		defer os.Unsetenv("GH_TOKEN")

		token, err := GetGitHubToken()
		assert.NoError(t, err)
		assert.Equal(t, "gh_token", token)
	})

	t.Run("GITHUB_TOKEN exists", func(t *testing.T) {
		os.Setenv("GITHUB_TOKEN", "github_token")
		defer os.Unsetenv("GITHUB_TOKEN")

		token, err := GetGitHubToken()
		assert.NoError(t, err)
		assert.Equal(t, "github_token", token)
	})

	t.Run("no token exists", func(t *testing.T) {
		os.Unsetenv("GH_TOKEN")
		os.Unsetenv("GITHUB_TOKEN")

		_, err := GetGitHubToken()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to get GitHub token")
	})
}
