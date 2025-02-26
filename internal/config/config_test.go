package config

import (
	"os"
	"testing"

	"autogov-helper/internal/util/testutil"

	"github.com/stretchr/testify/assert"
)

func TestLoad(t *testing.T) {
	cleanup := testutil.SetupTestEnv(t)
	defer cleanup()

	t.Run("loads default config", func(t *testing.T) {
		// unset all env vars for this test
		os.Unsetenv("POLICY_REPO_OWNER")
		os.Unsetenv("POLICY_REPO_NAME")
		os.Unsetenv("POLICY_VERSION")
		os.Unsetenv("SCHEMAS_PATH")

		cfg, err := Load()
		assert.NoError(t, err)
		assert.Equal(t, "liatrio", cfg.PolicyRepo.Owner)
		assert.Equal(t, "demo-gh-autogov-policy-library", cfg.PolicyRepo.Name)
		assert.Equal(t, "main", cfg.PolicyRepo.Ref)
		assert.Equal(t, "schemas/", cfg.SchemasPath)
	})

	t.Run("loads custom config", func(t *testing.T) {
		os.Setenv("POLICY_REPO_OWNER", "custom-owner")
		os.Setenv("POLICY_REPO_NAME", "custom-repo")
		os.Setenv("POLICY_VERSION", "v1.0.0")
		os.Setenv("SCHEMAS_PATH", "custom/schemas/")

		cfg, err := Load()
		assert.NoError(t, err)
		assert.Equal(t, "custom-owner", cfg.PolicyRepo.Owner)
		assert.Equal(t, "custom-repo", cfg.PolicyRepo.Name)
		assert.Equal(t, "v1.0.0", cfg.PolicyRepo.Ref)
		assert.Equal(t, "custom/schemas/", cfg.SchemasPath)
	})
}
