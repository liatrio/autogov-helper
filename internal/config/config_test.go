package config

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLoad(t *testing.T) {
	originalEnv := map[string]string{
		"POLICY_REPO_OWNER": os.Getenv("POLICY_REPO_OWNER"),
		"POLICY_REPO_NAME":  os.Getenv("POLICY_REPO_NAME"),
		"POLICY_VERSION":    os.Getenv("POLICY_VERSION"),
		"SCHEMAS_PATH":      os.Getenv("SCHEMAS_PATH"),
	}

	defer func() {
		for k, v := range originalEnv {
			if v == "" {
				os.Unsetenv(k)
			} else {
				os.Setenv(k, v)
			}
		}
	}()

	t.Run("loads default config", func(t *testing.T) {
		for k := range originalEnv {
			os.Unsetenv(k)
		}

		cfg, err := Load()
		assert.NoError(t, err)
		assert.Equal(t, "liatrio", cfg.PolicyRepo.Owner)
		assert.Equal(t, "", cfg.PolicyRepo.Name)
		assert.Equal(t, "", cfg.PolicyRepo.Ref)
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
