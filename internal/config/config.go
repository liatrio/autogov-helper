package config

import "os"

// PolicyRepo represents the configuration for the policy repository
type PolicyRepo struct {
	Owner string
	Name  string
	Ref   string
}

// Config represents the application configuration
type Config struct {
	PolicyRepo  PolicyRepo
	SchemasPath string
}

// Load loads the configuration from environment variables
func Load() (*Config, error) {
	cfg := &Config{
		PolicyRepo: PolicyRepo{
			Owner: getEnvOrDefault("POLICY_REPO_OWNER", "liatrio"),
			Name:  getEnvOrDefault("POLICY_REPO_NAME", "demo-gh-autogov-policy-library"),
			Ref:   getEnvOrDefault("POLICY_VERSION", "v0.8.0"),
		},
		SchemasPath: getEnvOrDefault("SCHEMAS_PATH", "schemas/"),
	}

	return cfg, nil
}

func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
