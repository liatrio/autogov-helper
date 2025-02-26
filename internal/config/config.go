package config

import (
	"autogov-helper/internal/util/env"
)

// config for policy repo
type PolicyRepo struct {
	Owner string
	Name  string
	Ref   string
}

// app config
type Config struct {
	PolicyRepo  PolicyRepo
	SchemasPath string
}

// loads config from env vars
func Load() (*Config, error) {
	cfg := &Config{
		PolicyRepo: PolicyRepo{
			Owner: env.GetEnvOrDefault(env.EnvPolicyRepoOwner, "liatrio"),
			Name:  env.GetEnvOrDefault(env.EnvPolicyRepoName, "demo-gh-autogov-policy-library"),
			Ref:   env.GetEnvOrDefault(env.EnvPolicyVersion, "main"),
		},
		SchemasPath: env.GetEnvOrDefault(env.EnvSchemasPath, "schemas/"),
	}

	return cfg, nil
}
