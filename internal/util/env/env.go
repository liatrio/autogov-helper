package env

import (
	"os"

	"autogov-helper/internal/util/errors"
)

// env var names
const (
	// github
	EnvGitHubRepository      = "GITHUB_REPOSITORY"
	EnvGitHubRepositoryID    = "GITHUB_REPOSITORY_ID"
	EnvGitHubRepositoryOwner = "GITHUB_REPOSITORY_OWNER"
	EnvGitHubOwnerID         = "GITHUB_REPOSITORY_OWNER_ID"
	EnvGitHubServerURL       = "GITHUB_SERVER_URL"
	EnvGitHubSHA             = "GITHUB_SHA"
	EnvGitHubRefName         = "GITHUB_REF_NAME"
	EnvGitHubEventName       = "GITHUB_EVENT_NAME"
	EnvGitHubActor           = "GITHUB_ACTOR"
	EnvGitHubRunID           = "GITHUB_RUN_ID"
	EnvGitHubRunNumber       = "GITHUB_RUN_NUMBER"
	EnvGitHubWorkflowRef     = "GITHUB_WORKFLOW_REF"
	EnvGitHubJobStatus       = "JOB_STATUS"
	EnvGitHubEventPath       = "GITHUB_EVENT_PATH"
	EnvGitHubWorkflowInputs  = "GITHUB_WORKFLOW_INPUTS"
	EnvGitHubOrganization    = "GITHUB_ORGANIZATION"

	// runner
	EnvRunnerOS          = "RUNNER_OS"
	EnvRunnerArch        = "RUNNER_ARCH"
	EnvRunnerEnvironment = "RUNNER_ENVIRONMENT"

	// tokens
	//nolint:gosec // These are environment variable names, not credentials
	EnvGitHubToken = "GITHUB_TOKEN"
	//nolint:gosec // These are environment variable names, not credentials
	EnvGHToken = "GH_TOKEN"

	// config
	EnvPolicyRepoOwner = "POLICY_REPO_OWNER"
	EnvPolicyRepoName  = "POLICY_REPO_NAME"
	EnvPolicyVersion   = "POLICY_VERSION"
	EnvSchemasPath     = "SCHEMAS_PATH"
)

// get env var or default
func GetEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// get required env var
func GetRequiredEnv(key string) (string, error) {
	if value := os.Getenv(key); value != "" {
		return value, nil
	}
	return "", errors.NewError("get required environment variable " + key)
}

// get github token from env
func GetGitHubToken() (string, error) {
	token := os.Getenv(EnvGHToken)
	if token == "" {
		token = os.Getenv(EnvGitHubToken)
	}

	if token == "" {
		return "", errors.NewError("get GitHub token from environment")
	}

	return token, nil
}
