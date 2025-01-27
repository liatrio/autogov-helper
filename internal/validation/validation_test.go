package validation

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidateMetadata(t *testing.T) {
	// Set up test environment
	os.Setenv("POLICY_REPO_OWNER", "liatrio")
	os.Setenv("POLICY_REPO_NAME", "demo-gh-autogov-policy-library")
	os.Setenv("POLICY_VERSION", "v0.8.0")
	os.Setenv("GITHUB_TOKEN", os.Getenv("GH_TOKEN"))

	t.Run("validates valid metadata", func(t *testing.T) {
		validJSON := []byte(`{
			"_type": "https://in-toto.io/Statement/v1",
			"predicateType": "https://cosign.sigstore.dev/attestation/v1",
			"subject": [{
				"name": "test-image",
				"digest": {
					"sha256": "abc123"
				}
			}],
			"predicate": {
				"artifact": {
					"version": "1.0.0",
					"created": "2024-01-01T00:00:00Z",
					"type": "container-image"
				},
				"repositoryData": {
					"repository": "test-repo",
					"repositoryId": "123",
					"githubServerURL": "https://github.com"
				},
				"ownerData": {
					"owner": "test-owner",
					"ownerId": "456"
				},
				"runnerData": {
					"os": "linux",
					"arch": "X64",
					"environment": "github-hosted"
				},
				"workflowData": {
					"workflowRefPath": ".github/workflows/build.yml",
					"inputs": {},
					"branch": "main",
					"event": "push"
				},
				"jobData": {
					"runNumber": "1",
					"runId": "123",
					"status": "success",
					"triggeredBy": "test-user",
					"startedAt": "2024-01-01T00:00:00Z",
					"completedAt": "2024-01-01T00:00:00Z"
				},
				"commitData": {
					"sha": "abc123",
					"timestamp": "2024-01-01T00:00:00Z"
				},
				"organization": {
					"name": "test-org"
				},
				"compliance": {
					"policyRef": "https://github.com/liatrio/demo-gh-autogov-policy-library",
					"controlIds": ["test-control"]
				},
				"security": {
					"permissions": {
						"id-token": "write",
						"attestations": "write",
						"contents": "read",
						"packages": "read"
					}
				}
			}
		}`)

		err := ValidateMetadata(validJSON)
		assert.NoError(t, err)
	})

	t.Run("fails on invalid metadata", func(t *testing.T) {
		invalidJSON := []byte(`{
			"_type": "https://in-toto.io/Statement/v1",
			"predicateType": "https://cosign.sigstore.dev/attestation/v1",
			"subject": [{
				"name": "test-image"
			}]
		}`)

		err := ValidateMetadata(invalidJSON)
		assert.Error(t, err)
	})
}

func TestValidateDepscan(t *testing.T) {
	// Set up test environment
	os.Setenv("POLICY_REPO_OWNER", "liatrio")
	os.Setenv("POLICY_REPO_NAME", "demo-gh-autogov-policy-library")
	os.Setenv("POLICY_VERSION", "v0.8.0")
	os.Setenv("GITHUB_TOKEN", os.Getenv("GH_TOKEN"))

	t.Run("validates valid depscan", func(t *testing.T) {
		validJSON := []byte(`{
			"_type": "https://in-toto.io/Statement/v1",
			"predicateType": "https://in-toto.io/attestation/vulns/v0.2",
			"subject": [{
				"name": "test-image",
				"digest": {
					"sha256": "abc123"
				}
			}],
			"predicate": {
				"scanner": {
					"uri": "https://github.com/anchore/grype",
					"version": "0.74.7",
					"db": {
						"name": "grype",
						"version": "1.0.0",
						"lastUpdated": "2024-01-01T00:00:00Z"
					},
					"result": [{
						"id": "CVE-2024-1234",
						"severity": {
							"method": "CVSSv3",
							"score": "7.5"
						}
					}]
				}
			}
		}`)

		err := ValidateDepscan(validJSON)
		assert.NoError(t, err)
	})

	t.Run("fails on invalid depscan", func(t *testing.T) {
		invalidJSON := []byte(`{
			"_type": "https://in-toto.io/Statement/v1",
			"predicateType": "https://in-toto.io/attestation/vulns/v0.2",
			"subject": [{
				"name": "test-image"
			}]
		}`)

		err := ValidateDepscan(invalidJSON)
		assert.Error(t, err)
	})
}
