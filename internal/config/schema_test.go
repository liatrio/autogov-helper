package config

import (
	"testing"

	"autogov-helper/internal/util/testutil"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateMetadata(t *testing.T) {
	cleanup := testutil.SetupTestEnv(t)
	defer cleanup()

	t.Run("validates valid metadata", func(t *testing.T) {
		validMetadata := []byte(`{
			"artifact": {
				"version": "1.0.0",
				"created": "2024-01-27T19:48:49Z",
				"type": "container-image",
				"registry": "ghcr.io",
				"fullName": "ghcr.io/test-org/test-repo@sha256:test",
				"digest": "sha256:test"
			},
			"repositoryData": {
				"repository": "test-org/test-repo",
				"repositoryId": "123",
				"githubServerURL": "https://github.com"
			},
			"ownerData": {
				"owner": "test-org",
				"ownerId": "456"
			},
			"runnerData": {
				"os": "linux",
				"arch": "amd64",
				"environment": "github-hosted"
			},
			"workflowData": {
				"workflowRefPath": "test-workflow",
				"inputs": {
					"test-input": "test-value"
				},
				"branch": "main",
				"event": "push"
			},
			"jobData": {
				"runNumber": "1",
				"runId": "123",
				"status": "success",
				"triggeredBy": "test-user",
				"startedAt": "2024-01-27T19:48:49Z",
				"completedAt": "2024-01-27T19:48:50Z"
			},
			"commitData": {
				"sha": "abc123",
				"timestamp": "2024-01-27T19:48:49Z"
			},
			"organization": {
				"name": "test-org"
			},
			"compliance": {
				"policyRef": "https://github.com/test-org/test-policy",
				"controlIds": ["test-control"]
			},
			"security": {
				"permissions": {
					"id-token": "write",
					"attestations": "write",
					"contents": "read",
					"packages": "write"
				}
			}
		}`)

		err := ValidateMetadata(validMetadata)
		assert.NoError(t, err)
	})

	t.Run("fails on invalid metadata", func(t *testing.T) {
		invalidMetadata := []byte(`{
			"artifact": {
				"version": "1.0.0",
				"type": "invalid-type"
			}
		}`)

		err := ValidateMetadata(invalidMetadata)
		require.Error(t, err)
	})
}

func TestValidateDepscan(t *testing.T) {
	cleanup := testutil.SetupTestEnv(t)
	defer cleanup()

	t.Run("validates valid depscan", func(t *testing.T) {
		validDepscan := []byte(`{
			"_type": "https://in-toto.io/Statement/v1",
			"subject": [{
				"name": "test-image",
				"digest": {
					"sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
				}
			}],
			"predicateType": "https://in-toto.io/attestation/vulns/v0.2",
			"predicate": {
				"scanner": {
					"name": "grype",
					"uri": "https://github.com/anchore/grype/releases/tag/v0.74.7",
					"version": "0.74.7",
					"db": {
						"uri": "https://toolbox-data.anchore.io/grype/databases/listing.json",
						"version": "1.5",
						"lastUpdate": "2024-01-27T19:48:49Z"
					},
					"result": [
						{
							"id": "CVE-2024-1234",
							"severity": [
								{
									"method": "CVSSv3",
									"score": "7.5"
								}
							]
						}
					]
				}
			}
		}`)

		err := ValidateDepscan(validDepscan)
		assert.NoError(t, err)
	})

	t.Run("fails on invalid depscan", func(t *testing.T) {
		invalidDepscan := []byte(`{
			"_type": "https://in-toto.io/Statement/v1",
			"subject": [{
				"name": "test-image",
				"digest": {
					"sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
				}
			}],
			"predicateType": "https://in-toto.io/attestation/vulns/v0.2",
			"predicate": {
				"scanner": {
					"uri": "https://github.com/anchore/grype/releases/tag/v0.74.7",
					"version": "0.74.7",
					"db": {
						"uri": "https://toolbox-data.anchore.io/grype/databases/listing.json",
						"version": "1.5",
						"lastUpdate": "2024-01-27T19:48:49Z"
					},
					"result": []
				}
			}
		}`)

		err := ValidateDepscan(invalidDepscan)
		require.Error(t, err)
	})
}
