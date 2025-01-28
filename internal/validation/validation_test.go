package validation

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupMockSchemaServer(t *testing.T) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var schema string
		switch r.URL.Path {
		case "/liatrio/demo-gh-autogov-policy-library/v0.8.0/schemas/metadata.json":
			schema = `{
				"$schema": "http://json-schema.org/draft-07/schema#",
				"type": "object",
				"properties": {
					"_type": {
						"type": "string",
						"const": "https://in-toto.io/Statement/v1"
					},
					"subject": {
						"type": "array",
						"items": {
							"type": "object",
							"properties": {
								"name": {
									"type": "string"
								},
								"digest": {
									"type": "object",
									"properties": {
										"sha256": {
											"type": "string"
										}
									},
									"required": ["sha256"]
								}
							},
							"required": ["name", "digest"]
						}
					},
					"predicateType": {
						"type": "string",
						"const": "https://cosign.sigstore.dev/attestation/v1"
					},
					"predicate": {
						"type": "object",
						"properties": {
							"artifact": {
								"type": "object",
								"properties": {
									"version": { "type": "string" },
									"created": { "type": "string", "format": "date-time" },
									"type": { "type": "string", "enum": ["container-image", "blob"] }
								},
								"required": ["version", "created", "type"]
							},
							"repositoryData": {
								"type": "object",
								"properties": {
									"repository": { "type": "string" },
									"repositoryId": { "type": "string" },
									"githubServerURL": { "type": "string" }
								},
								"required": ["repository", "repositoryId", "githubServerURL"]
							},
							"ownerData": {
								"type": "object",
								"properties": {
									"owner": { "type": "string" },
									"ownerId": { "type": "string" }
								},
								"required": ["owner", "ownerId"]
							},
							"runnerData": {
								"type": "object",
								"properties": {
									"os": { "type": "string" },
									"arch": { "type": "string" },
									"environment": { "type": "string" }
								},
								"required": ["os", "arch", "environment"]
							},
							"workflowData": {
								"type": "object",
								"properties": {
									"workflowRefPath": { "type": "string" },
									"inputs": { "type": "object" },
									"branch": { "type": "string" },
									"event": { "type": "string" }
								},
								"required": ["workflowRefPath", "inputs", "branch", "event"]
							},
							"jobData": {
								"type": "object",
								"properties": {
									"runNumber": { "type": "string" },
									"runId": { "type": "string" },
									"status": { "type": "string" },
									"triggeredBy": { "type": "string" },
									"startedAt": { "type": "string", "format": "date-time" },
									"completedAt": { "type": "string", "format": "date-time" }
								},
								"required": ["runNumber", "runId", "status", "triggeredBy", "startedAt", "completedAt"]
							},
							"commitData": {
								"type": "object",
								"properties": {
									"sha": { "type": "string" },
									"timestamp": { "type": "string", "format": "date-time" }
								},
								"required": ["sha", "timestamp"]
							},
							"organization": {
								"type": "object",
								"properties": {
									"name": { "type": "string" }
								},
								"required": ["name"]
							},
							"compliance": {
								"type": "object",
								"properties": {
									"policyRef": { "type": "string", "format": "uri" },
									"controlIds": {
										"type": "array",
										"items": { "type": "string" }
									}
								},
								"required": ["policyRef", "controlIds"]
							},
							"security": {
								"type": "object",
								"properties": {
									"permissions": {
										"type": "object",
										"properties": {
											"id-token": { "type": "string", "enum": ["write"] },
											"attestations": { "type": "string", "enum": ["write"] },
											"contents": { "type": "string", "enum": ["read"] },
											"packages": { "type": "string", "enum": ["read"] }
										}
									}
								},
								"required": ["permissions"]
							}
						},
						"required": [
							"artifact",
							"repositoryData",
							"ownerData",
							"runnerData",
							"workflowData",
							"jobData",
							"commitData",
							"organization",
							"compliance",
							"security"
						]
					}
				},
				"required": ["_type", "subject", "predicateType", "predicate"]
			}`
		case "/liatrio/demo-gh-autogov-policy-library/v0.8.0/schemas/dependency-vulnerability.json":
			schema = `{
				"$schema": "http://json-schema.org/draft-07/schema#",
				"type": "object",
				"properties": {
					"_type": {
						"type": "string",
						"const": "https://in-toto.io/Statement/v1"
					},
					"subject": {
						"type": "array",
						"items": {
							"type": "object",
							"properties": {
								"name": {
									"type": "string"
								},
								"digest": {
									"type": "object",
									"properties": {
										"sha256": {
											"type": "string"
										}
									},
									"required": ["sha256"]
								}
							},
							"required": ["name", "digest"]
						}
					},
					"predicateType": {
						"type": "string",
						"const": "https://in-toto.io/attestation/vulns/v0.2"
					},
					"predicate": {
						"type": "object",
						"properties": {
							"scanner": {
								"type": "object",
								"properties": {
									"uri": { "type": "string" },
									"version": { "type": "string" },
									"db": {
										"type": "object",
										"properties": {
											"name": { "type": "string" },
											"version": { "type": "string" },
											"lastUpdated": { "type": "string", "format": "date-time" }
										},
										"required": ["name", "version", "lastUpdated"]
									},
									"result": {
										"type": "array",
										"items": {
											"type": "object",
											"properties": {
												"id": { "type": "string" },
												"severity": {
													"type": "object",
													"properties": {
														"method": { "type": "string" },
														"score": { "type": "string" }
													},
													"required": ["method", "score"]
												}
											},
											"required": ["id", "severity"]
										}
									}
								},
								"required": ["uri", "version", "db", "result"]
							}
						},
						"required": ["scanner"]
					}
				},
				"required": ["_type", "subject", "predicateType", "predicate"]
			}`
		default:
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintln(w, schema)
	}))
}

func TestValidateMetadata(t *testing.T) {
	mockServer := setupMockSchemaServer(t)
	defer mockServer.Close()

	// Set up test environment
	os.Setenv("POLICY_REPO_OWNER", "liatrio")
	os.Setenv("POLICY_REPO_NAME", "demo-gh-autogov-policy-library")
	os.Setenv("POLICY_VERSION", "v0.8.0")
	os.Setenv("GITHUB_TOKEN", "test-token")

	// Use mock server URL
	setSchemaBaseURL(mockServer.URL)

	t.Run("validates valid metadata", func(t *testing.T) {
		validMetadata := []byte(`{
			"_type": "https://in-toto.io/Statement/v1",
			"subject": [{
				"name": "test-image",
				"digest": {
					"sha256": "abc123"
				}
			}],
			"predicateType": "https://cosign.sigstore.dev/attestation/v1",
			"predicate": {
				"artifact": {
					"version": "1.0.0",
					"created": "2024-01-27T19:48:49Z",
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
					"startedAt": "2024-01-27T19:48:49Z",
					"completedAt": "2024-01-27T19:48:49Z"
				},
				"commitData": {
					"sha": "abc123",
					"timestamp": "2024-01-27T19:48:49Z"
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

		err := ValidateMetadata(validMetadata)
		assert.NoError(t, err)
	})

	t.Run("fails on invalid metadata", func(t *testing.T) {
		invalidMetadata := []byte(`{
			"_type": "https://in-toto.io/Statement/v1",
			"subject": [{
				"name": "test-image",
				"digest": {
					"sha256": "abc123"
				}
			}],
			"predicateType": "https://cosign.sigstore.dev/attestation/v1",
			"predicate": {
				"artifact": {
					"version": "1.0.0",
					"type": "invalid-type"
				}
			}
		}`)

		err := ValidateMetadata(invalidMetadata)
		require.Error(t, err)
	})
}

func TestValidateDepscan(t *testing.T) {
	mockServer := setupMockSchemaServer(t)
	defer mockServer.Close()

	// Set up test environment
	os.Setenv("POLICY_REPO_OWNER", "liatrio")
	os.Setenv("POLICY_REPO_NAME", "demo-gh-autogov-policy-library")
	os.Setenv("POLICY_VERSION", "v0.8.0")
	os.Setenv("GITHUB_TOKEN", "test-token")

	// Use mock server URL
	setSchemaBaseURL(mockServer.URL)

	t.Run("validates valid depscan", func(t *testing.T) {
		validDepscan := []byte(`{
			"_type": "https://in-toto.io/Statement/v1",
			"subject": [{
				"name": "test-image",
				"digest": {
					"sha256": "abc123"
				}
			}],
			"predicateType": "https://in-toto.io/attestation/vulns/v0.2",
			"predicate": {
				"scanner": {
					"uri": "https://github.com/anchore/grype/releases/tag/v0.74.7",
					"version": "0.74.7",
					"db": {
						"name": "grype",
						"version": "1.5",
						"lastUpdated": "2024-01-27T19:48:49Z"
					},
					"result": [
						{
							"id": "CVE-2024-1234",
							"severity": {
								"method": "CVSSv3",
								"score": "7.5"
							}
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
					"sha256": "abc123"
				}
			}],
			"predicateType": "https://in-toto.io/attestation/vulns/v0.2",
			"predicate": {
				"scanner": {
					"uri": "https://github.com/anchore/grype/releases/tag/v0.74.7",
					"version": "0.74.7",
					"result": []
				}
			}
		}`)

		err := ValidateDepscan(invalidDepscan)
		require.Error(t, err)
	})
}
