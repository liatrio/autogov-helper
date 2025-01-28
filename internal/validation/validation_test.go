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
							"metadata": {
								"type": "object",
								"properties": {
									"buildType": { "type": "string" },
									"permissionType": { "type": "string" }
								},
								"required": ["buildType", "permissionType"]
							}
						},
						"required": ["artifact", "metadata"]
					}
				}
			}`
		case "/liatrio/demo-gh-autogov-policy-library/v0.8.0/schemas/dependency-vulnerability.json":
			schema = `{
				"$schema": "http://json-schema.org/draft-07/schema#",
				"type": "object",
				"properties": {
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
				}
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
			"predicate": {
				"artifact": {
					"version": "1.0.0",
					"created": "2024-01-27T19:48:49Z",
					"type": "container-image"
				},
				"metadata": {
					"buildType": "github-workflow",
					"permissionType": "github-workflow"
				}
			}
		}`)

		err := ValidateMetadata(validMetadata)
		assert.NoError(t, err)
	})

	t.Run("fails on invalid metadata", func(t *testing.T) {
		invalidMetadata := []byte(`{
			"_type": "https://in-toto.io/Statement/v1",
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
