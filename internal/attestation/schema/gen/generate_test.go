package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSanitizeFieldName(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"simple", "name", "Name"},
		{"snake_case", "first_name", "FirstName"},
		{"kebab-case", "first-name", "FirstName"},
		{"special_github", "github_url", "GitHubURL"},
		{"special_id", "repository-id", "RepositoryID"},
		{"special_os", "os", "OS"},
		{"special_sha", "sha", "SHA"},
		{"special_token", "id-token", "IDToken"},
		{"predicate_fields", "workflowData", "WorkflowData"},
		{"predicate_fields_kebab", "workflow-data", "WorkflowData"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sanitizeFieldName(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGenerateSchema(t *testing.T) {
	// test a simple schema
	simpleSchema := map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"name": map[string]interface{}{
				"type": "string",
			},
			"age": map[string]interface{}{
				"type": "integer",
			},
			"metadata": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"created-at": map[string]interface{}{
						"type": "string",
					},
					"github-url": map[string]interface{}{
						"type": "string",
					},
				},
			},
		},
	}

	result, err := generateSchema("TestType", simpleSchema)
	require.NoError(t, err)

	// verify the generated code contains expected fields
	assert.Contains(t, result, "package generated")
	assert.Contains(t, result, "type TestType struct")
	assert.Contains(t, result, "Name string `json:\"name\"`")
	assert.Contains(t, result, "Age int `json:\"age\"`")
	assert.Contains(t, result, "CreatedAt string `json:\"created-at\"`")
	assert.Contains(t, result, "GitHubURL string `json:\"github-url\"`")

	// test array type schema
	arraySchema := map[string]interface{}{
		"type": "array",
		"items": map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"id": map[string]interface{}{
					"type": "string",
				},
				"tags": map[string]interface{}{
					"type": "array",
					"items": map[string]interface{}{
						"type": "string",
					},
				},
			},
		},
	}

	result, err = generateSchema("ArrayType", arraySchema)
	require.NoError(t, err)

	// verify the generated array type
	assert.Contains(t, result, "type ArrayType []struct")
	assert.Contains(t, result, "ID string `json:\"id\"`")
	assert.Contains(t, result, "Tags []string `json:\"tags\"`")
}

func TestGenerateStructFields(t *testing.T) {
	props := map[string]interface{}{
		"permissions": map[string]interface{}{
			"type": "object",
		},
		"inputs": map[string]interface{}{
			"type": "object",
		},
		"nested": map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"field1": map[string]interface{}{
					"type": "string",
				},
				"field2": map[string]interface{}{
					"type": "array",
					"items": map[string]interface{}{
						"type": "string",
					},
				},
			},
		},
	}

	result, err := generateStructFields(props, "    ")
	require.NoError(t, err)

	// verify special cases for permissions and inputs
	assert.Contains(t, result, "Permissions map[string]string `json:\"permissions\"`")
	assert.Contains(t, result, "Inputs map[string]interface{} `json:\"inputs\"`")

	// verify nested struct generation
	assert.Contains(t, result, "Field1 string `json:\"field1\"`")
	assert.Contains(t, result, "Field2 []string `json:\"field2\"`")
}
