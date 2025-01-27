package main

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSanitizeFieldName(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"special_github", "github_url", "GitHubURL"},
		{"special_predicate_type", "predicate_type", "PredicateType"},
		{"special_owner_data", "owner_data", "OwnerData"},
		{"special_runner_data", "runner_data", "RunnerData"},
		{"special_commit_data", "commit_data", "CommitData"},
		{"special_repository_data", "repository_data", "RepositoryData"},
		{"special_workflow_data", "workflow_data", "WorkflowData"},
		{"special_job_data", "job_data", "JobData"},
		{"special_policy_ref", "policy_ref", "PolicyRef"},
		{"special_control_ids", "control_ids", "ControlIDs"},
		{"special_github_server_url", "github_server_url", "GitHubServerURL"},
		{"special_workflow_ref_path", "workflow_ref_path", "WorkflowRefPath"},
		{"special_run_number", "run_number", "RunNumber"},
		{"special_triggered_by", "triggered_by", "TriggeredBy"},
		{"special_started_at", "started_at", "StartedAt"},
		{"special_completed_at", "completed_at", "CompletedAt"},
		{"special_owner_id", "owner_id", "OwnerID"},
		{"special_repository_id", "repository_id", "RepositoryID"},
		{"special_run_id", "run_id", "RunID"},
		{"special_id_token", "id_token", "IDToken"},
		{"special_os", "os", "OS"},
		{"special_sha", "sha", "SHA"},
		{"special_type", "_type", "Type"},
		{"camelCase", "camelCase", "CamelCase"},
		{"snake_case", "snake_case", "SnakeCase"},
		{"mixed_CASE", "mixed_CASE", "MixedCase"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sanitizeFieldName(tt.input)
			if result != tt.expected {
				t.Errorf("expected: %q, got: %q", tt.expected, result)
			}
		})
	}
}

func TestGenerateSchema(t *testing.T) {
	schema := map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"_type": map[string]interface{}{
				"type": "string",
			},
			"predicateType": map[string]interface{}{
				"type": "string",
			},
			"subject": map[string]interface{}{
				"type": "array",
				"items": map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"name": map[string]interface{}{
							"type": "string",
						},
						"digest": map[string]interface{}{
							"type": "object",
							"properties": map[string]interface{}{
								"sha256": map[string]interface{}{
									"type": "string",
								},
							},
						},
					},
				},
			},
			"predicate": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"test": map[string]interface{}{
						"type": "string",
					},
				},
			},
		},
		"required": []interface{}{
			"_type",
			"predicateType",
			"subject",
			"predicate",
		},
	}

	code, err := generateSchema(schema, "TestStruct")
	assert.NoError(t, err)
	assert.NotEmpty(t, code)

	// Verify the generated code contains the expected struct
	expectedStruct := `type TestStruct struct {
	Type          string    ` + "`json:\"_type\"`" + `
	PredicateType string    ` + "`json:\"predicateType\"`" + `
	Subject       []Subject ` + "`json:\"subject\"`" + `
	Predicate     TestStructPredicate ` + "`json:\"predicate\"`" + `
}

type TestStructPredicate struct {
	Test string ` + "`json:\"test\"`" + `
}`

	assert.Contains(t, code, expectedStruct)
}

func TestGenerateStructFields(t *testing.T) {
	schema := map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"stringField": map[string]interface{}{
				"type": "string",
			},
			"intField": map[string]interface{}{
				"type": "integer",
			},
			"arrayField": map[string]interface{}{
				"type": "array",
				"items": map[string]interface{}{
					"type": "string",
				},
			},
			"objectField": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"nestedField": map[string]interface{}{
						"type": "string",
					},
				},
			},
		},
	}

	fields, nestedTypes, err := generateStructFields(schema, "TestStruct")
	if err != nil {
		t.Fatalf("generateStructFields failed: %v", err)
	}

	fieldsStr := strings.Join(fields, "\n")

	// Verify field types are correctly generated
	expectedTypes := map[string]string{
		"StringField": "string",
		"IntField":    "int",
		"ArrayField":  "[]string",
	}

	for fieldName, fieldType := range expectedTypes {
		if !strings.Contains(fieldsStr, fieldName+" "+fieldType) {
			t.Errorf("generated fields do not contain %s with type %s", fieldName, fieldType)
		}
	}

	// Verify nested type generation
	if len(nestedTypes) == 0 {
		t.Error("expected nested types for object field")
	}
}

func TestValidateSchema(t *testing.T) {
	tests := []struct {
		name          string
		schema        map[string]interface{}
		expectError   bool
		errorContains string
	}{
		{
			name: "valid schema",
			schema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"_type": map[string]interface{}{
						"type": "string",
					},
					"subject": map[string]interface{}{
						"type": "array",
					},
				},
				"required": []interface{}{"_type", "subject"},
			},
			expectError: false,
		},
		{
			name:          "missing type",
			schema:        map[string]interface{}{},
			expectError:   true,
			errorContains: "schema has no type field",
		},
		{
			name: "missing properties",
			schema: map[string]interface{}{
				"type": "object",
			},
			expectError:   true,
			errorContains: "schema has no properties",
		},
		{
			name: "missing required fields",
			schema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"foo": map[string]interface{}{
						"type": "string",
					},
				},
			},
			expectError:   true,
			errorContains: "missing required field",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateSchema(tt.schema)
			if tt.expectError {
				if err == nil {
					t.Error("expected error but got nil")
				} else if !strings.Contains(err.Error(), tt.errorContains) {
					t.Errorf("expected error containing %q but got %q", tt.errorContains, err.Error())
				}
			} else if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}
