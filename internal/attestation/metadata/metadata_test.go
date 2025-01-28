package metadata

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestNewFromOptions(t *testing.T) {
	now := time.Now().UTC()

	tests := []struct {
		name    string
		opts    Options
		wantErr bool
	}{
		{
			name: "valid container image metadata",
			opts: Options{
				Type:            ArtifactTypeContainerImage,
				Registry:        "ghcr.io",
				Repository:      "test-org/test-repo",
				FullName:        "ghcr.io/test-org/test-repo",
				Digest:          "sha256:test",
				Version:         "test-sha-test-run-number",
				Created:         now,
				GitHubServerURL: "https://github.com",
				Owner:           "test-org",
				OwnerID:         "test-owner-id",
				OS:              "test-os",
				Arch:            "test-arch",
				Environment:     "test-env",
				WorkflowRefPath: "test-workflow-ref",
				Branch:          "test-branch",
				Event:           "test-event",
				RunNumber:       "test-run-number",
				RunID:           "test-run-id",
				Status:          "test-status",
				TriggeredBy:     "test-user",
				StartedAt:       now,
				CompletedAt:     now,
				SHA:             "test-sha",
				Timestamp:       now,
				OrgName:         "test-org",
				PolicyRef:       "test-policy",
				ControlIds:      []string{"test-control"},
				Permissions: map[string]string{
					"id-token":     "write",
					"attestations": "write",
					"contents":     "read",
					"packages":     "read",
				},
			},
		},
		{
			name: "valid blob metadata",
			opts: Options{
				Type:            ArtifactTypeBlob,
				Repository:      "test-org/test-repo",
				SubjectPath:     "test-file",
				Digest:          "sha256:test",
				Version:         "test-sha-test-run-number",
				Created:         now,
				GitHubServerURL: "https://github.com",
				Owner:           "test-org",
				OwnerID:         "test-owner-id",
				OS:              "test-os",
				Arch:            "test-arch",
				Environment:     "test-env",
				WorkflowRefPath: "test-workflow-ref",
				Branch:          "test-branch",
				Event:           "test-event",
				RunNumber:       "test-run-number",
				RunID:           "test-run-id",
				Status:          "test-status",
				TriggeredBy:     "test-user",
				StartedAt:       now,
				CompletedAt:     now,
				SHA:             "test-sha",
				Timestamp:       now,
				OrgName:         "test-org",
				PolicyRef:       "test-policy",
				ControlIds:      []string{"test-control"},
				Permissions: map[string]string{
					"id-token":     "write",
					"attestations": "write",
					"contents":     "read",
					"packages":     "read",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, err := NewFromOptions(tt.opts)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)

			// verify metadata marshable to JSON
			output, err := json.Marshal(m)
			assert.NoError(t, err)
			assert.NotEmpty(t, output)

			// verify valid JSON object
			var jsonMap map[string]interface{}
			err = json.Unmarshal(output, &jsonMap)
			assert.NoError(t, err)
		})
	}
}
