package template

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRenderMetadataTemplate(t *testing.T) {
	testCases := []struct {
		name     string
		data     MetadataTemplateData
		validate func(t *testing.T, output []byte)
	}{
		{
			name: "container image with remote registry",
			data: MetadataTemplateData{
				Type:            "container-image",
				Version:         "1.0.0",
				Digest:          "sha256:abc123",
				Created:         "2024-01-27T19:48:49Z",
				Registry:        "ghcr.io",
				Repository:      "owner/repo",
				RepositoryID:    "123",
				GitHubServerURL: "https://github.com",
				Owner:           "owner",
				OwnerID:         "456",
				RunnerOS:        "linux",
				RunnerArch:      "X64",
				WorkflowInputs:  "{}",
			},
			validate: func(t *testing.T, output []byte) {
				var data map[string]interface{}
				err := json.Unmarshal(output, &data)
				require.NoError(t, err)

				artifact := data["artifact"].(map[string]interface{})
				assert.Equal(t, "container-image", artifact["type"])
				assert.Equal(t, "ghcr.io", artifact["registry"])
				assert.Equal(t, "ghcr.io/owner/repo@sha256:abc123", artifact["fullName"])
				assert.Equal(t, "write", data["security"].(map[string]interface{})["permissions"].(map[string]interface{})["packages"])
			},
		},
		{
			name: "container image with local registry",
			data: MetadataTemplateData{
				Type:            "container-image",
				Version:         "1.0.0",
				Digest:          "sha256:abc123",
				Created:         "2024-01-27T19:48:49Z",
				Registry:        "local",
				SubjectName:     "test-image",
				Repository:      "owner/repo",
				RepositoryID:    "123",
				GitHubServerURL: "https://github.com",
				Owner:           "owner",
				OwnerID:         "456",
				RunnerOS:        "linux",
				RunnerArch:      "X64",
				WorkflowInputs:  "{}",
			},
			validate: func(t *testing.T, output []byte) {
				var data map[string]interface{}
				err := json.Unmarshal(output, &data)
				require.NoError(t, err)

				artifact := data["artifact"].(map[string]interface{})
				assert.Equal(t, "container-image", artifact["type"])
				assert.Equal(t, "local", artifact["registry"])
				assert.Equal(t, "test-image", artifact["fullName"])
				assert.Equal(t, "read", data["security"].(map[string]interface{})["permissions"].(map[string]interface{})["packages"])
			},
		},
		{
			name: "blob",
			data: MetadataTemplateData{
				Type:            "blob",
				Version:         "1.0.0",
				Created:         "2024-01-27T19:48:49Z",
				Path:            "path/to/blob",
				Repository:      "owner/repo",
				RepositoryID:    "123",
				GitHubServerURL: "https://github.com",
				Owner:           "owner",
				OwnerID:         "456",
				RunnerOS:        "linux",
				RunnerArch:      "X64",
				WorkflowInputs:  "{}",
			},
			validate: func(t *testing.T, output []byte) {
				var data map[string]interface{}
				err := json.Unmarshal(output, &data)
				require.NoError(t, err)

				artifact := data["artifact"].(map[string]interface{})
				assert.Equal(t, "blob", artifact["type"])
				assert.Equal(t, "path/to/blob", artifact["path"])
				assert.Equal(t, "read", data["security"].(map[string]interface{})["permissions"].(map[string]interface{})["packages"])
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			output, err := RenderTemplate("metadata", tc.data)
			require.NoError(t, err)
			tc.validate(t, output)
		})
	}
}
