package metadata_test

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"

	"gh-attest-util/cmd/metadata"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMetadataCommand(t *testing.T) {
	t.Run("generates valid metadata", func(t *testing.T) {
		os.Setenv("GITHUB_REPOSITORY", "test-repo")
		os.Setenv("GITHUB_REPOSITORY_OWNER", "test-owner")
		os.Setenv("GITHUB_REPOSITORY_ID", "123")
		os.Setenv("GITHUB_SERVER_URL", "https://github.com")
		os.Setenv("GITHUB_REPOSITORY_OWNER_ID", "456")
		os.Setenv("GITHUB_WORKFLOW_REF", ".github/workflows/build.yml")
		os.Setenv("GITHUB_REF_NAME", "main")
		os.Setenv("GITHUB_EVENT_NAME", "push")
		os.Setenv("GITHUB_SHA", "abc1234")
		os.Setenv("GITHUB_RUN_NUMBER", "1")
		os.Setenv("GITHUB_RUN_ID", "789")
		os.Setenv("GITHUB_ACTOR", "test-user")
		os.Setenv("GITHUB_JOB_STATUS", "success")
		os.Setenv("RUNNER_OS", "Linux")
		os.Setenv("RUNNER_ARCH", "X64")
		os.Setenv("RUNNER_ENVIRONMENT", "github-hosted")

		cmd := metadata.NewCommand()
		var output bytes.Buffer
		cmd.SetOut(&output)

		cmd.SetArgs([]string{
			"--subject-name", "test-image",
			"--digest", "sha256:123",
			"--policy-ref", "https://example.com/policy",
			"--control-ids", "TEST-001,TEST-002",
		})

		err := cmd.Execute()
		require.NoError(t, err)

		var result map[string]interface{}
		err = json.Unmarshal(output.Bytes(), &result)
		require.NoError(t, err)

		subject := result["subject"].([]interface{})[0].(map[string]interface{})
		assert.Equal(t, "test-image", subject["name"])
		assert.Equal(t, "sha256:123", subject["digest"].(map[string]interface{})["sha256"])

		predicate := result["predicate"].(map[string]interface{})

		artifact := predicate["artifact"].(map[string]interface{})
		assert.Equal(t, "https://in-toto.io/attestation/github-workflow/v0.2", artifact["type"])

		repoData := predicate["repositoryData"].(map[string]interface{})
		assert.Equal(t, "test-repo", repoData["repository"])
		assert.Equal(t, "123", repoData["repositoryId"])
		assert.Equal(t, "https://github.com", repoData["githubServerURL"])

		ownerData := predicate["ownerData"].(map[string]interface{})
		assert.Equal(t, "test-owner", ownerData["owner"])
		assert.Equal(t, "456", ownerData["ownerId"])

		runnerData := predicate["runnerData"].(map[string]interface{})
		assert.Equal(t, "Linux", runnerData["os"])
		assert.Equal(t, "X64", runnerData["arch"])
		assert.Equal(t, "github-hosted", runnerData["environment"])

		workflowData := predicate["workflowData"].(map[string]interface{})
		assert.Equal(t, ".github/workflows/build.yml", workflowData["workflowRefPath"])
		assert.Equal(t, "main", workflowData["branch"])
		assert.Equal(t, "push", workflowData["event"])

		jobData := predicate["jobData"].(map[string]interface{})
		assert.Equal(t, "1", jobData["runNumber"])
		assert.Equal(t, "789", jobData["runId"])
		assert.Equal(t, "success", jobData["status"])
		assert.Equal(t, "test-user", jobData["triggeredBy"])

		commitData := predicate["commitData"].(map[string]interface{})
		assert.Equal(t, "abc1234", commitData["sha"])

		org := predicate["organization"].(map[string]interface{})
		assert.Equal(t, "test-owner", org["name"])

		compliance := predicate["compliance"].(map[string]interface{})
		assert.Equal(t, "https://example.com/policy", compliance["policyRef"])
		assert.Equal(t, []interface{}{"TEST-001", "TEST-002"}, compliance["controlIds"])

		security := predicate["security"].(map[string]interface{})
		permissions := security["permissions"].(map[string]interface{})
		assert.Equal(t, "write", permissions["id-token"])
		assert.Equal(t, "write", permissions["attestations"])
		assert.Equal(t, "write", permissions["packages"])
		assert.Equal(t, "read", permissions["contents"])
	})
}
