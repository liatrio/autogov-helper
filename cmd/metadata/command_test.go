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
		os.Setenv("POLICY_VERSION", "v0.8.0")
		os.Setenv("GITHUB_TOKEN", os.Getenv("GH_TOKEN"))

		// Set up test environment for compliance and security
		os.Setenv("POLICY_REF", "https://github.com/liatrio/demo-gh-autogov-policy-library")
		os.Setenv("CONTROL_IDS", "test-control")
		os.Setenv("PERMISSIONS_ID_TOKEN", "write")
		os.Setenv("PERMISSIONS_ATTESTATIONS", "write")
		os.Setenv("PERMISSIONS_CONTENTS", "read")
		os.Setenv("PERMISSIONS_PACKAGES", "read")

		cmd := metadata.NewCommand()
		var output bytes.Buffer
		cmd.SetOut(&output)

		cmd.SetArgs([]string{
			"--subject-name", "test-image",
			"--digest", "sha256:123",
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
		assert.Equal(t, "container-image", artifact["type"])

		repositoryData := predicate["repositoryData"].(map[string]interface{})
		assert.Equal(t, "test-repo", repositoryData["repository"])
		assert.Equal(t, "123", repositoryData["repositoryId"])
		assert.Equal(t, "https://github.com", repositoryData["githubServerURL"])

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

		organization := predicate["organization"].(map[string]interface{})
		assert.Equal(t, "test-owner", organization["name"])

		compliance := predicate["compliance"].(map[string]interface{})
		assert.Equal(t, "https://github.com/liatrio/demo-gh-autogov-policy-library", compliance["policyRef"])
		assert.Equal(t, []interface{}{"test-control"}, compliance["controlIds"])

		security := predicate["security"].(map[string]interface{})
		permissions := security["permissions"].(map[string]interface{})
		assert.Equal(t, "write", permissions["id-token"])
		assert.Equal(t, "write", permissions["attestations"])
		assert.Equal(t, "read", permissions["contents"])
		assert.Equal(t, "read", permissions["packages"])
	})
}
