package github

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLoadFromEnv(t *testing.T) {
	t.Run("valid_environment", func(t *testing.T) {
		os.Setenv(envRunnerOS, "Linux")
		os.Setenv(envRunnerArch, "X64")
		os.Setenv(envWorkflowInputs, `{"key":"value"}`)
		defer os.Unsetenv(envWorkflowInputs)

		ctx, err := LoadFromEnv()
		assert.NoError(t, err)

		assert.Equal(t, "value", ctx.Inputs["key"])
	})

	t.Run("workflow_inputs_from_json", func(t *testing.T) {
		os.Setenv(envRunnerOS, "Linux")
		os.Setenv(envRunnerArch, "X64")
		os.Setenv(envWorkflowInputs, `{
			"key": "value",
			"extra-key": "extra-value"
		}`)
		defer os.Unsetenv(envWorkflowInputs)

		ctx, err := LoadFromEnv()
		assert.NoError(t, err)

		assert.Equal(t, "value", ctx.Inputs["key"])
		assert.Equal(t, "extra-value", ctx.Inputs["extra-key"])
	})

	t.Run("missing_runner_os", func(t *testing.T) {
		os.Unsetenv(envRunnerOS)
		os.Setenv(envRunnerArch, "X64")

		_, err := LoadFromEnv()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "RUNNER_OS environment variable not set")
	})

	t.Run("missing_runner_arch", func(t *testing.T) {
		os.Setenv(envRunnerOS, "Linux")
		os.Unsetenv(envRunnerArch)

		_, err := LoadFromEnv()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "RUNNER_ARCH environment variable not set")
	})
}
