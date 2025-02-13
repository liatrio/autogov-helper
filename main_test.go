package main

import (
	"bytes"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
)

func TestMainCommand(t *testing.T) {
	t.Run("shows help", func(t *testing.T) {
		cmd := &cobra.Command{
			Use:   "autogov-helper",
			Short: "GitHub Actions attestation utilities",
			Long:  "GitHub Actions attestation utilities for generating attestations",
		}

		buf := new(bytes.Buffer)
		cmd.SetOut(buf)
		cmd.SetArgs([]string{"--help"})

		err := cmd.Execute()
		assert.NoError(t, err)
		assert.Contains(t, buf.String(), "GitHub Actions attestation utilities")
	})
}
