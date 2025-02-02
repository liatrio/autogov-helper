package main

import (
	"os"

	"gh-attest-util/cmd/metadata"
	"gh-attest-util/cmd/testresult"
	"gh-attest-util/cmd/vsa"

	"github.com/spf13/cobra"
)

func main() {
	cmd := &cobra.Command{
		Use:   "gh-attest-util",
		Short: "GitHub Actions attestation utilities",
		Long:  "GitHub Actions attestation utilities for generating attestations",
	}

	cmd.AddCommand(
		testresult.NewCommand(),
		metadata.NewCommand(),
		vsa.NewCommand(),
	)

	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
