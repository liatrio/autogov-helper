package main

import (
	"os"

	"gh-attest-util/cmd/depscan"
	"gh-attest-util/cmd/metadata"

	"github.com/spf13/cobra"
)

func main() {
	cmd := &cobra.Command{
		Use:   "gh-attest-util",
		Short: "GitHub Actions attestation utilities",
		Long:  "GitHub Actions attestation utilities for generating attestations",
	}

	cmd.AddCommand(
		depscan.NewCommand(),
		metadata.NewCommand(),
	)

	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
