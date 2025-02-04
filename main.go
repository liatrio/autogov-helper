package main

import (
	"os"

	"autogov-helper/cmd/depscan"
	"autogov-helper/cmd/metadata"

	"github.com/spf13/cobra"
)

func main() {
	cmd := &cobra.Command{
		Use:   "autogov-helper",
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
