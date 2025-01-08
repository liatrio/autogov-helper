package main

import (
	"fmt"
	"os"

	"gh-attest-util/cmd/depscan"
	"gh-attest-util/cmd/metadata"

	"github.com/spf13/cobra"
)

func main() {
	cmd := newRootCmd()
	if err := cmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func newRootCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "gh-attest-util",
		Short: "GitHub Attestation Utility",
		Long:  "A utility for generating custom predicates for GitHub artifact attestations",
	}

	cmd.AddCommand(metadata.NewCommand(), depscan.NewCommand())
	return cmd
}
