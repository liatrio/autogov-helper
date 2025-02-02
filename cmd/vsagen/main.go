package main

import (
	"log"
	"os"

	"gh-attest-util/internal/cmd/generate"

	"github.com/spf13/cobra"
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "vsagen",
		Short: "Generate various attestations",
	}

	rootCmd.AddCommand(generate.NewCommand())

	if err := rootCmd.Execute(); err != nil {
		log.Printf("Error: %v\n", err)
		os.Exit(1)
	}
}
