package vsa

import (
	"fmt"
	"os"

	"gh-attest-util/internal/attestation/vsa"

	"github.com/spf13/cobra"
)

func NewCommand() *cobra.Command {
	var vsaPath string
	var expectedLevel int
	var outputFile string

	cmd := &cobra.Command{
		Use:   "vsa",
		Short: "Verify SLSA build level from VSA",
		RunE: func(cmd *cobra.Command, args []string) error {
			// read vsa file
			vsaData, err := os.ReadFile(vsaPath)
			if err != nil {
				return fmt.Errorf("failed to read VSA file: %w", err)
			}

			// parse vsa
			vsaObj, err := vsa.NewVSAFromBytes(vsaData)
			if err != nil {
				return fmt.Errorf("failed to parse VSA: %w", err)
			}

			// verify build lvl
			if err := vsaObj.VerifyBuildLevel(expectedLevel); err != nil {
				return fmt.Errorf("VSA verification failed: %w", err)
			}

			if outputFile != "" {
				if err := os.WriteFile(outputFile, vsaData, 0600); err != nil {
					return fmt.Errorf("failed to write output file: %w", err)
				}
			}

			return nil
		},
	}

	cmd.Flags().StringVarP(&vsaPath, "vsa", "v", "", "Path to VSA file")
	cmd.Flags().IntVarP(&expectedLevel, "level", "l", 3, "Expected SLSA build level (L0-L3)")
	cmd.Flags().StringVarP(&outputFile, "output", "o", "", "Output file path")

	if err := cmd.MarkFlagRequired("vsa"); err != nil {
		panic(fmt.Sprintf("failed to mark 'vsa' flag as required: %v", err))
	}

	// validate lvl range before running
	cmd.PreRunE = func(cmd *cobra.Command, args []string) error {
		if expectedLevel < 0 || expectedLevel > 3 {
			return fmt.Errorf("invalid SLSA build level %d: per SLSA v1.0 spec, must be between 0 and 3", expectedLevel)
		}
		return nil
	}

	if err := cmd.MarkFlagRequired("vsa"); err != nil {
		panic(fmt.Sprintf("failed to mark 'vsa' flag as required: %v", err))
	}

	return cmd
}
