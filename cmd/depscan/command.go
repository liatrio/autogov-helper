package depscan

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	depscan "autogov-helper/internal/attestation/depscan"

	"github.com/spf13/cobra"
)

func calculateFileDigest(path string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("failed to stat path: %w", err)
	}

	if info.IsDir() {
		// get all files in dir
		var files []string
		err := filepath.Walk(path, func(filePath string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if !info.IsDir() {
				files = append(files, filePath)
			}
			return nil
		})
		if err != nil {
			return "", fmt.Errorf("failed to walk directory: %w", err)
		}

		// sort for consistent digest
		sort.Strings(files)

		// get combined digest of all files
		h := sha256.New()
		for _, file := range files {
			f, err := os.Open(file)
			if err != nil {
				return "", fmt.Errorf("failed to open file %s: %w", file, err)
			}
			if _, err := io.Copy(h, f); err != nil {
				f.Close()
				return "", fmt.Errorf("failed to calculate digest for %s: %w", file, err)
			}
			f.Close()
		}
		return fmt.Sprintf("sha256:%s", hex.EncodeToString(h.Sum(nil))), nil
	}

	// handle single file
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("failed to open file: %w", err)
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("failed to calculate digest: %w", err)
	}

	return fmt.Sprintf("sha256:%s", hex.EncodeToString(h.Sum(nil))), nil
}

func listFilesInDir(dir string) ([]string, error) {
	var files []string
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to walk directory: %w", err)
	}
	sort.Strings(files)
	return files, nil
}

func NewCommand() *cobra.Command {
	var opts depscan.Options
	var outputFile string
	var artifactType string
	var subjectPath string

	cmd := &cobra.Command{
		Use:   "depscan",
		Short: "Generate dependency scan predicate",
		RunE: func(cmd *cobra.Command, args []string) error {
			// digest based on artifact type
			switch artifactType {
			case "blob":
				if subjectPath == "" {
					return fmt.Errorf("subject-path is required for blob type")
				}

				// check path is dir
				info, err := os.Stat(subjectPath)
				if err != nil {
					return fmt.Errorf("failed to stat path: %w", err)
				}

				if info.IsDir() {
					// get list of files in dir
					files, err := listFilesInDir(subjectPath)
					if err != nil {
						return err
					}
					opts.SubjectName = strings.Join(files, "\n")
				} else {
					opts.SubjectName = subjectPath
				}

				if opts.Digest == "" {
					digest, err := calculateFileDigest(subjectPath)
					if err != nil {
						return fmt.Errorf("failed to calculate file digest: %w", err)
					}
					opts.Digest = digest
				}
			case "image":
				if opts.SubjectName == "" {
					return fmt.Errorf("subject-name is required for image type")
				}
				if opts.Digest == "" {
					return fmt.Errorf("digest is required for container images")
				}
			default:
				return fmt.Errorf("invalid artifact type: %s (must be 'image' or 'blob')", artifactType)
			}

			scan, err := depscan.NewFromGrypeResults(opts)
			if err != nil {
				return fmt.Errorf("failed to process scan results: %w", err)
			}

			output, err := scan.Generate()
			if err != nil {
				return fmt.Errorf("failed to generate predicate: %w", err)
			}

			if outputFile != "" {
				if err := os.WriteFile(outputFile, output, 0600); err != nil {
					return fmt.Errorf("failed to write output file: %w", err)
				}
			} else {
				if _, err := fmt.Fprintln(cmd.OutOrStdout(), string(output)); err != nil {
					return fmt.Errorf("failed to write output: %w", err)
				}
			}

			return nil
		},
	}

	flags := cmd.Flags()
	flags.StringVar(&opts.ResultsPath, "results-path", "", "Path to Grype results JSON file")
	flags.StringVar(&opts.SubjectName, "subject-name", "", "Name of the subject being scanned (required for image type)")
	flags.StringVar(&subjectPath, "subject-path", "", "Path to the subject file or directory (required for blob type)")
	flags.StringVar(&opts.Digest, "digest", "", "Digest of the subject being scanned (required for container images, auto-calculated for blobs)")
	flags.StringVar(&outputFile, "output", "", "Output file path (defaults to stdout)")
	flags.StringVar(&artifactType, "type", "image", "Type of artifact (image or blob)")
	cobra.CheckErr(cmd.MarkFlagRequired("results-path"))

	return cmd
}
