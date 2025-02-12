package metadata

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	metadata "autogov-helper/internal/attestation/metadata"
	"autogov-helper/internal/config"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func NewCommand() *cobra.Command {
	var opts metadata.Options
	var outputFile string
	var subjectName string
	var subjectPaths []string
	var subjectDigest string
	var artifactType string

	cmd := &cobra.Command{
		Use:   "metadata",
		Short: "Generate metadata predicate",
		RunE: func(cmd *cobra.Command, args []string) error {
			viper.AutomaticEnv()
			viper.SetEnvPrefix("")
			viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))

			opts.Repository = os.Getenv("GITHUB_REPOSITORY")
			opts.RepositoryID = os.Getenv("GITHUB_REPOSITORY_ID")
			opts.GitHubServerURL = os.Getenv("GITHUB_SERVER_URL")
			opts.Owner = os.Getenv("GITHUB_REPOSITORY_OWNER")
			opts.OwnerID = os.Getenv("GITHUB_REPOSITORY_OWNER_ID")
			opts.WorkflowRefPath = os.Getenv("GITHUB_WORKFLOW_REF")
			opts.Branch = os.Getenv("GITHUB_REF_NAME")
			opts.Event = os.Getenv("GITHUB_EVENT_NAME")
			opts.RunNumber = os.Getenv("GITHUB_RUN_NUMBER")
			opts.RunID = os.Getenv("GITHUB_RUN_ID")
			opts.Status = os.Getenv("GITHUB_JOB_STATUS")
			opts.TriggeredBy = os.Getenv("GITHUB_ACTOR")
			opts.SHA = os.Getenv("GITHUB_SHA")

			opts.OS = os.Getenv("RUNNER_OS")
			opts.Arch = os.Getenv("RUNNER_ARCH")
			opts.Environment = os.Getenv("RUNNER_ENVIRONMENT")

			if opts.Status == "" {
				if status := os.Getenv("JOB_STATUS"); status != "" {
					opts.Status = status
				} else if status := os.Getenv("GITHUB_JOB_STATUS"); status != "" {
					opts.Status = status
				} else {
					// default to success if we can't determine status
					// matches GitHub Actions behavior where a running job is considered successful
					opts.Status = "success"
				}
			}

			// org falls back to repo owner
			opts.OrgName = os.Getenv("GITHUB_ORGANIZATION")
			if opts.OrgName == "" {
				opts.OrgName = opts.Owner
			}

			if opts.SHA != "" && opts.RunNumber != "" {
				if len(opts.SHA) >= 7 {
					opts.Version = fmt.Sprintf("%s-%s", opts.SHA[:7], opts.RunNumber)
				} else {
					opts.Version = fmt.Sprintf("%s-%s", opts.SHA, opts.RunNumber)
				}
			}

			now := time.Now().UTC()
			opts.Created = now

			if startedAt := os.Getenv("GITHUB_EVENT_WORKFLOW_RUN_CREATED_AT"); startedAt != "" {
				if t, err := time.Parse(time.RFC3339, startedAt); err == nil {
					opts.StartedAt = t
				}
			} else {
				if startedAt := os.Getenv("GITHUB_JOB_STARTED_AT"); startedAt != "" {
					if t, err := time.Parse(time.RFC3339, startedAt); err == nil {
						opts.StartedAt = t
					}
				}
			}

			if completedAt := os.Getenv("GITHUB_JOB_COMPLETED_AT"); completedAt != "" {
				if t, err := time.Parse(time.RFC3339, completedAt); err == nil {
					opts.CompletedAt = t
				}
			} else {
				opts.CompletedAt = now
			}

			if timestamp := os.Getenv("GITHUB_EVENT_HEAD_COMMIT_TIMESTAMP"); timestamp != "" {
				if t, err := time.Parse(time.RFC3339, timestamp); err == nil {
					opts.Timestamp = t
				}
			} else {
				if timestamp := os.Getenv("GITHUB_EVENT_TIMESTAMP"); timestamp != "" {
					if t, err := time.Parse(time.RFC3339, timestamp); err == nil {
						opts.Timestamp = t
					}
				} else {
					opts.Timestamp = now
				}
			}

			// set workflow inputs
			if inputs := os.Getenv("GITHUB_WORKFLOW_INPUTS"); inputs != "" {
				var workflowInputs map[string]any
				if err := json.Unmarshal([]byte(inputs), &workflowInputs); err == nil {
					opts.Inputs = workflowInputs
				}
			}

			// load config for policy repo
			cfg, err := config.Load()
			if err != nil {
				return fmt.Errorf("failed to load config: %w", err)
			}

			// policy ref from config
			opts.PolicyRef = fmt.Sprintf("https://github.com/%s/%s", cfg.PolicyRepo.Owner, cfg.PolicyRepo.Name)

			if opts.Owner != "" {
				opts.ControlIds = []string{
					fmt.Sprintf("%s-PROVENANCE-001", opts.Owner),
					fmt.Sprintf("%s-SBOM-002", opts.Owner),
					fmt.Sprintf("%s-METADATA-003", opts.Owner),
				}
			}

			opts.Permissions = map[string]string{
				"id-token":     "write",
				"attestations": "write",
				"contents":     "read",
			}

			switch artifactType {
			case "image":
				opts.Type = metadata.ArtifactTypeContainerImage
				if subjectName == "" {
					return fmt.Errorf("subject-name is required for image type")
				}
				if subjectDigest == "" {
					return fmt.Errorf("subject-digest is required for image type")
				}

				parts := strings.Split(subjectName, "/")
				opts.Registry = parts[0]
				opts.FullName = fmt.Sprintf("%s@%s", subjectName, subjectDigest)
				opts.Digest = subjectDigest

				// container images get packages write permission
				opts.Permissions["packages"] = "write"

			case "blob":
				opts.Type = metadata.ArtifactTypeBlob
				if len(subjectPaths) == 0 {
					return fmt.Errorf("subject-path is required for blob type")
				}
				opts.SubjectPath = strings.Join(subjectPaths, "\n")
				opts.Digest = subjectDigest
				// blobs get packages: none
				opts.Permissions["packages"] = "none"

			default:
				return fmt.Errorf("invalid artifact type: %s", artifactType)
			}

			m, err := metadata.NewFromOptions(opts)
			if err != nil {
				return fmt.Errorf("failed to create metadata: %w", err)
			}

			output, err := m.Generate()
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
	flags.StringVar(&outputFile, "output", "", "Output file")
	flags.StringSliceVar(&subjectPaths, "subject-path", []string{}, "Path(s) to the subject file(s) (required for blob type, can be specified multiple times)")
	flags.StringVar(&subjectName, "subject-name", "", "Name of the subject being attested (required for image type)")
	flags.StringVar(&subjectDigest, "subject-digest", "", "SHA256 digest of the subject (required for image type)")
	flags.StringVar(&artifactType, "type", "image", "Type of build (image or blob)")

	return cmd
}
