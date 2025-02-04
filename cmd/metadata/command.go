package metadata

import (
	"fmt"
	"os"
	"strings"
	"time"

	metadata "autogov-helper/internal/attestation/metadata"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func mustBindEnv(key, envVar string) {
	if err := viper.BindEnv(key, envVar); err != nil {
		panic(fmt.Sprintf("failed to bind env var %s: %v", envVar, err))
	}
}

func NewCommand() *cobra.Command {
	var opts metadata.Options
	var outputFile string
	var subjectName string
	var subjectPath string
	var subjectDigest string
	var artifactType string

	cmd := &cobra.Command{
		Use:   "metadata",
		Short: "Generate metadata predicate",
		RunE: func(cmd *cobra.Command, args []string) error {

			viper.AutomaticEnv()
			viper.SetEnvPrefix("")
			viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))

			// bind env vars
			mustBindEnv("repository", "GITHUB_REPOSITORY")
			mustBindEnv("repository-id", "GITHUB_REPOSITORY_ID")
			mustBindEnv("github-server-url", "GITHUB_SERVER_URL")
			mustBindEnv("owner", "GITHUB_REPOSITORY_OWNER")
			mustBindEnv("owner-id", "GITHUB_REPOSITORY_OWNER_ID")
			mustBindEnv("runner-os", "RUNNER_OS")
			mustBindEnv("runner-arch", "RUNNER_ARCH")
			mustBindEnv("runner-environment", "RUNNER_ENVIRONMENT")
			mustBindEnv("workflow-ref", "GITHUB_WORKFLOW_REF")
			mustBindEnv("ref-name", "GITHUB_REF_NAME")
			mustBindEnv("event-name", "GITHUB_EVENT_NAME")
			mustBindEnv("run-number", "GITHUB_RUN_NUMBER")
			mustBindEnv("run-id", "GITHUB_RUN_ID")
			mustBindEnv("job-status", "GITHUB_JOB_STATUS")
			mustBindEnv("actor", "GITHUB_ACTOR")
			mustBindEnv("sha", "GITHUB_SHA")
			mustBindEnv("organization", "GITHUB_ORGANIZATION")
			mustBindEnv("policy-ref", "POLICY_REF")
			mustBindEnv("control-ids", "CONTROL_IDS")
			mustBindEnv("job-started-at", "GITHUB_JOB_STARTED_AT")
			mustBindEnv("job-completed-at", "GITHUB_JOB_COMPLETED_AT")
			mustBindEnv("event-timestamp", "GITHUB_EVENT_TIMESTAMP")

			// set repo data
			opts.Repository = viper.GetString("repository")
			opts.RepositoryID = viper.GetString("repository-id")
			opts.GitHubServerURL = viper.GetString("github-server-url")

			// set owner data
			opts.Owner = viper.GetString("owner")
			opts.OwnerID = viper.GetString("owner-id")

			// set runner data
			opts.OS = viper.GetString("runner-os")
			opts.Arch = viper.GetString("runner-arch")
			opts.Environment = viper.GetString("runner-environment")

			// set wf data
			opts.WorkflowRefPath = viper.GetString("workflow-ref")
			opts.Branch = viper.GetString("ref-name")
			opts.Event = viper.GetString("event-name")

			// set job data
			opts.RunNumber = viper.GetString("run-number")
			opts.RunID = viper.GetString("run-id")
			opts.Status = viper.GetString("job-status")
			opts.TriggeredBy = viper.GetString("actor")
			if startedAt, err := time.Parse(time.RFC3339, viper.GetString("job-started-at")); err == nil {
				opts.StartedAt = startedAt
			}
			if completedAt, err := time.Parse(time.RFC3339, viper.GetString("job-completed-at")); err == nil {
				opts.CompletedAt = completedAt
			}

			// set commit data
			opts.SHA = viper.GetString("sha")
			if timestamp, err := time.Parse(time.RFC3339, viper.GetString("event-timestamp")); err == nil {
				opts.Timestamp = timestamp
			}

			// set org data
			opts.OrgName = viper.GetString("organization")

			// set compliance data
			opts.PolicyRef = viper.GetString("policy-ref")
			if controlIds := viper.GetString("control-ids"); controlIds != "" {
				opts.ControlIds = []string{controlIds}
			}

			// set permissions data
			opts.Permissions = map[string]string{
				"id-token":     "write",
				"attestations": "write",
				"contents":     "read",
				"packages":     "read",
			}

			// set artifact data
			opts.Created = time.Now()
			opts.Version = fmt.Sprintf("%s-%s", opts.SHA, opts.RunNumber)

			// handle artifact specific fields (not predicate)
			switch artifactType {
			case "image":
				opts.Type = metadata.ArtifactTypeContainerImage
				if subjectName == "" {
					return fmt.Errorf("subject-name is required for image type")
				}
				if subjectDigest == "" {
					return fmt.Errorf("subject-digest is required for image type")
				}
				opts.FullName = subjectName
				opts.Digest = subjectDigest
			case "blob":
				opts.Type = metadata.ArtifactTypeBlob
				if subjectPath == "" {
					return fmt.Errorf("subject-path is required for blob type")
				}
				opts.SubjectPath = subjectPath
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
	flags.StringVar(&subjectPath, "subject-path", "", "Path to the subject file (required for blob type)")
	flags.StringVar(&subjectName, "subject-name", "", "Name of the subject being attested (required for image type)")
	flags.StringVar(&subjectDigest, "subject-digest", "", "SHA256 digest of the subject (required for image type)")
	flags.StringVar(&artifactType, "type", "image", "Type of build (image or blob)")

	return cmd
}
