package github

import (
	"encoding/json"
	"fmt"
	"os"
)

// Context represents the GitHub Actions context
type Context struct {
	// Repository info
	Repository      string `json:"repository"`
	RepositoryOwner string `json:"repository_owner"`
	RepositoryID    string `json:"repository_id"`
	ServerURL       string `json:"server_url"`

	// Owner info
	OwnerID string `json:"repository_owner_id"`

	// Workflow info
	WorkflowRef string `json:"workflow_ref"`
	RefName     string `json:"ref_name"`
	EventName   string `json:"event_name"`

	// Run info
	SHA       string `json:"sha"`
	RunNumber string `json:"run_number"`
	RunID     string `json:"run_id"`
	Actor     string `json:"actor"`

	// Event data
	Event struct {
		WorkflowRun struct {
			CreatedAt string `json:"created_at"`
		} `json:"workflow_run"`
		HeadCommit struct {
			Timestamp string `json:"timestamp"`
		} `json:"head_commit"`
	} `json:"event"`

	// Inputs passed to the workflow
	Inputs map[string]any `json:"inputs"`
}

// Runner represents GitHub Actions runner context
type Runner struct {
	OS          string `json:"os"`
	Arch        string `json:"arch"`
	Environment string `json:"environment"`
}

// LoadFromEnv loads GitHub context from environment variables
func LoadFromEnv() (*Context, error) {
	ctx := &Context{
		// Repository info
		Repository:      os.Getenv("GITHUB_REPOSITORY"),
		RepositoryOwner: os.Getenv("GITHUB_REPOSITORY_OWNER"),
		RepositoryID:    os.Getenv("GITHUB_REPOSITORY_ID"),
		ServerURL:       os.Getenv("GITHUB_SERVER_URL"),

		// Owner info
		OwnerID: os.Getenv("GITHUB_REPOSITORY_OWNER_ID"),

		// Workflow info
		WorkflowRef: os.Getenv("GITHUB_WORKFLOW_REF"),
		RefName:     os.Getenv("GITHUB_REF_NAME"),
		EventName:   os.Getenv("GITHUB_EVENT_NAME"),

		// Run info
		SHA:       os.Getenv("GITHUB_SHA"),
		RunNumber: os.Getenv("GITHUB_RUN_NUMBER"),
		RunID:     os.Getenv("GITHUB_RUN_ID"),
		Actor:     os.Getenv("GITHUB_ACTOR"),
	}

	// Load event data from GITHUB_EVENT_PATH
	eventPath := os.Getenv("GITHUB_EVENT_PATH")
	if eventPath != "" {
		eventData, err := os.ReadFile(eventPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read event data: %w", err)
		}

		var event struct {
			WorkflowRun struct {
				CreatedAt string `json:"created_at"`
			} `json:"workflow_run"`
			HeadCommit struct {
				Timestamp string `json:"timestamp"`
			} `json:"head_commit"`
		}
		if err := json.Unmarshal(eventData, &event); err != nil {
			return nil, fmt.Errorf("failed to parse event data: %w", err)
		}
		ctx.Event = event
	}

	// Load workflow inputs from GITHUB_EVENT_PATH
	if eventPath != "" {
		eventData, err := os.ReadFile(eventPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read event data: %w", err)
		}

		var event struct {
			Inputs map[string]any `json:"inputs"`
		}
		if err := json.Unmarshal(eventData, &event); err != nil {
			return nil, fmt.Errorf("failed to parse event data: %w", err)
		}
		ctx.Inputs = event.Inputs
	}

	return ctx, nil
}

// LoadRunnerFromEnv loads runner context from environment variables
func LoadRunnerFromEnv() (*Runner, error) {
	osName := os.Getenv("RUNNER_OS")
	if osName == "" {
		return nil, fmt.Errorf("RUNNER_OS environment variable not set")
	}

	arch := os.Getenv("RUNNER_ARCH")
	if arch == "" {
		return nil, fmt.Errorf("RUNNER_ARCH environment variable not set")
	}

	env := os.Getenv("RUNNER_ENVIRONMENT")

	return &Runner{
		OS:          osName,
		Arch:        arch,
		Environment: env,
	}, nil
}
