package attestation

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"autogov-helper/internal/util/env"
)

// github actions runtime context
type Context struct {
	// repo info
	Repository      string `json:"repository"`
	RepositoryOwner string `json:"repository_owner"`
	RepositoryID    string `json:"repository_id"`
	ServerURL       string `json:"server_url"`

	// owner info
	RepositoryOwnerID string `json:"repository_owner_id"`

	// workflow info
	WorkflowRef string `json:"workflow_ref"`
	RefName     string `json:"ref_name"`
	EventName   string `json:"event_name"`

	// run info
	SHA       string `json:"sha"`
	RunNumber string `json:"run_number"`
	RunID     string `json:"run_id"`
	Actor     string `json:"actor"`

	// event info
	Event struct {
		WorkflowRun struct {
			CreatedAt string `json:"created_at"`
		} `json:"workflow_run"`
		HeadCommit struct {
			Timestamp string `json:"timestamp"`
		} `json:"head_commit"`
	} `json:"event"`

	// workflow inputs
	Inputs map[string]any `json:"inputs"`

	// job info
	JobStatus string `json:"job_status"`

	// runner info
	Runner *Runner `json:"runner"`

	// org info
	Organization struct {
		Name string `json:"name"`
	} `json:"organization"`
}

// github actions runner info
type Runner struct {
	OS          string `json:"os"`
	Arch        string `json:"arch"`
	Environment string `json:"environment"`
}

// load github context from env
func LoadGitHubContext() (*Context, error) {
	ctx := &Context{
		Repository:        os.Getenv(env.EnvGitHubRepository),
		RepositoryID:      os.Getenv(env.EnvGitHubRepositoryID),
		RepositoryOwner:   os.Getenv(env.EnvGitHubRepositoryOwner),
		RepositoryOwnerID: os.Getenv(env.EnvGitHubOwnerID),
		ServerURL:         os.Getenv(env.EnvGitHubServerURL),
		SHA:               os.Getenv(env.EnvGitHubSHA),
		RefName:           os.Getenv(env.EnvGitHubRefName),
		EventName:         os.Getenv(env.EnvGitHubEventName),
		Actor:             os.Getenv(env.EnvGitHubActor),
		RunID:             os.Getenv(env.EnvGitHubRunID),
		RunNumber:         os.Getenv(env.EnvGitHubRunNumber),
		WorkflowRef:       os.Getenv(env.EnvGitHubWorkflowRef),
		JobStatus:         os.Getenv("GITHUB_JOB_STATUS"),
		Inputs:            make(map[string]any),
	}

	if ctx.JobStatus == "" {
		ctx.JobStatus = "success"
	}

	// get event data
	if eventData, err := os.ReadFile(os.Getenv(env.EnvGitHubEventPath)); err == nil {
		var event struct {
			WorkflowRun struct {
				CreatedAt string `json:"created_at"`
			} `json:"workflow_run"`
			HeadCommit struct {
				Timestamp string `json:"timestamp"`
			} `json:"head_commit"`
		}
		if err := json.Unmarshal(eventData, &event); err == nil {
			// parse and convert to utc
			if t, err := time.Parse(time.RFC3339, event.WorkflowRun.CreatedAt); err == nil {
				ctx.Event.WorkflowRun.CreatedAt = t.UTC().Format(time.RFC3339)
			} else {
				ctx.Event.WorkflowRun.CreatedAt = time.Now().UTC().Format(time.RFC3339)
			}
			if t, err := time.Parse(time.RFC3339, event.HeadCommit.Timestamp); err == nil {
				ctx.Event.HeadCommit.Timestamp = t.UTC().Format(time.RFC3339)
			}
		}
	}

	// set current time if not set
	if ctx.Event.HeadCommit.Timestamp == "" {
		ctx.Event.HeadCommit.Timestamp = time.Now().UTC().Format(time.RFC3339)
	}

	// get workflow inputs
	if workflowInputs := os.Getenv(env.EnvGitHubWorkflowInputs); workflowInputs != "" {
		var inputs map[string]any
		if err := json.Unmarshal([]byte(workflowInputs), &inputs); err != nil {
			return nil, fmt.Errorf("failed to parse workflow inputs: %w", err)
		}
		if len(inputs) > 0 {
			ctx.Inputs = inputs
		}
	}

	osName := os.Getenv(env.EnvRunnerOS)
	if osName == "" {
		return nil, fmt.Errorf("RUNNER_OS environment variable not set")
	}

	arch := os.Getenv(env.EnvRunnerArch)
	if arch == "" {
		return nil, fmt.Errorf("RUNNER_ARCH environment variable not set")
	}

	ctx.Runner = &Runner{
		OS:          osName,
		Arch:        arch,
		Environment: os.Getenv(env.EnvRunnerEnvironment),
	}

	if ctx.RepositoryOwner != "" {
		ctx.Organization.Name = ctx.RepositoryOwner
	}

	return ctx, nil
}
