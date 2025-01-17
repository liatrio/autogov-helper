package github

import (
	"encoding/json"
	"fmt"
	"os"
)

const (
	// env vars
	envRepository        = "GITHUB_REPOSITORY"
	envRepositoryID      = "GITHUB_REPOSITORY_ID"
	envRepositoryOwner   = "GITHUB_REPOSITORY_OWNER"
	envRepositoryOwnerID = "GITHUB_REPOSITORY_OWNER_ID"
	envServerURL         = "GITHUB_SERVER_URL"
	envSHA               = "GITHUB_SHA"
	envRefName           = "GITHUB_REF_NAME"
	envEventName         = "GITHUB_EVENT_NAME"
	envActor             = "GITHUB_ACTOR"
	envRunID             = "GITHUB_RUN_ID"
	envRunNumber         = "GITHUB_RUN_NUMBER"
	envWorkflowRef       = "GITHUB_WORKFLOW_REF"
	envJobStatus         = "GITHUB_JOB_STATUS"
	envEventPath         = "GITHUB_EVENT_PATH"
	envWorkflowInputs    = "GITHUB_WORKFLOW_INPUTS"
	envRunnerOS          = "RUNNER_OS"
	envRunnerArch        = "RUNNER_ARCH"
	envRunnerEnv         = "RUNNER_ENVIRONMENT"
)

type Context struct {
	// repo data
	Repository      string `json:"repository"`
	RepositoryOwner string `json:"repository_owner"`
	RepositoryID    string `json:"repository_id"`
	ServerURL       string `json:"server_url"`

	// repo owner
	RepositoryOwnerID string `json:"repository_owner_id"`

	// wf data
	WorkflowRef string `json:"workflow_ref"`
	RefName     string `json:"ref_name"`
	EventName   string `json:"event_name"`

	// run data
	SHA       string `json:"sha"`
	RunNumber string `json:"run_number"`
	RunID     string `json:"run_id"`
	Actor     string `json:"actor"`

	// event data
	Event struct {
		WorkflowRun struct {
			CreatedAt string `json:"created_at"`
		} `json:"workflow_run"`
		HeadCommit struct {
			Timestamp string `json:"timestamp"`
		} `json:"head_commit"`
	} `json:"event"`

	// inputs passed to the workflow
	Inputs map[string]any `json:"inputs"`

	// job status
	JobStatus string `json:"job_status"`

	// runner data
	Runner *Runner `json:"runner"`
}

type Runner struct {
	OS          string `json:"os"`
	Arch        string `json:"arch"`
	Environment string `json:"environment"`
}

// loads gh context from individual environment variables
func LoadFromEnv() (*Context, error) {
	ctx := &Context{
		Repository:        os.Getenv(envRepository),
		RepositoryID:      os.Getenv(envRepositoryID),
		RepositoryOwner:   os.Getenv(envRepositoryOwner),
		RepositoryOwnerID: os.Getenv(envRepositoryOwnerID),
		ServerURL:         os.Getenv(envServerURL),
		SHA:               os.Getenv(envSHA),
		RefName:           os.Getenv(envRefName),
		EventName:         os.Getenv(envEventName),
		Actor:             os.Getenv(envActor),
		RunID:             os.Getenv(envRunID),
		RunNumber:         os.Getenv(envRunNumber),
		WorkflowRef:       os.Getenv(envWorkflowRef),
		JobStatus:         os.Getenv(envJobStatus),
		Inputs:            make(map[string]any),
	}

	// get event data from GITHUB_EVENT_PATH
	if eventData, err := os.ReadFile(os.Getenv(envEventPath)); err == nil {
		var event struct {
			WorkflowRun struct {
				CreatedAt string `json:"created_at"`
			} `json:"workflow_run"`
			HeadCommit struct {
				Timestamp string `json:"timestamp"`
			} `json:"head_commit"`
		}
		if err := json.Unmarshal(eventData, &event); err == nil {
			ctx.Event.WorkflowRun.CreatedAt = event.WorkflowRun.CreatedAt
			ctx.Event.HeadCommit.Timestamp = event.HeadCommit.Timestamp
		}
	}

	// get workflow inputs from GITHUB_WORKFLOW_INPUTS
	// note: GITHUB_WORKFLOW_INPUTS is used exclusively as it provides a reliable JSON structure of all workflow inputs, rather than individual INPUT_* env vars
	if workflowInputs := os.Getenv(envWorkflowInputs); workflowInputs != "" {
		if err := json.Unmarshal([]byte(workflowInputs), &ctx.Inputs); err != nil {
			return nil, fmt.Errorf("failed to parse workflow inputs: %w", err)
		}
	}

	osName := os.Getenv(envRunnerOS)
	if osName == "" {
		return nil, fmt.Errorf("RUNNER_OS environment variable not set")
	}

	arch := os.Getenv(envRunnerArch)
	if arch == "" {
		return nil, fmt.Errorf("RUNNER_ARCH environment variable not set")
	}

	ctx.Runner = &Runner{
		OS:          osName,
		Arch:        arch,
		Environment: os.Getenv(envRunnerEnv),
	}

	return ctx, nil
}
