package validation

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

	"gh-attest-util/internal/config"

	"github.com/google/go-github/v68/github"
	"github.com/xeipuuv/gojsonschema"
)

// getGitHubClient returns a GitHub client using token from environment
func getGitHubClient() (*github.Client, error) {
	token := os.Getenv("GITHUB_TOKEN")
	if token == "" {
		return nil, fmt.Errorf("GITHUB_TOKEN environment variable not set")
	}
	return github.NewClient(nil).WithAuthToken(token), nil
}

// ValidateJSON validates a JSON document against a schema from the policy repo
func ValidateJSON(data []byte, schemaName string) error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Get GitHub client
	client, err := getGitHubClient()
	if err != nil {
		return fmt.Errorf("failed to create GitHub client: %w", err)
	}

	// Construct the raw GitHub URL for the schema
	schemaURL := fmt.Sprintf("https://raw.githubusercontent.com/%s/%s/%s/schemas/%s",
		cfg.PolicyRepo.Owner,
		cfg.PolicyRepo.Name,
		cfg.PolicyRepo.Ref,
		schemaName,
	)

	log.Printf("Fetching schema from: %s", schemaURL)

	// Create request with authentication
	req, err := http.NewRequest("GET", schemaURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Use the client's HTTP client which has auth configured
	resp, err := client.Client().Do(req)
	if err != nil {
		return fmt.Errorf("failed to fetch schema: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to fetch schema, status code: %d, url: %s", resp.StatusCode, schemaURL)
	}

	schemaBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read schema: %w", err)
	}

	// Parse the JSON document
	var doc interface{}
	if err := json.Unmarshal(data, &doc); err != nil {
		return fmt.Errorf("invalid JSON document: %w", err)
	}

	// Load the schema
	schemaLoader := gojsonschema.NewStringLoader(string(schemaBytes))
	documentLoader := gojsonschema.NewGoLoader(doc)

	// Validate
	result, err := gojsonschema.Validate(schemaLoader, documentLoader)
	if err != nil {
		return fmt.Errorf("validation error: %w", err)
	}

	if !result.Valid() {
		var errors []string
		for _, err := range result.Errors() {
			errors = append(errors, err.String())
		}
		return fmt.Errorf("validation failed: %v", errors)
	}

	return nil
}

// ValidateMetadata validates a metadata predicate against the schema
func ValidateMetadata(data []byte) error {
	return ValidateJSON(data, "metadata-schema.json")
}

// ValidateDepscan validates a dependency scan predicate against the schema
func ValidateDepscan(data []byte) error {
	return ValidateJSON(data, "dependency-vulnerability-schema.json")
}
