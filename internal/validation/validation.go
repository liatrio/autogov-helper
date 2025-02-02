package validation

import (
	"context"
	"fmt"
	"gh-attest-util/internal/attestation/vsa"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
	"time"

	"gh-attest-util/internal/config"

	"github.com/google/go-github/v68/github"
	"github.com/xeipuuv/gojsonschema"
)

var (
	schemaBaseURL = "https://raw.githubusercontent.com"
	httpClient    = &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			DisableKeepAlives:   true,
			DisableCompression:  true,
			MaxIdleConns:        1,
			IdleConnTimeout:     30 * time.Second,
			MaxIdleConnsPerHost: 1,
		},
	}
)

// for testing
func setSchemaBaseURL(url string) {
	schemaBaseURL = url
}

// returns a GitHub client using token from env
func getGitHubClient() (*github.Client, error) {
	// try gh token first, then github token
	token := os.Getenv("GH_TOKEN")
	if token == "" {
		token = os.Getenv("GITHUB_TOKEN")
	}

	if token == "" {
		return nil, fmt.Errorf("neither GH_TOKEN nor GITHUB_TOKEN environment variable is set")
	}

	return github.NewClient(nil).WithAuthToken(token), nil
}

// ensures the schema URL is safe
func validateSchemaURL(baseURL, schemaName string) (string, error) {
	// validate schema name
	if !strings.HasSuffix(schemaName, ".json") {
		return "", fmt.Errorf("schema name must end with .json")
	}
	if strings.Contains(schemaName, "..") {
		return "", fmt.Errorf("schema name cannot contain path traversal")
	}

	// parse and validate base url
	parsedURL, err := url.Parse(baseURL)
	if err != nil {
		return "", fmt.Errorf("invalid base url: %w", err)
	}

	// ensure schema path is clean and safe
	schemaPath := path.Clean("/schemas/" + schemaName)
	if !strings.HasPrefix(schemaPath, "/schemas/") {
		return "", fmt.Errorf("invalid schema path")
	}

	// construct final url
	parsedURL.Path = path.Join(parsedURL.Path, schemaPath)
	return parsedURL.String(), nil
}

// fetches schema content either from a direct URL or gh api
func fetchSchemaContent(schemaName string) (string, error) {
	cfg, err := config.Load()
	if err != nil {
		return "", fmt.Errorf("failed to load config: %w", err)
	}

	// if schema base url is set, use direct http
	if schemaBaseURL != "https://raw.githubusercontent.com" {
		url, err := validateSchemaURL(schemaBaseURL, schemaName)
		if err != nil {
			return "", fmt.Errorf("invalid schema url: %w", err)
		}

		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
		if err != nil {
			return "", fmt.Errorf("failed to create request: %w", err)
		}

		resp, err := httpClient.Do(req)
		if err != nil {
			return "", fmt.Errorf("failed to fetch schema: %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return "", fmt.Errorf("failed to fetch schema: HTTP %d", resp.StatusCode)
		}

		content, err := io.ReadAll(resp.Body)
		if err != nil {
			return "", fmt.Errorf("failed to read schema content: %w", err)
		}

		return string(content), nil
	}

	// otherwise use github api
	client, err := getGitHubClient()
	if err != nil {
		return "", fmt.Errorf("failed to create GitHub client: %w", err)
	}

	log.Printf("fetching schema %s from %s/%s@%s", schemaName, cfg.PolicyRepo.Owner, cfg.PolicyRepo.Name, cfg.PolicyRepo.Ref)

	content, _, _, err := client.Repositories.GetContents(
		context.Background(),
		cfg.PolicyRepo.Owner,
		cfg.PolicyRepo.Name,
		fmt.Sprintf("schemas/%s", schemaName),
		&github.RepositoryContentGetOptions{Ref: cfg.PolicyRepo.Ref},
	)
	if err != nil {
		return "", fmt.Errorf("failed to fetch schema: %w", err)
	}

	schemaContent, err := content.GetContent()
	if err != nil {
		return "", fmt.Errorf("failed to decode schema content: %w", err)
	}

	return schemaContent, nil
}

// validates json against schema from policy repo
func ValidateJSON(data []byte, schemaName string) error {
	schemaContent, err := fetchSchemaContent(schemaName)
	if err != nil {
		return err
	}

	// create schema loaders
	schemaLoader := gojsonschema.NewStringLoader(schemaContent)
	documentLoader := gojsonschema.NewBytesLoader(data)

	// validate schema
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

// validates a metadata attestation against the schema
func ValidateMetadata(data []byte) error {
	return ValidateJSON(data, "metadata.json")
}

// validates a dependency scan attestation against the test-result schema
func ValidateDepscan(data []byte) error {
	return ValidateJSON(data, "test-result.json")
}

// validates a verification summary attestation against the schema
func ValidateVSA(data []byte) error {
	// validate against schema
	if err := ValidateJSON(data, "verification-summary.json"); err != nil {
		return fmt.Errorf("schema validation failed: %w", err)
	}

	// parse / validate using VSA package
	vsa, err := vsa.NewVSAFromBytes(data)
	if err != nil {
		return fmt.Errorf("failed to parse VSA: %w", err)
	}

	// verify valid vsa
	if err := vsa.VerifyBuildLevel(1); err != nil {
		return fmt.Errorf("VSA verification failed: %w", err)
	}

	return nil
}
