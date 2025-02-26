package config

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"log"

	"autogov-helper/internal/util/env"
	"autogov-helper/internal/util/errors"

	"github.com/google/go-github/v68/github"
	"github.com/xeipuuv/gojsonschema"
)

//go:embed schemas/metadata-schema.json
var embeddedMetadataSchema string

//go:embed schemas/dependency-vulnerability-schema.json
var embeddedDepscanSchema string

// get embedded schema content by name
func getEmbeddedSchema(schemaName string) string {
	switch schemaName {
	case "metadata-schema.json":
		return embeddedMetadataSchema
	case "dependency-vulnerability-schema.json":
		return embeddedDepscanSchema
	default:
		return ""
	}
}

// fetch schema from github or embedded
func fetchSchemaContent(schemaName string) (string, error) {
	// try github api first
	if token, err := env.GetGitHubToken(); err == nil && token != "" {
		cfg, err := Load()
		if err != nil {
			return "", errors.WrapError("load config", err)
		}

		client := github.NewClient(nil).WithAuthToken(token)
		path := fmt.Sprintf("%s%s", cfg.SchemasPath, schemaName)
		content, _, resp, err := client.Repositories.GetContents(
			context.Background(),
			cfg.PolicyRepo.Owner,
			cfg.PolicyRepo.Name,
			path,
			&github.RepositoryContentGetOptions{Ref: cfg.PolicyRepo.Ref},
		)

		if err == nil && resp.StatusCode == 200 && content != nil {
			if schemaContent, err := content.GetContent(); err == nil {
				return schemaContent, nil
			}
		}
		log.Printf("failed to fetch schema from GitHub API, falling back to embedded")
	}

	// fallback to embedded
	if schema := getEmbeddedSchema(schemaName); schema != "" {
		return schema, nil
	}

	return "", fmt.Errorf("failed to fetch schema %s: no schema sources available", schemaName)
}

// validate json against schema
func ValidateJSON(data []byte, schemaName string) error {
	schemaContent, err := fetchSchemaContent(schemaName)
	if err != nil {
		return err
	}

	var schema map[string]interface{}
	if err := json.Unmarshal([]byte(schemaContent), &schema); err != nil {
		return errors.WrapError("parse schema", err)
	}

	predicateSchema := schema
	if props, ok := schema["properties"].(map[string]interface{}); ok {
		if predicate, ok := props["predicate"].(map[string]interface{}); ok {
			predicateSchema = predicate
		}
	}

	schemaData, err := json.Marshal(predicateSchema)
	if err != nil {
		return errors.WrapError("marshal schema", err)
	}

	result, err := gojsonschema.Validate(
		gojsonschema.NewStringLoader(string(schemaData)),
		gojsonschema.NewBytesLoader(data),
	)
	if err != nil {
		return errors.WrapError("validation", err)
	}

	if !result.Valid() {
		errs := make([]string, 0, len(result.Errors()))
		for _, err := range result.Errors() {
			errs = append(errs, err.String())
		}
		return fmt.Errorf("validation failed: %v", errs)
	}

	return nil
}

// validate metadata attestation
func ValidateMetadata(data []byte) error {
	return ValidateJSON(data, "metadata-schema.json")
}

// validate depscan attestation
func ValidateDepscan(data []byte) error {
	return ValidateJSON(data, "dependency-vulnerability-schema.json")
}
