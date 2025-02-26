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
	cfg, err := Load()
	if err != nil {
		return "", errors.WrapError("load config", err)
	}

	// try github api first
	if token, err := env.GetGitHubToken(); err == nil && token != "" {
		client := github.NewClient(nil).WithAuthToken(token)
		log.Printf("fetching schema %s from %s/%s@%s via GitHub API", schemaName, cfg.PolicyRepo.Owner, cfg.PolicyRepo.Name, cfg.PolicyRepo.Ref)

		content, _, resp, err := client.Repositories.GetContents(
			context.Background(),
			cfg.PolicyRepo.Owner,
			cfg.PolicyRepo.Name,
			fmt.Sprintf("%s%s", cfg.SchemasPath, schemaName),
			&github.RepositoryContentGetOptions{Ref: cfg.PolicyRepo.Ref},
		)
		if err == nil && resp.StatusCode == 200 && content != nil {
			schemaContent, err := content.GetContent()
			if err == nil {
				return schemaContent, nil
			}
			log.Printf("failed to decode GitHub API response: %v", err)
		} else if err != nil {
			log.Printf("failed to fetch from GitHub API: %v", err)
		} else {
			log.Printf("GitHub API returned status %d", resp.StatusCode)
		}
	}

	// fallback to embedded
	if embedded := getEmbeddedSchema(schemaName); embedded != "" {
		log.Printf("using embedded schema for %s", schemaName)
		return embedded, nil
	}

	return "", fmt.Errorf("failed to fetch schema %s: no schema sources available", schemaName)
}

// validate json against schema
func ValidateJSON(data []byte, schemaName string) error {
	schemaContent, err := fetchSchemaContent(schemaName)
	if err != nil {
		return err
	}

	// extract predicate portion
	var schema map[string]interface{}
	if err := json.Unmarshal([]byte(schemaContent), &schema); err != nil {
		return errors.WrapError("parse schema", err)
	}
	if props, ok := schema["properties"].(map[string]interface{}); ok {
		if predicate, ok := props["predicate"].(map[string]interface{}); ok {
			predicateSchema, err := json.Marshal(predicate)
			if err != nil {
				return errors.WrapError("marshal predicate schema", err)
			}
			schemaContent = string(predicateSchema)
		}
	}

	// create schema loaders
	schemaLoader := gojsonschema.NewStringLoader(schemaContent)
	documentLoader := gojsonschema.NewBytesLoader(data)

	// validate
	result, err := gojsonschema.Validate(schemaLoader, documentLoader)
	if err != nil {
		return errors.WrapError("validation", err)
	}

	if !result.Valid() {
		var errs []string
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
