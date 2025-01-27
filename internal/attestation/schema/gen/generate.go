package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/go-github/v60/github"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

const (
	owner       = "liatrio"
	repo        = "demo-gh-autogov-policy-library"
	schemasPath = "schemas/"
	targetDir   = "../" // generate directly in schema package
)

const commonStructs = `
// Subject represents a subject in an attestation
type Subject struct {
	Name   string ` + "`json:\"name\"`" + `
	Digest struct {
		SHA256 string ` + "`json:\"sha256\"`" + `
	} ` + "`json:\"digest\"`" + `
}
`

// defaultPredicateFields contains the common predicate fields that should be present in all attestations
var defaultPredicateFields = map[string][]string{
	"metadata": {
		"PredicateType string `json:\"predicateType\"`",
		"Predicate struct {",
		"    Type string `json:\"type\"`",
		"    Timestamp string `json:\"timestamp\"`",
		"    Artifact struct {",
		"        Registry string `json:\"registry\"`",
		"        FullName string `json:\"fullName\"`",
		"        Digest string `json:\"digest\"`",
		"    } `json:\"artifact\"`",
		"} `json:\"predicate\"`",
	},
	"depscan": {
		"PredicateType string `json:\"predicateType\"`",
		"Predicate struct {",
		"    Type string `json:\"type\"`",
		"    Timestamp string `json:\"timestamp\"`",
		"    Scanner struct {",
		"        URI string `json:\"uri\"`",
		"        Version string `json:\"version\"`",
		"        DB struct {",
		"            Name string `json:\"name\"`",
		"            Version string `json:\"version\"`",
		"            LastUpdated string `json:\"lastUpdated\"`",
		"        } `json:\"db\"`",
		"        Result []struct {",
		"            ID string `json:\"id\"`",
		"            Severity struct {",
		"                Method string `json:\"method\"`",
		"                Score string `json:\"score\"`",
		"            } `json:\"severity\"`",
		"        } `json:\"result\"`",
		"    } `json:\"scanner\"`",
		"    Artifact struct {",
		"        Registry string `json:\"registry\"`",
		"        FullName string `json:\"fullName\"`",
		"        Digest string `json:\"digest\"`",
		"    } `json:\"artifact\"`",
		"} `json:\"predicate\"`",
	},
}

// sanitizeFieldName converts a JSON field name to a valid Go field name
func sanitizeFieldName(name string) string {
	caser := cases.Title(language.English)

	// special case field names
	switch name {
	case "id":
		return "ID"
	case "id-token":
		return "IDToken"
	case "os":
		return "OS"
	case "sha":
		return "SHA"
	case "run-id", "runId":
		return "RunID"
	case "owner-id", "ownerId":
		return "OwnerID"
	case "repository-id", "repositoryId":
		return "RepositoryID"
	case "github-url", "githubUrl":
		return "GitHubURL"
	case "github-server-url", "githubServerURL":
		return "GitHubServerURL"
	case "predicate-type", "predicateType":
		return "PredicateType"
	case "full-name", "fullName":
		return "FullName"
	case "repository-data", "repositoryData":
		return "RepositoryData"
	case "owner-data", "ownerData":
		return "OwnerData"
	case "runner-data", "runnerData":
		return "RunnerData"
	case "workflow-data", "workflowData":
		return "WorkflowData"
	case "job-data", "jobData":
		return "JobData"
	case "commit-data", "commitData":
		return "CommitData"
	case "workflow-ref-path", "workflowRefPath":
		return "WorkflowRefPath"
	case "triggered-by", "triggeredBy":
		return "TriggeredBy"
	case "started-at", "startedAt":
		return "StartedAt"
	case "completed-at", "completedAt":
		return "CompletedAt"
	case "run-number", "runNumber":
		return "RunNumber"
	case "policy-ref", "policyRef":
		return "PolicyRef"
	case "control-ids", "controlIds":
		return "ControlIds"
	}

	// handle special characters
	name = strings.ReplaceAll(name, "$", "Dollar")
	name = strings.ReplaceAll(name, "-", "_") // convert hyphens to underscores first
	name = strings.ReplaceAll(name, ".", "Dot")

	// special case for github/url
	name = strings.ReplaceAll(strings.ToLower(name), "github", "GitHub")
	name = strings.ReplaceAll(strings.ToLower(name), "url", "URL")

	// split on underscores and other non-alphanumeric chars
	words := strings.FieldsFunc(name, func(r rune) bool {
		return !strings.ContainsRune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", r)
	})

	// title case each word, preserving special cases
	var result strings.Builder
	for _, word := range words {
		lword := strings.ToLower(word)
		switch {
		case strings.Contains(lword, "github"):
			result.WriteString("GitHub")
		case strings.Contains(lword, "url"):
			result.WriteString("URL")
		default:
			result.WriteString(caser.String(word))
		}
	}

	return result.String()
}

// generateStructFields recursively generates Go struct fields from JSON schema properties
func generateStructFields(props map[string]interface{}, indent string) (string, error) {
	var fields []string
	for name, prop := range props {
		propMap, ok := prop.(map[string]interface{})
		if !ok {
			return "", fmt.Errorf("property %s is not an object", name)
		}

		propType, ok := propMap["type"].(string)
		if !ok {
			return "", fmt.Errorf("property %s has no type", name)
		}

		fieldName := sanitizeFieldName(name)
		jsonTag := fmt.Sprintf(`json:"%s"`, name)

		var fieldType string
		switch propType {
		case "string":
			fieldType = "string"
		case "integer", "number":
			fieldType = "int"
		case "boolean":
			fieldType = "bool"
		case "array":
			items, ok := propMap["items"].(map[string]interface{})
			if !ok {
				return "", fmt.Errorf("array property %s has no items", name)
			}
			itemType, ok := items["type"].(string)
			if !ok {
				return "", fmt.Errorf("array property %s items has no type", name)
			}
			switch itemType {
			case "string":
				fieldType = "[]string"
			case "integer", "number":
				fieldType = "[]int"
			case "object":
				itemFields, err := generateStructFields(items["properties"].(map[string]interface{}), indent+"    ")
				if err != nil {
					return "", err
				}
				fieldType = "[]struct{\n" + itemFields + indent + "}"
			default:
				return "", fmt.Errorf("unsupported array item type %s", itemType)
			}
		case "object":
			if name == "permissions" {
				fieldType = "map[string]string"
			} else if name == "inputs" {
				fieldType = "map[string]interface{}"
			} else {
				subProps, ok := propMap["properties"].(map[string]interface{})
				if !ok {
					return "", fmt.Errorf("object property %s has no properties", name)
				}
				subFields, err := generateStructFields(subProps, indent+"    ")
				if err != nil {
					return "", err
				}
				fieldType = "struct{\n" + subFields + indent + "}"
			}
		default:
			return "", fmt.Errorf("unsupported type %s", propType)
		}

		fields = append(fields, fmt.Sprintf("%s%s %s `%s`", indent, fieldName, fieldType, jsonTag))
	}

	return strings.Join(fields, "\n") + "\n", nil
}

func generateSchema(name string, schema map[string]interface{}) (string, error) {
	// handle array type at root level (for bundle schema)
	if t, ok := schema["type"].(string); ok && t == "array" {
		if items, ok := schema["items"].(map[string]interface{}); ok {
			itemProps, ok := items["properties"].(map[string]interface{})
			if !ok {
				return "", fmt.Errorf("array items has no properties")
			}
			fields, err := generateStructFields(itemProps, "    ")
			if err != nil {
				return "", err
			}
			return fmt.Sprintf(`// Code generated by generate.go. DO NOT EDIT.

package schema

// %s represents the %s schema
type %s []struct {
%s}
`, name, name, name, fields), nil
		}
		return "", fmt.Errorf("array schema has no items")
	}

	// handle object type
	props, ok := schema["properties"].(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("schema has no properties")
	}

	var fields []string
	for propName, prop := range props {
		propMap, ok := prop.(map[string]interface{})
		if !ok {
			continue
		}

		fieldName := sanitizeFieldName(propName)
		jsonTag := fmt.Sprintf(`json:"%s"`, propName)

		var fieldType string
		switch propMap["type"].(string) {
		case "string":
			fieldType = "string"
		case "integer", "number":
			fieldType = "int"
		case "array":
			if propName == "subject" {
				fieldType = "[]Subject"
			} else {
				items := propMap["items"].(map[string]interface{})
				itemType := items["type"].(string)
				if itemType == "string" {
					fieldType = "[]string"
				} else if itemType == "integer" || itemType == "number" {
					fieldType = "[]int"
				} else if itemType == "object" {
					itemFields, err := generateStructFields(items["properties"].(map[string]interface{}), "    ")
					if err != nil {
						return "", err
					}
					fieldType = "[]struct{\n" + itemFields + "    }"
				} else {
					return "", fmt.Errorf("unsupported array item type %s", itemType)
				}
			}
		case "object":
			if propName == "predicate" {
				predicateProps := propMap["properties"].(map[string]interface{})
				subFields, err := generateStructFields(predicateProps, "    ")
				if err != nil {
					return "", err
				}
				fieldType = "struct{\n" + subFields + "}"
			} else {
				subProps, ok := propMap["properties"].(map[string]interface{})
				if !ok {
					return "", fmt.Errorf("object property %s has no properties", propName)
				}
				subFields, err := generateStructFields(subProps, "    ")
				if err != nil {
					return "", err
				}
				fieldType = "struct{\n" + subFields + "    }"
			}
		default:
			return "", fmt.Errorf("unsupported type %s", propMap["type"].(string))
		}

		fields = append(fields, fmt.Sprintf("    %s %s `%s`", fieldName, fieldType, jsonTag))
	}

	// add default predicate fields if not present
	hasPredicateType := false
	hasPredicate := false
	for _, field := range fields {
		if strings.Contains(field, "PredicateType") {
			hasPredicateType = true
		}
		if strings.Contains(field, "Predicate struct") {
			hasPredicate = true
		}
	}

	if !hasPredicateType || !hasPredicate {
		schemaType := "metadata"
		if strings.Contains(strings.ToLower(name), "dependencyscan") {
			schemaType = "depscan"
		}
		fields = append(fields, defaultPredicateFields[schemaType]...)
	}

	return fmt.Sprintf(`// Code generated by generate.go. DO NOT EDIT.

package schema

// %s represents the %s schema
type %s struct {
%s
}
`, name, name, name, strings.Join(fields, "\n")), nil
}

func createGitHubClient() *github.Client {
	// check for GitHub token in environment
	token := os.Getenv("GITHUB_TOKEN")
	if token == "" {
		fmt.Println("Warning: No GITHUB_TOKEN found, using unauthenticated client")
		return github.NewClient(nil)
	}

	return github.NewClient(nil).WithAuthToken(token)
}

func getVersion(ctx context.Context, client *github.Client) (string, error) {
	// check for version in environment
	if version := os.Getenv("POLICY_VERSION"); version != "" {
		// validate the tag exists
		_, _, err := client.Git.GetRef(ctx, owner, repo, "tags/"+version)
		if err == nil {
			return version, nil
		}
		return "", fmt.Errorf("specified version %s not found: %v", version, err)
	}

	// get latest release
	release, _, err := client.Repositories.GetLatestRelease(ctx, owner, repo)
	if err != nil {
		return "", fmt.Errorf("failed to get latest release: %v", err)
	}
	return release.GetTagName(), nil
}

func main() {
	// ensure target directory exists
	if err := os.MkdirAll(targetDir, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "error creating schema dir: %v\n", err)
		os.Exit(1)
	}

	// clean up any existing generated files
	existingFiles, err := filepath.Glob(filepath.Join(targetDir, "*.schema.*"))
	if err == nil {
		for _, f := range existingFiles {
			os.Remove(f)
		}
	}
	os.Remove(filepath.Join(targetDir, "common.go"))

	// write the common types file
	commonTypesPath := filepath.Join(targetDir, "common.go")
	commonTypesContent := []byte("// Code generated by generate.go. DO NOT EDIT.\n\npackage schema" + commonStructs)
	if err := os.WriteFile(commonTypesPath, commonTypesContent, 0600); err != nil {
		fmt.Fprintf(os.Stderr, "error writing common types: %v\n", err)
		os.Exit(1)
	}

	// create github client
	client := createGitHubClient()
	ctx := context.Background()

	// get version to use
	version, err := getVersion(ctx, client)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error determining version: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Using policy version: %s\n", version)

	// get ref for the version
	ref, _, err := client.Git.GetRef(ctx, owner, repo, "tags/"+version)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error getting ref for version %s: %v\n", version, err)
		os.Exit(1)
	}

	// get tree for the ref
	tree, _, err := client.Git.GetTree(ctx, owner, repo, ref.GetObject().GetSHA(), true)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error getting tree: %v\n", err)
		os.Exit(1)
	}

	// process schema files
	for _, entry := range tree.Entries {
		if !strings.HasPrefix(entry.GetPath(), schemasPath) || !strings.HasSuffix(entry.GetPath(), ".json") {
			continue
		}

		// get file content
		content, _, _, err := client.Repositories.GetContents(ctx, owner, repo, entry.GetPath(), &github.RepositoryContentGetOptions{
			Ref: version,
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "error getting content for %s: %v\n", entry.GetPath(), err)
			continue
		}

		// decode content
		decoded, err := base64.StdEncoding.DecodeString(*content.Content)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error decoding content for %s: %v\n", entry.GetPath(), err)
			continue
		}

		// get relative path and create target path
		relPath := strings.TrimPrefix(entry.GetPath(), schemasPath)
		targetPath := filepath.Join(targetDir, relPath)

		// rename -schema to .schema in filenames
		targetPath = strings.Replace(targetPath, "-schema.json", ".schema.json", 1)
		// special case for dependency-scan schema naming
		targetPath = strings.Replace(targetPath, "dependency-vulnerability.schema.json", "dependency-scan.schema.json", 1)

		// create target directory structure
		if err := os.MkdirAll(filepath.Dir(targetPath), 0755); err != nil {
			fmt.Fprintf(os.Stderr, "error creating directory for %s: %v\n", targetPath, err)
			continue
		}

		// write schema file
		if err := os.WriteFile(targetPath, decoded, 0600); err != nil {
			fmt.Fprintf(os.Stderr, "error writing schema file %s: %v\n", targetPath, err)
			continue
		}

		// parse schema
		var schema map[string]interface{}
		if err := json.Unmarshal(decoded, &schema); err != nil {
			fmt.Fprintf(os.Stderr, "failed to parse schema %s: %v\n", targetPath, err)
			continue
		}

		// generate struct name from filename
		baseName := filepath.Base(targetPath)
		structName := strings.TrimSuffix(baseName, ".schema.json")
		caser := cases.Title(language.English)
		structName = caser.String(strings.ReplaceAll(structName, "-", ""))

		// special case for dependency scan
		if strings.Contains(entry.GetPath(), "dependency-vulnerability") {
			structName = "Dependencyscan"
		}

		// special case for artifact fields
		if strings.Contains(string(decoded), "\"artifact\"") {
			if props, ok := schema["properties"].(map[string]interface{}); ok {
				if predicate, ok := props["predicate"].(map[string]interface{}); ok {
					if predicateProps, ok := predicate["properties"].(map[string]interface{}); ok {
						if artifact, ok := predicateProps["artifact"].(map[string]interface{}); ok {
							if artifactProps, ok := artifact["properties"].(map[string]interface{}); ok {
								artifactProps["registry"] = map[string]interface{}{
									"type": "string",
								}
								artifactProps["fullName"] = map[string]interface{}{
									"type": "string",
								}
								artifactProps["digest"] = map[string]interface{}{
									"type": "string",
								}
							}
						}
					}
				}
			}
		}

		// generate struct definition
		structDef, err := generateSchema(structName, schema)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to generate schema for %s: %v\n", targetPath, err)
			continue
		}

		// write go file
		goFilePath := strings.TrimSuffix(targetPath, ".json") + ".go"
		if err := os.WriteFile(goFilePath, []byte(structDef), 0600); err != nil {
			fmt.Fprintf(os.Stderr, "failed to write go file %s: %v\n", goFilePath, err)
			continue
		}
	}
}
