package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

const (
	policyRepo    = "https://github.com/liatrio/demo-gh-autogov-policy-library.git"
	schemasSubdir = "schemas/"
	targetDir     = "../generated" // generate in a dedicated folder
	branch        = "main"
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
	result := ""
	for i, word := range words {
		lword := strings.ToLower(word)
		switch {
		case strings.Contains(lword, "github"):
			result += "GitHub"
		case strings.Contains(lword, "url"):
			result += "URL"
		default:
			result += caser.String(word)
		}
		if i < len(words)-1 {
			result += ""
		}
	}

	return result
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

package generated

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

	// add predicateType field if not present
	if _, ok := props["predicateType"]; !ok {
		fields = append(fields, "    PredicateType string `json:\"predicateType\"`")
	}

	// add predicate field if not present
	if _, ok := props["predicate"]; !ok {
		fields = append(fields, "    Predicate struct{\n        Scanner struct{\n            URI string `json:\"uri\"`\n            Version string `json:\"version\"`\n            DB struct{\n                Name string `json:\"name\"`\n                Version string `json:\"version\"`\n                LastUpdated string `json:\"lastUpdated\"`\n            } `json:\"db\"`\n            Result []struct{\n                ID string `json:\"id\"`\n                Severity struct{\n                    Method string `json:\"method\"`\n                    Score string `json:\"score\"`\n                } `json:\"severity\"`\n            } `json:\"result\"`\n        } `json:\"scanner\"`\n    } `json:\"predicate\"`")
	}

	return fmt.Sprintf(`// Code generated by generate.go. DO NOT EDIT.

package generated

// %s represents the %s schema
type %s struct {
%s
}
`, name, name, name, strings.Join(fields, "\n")), nil
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

	// clone specific branch
	if err := exec.Command("git", "clone", "--branch", branch, "--depth=1", policyRepo, "tmp_policy_repo").Run(); err != nil {
		fmt.Fprintf(os.Stderr, "error cloning policy repo: %v\n", err)
		os.Exit(1)
	}
	defer os.RemoveAll("tmp_policy_repo")

	// write the common types file
	commonTypesPath := filepath.Join(targetDir, "common.go")
	commonTypesContent := []byte("// Code generated by generate.go. DO NOT EDIT.\n\npackage generated" + commonStructs)
	if err := os.WriteFile(commonTypesPath, commonTypesContent, 0600); err != nil {
		fmt.Fprintf(os.Stderr, "error writing common types: %v\n", err)
		os.Exit(1)
	}

	// copy schema files and generate go structs
	sourceDir := filepath.Join("tmp_policy_repo", schemasSubdir)
	fmt.Printf("copying schemas from: %s\n", sourceDir)
	if err := filepath.Walk(sourceDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.IsDir() && filepath.Ext(path) == ".json" {
			relPath, err := filepath.Rel(sourceDir, path)
			if err != nil {
				return fmt.Errorf("failed to get relative path: %w", err)
			}
			targetPath := filepath.Join(targetDir, relPath)

			// rename -schema to .schema in filenames
			targetPath = strings.Replace(targetPath, "-schema.json", ".schema.json", 1)
			// special case for dependency-scan schema naming
			targetPath = strings.Replace(targetPath, "dependency-vulnerability.schema.json", "dependency-scan.schema.json", 1)

			// create target directory structure
			if err := os.MkdirAll(filepath.Dir(targetPath), 0755); err != nil {
				return err
			}

			// read and parse schema
			input, err := os.ReadFile(path)
			if err != nil {
				return err
			}

			// copy schema file
			if err := os.WriteFile(targetPath, input, 0600); err != nil {
				return err
			}

			// parse schema
			var schema map[string]interface{}
			if err := json.Unmarshal(input, &schema); err != nil {
				return fmt.Errorf("failed to parse schema: %w", err)
			}

			// generate struct name from filename
			baseName := filepath.Base(targetPath)
			structName := strings.TrimSuffix(baseName, ".schema.json")
			caser := cases.Title(language.English)
			structName = caser.String(strings.ReplaceAll(structName, "-", ""))

			// special case for dependency scan
			if strings.Contains(path, "dependency-vulnerability") {
				structName = "Dependencyscan"
			}

			// special case for artifact fields
			if strings.Contains(string(input), "\"artifact\"") {
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
				return fmt.Errorf("failed to generate schema: %w", err)
			}

			// write go file
			goFilePath := strings.TrimSuffix(targetPath, ".json") + ".go"
			if err := os.WriteFile(goFilePath, []byte(structDef), 0600); err != nil {
				return fmt.Errorf("failed to write go file: %w", err)
			}
		}
		return nil
	}); err != nil {
		fmt.Fprintf(os.Stderr, "error processing schema files: %v\n", err)
		os.Exit(1)
	}
}
