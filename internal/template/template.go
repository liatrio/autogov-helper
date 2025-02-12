package template

import (
	"bytes"
	"embed"
	"fmt"
	"path/filepath"
	"text/template"
)

//go:embed templates/*.json
var templateFS embed.FS

// renders a template with the given data
func RenderTemplate(templateName string, data interface{}) ([]byte, error) {
	// template content
	templatePath := filepath.Join("templates", templateName+".json")
	tmplContent, err := templateFS.ReadFile(templatePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read template %s: %w", templateName, err)
	}

	// parse template
	tmpl, err := template.New(templateName).Parse(string(tmplContent))
	if err != nil {
		return nil, fmt.Errorf("failed to parse template %s: %w", templateName, err)
	}

	// execute/render template
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return nil, fmt.Errorf("failed to execute template %s: %w", templateName, err)
	}

	return buf.Bytes(), nil
}

// data for metadata templates
type MetadataTemplateData struct {
	Version           string
	Type              string // "container-image" or "blob"
	Digest            string
	Created           string
	Registry          string
	Repository        string
	SubjectName       string
	FullName          string
	Path              string
	RepositoryID      string
	GitHubServerURL   string
	Owner             string
	OwnerID           string
	RunnerOS          string
	RunnerArch        string
	RunnerEnvironment string
	WorkflowRefPath   string
	WorkflowInputs    string
	Branch            string
	Event             string
	RunNumber         string
	RunID             string
	Status            string
	TriggeredBy       string
	StartedAt         string
	CompletedAt       string
	CommitSHA         string
	CommitTimestamp   string
	OrganizationName  string
	PolicyRef         string
	ControlIds        []string
}

// data for depscan templates
type DepscanTemplateData struct {
	ScannerURI     string
	ScannerVersion string
	DBVersion      string
	DBLastUpdate   string
	Results        string
	Created        string // for scan finished timestamp
}
