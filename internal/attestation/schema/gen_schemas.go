package schema

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const GeneratedDir = "generated"

//go:generate go run gen/generate.go

// schemas stores all loaded schema data
var schemas = make(map[string][]byte)

func init() {
	// ensure generated directory exists
	if err := os.MkdirAll(GeneratedDir, 0755); err != nil {
		panic(fmt.Sprintf("failed to create generated directory: %v", err))
	}

	// load all schemas from disk
	entries, err := os.ReadDir(GeneratedDir)
	if err != nil {
		panic(fmt.Sprintf("failed to read schemas directory: %v", err))
	}

	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".schema.json") {
			name := strings.TrimSuffix(entry.Name(), ".schema.json")
			data, err := loadSchema(name)
			if err != nil {
				panic(fmt.Sprintf("failed to load schema %s: %v", name, err))
			}
			schemas[name] = data
		}
	}
}

func loadSchema(name string) ([]byte, error) {
	// load from disk
	diskPath := filepath.Join(GeneratedDir, name+".schema.json")
	data, err := os.ReadFile(diskPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read schema %s: %w", name, err)
	}

	// validate that the data is valid json
	var js map[string]interface{}
	if err := json.Unmarshal(data, &js); err != nil {
		return nil, fmt.Errorf("schema %s is not valid json: %w", name, err)
	}

	fmt.Printf("successfully loaded schema: %s (%d bytes)\n", name, len(data))
	return data, nil
}

// GetSchema returns the schema data for the given name
func GetSchema(name string) ([]byte, bool) {
	data, ok := schemas[name]
	return data, ok
}

// ListSchemas returns a list of all available schema names
func ListSchemas() []string {
	var names []string
	for name := range schemas {
		names = append(names, name)
	}
	return names
}
