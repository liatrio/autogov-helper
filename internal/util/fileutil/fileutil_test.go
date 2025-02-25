package fileutil

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCalculateDigest(t *testing.T) {
	// Create a temporary directory for test files
	tmpDir, err := os.MkdirTemp("", "fileutil_test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	// Create test files
	testFile1 := filepath.Join(tmpDir, "test1.txt")
	require.NoError(t, os.WriteFile(testFile1, []byte("test content 1"), 0600))

	testFile2 := filepath.Join(tmpDir, "test2.txt")
	require.NoError(t, os.WriteFile(testFile2, []byte("test content 2"), 0600))

	t.Run("single file", func(t *testing.T) {
		digest, err := CalculateDigest(testFile1)
		require.NoError(t, err)
		assert.NotEmpty(t, digest)
		assert.Contains(t, digest, "sha256:")
	})

	t.Run("directory", func(t *testing.T) {
		digest, err := CalculateDigest(tmpDir)
		require.NoError(t, err)
		assert.NotEmpty(t, digest)
		assert.Contains(t, digest, "sha256:")
	})

	t.Run("non-existent file", func(t *testing.T) {
		_, err := CalculateDigest("non-existent-file")
		assert.Error(t, err)
	})
}

func Test_listFiles(t *testing.T) {
	// Create a temporary directory for test files
	tmpDir, err := os.MkdirTemp("", "fileutil_test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	// Create test files and subdirectories
	files := []string{
		"file1.txt",
		"file2.txt",
		filepath.Join("subdir", "file3.txt"),
	}

	for _, f := range files {
		path := filepath.Join(tmpDir, f)
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0700))
		require.NoError(t, os.WriteFile(path, []byte("test content"), 0600))
	}

	t.Run("list all files", func(t *testing.T) {
		foundFiles, err := listFiles(tmpDir)
		require.NoError(t, err)
		assert.Len(t, foundFiles, len(files))
	})

	t.Run("non-existent directory", func(t *testing.T) {
		_, err := listFiles("non-existent-dir")
		assert.Error(t, err)
	})
}
