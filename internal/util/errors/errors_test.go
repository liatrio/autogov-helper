package errors

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestWrapError(t *testing.T) {
	originalErr := errors.New("original error")
	wrappedErr := WrapError("do something", originalErr)

	assert.ErrorIs(t, wrappedErr, originalErr)
	assert.Contains(t, wrappedErr.Error(), "failed to do something")
	assert.Contains(t, wrappedErr.Error(), originalErr.Error())
}

func TestWrapErrorf(t *testing.T) {
	originalErr := errors.New("original error")
	wrappedErr := WrapErrorf("custom format %s", originalErr, "value")

	assert.ErrorIs(t, wrappedErr, originalErr)
	assert.Contains(t, wrappedErr.Error(), "custom format value")
	assert.Contains(t, wrappedErr.Error(), originalErr.Error())
}

func TestNewError(t *testing.T) {
	err := NewError("do something")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to do something")
}
