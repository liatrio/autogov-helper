package errors

import "fmt"

// WrapError wraps an error with a descriptive action
func WrapError(action string, err error) error {
	return fmt.Errorf("failed to %s: %w", action, err)
}

// WrapErrorf wraps an error with a formatted message
func WrapErrorf(format string, err error, args ...interface{}) error {
	return fmt.Errorf(format+": %w", append(args, err)...)
}

// NewError creates a new error with a descriptive action
func NewError(action string) error {
	return fmt.Errorf("failed to %s", action)
}
