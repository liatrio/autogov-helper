package errors

import (
	"fmt"
)

// wrap error with action
func WrapError(action string, err error) error {
	return fmt.Errorf("failed to %s: %w", action, err)
}

// wrap error with formatted msg
func WrapErrorf(format string, err error, args ...interface{}) error {
	return fmt.Errorf("failed to "+format+": %w", append(args, err)...)
}

// create new error with action
func NewError(action string) error {
	return fmt.Errorf("failed to %s", action)
}
