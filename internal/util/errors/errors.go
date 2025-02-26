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

// create new error
func NewError(msg string) error {
	return fmt.Errorf("failed to %s", msg)
}
