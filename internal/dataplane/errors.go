package dataplane

import (
	"context"
	"errors"
)

// TemporaryError is the shared retry contract for transient dataplane
// execution failures. Validation and cancellation errors must not implement it.
type TemporaryError interface {
	error
	Temporary() bool
}

type temporaryError struct {
	cause error
}

func (err temporaryError) Error() string { return err.cause.Error() }
func (err temporaryError) Unwrap() error { return err.cause }
func (temporaryError) Temporary() bool   { return true }

func MarkTemporary(err error) error {
	if err == nil || errors.Is(err, context.Canceled) ||
		errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	var temporary TemporaryError
	if errors.As(err, &temporary) && temporary.Temporary() {
		return err
	}
	return temporaryError{cause: err}
}
