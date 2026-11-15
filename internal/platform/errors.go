// Package platform defines errors for Linux gateway facilities unavailable on Windows.
package platform

// UnsupportedError identifies a facility that cannot run on Windows.
type UnsupportedError struct{ Feature string }

func (e *UnsupportedError) Error() string { return e.Feature + ": unsupported on windows" }
func Unsupported(feature string) error    { return &UnsupportedError{Feature: feature} }
