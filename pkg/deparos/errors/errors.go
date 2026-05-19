package errors

import (
	"errors"
	"fmt"
)

// Common sentinel errors.
var (
	ErrInvalidConfig         = errors.New("invalid configuration")
	ErrInvalidURL            = errors.New("invalid URL")
	ErrInvalidDepth          = errors.New("invalid max depth: must be 1-32767")
	ErrInvalidThreadCount    = errors.New("invalid thread count")
	ErrFileNotFound          = errors.New("file not found")
	ErrFileNotReadable       = errors.New("file not readable")
	ErrTaskQueueFull         = errors.New("task queue full")
	ErrFingerprintNotLearned = errors.New("fingerprint not learned")
)

// ErrorType defines categories of errors.
type ErrorType string

const (
	ErrorTypeValidation ErrorType = "validation"
	ErrorTypeHTTP       ErrorType = "http"
	ErrorTypeNotFound   ErrorType = "not_found"
	ErrorTypeInternal   ErrorType = "internal"
)

// Error represents a structured error.
type Error struct {
	Type    ErrorType
	Message string
	Cause   error
	Context map[string]interface{}
}

func (e *Error) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("%s: %s: %v", e.Type, e.Message, e.Cause)
	}
	return fmt.Sprintf("%s: %s", e.Type, e.Message)
}

func (e *Error) Unwrap() error {
	return e.Cause
}

// Constructors.

func Validation(message string, cause error) *Error {
	return &Error{Type: ErrorTypeValidation, Message: message, Cause: cause}
}

func HTTP(message string, cause error) *Error {
	return &Error{Type: ErrorTypeHTTP, Message: message, Cause: cause}
}

func NotFound(message string, cause error) *Error {
	return &Error{Type: ErrorTypeNotFound, Message: message, Cause: cause}
}

func Internal(message string, cause error) *Error {
	return &Error{Type: ErrorTypeInternal, Message: message, Cause: cause}
}
