// Package form provides form handling for web crawling.
// Detection metadata is in DetectedInput (Go extension).
package form

// NOTE: FormInput and Form structs are now in detected_input.go
// This file only contains helper functions and legacy compatibility.

// The main types are:
// - form.DetectedInput: Go extension with detection metadata (wraps action.FormInput)
// - form.Form: Contains DetectedInputs with metadata

// For detection with metadata, use form.DetectedInput.
