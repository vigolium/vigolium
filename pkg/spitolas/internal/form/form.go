// Package form provides form handling for web crawling.
// CRAWLJAX PARITY: All form input handling uses action.FormInput directly.
// Detection metadata is in DetectedInput (Go extension).
package form

// NOTE: FormInput and Form structs are now in detected_input.go
// This file only contains helper functions and legacy compatibility.

// The main types are:
// - action.FormInput: Crawljax-parity form input (type, identification, inputValues)
// - form.DetectedInput: Go extension with detection metadata (wraps action.FormInput)
// - form.Form: Contains DetectedInputs with metadata

// For Crawljax parity, use action.FormInput directly.
// For detection with metadata, use form.DetectedInput.
