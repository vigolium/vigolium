package apicontract

import "sort"

// ErrorCode is the stable, machine-branchable classification of a failure. It
// is what `error.code` carries in a CLI error document and what the REST API
// reports alongside its HTTP status.
//
// The set is closed: add a new value rather than re-wording an existing one,
// because consumers branch on these strings. Every value must also be listed in
// knownErrorCodes below (a test enforces it), so `vigolium schema` and the REST
// docs can enumerate the vocabulary instead of copying it.
type ErrorCode string

// Generic outcomes.
const (
	// CodeFailed is the fallback when nothing more specific is known.
	CodeFailed ErrorCode = "failed"
	// CodeUsageError: the command line was wrong (exit 2). Nothing ran.
	CodeUsageError ErrorCode = "usage_error"
	// CodeGateTripped: the --fail-on severity gate fired (exit 4).
	CodeGateTripped ErrorCode = "gate_tripped"
	// CodeConfigInvalid: a configuration file or value failed validation.
	CodeConfigInvalid ErrorCode = "config_invalid"
	// CodeNotFound: the named object does not exist (generic; prefer a
	// specific *_not_found code when one exists).
	CodeNotFound ErrorCode = "not_found"
)

// Data source (database) states.
const (
	// CodeSourceMissing: the path does not exist.
	CodeSourceMissing ErrorCode = "source_missing"
	// CodeSourceUnreadable: the file exists but is not openable as a database:
	// not SQLite at all, or corrupt.
	CodeSourceUnreadable ErrorCode = "source_unreadable"
	// CodeSourceIncompatible: a valid SQLite file that is not a vigolium store.
	CodeSourceIncompatible ErrorCode = "source_incompatible"
	// CodeDatabaseLocked: the store is held by another writer and the busy
	// retry budget ran out.
	CodeDatabaseLocked ErrorCode = "database_locked"
	// CodeSchemaTooNew: the store was written by a newer vigolium than this
	// binary can read.
	CodeSchemaTooNew ErrorCode = "schema_too_new"
	// CodeSchemaOutdated: the store needs `vigolium db migrate` before use.
	CodeSchemaOutdated ErrorCode = "schema_outdated"
)

// Single-record extraction (traffic body / traffic headers).
const (
	// CodeRecordNotFound: no record carries the given UUID.
	CodeRecordNotFound ErrorCode = "record_not_found"
	// CodeAmbiguousID: a UUID prefix matches more than one record; the message
	// names the candidates.
	CodeAmbiguousID ErrorCode = "ambiguous_id"
	// CodeBodyUnavailable: the record exists, but the requested side was never
	// captured. Distinct from a captured empty body, which succeeds.
	CodeBodyUnavailable ErrorCode = "body_unavailable"
	// CodeBodyDecodeFailed: the body announces an encoding that could not be
	// undone.
	CodeBodyDecodeFailed ErrorCode = "body_decode_failed"
	// CodeBodyIncomplete: only a prefix of the body is available.
	CodeBodyIncomplete ErrorCode = "body_incomplete"
)

// Output and ingestion.
const (
	// CodeExportFailed: the work ran, but a requested artifact was not written.
	CodeExportFailed ErrorCode = "export_failed"
	// CodePDFFailed: a PDF report could not be rendered.
	CodePDFFailed ErrorCode = "pdf_failed"
	// CodeIngestIncomplete: not every record the ingest read reached the store.
	CodeIngestIncomplete ErrorCode = "ingest_incomplete"
	// CodeOutputTooLarge: --max-output-bytes cannot fit even an empty page.
	CodeOutputTooLarge ErrorCode = "output_too_large"
	// CodeUnsupportedInputMode: the input format is recognised but not
	// accepted on this path.
	CodeUnsupportedInputMode ErrorCode = "unsupported_input_mode"
	// CodeInputUnparsed: the input could not be parsed as any accepted format.
	CodeInputUnparsed ErrorCode = "input_unparsed"
)

// Scan admission and lifecycle.
const (
	// CodeNoTargetsInScope: every target was rejected by scope; nothing ran.
	CodeNoTargetsInScope ErrorCode = "no_targets_in_scope"
	// CodeNoTargetsReachable: no admitted target answered; nothing ran.
	CodeNoTargetsReachable ErrorCode = "no_targets_reachable"
	// CodeScanAbandoned: the scan's process stopped heartbeating.
	CodeScanAbandoned ErrorCode = "scan_abandoned"
	// CodeWaitTimeout: `scan wait` gave up before the scan finished.
	CodeWaitTimeout ErrorCode = "wait_timeout"
	// CodeLoginFailed: an authentication flow did not produce a session.
	CodeLoginFailed ErrorCode = "login_failed"
	// CodeNotAuthenticated: a session's credentials did not get it past the
	// login check on a protected URL (`auth check`: login wall, refused, or a
	// response no different from the anonymous one).
	CodeNotAuthenticated ErrorCode = "not_authenticated"
	// CodeProxyAuthRequired: the ingest proxy refused a request without its
	// token.
	CodeProxyAuthRequired ErrorCode = "proxy_auth_required"
)

// Completed-but-incomplete results (exit 5).
const (
	// CodeTimedOut: the run hit its time budget before finishing.
	CodeTimedOut ErrorCode = "timed_out"
	// CodeBudgetExhausted: the run hit a request or token budget.
	CodeBudgetExhausted ErrorCode = "budget_exhausted"
	// CodePartial: the run finished with some of its work failed or skipped.
	CodePartial ErrorCode = "partial"
)

// Agent runtime, health checks and extensions.
const (
	// CodeProviderMissing: no AI provider is configured or detectable.
	CodeProviderMissing ErrorCode = "provider_missing"
	// CodePreflightFailed: an agent preflight check failed before any work.
	CodePreflightFailed ErrorCode = "preflight_failed"
	// CodeProviderUnreachable: the AI provider's endpoint refused the
	// connection or its name did not resolve.
	CodeProviderUnreachable ErrorCode = "provider_unreachable"
	// CodeNotReady: `doctor` found a blocking problem.
	CodeNotReady ErrorCode = "not_ready"
	// CodeLintFailed: a lint (extension, auth session, config) reported errors.
	CodeLintFailed ErrorCode = "lint_failed"
	// CodeExtensionLoadFailed: an explicitly requested extension failed to load.
	CodeExtensionLoadFailed ErrorCode = "extension_load_failed"
)

// Projects.
const (
	// CodeProjectNotFound: no project carries the given UUID or name.
	CodeProjectNotFound ErrorCode = "project_not_found"
	// CodeStorageDisabled: a storage command or --upload ran with cloud storage
	// not enabled in the configuration.
	CodeStorageDisabled ErrorCode = "storage_disabled"
	// CodeInterrupted: a scan stopped on SIGINT/SIGTERM after flushing what it
	// had; the results cover what ran before the signal (exit 5).
	CodeInterrupted ErrorCode = "interrupted"
	// CodeInvalidProjectUUID: the project UUID is not well formed.
	CodeInvalidProjectUUID ErrorCode = "invalid_project_uuid"
)

// REST-only classifications (pkg/server). The CLI reports these situations
// through the codes above; they exist so the REST API can default by status.
const (
	CodeInvalidRequest ErrorCode = "invalid_request"
	CodeUnauthorized   ErrorCode = "unauthorized"
	CodeForbidden      ErrorCode = "forbidden"
	CodeConflict       ErrorCode = "conflict"
	CodeRateLimited    ErrorCode = "rate_limited"
	CodeQueueFull      ErrorCode = "queue_full"
	CodeScanNotFound   ErrorCode = "scan_not_found"
	CodeInternalError  ErrorCode = "internal_error"
	// CodeFindingNotFound: no finding carries the given id in this project.
	CodeFindingNotFound ErrorCode = "finding_not_found"
	// CodeMethodNotAllowed: the route exists but not for this HTTP method.
	CodeMethodNotAllowed ErrorCode = "method_not_allowed"
	// CodePayloadTooLarge: the request body exceeds the route's size limit.
	CodePayloadTooLarge ErrorCode = "payload_too_large"
	// CodeServiceUnavailable: the server cannot take the request right now
	// (shutting down, feature disabled, dependency missing).
	CodeServiceUnavailable ErrorCode = "service_unavailable"
	// CodeDatabaseUnavailable: the request needs the database and it is not
	// configured or not answering.
	CodeDatabaseUnavailable ErrorCode = "database_unavailable"
	// CodeUnsupportedAPIVersion: the client asked for a REST API version this
	// server does not speak.
	CodeUnsupportedAPIVersion ErrorCode = "unsupported_api_version"
)

// knownErrorCodes is the closed set, in declaration order.
var knownErrorCodes = []ErrorCode{
	CodeFailed, CodeUsageError, CodeGateTripped, CodeConfigInvalid, CodeNotFound,
	CodeSourceMissing, CodeSourceUnreadable, CodeSourceIncompatible,
	CodeDatabaseLocked, CodeSchemaTooNew, CodeSchemaOutdated,
	CodeRecordNotFound, CodeAmbiguousID, CodeBodyUnavailable, CodeBodyDecodeFailed, CodeBodyIncomplete,
	CodeExportFailed, CodePDFFailed, CodeIngestIncomplete, CodeOutputTooLarge,
	CodeUnsupportedInputMode, CodeInputUnparsed,
	CodeNoTargetsInScope, CodeNoTargetsReachable, CodeScanAbandoned, CodeWaitTimeout,
	CodeLoginFailed, CodeNotAuthenticated, CodeProxyAuthRequired,
	CodeTimedOut, CodeBudgetExhausted, CodePartial,
	CodeProviderMissing, CodePreflightFailed, CodeNotReady, CodeLintFailed,
	CodeExtensionLoadFailed,
	CodeProjectNotFound, CodeInvalidProjectUUID, CodeStorageDisabled, CodeInterrupted,
	CodeInvalidRequest, CodeUnauthorized, CodeForbidden, CodeConflict,
	CodeRateLimited, CodeQueueFull, CodeScanNotFound, CodeInternalError,
	CodeFindingNotFound, CodeMethodNotAllowed, CodePayloadTooLarge,
	CodeServiceUnavailable, CodeDatabaseUnavailable, CodeUnsupportedAPIVersion,
	CodeProviderUnreachable,
}

var knownErrorCodeSet = func() map[ErrorCode]struct{} {
	m := make(map[ErrorCode]struct{}, len(knownErrorCodes))
	for _, c := range knownErrorCodes {
		m[c] = struct{}{}
	}
	return m
}()

// String returns the wire form of the code.
func (c ErrorCode) String() string { return string(c) }

// Valid reports whether c is a member of the closed set.
func (c ErrorCode) Valid() bool {
	_, ok := knownErrorCodeSet[c]
	return ok
}

// IsIncomplete reports whether c names a completed-but-incomplete result,
// which exits ExitIncomplete rather than ExitError.
func (c ErrorCode) IsIncomplete() bool {
	switch c {
	case CodeTimedOut, CodeBudgetExhausted, CodePartial, CodeInterrupted:
		return true
	}
	return false
}

// ErrorCodes returns every known code, sorted, as a fresh slice.
func ErrorCodes() []ErrorCode {
	out := append([]ErrorCode(nil), knownErrorCodes...)
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
