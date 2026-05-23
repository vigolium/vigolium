// Package http provides the Requester — Vigolium's HTTP client used by scanner
// modules to send probes. It layers a middleware pipeline, per-host rate
// limiting and error tracking, retries, redirect control, and a response-chain
// abstraction that owns response-body lifecycle over the standard library
// transport. Requests can be bound to a context (WithContext / ExecuteContext)
// so in-flight calls abort on scan shutdown or phase deadline.
package http
