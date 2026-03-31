package backend

import "errors"

// Sentinel errors for agent backend failures. These enable reliable retry
// classification via errors.Is() instead of fragile string matching.
var (
	ErrSDKQueryFailed  = errors.New("sdk query failed")
	ErrSDKStreamError  = errors.New("sdk stream error")
	ErrSDKOutputFailed = errors.New("sdk output collection failed")

	ErrCodexStartFailed = errors.New("codex SDK start failed")
	ErrCodexInitFailed  = errors.New("codex SDK initialize failed")
	ErrCodexTurnFailed  = errors.New("codex SDK turn failed")

	ErrOpenCodeStartFailed   = errors.New("opencode SDK start failed")
	ErrOpenCodeSessionFailed = errors.New("opencode SDK session creation failed")
	ErrOpenCodePromptFailed  = errors.New("opencode SDK prompt failed")
)
