package sessionlog

// The structs below mirror the Pi session-log JSONL schema. Field tags and
// ordering are chosen to match what a Pi viewer expects; see the package doc
// for the fidelity caveats (signatures / cost split / responseId are omitted).

// sessionEvt is the standalone header line. It has no parentId — the parent
// chain starts at the following model_change with a null parent.
type sessionEvt struct {
	Type      string `json:"type"`
	Version   int    `json:"version"`
	ID        string `json:"id"`
	Timestamp string `json:"timestamp"`
	Cwd       string `json:"cwd"`
}

type modelChangeEvt struct {
	Type      string  `json:"type"`
	ID        string  `json:"id"`
	ParentID  *string `json:"parentId"`
	Timestamp string  `json:"timestamp"`
	Provider  string  `json:"provider"`
	ModelID   string  `json:"modelId"`
}

type thinkingLevelEvt struct {
	Type          string  `json:"type"`
	ID            string  `json:"id"`
	ParentID      *string `json:"parentId"`
	Timestamp     string  `json:"timestamp"`
	ThinkingLevel string  `json:"thinkingLevel"`
}

// messageEvt is the top-level envelope for user / assistant / toolResult
// messages. Message holds one of userMsg / assistantMsg / toolResultMsg.
type messageEvt struct {
	Type      string  `json:"type"`
	ID        string  `json:"id"`
	ParentID  *string `json:"parentId"`
	Timestamp string  `json:"timestamp"`
	Message   any     `json:"message"`
}

// errorEvt records a terminal engine error. Not part of the Pi schema; Pi
// viewers ignore unknown event types, and it is valuable when debugging a run
// that died mid-stream.
type errorEvt struct {
	Type      string  `json:"type"`
	ID        string  `json:"id"`
	ParentID  *string `json:"parentId"`
	Timestamp string  `json:"timestamp"`
	Error     string  `json:"error"`
}

// section_start / section_end / section_interrupted mark the durable-autopilot
// bounded-section boundaries (an engine Reset() + reconstructed-brief cycle).
// Not part of the Pi schema — like errorEvt, they follow the additive-event
// pattern (Pi viewers ignore unknown types) so a durable-autopilot transcript
// stays readable in a Pi viewer while carrying the extra rotation structure.
// Operator sections are strictly serial (one goroutine), so no per-section
// sequence tag or concurrency handling is needed.
type sectionStartEvt struct {
	Type      string  `json:"type"`
	ID        string  `json:"id"`
	ParentID  *string `json:"parentId"`
	Timestamp string  `json:"timestamp"`
	SectionID string  `json:"sectionId"`
	Seq       int     `json:"seq"`
	Kind      string  `json:"kind,omitempty"`
	Task      string  `json:"task,omitempty"`
}

type sectionEndEvt struct {
	Type           string  `json:"type"`
	ID             string  `json:"id"`
	ParentID       *string `json:"parentId"`
	Timestamp      string  `json:"timestamp"`
	SectionID      string  `json:"sectionId"`
	Status         string  `json:"status"`
	RotationReason string  `json:"rotationReason,omitempty"`
	Summary        string  `json:"summary,omitempty"`
	DurationMs     int64   `json:"durationMs"`
}

type sectionInterruptedEvt struct {
	Type      string  `json:"type"`
	ID        string  `json:"id"`
	ParentID  *string `json:"parentId"`
	Timestamp string  `json:"timestamp"`
	SectionID string  `json:"sectionId"`
}

// --- message bodies ---

type userMsg struct {
	Role      string `json:"role"`
	Content   []any  `json:"content"`
	Timestamp int64  `json:"timestamp"`
}

type assistantMsg struct {
	Role       string    `json:"role"`
	Content    []any     `json:"content"`
	Provider   string    `json:"provider,omitempty"`
	Model      string    `json:"model,omitempty"`
	Usage      *usageObj `json:"usage,omitempty"`
	StopReason string    `json:"stopReason,omitempty"`
	Timestamp  int64     `json:"timestamp"`
}

type toolResultMsg struct {
	Role       string `json:"role"`
	ToolCallID string `json:"toolCallId"`
	ToolName   string `json:"toolName"`
	Content    []any  `json:"content"`
	IsError    bool   `json:"isError"`
	Timestamp  int64  `json:"timestamp"`
}

// --- content parts ---

type textPart struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type thinkingPart struct {
	Type     string `json:"type"`
	Thinking string `json:"thinking"`
}

type toolCallPart struct {
	Type      string         `json:"type"`
	ID        string         `json:"id"`
	Name      string         `json:"name"`
	Arguments map[string]any `json:"arguments"`
}

// --- usage ---

type usageObj struct {
	Input       int     `json:"input"`
	Output      int     `json:"output"`
	CacheRead   int     `json:"cacheRead"`
	CacheWrite  int     `json:"cacheWrite"`
	TotalTokens int     `json:"totalTokens"`
	Cost        costObj `json:"cost"`
}

type costObj struct {
	Input      float64 `json:"input"`
	Output     float64 `json:"output"`
	CacheRead  float64 `json:"cacheRead"`
	CacheWrite float64 `json:"cacheWrite"`
	Total      float64 `json:"total"`
}
