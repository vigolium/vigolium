package pilot

import (
	"context"
	"fmt"
	"strings"

	"github.com/vigolium/vigolium/pkg/spitolas/internal/action"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/browser"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/form"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/state"
)

// maxTextLen is the maximum length for element text in serialization.
const maxTextLen = 60

// SerializePage extracts the full page state and serializes it to text
// that the ACP agent receives after every action.
func (bc *PilotCrawler) SerializePage(ctx context.Context, page *browser.Page, curState *state.State) (string, error) {
	var b strings.Builder

	pageURL, _ := page.URL()
	title, _ := page.Title()

	stateID := ""
	depth := 0
	if curState != nil {
		stateID = curState.Name
		depth = curState.Depth
	}

	// === PAGE STATE ===
	fmt.Fprintf(&b, "=== PAGE STATE ===\n")
	fmt.Fprintf(&b, "URL: %s\n", pageURL)
	if stateID != "" {
		fmt.Fprintf(&b, "State ID: %s (depth: %d)\n", stateID, depth)
	}
	fmt.Fprintf(&b, "Title: %s\n", title)

	// === HEADINGS ===
	headings := bc.extractHeadings(page)
	if headings != "" {
		fmt.Fprintf(&b, "\n=== HEADINGS ===\n%s\n", headings)
	}

	// === NAVIGATION ===
	nav := bc.extractNavigation(page)
	if nav != "" {
		fmt.Fprintf(&b, "\n=== NAVIGATION ===\n%s\n", nav)
	}

	// === CLICKABLE ELEMENTS ===
	elements, _ := bc.extractor.Extract(ctx, page)
	fmt.Fprintf(&b, "\n=== CLICKABLE ELEMENTS (%d found) ===\n", len(elements))
	for i, elem := range elements {
		bc.serializeElement(&b, i, elem)
	}

	// === FORMS & INPUTS ===
	forms, orphanInputs, _ := bc.formHandler.DetectAll(page)
	if len(forms) > 0 {
		fmt.Fprintf(&b, "\n=== FORMS (%d found) ===\n", len(forms))
		for i, f := range forms {
			bc.serializeForm(&b, i, f)
		}
	}
	if len(orphanInputs) > 0 {
		var visible []*form.DetectedInput
		for _, inp := range orphanInputs {
			if inp.Hidden {
				continue
			}
			visible = append(visible, inp)
		}
		if len(visible) > 0 {
			fmt.Fprintf(&b, "\n=== ORPHAN INPUTS (%d found, not inside any <form>) ===\n", len(visible))
			for i, inp := range visible {
				bc.serializeOrphanInput(&b, i, inp)
			}
		}
	}

	// === FEEDBACK ===
	fmt.Fprintf(&b, "\n=== FEEDBACK ===\n")
	feedback := bc.extractFeedback(page)
	if feedback != "" {
		b.WriteString(feedback)
		b.WriteByte('\n')
	} else {
		b.WriteString("[none]\n")
	}

	// === CHECKPOINT COMPASS ===
	b.WriteByte('\n')
	b.WriteString(bc.renderCompass())

	return b.String(), nil
}

// serializeElement writes a single clickable element line.
func (bc *PilotCrawler) serializeElement(b *strings.Builder, idx int, elem *action.CandidateElement) {
	text := truncate(elem.Text, maxTextLen)
	xpath := ""
	if elem.Identification != nil {
		xpath = elem.Identification.Value
	}

	reason, blacklisted := bc.blacklist.IsBlacklisted(xpath)

	fmt.Fprintf(b, "[%d] <%s>", idx, elem.TagName)
	if text != "" {
		fmt.Fprintf(b, " %q", text)
	}
	if elem.Href != "" {
		fmt.Fprintf(b, " href=%s", elem.Href)
	}
	if xpath != "" {
		fmt.Fprintf(b, " xpath=%s", xpath)
	}
	if blacklisted {
		fmt.Fprintf(b, " [BLACKLISTED: %s]", reason)
	}
	b.WriteByte('\n')
}

// serializeForm writes a form with its fields and usage hints.
func (bc *PilotCrawler) serializeForm(b *strings.Builder, idx int, f *form.Form) {
	fmt.Fprintf(b, "Form #%d: action=%s method=%s xpath=%s\n", idx, f.Action, f.Method, f.XPath)
	for _, input := range f.Inputs {
		serializeInput(b, input, false)
	}
}

// serializeOrphanInput writes a single orphan input with usage hints.
func (bc *PilotCrawler) serializeOrphanInput(b *strings.Builder, _ int, input *form.DetectedInput) {
	serializeInput(b, input, true)
}

// serializeInput writes a single form input with attributes and usage hints.
func serializeInput(b *strings.Builder, input *form.DetectedInput, showSubmitHint bool) {
	if input.FormInput == nil {
		return
	}
	typeName := string(input.Type)
	xpath := input.XPath
	if xpath == "" && input.Identification != nil {
		xpath = input.Identification.Value
	}

	fmt.Fprintf(b, "  - [%s]", typeName)
	if input.Name != "" {
		fmt.Fprintf(b, " name=%q", input.Name)
	}
	if input.Placeholder != "" {
		fmt.Fprintf(b, " placeholder=%q", input.Placeholder)
	}
	if input.Label != "" {
		fmt.Fprintf(b, " label=%q", input.Label)
	}
	if input.Required {
		b.WriteString(" required")
	}
	if input.Pattern != "" {
		fmt.Fprintf(b, " pattern=%q", input.Pattern)
	}
	b.WriteByte('\n')
	if xpath != "" {
		fmt.Fprintf(b, "    xpath=%s\n", xpath)
		switch input.Type {
		case action.InputTypeSelect:
			fmt.Fprintf(b, "    → Use: select_option(%q, \"value\")\n", xpath)
		case action.InputTypeCheckbox, action.InputTypeRadio:
			fmt.Fprintf(b, "    → Use: check(%q, true)\n", xpath)
		default:
			fmt.Fprintf(b, "    → Use: type_text(%q, \"value\")\n", xpath)
		}
	}
	if showSubmitHint && input.SubmitXPath != "" {
		fmt.Fprintf(b, "    nearby_button: xpath=%s  ← click() to submit\n", input.SubmitXPath)
	}
}

// extractHeadings extracts h1-h6 text via JavaScript.
func (bc *PilotCrawler) extractHeadings(page *browser.Page) string {
	result, err := page.Eval(`(() => {
		const headings = [];
		for (let i = 1; i <= 6; i++) {
			for (const h of document.querySelectorAll('h' + i)) {
				let text = h.textContent.trim();
				if (!text) continue;
				if (text.length > 80) text = text.substring(0, 80) + '...';
				headings.push('h' + i + ': ' + text);
				if (headings.length >= 20) break;
			}
			if (headings.length >= 20) break;
		}
		return headings.join('\n');
	})()`)
	if err != nil {
		return ""
	}
	if s, ok := result.(string); ok {
		return s
	}
	return ""
}

// extractNavigation extracts navigation text from nav/header elements.
func (bc *PilotCrawler) extractNavigation(page *browser.Page) string {
	result, err := page.Eval(`(() => {
		const navEls = document.querySelectorAll('nav, [role=navigation], header nav');
		const parts = [];
		for (const el of navEls) {
			const links = [];
			for (const a of el.querySelectorAll('a, button')) {
				const text = a.textContent.trim();
				if (text && text.length < 50) links.push(text);
			}
			if (links.length > 0) parts.push('<nav> ' + links.join(' | '));
		}
		return parts.join('\n');
	})()`)
	if err != nil {
		return ""
	}
	if s, ok := result.(string); ok {
		return s
	}
	return ""
}

// extractFeedback extracts error/success/feedback messages from the page.
func (bc *PilotCrawler) extractFeedback(page *browser.Page) string {
	result, err := page.Eval(`(() => {
		const selectors = [
			'.error', '.alert', '.success', '.warning',
			'[role=alert]', '.toast', '.notification',
			'.validation-error', '.form-error', '.field-error',
			'.help-block.error', '.invalid-feedback'
		];
		const messages = [];
		for (const sel of selectors) {
			for (const el of document.querySelectorAll(sel)) {
				const text = el.textContent.trim();
				if (text && text.length < 200) {
					messages.push(sel + ': ' + text);
				}
			}
		}
		return messages.join('\n');
	})()`)
	if err != nil {
		return ""
	}
	if s, ok := result.(string); ok {
		return s
	}
	return ""
}

// renderCompass renders the Checkpoint Compass appended to every tool result.
func (bc *PilotCrawler) renderCompass() string {
	var b strings.Builder

	discovered, active, completed, blocked := bc.checkpoints.Stats()
	abandoned := bc.countAbandoned()
	total := discovered + active + completed + blocked + abandoned

	stateCount := 0
	if bc.graph != nil {
		stateCount = bc.graph.StateCount()
	}

	activeCP := bc.checkpoints.Active()
	activeName := ""
	if activeCP != nil {
		activeName = activeCP.Name
	}

	b.WriteString("=== CHECKPOINT COMPASS ===\n")
	fmt.Fprintf(&b, "States: %d discovered", stateCount)
	if activeName != "" {
		fmt.Fprintf(&b, " | Active: %s (exploring)", activeName)
	}
	b.WriteByte('\n')

	if total == 0 {
		b.WriteString("\nNo checkpoints yet. Explore the app and use create_checkpoint() to mark features.\n")
		return b.String()
	}

	pendingLabel := fmt.Sprintf("%d pending", discovered)
	if abandoned > 0 {
		pendingLabel += fmt.Sprintf(" / %d abandoned", abandoned)
	}
	fmt.Fprintf(&b, "\nCHECKPOINTS (%s / %d completed / %d total):\n", pendingLabel, completed, total)

	for _, cp := range bc.checkpoints.All() {
		status := string(cp.Status)
		if cp.Status == CheckpointActive && cp.ActionCount > StallThreshold {
			status = "STALLED"
		}

		fmt.Fprintf(&b, "  [%s] %s (%s)", strings.ToUpper(status), cp.Name, cp.ID)
		if cp.Status == CheckpointActive {
			fmt.Fprintf(&b, " (%d actions)", cp.ActionCount)
		}
		if (cp.Status == CheckpointCompleted || cp.Status == CheckpointAbandoned) && cp.Notes != "" {
			fmt.Fprintf(&b, " — %s", truncate(cp.Notes, 80))
		}
		if cp.ParentID != "" {
			fmt.Fprintf(&b, " [child of %s]", cp.ParentID)
		}
		b.WriteByte('\n')

		if cp.Status == CheckpointDiscovered {
			fmt.Fprintf(&b, " [P:%d]", cp.Priority)
			fmt.Fprintf(&b, "\n    → go_to_checkpoint(%q)\n", cp.ID)
		}
	}

	// Progress
	progressPct := 0
	if total > 0 {
		progressPct = completed * 100 / total
	}
	stalledCount := len(bc.checkpoints.StalledCheckpoints())
	fmt.Fprintf(&b, "\nPROGRESS: %d%% completed (%d/%d). %d stalled.\n", progressPct, completed, total, stalledCount)

	return b.String()
}

// countAbandoned returns the number of abandoned checkpoints.
func (bc *PilotCrawler) countAbandoned() int {
	count := 0
	for _, cp := range bc.checkpoints.All() {
		if cp.Status == CheckpointAbandoned {
			count++
		}
	}
	return count
}

// truncate truncates a string to maxLen, appending "..." if truncated.
func truncate(s string, maxLen int) string {
	s = strings.TrimSpace(s)
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
