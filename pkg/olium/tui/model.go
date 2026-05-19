// Package tui implements the interactive Bubble Tea front-end for
// `vigolium agent olium`.
//
// It runs in inline/scrollback mode — NOT alt-screen. Completed messages
// are emitted to the terminal's normal output via tea.Printf so the user
// can scroll up, select, and copy like any other CLI. Only the prompt
// input box and the currently-streaming fragment are rendered as the
// live view; as soon as a fragment finalizes (a turn's text completes,
// a tool call finishes), it flushes into scrollback and the live view
// shrinks back to just the input.
package tui

import (
	"context"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"

	"charm.land/bubbles/v2/textarea"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/alecthomas/chroma/v2/quick"

	"github.com/vigolium/vigolium/pkg/olium/engine"
	"github.com/vigolium/vigolium/pkg/olium/skill"
	"github.com/vigolium/vigolium/pkg/terminal"
)

// Config configures the TUI.
type Config struct {
	Engine       *engine.Engine
	ProviderName string
	Model        string
	// Effort is the reasoning effort label (minimal|low|medium|high|xhigh)
	// shown next to the model id in the boot banner. Empty hides it.
	Effort string
	// Version is the vigolium build version, shown after "Olium agent" in
	// the boot banner. Empty hides the parenthetical.
	Version string
	// Skills is consulted when the user types `/skill:name args`. The
	// matching skill's body is expanded inline into the submitted prompt.
	// nil → /skill: commands are rejected with an error.
	Skills *skill.Registry
	// InitialPrompt, when non-empty, is auto-sent as the first message on
	// startup — same as if the user typed it and pressed enter.
	InitialPrompt string
	// quit is wired by Run() to the external context cancel passed via
	// tea.WithContext. When called, Bubble Tea's shutdown flips to "killed"
	// mode, which skips its 500 ms waitForReadLoop timeout on the TTY input
	// reader — otherwise ctrl+C takes up to that long to return.
	quit func()
}

type eventMsg engine.Event
type runClosedMsg struct{}
type sendMsg struct{ prompt string }

type turnState int

const (
	stateIdle turnState = iota
	stateStreaming
)

// --- Palette (xterm 256) ---
var (
	colorAccent    = lipgloss.Color("86") // cyan — brand, borders, hints
	colorAccentDim = lipgloss.Color("73")
	colorVigolium  = lipgloss.Color("46") // hi green — the assistant label
	colorUser      = lipgloss.Color("114")
	colorText      = lipgloss.Color("252")
	colorMuted     = lipgloss.Color("245")
	colorDim       = lipgloss.Color("240")
	colorWarn      = lipgloss.Color("215")
	colorErr       = lipgloss.Color("204")
	colorOK        = lipgloss.Color("114")
	// colorUserBg is the subtle "chat bubble" tint applied to every line of a
	// user prompt so it reads as a distinct block from the assistant's reply
	// (which stays on the default terminal background). 235 = #262626 — light
	// enough to lift off a black background, dim enough not to hurt on a dark
	// terminal theme. Bump to 236/237 for more contrast.
	colorUserBg = lipgloss.Color("235")
)

// userRail is the leading column glyph on every line of a user prompt block.
// Easy to swap — see the alternatives noted in renderUserBlock's docstring.
const userRail = "▶ "

var (
	styleUserLabel   = lipgloss.NewStyle().Bold(true).Foreground(colorUser)
	styleUserBody    = lipgloss.NewStyle().Foreground(colorText).Background(colorUserBg)
	styleBody        = lipgloss.NewStyle().Foreground(colorText)
	styleThinking    = lipgloss.NewStyle().Italic(true).Faint(true).Foreground(colorMuted)
	styleToolName    = lipgloss.NewStyle().Bold(true).Foreground(colorWarn)
	styleToolArgs    = lipgloss.NewStyle().Foreground(colorMuted)
	styleToolOK      = lipgloss.NewStyle().Foreground(colorOK)
	styleToolErr     = lipgloss.NewStyle().Foreground(colorErr)
	styleErr         = lipgloss.NewStyle().Bold(true).Foreground(colorErr)
	styleHint        = lipgloss.NewStyle().Foreground(colorDim)
	styleStatus      = lipgloss.NewStyle().Foreground(colorMuted)
	styleCaret       = lipgloss.NewStyle().Foreground(colorAccentDim)
	styleMDMarker    = lipgloss.NewStyle().Foreground(colorDim)
	styleInputBorder = lipgloss.NewStyle().
				Border(lipgloss.RoundedBorder()).
				BorderForeground(colorDim).
				Padding(0, 1)

	// Markdown inline styles. These only add ANSI attributes — they never
	// rewrite characters — so stripping ANSI from renderProse output still
	// yields the original raw markdown source.
	styleMDH1        = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("10"))
	styleMDH2        = lipgloss.NewStyle().Bold(true).Foreground(colorAccent)
	styleMDH3        = lipgloss.NewStyle().Bold(true).Foreground(colorUser)
	styleMDHMark     = lipgloss.NewStyle().Faint(true).Foreground(colorAccentDim)
	styleMDBold      = lipgloss.NewStyle().Bold(true).Foreground(colorText)
	styleMDItalic    = lipgloss.NewStyle().Italic(true).Foreground(colorText)
	styleMDStrike    = lipgloss.NewStyle().Strikethrough(true).Foreground(colorMuted)
	styleMDCode      = lipgloss.NewStyle().Foreground(colorWarn)
	styleMDLinkText  = lipgloss.NewStyle().Underline(true).Foreground(colorAccent)
	styleMDLinkURL   = lipgloss.NewStyle().Faint(true).Foreground(colorAccentDim)
	styleMDLinkPunct = lipgloss.NewStyle().Foreground(colorDim)
	styleMDListMark  = lipgloss.NewStyle().Bold(true).Foreground(colorAccent)
	styleMDQuoteMark = lipgloss.NewStyle().Bold(true).Foreground(colorAccent)
	styleMDQuote     = lipgloss.NewStyle().Italic(true).Foreground(colorMuted)
)

var (
	reMDHeading  = regexp.MustCompile(`^(#{1,6})(\s+.*?)(\s*#*\s*)$`)
	reMDBullet   = regexp.MustCompile(`^(\s*)([-*+])(\s+)(.*)$`)
	reMDNumbered = regexp.MustCompile(`^(\s*)(\d+\.)(\s+)(.*)$`)
	reMDQuote    = regexp.MustCompile(`^(\s*>)(.*)$`)
	reMDLink     = regexp.MustCompile(`^\[([^\]\n]+)\]\(([^)\n]+)\)`)
)

// Model is the Bubble Tea model.
type Model struct {
	cfg Config

	input textarea.Model

	state   turnState
	eventCh <-chan engine.Event
	cancel  context.CancelFunc

	// Live-render state: only shown in View(), not yet committed to scrollback.
	//
	// Assistant text streams line-at-a-time into scrollback: every completed
	// `\n`-terminated line is flushed immediately via tea.Printf, so the user
	// watches the reply unfold instead of seeing only a one-line ticker.
	// streamPartial holds the bytes received since the last newline — the
	// still-in-progress line that hasn't been committed yet.
	//
	// Fenced code blocks are the one exception: chroma needs the whole body
	// to highlight, so when a ```lang opener arrives we flip inFence and
	// buffer every subsequent line in fenceBuf until the closing ``` line
	// arrives. At that point the whole fence flushes as a single highlighted
	// block. mdFenceNested tracks the nested-fence state machine used for
	// ```md / ```markdown outer fences (empty-lang closes the outer only when
	// not already inside a nested fence).
	streamPartial   string
	inFence         bool
	fenceLang       string
	fenceOpenLine   string
	fenceBuf        []string
	mdFenceNested   bool
	thinkingBuf     string
	thinkingFlushed bool
	liveTool        *liveTool // currently-executing tool, if any

	// Slash-command chooser state. slashOpen flips to true the moment the
	// input value starts with "/" (and contains no space/newline yet). The
	// chooser lists every available command — built-ins like /clear plus one
	// /skill:NAME entry per registered skill — filtered by what the user has
	// typed. Up/Down navigate, Tab autocompletes the highlighted entry into
	// the input, Esc dismisses, Enter still submits whatever's in the input.
	slashOpen     bool
	slashIdx      int
	slashFiltered []slashItem

	lastUsageLine string
	errMsg        string
	width         int
	height        int
}

type liveTool struct {
	id      string
	name    string
	args    map[string]any
	partial string
}

// slashItem is one row in the slash-command chooser. label is what the user
// sees (and what we prefix-match against), description is the hint shown to
// its right, and insertion is what gets written into the textarea on Tab —
// commands that take args end with a trailing space so the cursor lands
// where args belong.
type slashItem struct {
	label       string
	description string
	insertion   string
}

// buildSlashItems returns every command available to the chooser: the
// built-in /clear plus one /skill:NAME entry per registered skill, in the
// registry's stable order.
func buildSlashItems(reg *skill.Registry) []slashItem {
	items := []slashItem{
		{
			label:       "/clear",
			description: "reset the conversation and clear the screen",
			insertion:   "/clear",
		},
	}
	if reg == nil {
		return items
	}
	for _, s := range reg.List() {
		items = append(items, slashItem{
			label:       "/skill:" + s.Name,
			description: s.Description,
			insertion:   "/skill:" + s.Name + " ",
		})
	}
	return items
}

// filterSlashItems keeps every item whose label starts with the typed query.
// Prefix match (not fuzzy) so the results are predictable and the autocomplete
// always extends what the user is already typing.
func filterSlashItems(items []slashItem, query string) []slashItem {
	out := make([]slashItem, 0, len(items))
	for _, it := range items {
		if strings.HasPrefix(it.label, query) {
			out = append(out, it)
		}
	}
	return out
}

// New constructs a fresh Model.
func New(cfg Config) Model {
	ta := textarea.New()
	ta.Placeholder = "type your message…"
	ta.Prompt = styleCaret.Render("▶ ")
	ta.ShowLineNumbers = false
	ta.CharLimit = 0
	ta.SetHeight(1)

	// Neutralize placeholder highlight and cursor-line background that
	// some terminals render as a jarring selection block.
	// v2 hides the style fields behind Styles()/SetStyles() so the model
	// can keep its memoization cache in sync; mutate on a snapshot then
	// write back.
	placeholderStyle := lipgloss.NewStyle().Foreground(colorDim).Italic(true)
	taStyles := ta.Styles()
	taStyles.Focused.Placeholder = placeholderStyle
	taStyles.Blurred.Placeholder = placeholderStyle
	taStyles.Focused.CursorLine = lipgloss.NewStyle()
	taStyles.Blurred.CursorLine = lipgloss.NewStyle()
	ta.SetStyles(taStyles)

	ta.Focus()

	return Model{cfg: cfg, input: ta}
}

func (m Model) Init() tea.Cmd {
	cmds := []tea.Cmd{textarea.Blink, m.printBootHeader()}
	if p := strings.TrimSpace(m.cfg.InitialPrompt); p != "" {
		cmds = append(cmds, func() tea.Msg { return sendMsg{prompt: p} })
	}
	return tea.Batch(cmds...)
}

// mascotBodyStyle / mascotEyeStyle are the two colors the boot banner
// mascot is rendered with. Two colors keep the creature cohesive — the
// frame reads as one shape, the `(o)` / `<o>` eye pops as its accent.
var (
	mascotBodyStyle = lipgloss.NewStyle().Bold(true).Foreground(colorVigolium)
	mascotEyeStyle  = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("196"))
)

// styledMascot picks a random entry from the shared mascot pool and
// applies the 2-color scheme via lipgloss (so it composes with the rest
// of the banner's styling).
func styledMascot() string {
	return terminal.ColoredMascot(
		terminal.RandomMascot(),
		func(s string) string { return mascotBodyStyle.Render(s) },
		func(s string) string { return mascotEyeStyle.Render(s) },
	)
}

// homeShorten swaps the user's $HOME prefix back to "~" so the directory
// row stays readable in the banner.
func homeShorten(p string) string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return p
	}
	if p == home {
		return "~"
	}
	if strings.HasPrefix(p, home+string(os.PathSeparator)) {
		return "~" + p[len(home):]
	}
	return p
}

// printBootHeader emits a compact two-line welcome banner into scrollback:
//
//	<mascot>  Olium agent (v0.1.0-alpha)
//	escape interrupt · ctrl+c/ctrl+d clear/exit · / commands · ! bash
//
// The previous layout surfaced backend/model/cwd in the banner; those have
// moved to the persistent View() footer so they stay visible across turns
// instead of scrolling out of sight.
func (m Model) printBootHeader() tea.Cmd {
	prefix := styledMascot()

	title := lipgloss.NewStyle().Bold(true).Foreground(colorVigolium).Render("Olium agent")
	if v := strings.TrimSpace(m.cfg.Version); v != "" {
		title += " " + lipgloss.NewStyle().Faint(true).Foreground(colorMuted).Render("("+v+")")
	}
	headLine := prefix + "  " + title
	hint := styleHint.Render("escape interrupt · ctrl+c/ctrl+d clear/exit · / commands · ! bash")
	return tea.Printf("%s\n%s\n", headLine, hint)
}

// renderFooter builds the persistent status line drawn at the bottom of
// View(): `<dir> · <tokens> · <model> · <effort> (<backend>)`. Segments
// without data (tokens before the first turn, empty effort/backend) are
// dropped so the line stays compact.
func (m Model) renderFooter() string {
	cwd, err := os.Getwd()
	if err != nil {
		cwd = "?"
	}
	dir := homeShorten(cwd)

	modelSpec := strings.TrimSpace(m.cfg.Model)
	if e := strings.TrimSpace(m.cfg.Effort); e != "" {
		modelSpec = strings.TrimSpace(modelSpec + " · " + e)
	}
	if p := strings.TrimSpace(m.cfg.ProviderName); p != "" {
		if modelSpec == "" {
			modelSpec = p
		} else {
			modelSpec += " (" + p + ")"
		}
	}

	var parts []string
	parts = append(parts, styleStatus.Render(dir))
	if m.lastUsageLine != "" {
		parts = append(parts, styleStatus.Render(m.lastUsageLine))
	}
	if modelSpec != "" {
		parts = append(parts, styleStatus.Render(modelSpec))
	}
	return strings.Join(parts, styleHint.Render(" · "))
}

// maxInputLines caps how tall the input box can grow before it starts
// scrolling internally. 10 fits long multi-line prompts without taking
// over the screen.
const maxInputLines = 10

// resyncInputHeight grows / shrinks the textarea's internal viewport to
// match its current line count. Safe to call after any update — it only
// touches m.input.SetHeight, leaving cursor position alone.
func (m *Model) resyncInputHeight() {
	h := m.input.LineCount()
	if h < 1 {
		h = 1
	} else if h > maxInputLines {
		h = maxInputLines
	}
	m.input.SetHeight(h)
}

// resetInputViewport snaps the textarea's internal scroll offset back to
// the top by walking the cursor to the begin then to the end. It's needed
// after `splitLine` inserts a new row: the textarea's `repositionView`
// only scrolls to keep the cursor visible, so the viewport stays pinned
// to the new (empty) row and the row above it (with the user's typed
// text) becomes invisible. Walking via MoveToBegin first scrolls
// YOffset back to 0; MoveToEnd then puts the cursor where splitLine left
// it, but with the viewport now showing all rows.
func (m *Model) resetInputViewport() {
	m.input.MoveToBegin()
	m.input.MoveToEnd()
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.input.SetWidth(msg.Width - 4)
		return m, nil

	case tea.KeyPressMsg:
		// v2 matches keys via String() — stable across terminals and across
		// any modifier permutation. The kitty keyboard protocol (auto-
		// negotiated by Bubble Tea v2 when the terminal advertises support)
		// is what makes "shift+enter" actually distinguishable from "enter".
		switch msg.String() {
		case "esc":
			// Priority: dismiss the slash chooser if it's open, otherwise
			// cancel an in-flight turn. Ctrl+C kills the whole program; Esc
			// is the softer "stop what you're doing, I want the prompt back"
			// affordance — matches the "escape interrupt" hint in the banner.
			if m.slashOpen {
				m.slashOpen = false
				return m, nil
			}
			if m.state == stateStreaming && m.cancel != nil {
				m.cancel()
				return m, nil
			}
		case "up":
			if m.slashOpen && len(m.slashFiltered) > 0 {
				m.slashIdx = (m.slashIdx - 1 + len(m.slashFiltered)) % len(m.slashFiltered)
				return m, nil
			}
		case "down":
			if m.slashOpen && len(m.slashFiltered) > 0 {
				m.slashIdx = (m.slashIdx + 1) % len(m.slashFiltered)
				return m, nil
			}
		case "tab":
			// Tab autocompletes the highlighted entry into the textarea. Only
			// intercept when the chooser is open; otherwise let the textarea
			// handle Tab as a literal character.
			if m.slashOpen && len(m.slashFiltered) > 0 {
				chosen := m.slashFiltered[m.slashIdx]
				m.input.SetValue(chosen.insertion)
				m.input.CursorEnd()
				m.refilterSlash()
				return m, nil
			}
		}
		switch msg.String() {
		case "ctrl+c":
			if m.cancel != nil {
				m.cancel()
			}
			// Cancelling the external context flags Bubble Tea's shutdown
			// as "killed", which skips the 500 ms waitForReadLoop timeout
			// on the TTY input reader. Keep tea.Quit as a fallback in case
			// Run() wasn't the one that created this Model.
			if m.cfg.quit != nil {
				m.cfg.quit()
			}
			return m, tea.Quit

		case "ctrl+j", "alt+enter", "shift+enter":
			// All three are "soft return" — insert a newline into the
			// textarea instead of submitting. ctrl+j works on every
			// terminal; alt+enter works wherever Option/Alt sends ESC;
			// shift+enter works on terminals that negotiate the kitty
			// keyboard protocol (kitty, ghostty, wezterm, recent iTerm2).
			var cmd tea.Cmd
			m.input, cmd = m.input.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
			m.resyncInputHeight()
			m.resetInputViewport()
			return m, cmd

		case "enter":
			// Backslash-at-end + Enter → strip backslash, insert newline.
			// Mirrors Claude Code / bash line-continuation habit; works on
			// every terminal.
			if strings.HasSuffix(m.input.Value(), `\`) {
				cur := m.input.Value()
				m.input.SetValue(cur[:len(cur)-1])
				// Move cursor to end and insert newline.
				m.input.CursorEnd()
				var cmd tea.Cmd
				m.input, cmd = m.input.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
				m.resyncInputHeight()
				m.resetInputViewport()
				return m, cmd
			}
			if m.state != stateIdle {
				return m, nil
			}
			prompt := strings.TrimSpace(m.input.Value())
			if prompt == "" {
				return m, nil
			}
			if prompt == "/clear" {
				m.cfg.Engine.Reset()
				m.resetStreamState()
				m.lastUsageLine = ""
				m.errMsg = ""
				m.input.Reset()
				m.resyncInputHeight()
				m.refilterSlash()
				// In inline mode, tea.ClearScreen only redraws the live view
				// (ultraviolet's clearUpdate does clearBelow(row=0) when not
				// fullscreen) — content that was pushed above via insertAbove
				// stays visible. ESC[3J alone just drops the off-screen
				// scrollback buffer, not the visible lines above the prompt.
				// Raw-writing H + 2J + 3J first scrubs the whole viewport and
				// scrollback, then tea.ClearScreen forces the renderer to
				// re-anchor the live view at the top of a blank screen before
				// the boot banner is re-inserted.
				return m, tea.Sequence(
					tea.Raw("\x1b[H\x1b[2J\x1b[3J"),
					tea.ClearScreen,
					m.printBootHeader(),
				)
			}
			if name, args, isSkill := skill.ParseInlineInvocation(prompt); isSkill {
				expanded, ok := skill.ExpandInlineInvocation(m.cfg.Skills, name, args)
				if !ok {
					m.errMsg = fmt.Sprintf("unknown skill %q — type a real skill name after /skill:", name)
					return m, nil
				}
				prompt = expanded
			}
			m.input.Reset()
			m.resyncInputHeight()
			m.refilterSlash()
			return m, func() tea.Msg { return sendMsg{prompt: prompt} }
		}

	case sendMsg:
		return m.startTurn(msg.prompt)

	case eventMsg:
		return m.applyEvent(engine.Event(msg))

	case runClosedMsg:
		m.state = stateIdle
		m.eventCh = nil
		if m.cancel != nil {
			m.cancel()
			m.cancel = nil
		}
		m.resetStreamState()
		// Terminating blank line in scrollback — separates turns visually.
		return m, tea.Printf("")
	}

	var cmd tea.Cmd
	m.input, cmd = m.input.Update(msg)
	m.resyncInputHeight()
	m.refilterSlash()
	return m, cmd
}

// refilterSlash re-evaluates whether the chooser should be open and which
// entries match what the user has typed. Open iff the input starts with "/"
// and contains no whitespace yet — once the user types past the command name
// (a space, or a newline), we close so the popup isn't in the way of args.
func (m *Model) refilterSlash() {
	val := m.input.Value()
	if !strings.HasPrefix(val, "/") || strings.ContainsAny(val, " \t\n") {
		m.slashOpen = false
		m.slashFiltered = nil
		m.slashIdx = 0
		return
	}
	m.slashFiltered = filterSlashItems(buildSlashItems(m.cfg.Skills), val)
	m.slashOpen = len(m.slashFiltered) > 0
	if m.slashIdx >= len(m.slashFiltered) {
		m.slashIdx = 0
	}
}

func (m *Model) startTurn(prompt string) (tea.Model, tea.Cmd) {
	m.resetStreamState()
	m.errMsg = ""
	m.state = stateStreaming

	// Flush user's prompt into scrollback right away so it looks anchored.
	// Prefix every line with the `▶` rail (in the user color) so multi-line
	// prompts read as one grouped block — no separate "you" label line.
	// Trailing "\n" gives the assistant reply breathing room — without it
	// the tinted user bubble butts directly against the first line of the
	// response and the two blocks visually smear together.
	userBlock := renderUserBlock(prompt, m.width) + "\n"

	ctx, cancel := context.WithCancel(context.Background())
	m.cancel = cancel
	ch := m.cfg.Engine.Run(ctx, prompt)
	m.eventCh = ch
	return m, tea.Sequence(m.printScrollback(userBlock), pumpEvents(ch))
}

func pumpEvents(ch <-chan engine.Event) tea.Cmd {
	return func() tea.Msg {
		ev, ok := <-ch
		if !ok {
			return runClosedMsg{}
		}
		return eventMsg(ev)
	}
}

func (m Model) applyEvent(ev engine.Event) (tea.Model, tea.Cmd) {
	var print tea.Cmd

	switch ev.Type {
	case engine.EventTextDelta:
		print = m.handleTextDelta(ev.Delta)

	case engine.EventThinkingDelta:
		m.thinkingBuf += ev.Delta

	case engine.EventToolCallStart:
		m.liveTool = &liveTool{
			id:   ev.ToolCallID,
			name: ev.ToolName,
			args: ev.ToolArgs,
		}

	case engine.EventToolExecStart:
		if m.liveTool == nil || m.liveTool.id != ev.ToolCallID {
			m.liveTool = &liveTool{id: ev.ToolCallID, name: ev.ToolName, args: ev.ToolArgs}
		} else {
			m.liveTool.args = ev.ToolArgs
		}

	case engine.EventToolExecProgress:
		if m.liveTool != nil && m.liveTool.id == ev.ToolCallID {
			m.liveTool.partial = ev.ToolResult
		}

	case engine.EventToolExecEnd:
		// Flush the tool card to scrollback.
		card := renderToolBlock(ev.ToolName, ev.ToolArgs, ev.ToolResult, ev.ToolIsErr)
		print = m.printScrollback(card)
		if m.liveTool != nil && m.liveTool.id == ev.ToolCallID {
			m.liveTool = nil
		}

	case engine.EventTurnDone:
		// Streaming has already pushed completed prose lines and closed
		// fences into scrollback as they arrived. All that's left to drain
		// is: thinking buffered for a turn that never produced text (rare —
		// usually a tool-only turn), an unclosed fence, and the final
		// partial line that was still in flight.
		var prints []tea.Cmd
		if m.thinkingBuf != "" {
			prints = append(prints, m.printScrollback(m.renderThinkingBlock()))
			m.thinkingBuf = ""
		}
		if m.inFence {
			prints = append(prints, m.printScrollback(m.drainUnclosedFence()))
		}
		if m.streamPartial != "" {
			prints = append(prints, m.printScrollback(renderProseLine(m.streamPartial)))
			m.streamPartial = ""
		}
		m.thinkingFlushed = false
		if len(prints) > 0 {
			print = tea.Sequence(prints...)
		}
		if ev.Usage != nil {
			m.lastUsageLine = fmt.Sprintf("in %d · out %d · cached %d",
				ev.Usage.Input, ev.Usage.Output, ev.Usage.CacheRead)
		}

	case engine.EventRunDone:
		// handled on runClosedMsg

	case engine.EventError:
		m.errMsg = ev.Err
		print = m.printScrollback(styleErr.Render(terminal.SymbolError + " " + ev.Err))
	}

	pump := tea.Cmd(nil)
	if m.eventCh != nil {
		pump = pumpEvents(m.eventCh)
	}
	if print != nil {
		return m, tea.Sequence(print, pump)
	}
	return m, pump
}

// handleTextDelta consumes a chunk of streamed assistant text, flushing every
// completed line to scrollback as it arrives. The trailing partial (everything
// after the last `\n`) stays in m.streamPartial and is rendered as the live
// ticker until either more text arrives to complete it or the turn ends.
//
// Fenced code blocks are buffered: chroma needs the whole body to highlight,
// so a ```lang opener flips inFence and every subsequent line goes into
// fenceBuf until the closing fence arrives, at which point the entire fence
// flushes as one highlighted block.
//
// Thinking that was buffered before this delta is flushed first, so the user
// reads top-down: think → answer.
func (m *Model) handleTextDelta(delta string) tea.Cmd {
	var prints []tea.Cmd
	if !m.thinkingFlushed && m.thinkingBuf != "" {
		prints = append(prints, m.printScrollback(m.renderThinkingBlock()))
		m.thinkingBuf = ""
		m.thinkingFlushed = true
	}

	combined := m.streamPartial + delta
	parts := strings.Split(combined, "\n")
	m.streamPartial = parts[len(parts)-1]
	completeLines := parts[:len(parts)-1]

	var proseBatch []string
	flushProse := func() {
		if len(proseBatch) > 0 {
			prints = append(prints, m.printScrollback(strings.Join(proseBatch, "\n")))
			proseBatch = nil
		}
	}

	for _, line := range completeLines {
		if m.inFence {
			block, closed := m.feedFence(line)
			if closed {
				prints = append(prints, m.printScrollback(block))
			}
			continue
		}
		if lang, ok := parseFenceLine(line); ok {
			// Opening fence — flush any pending prose first so the fence
			// drops cleanly under the prose that came before it.
			flushProse()
			m.inFence = true
			m.fenceLang = lang
			m.fenceOpenLine = line
			m.fenceBuf = nil
			m.mdFenceNested = false
			continue
		}
		proseBatch = append(proseBatch, renderProseLine(line))
	}
	flushProse()

	if len(prints) == 0 {
		return nil
	}
	return tea.Sequence(prints...)
}

// feedFence consumes one line while inside a fenced code block. When the line
// closes the fence, returns (rendered block, true); otherwise the line is
// appended to fenceBuf and the call returns ("", false). The close rule
// mirrors findFenceClose / findMarkdownFenceClose so streaming and batch
// rendering produce the same fence boundaries.
func (m *Model) feedFence(line string) (string, bool) {
	innerLang, isFence := parseFenceLine(line)
	if !isFence {
		m.fenceBuf = append(m.fenceBuf, line)
		return "", false
	}
	innerLang = strings.TrimSpace(innerLang)
	if isMarkdownLang(m.fenceLang) {
		// Markdown-language fences nest: an inner fence with a lang opens a
		// nested block; only an empty-lang fence at depth 0 closes the outer
		// markdown block.
		if m.mdFenceNested {
			if innerLang == "" {
				m.mdFenceNested = false
			}
			m.fenceBuf = append(m.fenceBuf, line)
			return "", false
		}
		if innerLang != "" {
			m.mdFenceNested = true
			m.fenceBuf = append(m.fenceBuf, line)
			return "", false
		}
		return m.finishFence(line), true
	}
	if innerLang == "" {
		return m.finishFence(line), true
	}
	// Fence-like line carrying a lang inside a non-markdown fence is just
	// content — findFenceClose only treats empty-lang fences as closers.
	m.fenceBuf = append(m.fenceBuf, line)
	return "", false
}

// finishFence renders the buffered fence (opener + body + closer) via chroma
// and resets the fence state. The opener / closer lines are kept verbatim so
// users see the original ```lang they wrote.
func (m *Model) finishFence(closingLine string) string {
	parts := make([]string, 0, len(m.fenceBuf)+2)
	parts = append(parts, m.fenceOpenLine)
	parts = append(parts, m.fenceBuf...)
	parts = append(parts, closingLine)
	fence := strings.Join(parts, "\n")
	code := strings.Join(m.fenceBuf, "\n")
	lang := m.fenceLang
	m.inFence = false
	m.fenceLang = ""
	m.fenceOpenLine = ""
	m.fenceBuf = nil
	m.mdFenceNested = false
	return renderHighlightedFence(fence, lang, code)
}

// drainUnclosedFence is the EventTurnDone fallback for when the model stopped
// without closing a fence. We emit the opener + buffered lines as raw prose so
// nothing is dropped; chroma is skipped because the body is incomplete.
func (m *Model) drainUnclosedFence() string {
	lines := make([]string, 0, len(m.fenceBuf)+1)
	lines = append(lines, m.fenceOpenLine)
	lines = append(lines, m.fenceBuf...)
	out := renderProse(strings.Join(lines, "\n"))
	m.inFence = false
	m.fenceLang = ""
	m.fenceOpenLine = ""
	m.fenceBuf = nil
	m.mdFenceNested = false
	return out
}

// renderThinkingBlock formats the buffered reasoning stream as a tight,
// muted-italic block prefixed by the ⋈ bowtie so it reads as its own
// conversational lane (distinct from the user's ▶ rail and the assistant's
// default body). The thinking lane is a status channel, not prose — the
// reader wants to know *what* the model is reasoning about, not a faithful
// reproduction of paragraph structure. compactThinkingBody drops blank
// rows entirely and trims each surviving line, so a GPT-5-style reasoning
// summary ("**Title**\n\n\n\n\n\n\n\nBody…") renders as two adjacent lines
// instead of an empty half-page between them. Returns "" when nothing
// survives compaction so the caller skips the scrollback push.
func (m *Model) renderThinkingBlock() string {
	body := compactThinkingBody(m.thinkingBuf)
	if body == "" {
		return ""
	}
	header := styleThinking.Render("  " + terminal.SymbolBowtie + " thinking")
	return header + "\n" + styleThinking.Render(indent(body, "    "))
}

// compactThinkingBody trims each line and drops every blank line. "Blank"
// means empty *after* stripping Unicode whitespace — so tabs, non-breaking
// spaces, and any other IsSpace-class padding all collapse. We don't
// preserve paragraph breaks because the thinking lane is faint/italic
// status text, and GPT-5's reasoning summaries in particular embed huge
// runs of newlines between title and body that otherwise blow the block
// up into dead space.
func compactThinkingBody(s string) string {
	if s == "" {
		return ""
	}
	lines := strings.Split(s, "\n")
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		out = append(out, trimmed)
	}
	return strings.Join(out, "\n")
}

// resetStreamState wipes per-turn streaming buffers so a stray partial / open
// fence from a prior turn never leaks into the next one.
func (m *Model) resetStreamState() {
	m.streamPartial = ""
	m.inFence = false
	m.fenceLang = ""
	m.fenceOpenLine = ""
	m.fenceBuf = nil
	m.mdFenceNested = false
	m.thinkingBuf = ""
	m.thinkingFlushed = false
	m.liveTool = nil
}

// View renders the live area: a constant-size status line (so the live region
// never shrinks — shrinkage was leaving leftover ANSI cells under the input),
// the input box, and a hint line. Completed prose lines and closed fences are
// pushed into scrollback by `tea.Printf` as they stream in (see
// handleTextDelta), so the user sees the reply unfold persistently above the
// live region.
//
// Bubble Tea v2 requires View() to return a tea.View struct. We also opt in
// to kitty keyboard event reporting here so the terminal will distinguish
// shift+enter from plain enter (when supported — gracefully degrades to
// "enter" on terminals that don't negotiate the protocol).
func (m Model) View() tea.View {
	var b strings.Builder

	// Status line — always one line so the live view height only varies
	// with the textarea, not with streaming output. The streamed reply itself
	// flushes line-by-line into scrollback (see handleTextDelta); the ticker
	// here just shows the in-progress partial line that hasn't been newlined
	// yet, plus a hint if we're inside a code fence (which buffers until
	// close so chroma can highlight the whole body).
	switch {
	case m.state == stateStreaming && m.liveTool != nil:
		// Tool cards are inherently multi-line; let them through. They
		// disappear when the tool finishes, but tools are infrequent so
		// the brief shrink doesn't accumulate visible artifacts.
		b.WriteString(renderLiveToolCard(*m.liveTool))
		b.WriteString("\n")
	case m.state == stateStreaming:
		var label string
		partial := strings.TrimRight(m.streamPartial, " \t")
		switch {
		case m.inFence:
			lang := strings.TrimSpace(m.fenceLang)
			if lang == "" {
				lang = "code"
			}
			head := "writing " + lang + " block…"
			if partial != "" {
				head += "  " + truncateForStatus(partial, m.width-len(head)-8)
			}
			label = styleStatus.Render("  ● " + head)
		case partial != "":
			label = styleStatus.Render("  ● ") + styleBody.Render(truncateForStatus(partial, m.width-4))
		case m.thinkingBuf != "":
			// Match the scrollback thinking card's ⋈ marker so the live
			// ticker reads as the same "channel" as the flushed block
			// that lands above when the reply starts streaming.
			label = styleStatus.Render("  " + terminal.SymbolBowtie + " thinking…")
		default:
			label = styleStatus.Render("  ● working…")
		}
		b.WriteString(label)
		b.WriteString("\n")
	default:
		b.WriteString("\n")
	}

	// Slash-command chooser — appears above the input the moment the user
	// types a leading "/", goes away as soon as they type past the command
	// name (a space or newline) or hit Esc. The popup grows the live region
	// while open; that's accepted because it's short-lived and entirely
	// driven by the user's own keystrokes.
	if chooser := m.renderSlashChooser(); chooser != "" {
		b.WriteString(chooser)
		b.WriteString("\n")
	}

	// Input box — always visible. Height is updated in Update() now (so the
	// textarea's internal viewport stays in sync with content); here we just
	// render whatever the textarea currently knows.
	b.WriteString(styleInputBorder.Render(m.input.View()))

	// Footer — persistent context: directory · tokens · model · effort (backend).
	// Keyboard hints live in the boot banner (shown once in scrollback), so the
	// footer can focus on state that's useful to glance at mid-session.
	b.WriteString("\n")
	b.WriteString(m.renderFooter())

	v := tea.NewView(b.String())
	// Ask the terminal to report key event types via the kitty keyboard
	// protocol. On terminals that support it (kitty, ghostty, wezterm,
	// recent iTerm2) shift+enter arrives as a distinct KeyPressMsg with
	// String()="shift+enter". On terminals that don't, the request is a
	// no-op and shift+enter still collapses to plain "enter".
	v.KeyboardEnhancements.ReportEventTypes = true
	return v
}

// --- Scrollback block rendering ---
//
// These functions produce a multi-line string that is emitted via
// tea.Printf and then persists in the terminal's normal scrollback.

// truncateForStatus shortens s to fit within max columns, trimming from the
// LEFT (so the most recently emitted text stays visible). Falls back to a
// 60-column window when max isn't yet known.
func truncateForStatus(s string, max int) string {
	if max <= 8 {
		max = 60
	}
	const ellipsis = "…"
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	keep := max - len([]rune(ellipsis))
	if keep < 1 {
		keep = 1
	}
	return ellipsis + string(r[len(r)-keep:])
}

const maxScrollbackChunkRows = 24

// printScrollback emits completed content above the live input area. Large
// writes are chunked because Bubble Tea's inline renderer can lose the live
// input when one insertAbove call is taller than the visible terminal.
func (m Model) printScrollback(s string) tea.Cmd {
	chunks := splitScrollbackChunks(s, m.width, maxScrollbackChunkRows)
	if len(chunks) == 0 {
		return nil
	}
	cmds := make([]tea.Cmd, 0, len(chunks)+1)
	for _, chunk := range chunks {
		chunk := chunk
		cmds = append(cmds, tea.Printf("%s", chunk))
	}
	if repaint := repaintCurrentSize(m.width, m.height); repaint != nil {
		cmds = append(cmds, repaint)
	}
	return tea.Sequence(cmds...)
}

func repaintCurrentSize(width, height int) tea.Cmd {
	if width <= 0 || height <= 0 {
		return nil
	}
	return func() tea.Msg {
		return tea.WindowSizeMsg{Width: width, Height: height}
	}
}

func splitScrollbackChunks(s string, width, maxRows int) []string {
	if s == "" {
		return nil
	}
	if width <= 8 {
		width = 80
	}
	if maxRows <= 0 {
		maxRows = maxScrollbackChunkRows
	}

	lines := strings.Split(s, "\n")
	chunks := make([]string, 0, 1+(len(lines)/maxRows))
	buf := make([]string, 0, maxRows)
	rows := 0
	for _, line := range lines {
		lineRows := visualRows(line, width)
		if len(buf) > 0 && rows+lineRows > maxRows {
			chunks = append(chunks, strings.Join(buf, "\n"))
			buf = buf[:0]
			rows = 0
		}
		buf = append(buf, line)
		rows += lineRows
	}
	if len(buf) > 0 {
		chunks = append(chunks, strings.Join(buf, "\n"))
	}
	return chunks
}

func visualRows(line string, width int) int {
	if width <= 0 {
		width = 80
	}
	w := lipgloss.Width(line)
	if w <= 0 {
		return 1
	}
	return ((w - 1) / width) + 1
}

// renderUserBlock formats a user prompt with the userRail glyph prefixed onto
// every line, so a multi-line message reads as a single grouped block without
// an extra "you" label. Each line's body is padded with a subtle background
// tint (colorUserBg) out to the terminal width so the user prompt looks like
// a chat bubble distinct from the assistant's reply, which renders on the
// default terminal background.
//
// userRail alternatives that look good in monospace: ▎ (lighter), ▏ (very
// thin), ┃ (heavy box), │ (light box), ║ (double), ❯ / › (angle), > (ASCII).
func renderUserBlock(prompt string, width int) string {
	rail := styleUserLabel.Render(userRail)
	body := styleUserBody
	if bodyWidth := width - lipgloss.Width(userRail); bodyWidth >= 20 {
		body = body.Width(bodyWidth)
	}
	lines := strings.Split(prompt, "\n")
	for i, line := range lines {
		lines[i] = rail + body.Render(line)
	}
	return strings.Join(lines, "\n")
}

// renderSlashChooser draws the /command popup that sits above the input. It's
// a bordered box listing every matching command, with the highlighted entry
// rendered bold + accent. Returns "" when the chooser is closed so the caller
// can skip emitting any extra rows.
//
// The label column is left-padded to the longest visible label so descriptions
// align in a clean second column.
func (m Model) renderSlashChooser() string {
	if !m.slashOpen || len(m.slashFiltered) == 0 {
		return ""
	}

	maxLabel := 0
	for _, it := range m.slashFiltered {
		if w := lipgloss.Width(it.label); w > maxLabel {
			maxLabel = w
		}
	}

	rows := make([]string, 0, len(m.slashFiltered)+1)
	rows = append(rows, styleHint.Render("commands  ·  ↑/↓ to navigate  ·  tab to autocomplete  ·  esc to dismiss"))
	for i, it := range m.slashFiltered {
		marker := "  "
		labelStyle := lipgloss.NewStyle().Foreground(colorText)
		if i == m.slashIdx {
			marker = lipgloss.NewStyle().Foreground(colorAccent).Render("▸ ")
			labelStyle = labelStyle.Bold(true).Foreground(colorAccent)
		}
		label := it.label + strings.Repeat(" ", maxLabel-lipgloss.Width(it.label))
		row := marker + labelStyle.Render(label)
		if it.description != "" {
			row += "  " + styleHint.Render(it.description)
		}
		rows = append(rows, row)
	}

	return lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(colorAccentDim).
		Padding(0, 1).
		Render(strings.Join(rows, "\n"))
}

// renderAssistant prints the assistant's markdown reply raw, except fenced
// code block bodies get Chroma syntax highlighting. Fence lines and all prose
// markdown markers remain visible so the user can copy the original content.
//
// On any chroma error (unknown lexer, format failure) we fall back to the
// fence's raw text via styleBody — never drop content.
func (m *Model) renderAssistant(text string) string {
	if strings.TrimSpace(text) == "" {
		return ""
	}

	lines := strings.Split(text, "\n")
	var b strings.Builder
	prose := make([]string, 0, len(lines))

	flushProse := func(addTrailingNewline bool) {
		if len(prose) == 0 {
			return
		}
		b.WriteString(renderProse(strings.Join(prose, "\n")))
		if addTrailingNewline {
			b.WriteString("\n")
		}
		prose = prose[:0]
	}

	for i := 0; i < len(lines); {
		lang, ok := parseFenceLine(lines[i])
		if !ok {
			prose = append(prose, lines[i])
			i++
			continue
		}

		closeIdx := findFenceClose(lines, i, lang)
		if closeIdx < 0 {
			prose = append(prose, lines[i])
			i++
			continue
		}

		flushProse(true)
		fence := strings.Join(lines[i:closeIdx+1], "\n")
		code := strings.Join(lines[i+1:closeIdx], "\n")
		b.WriteString(renderHighlightedFence(fence, lang, code))
		if closeIdx < len(lines)-1 {
			b.WriteString("\n")
		}
		i = closeIdx + 1
	}

	flushProse(false)
	return b.String()
}

func parseFenceLine(line string) (lang string, ok bool) {
	line = strings.TrimRight(line, "\r")
	trimmed := strings.TrimSpace(line)
	if !strings.HasPrefix(trimmed, "```") {
		return "", false
	}
	return strings.TrimSpace(strings.TrimPrefix(trimmed, "```")), true
}

func findFenceClose(lines []string, openIdx int, lang string) int {
	if isMarkdownLang(lang) {
		return findMarkdownFenceClose(lines, openIdx)
	}
	for i := openIdx + 1; i < len(lines); i++ {
		closeLang, ok := parseFenceLine(lines[i])
		if ok && strings.TrimSpace(closeLang) == "" {
			return i
		}
	}
	return -1
}

func findMarkdownFenceClose(lines []string, openIdx int) int {
	inNestedFence := false
	for i := openIdx + 1; i < len(lines); i++ {
		innerLang, ok := parseFenceLine(lines[i])
		if !ok {
			continue
		}
		innerLang = strings.TrimSpace(innerLang)
		if inNestedFence {
			if innerLang == "" {
				inNestedFence = false
			}
			continue
		}
		if innerLang != "" {
			inNestedFence = true
			continue
		}
		return i
	}
	return -1
}

// renderProse colors raw text with per-line markdown highlighting. Block-level
// classification (heading / bullet / numbered / quote) runs first, then inline
// tokens (bold, italic, strikethrough, inline code, links) are styled within
// each line. Only ANSI attributes are added — markdown markers remain visible
// so stripping ANSI returns the original source, and copy/paste still yields
// raw markdown.
func renderProse(s string) string {
	if s == "" {
		return ""
	}
	lines := strings.Split(s, "\n")
	for i, line := range lines {
		if line == "" {
			continue
		}
		lines[i] = renderProseLine(line)
	}
	return strings.Join(lines, "\n")
}

func renderProseLine(line string) string {
	if m := reMDHeading.FindStringSubmatch(line); m != nil {
		style := headingStyle(len(m[1]))
		return styleMDHMark.Render(m[1]) + style.Render(m[2]) + styleMDHMark.Render(m[3])
	}
	if m := reMDQuote.FindStringSubmatch(line); m != nil {
		return styleMDQuoteMark.Render(m[1]) + styleMDQuote.Render(m[2])
	}
	if m := reMDBullet.FindStringSubmatch(line); m != nil {
		return m[1] + styleMDListMark.Render(m[2]) + m[3] + renderInline(m[4])
	}
	if m := reMDNumbered.FindStringSubmatch(line); m != nil {
		return m[1] + styleMDListMark.Render(m[2]) + m[3] + renderInline(m[4])
	}
	return renderInline(line)
}

func headingStyle(level int) lipgloss.Style {
	switch level {
	case 1:
		return styleMDH1
	case 2:
		return styleMDH2
	default:
		return styleMDH3
	}
}

// renderInline walks s left-to-right, emitting styled spans for inline
// markdown constructs and body-colored plain text in between. Characters are
// preserved verbatim — only ANSI is added. Order of detection (code → bold →
// strikethrough → italic → link) matters so overlapping markers resolve to
// the widest sensible span (e.g. `**x**` is bold, not two italics).
func renderInline(s string) string {
	var b strings.Builder
	plain := 0
	flushPlain := func(end int) {
		if end > plain {
			b.WriteString(styleBody.Render(s[plain:end]))
		}
	}
	i := 0
	for i < len(s) {
		switch {
		case s[i] == '`':
			if j := strings.IndexByte(s[i+1:], '`'); j > 0 {
				end := i + 1 + j
				if !strings.ContainsRune(s[i+1:end], '\n') {
					flushPlain(i)
					b.WriteString(styleMDCode.Render(s[i : end+1]))
					i = end + 1
					plain = i
					continue
				}
			}
		case i+3 < len(s) && s[i] == '*' && s[i+1] == '*' && !isInlineSpace(s[i+2]):
			if end := findMarkerOnLine(s, i+2, "**"); end > i+2 && !isInlineSpace(s[end-1]) {
				flushPlain(i)
				b.WriteString(styleMDBold.Render(s[i : end+2]))
				i = end + 2
				plain = i
				continue
			}
		case i+3 < len(s) && s[i] == '~' && s[i+1] == '~' && !isInlineSpace(s[i+2]):
			if end := findMarkerOnLine(s, i+2, "~~"); end > i+2 && !isInlineSpace(s[end-1]) {
				flushPlain(i)
				b.WriteString(styleMDStrike.Render(s[i : end+2]))
				i = end + 2
				plain = i
				continue
			}
		case s[i] == '*' && i+1 < len(s) && !isInlineSpace(s[i+1]):
			if j := strings.IndexAny(s[i+1:], "*\n"); j > 0 && s[i+1+j] == '*' && !isInlineSpace(s[i+j]) {
				end := i + 1 + j
				flushPlain(i)
				b.WriteString(styleMDItalic.Render(s[i : end+1]))
				i = end + 1
				plain = i
				continue
			}
		case s[i] == '[':
			if loc := reMDLink.FindStringSubmatchIndex(s[i:]); loc != nil {
				textStart, textEnd := i+loc[2], i+loc[3]
				urlStart, urlEnd := i+loc[4], i+loc[5]
				matchEnd := i + loc[1]
				flushPlain(i)
				b.WriteString(styleMDLinkPunct.Render("["))
				b.WriteString(styleMDLinkText.Render(s[textStart:textEnd]))
				b.WriteString(styleMDLinkPunct.Render("]("))
				b.WriteString(styleMDLinkURL.Render(s[urlStart:urlEnd]))
				b.WriteString(styleMDLinkPunct.Render(")"))
				i = matchEnd
				plain = i
				continue
			}
		}
		i++
	}
	flushPlain(len(s))
	return b.String()
}

func findMarkerOnLine(s string, start int, marker string) int {
	for i := start; i <= len(s)-len(marker); i++ {
		if s[i] == '\n' {
			return -1
		}
		if strings.HasPrefix(s[i:], marker) {
			return i
		}
	}
	return -1
}

func isInlineSpace(b byte) bool {
	return b == ' ' || b == '\t'
}

// noHighlightLangs are language tags we deliberately do NOT pass through
// chroma. "markdown" is the big one: a fenced markdown block is usually a
// literal sample. Empty lang and generic "text"/"plain" tags get the same
// verbatim treatment for symmetry.
var noHighlightLangs = map[string]bool{
	"":          true,
	"text":      true,
	"plain":     true,
	"plaintext": true,
	"txt":       true,
	"markdown":  true,
	"md":        true,
}

func isMarkdownLang(lang string) bool {
	switch strings.ToLower(strings.TrimSpace(lang)) {
	case "markdown", "md":
		return true
	default:
		return false
	}
}

func renderHighlightedFence(fence, lang, code string) string {
	opening, closing := splitFenceLines(fence)
	var b strings.Builder
	b.WriteString(styleMDMarker.Render(opening))
	b.WriteString("\n")
	if code != "" {
		b.WriteString(highlightCodeBlock(lang, code))
		b.WriteString("\n")
	}
	b.WriteString(styleMDMarker.Render(closing))
	return b.String()
}

func splitFenceLines(fence string) (opening, closing string) {
	lines := strings.Split(fence, "\n")
	if len(lines) == 0 {
		return "```", "```"
	}
	opening = strings.TrimRight(lines[0], "\r")
	closing = "```"
	for i := len(lines) - 1; i >= 0; i-- {
		line := strings.TrimRight(lines[i], "\r")
		if strings.HasPrefix(strings.TrimSpace(line), "```") {
			closing = line
			break
		}
	}
	return opening, closing
}

// highlightCodeBlock runs Chroma over code fence bodies. Documentation-style
// languages bypass Chroma and indentation entirely so samples stay copyable.
func highlightCodeBlock(lang, code string) string {
	if noHighlightLangs[strings.ToLower(strings.TrimSpace(lang))] {
		return renderProse(code)
	}
	var buf strings.Builder
	if err := quick.Highlight(&buf, code, lang, "terminal256", "monokai"); err != nil {
		// Couldn't highlight — emit the raw block so the user still sees it.
		return indent(code, "  ")
	}
	return indent(strings.TrimRight(buf.String(), "\n"), "  ")
}

func renderToolBlock(name string, args map[string]any, result string, isErr bool) string {
	symbol := terminal.SymbolFunction
	if name == "bash" {
		symbol = terminal.SymbolBash
	}

	header := styleToolName.Render(symbol+" "+name) + "  " + styleToolArgs.Render(oneLineArgs(args))

	marker := styleToolOK.Render("  " + terminal.SymbolSuccess + " ")
	if isErr {
		marker = styleToolErr.Render("  " + terminal.SymbolError + " ")
	}
	body := marker + styleToolArgs.Render(truncateLines(result, 12, 4))

	return header + "\n" + body
}

// renderLiveToolCard is the in-flight variant shown in View() while a
// tool is executing. Same shape as renderToolBlock but with a spinner-ish
// marker and partial output.
func renderLiveToolCard(c liveTool) string {
	symbol := terminal.SymbolFunction
	if c.name == "bash" {
		symbol = terminal.SymbolBash
	}
	header := styleToolName.Render(symbol+" "+c.name) + "  " + styleToolArgs.Render(oneLineArgs(c.args))
	if c.partial != "" {
		return header + "\n" + styleToolArgs.Render("  … "+truncateLines(c.partial, 4, 4))
	}
	return header + "  " + styleToolArgs.Render("…")
}

func oneLineArgs(args map[string]any) string {
	if len(args) == 0 {
		return ""
	}
	var parts []string
	for k, v := range args {
		val := fmt.Sprintf("%v", v)
		val = strings.ReplaceAll(val, "\n", " ")
		if len(val) > 80 {
			val = val[:77] + "…"
		}
		parts = append(parts, fmt.Sprintf("%s=%s", k, val))
	}
	return "(" + strings.Join(parts, "  ") + ")"
}

// truncateLines trims a tool output to a maximum number of lines so
// scrollback stays readable. Indents every line with indentSpaces so
// the result drops neatly under a card header. The full content remains
// in Engine history if the user asks for it.
func truncateLines(s string, maxLines, indentSpaces int) string {
	s = strings.TrimRight(s, "\n")
	if s == "" {
		return ""
	}
	lines := strings.Split(s, "\n")
	pad := strings.Repeat(" ", indentSpaces)
	var kept []string
	if len(lines) <= maxLines {
		kept = lines
	} else {
		kept = append(kept, lines[:maxLines]...)
		omitted := len(lines) - maxLines
		kept = append(kept, styleHint.Render(fmt.Sprintf("… (%d more line%s)", omitted, plural(omitted))))
	}
	for i := range kept {
		kept[i] = pad + kept[i]
	}
	// Trim the leading padding on the first line — it sits right after the
	// marker on the same row, so extra spaces would look wrong.
	kept[0] = strings.TrimLeft(kept[0], " ")
	return strings.Join(kept, "\n")
}

func indent(s, prefix string) string {
	lines := strings.Split(s, "\n")
	for i, l := range lines {
		lines[i] = prefix + l
	}
	return strings.Join(lines, "\n")
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

// Run starts the TUI loop. Blocks until the user quits.
// Inline mode (NO alt-screen) so scrollback and mouse selection work.
//
// If stdin has been piped into the process (e.g., `echo hi | vigolium
// agent olium`), the caller is expected to have already consumed the pipe
// and populated cfg.InitialPrompt. In that case stdin is no longer a
// tty, so we reopen /dev/tty for Bubble Tea's key input — otherwise the
// program would see EOF and exit immediately.
func Run(cfg Config) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cfg.quit = cancel

	opts := []tea.ProgramOption{tea.WithContext(ctx)}
	if fi, err := os.Stdin.Stat(); err == nil && (fi.Mode()&os.ModeCharDevice) == 0 {
		if tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0); err == nil {
			opts = append(opts, tea.WithInput(tty))
		}
	}
	p := tea.NewProgram(New(cfg), opts...)
	_, err := p.Run()
	// ErrProgramKilled is the expected outcome when ctrl+c cancels the
	// external context — not an error from the user's perspective.
	if errors.Is(err, tea.ErrProgramKilled) {
		return nil
	}
	return err
}
