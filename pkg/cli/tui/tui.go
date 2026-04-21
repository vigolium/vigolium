// Package tui provides a reusable list picker for CLI list subcommands.
//
// It wraps bubbletea/bubbles/list to render a scrollable/filterable list of
// items with arrow-key navigation, `/` filter (built-in), `c` to copy the
// selected item's ID to the system clipboard, `enter` to return the
// selection to the caller, and `q`/`ctrl+c` to quit without selecting.
//
// The caller is responsible for rendering the detail view after the TUI
// exits — this package does not show details itself.
package tui

import (
	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/list"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// Theme: green is the primary accent (selection, title bar, filter cursor,
// status flash). Blue is the secondary accent (descriptions, counts).
var (
	primaryColor   = lipgloss.Color("10")  // bright green — primary accent
	primaryBg      = lipgloss.Color("10")  // bright green — title bar background
	titleFg        = lipgloss.Color("0")   // black — title text on bright green bg
	secondaryColor = lipgloss.Color("12")  // bright blue — secondary accent
	mutedColor     = lipgloss.Color("241") // soft gray
	errorColor     = lipgloss.Color("196") // red — copy/clipboard errors

	flashStyle    = lipgloss.NewStyle().Foreground(primaryColor).Bold(true)
	flashErrStyle = lipgloss.NewStyle().Foreground(errorColor).Bold(true)
)

// Item is a selectable row. ID is what `c` copies and what is returned to
// the caller when the user selects the row. TitleText and DescText are
// shown in the list; FilterText (optional) is matched by `/`.
type Item struct {
	ID         string
	TitleText  string
	DescText   string
	FilterText string
}

// Title implements list.DefaultItem.
func (i Item) Title() string { return i.TitleText }

// Description implements list.DefaultItem.
func (i Item) Description() string { return i.DescText }

// FilterValue implements list.Item.
func (i Item) FilterValue() string {
	if i.FilterText != "" {
		return i.FilterText
	}
	return i.TitleText + " " + i.DescText
}

// ListConfig configures a list session.
type ListConfig struct {
	Title string
	Items []Item
}

// Result carries the outcome of a list session.
type Result struct {
	// SelectedID is set to the chosen item's ID if the user pressed enter.
	// Empty when the user quit without selecting.
	SelectedID string
}

type listModel struct {
	list       list.Model
	selectedID string
}

func (m listModel) Init() tea.Cmd { return nil }

func (m listModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.list.SetSize(msg.Width, msg.Height)
		return m, nil

	case tea.KeyMsg:
		// Let list own every keystroke while the user is typing in the filter.
		if m.list.FilterState() == list.Filtering {
			var cmd tea.Cmd
			m.list, cmd = m.list.Update(msg)
			return m, cmd
		}
		switch msg.String() {
		case "q", "ctrl+c":
			return m, tea.Quit
		case "c":
			it, ok := m.list.SelectedItem().(Item)
			if !ok || it.ID == "" {
				return m, nil
			}
			if err := copyToClipboard(it.ID); err != nil {
				return m, m.list.NewStatusMessage(flashErrStyle.Render("copy failed: " + err.Error()))
			}
			return m, m.list.NewStatusMessage(flashStyle.Render("copied " + it.ID))
		case "enter":
			if it, ok := m.list.SelectedItem().(Item); ok && it.ID != "" {
				m.selectedID = it.ID
				return m, tea.Quit
			}
			return m, nil
		}
	}

	var cmd tea.Cmd
	m.list, cmd = m.list.Update(msg)
	return m, cmd
}

func (m listModel) View() string { return m.list.View() }

// newDelegate returns a list delegate styled with the green/blue theme:
// green accents the selected row (left border, title, filter match),
// blue accents descriptions.
func newDelegate() list.DefaultDelegate {
	d := list.NewDefaultDelegate()

	d.Styles.NormalTitle = d.Styles.NormalTitle.Foreground(lipgloss.Color("252"))
	d.Styles.NormalDesc = d.Styles.NormalDesc.Foreground(secondaryColor)

	d.Styles.SelectedTitle = d.Styles.SelectedTitle.
		Foreground(primaryColor).
		BorderForeground(primaryColor).
		Bold(true)
	d.Styles.SelectedDesc = d.Styles.SelectedDesc.
		Foreground(secondaryColor).
		BorderForeground(primaryColor)

	d.Styles.DimmedTitle = d.Styles.DimmedTitle.Foreground(mutedColor)
	d.Styles.DimmedDesc = d.Styles.DimmedDesc.Foreground(mutedColor)

	d.Styles.FilterMatch = d.Styles.FilterMatch.
		Foreground(primaryColor).
		Underline(true)

	return d
}

// themedListStyles overrides the list.Model styles with the green/blue
// theme for title bar, status bar, filter prompt, and status flash.
func themedListStyles() list.Styles {
	s := list.DefaultStyles()

	s.Title = s.Title.
		Background(primaryBg).
		Foreground(titleFg).
		Bold(true)

	s.StatusBar = s.StatusBar.Foreground(secondaryColor)
	s.StatusEmpty = s.StatusEmpty.Foreground(mutedColor)
	s.StatusBarActiveFilter = s.StatusBarActiveFilter.Foreground(primaryColor).Bold(true)
	s.StatusBarFilterCount = s.StatusBarFilterCount.Foreground(secondaryColor)

	s.FilterPrompt = s.FilterPrompt.Foreground(primaryColor)
	s.FilterCursor = s.FilterCursor.Foreground(primaryColor)
	s.DefaultFilterCharacterMatch = s.DefaultFilterCharacterMatch.Foreground(primaryColor).Underline(true)

	s.ActivePaginationDot = s.ActivePaginationDot.Foreground(primaryColor)
	s.InactivePaginationDot = s.InactivePaginationDot.Foreground(mutedColor)

	s.DividerDot = s.DividerDot.Foreground(mutedColor)
	s.HelpStyle = s.HelpStyle.Foreground(mutedColor)

	return s
}

// RunList displays the list picker and blocks until the user quits or
// selects an item. On selection, returns the chosen ID. On quit, returns
// an empty ID.
func RunList(cfg ListConfig) (Result, error) {
	items := make([]list.Item, len(cfg.Items))
	for i, it := range cfg.Items {
		items[i] = it
	}

	l := list.New(items, newDelegate(), 0, 0)
	l.Title = cfg.Title
	l.Styles = themedListStyles()
	l.SetStatusBarItemName("item", "items")
	l.AdditionalShortHelpKeys = func() []key.Binding {
		return []key.Binding{
			key.NewBinding(key.WithKeys("enter"), key.WithHelp("enter", "view")),
			key.NewBinding(key.WithKeys("c"), key.WithHelp("c", "copy id")),
		}
	}
	l.AdditionalFullHelpKeys = l.AdditionalShortHelpKeys

	m := listModel{list: l}
	p := tea.NewProgram(m, tea.WithAltScreen())
	final, err := p.Run()
	if err != nil {
		return Result{}, err
	}
	if lm, ok := final.(listModel); ok {
		return Result{SelectedID: lm.selectedID}, nil
	}
	return Result{}, nil
}
