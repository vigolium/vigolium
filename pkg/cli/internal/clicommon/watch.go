package clicommon

import (
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/vigolium/vigolium/pkg/terminal"
)

// ParseWatchInterval parses a --watch value. Bare integers (e.g. "5") are
// treated as seconds; otherwise standard Go duration syntax is used (5s, 1m, 1h).
// An empty value yields a zero duration (watch disabled).
func ParseWatchInterval(raw string) (time.Duration, error) {
	if raw == "" {
		return 0, nil
	}
	// Bare integer → treat as seconds
	if n, err := strconv.Atoi(raw); err == nil {
		return time.Duration(n) * time.Second, nil
	}
	return time.ParseDuration(raw)
}

// RunWithWatch runs fn once, then repeats it every watchRaw interval if set.
// It clears the screen between iterations and exits on Ctrl+C.
func RunWithWatch(watchRaw string, fn func() error) error {
	if err := fn(); err != nil {
		return err
	}

	interval, err := ParseWatchInterval(watchRaw)
	if err != nil {
		return fmt.Errorf("invalid --watch value %q: %w", watchRaw, err)
	}
	if interval <= 0 {
		return nil
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigChan)

	for {
		select {
		case <-sigChan:
			return nil
		case <-time.After(interval):
			// Clear screen and move cursor to top-left
			fmt.Print("\033[2J\033[H")
			fmt.Printf("%s Refreshed at %s (every %s, Ctrl+C to stop)\n\n",
				terminal.InfoSymbol(),
				terminal.Gray(time.Now().Format("15:04:05")),
				terminal.Cyan(interval.String()))
			if err := fn(); err != nil {
				return err
			}
		}
	}
}
