// Package memlimit derives and applies a soft Go heap ceiling (GOMEMLIMIT) for
// scan processes, so the garbage collector reclaims aggressively as the heap
// approaches the limit instead of letting it grow until the OS OOM-killer fires
// (a hard kill rather than a slowdown). The limit is auto-sized from the
// machine's usable RAM (respecting any cgroup memory limit) and the
// -P/--parallel fan-out, applied via runtime/debug.SetMemoryLimit, and exported
// into the environment so child scan processes inherit it automatically.
package memlimit

import (
	"math"
	"os"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"

	"github.com/dustin/go-humanize"
	"github.com/shirou/gopsutil/v4/mem"
)

const (
	// flatFraction caps a single scan process at ~1/3 of usable RAM — the
	// conservative default when running alone or with low parallelism.
	flatFraction = 1.0 / 3.0
	// aggregateFraction caps the COMBINED footprint of all parallel scan
	// processes at ~2/3 of usable RAM, leaving the remainder for the OS, page
	// cache, and the headless browser's substantial out-of-heap memory.
	aggregateFraction = 2.0 / 3.0
	// minTotalRAM is the smallest machine we will auto-cap. Below this a 1/3
	// ceiling risks GC thrash for little OOM benefit, so we stay unbounded.
	minTotalRAM = 2 << 30 // 2 GiB
	// minAutoLimit floors the auto limit so a high -P can't compute a
	// pathologically tight ceiling.
	minAutoLimit = 512 << 20 // 512 MiB
	// unlimited mirrors the runtime's "no limit" sentinel.
	unlimited = math.MaxInt64
)

// Options configure Apply.
type Options struct {
	// Override is the raw --mem-limit value:
	//   ""                 → auto (min of 1/3 RAM and 2/3 RAM ÷ Parallelism)
	//   "off"/"none"/"0"   → disable (no ceiling)
	//   "6GiB", "8G", ...  → explicit per-process size (verbatim, not ÷P)
	//   "50%"              → explicit per-process percentage of RAM (not ÷P)
	Override string
	// Parallelism is the number of concurrent scan processes (-P). Used only in
	// auto mode, to keep the combined footprint under aggregateFraction.
	Parallelism int
}

// Result describes the outcome of Apply, for operator logging.
type Result struct {
	LimitBytes int64  // active soft limit; unlimited (math.MaxInt64) means no ceiling
	Changed    bool   // Apply set or changed the limit this call
	Disabled   bool   // the ceiling is explicitly disabled
	Note       string // one-line human summary (empty when there is nothing to report)
}

// DetectRAM returns usable RAM in bytes and its source. On Linux it takes the
// smaller of physical RAM and any cgroup memory limit, so container limits are
// respected; elsewhere it returns physical RAM.
func DetectRAM() (uint64, string) {
	phys := physicalRAM()
	if cg, ok := cgroupLimit(); ok && cg > 0 && (phys == 0 || cg < phys) {
		return cg, "cgroup"
	}
	return phys, "physical"
}

func physicalRAM() uint64 {
	if vm, err := mem.VirtualMemory(); err == nil && vm != nil && vm.Total > 0 {
		return vm.Total
	}
	return 0
}

// cgroupLimit reads the container memory limit on Linux (cgroup v2 then v1),
// returning ok=false when there is no real limit set.
func cgroupLimit() (uint64, bool) {
	if runtime.GOOS != "linux" {
		return 0, false
	}
	// cgroup v2: a numeric byte count, or the literal "max" for unlimited.
	if b, err := os.ReadFile("/sys/fs/cgroup/memory.max"); err == nil {
		s := strings.TrimSpace(string(b))
		if s != "" && s != "max" {
			if v, err := strconv.ParseUint(s, 10, 64); err == nil && v > 0 && v < unlimited {
				return v, true
			}
		}
	}
	// cgroup v1: a byte count; "unlimited" is encoded as a near-maxint sentinel.
	if b, err := os.ReadFile("/sys/fs/cgroup/memory/memory.limit_in_bytes"); err == nil {
		s := strings.TrimSpace(string(b))
		if v, err := strconv.ParseUint(s, 10, 64); err == nil && v > 0 && v < (1<<62) {
			return v, true
		}
	}
	return 0, false
}

// autoLimit computes the per-process soft limit from total RAM and parallelism.
// Returns 0 when the machine is too small to cap safely.
func autoLimit(total uint64, parallelism int) int64 {
	if total < minTotalRAM {
		return 0
	}
	if parallelism < 1 {
		parallelism = 1
	}
	flat := float64(total) * flatFraction
	agg := (float64(total) * aggregateFraction) / float64(parallelism)
	v := int64(math.Min(flat, agg))
	if v < minAutoLimit {
		v = minAutoLimit
	}
	return v
}

// Apply derives the soft heap ceiling from opts, sets it on the runtime, and
// exports GOMEMLIMIT so child scan processes inherit it. An explicit GOMEMLIMIT
// already in the environment (set by the user or an ancestor) always wins and is
// left untouched. The returned Result is safe to log verbatim.
func Apply(opts Options) Result {
	// An explicit GOMEMLIMIT (user or ancestor scan process) always wins: the
	// runtime already applied it at startup, so we only read it back.
	if _, ok := os.LookupEnv("GOMEMLIMIT"); ok {
		cur := debug.SetMemoryLimit(-1) // negative input reads without changing
		if cur >= unlimited {
			return Result{LimitBytes: unlimited, Disabled: true, Note: "GOMEMLIMIT=off (inherited) — no heap ceiling"}
		}
		return Result{LimitBytes: cur, Note: "GOMEMLIMIT=" + humanize.IBytes(uint64(cur)) + " (inherited)"}
	}

	total, src := DetectRAM()
	ov := strings.ToLower(strings.TrimSpace(opts.Override))

	// Explicit disable.
	switch ov {
	case "off", "none", "no", "disable", "disabled", "0":
		_ = os.Setenv("GOMEMLIMIT", "off") // propagate the opt-out to children
		return Result{LimitBytes: unlimited, Disabled: true,
			Note: "heap ceiling disabled (--mem-limit off)"}
	}

	var (
		limit int64
		note  string
	)
	switch {
	case ov == "":
		limit = autoLimit(total, opts.Parallelism)
		if limit <= 0 {
			// Machine too small or RAM undetectable: stay unbounded, quietly.
			return Result{}
		}
		note = "heap ceiling " + humanize.IBytes(uint64(limit)) + " (auto from " + humanize.IBytes(total) + " " + src + " RAM"
		if p := opts.Parallelism; p > 1 {
			note += ", ÷" + strconv.Itoa(p) + " parallel"
		}
		note += ")"

	case strings.HasSuffix(ov, "%"):
		pct, err := strconv.ParseFloat(strings.TrimSpace(strings.TrimSuffix(ov, "%")), 64)
		if err != nil || pct <= 0 || total == 0 {
			return Result{Note: "ignored --mem-limit " + opts.Override + " (invalid percent or RAM undetected)"}
		}
		limit = int64(float64(total) * pct / 100.0)
		note = "heap ceiling " + humanize.IBytes(uint64(limit)) + " (" + opts.Override + " of " + humanize.IBytes(total) + " " + src + " RAM)"

	default:
		b, err := humanize.ParseBytes(opts.Override)
		if err != nil || b == 0 {
			return Result{Note: "ignored --mem-limit " + opts.Override + " (unparseable; use e.g. 6GiB, 50%, or off)"}
		}
		limit = int64(b)
		note = "heap ceiling " + humanize.IBytes(b) + " (--mem-limit " + opts.Override + ")"
	}

	debug.SetMemoryLimit(limit)
	_ = os.Setenv("GOMEMLIMIT", strconv.FormatInt(limit, 10)) // bytes; inherited by child scan processes
	return Result{LimitBytes: limit, Changed: true, Note: note}
}
