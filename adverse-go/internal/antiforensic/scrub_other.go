//go:build !windows

package antiforensic

// scrub is a no-op on non-Windows platforms: the trace surface documented in
// this package is Windows-specific. Even when Enabled is set, the call is
// inert and returns an empty Report.
func scrub(cfg Config) Report {
	_ = cfg
	return Report{}
}
