// Package hygiene applies best-effort execution hygiene to the agent process.
//
// On Windows, Apply suppresses interactive critical-error, general-protection-
// fault, and missing-file dialogs and hides an attached console window. On
// other platforms it is a no-op.
//
// Apply never panics and never returns an error. It does not spawn any process
// and does not require administrative privileges.
package hygiene
