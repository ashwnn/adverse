// Package antiforensic implements opt-in, best-effort removal of the execution
// traces the agent itself creates on a Windows host.
//
// HONEST TRADE-OFF — deletion is itself observable:
//
//   - Removing a Prefetch file, an MRU value, a BAM/DAM entry, or a temp copy
//     creates fresh USN journal records, changes MFT timestamps, and writes
//     registry hive transaction logs. An examiner can tell that cleanup ran
//     even when the artifact itself is gone.
//   - Defender/EDR may flag the scrub. Bulk deletes under %TEMP% and deletes
//     inside UserAssist/ComDlg32/BAM are common anti-forensic (and ransomware)
//     behaviors; this package uses ordinary user-mode registry and file APIs
//     and is not evasive.
//   - Kernel telemetry is unaffected. Event logs, ETW and ETW-TI, the USN
//     journal, MFT timestamps, and registry transaction logs are never
//     touched. Only the user-visible convenience artifacts listed below are
//     removed.
//
// Because the cleanup is itself a forensic indicator and may trip EDR, it is
// strictly opt-in (Config.Enabled) and intended for disposable lab hosts.
// Scrub never returns an error and never fails hard: every failure is recorded
// in Report.Skipped or Report.Errors and execution continues.
//
// Windows scope, identity-gated (only entries that reference the configured
// exe basename/path are touched):
//
//  1. %SystemRoot%\Prefetch\<exeBase>-*.pf
//  2. HKCU ...\Explorer\UserAssist\{GUID}\Count values whose ROT13-decoded
//     name references the exe
//  3. HKCU ...\Explorer\RecentDocs and ...\Explorer\ComDlg32 MRU values
//     (RecentDocs, OpenSavePidlMRU, LastVisitedPidlMRU) whose name or raw data
//     references the exe
//  4. HKLM SYSTEM\CurrentControlSet\Services\bam (and dam)\State\UserSettings
//     values whose name references the exe; normally requires admin
//  5. %TEMP% files whose name starts with the exe basename, excluding the
//     running executable itself
//
// No other directory or registry location is enumerated, and nothing whose
// name does not match the configured exe is deleted. On non-Windows platforms
// Scrub is a no-op.
package antiforensic
