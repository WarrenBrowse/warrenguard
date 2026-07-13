//! Persistent state on the Warren exit side - multi-client persistence.
//!
//! Without persistence, every restart of the exit process (deploy, kernel
//! upgrade, OOM, etc.) **breaks all clients**: their tunnel IPs are
//! re-allocated to others, NAT state on the exit is lost, in-flight TCP
//! connections time out. Unacceptable for production.
//!
//! This module saves the live session map to disk as JSON. On restart
//! no connection survives the process, so the loaded entries become
//! **sticky hints** in the IP allocators: a reconnecting client gets
//! its previous tunnel IP back as long as that address is still free,
//! and every persisted address stays allocatable (no permanently
//! burned offsets - the pre-v2 monotonic counter is gone).
//!
//! ## JSON format (version 2)
//!
//! ```json
//! {
//!   "version": 2,
//!   "sessions": {
//!     "<pubkey_hex_64>:<device_id_hex_32>": { "ipv4": "10.66.0.2", "max_mtu": 1350, "total": 32 }
//!   }
//! }
//! ```
//!
//! Version 1 files (which additionally carried `allocator_next` /
//! `allocator_next_v6` counters) load transparently: the counters are
//! ignored (nothing to burn) and the sessions become hints.
//!
//! `WarrenPubkey` is serialized as **hex 64 chars** (32 bytes = Ed25519
//! pubkey). This allows human inspection and manual edits when needed
//! (e.g. recycling the IP of a banned client).
//!
//! ## Atomicity
//!
//! `save_atomic` writes to a sibling tmpfile then renames - no
//! corruption on SIGKILL during the write (POSIX rename(2) is atomic).
//! Guaranteed on Linux ext4 and macOS APFS.
//!
//! ## Versioning
//!
//! The `version` field allows evolving the JSON format without breaking
//! existing deployments. On any schema change: bump the version, then
//! either migrate the older versions (preferred, cf. the v1 -> v2 hint
//! migration) or reject them with an explicit log.

use std::collections::HashMap;
use std::io::Write;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use serde::{Deserialize, Serialize};
use tokio::sync::Mutex as AsyncMutex;
use warrenguard_wire::WarrenPubkey;

use crate::exit::{MultiSessionState, SessionKey};
use warrenguard_transport_core::error::{Result, TunnelError};

/// Shared live-session map type persisted by [`StatePersister`].
type SharedSessions = Arc<AsyncMutex<HashMap<SessionKey, MultiSessionState>>>;

/// Minimum interval between two state-file writes.
const SAVE_DEBOUNCE: std::time::Duration = std::time::Duration::from_secs(1);

/// Debounced, off-thread persister for the exit session state.
///
/// The previous design snapshotted the whole session map under the
/// handshake lock and ran `save_atomic` (write + fsync, sync I/O)
/// inline in the async handshake path: every churning client paid an
/// O(N) clone plus a disk fsync. The persister decouples that:
///
/// - [`Self::request_save`] is O(1) (flag + wakeup), callable from any
///   path that mutates the session map.
/// - A background task coalesces requests to **at most one write per
///   second**; the LAST state wins (the snapshot is taken from the
///   live map at write time, not at request time).
/// - The blocking write + fsync runs on the `spawn_blocking` pool,
///   never on the async runtime workers.
/// - On drop (graceful shutdown), a pending request is flushed
///   best-effort so at most the final debounce window is lost.
pub(crate) struct StatePersister {
    path: PathBuf,
    sessions: SharedSessions,
    dirty: Arc<AtomicBool>,
    notify: Arc<tokio::sync::Notify>,
    saves_performed: Arc<AtomicU64>,
    task: tokio::task::JoinHandle<()>,
}

impl StatePersister {
    /// Spawns the background saver task. `sessions` is the live map the
    /// snapshots are taken from.
    pub(crate) fn spawn(path: PathBuf, sessions: SharedSessions) -> Self {
        let dirty = Arc::new(AtomicBool::new(false));
        let notify = Arc::new(tokio::sync::Notify::new());
        let saves_performed = Arc::new(AtomicU64::new(0));

        let task = {
            let path = path.clone();
            let sessions = sessions.clone();
            let dirty = dirty.clone();
            let notify = notify.clone();
            let saves_performed = saves_performed.clone();
            tokio::spawn(async move {
                loop {
                    notify.notified().await;
                    while dirty.swap(false, Ordering::AcqRel) {
                        save_snapshot_blocking(&path, &sessions, &saves_performed).await;
                        // Debounce window: coalesce every request that
                        // lands during this sleep into one trailing
                        // write (last state wins).
                        tokio::time::sleep(SAVE_DEBOUNCE).await;
                    }
                }
            })
        };

        Self {
            path,
            sessions,
            dirty,
            notify,
            saves_performed,
            task,
        }
    }

    /// Marks the state dirty and wakes the saver. O(1), never blocks,
    /// never performs I/O on the caller's task.
    pub(crate) fn request_save(&self) {
        self.dirty.store(true, Ordering::Release);
        self.notify.notify_one();
    }

    /// Number of state-file writes performed so far (test/ops gauge).
    #[cfg(test)]
    pub(crate) fn saves_performed(&self) -> u64 {
        self.saves_performed.load(Ordering::Relaxed)
    }
}

/// Snapshot the live map (brief async lock) then write it on the
/// blocking pool. Errors are logged, never propagated: persistence is
/// best-effort and must not take the handshake path down.
async fn save_snapshot_blocking(
    path: &Path,
    sessions: &SharedSessions,
    saves_performed: &Arc<AtomicU64>,
) {
    let snap = {
        let map = sessions.lock().await;
        PersistedState::from_runtime(&map)
    };
    saves_performed.fetch_add(1, Ordering::Relaxed);
    let path = path.to_path_buf();
    let res = tokio::task::spawn_blocking(move || {
        let shown_path = path.display().to_string();
        (snap.save_atomic(&path), shown_path)
    })
    .await;
    match res {
        Ok((Ok(()), _)) => {}
        Ok((Err(e), shown_path)) => {
            tracing::warn!(error = %e, path = %shown_path, "failed to persist exit state - continuing");
        }
        Err(e) => {
            tracing::warn!(error = %e, "exit state save task panicked - continuing");
        }
    }
}

impl Drop for StatePersister {
    fn drop(&mut self) {
        self.task.abort();
        // Best-effort shutdown flush: if a request is still pending,
        // write it synchronously so a graceful shutdown loses at most
        // nothing (an abrupt kill loses at most the last debounce
        // window). `try_lock` because Drop cannot await; under
        // contention we skip rather than block shutdown.
        if self.dirty.swap(false, Ordering::AcqRel) {
            match self.sessions.try_lock() {
                Ok(map) => {
                    let snap = PersistedState::from_runtime(&map);
                    drop(map);
                    self.saves_performed.fetch_add(1, Ordering::Relaxed);
                    if let Err(e) = snap.save_atomic(&self.path) {
                        tracing::warn!(error = %e, path = %self.path.display(), "shutdown flush of exit state failed");
                    }
                }
                Err(_) => {
                    tracing::warn!(
                        path = %self.path.display(),
                        "shutdown flush of exit state skipped (sessions lock contended)"
                    );
                }
            }
        }
    }
}

/// Current JSON schema version.
pub(crate) const STATE_VERSION: u32 = 2;

/// Oldest schema version this build still loads (soft migration: the
/// v1 allocator counters are ignored, the v1 sessions become hints).
pub(crate) const STATE_VERSION_MIN: u32 = 1;

/// Persistent snapshot of the exit state.
///
/// Version 1 files carried `allocator_next` / `allocator_next_v6`
/// counters for the pre-recycling monotonic allocators; those fields
/// are now ignored on load (serde skips unknown fields) and no longer
/// written.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct PersistedState {
    pub(crate) version: u32,
    /// Sessions indexed by `<pubkey_hex>:<device_id_hex>`. Loaded
    /// entries become sticky hints, never live sessions (no connection
    /// survives a restart).
    #[serde(default)]
    pub(crate) sessions: HashMap<String, PersistedSession>,
}

/// Serializable active session. Mirror of `MultiSessionState` flattened
/// for JSON.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct PersistedSession {
    pub(crate) ipv4: Ipv4Addr,
    /// Optional IPv6. Absent from JSON for sessions without
    /// `features::IPV6`.
    #[serde(default)]
    pub(crate) ipv6: Option<Ipv6Addr>,
    pub(crate) max_mtu: u16,
    pub(crate) total: u8,
    /// Per-run device id (16 bytes as 32 lowercase hex chars), part of
    /// the v2 session key `(pubkey, device_id)`. Absent in pre-v2 state
    /// files; such legacy records carry no device dimension and are
    /// skipped on load (a reconnecting client re-establishes its session
    /// on a fresh device id).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) device_id_hex: Option<String>,
}

impl PersistedState {
    /// Empty state (= fresh start).
    pub(crate) fn empty() -> Self {
        Self {
            version: STATE_VERSION,
            sessions: HashMap::new(),
        }
    }

    /// Load from disk, or return `empty()` if the file is absent /
    /// corrupt / version-incompatible. **Never panics** - a corrupt
    /// state must be tolerable (warn log + start fresh) rather than
    /// preventing the exit from starting.
    ///
    /// # Errors
    ///
    /// None. All error cases fall back to `empty()` with an explicit
    /// warn log (reason + path).
    pub(crate) fn load_or_default(path: &Path) -> Self {
        if !path.exists() {
            tracing::info!(path = %path.display(), "no state file - starting fresh");
            return Self::empty();
        }
        let data = match std::fs::read_to_string(path) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(error = %e, path = %path.display(), "state file unreadable - starting fresh");
                return Self::empty();
            }
        };
        let parsed: Self = match serde_json::from_str(&data) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(error = %e, path = %path.display(), "state file corrupt JSON - starting fresh");
                return Self::empty();
            }
        };
        if parsed.version < STATE_VERSION_MIN || parsed.version > STATE_VERSION {
            tracing::warn!(
                file_version = parsed.version,
                supported_min = STATE_VERSION_MIN,
                supported_max = STATE_VERSION,
                "state file version unsupported - starting fresh"
            );
            return Self::empty();
        }
        tracing::info!(
            path = %path.display(),
            file_version = parsed.version,
            sessions_count = parsed.sessions.len(),
            "loaded state from disk"
        );
        parsed
    }

    /// Atomic save: writes to `<path>.tmp` then renames - no corrupt
    /// file if SIGKILL hits during the write.
    ///
    /// # Errors
    ///
    /// I/O error (disk full, perm denied, etc.) or JSON serialize
    /// error (in practice should not happen for our simple struct).
    pub(crate) fn save_atomic(&self, path: &Path) -> Result<()> {
        let tmp_path: PathBuf = {
            let mut p = path.to_path_buf();
            let mut name = p
                .file_name()
                .ok_or_else(|| {
                    TunnelError::Internal(format!(
                        "state path has no file name: {}",
                        path.display()
                    ))
                })?
                .to_os_string();
            name.push(".tmp");
            p.set_file_name(name);
            p
        };

        // Create the parent dir if absent (typical at first save).
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent).map_err(|source| TunnelError::Fs {
                path: parent.display().to_string(),
                source,
            })?;
        }

        let json = serde_json::to_string_pretty(self)
            .map_err(|e| TunnelError::Internal(format!("serialize PersistedState failed: {e}")))?;
        let mut f = std::fs::File::create(&tmp_path).map_err(|source| TunnelError::Fs {
            path: tmp_path.display().to_string(),
            source,
        })?;
        f.write_all(json.as_bytes())
            .map_err(|source| TunnelError::Fs {
                path: tmp_path.display().to_string(),
                source,
            })?;
        f.sync_all().map_err(|source| TunnelError::Fs {
            path: tmp_path.display().to_string(),
            source,
        })?;
        drop(f);

        std::fs::rename(&tmp_path, path).map_err(|source| TunnelError::Fs {
            path: format!("{} -> {}", tmp_path.display(), path.display()),
            source,
        })?;
        Ok(())
    }

    /// Convert the string-keyed HashMap into `(pubkey, device_id)`
    /// sticky hints for the IP allocators. No connection survives a
    /// restart, so persisted sessions are never resurrected as live
    /// map entries: they only bias the allocators so a reconnecting
    /// device lands back on its previous tunnel IPs (best-effort).
    ///
    /// Legacy records (no `device_id_hex`) carry no device dimension
    /// and are **skipped**: there is no safe `device_id` to key them
    /// by, and a reconnecting client simply re-establishes its session
    /// under a fresh device id (losing only the sticky IP across the
    /// one-time upgrade restart).
    pub(crate) fn into_sticky_hints(
        self,
    ) -> Vec<(super::exit::SessionKey, Ipv4Addr, Option<Ipv6Addr>)> {
        let mut hints = Vec::with_capacity(self.sessions.len());
        for (key, session) in self.sessions {
            // The JSON map key is the pubkey hex. The device id travels
            // in the value (`device_id_hex`), so two devices of one
            // account are distinguished by a unique composite JSON key
            // `<pubkey_hex>:<device_id_hex>` written by `from_runtime`.
            // Tolerate a bare pubkey key (legacy / hand-edited) by
            // taking the part before the first `:`.
            let pubkey_part = key.split(':').next().unwrap_or(&key);
            let pk = match pubkey_from_hex(pubkey_part) {
                Ok(pk) => pk,
                Err(e) => {
                    tracing::warn!(
                        key_prefix = %warrenguard_config::log_prefix(pubkey_part),
                        error = %e,
                        "invalid pubkey in state file - skipping"
                    );
                    continue;
                }
            };
            let Some(device_id_hex) = session.device_id_hex.as_deref() else {
                tracing::info!(
                    key_prefix = %warrenguard_config::log_prefix(pubkey_part),
                    "legacy session record without device_id - skipping (v2 upgrade)"
                );
                continue;
            };
            let device_id = match device_id_from_hex(device_id_hex) {
                Ok(id) => id,
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        "invalid device_id hex in state file - skipping"
                    );
                    continue;
                }
            };
            hints.push(((pk, device_id), session.ipv4, session.ipv6));
        }
        hints
    }

    /// Inverse: from the live session map, build a persistable snapshot.
    pub(crate) fn from_runtime(
        sessions: &HashMap<super::exit::SessionKey, super::exit::MultiSessionState>,
    ) -> Self {
        let mut out = HashMap::with_capacity(sessions.len());
        for ((pk, device_id), state) in sessions {
            let device_id_hex = hex::encode(device_id);
            // Composite JSON key `<pubkey_hex>:<device_id_hex>` so two
            // devices of one account do not collide on the pubkey hex.
            let json_key = format!("{}:{}", pk.to_hex(), device_id_hex);
            out.insert(
                json_key,
                PersistedSession {
                    ipv4: state.ipv4,
                    ipv6: state.ipv6,
                    max_mtu: state.max_mtu,
                    total: state.total,
                    device_id_hex: Some(device_id_hex),
                },
            );
        }
        Self {
            version: STATE_VERSION,
            sessions: out,
        }
    }
}

/// Deserialize 32 hex chars (16 bytes) into a `device_id` array.
fn device_id_from_hex(s: &str) -> Result<[u8; warrenguard_wire::DEVICE_ID_LEN]> {
    let bytes = hex::decode(s)
        .map_err(|e| TunnelError::Internal(format!("device_id hex decode failed: {e}")))?;
    bytes.try_into().map_err(|v: Vec<u8>| {
        TunnelError::Internal(format!(
            "device_id must be {} bytes, got {}",
            warrenguard_wire::DEVICE_ID_LEN,
            v.len()
        ))
    })
}

/// Deserialize 64 hex chars into a `WarrenPubkey`.
fn pubkey_from_hex(s: &str) -> Result<WarrenPubkey> {
    WarrenPubkey::from_hex(s).map_err(|e| TunnelError::PubkeyHex(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use warrenguard_wire::DEVICE_ID_LEN;

    fn key(pk_byte: u8, dev_byte: u8) -> super::super::exit::SessionKey {
        (
            WarrenPubkey::from_bytes([pk_byte; 32]),
            [dev_byte; DEVICE_ID_LEN],
        )
    }

    #[test]
    fn empty_state_has_current_version_and_no_sessions() {
        let s = PersistedState::empty();
        assert_eq!(s.version, STATE_VERSION);
        assert!(s.sessions.is_empty());
    }

    #[test]
    fn load_from_missing_file_returns_empty() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("no-such-file.json");
        let s = PersistedState::load_or_default(&path);
        assert!(s.sessions.is_empty());
    }

    #[test]
    fn load_from_corrupt_file_returns_empty() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("corrupt.json");
        std::fs::write(&path, "not valid json {{{").expect("write");
        let s = PersistedState::load_or_default(&path);
        assert!(s.sessions.is_empty(), "corrupt file -> fresh state");
    }

    #[test]
    fn load_from_unsupported_version_returns_empty() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("future-version.json");
        std::fs::write(
            &path,
            r#"{"version": 999, "sessions": {"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": {"ipv4": "10.66.0.5", "max_mtu": 1350, "total": 1}}}"#,
        )
        .expect("write");
        let s = PersistedState::load_or_default(&path);
        assert!(
            s.sessions.is_empty(),
            "unsupported future version -> start fresh, never guess at the schema"
        );
    }

    #[test]
    fn v1_state_file_loads_sessions_as_hints_and_ignores_burned_counters() {
        // Soft migration: a v1 file written by the pre-recycling exit
        // carries monotonic allocator counters. Even a fully-burned
        // counter (allocator_next = 65535 = permanent exhaustion under
        // the old allocator) must NOT poison the new pool: the counters
        // are ignored and the sessions become reconnect hints.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("v1-state.json");
        let pk_hex = "a".repeat(64);
        let dev_hex = "ab".repeat(16);
        std::fs::write(
            &path,
            format!(
                r#"{{"version": 1, "allocator_next": 65535, "allocator_next_v6": 99,
                     "sessions": {{"{pk_hex}:{dev_hex}":
                       {{"ipv4": "10.66.0.7", "max_mtu": 1350, "total": 1,
                         "device_id_hex": "{dev_hex}"}}}}}}"#
            ),
        )
        .expect("write");

        let s = PersistedState::load_or_default(&path);
        assert_eq!(s.version, 1, "v1 must load, not start fresh");
        let hints = s.into_sticky_hints();
        assert_eq!(hints.len(), 1, "the v1 session must become a hint");
        let (hint_key, v4, v6) = &hints[0];
        assert_eq!(
            *hint_key,
            (WarrenPubkey::from_bytes([0xaa; 32]), [0xab; 16])
        );
        assert_eq!(*v4, Ipv4Addr::new(10, 66, 0, 7));
        assert_eq!(*v6, None);
    }

    #[test]
    fn save_atomic_then_load_roundtrip() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("state.json");

        let original = PersistedState {
            version: STATE_VERSION,
            sessions: HashMap::from([(
                "a".repeat(64),
                PersistedSession {
                    ipv4: Ipv4Addr::new(10, 66, 0, 5),
                    ipv6: Some(Ipv6Addr::new(0xfdcc, 0xf, 1, 0, 0, 0, 0, 5)),
                    max_mtu: 1350,
                    total: 32,
                    device_id_hex: Some("ab".repeat(16)),
                },
            )]),
        };
        original.save_atomic(&path).expect("save");
        assert!(path.exists());

        let loaded = PersistedState::load_or_default(&path);
        assert_eq!(loaded.version, STATE_VERSION);
        assert_eq!(loaded.sessions.len(), 1);
        let s = loaded
            .sessions
            .get("a".repeat(64).as_str())
            .expect("session present");
        assert_eq!(s.ipv4, Ipv4Addr::new(10, 66, 0, 5));
        assert_eq!(s.ipv6, Some(Ipv6Addr::new(0xfdcc, 0xf, 1, 0, 0, 0, 0, 5)));
        assert_eq!(s.max_mtu, 1350);
        assert_eq!(s.total, 32);
        assert_eq!(s.device_id_hex.as_deref(), Some("ab".repeat(16).as_str()));
    }

    #[test]
    fn from_runtime_then_into_hints_preserves_device_id_key() {
        // Two devices of one account must survive a persist/reload
        // round-trip as two DISTINCT `(pubkey, device_id)` hints on
        // two distinct IPs, not collapse onto the pubkey hex.
        let (pk, dev_a) = key(0x11, 0xAA);
        let dev_b = [0xBBu8; DEVICE_ID_LEN];
        let mut sessions = HashMap::new();
        sessions.insert(
            (pk, dev_a),
            super::super::exit::MultiSessionState {
                ipv4: Ipv4Addr::new(10, 66, 0, 2),
                ipv6: None,
                max_mtu: 1350,
                total: 1,
                daita_spec: None,
                token_serial: None,
            },
        );
        sessions.insert(
            (pk, dev_b),
            super::super::exit::MultiSessionState {
                ipv4: Ipv4Addr::new(10, 66, 0, 3),
                ipv6: None,
                max_mtu: 1350,
                total: 1,
                daita_spec: None,
                token_serial: None,
            },
        );

        let snap = PersistedState::from_runtime(&sessions);
        assert_eq!(snap.sessions.len(), 2, "both devices must persist");

        let hints = snap.into_sticky_hints();
        assert_eq!(hints.len(), 2, "both devices must reload distinctly");
        let find = |dev: [u8; DEVICE_ID_LEN]| {
            hints
                .iter()
                .find(|(k, _, _)| *k == (pk, dev))
                .map(|(_, v4, _)| *v4)
        };
        assert_eq!(find(dev_a), Some(Ipv4Addr::new(10, 66, 0, 2)));
        assert_eq!(find(dev_b), Some(Ipv4Addr::new(10, 66, 0, 3)));
    }

    #[test]
    fn into_sticky_hints_skips_legacy_records_without_device_id() {
        // A pre-device-cap state file has no `device_id_hex`. Such
        // records carry no device dimension, so they are skipped.
        let mut s = PersistedState::empty();
        s.sessions.insert(
            "c".repeat(64),
            PersistedSession {
                ipv4: Ipv4Addr::new(10, 66, 0, 9),
                ipv6: None,
                max_mtu: 1350,
                total: 1,
                device_id_hex: None,
            },
        );
        assert!(
            s.into_sticky_hints().is_empty(),
            "legacy record without device_id must be skipped"
        );
    }

    #[test]
    fn save_atomic_creates_parent_dir() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("nested/sub/dir/state.json");
        let s = PersistedState::empty();
        s.save_atomic(&path).expect("save with mkdir parent");
        assert!(path.exists());
    }

    #[test]
    fn save_atomic_uses_tmpfile_then_rename() {
        // Verify no .tmp file is left behind after a successful save.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("state.json");
        let s = PersistedState::empty();
        s.save_atomic(&path).expect("save");

        let tmp_path = dir.path().join("state.json.tmp");
        assert!(!tmp_path.exists(), "tmpfile must be renamed away");
        assert!(path.exists());
    }

    fn shared_sessions_with(entries: &[(u8, u8, Ipv4Addr)]) -> SharedSessions {
        let mut map = HashMap::new();
        for &(pk, dev, ipv4) in entries {
            map.insert(
                key(pk, dev),
                MultiSessionState {
                    ipv4,
                    ipv6: None,
                    max_mtu: 1350,
                    total: 1,
                    daita_spec: None,
                    token_serial: None,
                },
            );
        }
        Arc::new(AsyncMutex::new(map))
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn persister_converges_to_the_last_state_on_disk() {
        // Last state wins: the snapshot is taken at WRITE time, so the
        // disk must end up reflecting the final map content even when
        // requests fire faster than the debounce window.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("state.json");
        let sessions = shared_sessions_with(&[(1, 1, Ipv4Addr::new(10, 66, 0, 2))]);
        let persister = StatePersister::spawn(path.clone(), sessions.clone());

        persister.request_save();
        sessions.lock().await.insert(
            key(2, 2),
            MultiSessionState {
                ipv4: Ipv4Addr::new(10, 66, 0, 3),
                ipv6: None,
                max_mtu: 1350,
                total: 1,
                daita_spec: None,
                token_serial: None,
            },
        );
        persister.request_save();

        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            let on_disk = PersistedState::load_or_default(&path);
            if on_disk.sessions.len() == 2 {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "disk state must converge to the final 2-session map, got {} sessions",
                on_disk.sessions.len()
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn persister_debounces_to_at_most_one_save_per_second() {
        // 20 requests spread over ~1 s must coalesce into a handful of
        // writes (leading + trailing edge), never one fsync per
        // handshake like the previous inline design.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("state.json");
        let sessions = shared_sessions_with(&[(1, 1, Ipv4Addr::new(10, 66, 0, 2))]);
        let persister = StatePersister::spawn(path.clone(), sessions.clone());

        for _ in 0..20 {
            persister.request_save();
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        // Let the trailing debounced write land.
        tokio::time::sleep(Duration::from_millis(1_300)).await;

        let saves = persister.saves_performed();
        assert!(
            (1..=4).contains(&saves),
            "20 requests over ~1 s must coalesce to a handful of writes, got {saves}"
        );
        assert_eq!(
            PersistedState::load_or_default(&path).sessions.len(),
            1,
            "the coalesced write must still land the real state on disk"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn persister_drop_flushes_a_pending_request() {
        // Graceful shutdown right after a state change: the pending
        // request must reach the disk (either the task already wrote it
        // or the Drop flush does), so a clean restart never loses the
        // final session map.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("state.json");
        let sessions = shared_sessions_with(&[(7, 7, Ipv4Addr::new(10, 66, 0, 9))]);
        let persister = StatePersister::spawn(path.clone(), sessions);
        persister.request_save();
        drop(persister);

        let on_disk = PersistedState::load_or_default(&path);
        assert_eq!(
            on_disk.sessions.len(),
            1,
            "pending state must be flushed on shutdown"
        );
    }

    #[test]
    fn into_sticky_hints_skips_invalid_keys() {
        let mut s = PersistedState::empty();
        s.sessions.insert(
            "not-hex".to_string(),
            PersistedSession {
                ipv4: Ipv4Addr::new(10, 66, 0, 5),
                ipv6: None,
                max_mtu: 1350,
                total: 32,
                device_id_hex: Some("ab".repeat(16)),
            },
        );
        // Should load without panic, just skip the invalid key.
        assert!(s.into_sticky_hints().is_empty(), "invalid hex key skipped");
    }
}
