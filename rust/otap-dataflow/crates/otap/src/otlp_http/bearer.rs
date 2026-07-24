// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//! Shared, refreshable bearer-token store for OTLP/HTTP exporters.
//!
//! # Why this exists
//!
//! An OTLP/HTTP exporter can be configured to attach an `Authorization: Bearer
//! <token>` header to every outbound request, where the token is *owned and
//! periodically refreshed by an external party* (for example a host C++
//! application that embeds or supervises `df_engine`). The token therefore
//! cannot be a static config value baked into the reqwest client at build time;
//! it must be read fresh on each request and updated out-of-band.
//!
//! # The seam
//!
//! This module is deliberately split into two halves that meet at a
//! process-global registry so the *source* of the token can change without
//! touching the exporter that *reads* it:
//!
//! ```text
//!   token SOURCE (writer)                registry                 exporter (reader)
//!   ---------------------                --------                 -----------------
//!   Option 1: file poller  -+                                    +- slot(id).load()
//!                           +--> set_token(id, ..) --> ArcSwap --+   per request
//!   Option 2: C-ABI setter -+          (keyed by id)             +-  (add header / drop)
//! ```
//!
//! - The reader ([`slot`]) and every writer ([`set_token`]) rendezvous purely by
//!   `id`, so no handle has to be threaded through configuration or FFI.
//! - Reads are lock-free ([`arc_swap::ArcSwapOption`]), which matters because the
//!   read happens on the exporter's hot send path.
//! - Swapping Option 1 -> Option 2 is a config change (`source: file` -> `ffi`)
//!   plus calling [`set_token`] from a C entry point. The exporter code is
//!   unchanged.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use arc_swap::ArcSwapOption;
use http::HeaderValue;
use parking_lot::Mutex;

/// A lock-free, refreshable holder of a prepared `Authorization` header value.
///
/// `None` means "no token currently available" -- the exporter treats this as a
/// hard failure and drops the payload rather than sending an unauthenticated
/// request.
pub type SharedBearerToken = Arc<ArcSwapOption<HeaderValue>>;

/// Default registry key used when a configuration does not specify one.
pub const DEFAULT_TOKEN_ID: &str = "default";

/// Errors that can occur when updating a bearer token.
#[derive(Debug, thiserror::Error)]
pub enum BearerTokenError {
    /// The provided token could not be encoded as an HTTP header value (e.g. it
    /// contained control characters or non-visible-ASCII bytes).
    #[error("token is not a valid HTTP header value: {0}")]
    InvalidTokenValue(String),
}

/// Process-global map of token slots keyed by id. Created lazily on first use.
static REGISTRY: OnceLock<Mutex<HashMap<String, SharedBearerToken>>> = OnceLock::new();

fn registry() -> &'static Mutex<HashMap<String, SharedBearerToken>> {
    REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Returns the shared token slot for `id`, creating an empty one if needed.
///
/// Both the token source (writer) and the exporter (reader) call this; because
/// the slot is an `Arc`, they observe the same `ArcSwapOption` regardless of
/// call order.
#[must_use]
pub fn slot(id: &str) -> SharedBearerToken {
    let mut map = registry().lock();
    map.entry(id.to_owned())
        .or_insert_with(|| Arc::new(ArcSwapOption::from(None)))
        .clone()
}

/// Updates the token for `id`.
///
/// - `Some(non-empty)` prepares a sensitive `Bearer <token>` header value and
///   publishes it.
/// - `Some(empty/whitespace)` or `None` clears the slot, after which the
///   exporter will drop payloads until a token is published again.
///
/// This is the single write entry point shared by every token source. The file
/// poller calls it now; a future C-ABI setter (Option 2) will call the exact
/// same function, so the exporter never needs to know which source is active.
pub fn set_token(id: &str, token: Option<&str>) -> Result<(), BearerTokenError> {
    let slot = slot(id);
    match token {
        Some(t) if !t.trim().is_empty() => {
            let mut value = HeaderValue::from_str(&format!("Bearer {t}"))
                .map_err(|e| BearerTokenError::InvalidTokenValue(e.to_string()))?;
            // Redact in Debug output and exclude from HTTP/2 HPACK indexing.
            value.set_sensitive(true);
            slot.store(Some(Arc::new(value)));
        }
        _ => slot.store(None),
    }
    Ok(())
}

/// Tracks which `id`s already have a running file poller so that multiple
/// exporter instances (e.g. one per core) sharing the same id start only one.
static ACTIVE_FILE_SOURCES: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();

fn active_file_sources() -> &'static Mutex<HashSet<String>> {
    ACTIVE_FILE_SOURCES.get_or_init(|| Mutex::new(HashSet::new()))
}

/// Ensures a background poller is publishing the token found in `path` into the
/// slot for `id`, refreshing every `interval`.
///
/// Idempotent per `id`: the first caller starts a daemon thread; later callers
/// (additional exporter instances with the same id) are no-ops. The thread
/// reads the file only when its modification time changes, then calls
/// [`set_token`]. A missing/unreadable file clears the slot (payloads drop)
/// rather than being treated as fatal, because the external owner may not have
/// written the token yet.
///
/// Returns the shared slot so the caller can read from it immediately.
pub fn ensure_file_source(
    id: &str,
    path: impl Into<PathBuf>,
    interval: Duration,
) -> SharedBearerToken {
    let token = slot(id);
    let path = path.into();

    {
        let mut active = active_file_sources().lock();
        if !active.insert(id.to_owned()) {
            // A poller for this id is already running.
            return token;
        }
    }

    let id_owned = id.to_owned();
    let interval = interval.max(Duration::from_millis(100));
    let _ = std::thread::Builder::new()
        .name(format!("bearer-token-file:{id_owned}"))
        .spawn(move || run_file_poller(&id_owned, &path, interval));

    token
}

/// Reads `path` and publishes its trimmed contents as the token for `id`.
///
/// Exposed (crate-internal) so tests can drive a single synchronous refresh
/// without spawning the poller thread.
pub(crate) fn refresh_from_file(id: &str, path: &Path) {
    match std::fs::read_to_string(path) {
        Ok(contents) => {
            let trimmed = contents.trim();
            let _ = set_token(id, Some(trimmed));
        }
        Err(_) => {
            // File missing or unreadable: clear the token so requests drop
            // instead of going out unauthenticated.
            let _ = set_token(id, None);
        }
    }
}

fn run_file_poller(id: &str, path: &Path, interval: Duration) {
    let mut last_modified: Option<std::time::SystemTime> = None;
    loop {
        let modified = std::fs::metadata(path).and_then(|m| m.modified()).ok();
        if modified != last_modified {
            last_modified = modified;
            refresh_from_file(id, path);
        } else if modified.is_none() {
            // Still missing since last check -- keep the slot cleared.
            let _ = set_token(id, None);
        }
        std::thread::sleep(interval);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Scenario: two `slot` calls for the same id return handles to the same
    /// underlying store.
    /// Guarantees: writer and reader rendezvous by id (shared `Arc`).
    #[test]
    fn slot_is_shared_by_id() {
        let a = slot("share-test");
        let b = slot("share-test");
        set_token("share-test", Some("abc")).unwrap();
        assert!(a.load().is_some());
        assert!(b.load().is_some());
        assert_eq!(a.load().as_ref().unwrap().to_str().unwrap(), "Bearer abc");
    }

    /// Scenario: set a token, then clear it with `None` and with whitespace.
    /// Guarantees: cleared slot loads as `None` so the exporter will drop.
    #[test]
    fn set_token_publishes_and_clears() {
        let s = slot("clear-test");
        set_token("clear-test", Some("tok")).unwrap();
        assert!(s.load().is_some());
        set_token("clear-test", None).unwrap();
        assert!(s.load().is_none());
        set_token("clear-test", Some("   ")).unwrap();
        assert!(s.load().is_none());
    }

    /// Scenario: the published header value is marked sensitive.
    /// Guarantees: token is excluded from HPACK indexing / redacted in Debug.
    #[test]
    fn published_value_is_sensitive() {
        let s = slot("sensitive-test");
        set_token("sensitive-test", Some("secret")).unwrap();
        let guard = s.load();
        assert!(guard.as_ref().unwrap().is_sensitive());
    }

    /// Scenario: an invalid token (control char) is rejected.
    /// Guarantees: `set_token` returns an error and does not publish garbage.
    #[test]
    fn invalid_token_is_rejected() {
        let s = slot("invalid-test");
        let err = set_token("invalid-test", Some("bad\nvalue"));
        assert!(err.is_err());
        assert!(s.load().is_none());
    }

    /// Scenario: refresh reads the file, then reflects an updated file.
    /// Guarantees: exporters observe refreshed tokens without restart.
    #[test]
    fn refresh_from_file_reflects_updates() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("bearer-token-{}.txt", std::process::id()));
        std::fs::write(&path, "first\n").unwrap();
        let s = slot("file-test");
        refresh_from_file("file-test", &path);
        assert_eq!(s.load().as_ref().unwrap().to_str().unwrap(), "Bearer first");

        std::fs::write(&path, "second").unwrap();
        refresh_from_file("file-test", &path);
        assert_eq!(
            s.load().as_ref().unwrap().to_str().unwrap(),
            "Bearer second"
        );

        // Missing file clears the slot.
        std::fs::remove_file(&path).unwrap();
        refresh_from_file("file-test", &path);
        assert!(s.load().is_none());
    }
}
