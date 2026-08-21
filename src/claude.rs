use std::collections::{HashMap, HashSet};
use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read};
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Deserialize;

use crate::model::{
    AttentionKind, BeaconEvent, ClaudeAttentionEvent, ClaudeProjection, ClaudeSession,
    ClaudeSessionKey, ClaudeStatus, ClaudeTransition,
};

const MAX_MARKER_SIZE: u64 = 64 * 1024;
const MAX_CMDLINE_SIZE: u64 = 64 * 1024;
const MAX_PROC_STAT_SIZE: u64 = 8 * 1024;
const MAX_PROC_STATUS_SIZE: u64 = 64 * 1024;
const MAX_MARKERS_PER_SCAN: usize = 1024;
const MAX_SESSION_ID_SIZE: usize = 256;
const MAX_NAME_SIZE: usize = 512;

/// Claude Code live-session discovery configuration.
#[derive(Clone, Debug)]
pub struct ClaudeConfig {
    pub enabled: bool,
    pub poll_interval: Duration,
    /// Overrides `CLAUDE_CONFIG_DIR` and `$HOME/.claude`, primarily for tests.
    pub config_dir: Option<PathBuf>,
    pub proc_root: PathBuf,
}

impl Default for ClaudeConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            poll_interval: Duration::from_secs(1),
            config_dir: None,
            proc_root: PathBuf::from("/proc"),
        }
    }
}

impl ClaudeConfig {
    fn sessions_dir(&self) -> io::Result<PathBuf> {
        if let Some(config_dir) = &self.config_dir {
            return Ok(config_dir.join("sessions"));
        }
        if let Some(config_dir) =
            std::env::var_os("CLAUDE_CONFIG_DIR").filter(|path| !path.is_empty())
        {
            return Ok(PathBuf::from(config_dir).join("sessions"));
        }
        std::env::var_os("HOME")
            .filter(|path| !path.is_empty())
            .map(PathBuf::from)
            .map(|home| home.join(".claude/sessions"))
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "HOME is not set"))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ObservedSession {
    session: ClaudeSession,
    status: ClaudeStatus,
}

/// One bounded, same-UID Claude Code marker scan.
#[derive(Clone, Debug)]
pub struct ClaudeDiscovery {
    config: ClaudeConfig,
}

impl ClaudeDiscovery {
    #[must_use]
    pub const fn new(config: ClaudeConfig) -> Self {
        Self { config }
    }

    /// Returns one validated, privacy-limited snapshot of live Claude sessions.
    ///
    /// # Errors
    ///
    /// Returns an error when the configuration root or current UID cannot be read.
    pub fn snapshot(&self) -> io::Result<Vec<ClaudeProjection>> {
        self.discover().map(|sessions| {
            sessions
                .into_iter()
                .map(|observed| ClaudeProjection {
                    session: observed.session,
                    status: observed.status,
                    stale: false,
                })
                .collect()
        })
    }

    fn discover(&self) -> io::Result<Vec<ObservedSession>> {
        let self_uid = effective_uid(&self.config.proc_root.join("self"))?;
        let sessions_dir = self.config.sessions_dir()?;
        let entries = match fs::read_dir(sessions_dir) {
            Ok(entries) => entries,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(error),
        };
        let mut sessions = Vec::new();
        let mut seen_pids = HashSet::new();
        for (index, entry) in entries.enumerate() {
            if index >= MAX_MARKERS_PER_SCAN {
                return Err(io::Error::other("Claude marker count exceeds safety limit"));
            }
            let entry = entry?;
            let path = entry.path();
            let Some(pid) = marker_pid(&path) else {
                continue;
            };
            if !seen_pids.insert(pid) {
                continue;
            }
            if let Some(session) = self.read_marker(&path, pid, self_uid) {
                sessions.push(session);
            }
        }
        sessions.sort_by_key(|session| (session.session.key.pid, session.session.key.start_time));
        Ok(sessions)
    }

    fn read_marker(&self, path: &Path, pid: u32, self_uid: u32) -> Option<ObservedSession> {
        let metadata = fs::symlink_metadata(path).ok()?;
        if !metadata.file_type().is_file()
            || metadata.uid() != self_uid
            || metadata.len() > MAX_MARKER_SIZE
        {
            return None;
        }
        let process = self.config.proc_root.join(pid.to_string());
        let before = read_process_stat(&process).ok()?;
        if before.pid != pid
            || effective_uid(&process).ok() != Some(self_uid)
            || !is_claude_process(&process)
        {
            return None;
        }
        let marker = read_marker_json::<Marker>(path, &metadata).ok()?;
        if marker.pid != pid
            || marker.session_id.is_empty()
            || marker.session_id.len() > MAX_SESSION_ID_SIZE
            || !marker.cwd.is_absolute()
            || marker
                .name
                .as_ref()
                .is_some_and(|name| name.len() > MAX_NAME_SIZE)
        {
            return None;
        }
        let after = read_process_stat(&process).ok()?;
        if after != before
            || effective_uid(&process).ok() != Some(self_uid)
            || !is_claude_process(&process)
        {
            return None;
        }
        Some(ObservedSession {
            session: ClaudeSession {
                key: ClaudeSessionKey {
                    pid,
                    start_time: before.start_time,
                },
                session_id: marker.session_id,
                cwd: marker.cwd,
                name: marker.name.filter(|name| !name.is_empty()),
                has_tty: before.tty != 0,
            },
            status: normalize_status(marker.status.as_deref()),
        })
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Marker {
    pid: u32,
    session_id: String,
    cwd: PathBuf,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    status: Option<String>,
}

fn normalize_status(status: Option<&str>) -> ClaudeStatus {
    match status
        .map(str::trim)
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        Some("busy" | "working" | "active") => ClaudeStatus::Busy,
        Some("waiting") => ClaudeStatus::Waiting,
        Some("idle") => ClaudeStatus::Idle,
        _ => ClaudeStatus::Unknown,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ProcessStat {
    pid: u32,
    tty: i64,
    start_time: u64,
}

fn read_process_stat(process: &Path) -> io::Result<ProcessStat> {
    let contents = read_bounded_string(process.join("stat"), MAX_PROC_STAT_SIZE)?;
    let open = contents
        .find('(')
        .ok_or_else(|| invalid("stat has no command start"))?;
    let close = contents
        .rfind(')')
        .ok_or_else(|| invalid("stat has no command end"))?;
    let fields = contents[close + 1..].split_whitespace().collect::<Vec<_>>();
    if close <= open || fields.len() < 20 {
        return Err(invalid("stat has too few fields"));
    }
    Ok(ProcessStat {
        pid: contents[..open].trim().parse().map_err(invalid_data)?,
        tty: fields[4].parse().map_err(invalid_data)?,
        start_time: fields[19].parse().map_err(invalid_data)?,
    })
}

fn effective_uid(process: &Path) -> io::Result<u32> {
    read_bounded_string(process.join("status"), MAX_PROC_STATUS_SIZE)?
        .lines()
        .find_map(|line| line.strip_prefix("Uid:"))
        .and_then(|uids| uids.split_whitespace().nth(1))
        .ok_or_else(|| invalid("status has no effective UID"))?
        .parse()
        .map_err(invalid_data)
}

fn is_claude_process(process: &Path) -> bool {
    fs::read_link(process.join("exe")).map_or_else(
        |_| {
            read_bounded(process.join("cmdline"), MAX_CMDLINE_SIZE)
                .ok()
                .and_then(|cmdline| {
                    cmdline
                        .split(|byte| *byte == 0)
                        .next()
                        .map(ToOwned::to_owned)
                })
                .and_then(|argument| {
                    PathBuf::from(std::ffi::OsString::from_vec(argument))
                        .file_name()
                        .map(ToOwned::to_owned)
                })
                .is_some_and(|name| name == "claude")
        },
        |executable| executable.file_name() == Some(OsStr::new("claude")),
    )
}

fn marker_pid(path: &Path) -> Option<u32> {
    let stem = path.file_name()?.to_str()?.strip_suffix(".json")?;
    if stem.is_empty() || stem.starts_with('0') || !stem.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    stem.parse().ok().filter(|pid| *pid > 0)
}

fn read_marker_json<T: for<'de> Deserialize<'de>>(
    path: &Path,
    expected: &fs::Metadata,
) -> io::Result<T> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let opened = file.metadata()?;
    if !same_marker(expected, &opened) {
        return Err(invalid("marker identity changed while opening"));
    }
    let bytes = read_bounded_file(&file, MAX_MARKER_SIZE)?;
    if !same_marker(&opened, &file.metadata()?) {
        return Err(invalid("marker changed while reading"));
    }
    serde_json::from_slice(&bytes).map_err(invalid_data)
}

fn same_marker(expected: &fs::Metadata, actual: &fs::Metadata) -> bool {
    actual.file_type().is_file()
        && actual.dev() == expected.dev()
        && actual.ino() == expected.ino()
        && actual.uid() == expected.uid()
        && actual.len() == expected.len()
        && actual.mtime() == expected.mtime()
        && actual.mtime_nsec() == expected.mtime_nsec()
        && actual.ctime() == expected.ctime()
        && actual.ctime_nsec() == expected.ctime_nsec()
}

fn read_bounded(path: impl AsRef<Path>, limit: u64) -> io::Result<Vec<u8>> {
    read_bounded_file(File::open(path)?, limit)
}

fn read_bounded_string(path: impl AsRef<Path>, limit: u64) -> io::Result<String> {
    String::from_utf8(read_bounded(path, limit)?).map_err(invalid_data)
}

fn read_bounded_file(file: impl Read, limit: u64) -> io::Result<Vec<u8>> {
    let mut reader = file.take(limit + 1);
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes)?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > limit {
        return Err(invalid("file exceeds safety limit"));
    }
    Ok(bytes)
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn invalid_data(error: impl std::error::Error + Send + Sync + 'static) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error)
}

#[derive(Clone, Debug)]
struct RetainedSession {
    observed: ObservedSession,
    misses: u8,
    armed: bool,
    stale: bool,
}

/// Reduces complete marker scans into provider-specific monitor events.
#[derive(Default)]
pub(crate) struct ClaudeTracker {
    sessions: HashMap<ClaudeSessionKey, RetainedSession>,
}

impl ClaudeTracker {
    #[allow(clippy::too_many_lines)]
    pub(crate) fn apply_success(&mut self, observed: Vec<ObservedSession>) -> Vec<BeaconEvent> {
        let mut events = Vec::new();
        let keys = observed
            .iter()
            .map(|session| session.session.key)
            .collect::<HashSet<_>>();
        let replacements = self
            .sessions
            .iter()
            .filter_map(|(key, retained)| {
                observed
                    .iter()
                    .any(|current| {
                        current.session.key.pid == retained.observed.session.key.pid
                            && current.session.key != retained.observed.session.key
                    })
                    .then_some(*key)
            })
            .collect::<Vec<_>>();
        for key in replacements {
            if let Some(retained) = self.sessions.remove(&key) {
                events.push(BeaconEvent::ClaudeSessionRemoved(retained.observed.session));
            }
        }
        for retained in self.sessions.values_mut() {
            if !keys.contains(&retained.observed.session.key) {
                retained.misses = retained.misses.saturating_add(1);
                if !retained.stale {
                    retained.stale = true;
                    events.push(BeaconEvent::ClaudeStateProjection(ClaudeProjection {
                        session: retained.observed.session.clone(),
                        status: retained.observed.status,
                        stale: true,
                    }));
                }
            }
        }
        let removed = self
            .sessions
            .iter()
            .filter_map(|(key, retained)| (retained.misses >= 2).then_some(*key))
            .collect::<Vec<_>>();
        for key in removed {
            if let Some(retained) = self.sessions.remove(&key) {
                events.push(BeaconEvent::ClaudeSessionRemoved(retained.observed.session));
            }
        }
        for current in observed {
            let key = current.session.key;
            if let Some(retained) = self.sessions.get_mut(&key) {
                if retained.observed.session.session_id != current.session.session_id {
                    let previous = retained.observed.session.clone();
                    let armed =
                        matches!(current.status, ClaudeStatus::Busy | ClaudeStatus::Waiting);
                    *retained = RetainedSession {
                        observed: current.clone(),
                        misses: 0,
                        armed,
                        stale: false,
                    };
                    events.push(BeaconEvent::ClaudeSessionRemoved(previous));
                    events.push(BeaconEvent::ClaudeSessionFound(current.session.clone()));
                    events.push(BeaconEvent::ClaudeStateProjection(ClaudeProjection {
                        session: current.session,
                        status: current.status,
                        stale: false,
                    }));
                    continue;
                }
                let changed = retained.observed != current || retained.stale;
                retained.misses = 0;
                retained.stale = false;
                let previous = retained.observed.status;
                retained.observed.session.clone_from(&current.session);
                retained.observed.status = current.status;
                if previous != current.status {
                    if matches!(current.status, ClaudeStatus::Busy | ClaudeStatus::Waiting) {
                        retained.armed = true;
                    }
                    events.push(BeaconEvent::ClaudeTransition(ClaudeTransition {
                        session: current.session.clone(),
                        previous,
                        current: current.status,
                    }));
                    if retained.armed && current.status == ClaudeStatus::Idle {
                        retained.armed = false;
                        events.push(BeaconEvent::ClaudeAttention(ClaudeAttentionEvent {
                            kind: AttentionKind::Ready,
                            session: current.session.clone(),
                            initial: false,
                        }));
                    }
                }
                if changed {
                    events.push(BeaconEvent::ClaudeStateProjection(ClaudeProjection {
                        session: current.session,
                        status: current.status,
                        stale: false,
                    }));
                }
            } else {
                let armed = matches!(current.status, ClaudeStatus::Busy | ClaudeStatus::Waiting);
                events.push(BeaconEvent::ClaudeSessionFound(current.session.clone()));
                events.push(BeaconEvent::ClaudeStateProjection(ClaudeProjection {
                    session: current.session.clone(),
                    status: current.status,
                    stale: false,
                }));
                self.sessions.insert(
                    key,
                    RetainedSession {
                        observed: current,
                        misses: 0,
                        armed,
                        stale: false,
                    },
                );
            }
        }
        events
    }

    pub(crate) fn apply_failure(&mut self) -> Vec<BeaconEvent> {
        self.sessions
            .values_mut()
            .filter_map(|retained| {
                if retained.stale {
                    return None;
                }
                retained.stale = true;
                Some(BeaconEvent::ClaudeStateProjection(ClaudeProjection {
                    session: retained.observed.session.clone(),
                    status: retained.observed.status,
                    stale: true,
                }))
            })
            .collect()
    }
}

pub(crate) async fn scan(
    discovery: &ClaudeDiscovery,
    stopped: impl Fn() -> bool,
) -> io::Result<Option<Vec<ObservedSession>>> {
    let self_uid = effective_uid(&discovery.config.proc_root.join("self"))?;
    let sessions_dir = discovery.config.sessions_dir()?;
    let entries = match fs::read_dir(sessions_dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Some(Vec::new())),
        Err(error) => return Err(error),
    };
    let mut sessions = Vec::new();
    let mut seen_pids = HashSet::new();
    for (index, entry) in entries.enumerate() {
        if stopped() {
            return Ok(None);
        }
        if index >= MAX_MARKERS_PER_SCAN {
            return Err(io::Error::other("Claude marker count exceeds safety limit"));
        }
        let entry = entry?;
        let path = entry.path();
        if let Some(pid) = marker_pid(&path)
            && seen_pids.insert(pid)
            && let Some(session) = discovery.read_marker(&path, pid, self_uid)
        {
            sessions.push(session);
        }
        tokio::task::yield_now().await;
    }
    if stopped() {
        return Ok(None);
    }
    sessions.sort_by_key(|session| (session.session.key.pid, session.session.key.start_time));
    Ok(Some(sessions))
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::{MetadataExt, symlink};

    use super::*;

    fn process_stat(pid: u32, tty: i64, start_time: u64) -> String {
        format!("{pid} (claude) S 0 0 0 {tty} 0 0 0 0 0 0 0 0 0 0 0 0 0 0 {start_time} 0\n")
    }

    fn fixture() -> (tempfile::TempDir, ClaudeDiscovery, u32) {
        let directory =
            tempfile::tempdir().unwrap_or_else(|error| unreachable!("tempdir: {error}"));
        let proc_root = directory.path().join("proc");
        let config_dir = directory.path().join("claude");
        assert!(fs::create_dir_all(proc_root.join("self")).is_ok());
        assert!(fs::create_dir_all(config_dir.join("sessions")).is_ok());
        let uid = fs::metadata(directory.path())
            .unwrap_or_else(|error| unreachable!("metadata: {error}"))
            .uid();
        assert!(
            fs::write(
                proc_root.join("self/status"),
                format!("Uid:\t{uid}\t{uid}\t{uid}\t{uid}\n")
            )
            .is_ok()
        );
        let discovery = ClaudeDiscovery::new(ClaudeConfig {
            enabled: true,
            config_dir: Some(config_dir),
            proc_root,
            ..ClaudeConfig::default()
        });
        (directory, discovery, uid)
    }

    fn write_session(
        directory: &tempfile::TempDir,
        discovery: &ClaudeDiscovery,
        uid: u32,
        pid: u32,
        start_time: u64,
        status: &str,
    ) {
        let process = discovery.config.proc_root.join(pid.to_string());
        assert!(fs::create_dir_all(&process).is_ok());
        assert!(
            fs::write(
                process.join("status"),
                format!("Uid:\t{uid}\t{uid}\t{uid}\t{uid}\n")
            )
            .is_ok()
        );
        assert!(fs::write(process.join("stat"), process_stat(pid, 0, start_time)).is_ok());
        let executable = directory.path().join("bin/claude");
        assert!(
            fs::create_dir_all(
                executable
                    .parent()
                    .unwrap_or_else(|| unreachable!("binary has parent"))
            )
            .is_ok()
        );
        if !executable.exists() {
            assert!(fs::write(&executable, "binary").is_ok());
        }
        assert!(symlink(executable, process.join("exe")).is_ok());
        let marker = serde_json::json!({
            "pid": pid,
            "sessionId": format!("session-{pid}"),
            "cwd": format!("/workspace/{pid}"),
            "name": format!("Claude {pid}"),
            "status": status,
            "waitingFor": "sensitive text is ignored",
        });
        assert!(
            fs::write(
                discovery
                    .config
                    .sessions_dir()
                    .unwrap_or_else(|error| unreachable!("sessions dir: {error}"))
                    .join(format!("{pid}.json")),
                serde_json::to_vec(&marker).unwrap_or_else(|error| unreachable!("json: {error}")),
            )
            .is_ok()
        );
    }

    fn observed(pid: u32, start_time: u64, status: ClaudeStatus) -> ObservedSession {
        ObservedSession {
            session: ClaudeSession {
                key: ClaudeSessionKey { pid, start_time },
                session_id: format!("session-{pid}"),
                cwd: PathBuf::from(format!("/workspace/{pid}")),
                name: None,
                has_tty: false,
            },
            status,
        }
    }

    #[test]
    fn claude_discovery_requires_same_uid_exact_process_and_stable_pid() {
        let (directory, discovery, uid) = fixture();
        write_session(&directory, &discovery, uid, 101, 900, "busy");
        let sessions = discovery
            .discover()
            .unwrap_or_else(|error| unreachable!("discover: {error}"));
        assert_eq!(
            sessions,
            vec![observed_with_name(101, 900, ClaudeStatus::Busy)]
        );

        assert!(
            fs::write(
                discovery.config.proc_root.join("101/stat"),
                process_stat(101, 7, 900)
            )
            .is_ok()
        );
        let interactive = discovery
            .discover()
            .unwrap_or_else(|error| unreachable!("discover interactive: {error}"));
        assert!(interactive[0].session.has_tty);

        assert!(fs::remove_file(discovery.config.proc_root.join("101/exe")).is_ok());
        let other = directory.path().join("bin/not-claude");
        assert!(fs::write(&other, "binary").is_ok());
        assert!(symlink(&other, discovery.config.proc_root.join("101/exe")).is_ok());
        assert!(
            discovery
                .discover()
                .is_ok_and(|sessions| sessions.is_empty())
        );
        assert!(fs::remove_file(discovery.config.proc_root.join("101/exe")).is_ok());
        assert!(
            symlink(
                directory.path().join("bin/claude"),
                discovery.config.proc_root.join("101/exe")
            )
            .is_ok()
        );

        assert!(
            fs::write(
                discovery.config.proc_root.join("101/stat"),
                process_stat(101, 0, 901)
            )
            .is_ok()
        );
        let changed = discovery
            .discover()
            .unwrap_or_else(|error| unreachable!("discover: {error}"));
        assert_eq!(changed[0].session.key.start_time, 901);

        assert!(
            fs::write(
                discovery.config.proc_root.join("101/status"),
                format!("Uid:\t{}\t{}\t{}\t{}\n", uid + 1, uid + 1, uid + 1, uid + 1)
            )
            .is_ok()
        );
        assert!(
            discovery
                .discover()
                .is_ok_and(|sessions| sessions.is_empty())
        );
    }

    fn observed_with_name(pid: u32, start_time: u64, status: ClaudeStatus) -> ObservedSession {
        let mut session = observed(pid, start_time, status);
        session.session.name = Some(format!("Claude {pid}"));
        session
    }

    #[test]
    fn claude_status_parsing_is_tolerant() {
        for (raw, expected) in [
            (Some("busy"), ClaudeStatus::Busy),
            (Some("WORKING"), ClaudeStatus::Busy),
            (Some("active"), ClaudeStatus::Busy),
            (Some("waiting"), ClaudeStatus::Waiting),
            (Some("idle"), ClaudeStatus::Idle),
            (Some("future"), ClaudeStatus::Unknown),
            (None, ClaudeStatus::Unknown),
        ] {
            assert_eq!(normalize_status(raw), expected);
        }
    }

    #[test]
    fn claude_marker_rejects_symlinks_and_oversized_files() {
        let (directory, discovery, uid) = fixture();
        write_session(&directory, &discovery, uid, 102, 901, "idle");
        let marker = discovery
            .config
            .sessions_dir()
            .unwrap_or_else(|error| unreachable!("sessions directory: {error}"))
            .join("102.json");
        let outside = directory.path().join("outside.json");
        assert!(fs::rename(&marker, &outside).is_ok());
        assert!(symlink(&outside, &marker).is_ok());
        assert!(
            discovery
                .discover()
                .is_ok_and(|sessions| sessions.is_empty())
        );

        assert!(fs::remove_file(&marker).is_ok());
        assert!(
            fs::write(
                &marker,
                vec![b'x'; usize::try_from(MAX_MARKER_SIZE + 1).unwrap_or(65_537)]
            )
            .is_ok()
        );
        assert!(
            discovery
                .discover()
                .is_ok_and(|sessions| sessions.is_empty())
        );
    }

    #[test]
    fn claude_marker_open_rejects_a_symlink_replacement_race() {
        let directory =
            tempfile::tempdir().unwrap_or_else(|error| unreachable!("tempdir: {error}"));
        let marker = directory.path().join("123.json");
        let moved = directory.path().join("moved.json");
        assert!(fs::write(&marker, br#"{"pid":123}"#).is_ok());
        let expected = fs::symlink_metadata(&marker)
            .unwrap_or_else(|error| unreachable!("marker metadata: {error}"));
        assert!(fs::rename(&marker, &moved).is_ok());
        assert!(symlink(&moved, &marker).is_ok());

        assert!(read_marker_json::<serde_json::Value>(&marker, &expected).is_err());
    }

    #[test]
    fn claude_marker_names_are_canonical_positive_pids() {
        assert_eq!(marker_pid(Path::new("1.json")), Some(1));
        assert_eq!(marker_pid(Path::new("4294967295.json")), Some(u32::MAX));
        for name in [
            "0.json",
            "01.json",
            "+1.json",
            " 1.json",
            "1.JSON",
            "1.json.extra",
            "4294967296.json",
        ] {
            assert_eq!(marker_pid(Path::new(name)), None, "accepted {name}");
        }
    }

    #[test]
    fn claude_proc_identity_reads_are_bounded() {
        let directory =
            tempfile::tempdir().unwrap_or_else(|error| unreachable!("tempdir: {error}"));
        assert!(
            fs::write(
                directory.path().join("stat"),
                vec![b'x'; usize::try_from(MAX_PROC_STAT_SIZE + 1).unwrap_or(8193)]
            )
            .is_ok()
        );
        assert!(read_process_stat(directory.path()).is_err());
        assert!(
            fs::write(
                directory.path().join("status"),
                vec![b'x'; usize::try_from(MAX_PROC_STATUS_SIZE + 1).unwrap_or(65_537)]
            )
            .is_ok()
        );
        assert!(effective_uid(directory.path()).is_err());
    }

    #[tokio::test]
    async fn claude_continuous_scan_honors_cancellation_before_publication() {
        let (directory, discovery, uid) = fixture();
        write_session(&directory, &discovery, uid, 103, 902, "busy");
        assert!(matches!(scan(&discovery, || true).await, Ok(None)));
    }

    #[test]
    fn initial_idle_is_silent_until_work_arms_ready() {
        let mut tracker = ClaudeTracker::default();
        let initial = tracker.apply_success(vec![observed(1, 10, ClaudeStatus::Idle)]);
        assert!(
            initial
                .iter()
                .all(|event| !matches!(event, BeaconEvent::ClaudeAttention(_)))
        );

        let busy = tracker.apply_success(vec![observed(1, 10, ClaudeStatus::Busy)]);
        assert!(
            busy.iter()
                .any(|event| matches!(event, BeaconEvent::ClaudeTransition(_)))
        );
        let idle = tracker.apply_success(vec![observed(1, 10, ClaudeStatus::Idle)]);
        assert_eq!(
            idle.iter()
                .filter(|event| matches!(event, BeaconEvent::ClaudeAttention(_)))
                .count(),
            1
        );
        let repeated = tracker.apply_success(vec![observed(1, 10, ClaudeStatus::Idle)]);
        assert!(
            repeated
                .iter()
                .all(|event| !matches!(event, BeaconEvent::ClaudeAttention(_)))
        );
    }

    #[test]
    fn headless_sessions_remain_in_provider_events() {
        let mut tracker = ClaudeTracker::default();
        let events = tracker.apply_success(vec![observed(1, 10, ClaudeStatus::Idle)]);

        assert!(events.iter().any(|event| {
            matches!(event, BeaconEvent::ClaudeSessionFound(session) if !session.has_tty)
        }));
        assert!(events.iter().any(|event| {
            matches!(event, BeaconEvent::ClaudeStateProjection(projection) if !projection.session.has_tty)
        }));
    }

    #[test]
    fn successful_misses_remove_on_second_pass_but_failures_only_mark_stale() {
        let mut tracker = ClaudeTracker::default();
        tracker.apply_success(vec![observed(1, 10, ClaudeStatus::Idle)]);
        let failure = tracker.apply_failure();
        assert!(matches!(
            failure.as_slice(),
            [BeaconEvent::ClaudeStateProjection(ClaudeProjection {
                stale: true,
                ..
            })]
        ));
        assert!(
            tracker
                .apply_success(Vec::new())
                .iter()
                .all(|event| !matches!(event, BeaconEvent::ClaudeSessionRemoved(_)))
        );
        assert!(
            tracker
                .apply_success(Vec::new())
                .iter()
                .any(|event| matches!(event, BeaconEvent::ClaudeSessionRemoved(_)))
        );
    }

    #[test]
    fn pid_reuse_has_distinct_identity() {
        let mut tracker = ClaudeTracker::default();
        tracker.apply_success(vec![observed(1, 10, ClaudeStatus::Idle)]);
        let events = tracker.apply_success(vec![observed(1, 11, ClaudeStatus::Idle)]);
        assert!(events.iter().any(|event| matches!(event, BeaconEvent::ClaudeSessionRemoved(session) if session.key.start_time == 10)));
        let removed = events
            .iter()
            .position(|event| matches!(event, BeaconEvent::ClaudeSessionRemoved(_)))
            .unwrap_or_else(|| unreachable!("replacement removes old session"));
        let found = events
            .iter()
            .position(|event| matches!(event, BeaconEvent::ClaudeSessionFound(_)))
            .unwrap_or_else(|| unreachable!("replacement finds new session"));
        assert!(removed < found);
    }

    #[test]
    fn changed_session_id_resets_ready_arm_as_replacement() {
        let mut tracker = ClaudeTracker::default();
        tracker.apply_success(vec![observed(1, 10, ClaudeStatus::Busy)]);
        let mut replacement = observed(1, 10, ClaudeStatus::Idle);
        replacement.session.session_id = "replacement".to_owned();
        let events = tracker.apply_success(vec![replacement]);
        assert!(matches!(
            events.first(),
            Some(BeaconEvent::ClaudeSessionRemoved(_))
        ));
        assert!(matches!(
            events.get(1),
            Some(BeaconEvent::ClaudeSessionFound(_))
        ));
        assert!(
            events
                .iter()
                .all(|event| !matches!(event, BeaconEvent::ClaudeAttention(_)))
        );
    }
}
