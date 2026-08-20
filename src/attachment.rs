use std::collections::{HashMap, HashSet};
use std::ffi::{OsStr, OsString};
use std::fs;
use std::fs::File;
use std::io::{self, BufRead, BufReader, Read};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::{Component, Path, PathBuf};

use opencode_beacon::model::{
    BeaconEvent, InstanceKey, InstanceSource, OpenCodeProtocol, ServerEndpoint,
};

const MAX_PROCESS_ENVIRONMENT_SIZE: u64 = 256 * 1024;
const MAX_PROCESS_STAT_SIZE: u64 = 8 * 1024;
const MAX_PROCESS_STATUS_SIZE: u64 = 64 * 1024;
const MAX_PROCESS_CMDLINE_SIZE: u64 = 64 * 1024;
const MAX_UNIX_SOCKET_TABLE_SIZE: u64 = 1024 * 1024;
const MAX_KONSOLE_IDENTIFIER_SIZE: usize = 128;
const MAX_KITTY_PID_SIZE: usize = 10;
const MAX_KITTY_WINDOW_ID_SIZE: usize = 20;
const MAX_KITTY_SOCKET_PATH_SIZE: usize = 107;
const MAX_KITTY_LISTEN_ON_SIZE: usize = "unix:".len() + MAX_KITTY_SOCKET_PATH_SIZE;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct TuiKey {
    pub pid: u32,
    pub start_time: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KonsoleTarget {
    pub service: String,
    pub session_path: String,
    pub window_path: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KittyTarget {
    pub process: TuiKey,
    pub window_id: u64,
    pub socket_path: PathBuf,
    pub socket_device: u64,
    pub socket_inode: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ClientFocusTarget {
    Konsole(KonsoleTarget),
    Kitty(KittyTarget),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FocusProcessSource {
    OpenCode,
    Claude,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FocusTarget {
    pub process: TuiKey,
    pub source: FocusProcessSource,
    pub client: ClientFocusTarget,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InteractiveKind {
    Full,
    Mini,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LikelyTui {
    pub key: TuiKey,
    pub instance: InstanceKey,
    pub kind: InteractiveKind,
    pub cwd: PathBuf,
    pub startup_directory: Option<PathBuf>,
    pub explicit_session: Option<String>,
    pub continue_session: bool,
    pub focus: Option<FocusTarget>,
    pub stale: bool,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AttachmentSnapshot {
    pub tuis: Vec<LikelyTui>,
    pub v1_focus: HashMap<InstanceKey, FocusTarget>,
    pub claude_focus: HashMap<TuiKey, FocusTarget>,
    pub diagnostic: Option<String>,
}

#[derive(Clone, Debug)]
struct V2Target {
    instance: InstanceKey,
    service_pid: u32,
}

#[derive(Clone, Copy, Debug)]
struct V1Target {
    pid: u32,
    start_time: Option<u64>,
}

#[derive(Clone, Debug)]
struct RetainedTui {
    tui: LikelyTui,
    misses: u8,
}

pub struct AttachmentSampler {
    proc_root: PathBuf,
    targets: HashMap<ServerEndpoint, V2Target>,
    v1_targets: HashMap<InstanceKey, V1Target>,
    claude_targets: HashSet<TuiKey>,
    retained: HashMap<TuiKey, RetainedTui>,
}

impl Default for AttachmentSampler {
    fn default() -> Self {
        Self::new(PathBuf::from("/proc"))
    }
}

impl AttachmentSampler {
    fn new(proc_root: PathBuf) -> Self {
        Self {
            proc_root,
            targets: HashMap::new(),
            v1_targets: HashMap::new(),
            claude_targets: HashSet::new(),
            retained: HashMap::new(),
        }
    }

    pub fn observe(&mut self, event: &BeaconEvent) {
        match event {
            BeaconEvent::ServerFound(instance) if instance.protocol == OpenCodeProtocol::V2 => {
                self.targets.insert(
                    instance.endpoint,
                    V2Target {
                        instance: instance.key.clone(),
                        service_pid: instance.key.pid,
                    },
                );
            }
            BeaconEvent::ServerFound(instance)
                if instance.protocol == OpenCodeProtocol::V1
                    && instance.key.source == InstanceSource::LinuxProcfs =>
            {
                let process = self.proc_root.join(instance.key.pid.to_string());
                let start_time = read_process_stat(&process)
                    .ok()
                    .filter(|stat| stat.pid == instance.key.pid)
                    .map(|stat| stat.start_time);
                self.v1_targets
                    .entry(instance.key.clone())
                    .and_modify(|target| {
                        if target.start_time.is_none() {
                            target.start_time = start_time;
                        }
                    })
                    .or_insert(V1Target {
                        pid: instance.key.pid,
                        start_time,
                    });
            }
            BeaconEvent::ServerRemoved(instance) => {
                self.targets.remove(&instance.endpoint);
                self.v1_targets.remove(&instance.key);
                self.retained
                    .retain(|_, retained| retained.tui.instance != instance.key);
            }
            BeaconEvent::ClaudeSessionFound(session) => {
                self.claude_targets.insert(TuiKey {
                    pid: session.key.pid,
                    start_time: session.key.start_time,
                });
            }
            BeaconEvent::ClaudeSessionRemoved(session) => {
                self.claude_targets.remove(&TuiKey {
                    pid: session.key.pid,
                    start_time: session.key.start_time,
                });
            }
            _ => {}
        }
    }

    pub fn sample(&mut self) -> AttachmentSnapshot {
        let mut snapshot = match scan(&self.proc_root, &self.targets) {
            Ok(observed) => {
                let mut snapshot = self.apply_success(observed);
                snapshot.v1_focus = scan_v1_focus(&self.proc_root, &mut self.v1_targets);
                snapshot
            }
            Err(error) => self.apply_failure(&error),
        };
        snapshot.claude_focus = scan_claude_focus(&self.proc_root, &self.claude_targets);
        snapshot
    }

    fn apply_success(&mut self, observed: Vec<LikelyTui>) -> AttachmentSnapshot {
        let observed_keys = observed.iter().map(|tui| tui.key).collect::<HashSet<_>>();
        for retained in self.retained.values_mut() {
            if !observed_keys.contains(&retained.tui.key) {
                retained.misses = retained.misses.saturating_add(1);
                retained.tui.stale = true;
            }
        }
        self.retained.retain(|_, retained| retained.misses < 2);
        for mut tui in observed {
            tui.stale = false;
            self.retained
                .insert(tui.key, RetainedTui { tui, misses: 0 });
        }
        AttachmentSnapshot {
            tuis: self.current(),
            v1_focus: HashMap::new(),
            claude_focus: HashMap::new(),
            diagnostic: None,
        }
    }

    fn apply_failure(&mut self, error: &io::Error) -> AttachmentSnapshot {
        for retained in self.retained.values_mut() {
            retained.tui.stale = true;
        }
        AttachmentSnapshot {
            tuis: self.current(),
            v1_focus: HashMap::new(),
            claude_focus: HashMap::new(),
            diagnostic: Some(format!("v2 TUI attachment scan failed: {error}")),
        }
    }

    fn current(&self) -> Vec<LikelyTui> {
        let mut tuis = self
            .retained
            .values()
            .map(|retained| retained.tui.clone())
            .collect::<Vec<_>>();
        tuis.sort_by_key(|tui| (tui.key.pid, tui.key.start_time));
        tuis
    }
}

#[derive(Clone, Copy)]
struct EstablishedSocket {
    peer: ServerEndpoint,
    uid: u32,
    inode: u64,
}

#[allow(clippy::too_many_lines)]
fn scan(
    proc_root: &Path,
    targets: &HashMap<ServerEndpoint, V2Target>,
) -> io::Result<Vec<LikelyTui>> {
    if targets.is_empty() {
        return Ok(Vec::new());
    }
    let self_root = proc_root.join("self");
    let uid = effective_uid(&self_root)?;
    let namespace = fs::metadata(self_root.join("ns/net"))?.ino();
    let mut sockets = parse_established(&fs::read_to_string(self_root.join("net/tcp"))?, false)?;
    match fs::read_to_string(self_root.join("net/tcp6")) {
        Ok(contents) => sockets.extend(parse_established(&contents, true)?),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    sockets.retain(|socket| socket.uid == uid && targets.contains_key(&socket.peer));
    let wanted = sockets
        .iter()
        .map(|socket| socket.inode)
        .collect::<HashSet<_>>();
    let peers = sockets
        .iter()
        .map(|socket| (socket.inode, socket.peer))
        .collect::<HashMap<_, _>>();
    let service_pids = targets
        .values()
        .map(|target| target.service_pid)
        .collect::<HashSet<_>>();
    let mut tuis = HashMap::<TuiKey, LikelyTui>::new();

    for entry in fs::read_dir(proc_root)? {
        let Ok(entry) = entry else { continue };
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse().ok())
        else {
            continue;
        };
        if service_pids.contains(&pid) {
            continue;
        }
        let process = entry.path();
        if effective_uid(&process).ok() != Some(uid)
            || fs::metadata(process.join("ns/net"))
                .map(|value| value.ino())
                .ok()
                != Some(namespace)
        {
            continue;
        }
        let Ok(before) = read_process_stat(&process) else {
            continue;
        };
        if before.pid != pid || before.tty == 0 {
            continue;
        }
        let Ok(argv) = read_argv(&process) else {
            continue;
        };
        let Some(arguments) = classify_argv(&argv) else {
            continue;
        };
        let Ok(cwd) = fs::read_link(process.join("cwd")) else {
            continue;
        };
        let Ok(fds) = fs::read_dir(process.join("fd")) else {
            continue;
        };
        let mut matched_peers = HashSet::new();
        for fd in fds.flatten() {
            let Ok(target) = fs::read_link(fd.path()) else {
                continue;
            };
            let target = target.to_string_lossy();
            let Some(inode) = target
                .strip_prefix("socket:[")
                .and_then(|value| value.strip_suffix(']'))
                .and_then(|value| value.parse::<u64>().ok())
            else {
                continue;
            };
            if wanted.contains(&inode)
                && let Some(peer) = peers.get(&inode)
            {
                matched_peers.insert(*peer);
            }
        }
        if matched_peers.len() != 1
            || fs::metadata(process.join("ns/net"))
                .map(|value| value.ino())
                .ok()
                != Some(namespace)
            || read_process_stat(&process).ok().as_ref() != Some(&before)
        {
            continue;
        }
        let peer = *matched_peers
            .iter()
            .next()
            .ok_or_else(|| invalid("matched peer disappeared"))?;
        let Some(target) = targets.get(&peer) else {
            continue;
        };
        let key = TuiKey {
            pid,
            start_time: before.start_time,
        };
        let focus = read_focus_target(proc_root, &process, key, FocusProcessSource::OpenCode);
        tuis.insert(
            key,
            LikelyTui {
                key,
                instance: target.instance.clone(),
                kind: arguments.kind,
                cwd,
                startup_directory: arguments.startup_directory,
                explicit_session: arguments.explicit_session,
                continue_session: arguments.continue_session,
                focus,
                stale: false,
            },
        );
    }
    Ok(tuis.into_values().collect())
}

fn scan_v1_focus(
    proc_root: &Path,
    targets: &mut HashMap<InstanceKey, V1Target>,
) -> HashMap<InstanceKey, FocusTarget> {
    let self_root = proc_root.join("self");
    let Some((uid, namespace)) = effective_uid(&self_root).ok().zip(
        fs::metadata(self_root.join("ns/net"))
            .ok()
            .map(|value| value.ino()),
    ) else {
        return HashMap::new();
    };
    targets
        .iter_mut()
        .filter_map(|(instance, target)| {
            let process = proc_root.join(target.pid.to_string());
            if instance.network_namespace_inode != namespace
                || effective_uid(&process).ok() != Some(uid)
                || fs::metadata(process.join("ns/net"))
                    .ok()
                    .map(|value| value.ino())
                    != Some(namespace)
            {
                return None;
            }
            let before = read_process_stat(&process).ok()?;
            if before.pid != target.pid
                || target
                    .start_time
                    .is_some_and(|start_time| before.start_time != start_time)
                || before.tty == 0
                || !process_owns_socket(&process, instance.socket_inode)
            {
                return None;
            }
            let focus = read_focus_target(
                proc_root,
                &process,
                TuiKey {
                    pid: target.pid,
                    start_time: before.start_time,
                },
                FocusProcessSource::OpenCode,
            )?;
            if read_process_stat(&process).ok().as_ref() != Some(&before)
                || fs::metadata(process.join("ns/net"))
                    .ok()
                    .map(|value| value.ino())
                    != Some(namespace)
                || !process_owns_socket(&process, instance.socket_inode)
            {
                return None;
            }
            target.start_time = Some(before.start_time);
            Some((instance.clone(), focus))
        })
        .collect()
}

fn scan_claude_focus(proc_root: &Path, targets: &HashSet<TuiKey>) -> HashMap<TuiKey, FocusTarget> {
    targets
        .iter()
        .filter_map(|key| {
            let process = proc_root.join(key.pid.to_string());
            let target = read_focus_target(proc_root, &process, *key, FocusProcessSource::Claude)?;
            focus_process_matches(proc_root, &target).then_some((*key, target))
        })
        .collect()
}

fn process_owns_socket(process: &Path, socket_inode: u64) -> bool {
    fs::read_dir(process.join("fd")).is_ok_and(|fds| {
        fds.flatten().any(|fd| {
            fs::read_link(fd.path()).is_ok_and(|target| {
                target
                    .to_str()
                    .and_then(|target| target.strip_prefix("socket:["))
                    .and_then(|target| target.strip_suffix(']'))
                    .and_then(|target| target.parse::<u64>().ok())
                    == Some(socket_inode)
            })
        })
    })
}

#[derive(Default)]
struct FocusEnvironment {
    konsole_service: Option<Vec<u8>>,
    konsole_session: Option<Vec<u8>>,
    konsole_window: Option<Vec<u8>>,
    kitty_pid: Option<Vec<u8>>,
    kitty_window_id: Option<Vec<u8>>,
    kitty_listen_on: Option<Vec<u8>>,
    konsole_valid: bool,
    kitty_valid: bool,
}

fn read_focus_environment(process: &Path) -> Option<FocusEnvironment> {
    let file = File::open(process.join("environ")).ok()?;
    let mut environment = BufReader::new(file.take(MAX_PROCESS_ENVIRONMENT_SIZE + 1));
    let mut total = 0_u64;
    let mut entry = Vec::new();
    let mut result = FocusEnvironment {
        konsole_valid: true,
        kitty_valid: true,
        ..FocusEnvironment::default()
    };
    loop {
        entry.clear();
        let read = environment.read_until(0, &mut entry).ok()?;
        if read == 0 {
            break;
        }
        total = total.saturating_add(read as u64);
        if total > MAX_PROCESS_ENVIRONMENT_SIZE {
            return None;
        }
        if entry.last() == Some(&0) {
            entry.pop();
        }
        if let Some(value) = entry.strip_prefix(b"KONSOLE_DBUS_SERVICE=") {
            result.konsole_valid &= set_unique(
                &mut result.konsole_service,
                value,
                MAX_KONSOLE_IDENTIFIER_SIZE,
            );
        } else if let Some(value) = entry.strip_prefix(b"KONSOLE_DBUS_SESSION=") {
            result.konsole_valid &= set_unique(
                &mut result.konsole_session,
                value,
                MAX_KONSOLE_IDENTIFIER_SIZE,
            );
        } else if let Some(value) = entry.strip_prefix(b"KONSOLE_DBUS_WINDOW=") {
            result.konsole_valid &= set_unique(
                &mut result.konsole_window,
                value,
                MAX_KONSOLE_IDENTIFIER_SIZE,
            );
        } else if let Some(value) = entry.strip_prefix(b"KITTY_PID=") {
            result.kitty_valid &= set_unique(&mut result.kitty_pid, value, MAX_KITTY_PID_SIZE);
        } else if let Some(value) = entry.strip_prefix(b"KITTY_WINDOW_ID=") {
            result.kitty_valid &=
                set_unique(&mut result.kitty_window_id, value, MAX_KITTY_WINDOW_ID_SIZE);
        } else if let Some(value) = entry.strip_prefix(b"KITTY_LISTEN_ON=") {
            result.kitty_valid &=
                set_unique(&mut result.kitty_listen_on, value, MAX_KITTY_LISTEN_ON_SIZE);
        }
    }
    Some(result)
}

fn set_unique(slot: &mut Option<Vec<u8>>, value: &[u8], max_size: usize) -> bool {
    if value.len() > max_size {
        return false;
    }
    if slot.as_deref().is_some_and(|old| old != value) {
        return false;
    }
    *slot = Some(value.to_vec());
    true
}

fn read_focus_target(
    proc_root: &Path,
    process: &Path,
    key: TuiKey,
    source: FocusProcessSource,
) -> Option<FocusTarget> {
    let environment = read_focus_environment(process)?;
    if let Some(kitty) = kitty_target_from_environment(proc_root, key, &environment) {
        return Some(FocusTarget {
            process: key,
            source,
            client: ClientFocusTarget::Kitty(kitty),
        });
    }
    konsole_target_from_environment(&environment).map(|konsole| FocusTarget {
        process: key,
        source,
        client: ClientFocusTarget::Konsole(konsole),
    })
}

#[cfg(test)]
fn read_konsole_target(process: &Path) -> Option<KonsoleTarget> {
    konsole_target_from_environment(&read_focus_environment(process)?)
}

fn konsole_target_from_environment(environment: &FocusEnvironment) -> Option<KonsoleTarget> {
    if !environment.konsole_valid {
        return None;
    }
    Some(KonsoleTarget {
        service: valid_konsole_service(environment.konsole_service.as_deref()?)?,
        session_path: valid_konsole_session(environment.konsole_session.as_deref()?)?,
        window_path: valid_konsole_window(environment.konsole_window.as_deref()?)?,
    })
}

fn kitty_target_from_environment(
    proc_root: &Path,
    tui: TuiKey,
    environment: &FocusEnvironment,
) -> Option<KittyTarget> {
    if !environment.kitty_valid {
        return None;
    }
    let pid = positive_decimal(environment.kitty_pid.as_deref()?)?;
    let window_id = positive_decimal_u64(environment.kitty_window_id.as_deref()?)?;
    let socket_path = valid_kitty_socket_path(environment.kitty_listen_on.as_deref()?)?;
    let process = read_process_stat(&proc_root.join(pid.to_string())).ok()?;
    let uid = effective_uid(&proc_root.join("self")).ok()?;
    let socket = valid_kitty_socket(&socket_path, uid)?;
    let target = KittyTarget {
        process: TuiKey {
            pid,
            start_time: process.start_time,
        },
        window_id,
        socket_path,
        socket_device: socket.dev(),
        socket_inode: socket.ino(),
    };
    kitty_target_matches(proc_root, tui, &target).then_some(target)
}

fn positive_decimal(value: &[u8]) -> Option<u32> {
    let value = std::str::from_utf8(value).ok()?;
    (!value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()))
        .then(|| value.parse::<u32>().ok())
        .flatten()
        .filter(|value| *value > 0)
}

fn positive_decimal_u64(value: &[u8]) -> Option<u64> {
    let value = std::str::from_utf8(value).ok()?;
    (!value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()))
        .then(|| value.parse::<u64>().ok())
        .flatten()
        .filter(|value| *value > 0)
}

fn valid_kitty_socket_path(value: &[u8]) -> Option<PathBuf> {
    let value = std::str::from_utf8(value).ok()?;
    let raw = value.strip_prefix("unix:")?;
    let path = PathBuf::from(raw);
    (raw.len() <= MAX_KITTY_SOCKET_PATH_SIZE
        && path.is_absolute()
        && path
            .components()
            .all(|component| !matches!(component, Component::CurDir | Component::ParentDir)))
    .then_some(path)
}

fn valid_konsole_service(value: &[u8]) -> Option<String> {
    let value = std::str::from_utf8(value).ok()?;
    (value.len() <= MAX_KONSOLE_IDENTIFIER_SIZE
        && value.starts_with(':')
        && value[1..].split('.').count() == 2
        && value[1..]
            .split('.')
            .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit())))
    .then(|| value.to_owned())
}

fn valid_konsole_session(value: &[u8]) -> Option<String> {
    let value = std::str::from_utf8(value).ok()?;
    let id = value.strip_prefix("/Sessions/")?;
    (value.len() <= MAX_KONSOLE_IDENTIFIER_SIZE
        && !id.is_empty()
        && id.bytes().all(|byte| byte.is_ascii_digit()))
    .then(|| value.to_owned())
}

fn valid_konsole_window(value: &[u8]) -> Option<String> {
    let value = std::str::from_utf8(value).ok()?;
    let id = value.strip_prefix("/Windows/")?;
    (value.len() <= MAX_KONSOLE_IDENTIFIER_SIZE
        && !id.is_empty()
        && id.bytes().all(|byte| byte.is_ascii_digit()))
    .then(|| value.to_owned())
}

pub fn kitty_target_matches(proc_root: &Path, tui: TuiKey, target: &KittyTarget) -> bool {
    if !process_matches(proc_root, tui) || !process_matches(proc_root, target.process) {
        return false;
    }
    let self_root = proc_root.join("self");
    let kitty = proc_root.join(target.process.pid.to_string());
    let tui_process = proc_root.join(tui.pid.to_string());
    let Some(uid) = effective_uid(&self_root).ok() else {
        return false;
    };
    if effective_uid(&kitty).ok() != Some(uid) || effective_uid(&tui_process).ok() != Some(uid) {
        return false;
    }
    for namespace in ["ns/net", "ns/mnt"] {
        let Some(expected) = fs::metadata(self_root.join(namespace))
            .ok()
            .map(|metadata| metadata.ino())
        else {
            return false;
        };
        if fs::metadata(kitty.join(namespace))
            .ok()
            .map(|metadata| metadata.ino())
            != Some(expected)
        {
            return false;
        }
    }
    if !read_focus_environment(&tui_process)
        .as_ref()
        .is_some_and(|environment| kitty_identifiers_match(environment, target))
    {
        return false;
    }
    let Some(before) = valid_kitty_socket(&target.socket_path, uid) else {
        return false;
    };
    if before.dev() != target.socket_device || before.ino() != target.socket_inode {
        return false;
    }
    let Some(socket_inode) =
        read_bounded_string(kitty.join("net/unix"), MAX_UNIX_SOCKET_TABLE_SIZE)
            .ok()
            .and_then(|contents| unix_listener_inode(&contents, &target.socket_path))
    else {
        return false;
    };
    process_owns_socket(&kitty, socket_inode)
        && fs::symlink_metadata(&target.socket_path)
            .is_ok_and(|after| after.dev() == before.dev() && after.ino() == before.ino())
        && process_matches(proc_root, tui)
        && process_matches(proc_root, target.process)
}

fn valid_kitty_socket(path: &Path, uid: u32) -> Option<fs::Metadata> {
    let metadata = fs::symlink_metadata(path).ok()?;
    (metadata.file_type().is_socket()
        && metadata.uid() == uid
        && fs::canonicalize(path).ok().as_deref() == Some(path)
        && (metadata.mode() & 0o022 == 0 || has_private_socket_ancestor(path, uid)))
    .then_some(metadata)
}

fn has_private_socket_ancestor(path: &Path, uid: u32) -> bool {
    path.ancestors().skip(1).any(|ancestor| {
        fs::symlink_metadata(ancestor).is_ok_and(|metadata| {
            // A directory's low six mode bits are group/other permissions.
            metadata.file_type().is_dir()
                && metadata.uid() == uid
                && metadata.mode().trailing_zeros() >= 6
        })
    })
}

fn kitty_identifiers_match(environment: &FocusEnvironment, target: &KittyTarget) -> bool {
    environment.kitty_valid
        && environment.kitty_pid.as_deref().and_then(positive_decimal) == Some(target.process.pid)
        && environment
            .kitty_window_id
            .as_deref()
            .and_then(positive_decimal_u64)
            == Some(target.window_id)
        && environment
            .kitty_listen_on
            .as_deref()
            .and_then(valid_kitty_socket_path)
            .as_ref()
            == Some(&target.socket_path)
}

fn unix_listener_inode(contents: &str, socket_path: &Path) -> Option<u64> {
    let target = socket_path.to_str()?;
    let mut matches = contents.lines().skip(1).filter_map(|line| {
        let (fields, path) = split_unix_socket_row(line)?;
        let flags = u32::from_str_radix(fields[3], 16).ok()?;
        (fields[4] == "0001" && fields[5] == "01" && flags & 0x0001_0000 != 0 && path == target)
            .then(|| fields[6].parse::<u64>().ok())
            .flatten()
    });
    let inode = matches.next()?;
    matches.next().is_none().then_some(inode)
}

fn split_unix_socket_row(line: &str) -> Option<([&str; 7], &str)> {
    let mut rest = line;
    let mut fields = [""; 7];
    for field in &mut fields {
        rest = rest.trim_start_matches(char::is_whitespace);
        let end = rest.find(char::is_whitespace)?;
        (*field, rest) = (&rest[..end], &rest[end..]);
    }
    let path = rest.trim_start_matches(char::is_whitespace);
    (!path.is_empty()).then_some((fields, path))
}

pub fn process_matches(proc_root: &Path, key: TuiKey) -> bool {
    read_process_stat(&proc_root.join(key.pid.to_string()))
        .is_ok_and(|stat| stat.pid == key.pid && stat.start_time == key.start_time)
}

pub fn focus_process_matches(proc_root: &Path, target: &FocusTarget) -> bool {
    match target.source {
        FocusProcessSource::OpenCode => process_matches(proc_root, target.process),
        FocusProcessSource::Claude => claude_focus_process_matches(proc_root, target),
    }
}

fn claude_focus_process_matches(proc_root: &Path, target: &FocusTarget) -> bool {
    let self_root = proc_root.join("self");
    let process = proc_root.join(target.process.pid.to_string());
    let Some(uid) = effective_uid(&self_root).ok() else {
        return false;
    };
    let Some(before) = read_process_stat(&process).ok() else {
        return false;
    };
    if before.pid != target.process.pid
        || before.start_time != target.process.start_time
        || before.tty == 0
        || effective_uid(&process).ok() != Some(uid)
        || !is_claude_process(&process)
    {
        return false;
    }
    let identifiers_match = read_focus_environment(&process)
        .as_ref()
        .is_some_and(|environment| match &target.client {
            ClientFocusTarget::Konsole(konsole) => {
                konsole_target_from_environment(environment).as_ref() == Some(konsole)
            }
            ClientFocusTarget::Kitty(kitty) => kitty_identifiers_match(environment, kitty),
        });
    identifiers_match
        && read_process_stat(&process).ok().as_ref() == Some(&before)
        && effective_uid(&process).ok() == Some(uid)
        && is_claude_process(&process)
}

fn is_claude_process(process: &Path) -> bool {
    fs::read_link(process.join("exe")).map_or_else(
        |_| {
            read_bounded(process.join("cmdline"), MAX_PROCESS_CMDLINE_SIZE)
                .ok()
                .and_then(|cmdline| {
                    cmdline
                        .split(|byte| *byte == 0)
                        .next()
                        .map(ToOwned::to_owned)
                })
                .and_then(|argument| {
                    PathBuf::from(OsString::from_vec(argument))
                        .file_name()
                        .map(ToOwned::to_owned)
                })
                .is_some_and(|name| name == "claude")
        },
        |executable| executable.file_name() == Some(OsStr::new("claude")),
    )
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ProcessStat {
    pid: u32,
    tty: i64,
    start_time: u64,
}

fn read_process_stat(process: &Path) -> io::Result<ProcessStat> {
    parse_process_stat(&read_bounded_string(
        process.join("stat"),
        MAX_PROCESS_STAT_SIZE,
    )?)
}

fn parse_process_stat(contents: &str) -> io::Result<ProcessStat> {
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

fn read_argv(process: &Path) -> io::Result<Vec<OsString>> {
    let bytes = read_bounded(process.join("cmdline"), MAX_PROCESS_CMDLINE_SIZE)?;
    let argv = bytes
        .split(|byte| *byte == 0)
        .filter(|argument| !argument.is_empty())
        .map(|argument| OsString::from_vec(argument.to_vec()))
        .collect::<Vec<_>>();
    if argv.is_empty() {
        return Err(invalid("process has no argv"));
    }
    Ok(argv)
}

#[derive(Debug, Eq, PartialEq)]
struct InteractiveArguments {
    kind: InteractiveKind,
    startup_directory: Option<PathBuf>,
    explicit_session: Option<String>,
    continue_session: bool,
}

fn classify_argv(argv: &[OsString]) -> Option<InteractiveArguments> {
    let executable = Path::new(argv.first()?).file_name()?.to_string_lossy();
    if !executable.to_ascii_lowercase().contains("opencode") || executable.contains("beacon") {
        return None;
    }
    let values = argv
        .iter()
        .skip(1)
        .map(|value| value.to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    let mut explicit_session = None;
    let mut continue_session = false;
    let mut positional = Vec::new();
    let mut index = 0;
    while index < values.len() {
        let value = &values[index];
        if let Some(session) = value.strip_prefix("--session=") {
            explicit_session = Some(session.to_owned());
        } else if matches!(value.as_str(), "--session" | "-s") {
            explicit_session = values.get(index + 1).cloned();
            index += 1;
        } else if matches!(value.as_str(), "--continue" | "-c") {
            continue_session = true;
        } else if option_takes_value(value) {
            index += 1;
        } else if !value.starts_with('-') {
            positional.push(value.clone());
        }
        index += 1;
    }
    let kind = match positional.first().map(String::as_str) {
        Some("mini") => InteractiveKind::Mini,
        Some(
            "acp" | "agent" | "api" | "attach" | "auth" | "completion" | "console" | "db" | "debug"
            | "export" | "github" | "import" | "mcp" | "models" | "pair" | "plugin" | "providers"
            | "run" | "serve" | "service" | "session" | "stats" | "uninstall" | "upgrade" | "web",
        ) => return None,
        _ => InteractiveKind::Full,
    };
    Some(InteractiveArguments {
        kind,
        startup_directory: (kind == InteractiveKind::Full)
            .then(|| positional.last().map(PathBuf::from))
            .flatten(),
        explicit_session,
        continue_session,
    })
}

fn option_takes_value(value: &str) -> bool {
    matches!(
        value,
        "--agent"
            | "--cors"
            | "--hostname"
            | "--log-level"
            | "--mdns-domain"
            | "--model"
            | "-m"
            | "--port"
            | "--prompt"
            | "--server"
            | "--replay-limit"
    )
}

fn parse_established(contents: &str, ipv6: bool) -> io::Result<Vec<EstablishedSocket>> {
    let mut sockets = Vec::new();
    for line in contents.lines().skip(1) {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        if fields.len() < 10 || fields[3] != "01" {
            continue;
        }
        let local = parse_proc_address(fields[1], ipv6)?;
        let peer = parse_proc_address(fields[2], ipv6)?;
        if local == peer {
            continue;
        }
        let Ok(peer) = ServerEndpoint::new(peer) else {
            continue;
        };
        sockets.push(EstablishedSocket {
            peer,
            uid: fields[7].parse().map_err(invalid_data)?,
            inode: fields[9].parse().map_err(invalid_data)?,
        });
    }
    Ok(sockets)
}

fn parse_proc_address(value: &str, ipv6: bool) -> io::Result<SocketAddr> {
    let (address, port) = value
        .split_once(':')
        .ok_or_else(|| invalid("socket address has no port"))?;
    let port = u16::from_str_radix(port, 16).map_err(invalid_data)?;
    let ip = if ipv6 {
        if address.len() != 32 {
            return Err(invalid("invalid IPv6 socket address"));
        }
        let mut octets = [0_u8; 16];
        for (index, word) in address.as_bytes().chunks_exact(8).enumerate() {
            let word = std::str::from_utf8(word).map_err(invalid_data)?;
            octets[index * 4..index * 4 + 4].copy_from_slice(
                &u32::from_str_radix(word, 16)
                    .map_err(invalid_data)?
                    .to_le_bytes(),
            );
        }
        IpAddr::V6(Ipv6Addr::from(octets))
    } else {
        let raw = u32::from_str_radix(address, 16).map_err(invalid_data)?;
        IpAddr::V4(Ipv4Addr::from(raw.to_le_bytes()))
    };
    Ok(SocketAddr::new(ip, port))
}

fn effective_uid(process: &Path) -> io::Result<u32> {
    read_bounded_string(process.join("status"), MAX_PROCESS_STATUS_SIZE)?
        .lines()
        .find_map(|line| line.strip_prefix("Uid:"))
        .and_then(|uids| uids.split_whitespace().nth(1))
        .ok_or_else(|| invalid("status has no effective UID"))?
        .parse()
        .map_err(invalid_data)
}

fn read_bounded(path: impl AsRef<Path>, limit: u64) -> io::Result<Vec<u8>> {
    let mut reader = File::open(path)?.take(limit + 1);
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes)?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > limit {
        return Err(invalid("file exceeds safety limit"));
    }
    Ok(bytes)
}

fn read_bounded_string(path: impl AsRef<Path>, limit: u64) -> io::Result<String> {
    String::from_utf8(read_bounded(path, limit)?).map_err(invalid_data)
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn invalid_data(error: impl std::error::Error + Send + Sync + 'static) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error)
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::os::unix::net::UnixListener;

    use super::*;
    use opencode_beacon::model::{ClaudeSession, ClaudeSessionKey, InstanceSource};

    fn os(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }

    fn write_process(proc_root: &Path, pid: u32, start_time: u64, uid: u32) -> PathBuf {
        let process = proc_root.join(pid.to_string());
        assert!(fs::create_dir_all(process.join("fd")).is_ok());
        assert!(fs::create_dir_all(process.join("ns")).is_ok());
        assert!(fs::create_dir_all(process.join("net")).is_ok());
        assert!(
            fs::write(
                process.join("status"),
                format!("Uid:\t{uid}\t{uid}\t{uid}\t{uid}\n")
            )
            .is_ok()
        );
        assert!(
            fs::write(
                process.join("stat"),
                format!(
                    "{pid} (process) S 1 0 0 7 {} {start_time}\n",
                    vec!["0"; 14].join(" ")
                )
            )
            .is_ok()
        );
        process
    }

    fn claude_found(pid: u32, start_time: u64) -> BeaconEvent {
        BeaconEvent::ClaudeSessionFound(ClaudeSession {
            key: ClaudeSessionKey { pid, start_time },
            session_id: format!("session-{pid}"),
            cwd: PathBuf::from("/workspace"),
            name: Some("Claude session".to_owned()),
        })
    }

    fn kitty_fixture() -> (tempfile::TempDir, UnixListener, TuiKey, KittyTarget) {
        let directory = tempfile::tempdir()
            .unwrap_or_else(|error| unreachable!("temporary directory: {error}"));
        let proc_root = directory.path().join("proc");
        let uid = fs::metadata(directory.path())
            .unwrap_or_else(|error| unreachable!("metadata: {error}"))
            .uid();
        let self_root = write_process(&proc_root, 999, 1, uid);
        assert!(symlink("999", proc_root.join("self")).is_ok());
        let tui = TuiKey {
            pid: 123,
            start_time: 100,
        };
        let tui_process = write_process(&proc_root, tui.pid, tui.start_time, uid);
        let kitty_process = write_process(&proc_root, 500, 80, uid);
        let net_namespace = directory.path().join("net-namespace");
        let mount_namespace = directory.path().join("mount-namespace");
        assert!(fs::write(&net_namespace, "net").is_ok());
        assert!(fs::write(&mount_namespace, "mnt").is_ok());
        for process in [&self_root, &tui_process, &kitty_process] {
            assert!(symlink(&net_namespace, process.join("ns/net")).is_ok());
            assert!(symlink(&mount_namespace, process.join("ns/mnt")).is_ok());
        }
        let socket_path = directory.path().join("kitty beacon.sock");
        let listener = UnixListener::bind(&socket_path)
            .unwrap_or_else(|error| unreachable!("bind synthetic Kitty socket: {error}"));
        assert!(fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o600)).is_ok());
        let socket = fs::symlink_metadata(&socket_path)
            .unwrap_or_else(|error| unreachable!("socket metadata: {error}"));
        assert!(fs::write(
            kitty_process.join("net/unix"),
            format!(
                "Num RefCount Protocol Flags Type St Inode Path\n00000000: 00000002 00000000 00010000 0001 01 9001 {}\n",
                socket_path.display()
            )
        ).is_ok());
        assert!(symlink("socket:[9001]", kitty_process.join("fd/7")).is_ok());
        assert!(
            fs::write(
                tui_process.join("environ"),
                format!(
                    "KITTY_PID=500\0KITTY_WINDOW_ID=77\0KITTY_LISTEN_ON=unix:{}\0",
                    socket_path.display()
                )
            )
            .is_ok()
        );
        (
            directory,
            listener,
            tui,
            KittyTarget {
                process: TuiKey {
                    pid: 500,
                    start_time: 80,
                },
                window_id: 77,
                socket_path,
                socket_device: socket.dev(),
                socket_inode: socket.ino(),
            },
        )
    }

    #[test]
    fn classifier_accepts_full_and_mini_and_rejects_noninteractive_commands() {
        assert_eq!(
            classify_argv(&os(&[
                "/usr/bin/opencode2",
                "--continue",
                "--session",
                "ses_explicit",
                "/workspace",
            ])),
            Some(InteractiveArguments {
                kind: InteractiveKind::Full,
                startup_directory: Some(PathBuf::from("/workspace")),
                explicit_session: Some("ses_explicit".to_owned()),
                continue_session: true,
            })
        );
        assert_eq!(
            classify_argv(&os(&["opencode2", "mini", "-c"])).map(|value| value.kind),
            Some(InteractiveKind::Mini)
        );
        for command in ["run", "serve", "service", "acp", "api"] {
            assert!(classify_argv(&os(&["opencode2", command])).is_none());
        }
        assert!(
            classify_argv(&os(&[
                "opencode2",
                "--hostname",
                "127.0.0.1",
                "--port",
                "0",
                "run",
                "prompt",
            ]))
            .is_none()
        );
        assert!(classify_argv(&os(&["opencode-beacon"])).is_none());
        assert_eq!(
            classify_argv(&os(&["opencode2", "--standalone"])).map(|value| value.kind),
            Some(InteractiveKind::Full)
        );
    }

    #[test]
    fn proc_socket_parser_keeps_only_established_client_rows() {
        let contents = "sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n\
            0: 0100007F:C350 0100007F:1000 01 0:0 0:0 0 1000 0 42\n\
            1: 0100007F:1000 0100007F:C350 0A 0:0 0:0 0 1000 0 43\n";
        let sockets = parse_established(contents, false)
            .unwrap_or_else(|error| unreachable!("synthetic table parses: {error}"));
        assert_eq!(sockets.len(), 1);
        assert_eq!(
            sockets[0].peer.address(),
            SocketAddr::from(([127, 0, 0, 1], 4096))
        );
        assert_eq!(sockets[0].inode, 42);
    }

    #[test]
    fn scanner_correlates_and_deduplicates_tui_socket_fds() {
        let directory = tempfile::tempdir()
            .unwrap_or_else(|error| unreachable!("temporary directory: {error}"));
        let proc_root = directory.path().join("proc");
        let self_root = proc_root.join("self");
        let process = proc_root.join("123");
        assert!(fs::create_dir_all(self_root.join("net")).is_ok());
        assert!(fs::create_dir_all(self_root.join("ns")).is_ok());
        assert!(fs::create_dir_all(process.join("fd")).is_ok());
        assert!(fs::create_dir_all(process.join("ns")).is_ok());
        let uid = fs::metadata(directory.path())
            .unwrap_or_else(|error| unreachable!("metadata: {error}"))
            .uid();
        for root in [&self_root, &process] {
            assert!(
                fs::write(
                    root.join("status"),
                    format!("Uid:\t{uid}\t{uid}\t{uid}\t{uid}\n")
                )
                .is_ok()
            );
        }
        let namespace = directory.path().join("namespace");
        assert!(fs::write(&namespace, "namespace").is_ok());
        assert!(symlink(&namespace, self_root.join("ns/net")).is_ok());
        assert!(symlink(&namespace, process.join("ns/net")).is_ok());
        assert!(fs::write(
            self_root.join("net/tcp"),
            format!("sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n0: 0100007F:C350 0100007F:1000 01 0:0 0:0 0 {uid} 0 42\n")
        ).is_ok());
        let stat = format!(
            "123 (opencode2) S 1 0 0 7 {} 100\n",
            vec!["0"; 15].join(" ")
        );
        assert!(fs::write(process.join("stat"), &stat).is_ok());
        assert!(fs::write(process.join("cmdline"), b"opencode2\0--continue\0").is_ok());
        assert!(symlink(directory.path(), process.join("cwd")).is_ok());
        assert!(symlink("socket:[42]", process.join("fd/3")).is_ok());
        assert!(symlink("socket:[42]", process.join("fd/4")).is_ok());
        let endpoint = ServerEndpoint::new(SocketAddr::from(([127, 0, 0, 1], 4096)))
            .unwrap_or_else(|error| unreachable!("endpoint: {error}"));
        let instance = InstanceKey {
            network_namespace_inode: 0,
            socket_inode: 0,
            listener: endpoint.address(),
            pid: 999,
            source: InstanceSource::ManagedService {
                registration: PathBuf::from("/state/service.json"),
                id: None,
            },
        };
        let targets = HashMap::from([(
            endpoint,
            V2Target {
                instance: instance.clone(),
                service_pid: 999,
            },
        )]);
        let tuis = scan(&proc_root, &targets)
            .unwrap_or_else(|error| unreachable!("synthetic scan succeeds: {error}"));
        assert_eq!(tuis.len(), 1);
        assert_eq!(tuis[0].key.pid, 123);
        assert_eq!(tuis[0].instance, instance);
    }

    #[test]
    fn v1_focus_requires_original_process_namespace_uid_and_listener_socket() {
        let directory = tempfile::tempdir()
            .unwrap_or_else(|error| unreachable!("temporary directory: {error}"));
        let proc_root = directory.path().join("proc");
        let self_root = proc_root.join("self");
        let process = proc_root.join("123");
        assert!(fs::create_dir_all(self_root.join("ns")).is_ok());
        assert!(fs::create_dir_all(process.join("ns")).is_ok());
        assert!(fs::create_dir_all(process.join("fd")).is_ok());
        let uid = fs::metadata(directory.path())
            .unwrap_or_else(|error| unreachable!("metadata: {error}"))
            .uid();
        for root in [&self_root, &process] {
            assert!(
                fs::write(
                    root.join("status"),
                    format!("Uid:\t{uid}\t{uid}\t{uid}\t{uid}\n")
                )
                .is_ok()
            );
        }
        let namespace = directory.path().join("namespace");
        assert!(fs::write(&namespace, "namespace").is_ok());
        assert!(symlink(&namespace, self_root.join("ns/net")).is_ok());
        assert!(symlink(&namespace, process.join("ns/net")).is_ok());
        let namespace_inode = fs::metadata(&namespace)
            .unwrap_or_else(|error| unreachable!("namespace metadata: {error}"))
            .ino();
        let stat = format!("123 (opencode) S 1 0 0 7 {} 100\n", vec!["0"; 14].join(" "));
        assert!(fs::write(process.join("stat"), &stat).is_ok());
        assert!(symlink("socket:[42]", process.join("fd/3")).is_ok());
        assert!(
            fs::write(
                process.join("environ"),
                b"KONSOLE_DBUS_SERVICE=:1.108\0KONSOLE_DBUS_SESSION=/Sessions/1\0KONSOLE_DBUS_WINDOW=/Windows/1\0"
            )
            .is_ok()
        );
        let instance = InstanceKey {
            network_namespace_inode: namespace_inode,
            socket_inode: 42,
            listener: SocketAddr::from(([127, 0, 0, 1], 4096)),
            pid: 123,
            source: InstanceSource::LinuxProcfs,
        };
        assert!(fs::remove_file(process.join("stat")).is_ok());
        let endpoint = ServerEndpoint::new(instance.listener)
            .unwrap_or_else(|error| unreachable!("endpoint: {error}"));
        let mut sampler = AttachmentSampler::new(proc_root.clone());
        sampler.observe(&BeaconEvent::ServerFound(
            opencode_beacon::model::ServerInstance {
                key: instance.clone(),
                endpoint,
                protocol: OpenCodeProtocol::V1,
                executable: None,
                version: "test".to_owned(),
            },
        ));
        assert_eq!(
            sampler
                .v1_targets
                .get(&instance)
                .and_then(|target| target.start_time),
            None
        );
        assert!(fs::write(process.join("stat"), &stat).is_ok());
        assert!(sampler.sample().v1_focus.contains_key(&instance));
        assert_eq!(
            sampler
                .v1_targets
                .get(&instance)
                .and_then(|target| target.start_time),
            Some(100)
        );

        let mut targets = HashMap::from([(
            instance.clone(),
            V1Target {
                pid: 123,
                start_time: Some(100),
            },
        )]);
        assert!(scan_v1_focus(&proc_root, &mut targets).contains_key(&instance));

        let mut reused = HashMap::from([(
            instance,
            V1Target {
                pid: 123,
                start_time: Some(99),
            },
        )]);
        assert!(scan_v1_focus(&proc_root, &mut reused).is_empty());
        assert!(fs::remove_file(process.join("fd/3")).is_ok());
        assert!(scan_v1_focus(&proc_root, &mut targets).is_empty());
    }

    #[test]
    fn lifecycle_requires_two_successful_misses_and_failure_retains_stale() {
        let key = TuiKey {
            pid: 1,
            start_time: 2,
        };
        let endpoint = ServerEndpoint::new(SocketAddr::from(([127, 0, 0, 1], 4096)))
            .unwrap_or_else(|error| unreachable!("endpoint: {error}"));
        let instance = InstanceKey {
            network_namespace_inode: 0,
            socket_inode: 0,
            listener: endpoint.address(),
            pid: 9,
            source: InstanceSource::ManagedService {
                registration: PathBuf::new(),
                id: None,
            },
        };
        let tui = LikelyTui {
            key,
            instance,
            kind: InteractiveKind::Full,
            cwd: PathBuf::from("/workspace"),
            startup_directory: None,
            explicit_session: None,
            continue_session: false,
            focus: None,
            stale: false,
        };
        let mut sampler = AttachmentSampler::new(PathBuf::new());
        assert!(!sampler.apply_success(vec![tui]).tuis[0].stale);
        assert!(sampler.apply_success(Vec::new()).tuis[0].stale);
        let failed = sampler.apply_failure(&io::Error::other("synthetic failure"));
        assert_eq!(failed.tuis.len(), 1);
        assert!(failed.tuis[0].stale);
        assert!(failed.diagnostic.is_some());
        assert!(sampler.apply_success(Vec::new()).tuis.is_empty());
    }

    #[test]
    fn konsole_target_reads_only_bounded_strict_identifiers() {
        let directory = tempfile::tempdir()
            .unwrap_or_else(|error| unreachable!("temporary directory: {error}"));
        let process = directory.path().join("123");
        assert!(fs::create_dir(&process).is_ok());
        assert!(
            fs::write(
                process.join("environ"),
                b"SECRET=not-retained\0KONSOLE_DBUS_SERVICE=:1.108\0KONSOLE_DBUS_SESSION=/Sessions/4\0KONSOLE_DBUS_WINDOW=/Windows/9\0"
            )
            .is_ok()
        );
        assert_eq!(
            read_konsole_target(&process),
            Some(KonsoleTarget {
                service: ":1.108".to_owned(),
                session_path: "/Sessions/4".to_owned(),
                window_path: "/Windows/9".to_owned(),
            })
        );

        assert!(
            fs::write(
                process.join("environ"),
                vec![b'x'; usize::try_from(MAX_PROCESS_ENVIRONMENT_SIZE).unwrap_or(0) + 1]
            )
            .is_ok()
        );
        assert!(read_konsole_target(&process).is_none());
    }

    #[test]
    fn konsole_target_rejects_malformed_or_conflicting_values() {
        let directory = tempfile::tempdir()
            .unwrap_or_else(|error| unreachable!("temporary directory: {error}"));
        let process = directory.path().join("123");
        assert!(fs::create_dir(&process).is_ok());
        for environment in [
            b"KONSOLE_DBUS_SERVICE=org.kde.konsole\0KONSOLE_DBUS_SESSION=/Sessions/1\0KONSOLE_DBUS_WINDOW=/Windows/1\0"
                .as_slice(),
            b"KONSOLE_DBUS_SERVICE=:1.2\0KONSOLE_DBUS_SESSION=/Sessions/not-a-number\0KONSOLE_DBUS_WINDOW=/Windows/1\0",
            b"KONSOLE_DBUS_SERVICE=:1.2\0KONSOLE_DBUS_SESSION=/Sessions/1\0KONSOLE_DBUS_WINDOW=/Windows/not-a-number\0",
            b"KONSOLE_DBUS_SERVICE=:1.2\0KONSOLE_DBUS_SERVICE=:1.3\0KONSOLE_DBUS_SESSION=/Sessions/1\0KONSOLE_DBUS_WINDOW=/Windows/1\0",
            b"KONSOLE_DBUS_SERVICE=:1.2\0KONSOLE_DBUS_SESSION=/Sessions/1\0KONSOLE_DBUS_WINDOW=/Windows/1\0KONSOLE_DBUS_WINDOW=/Windows/2\0",
            b"KONSOLE_DBUS_SERVICE=:1.2\0KONSOLE_DBUS_SESSION=/Sessions/1\0",
        ] {
            assert!(fs::write(process.join("environ"), environment).is_ok());
            assert!(read_konsole_target(&process).is_none());
        }
    }

    #[test]
    fn kitty_target_requires_exact_owned_listener_and_takes_focus_precedence() {
        let (directory, _listener, tui, expected) = kitty_fixture();
        let process = directory.path().join("proc/123");
        let mut environment = fs::read(process.join("environ"))
            .unwrap_or_else(|error| unreachable!("read environment: {error}"));
        environment.extend_from_slice(
            b"KONSOLE_DBUS_SERVICE=:1.108\0KONSOLE_DBUS_SESSION=/Sessions/4\0KONSOLE_DBUS_WINDOW=/Windows/9\0",
        );
        assert!(fs::write(process.join("environ"), environment).is_ok());

        assert_eq!(
            read_focus_target(
                &directory.path().join("proc"),
                &process,
                tui,
                FocusProcessSource::OpenCode,
            ),
            Some(FocusTarget {
                process: tui,
                source: FocusProcessSource::OpenCode,
                client: ClientFocusTarget::Kitty(expected.clone()),
            })
        );
        assert!(kitty_target_matches(
            &directory.path().join("proc"),
            tui,
            &expected
        ));
    }

    #[test]
    fn claude_konsole_focus_requires_stable_uid_process_tty_and_identifiers() {
        let directory = tempfile::tempdir()
            .unwrap_or_else(|error| unreachable!("temporary directory: {error}"));
        let proc_root = directory.path().join("proc");
        let uid = fs::metadata(directory.path())
            .unwrap_or_else(|error| unreachable!("metadata: {error}"))
            .uid();
        write_process(&proc_root, 999, 1, uid);
        assert!(symlink("999", proc_root.join("self")).is_ok());
        let process = write_process(&proc_root, 321, 700, uid);
        assert!(fs::write(process.join("cmdline"), b"claude\0").is_ok());
        let environment = b"KONSOLE_DBUS_SERVICE=:1.108\0KONSOLE_DBUS_SESSION=/Sessions/4\0KONSOLE_DBUS_WINDOW=/Windows/9\0SECRET_DO_NOT_RETAIN=sensitive\0";
        assert!(fs::write(process.join("environ"), environment).is_ok());

        let mut sampler = AttachmentSampler::new(proc_root.clone());
        sampler.observe(&claude_found(321, 700));
        let key = TuiKey {
            pid: 321,
            start_time: 700,
        };
        let target = sampler
            .sample()
            .claude_focus
            .get(&key)
            .cloned()
            .unwrap_or_else(|| unreachable!("validated Claude Konsole target"));
        assert_eq!(target.source, FocusProcessSource::Claude);
        assert!(matches!(target.client, ClientFocusTarget::Konsole(_)));
        assert!(!format!("{target:?}").contains("sensitive"));
        assert!(focus_process_matches(&proc_root, &target));

        assert!(fs::write(
            process.join("environ"),
            b"KONSOLE_DBUS_SERVICE=:1.108\0KONSOLE_DBUS_SESSION=/Sessions/5\0KONSOLE_DBUS_WINDOW=/Windows/9\0"
        ).is_ok());
        assert!(!focus_process_matches(&proc_root, &target));
        let changed = sampler
            .sample()
            .claude_focus
            .get(&key)
            .cloned()
            .unwrap_or_else(|| unreachable!("changed identifiers form a new valid target"));
        assert_ne!(changed, target);
        assert!(focus_process_matches(&proc_root, &changed));

        assert!(fs::write(process.join("environ"), environment).is_ok());
        assert!(
            fs::write(
                process.join("stat"),
                format!("321 (process) S 1 0 0 7 {} 701\n", vec!["0"; 14].join(" "))
            )
            .is_ok()
        );
        assert!(!focus_process_matches(&proc_root, &target));
        assert!(sampler.sample().claude_focus.is_empty());

        assert!(
            fs::write(
                process.join("stat"),
                format!("321 (process) S 1 0 0 7 {} 700\n", vec!["0"; 14].join(" "))
            )
            .is_ok()
        );
        assert!(fs::write(process.join("cmdline"), b"not-claude\0").is_ok());
        assert!(sampler.sample().claude_focus.is_empty());
        assert!(fs::write(process.join("cmdline"), b"claude\0").is_ok());
        assert!(
            fs::write(
                process.join("stat"),
                format!("321 (process) S 1 0 0 0 {} 700\n", vec!["0"; 14].join(" "))
            )
            .is_ok()
        );
        assert!(sampler.sample().claude_focus.is_empty());
        assert!(
            fs::write(
                process.join("stat"),
                format!("321 (process) S 1 0 0 7 {} 700\n", vec!["0"; 14].join(" "))
            )
            .is_ok()
        );
        assert!(
            fs::write(
                process.join("status"),
                format!("Uid:\t{}\t{}\t{}\t{}\n", uid + 1, uid + 1, uid + 1, uid + 1)
            )
            .is_ok()
        );
        assert!(sampler.sample().claude_focus.is_empty());
    }

    #[test]
    fn claude_kitty_focus_reuses_full_socket_validation_and_removal() {
        let (directory, _listener, tui, expected) = kitty_fixture();
        let proc_root = directory.path().join("proc");
        assert!(fs::write(proc_root.join("123/cmdline"), b"claude\0").is_ok());
        let mut sampler = AttachmentSampler::new(proc_root.clone());
        sampler.observe(&claude_found(tui.pid, tui.start_time));

        let snapshot = sampler.sample();
        let focus = snapshot
            .claude_focus
            .get(&tui)
            .unwrap_or_else(|| unreachable!("validated Claude Kitty target"));
        assert_eq!(focus.source, FocusProcessSource::Claude);
        assert_eq!(focus.client, ClientFocusTarget::Kitty(expected.clone()));
        assert!(focus_process_matches(&proc_root, focus));
        assert!(kitty_target_matches(&proc_root, tui, &expected));

        let BeaconEvent::ClaudeSessionFound(session) = claude_found(tui.pid, tui.start_time) else {
            unreachable!("fixture is a Claude lifecycle event");
        };
        sampler.observe(&BeaconEvent::ClaudeSessionRemoved(session));
        assert!(sampler.sample().claude_focus.is_empty());
    }

    #[test]
    fn malformed_kitty_evidence_falls_back_to_valid_konsole() {
        let directory = tempfile::tempdir()
            .unwrap_or_else(|error| unreachable!("temporary directory: {error}"));
        let process = directory.path().join("123");
        assert!(fs::create_dir(&process).is_ok());
        assert!(fs::write(
            process.join("environ"),
            b"KITTY_PID=not-a-pid\0KITTY_WINDOW_ID=7\0KITTY_LISTEN_ON=tcp:localhost:1\0KONSOLE_DBUS_SERVICE=:1.108\0KONSOLE_DBUS_SESSION=/Sessions/4\0KONSOLE_DBUS_WINDOW=/Windows/9\0"
        ).is_ok());
        let key = TuiKey {
            pid: 123,
            start_time: 100,
        };
        assert_eq!(
            read_focus_target(
                directory.path(),
                &process,
                key,
                FocusProcessSource::OpenCode,
            ),
            Some(FocusTarget {
                process: key,
                source: FocusProcessSource::OpenCode,
                client: ClientFocusTarget::Konsole(KonsoleTarget {
                    service: ":1.108".to_owned(),
                    session_path: "/Sessions/4".to_owned(),
                    window_path: "/Windows/9".to_owned(),
                }),
            })
        );
    }

    #[test]
    fn kitty_target_rejects_changed_process_socket_and_environment_identity() {
        let (directory, _listener, tui, target) = kitty_fixture();
        let proc_root = directory.path().join("proc");
        assert!(fs::remove_file(proc_root.join("500/fd/7")).is_ok());
        assert!(!kitty_target_matches(&proc_root, tui, &target));
        assert!(symlink("socket:[9001]", proc_root.join("500/fd/7")).is_ok());

        assert!(
            fs::write(
                proc_root.join("123/environ"),
                format!(
                    "KITTY_PID=500\0KITTY_WINDOW_ID=78\0KITTY_LISTEN_ON=unix:{}\0",
                    target.socket_path.display()
                )
            )
            .is_ok()
        );
        assert!(!kitty_target_matches(&proc_root, tui, &target));
    }

    #[test]
    fn kitty_target_validates_uid_namespace_effective_privacy_and_socket_identity() {
        let (directory, _listener, tui, target) = kitty_fixture();
        let proc_root = directory.path().join("proc");
        let uid = fs::metadata(directory.path())
            .unwrap_or_else(|error| unreachable!("metadata: {error}"))
            .uid();

        assert!(
            fs::write(
                proc_root.join("500/status"),
                format!("Uid:\t{}\t{}\t{}\t{}\n", uid + 1, uid + 1, uid + 1, uid + 1)
            )
            .is_ok()
        );
        assert!(!kitty_target_matches(&proc_root, tui, &target));
        assert!(
            fs::write(
                proc_root.join("500/status"),
                format!("Uid:\t{uid}\t{uid}\t{uid}\t{uid}\n")
            )
            .is_ok()
        );

        assert!(fs::remove_file(proc_root.join("500/ns/mnt")).is_ok());
        let other_namespace = directory.path().join("other-mount-namespace");
        assert!(fs::write(&other_namespace, "mnt").is_ok());
        assert!(symlink(&other_namespace, proc_root.join("500/ns/mnt")).is_ok());
        assert!(!kitty_target_matches(&proc_root, tui, &target));
        assert!(fs::remove_file(proc_root.join("500/ns/mnt")).is_ok());
        assert!(
            symlink(
                directory.path().join("mount-namespace"),
                proc_root.join("500/ns/mnt")
            )
            .is_ok()
        );

        assert!(fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).is_ok());
        assert!(
            fs::set_permissions(&target.socket_path, fs::Permissions::from_mode(0o775)).is_ok()
        );
        assert!(kitty_target_matches(&proc_root, tui, &target));
        assert!(fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o755)).is_ok());
        assert!(!kitty_target_matches(&proc_root, tui, &target));
        assert!(
            fs::set_permissions(&target.socket_path, fs::Permissions::from_mode(0o755)).is_ok()
        );
        assert!(kitty_target_matches(&proc_root, tui, &target));
        assert!(
            fs::set_permissions(&target.socket_path, fs::Permissions::from_mode(0o600)).is_ok()
        );

        let replacement_path = directory.path().join("replacement-kitty.sock");
        let _replacement = UnixListener::bind(&replacement_path)
            .unwrap_or_else(|error| unreachable!("bind replacement Kitty socket: {error}"));
        assert!(fs::set_permissions(&replacement_path, fs::Permissions::from_mode(0o600)).is_ok());
        assert!(fs::rename(&replacement_path, &target.socket_path).is_ok());
        assert!(!kitty_target_matches(&proc_root, tui, &target));
    }

    #[test]
    fn kitty_identifiers_reject_unsupported_addresses_and_conflicts() {
        for value in [
            b"tcp:localhost:5000".as_slice(),
            b"tcp6:[::1]:5000",
            b"fd:7",
            b"unix:@abstract",
            b"unix:relative",
            b"unix:/tmp/../socket",
        ] {
            assert!(
                valid_kitty_socket_path(value).is_none(),
                "accepted {value:?}"
            );
        }
        assert_eq!(positive_decimal(b"42"), Some(42));
        assert_eq!(positive_decimal_u64(b"42"), Some(42));
        for value in [b"".as_slice(), b"0", b"-1", b"1x"] {
            assert!(positive_decimal(value).is_none());
            assert!(positive_decimal_u64(value).is_none());
        }

        let directory = tempfile::tempdir()
            .unwrap_or_else(|error| unreachable!("temporary directory: {error}"));
        let process = directory.path().join("123");
        assert!(fs::create_dir(&process).is_ok());
        assert!(
            fs::write(
                process.join("environ"),
                b"KITTY_PID=1\0KITTY_PID=2\0KITTY_WINDOW_ID=7\0KITTY_LISTEN_ON=unix:/tmp/socket\0"
            )
            .is_ok()
        );
        assert!(
            !read_focus_environment(&process).is_some_and(|environment| environment.kitty_valid)
        );
    }

    #[test]
    fn unix_listener_parser_ignores_connections_and_rejects_duplicate_listeners() {
        let path = Path::new("/run/user/1000/kitty beacon.sock");
        let header = "Num RefCount Protocol Flags Type St Inode Path\n";
        let connection = "000: 2 0 00000000 0001 03 41 /run/user/1000/kitty beacon.sock\n";
        let listener = "000: 2 0 00010000 0001 01 42 /run/user/1000/kitty beacon.sock\n";
        assert_eq!(
            unix_listener_inode(&format!("{header}{connection}{listener}"), path),
            Some(42)
        );
        assert_eq!(
            unix_listener_inode(&format!("{header}{listener}{listener}"), path),
            None
        );
        assert_eq!(
            unix_listener_inode(&format!("{header}{connection}"), path),
            None
        );
    }
}
