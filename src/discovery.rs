use std::collections::{BTreeSet, HashMap, HashSet};
use std::ffi::{OsStr, OsString};
use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, Read};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use futures_util::{StreamExt, stream};

use secrecy::SecretString;
use serde::Deserialize;

use crate::client::{BasicAuth, ClientConfig, OpenCodeClient, OpenCodeV2Client};
use crate::model::{
    InstanceKey, InstanceSource, OpenCodeProtocol, ServerEndpoint, ServerInstance, Snapshot,
};

const MAX_REGISTRATION_SIZE: u64 = 64 * 1024;
const MAX_PROCESS_ENVIRONMENT_SIZE: u64 = 4 * 1024 * 1024;

/// Linux procfs discovery behavior.
#[derive(Clone, Debug)]
pub struct DiscoveryConfig {
    pub proc_root: PathBuf,
    pub probe_concurrency: usize,
}

/// Managed `OpenCode` service registration discovery behavior.
#[derive(Clone, Debug, Default)]
pub struct ManagedDiscoveryConfig {
    /// Overrides `OpenCode`'s XDG state directory, primarily for tests.
    pub state_dir: Option<PathBuf>,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) enum DiscoveryBackend {
    Procfs,
    Managed,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct ConnectionSettings {
    pub auth: Option<BasicAuth>,
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            proc_root: PathBuf::from("/proc"),
            probe_concurrency: 16,
        }
    }
}

/// One non-fatal discovery detail.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CandidateDiagnostic {
    pub message: String,
}

/// Results of one discovery pass.
#[derive(Clone, Debug, Default)]
pub struct DiscoveryReport {
    pub instances: Vec<ServerInstance>,
    pub diagnostics: Vec<CandidateDiagnostic>,
    pub listener_fingerprint: ListenerTableFingerprint,
    pub(crate) connections: HashMap<InstanceKey, ConnectionSettings>,
    pub(crate) incomplete_backends: HashSet<DiscoveryBackend>,
}

impl DiscoveryReport {
    /// Fetches a snapshot using the private connection metadata from this report.
    ///
    /// # Errors
    ///
    /// Returns an error when the instance is absent from the report or client setup or
    /// snapshot retrieval fails.
    pub async fn snapshot_for(
        &self,
        instance: &ServerInstance,
        mut client_config: ClientConfig,
    ) -> Result<Snapshot, String> {
        let connection = self
            .connections
            .get(&instance.key)
            .ok_or_else(|| "discovery report has no connection settings for instance".to_owned())?;
        match instance.protocol {
            OpenCodeProtocol::V1 => OpenCodeClient::new(instance.endpoint, client_config)
                .map_err(|error| error.to_string())?
                .snapshot()
                .await
                .map_err(|error| error.to_string()),
            OpenCodeProtocol::V2 => {
                client_config.auth = connection.auth.clone();
                OpenCodeV2Client::new(instance.endpoint, client_config)
                    .map_err(|error| error.to_string())?
                    .snapshot()
                    .await
                    .map_err(|error| error.to_string())
            }
        }
    }
}

/// Stable identity of eligible current-UID procfs listener rows.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ListenerTableFingerprint(
    BTreeSet<ListenerTableEntry>,
    BTreeSet<RegistrationTableEntry>,
);

impl ListenerTableFingerprint {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty() && self.1.is_empty()
    }

    #[cfg(test)]
    pub(crate) fn single(address: SocketAddr, inode: u64) -> Self {
        Self(
            BTreeSet::from([ListenerTableEntry { address, inode }]),
            BTreeSet::new(),
        )
    }

    pub(crate) fn with_registrations(
        mut self,
        registrations: BTreeSet<RegistrationTableEntry>,
    ) -> Self {
        self.1 = registrations;
        self
    }

    pub(crate) fn merged(mut self, other: Self) -> Self {
        self.0.extend(other.0);
        self.1.extend(other.1);
        self
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct ListenerTableEntry {
    address: SocketAddr,
    inode: u64,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct RegistrationTableEntry {
    path: PathBuf,
    device: u64,
    inode: u64,
    uid: u32,
    mode: u32,
    size: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

/// Discovers same-UID local `OpenCode` listeners without scanning ports.
#[derive(Clone, Debug)]
pub struct LinuxProcfsDiscovery {
    config: DiscoveryConfig,
}

impl LinuxProcfsDiscovery {
    #[must_use]
    pub const fn new(config: DiscoveryConfig) -> Self {
        Self { config }
    }

    /// Discovers and verifies likely `OpenCode` listeners.
    ///
    /// # Errors
    ///
    /// Returns an error when the current process's procfs network data cannot be read.
    pub async fn discover(
        &self,
        client_config: &ClientConfig,
    ) -> Result<DiscoveryReport, DiscoveryError> {
        let (candidates, mut diagnostics, listener_fingerprint) = scan(&self.config).await?;
        let concurrency = self.config.probe_concurrency.max(1);
        let probed = stream::iter(candidates)
            .map(|candidate| {
                let mut client_config = client_config.clone();
                async move {
                    let endpoint = ServerEndpoint::new(candidate.connect_address)
                        .map_err(|error| error.to_string())?;
                    let (version, connection) = match candidate.protocol {
                        OpenCodeProtocol::V1 => {
                            let client = OpenCodeClient::new(endpoint, client_config)
                                .map_err(|error| error.to_string())?;
                            let health =
                                client.health().await.map_err(|error| error.to_string())?;
                            if !health.healthy {
                                return Err("health response reported unhealthy".to_owned());
                            }
                            (health.version, ConnectionSettings { auth: None })
                        }
                        OpenCodeProtocol::V2 => {
                            client_config.auth = candidate.auth.clone();
                            let client = OpenCodeV2Client::new(endpoint, client_config)
                                .map_err(|error| error.to_string())?;
                            let health =
                                client.health().await.map_err(|error| error.to_string())?;
                            if !health.healthy || health.pid != candidate.pid {
                                return Err("standalone health identity mismatch".to_owned());
                            }
                            (
                                health.version,
                                ConnectionSettings {
                                    auth: candidate.auth,
                                },
                            )
                        }
                    };
                    Ok((
                        ServerInstance {
                            key: InstanceKey {
                                network_namespace_inode: candidate.network_namespace_inode,
                                socket_inode: candidate.socket_inode,
                                listener: candidate.listener,
                                pid: candidate.pid,
                                source: InstanceSource::LinuxProcfs,
                            },
                            endpoint,
                            protocol: candidate.protocol,
                            executable: candidate.executable,
                            version,
                        },
                        connection,
                    ))
                }
            })
            .buffer_unordered(concurrency)
            .collect::<Vec<_>>()
            .await;

        let mut instances = Vec::new();
        let mut connections = HashMap::new();
        for result in probed {
            match result {
                Ok((instance, connection)) => {
                    connections.insert(instance.key.clone(), connection);
                    instances.push(instance);
                }
                Err(message) => diagnostics.push(CandidateDiagnostic {
                    message: format!("candidate probe rejected: {message}"),
                }),
            }
        }
        let unique_instances = retain_unique_endpoints(instances, &mut diagnostics);
        let unique_keys = unique_instances
            .iter()
            .map(|instance| instance.key.clone())
            .collect::<HashSet<_>>();
        connections.retain(|key, _| unique_keys.contains(key));
        Ok(DiscoveryReport {
            instances: unique_instances,
            diagnostics,
            listener_fingerprint,
            connections,
            incomplete_backends: HashSet::new(),
        })
    }

    /// Reads only eligible current-UID TCP listener rows.
    ///
    /// This gate does not inspect processes, file descriptors, ancestry, or health.
    ///
    /// # Errors
    ///
    /// Returns an error when the current process's procfs TCP data is unavailable or malformed.
    pub fn listener_fingerprint(&self) -> Result<ListenerTableFingerprint, DiscoveryError> {
        let (_, fingerprint) = read_listener_table(&self.config)?;
        Ok(fingerprint)
    }
}

/// Discovers managed `OpenCode` v2 services from central registration files.
#[derive(Clone, Debug)]
pub struct ManagedServiceDiscovery {
    config: ManagedDiscoveryConfig,
    proc_root: PathBuf,
}

impl ManagedServiceDiscovery {
    #[must_use]
    pub const fn new(config: ManagedDiscoveryConfig, proc_root: PathBuf) -> Self {
        Self { config, proc_root }
    }

    pub(crate) fn registration_fingerprint(
        &self,
    ) -> Result<BTreeSet<RegistrationTableEntry>, DiscoveryError> {
        let mut fingerprint = BTreeSet::new();
        for path in registration_paths(&self.state_dir())? {
            let metadata = match fs::symlink_metadata(&path) {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error.into()),
            };
            fingerprint.insert(registration_table_entry(path, &metadata));
        }
        Ok(fingerprint)
    }

    /// Discovers and validates every recognized managed registration.
    ///
    /// # Errors
    ///
    /// Returns an error when the state directory or current effective UID cannot
    /// be inspected. Invalid individual registrations become diagnostics.
    pub async fn discover(
        &self,
        client_config: &ClientConfig,
    ) -> Result<DiscoveryReport, DiscoveryError> {
        let state_dir = self.state_dir();
        let uid = effective_uid(&self.proc_root.join("self"))?;
        let registrations = registration_paths(&state_dir)?;
        let registration_fingerprint = self.registration_fingerprint()?;
        let probed = stream::iter(registrations)
            .map(|path| {
                let client_config = client_config.clone();
                async move { discover_registration(path, uid, client_config).await }
            })
            .buffer_unordered(16)
            .collect::<Vec<_>>()
            .await;

        let mut instances = Vec::new();
        let mut connections = HashMap::new();
        let mut diagnostics = Vec::new();
        for result in probed {
            match result {
                Ok((instance, settings)) => {
                    connections.insert(instance.key.clone(), settings);
                    instances.push(instance);
                }
                Err(message) => diagnostics.push(CandidateDiagnostic { message }),
            }
        }
        instances.sort_by_key(|instance| instance.endpoint.address());
        let mut unique = Vec::new();
        for group in instances.chunk_by(|left, right| left.endpoint == right.endpoint) {
            if group.len() == 1 {
                unique.push(group[0].clone());
            } else {
                for instance in group {
                    connections.remove(&instance.key);
                }
                diagnostics.push(CandidateDiagnostic {
                    message: format!(
                        "managed endpoint {} has {} distinct registrations",
                        group[0].endpoint,
                        group.len()
                    ),
                });
            }
        }
        Ok(DiscoveryReport {
            instances: unique,
            diagnostics,
            listener_fingerprint: ListenerTableFingerprint::default()
                .with_registrations(registration_fingerprint),
            connections,
            incomplete_backends: HashSet::new(),
        })
    }

    /// Reopens the registration for a previously discovered instance without
    /// exposing its credential through lifecycle events.
    ///
    /// # Errors
    ///
    /// Returns an error if the registration is inaccessible, unsafe, changed,
    /// malformed, or cannot produce a client.
    pub fn client_for(
        &self,
        instance: &ServerInstance,
        mut client_config: ClientConfig,
    ) -> Result<OpenCodeV2Client, DiscoveryError> {
        let InstanceSource::ManagedService { registration, id } = &instance.key.source else {
            return Err(DiscoveryError::InvalidRegistration(
                "instance is not a managed service".to_owned(),
            ));
        };
        let uid = effective_uid(&self.proc_root.join("self"))?;
        let info =
            read_registration(registration, uid).map_err(DiscoveryError::InvalidRegistration)?;
        let endpoint =
            registration_endpoint(&info.url).map_err(DiscoveryError::InvalidRegistration)?;
        if endpoint != instance.endpoint
            || info.pid != instance.key.pid
            || &info.id != id
            || info
                .version
                .as_ref()
                .is_some_and(|version| version != &instance.version)
        {
            return Err(DiscoveryError::InvalidRegistration(
                "managed registration changed after discovery".to_owned(),
            ));
        }
        client_config.auth = info
            .password
            .map(|password| BasicAuth::new("opencode".to_owned(), SecretString::from(password)));
        OpenCodeV2Client::new(endpoint, client_config)
            .map_err(|error| DiscoveryError::InvalidRegistration(error.to_string()))
    }

    fn state_dir(&self) -> PathBuf {
        self.config.state_dir.clone().unwrap_or_else(|| {
            std::env::var_os("XDG_STATE_HOME").map_or_else(
                || {
                    std::env::var_os("HOME").map_or_else(
                        || PathBuf::from("/.local/state/opencode"),
                        |home| PathBuf::from(home).join(".local/state/opencode"),
                    )
                },
                |state| PathBuf::from(state).join("opencode"),
            )
        })
    }
}

#[derive(Deserialize)]
struct Registration {
    id: Option<String>,
    version: Option<String>,
    url: String,
    pid: u32,
    password: Option<String>,
}

async fn discover_registration(
    path: PathBuf,
    uid: u32,
    mut client_config: ClientConfig,
) -> Result<(ServerInstance, ConnectionSettings), String> {
    let registration = read_registration(&path, uid)?;
    let endpoint = registration_endpoint(&registration.url)?;
    client_config.auth = registration
        .password
        .map(|password| BasicAuth::new("opencode".to_owned(), SecretString::from(password)));
    let client = OpenCodeV2Client::new(endpoint, client_config.clone())
        .map_err(|error| format!("managed registration {} rejected: {error}", path.display()))?;
    let health = client.health().await.map_err(|error| {
        format!(
            "managed registration {} probe rejected: {error}",
            path.display()
        )
    })?;
    if !health.healthy || health.pid != registration.pid {
        return Err(format!(
            "managed registration {} health identity mismatch",
            path.display()
        ));
    }
    if registration
        .version
        .as_ref()
        .is_some_and(|version| version != &health.version)
    {
        return Err(format!(
            "managed registration {} health version mismatch",
            path.display()
        ));
    }
    let key = InstanceKey {
        network_namespace_inode: 0,
        socket_inode: 0,
        listener: endpoint.address(),
        pid: registration.pid,
        source: InstanceSource::ManagedService {
            registration: path,
            id: registration.id,
        },
    };
    Ok((
        ServerInstance {
            key,
            endpoint,
            protocol: OpenCodeProtocol::V2,
            executable: None,
            version: health.version,
        },
        ConnectionSettings {
            auth: client_config.auth,
        },
    ))
}

fn registration_paths(state_dir: &Path) -> Result<Vec<PathBuf>, DiscoveryError> {
    let entries = match fs::read_dir(state_dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error.into()),
    };
    let mut paths = Vec::new();
    for entry in entries {
        let path = entry?.path();
        if path
            .file_name()
            .and_then(OsStr::to_str)
            .is_some_and(is_registration_name)
        {
            paths.push(path);
        }
    }
    paths.sort();
    Ok(paths)
}

fn is_registration_name(name: &str) -> bool {
    name == "service.json"
        || name
            .strip_prefix("service-")
            .and_then(|suffix| suffix.strip_suffix(".json"))
            .is_some_and(|channel| {
                !channel.is_empty()
                    && channel.bytes().all(|byte| {
                        byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')
                    })
            })
}

fn registration_table_entry(path: PathBuf, metadata: &fs::Metadata) -> RegistrationTableEntry {
    RegistrationTableEntry {
        path,
        device: metadata.dev(),
        inode: metadata.ino(),
        uid: metadata.uid(),
        mode: metadata.mode(),
        size: metadata.len(),
        modified_seconds: metadata.mtime(),
        modified_nanoseconds: metadata.mtime_nsec(),
        changed_seconds: metadata.ctime(),
        changed_nanoseconds: metadata.ctime_nsec(),
    }
}

fn safe_registration_metadata(metadata: &fs::Metadata, uid: u32) -> bool {
    metadata.file_type().is_file()
        && metadata.uid() == uid
        && metadata.permissions().mode().is_multiple_of(0o100)
        && metadata.len() <= MAX_REGISTRATION_SIZE
}

fn read_registration(path: &Path, uid: u32) -> Result<Registration, String> {
    let before = fs::symlink_metadata(path).map_err(|error| {
        format!(
            "could not inspect managed registration {}: {error}",
            path.display()
        )
    })?;
    if !safe_registration_metadata(&before, uid) {
        return Err(format!(
            "managed registration {} has unsafe ownership, mode, type, or size",
            path.display()
        ));
    }
    let file = File::open(path).map_err(|error| {
        format!(
            "could not open managed registration {}: {error}",
            path.display()
        )
    })?;
    let opened = file.metadata().map_err(|error| {
        format!(
            "could not inspect managed registration {}: {error}",
            path.display()
        )
    })?;
    if !safe_registration_metadata(&opened, uid)
        || registration_table_entry(path.to_owned(), &opened)
            != registration_table_entry(path.to_owned(), &before)
    {
        return Err(format!(
            "managed registration {} changed while opening",
            path.display()
        ));
    }
    let mut text = String::new();
    (&file)
        .take(MAX_REGISTRATION_SIZE + 1)
        .read_to_string(&mut text)
        .map_err(|error| {
            format!(
                "could not read managed registration {}: {error}",
                path.display()
            )
        })?;
    if text.len() as u64 > MAX_REGISTRATION_SIZE {
        return Err(format!(
            "managed registration {} is too large",
            path.display()
        ));
    }
    let after = file.metadata().map_err(|error| {
        format!(
            "could not inspect managed registration {}: {error}",
            path.display()
        )
    })?;
    let path_after = fs::symlink_metadata(path).map_err(|error| {
        format!(
            "could not reinspect managed registration {}: {error}",
            path.display()
        )
    })?;
    let opened = registration_table_entry(path.to_owned(), &opened);
    if opened != registration_table_entry(path.to_owned(), &after)
        || opened != registration_table_entry(path.to_owned(), &path_after)
    {
        return Err(format!(
            "managed registration {} changed while reading",
            path.display()
        ));
    }
    let registration: Registration = serde_json::from_str(&text)
        .map_err(|error| format!("invalid managed registration {}: {error}", path.display()))?;
    if registration.pid == 0 {
        return Err(format!(
            "managed registration {} has invalid PID",
            path.display()
        ));
    }
    Ok(registration)
}

fn registration_endpoint(value: &str) -> Result<ServerEndpoint, String> {
    let url = url::Url::parse(value).map_err(|error| format!("invalid service URL: {error}"))?;
    if url.scheme() != "http"
        || url.username() != ""
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !matches!(url.path(), "" | "/")
    {
        return Err("managed service URL must be an uncredentialed HTTP origin".to_owned());
    }
    let ip = match url.host() {
        Some(url::Host::Ipv4(ip)) => IpAddr::V4(ip),
        Some(url::Host::Ipv6(ip)) => IpAddr::V6(ip),
        _ => return Err("managed service URL host must be a loopback IP address".to_owned()),
    };
    let port = url
        .port()
        .ok_or_else(|| "managed service URL must include a port".to_owned())?;
    ServerEndpoint::new(SocketAddr::new(ip, port)).map_err(|error| error.to_string())
}

fn retain_unique_endpoints(
    mut instances: Vec<ServerInstance>,
    diagnostics: &mut Vec<CandidateDiagnostic>,
) -> Vec<ServerInstance> {
    instances.sort_by_key(|instance| (instance.endpoint.address(), instance.key.socket_inode));
    let mut unique_instances = Vec::new();
    for instances in instances.chunk_by(|left, right| left.endpoint == right.endpoint) {
        if instances.len() == 1 {
            unique_instances.push(instances[0].clone());
        } else {
            diagnostics.push(CandidateDiagnostic {
                message: format!(
                    "candidate endpoint {} has {} distinct socket identities",
                    instances[0].endpoint,
                    instances.len()
                ),
            });
        }
    }
    unique_instances
}

#[derive(Clone, Debug)]
struct Listener {
    address: SocketAddr,
    uid: u32,
    inode: u64,
}

#[derive(Clone, Debug)]
struct Candidate {
    listener: SocketAddr,
    connect_address: SocketAddr,
    socket_inode: u64,
    network_namespace_inode: u64,
    pid: u32,
    executable: Option<String>,
    protocol: OpenCodeProtocol,
    auth: Option<BasicAuth>,
}

#[derive(Clone, Debug)]
struct CandidateOwner {
    pid: u32,
    executable: Option<String>,
    protocol: OpenCodeProtocol,
    auth: Option<BasicAuth>,
}

trait NamespaceIdentitySource {
    fn network_namespace_inode(&self, process: &Path) -> io::Result<u64>;
}

struct ProcfsNamespaceIdentitySource;

impl NamespaceIdentitySource for ProcfsNamespaceIdentitySource {
    fn network_namespace_inode(&self, process: &Path) -> io::Result<u64> {
        Ok(fs::metadata(process.join("ns/net"))?.ino())
    }
}

// TODO: Make excluded ancestor launcher basenames configurable.
const EXCLUDED_ANCESTOR_LAUNCHERS: [&str; 1] = ["opencode-orchestrator-mcp"];
const MAX_ANCESTRY_DEPTH: usize = 256;

#[derive(Clone, Debug, Eq, PartialEq)]
struct ProcessStat {
    pid: u32,
    parent_pid: u32,
    start_time: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum LauncherIdentity {
    Executable(OsString),
    Argv0(OsString),
}

impl LauncherIdentity {
    fn basename(&self) -> &OsStr {
        match self {
            Self::Executable(basename) | Self::Argv0(basename) => basename,
        }
    }
}

trait ProcessAncestrySource {
    fn process_stat(&self, pid: u32) -> io::Result<ProcessStat>;
    fn launcher_identity(&self, pid: u32) -> io::Result<LauncherIdentity>;
}

struct ProcfsProcessAncestrySource<'a> {
    root: &'a Path,
}

impl ProcessAncestrySource for ProcfsProcessAncestrySource<'_> {
    fn process_stat(&self, pid: u32) -> io::Result<ProcessStat> {
        parse_process_stat(&fs::read_to_string(
            self.root.join(pid.to_string()).join("stat"),
        )?)
    }

    fn launcher_identity(&self, pid: u32) -> io::Result<LauncherIdentity> {
        let process = self.root.join(pid.to_string());
        if let Ok(executable) = fs::read_link(process.join("exe")) {
            let basename = executable.file_name().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "executable has no basename")
            })?;
            return Ok(LauncherIdentity::Executable(basename.to_owned()));
        }

        let cmdline = fs::read(process.join("cmdline"))?;
        let argv0 = cmdline.split(|byte| *byte == 0).next().unwrap_or_default();
        if argv0.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "process has no argv[0]",
            ));
        }
        let basename = Path::new(OsStr::from_bytes(argv0))
            .file_name()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "argv[0] has no basename"))?;
        Ok(LauncherIdentity::Argv0(basename.to_owned()))
    }
}

async fn scan(
    config: &DiscoveryConfig,
) -> Result<
    (
        Vec<Candidate>,
        Vec<CandidateDiagnostic>,
        ListenerTableFingerprint,
    ),
    DiscoveryError,
> {
    scan_with_namespace_source(config, &ProcfsNamespaceIdentitySource).await
}

#[allow(clippy::too_many_lines)]
async fn scan_with_namespace_source<N: NamespaceIdentitySource + Sync>(
    config: &DiscoveryConfig,
    namespaces: &N,
) -> Result<
    (
        Vec<Candidate>,
        Vec<CandidateDiagnostic>,
        ListenerTableFingerprint,
    ),
    DiscoveryError,
> {
    let self_root = config.proc_root.join("self");
    let network_namespace_inode = namespaces.network_namespace_inode(&self_root)?;
    let (listeners, listener_fingerprint) = read_listener_table(config)?;
    let uid = effective_uid(&self_root)?;

    let wanted = listeners
        .iter()
        .map(|listener| listener.inode)
        .collect::<HashSet<_>>();
    let mut owners: HashMap<u64, Vec<CandidateOwner>> = HashMap::new();
    let mut diagnostics = Vec::new();
    let ancestry = ProcfsProcessAncestrySource {
        root: &config.proc_root,
    };
    for entry in fs::read_dir(&config.proc_root)? {
        tokio::task::yield_now().await;
        let Ok(entry) = entry else { continue };
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<u32>().ok())
        else {
            continue;
        };
        let process = entry.path();
        let Ok(process_uid) = effective_uid(&process) else {
            continue;
        };
        if !owned_by_current_uid(process_uid, uid) || !likely_opencode(&process) {
            continue;
        }
        let process_stat_before = ancestry
            .process_stat(pid)
            .ok()
            .filter(|stat| stat.pid == pid);
        let namespace_before = match namespaces.network_namespace_inode(&process) {
            Ok(inode) => inode,
            Err(error) => {
                diagnostics.push(CandidateDiagnostic {
                    message: format!("could not inspect network namespace for PID {pid}: {error}"),
                });
                continue;
            }
        };
        if namespace_before != network_namespace_inode {
            diagnostics.push(CandidateDiagnostic {
                message: format!("PID {pid} is in a different network namespace"),
            });
            continue;
        }
        let executable = fs::read_link(process.join("exe"))
            .ok()
            .map(|path| path.to_string_lossy().into_owned());
        let Ok(fds) = fs::read_dir(process.join("fd")) else {
            diagnostics.push(CandidateDiagnostic {
                message: format!("could not inspect file descriptors for PID {pid}"),
            });
            continue;
        };
        let mut matched_inodes = HashSet::new();
        for (index, fd) in fds.flatten().enumerate() {
            if index % 64 == 0 {
                tokio::task::yield_now().await;
            }
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
            if wanted.contains(&inode) {
                matched_inodes.insert(inode);
            }
        }
        if matched_inodes.is_empty() {
            continue;
        }
        let namespace_after = match namespaces.network_namespace_inode(&process) {
            Ok(inode) => inode,
            Err(error) => {
                diagnostics.push(CandidateDiagnostic {
                    message: format!(
                        "network namespace became inaccessible for PID {pid}: {error}"
                    ),
                });
                continue;
            }
        };
        if namespace_after != namespace_before {
            diagnostics.push(CandidateDiagnostic {
                message: format!("network namespace changed while inspecting PID {pid}"),
            });
            continue;
        }
        if let Some(launcher) = process_stat_before
            .as_ref()
            .and_then(|initial| excluded_ancestor_launcher_from(&ancestry, initial))
        {
            diagnostics.push(CandidateDiagnostic {
                message: format!(
                    "excluded OpenCode listener owned by PID {pid} with ancestor launcher {launcher}"
                ),
            });
            continue;
        }
        let protocol = if is_stdio_v2_server(&process) {
            OpenCodeProtocol::V2
        } else {
            OpenCodeProtocol::V1
        };
        let auth = if protocol == OpenCodeProtocol::V2 {
            match standalone_auth(&process) {
                Ok(auth) => Some(auth),
                Err(message) => {
                    diagnostics.push(CandidateDiagnostic {
                        message: format!(
                            "standalone OpenCode server PID {pid} rejected: {message}"
                        ),
                    });
                    continue;
                }
            }
        } else {
            None
        };
        if protocol == OpenCodeProtocol::V2
            && process_stat_before
                .as_ref()
                .is_none_or(|before| ancestry.process_stat(pid).ok().as_ref() != Some(before))
        {
            diagnostics.push(CandidateDiagnostic {
                message: format!(
                    "standalone OpenCode server PID {pid} changed while credentials were inspected"
                ),
            });
            continue;
        }
        for inode in matched_inodes {
            owners.entry(inode).or_default().push(CandidateOwner {
                pid,
                executable: executable.clone(),
                protocol,
                auth: auth.clone(),
            });
        }
    }

    let mut candidates = Vec::new();
    for listener in listeners {
        let Some(processes) = owners.get(&listener.inode) else {
            continue;
        };
        let Some(owner) = processes.iter().min_by_key(|owner| owner.pid) else {
            continue;
        };
        candidates.push(Candidate {
            listener: listener.address,
            connect_address: normalize_connect_address(listener.address),
            socket_inode: listener.inode,
            network_namespace_inode,
            pid: owner.pid,
            executable: owner.executable.clone(),
            protocol: owner.protocol,
            auth: owner.auth.clone(),
        });
    }
    candidates.sort_by_key(|candidate| {
        (
            candidate.connect_address,
            candidate.socket_inode,
            candidate.listener,
        )
    });
    candidates.dedup_by_key(|candidate| {
        (
            candidate.connect_address,
            candidate.socket_inode,
            candidate.listener,
        )
    });
    Ok((candidates, diagnostics, listener_fingerprint))
}

fn is_stdio_v2_server(process: &Path) -> bool {
    let Ok(command_line) = fs::read(process.join("cmdline")) else {
        return false;
    };
    let arguments = command_line
        .split(|byte| *byte == 0)
        .filter(|argument| !argument.is_empty())
        .collect::<Vec<_>>();
    let Some(executable) = arguments.first() else {
        return false;
    };
    let executable = Path::new(OsStr::from_bytes(executable))
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_ascii_lowercase();
    executable.contains("opencode")
        && arguments
            .iter()
            .skip(1)
            .any(|argument| *argument == b"serve")
        && arguments
            .iter()
            .skip(1)
            .any(|argument| *argument == b"--stdio")
}

fn standalone_auth(process: &Path) -> Result<BasicAuth, &'static str> {
    let file =
        File::open(process.join("environ")).map_err(|_| "process environment is unavailable")?;
    let mut environment = BufReader::new(file.take(MAX_PROCESS_ENVIRONMENT_SIZE + 1));
    let prefix = b"OPENCODE_PASSWORD=";
    let mut total = 0_u64;
    let mut entry = Vec::new();
    loop {
        entry.clear();
        let read = environment
            .read_until(0, &mut entry)
            .map_err(|_| "process environment could not be read")?;
        if read == 0 {
            return Err("standalone credential is unavailable");
        }
        total = total.saturating_add(read as u64);
        if total > MAX_PROCESS_ENVIRONMENT_SIZE {
            return Err("process environment exceeds the safety limit");
        }
        if entry.last() == Some(&0) {
            entry.pop();
        }
        let Some(password) = entry
            .strip_prefix(prefix)
            .filter(|password| !password.is_empty())
        else {
            continue;
        };
        let password = String::from_utf8(password.to_vec())
            .map_err(|_| "standalone credential is not UTF-8")?;
        return Ok(BasicAuth::new(
            "opencode".to_owned(),
            SecretString::from(password),
        ));
    }
}

fn read_listener_table(
    config: &DiscoveryConfig,
) -> Result<(Vec<Listener>, ListenerTableFingerprint), DiscoveryError> {
    let self_root = config.proc_root.join("self");
    let uid = effective_uid(&self_root)?;
    let mut listeners = parse_listeners(&fs::read_to_string(self_root.join("net/tcp"))?, false)?;
    match fs::read_to_string(self_root.join("net/tcp6")) {
        Ok(contents) => listeners.extend(parse_listeners(&contents, true)?),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    listeners.retain(|listener| eligible_listener(listener.address) && listener.uid == uid);
    let fingerprint = ListenerTableFingerprint(
        listeners
            .iter()
            .map(|listener| ListenerTableEntry {
                address: listener.address,
                inode: listener.inode,
            })
            .collect(),
        BTreeSet::new(),
    );
    Ok((listeners, fingerprint))
}

const fn eligible_listener(address: SocketAddr) -> bool {
    address.ip().is_loopback() || address.ip().is_unspecified()
}

const fn owned_by_current_uid(process_uid: u32, current_uid: u32) -> bool {
    process_uid == current_uid
}

fn effective_uid(process: &Path) -> io::Result<u32> {
    let status = fs::read_to_string(process.join("status"))?;
    let uid = status
        .lines()
        .find_map(|line| line.strip_prefix("Uid:"))
        .and_then(|uids| uids.split_whitespace().nth(1))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "status has no effective UID"))?;
    uid.parse()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

fn likely_opencode(process: &Path) -> bool {
    let exe = fs::read_link(process.join("exe"))
        .ok()
        .map(|value| value.to_string_lossy().to_ascii_lowercase());
    let comm = fs::read_to_string(process.join("comm"))
        .ok()
        .map(|value| value.to_ascii_lowercase());
    let cmdline = fs::read(process.join("cmdline"))
        .ok()
        .map(|value| String::from_utf8_lossy(&value).to_ascii_lowercase());
    [exe, comm, cmdline]
        .into_iter()
        .flatten()
        .any(|value| value.contains("opencode"))
}

fn parse_process_stat(contents: &str) -> io::Result<ProcessStat> {
    let open = contents.find('(').ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "process stat has no command start",
        )
    })?;
    let close = contents
        .rfind(')')
        .filter(|close| *close > open)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "process stat has no command end",
            )
        })?;
    let pid = contents[..open]
        .trim()
        .parse::<u32>()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let fields = contents[close + 1..].split_whitespace().collect::<Vec<_>>();
    if fields.len() < 20 || fields[0].len() != 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "process stat has too few fields",
        ));
    }
    let parent_pid = fields[1]
        .parse::<u32>()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let start_time = fields[19]
        .parse::<u64>()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    Ok(ProcessStat {
        pid,
        parent_pid,
        start_time,
    })
}

fn excluded_ancestor_launcher_from<S: ProcessAncestrySource>(
    source: &S,
    initial: &ProcessStat,
) -> Option<&'static str> {
    if source.process_stat(initial.pid).ok().as_ref() != Some(initial) {
        return None;
    }

    let mut snapshots = vec![(initial.pid, initial.clone())];
    let mut visited = HashSet::from([initial.pid]);
    let mut matched = None;
    for _ in 0..MAX_ANCESTRY_DEPTH {
        let parent_pid = snapshots.last()?.1.parent_pid;
        if parent_pid == 0 {
            return None;
        }
        if parent_pid == 1 {
            let (launcher, marker_pid, marker_identity) = matched?;
            if snapshots.iter().any(|(snapshot_pid, snapshot)| {
                !matches!(source.process_stat(*snapshot_pid), Ok(current) if current == *snapshot)
            }) || !matches!(source.launcher_identity(marker_pid), Ok(current) if current == marker_identity)
            {
                return None;
            }
            return Some(launcher);
        }
        if !visited.insert(parent_pid) {
            return None;
        }

        let parent_stat = source.process_stat(parent_pid).ok()?;
        if parent_stat.pid != parent_pid || parent_stat.start_time > snapshots.last()?.1.start_time
        {
            return None;
        }
        let identity = source.launcher_identity(parent_pid).ok()?;
        snapshots.push((parent_pid, parent_stat));

        if matched.is_none() {
            matched = EXCLUDED_ANCESTOR_LAUNCHERS
                .iter()
                .find(|launcher| identity.basename() == OsStr::new(launcher))
                .copied()
                .map(|launcher| (launcher, parent_pid, identity));
        }
    }
    None
}

const fn normalize_connect_address(listener: SocketAddr) -> SocketAddr {
    match listener.ip() {
        IpAddr::V4(ip) if ip.is_unspecified() => {
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), listener.port())
        }
        IpAddr::V6(ip) if ip.is_unspecified() => {
            SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), listener.port())
        }
        _ => listener,
    }
}

fn parse_listeners(contents: &str, ipv6: bool) -> Result<Vec<Listener>, DiscoveryError> {
    let mut listeners = Vec::new();
    for line in contents.lines().skip(1) {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        if fields.len() < 10 || fields[3] != "0A" {
            continue;
        }
        let (address, port) = fields[1]
            .split_once(':')
            .ok_or_else(|| DiscoveryError::MalformedProcfs(line.to_owned()))?;
        let port = u16::from_str_radix(port, 16)
            .map_err(|_| DiscoveryError::MalformedProcfs(line.to_owned()))?;
        let ip = if ipv6 {
            IpAddr::V6(
                parse_ipv6(address)
                    .ok_or_else(|| DiscoveryError::MalformedProcfs(line.to_owned()))?,
            )
        } else {
            let raw = u32::from_str_radix(address, 16)
                .map_err(|_| DiscoveryError::MalformedProcfs(line.to_owned()))?;
            IpAddr::V4(Ipv4Addr::from(raw.to_le_bytes()))
        };
        let inode = fields[9]
            .parse::<u64>()
            .map_err(|_| DiscoveryError::MalformedProcfs(line.to_owned()))?;
        let uid = fields[7]
            .parse::<u32>()
            .map_err(|_| DiscoveryError::MalformedProcfs(line.to_owned()))?;
        listeners.push(Listener {
            address: SocketAddr::new(ip, port),
            uid,
            inode,
        });
    }
    Ok(listeners)
}

fn parse_ipv6(value: &str) -> Option<Ipv6Addr> {
    if value.len() != 32 {
        return None;
    }
    let mut octets = [0_u8; 16];
    for (word_index, word) in value.as_bytes().chunks_exact(8).enumerate() {
        let text = std::str::from_utf8(word).ok()?;
        let parsed = u32::from_str_radix(text, 16).ok()?.to_le_bytes();
        octets[word_index * 4..word_index * 4 + 4].copy_from_slice(&parsed);
    }
    Some(Ipv6Addr::from(octets))
}

/// Procfs discovery failure.
#[derive(Debug, thiserror::Error)]
pub enum DiscoveryError {
    #[error("procfs access failed: {0}")]
    Io(#[from] io::Error),
    #[error("malformed procfs TCP row: {0}")]
    MalformedProcfs(String),
    #[error("invalid managed service registration: {0}")]
    InvalidRegistration(String),
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::Mutex;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use super::*;

    struct ScriptedNamespaceSource {
        responses: Mutex<HashMap<PathBuf, VecDeque<Result<u64, io::ErrorKind>>>>,
    }

    struct ScriptedAncestrySource {
        stats: Mutex<HashMap<u32, VecDeque<Result<ProcessStat, io::ErrorKind>>>>,
        identities: Mutex<HashMap<u32, VecDeque<Result<LauncherIdentity, io::ErrorKind>>>>,
    }

    impl NamespaceIdentitySource for ScriptedNamespaceSource {
        fn network_namespace_inode(&self, process: &Path) -> io::Result<u64> {
            let mut responses = self
                .responses
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            match responses.get_mut(process).and_then(VecDeque::pop_front) {
                Some(Ok(inode)) => Ok(inode),
                Some(Err(kind)) => Err(io::Error::from(kind)),
                None => Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("no scripted namespace identity for {}", process.display()),
                )),
            }
        }
    }

    impl ProcessAncestrySource for ScriptedAncestrySource {
        fn process_stat(&self, pid: u32) -> io::Result<ProcessStat> {
            let mut stats = self
                .stats
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            match stats.get_mut(&pid).and_then(VecDeque::pop_front) {
                Some(Ok(stat)) => Ok(stat),
                Some(Err(kind)) => Err(io::Error::from(kind)),
                None => Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("no scripted process stat for PID {pid}"),
                )),
            }
        }

        fn launcher_identity(&self, pid: u32) -> io::Result<LauncherIdentity> {
            let mut identities = self
                .identities
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            match identities.get_mut(&pid).and_then(VecDeque::pop_front) {
                Some(Ok(identity)) => Ok(identity),
                Some(Err(kind)) => Err(io::Error::from(kind)),
                None => Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("no scripted launcher identity for PID {pid}"),
                )),
            }
        }
    }

    fn synthetic_stat(pid: u32, parent_pid: u32, start_time: u64) -> String {
        format!(
            "{pid} (synthetic process) S {parent_pid} {} {start_time}\n",
            vec!["0"; 17].join(" ")
        )
    }

    fn synthetic_status(uid: u32) -> String {
        format!("Name:\tsynthetic\nUid:\t{uid}\t{uid}\t{uid}\t{uid}\n")
    }

    fn write_process(
        root: &Path,
        pid: u32,
        parent_pid: u32,
        start_time: u64,
        basename: &str,
        executable_available: bool,
    ) {
        let process = root.join(pid.to_string());
        assert!(fs::create_dir_all(&process).is_ok());
        assert!(
            fs::write(
                process.join("stat"),
                synthetic_stat(pid, parent_pid, start_time)
            )
            .is_ok()
        );
        assert!(fs::write(process.join("cmdline"), format!("/tools/{basename}\0")).is_ok());
        if executable_available {
            assert!(
                std::os::unix::fs::symlink(format!("/tools/{basename}"), process.join("exe"))
                    .is_ok()
            );
        }
    }

    fn synthetic_procfs() -> (tempfile::TempDir, DiscoveryConfig) {
        let directory =
            tempfile::tempdir().unwrap_or_else(|error| unreachable!("temp directory: {error}"));
        let root = directory.path();
        assert!(fs::create_dir_all(root.join("self/net")).is_ok());
        assert!(fs::create_dir_all(root.join("123/fd")).is_ok());
        assert!(fs::write(root.join("123/comm"), "opencode\n").is_ok());
        assert!(fs::write(root.join("123/cmdline"), b"opencode\0serve\0").is_ok());
        assert!(fs::write(root.join("123/stat"), synthetic_stat(123, 1, 100)).is_ok());
        assert!(std::os::unix::fs::symlink("socket:[42]", root.join("123/fd/3")).is_ok());
        let uid = fs::metadata(root.join("self"))
            .unwrap_or_else(|error| unreachable!("self metadata: {error}"))
            .uid();
        assert!(fs::write(root.join("self/status"), synthetic_status(uid)).is_ok());
        assert!(fs::write(root.join("123/status"), synthetic_status(uid)).is_ok());
        let tcp = format!("header\n0: 0100007F:1234 00000000:0000 0A 0:0 00:0 0 {uid} 0 42\n");
        assert!(fs::write(root.join("self/net/tcp"), tcp).is_ok());
        let config = DiscoveryConfig {
            proc_root: root.to_path_buf(),
            probe_concurrency: 1,
        };
        (directory, config)
    }

    async fn scan_with_scripted_process_namespaces(
        process_responses: Vec<Result<u64, io::ErrorKind>>,
    ) -> (Vec<Candidate>, Vec<CandidateDiagnostic>) {
        let (_directory, config) = synthetic_procfs();
        scan_config_with_scripted_process_namespaces(&config, process_responses).await
    }

    async fn scan_config_with_scripted_process_namespaces(
        config: &DiscoveryConfig,
        process_responses: Vec<Result<u64, io::ErrorKind>>,
    ) -> (Vec<Candidate>, Vec<CandidateDiagnostic>) {
        let source = ScriptedNamespaceSource {
            responses: Mutex::new(HashMap::from([
                (config.proc_root.join("self"), VecDeque::from([Ok(10)])),
                (
                    config.proc_root.join("123"),
                    VecDeque::from(process_responses),
                ),
            ])),
        };
        let (candidates, diagnostics, _) = scan_with_namespace_source(config, &source)
            .await
            .unwrap_or_else(|error| unreachable!("synthetic procfs scans: {error}"));
        (candidates, diagnostics)
    }

    #[test]
    fn parses_only_listening_ipv4_sockets() {
        let data = include_str!("../tests/fixtures/proc-net-tcp.txt");
        let parsed = parse_listeners(data, false);
        assert!(parsed.is_ok_and(|listeners| {
            listeners.len() == 2
                && listeners[0].address == SocketAddr::from(([127, 0, 0, 1], 4660))
                && listeners[0].uid == 1000
                && listeners[0].inode == 42
                && listeners[1].uid == 1001
                && listeners[1].inode == 43
        }));
    }

    #[test]
    fn tcp_row_uid_is_part_of_the_discovery_boundary() {
        let mut listeners =
            parse_listeners(include_str!("../tests/fixtures/proc-net-tcp.txt"), false)
                .unwrap_or_else(|error| unreachable!("fixture parses: {error}"));
        listeners.retain(|listener| eligible_listener(listener.address) && listener.uid == 1000);
        assert_eq!(listeners.len(), 1);
        assert_eq!(listeners[0].inode, 42);
    }

    #[test]
    fn listener_gate_filters_uid_binding_and_state_across_ipv4_and_ipv6() {
        let (_directory, config) = synthetic_procfs();
        let uid = fs::metadata(config.proc_root.join("self"))
            .unwrap_or_else(|error| unreachable!("self metadata: {error}"))
            .uid();
        let tcp = format!(
            "header\n0: 0100007F:1000 00000000:0000 0A 0:0 00:0 0 {uid} 0 10\n1: 00000000:1001 00000000:0000 0A 0:0 00:0 0 {uid} 0 11\n2: 010200C0:1002 00000000:0000 0A 0:0 00:0 0 {uid} 0 12\n3: 0100007F:1003 00000000:0000 01 0:0 00:0 0 {uid} 0 13\n4: 0100007F:1004 00000000:0000 0A 0:0 00:0 0 {} 0 14\n",
            uid.wrapping_add(1)
        );
        let tcp6 = format!(
            "header\n0: 00000000000000000000000001000000:1005 00000000000000000000000000000000:0000 0A 0:0 00:0 0 {uid} 0 15\n1: 00000000000000000000000000000000:1006 00000000000000000000000000000000:0000 0A 0:0 00:0 0 {uid} 0 16\n"
        );
        assert!(fs::write(config.proc_root.join("self/net/tcp"), tcp).is_ok());
        assert!(fs::write(config.proc_root.join("self/net/tcp6"), tcp6).is_ok());

        let fingerprint = LinuxProcfsDiscovery::new(config)
            .listener_fingerprint()
            .unwrap_or_else(|error| unreachable!("listener table parses: {error}"));
        assert_eq!(fingerprint.0.len(), 4);
        assert!(fingerprint.0.iter().any(|entry| entry.address.is_ipv4()));
        assert!(fingerprint.0.iter().any(|entry| entry.address.is_ipv6()));
    }

    #[test]
    fn listener_gate_fingerprint_is_order_stable_and_tracks_all_identity_changes() {
        let (_directory, config) = synthetic_procfs();
        let discovery = LinuxProcfsDiscovery::new(config.clone());
        let first = discovery
            .listener_fingerprint()
            .unwrap_or_else(|error| unreachable!("initial gate check: {error}"));
        let uid = fs::metadata(config.proc_root.join("self"))
            .unwrap_or_else(|error| unreachable!("self metadata: {error}"))
            .uid();
        let extra = format!("1: 00000000:1235 00000000:0000 0A 0:0 00:0 0 {uid} 0 43\n");
        let original = fs::read_to_string(config.proc_root.join("self/net/tcp"))
            .unwrap_or_else(|error| unreachable!("synthetic TCP table: {error}"));
        let original_row = original.lines().nth(1).unwrap_or_default();
        assert!(
            fs::write(
                config.proc_root.join("self/net/tcp"),
                format!("header\n{extra}{original_row}\n")
            )
            .is_ok()
        );
        let added = discovery
            .listener_fingerprint()
            .unwrap_or_else(|error| unreachable!("added listener gate check: {error}"));
        assert_ne!(first, added);

        assert!(
            fs::write(
                config.proc_root.join("self/net/tcp"),
                format!("header\n{original_row}\n{extra}")
            )
            .is_ok()
        );
        assert_eq!(
            discovery
                .listener_fingerprint()
                .unwrap_or_else(|error| unreachable!("reordered gate check: {error}")),
            added
        );

        let replaced = original_row.replace(" 42", " 44");
        assert!(
            fs::write(
                config.proc_root.join("self/net/tcp"),
                format!("header\n{replaced}\n{extra}")
            )
            .is_ok()
        );
        assert_ne!(
            discovery
                .listener_fingerprint()
                .unwrap_or_else(|error| unreachable!("replacement gate check: {error}")),
            added
        );
    }

    #[test]
    fn listener_gate_never_traverses_processes_and_errors_on_tcp_uncertainty() {
        let (_directory, config) = synthetic_procfs();
        let discovery = LinuxProcfsDiscovery::new(config.clone());
        let expected = discovery
            .listener_fingerprint()
            .unwrap_or_else(|error| unreachable!("initial gate check: {error}"));
        assert!(fs::remove_dir_all(config.proc_root.join("123")).is_ok());
        assert_eq!(
            discovery
                .listener_fingerprint()
                .unwrap_or_else(|error| unreachable!("process-independent gate check: {error}")),
            expected
        );
        assert!(fs::remove_file(config.proc_root.join("self/net/tcp")).is_ok());
        assert!(discovery.listener_fingerprint().is_err());
    }

    #[tokio::test]
    async fn scan_requires_tcp_row_and_process_to_match_current_uid() {
        let directory =
            tempfile::tempdir().unwrap_or_else(|error| unreachable!("temp directory: {error}"));
        let root = directory.path();
        assert!(fs::create_dir_all(root.join("self/ns")).is_ok());
        assert!(fs::create_dir_all(root.join("self/net")).is_ok());
        assert!(fs::create_dir_all(root.join("123/ns")).is_ok());
        assert!(fs::create_dir_all(root.join("123/fd")).is_ok());
        assert!(fs::write(root.join("self/ns/net"), "namespace").is_ok());
        assert!(fs::hard_link(root.join("self/ns/net"), root.join("123/ns/net")).is_ok());
        assert!(fs::write(root.join("123/comm"), "opencode\n").is_ok());
        assert!(fs::write(root.join("123/cmdline"), b"opencode\0serve\0").is_ok());
        assert!(std::os::unix::fs::symlink("socket:[42]", root.join("123/fd/3")).is_ok());
        assert!(std::os::unix::fs::symlink("socket:[43]", root.join("123/fd/4")).is_ok());
        let uid = fs::metadata(root.join("self"))
            .unwrap_or_else(|error| unreachable!("self metadata: {error}"))
            .uid();
        assert!(fs::write(root.join("self/status"), synthetic_status(uid)).is_ok());
        assert!(fs::write(root.join("123/status"), synthetic_status(uid)).is_ok());
        let tcp = format!(
            "header\n0: 0100007F:1234 00000000:0000 0A 0:0 00:0 0 {uid} 0 42\n1: 0100007F:1235 00000000:0000 0A 0:0 00:0 0 {} 0 43\n",
            uid.wrapping_add(1)
        );
        assert!(fs::write(root.join("self/net/tcp"), tcp).is_ok());

        let (candidates, _, _) = scan(&DiscoveryConfig {
            proc_root: root.to_path_buf(),
            probe_concurrency: 1,
        })
        .await
        .unwrap_or_else(|error| unreachable!("synthetic procfs scans: {error}"));
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].socket_inode, 42);
        assert_eq!(candidates[0].pid, 123);

        assert!(
            fs::write(
                root.join("123/status"),
                synthetic_status(uid.wrapping_add(1))
            )
            .is_ok()
        );
        let (candidates, _, _) = scan(&DiscoveryConfig {
            proc_root: root.to_path_buf(),
            probe_concurrency: 1,
        })
        .await
        .unwrap_or_else(|error| unreachable!("synthetic procfs rescans: {error}"));
        assert!(candidates.is_empty());
    }

    #[tokio::test]
    async fn process_fd_is_correlated_in_the_same_network_namespace() {
        let (candidates, diagnostics) =
            scan_with_scripted_process_namespaces(vec![Ok(10), Ok(10)]).await;
        assert_eq!(candidates.len(), 1);
        assert!(diagnostics.is_empty());
    }

    #[tokio::test]
    async fn direct_network_enabled_tui_remains_discoverable() {
        let (_directory, config) = synthetic_procfs();
        let (candidates, diagnostics) =
            scan_config_with_scripted_process_namespaces(&config, vec![Ok(10), Ok(10)]).await;
        assert_eq!(candidates.len(), 1);
        assert!(diagnostics.is_empty());
    }

    #[tokio::test]
    async fn direct_orchestrator_descendant_is_excluded_by_executable_basename() {
        let (_directory, config) = synthetic_procfs();
        assert!(
            fs::write(
                config.proc_root.join("123/stat"),
                synthetic_stat(123, 200, 100)
            )
            .is_ok()
        );
        write_process(
            &config.proc_root,
            200,
            1,
            90,
            "opencode-orchestrator-mcp",
            true,
        );
        assert!(
            fs::write(
                config.proc_root.join("200/cmdline"),
                b"/tools/not-the-marker\0"
            )
            .is_ok()
        );

        let (candidates, diagnostics) =
            scan_config_with_scripted_process_namespaces(&config, vec![Ok(10), Ok(10)]).await;
        assert!(candidates.is_empty());
        assert!(diagnostics.iter().any(|diagnostic| {
            diagnostic
                .message
                .contains("ancestor launcher opencode-orchestrator-mcp")
        }));
    }

    #[tokio::test]
    async fn multi_level_orchestrator_descendant_is_excluded_by_argv0_fallback() {
        let (_directory, config) = synthetic_procfs();
        assert!(
            fs::write(
                config.proc_root.join("123/stat"),
                synthetic_stat(123, 200, 100)
            )
            .is_ok()
        );
        write_process(&config.proc_root, 200, 300, 90, "intermediate", true);
        write_process(
            &config.proc_root,
            300,
            1,
            80,
            "opencode-orchestrator-mcp",
            false,
        );

        let (candidates, _) =
            scan_config_with_scripted_process_namespaces(&config, vec![Ok(10), Ok(10)]).await;
        assert!(candidates.is_empty());
    }

    #[tokio::test]
    async fn manual_opencode_serve_remains_discoverable() {
        let (_directory, config) = synthetic_procfs();
        let (candidates, diagnostics) =
            scan_config_with_scripted_process_namespaces(&config, vec![Ok(10), Ok(10)]).await;
        assert_eq!(candidates.len(), 1);
        assert!(diagnostics.is_empty());
    }

    #[tokio::test]
    async fn excluded_launcher_matching_is_exact() {
        for (near_name, executable_available) in [
            ("opencode-orchestrator-mcp-helper", true),
            ("not-opencode-orchestrator-mcp", false),
        ] {
            let (_directory, config) = synthetic_procfs();
            assert!(
                fs::write(
                    config.proc_root.join("123/stat"),
                    synthetic_stat(123, 200, 100)
                )
                .is_ok()
            );
            write_process(
                &config.proc_root,
                200,
                1,
                90,
                near_name,
                executable_available,
            );

            let (candidates, diagnostics) =
                scan_config_with_scripted_process_namespaces(&config, vec![Ok(10), Ok(10)]).await;
            assert_eq!(candidates.len(), 1, "near name {near_name}");
            assert!(
                diagnostics
                    .iter()
                    .all(|diagnostic| !diagnostic.message.contains("excluded OpenCode listener")),
                "near name {near_name}"
            );
        }
    }

    #[tokio::test]
    async fn argv0_marker_is_ignored_when_executable_basename_is_available() {
        let (_directory, config) = synthetic_procfs();
        assert!(
            fs::write(
                config.proc_root.join("123/stat"),
                synthetic_stat(123, 200, 100)
            )
            .is_ok()
        );
        write_process(&config.proc_root, 200, 1, 90, "intermediate", true);
        assert!(
            fs::write(
                config.proc_root.join("200/cmdline"),
                b"/tools/opencode-orchestrator-mcp\0"
            )
            .is_ok()
        );

        let (candidates, diagnostics) =
            scan_config_with_scripted_process_namespaces(&config, vec![Ok(10), Ok(10)]).await;
        assert_eq!(candidates.len(), 1);
        assert!(
            diagnostics
                .iter()
                .all(|diagnostic| !diagnostic.message.contains("excluded OpenCode listener"))
        );
    }

    #[tokio::test]
    async fn missing_or_malformed_ancestry_is_retained() {
        for malformed_parent in [false, true] {
            let (_directory, config) = synthetic_procfs();
            assert!(
                fs::write(
                    config.proc_root.join("123/stat"),
                    synthetic_stat(123, 200, 100)
                )
                .is_ok()
            );
            if malformed_parent {
                assert!(fs::create_dir_all(config.proc_root.join("200")).is_ok());
                assert!(fs::write(config.proc_root.join("200/stat"), "malformed").is_ok());
            }

            let (candidates, diagnostics) =
                scan_config_with_scripted_process_namespaces(&config, vec![Ok(10), Ok(10)]).await;
            assert_eq!(candidates.len(), 1);
            assert!(diagnostics.is_empty());
        }
    }

    #[tokio::test]
    async fn inconsistent_process_identity_or_timing_is_retained() {
        for case in ["embedded-pid", "parent-start", "non-root-zero-parent"] {
            let (_directory, config) = synthetic_procfs();
            let candidate_pid = if case == "embedded-pid" { 999 } else { 123 };
            assert!(
                fs::write(
                    config.proc_root.join("123/stat"),
                    synthetic_stat(candidate_pid, 200, 100)
                )
                .is_ok()
            );
            let parent_pid = u32::from(case != "non-root-zero-parent");
            let parent_start = if case == "parent-start" { 101 } else { 90 };
            write_process(
                &config.proc_root,
                200,
                parent_pid,
                parent_start,
                "opencode-orchestrator-mcp",
                true,
            );

            let (candidates, diagnostics) =
                scan_config_with_scripted_process_namespaces(&config, vec![Ok(10), Ok(10)]).await;
            assert_eq!(candidates.len(), 1, "case {case}");
            assert!(
                diagnostics
                    .iter()
                    .all(|diagnostic| !diagnostic.message.contains("excluded OpenCode listener")),
                "case {case}"
            );
        }
    }

    #[tokio::test]
    async fn cyclic_ancestry_terminates_and_is_retained() {
        let (_directory, config) = synthetic_procfs();
        assert!(
            fs::write(
                config.proc_root.join("123/stat"),
                synthetic_stat(123, 200, 100)
            )
            .is_ok()
        );
        write_process(
            &config.proc_root,
            200,
            123,
            90,
            "opencode-orchestrator-mcp",
            true,
        );

        let (candidates, diagnostics) =
            scan_config_with_scripted_process_namespaces(&config, vec![Ok(10), Ok(10)]).await;
        assert_eq!(candidates.len(), 1);
        assert!(
            diagnostics
                .iter()
                .all(|diagnostic| !diagnostic.message.contains("excluded OpenCode listener"))
        );
    }

    #[test]
    fn disappearing_or_changed_ancestry_is_retained() {
        let child = ProcessStat {
            pid: 123,
            parent_pid: 200,
            start_time: 100,
        };
        let parent = ProcessStat {
            pid: 200,
            parent_pid: 1,
            start_time: 90,
        };
        let marker = LauncherIdentity::Executable(OsString::from("opencode-orchestrator-mcp"));

        for changed_child in [
            Err(io::ErrorKind::NotFound),
            Ok(ProcessStat {
                parent_pid: 201,
                ..child.clone()
            }),
            Ok(ProcessStat {
                start_time: 101,
                ..child.clone()
            }),
        ] {
            let source = ScriptedAncestrySource {
                stats: Mutex::new(HashMap::from([
                    (123, VecDeque::from([Ok(child.clone()), changed_child])),
                    (
                        200,
                        VecDeque::from([Ok(parent.clone()), Ok(parent.clone())]),
                    ),
                ])),
                identities: Mutex::new(HashMap::from([(
                    200,
                    VecDeque::from([Ok(marker.clone()), Ok(marker.clone())]),
                )])),
            };
            assert_eq!(excluded_ancestor_launcher_from(&source, &child), None);
        }
    }

    #[tokio::test]
    async fn process_fd_is_skipped_in_a_different_network_namespace() {
        let (candidates, diagnostics) = scan_with_scripted_process_namespaces(vec![Ok(11)]).await;
        assert!(candidates.is_empty());
        assert!(
            diagnostics
                .iter()
                .any(|diagnostic| diagnostic.message.contains("different network namespace"))
        );
    }

    #[tokio::test]
    async fn process_fd_is_skipped_when_namespace_link_is_inaccessible() {
        let (candidates, diagnostics) =
            scan_with_scripted_process_namespaces(vec![Err(io::ErrorKind::PermissionDenied)]).await;
        assert!(candidates.is_empty());
        assert!(diagnostics.iter().any(|diagnostic| {
            diagnostic
                .message
                .contains("could not inspect network namespace")
        }));
    }

    #[tokio::test]
    async fn process_fd_is_skipped_when_namespace_link_becomes_inaccessible() {
        let (candidates, diagnostics) =
            scan_with_scripted_process_namespaces(vec![Ok(10), Err(io::ErrorKind::NotFound)]).await;
        assert!(candidates.is_empty());
        assert!(diagnostics.iter().any(|diagnostic| {
            diagnostic
                .message
                .contains("network namespace became inaccessible")
        }));
    }

    #[tokio::test]
    async fn process_fd_is_skipped_when_namespace_changes_during_scan() {
        let (candidates, diagnostics) =
            scan_with_scripted_process_namespaces(vec![Ok(10), Ok(11)]).await;
        assert!(candidates.is_empty());
        assert!(
            diagnostics
                .iter()
                .any(|diagnostic| diagnostic.message.contains("network namespace changed"))
        );
    }

    #[test]
    fn parses_ipv6_loopback_and_normalizes_wildcards() {
        let loopback = parse_ipv6("00000000000000000000000001000000");
        assert_eq!(loopback, Some(Ipv6Addr::LOCALHOST));
        let v4 = normalize_connect_address(SocketAddr::from(([0, 0, 0, 0], 4096)));
        assert_eq!(v4, SocketAddr::from(([127, 0, 0, 1], 4096)));
        let v6 =
            normalize_connect_address(SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 4096));
        assert_eq!(v6, SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 4096));
    }

    #[test]
    fn distinct_socket_identities_cannot_share_a_normalized_endpoint() {
        let endpoint = ServerEndpoint::new(SocketAddr::from(([127, 0, 0, 1], 4096)))
            .unwrap_or_else(|error| unreachable!("loopback endpoint: {error}"));
        let instance = |socket_inode, listener| ServerInstance {
            key: InstanceKey {
                network_namespace_inode: 1,
                socket_inode,
                listener,
                pid: 2,
                source: InstanceSource::LinuxProcfs,
            },
            endpoint,
            protocol: OpenCodeProtocol::V1,
            executable: None,
            version: "1.17.4".to_owned(),
        };
        let mut diagnostics = Vec::new();
        let instances = retain_unique_endpoints(
            vec![
                instance(10, SocketAddr::from(([0, 0, 0, 0], 4096))),
                instance(11, endpoint.address()),
            ],
            &mut diagnostics,
        );
        assert!(instances.is_empty());
        assert!(
            diagnostics
                .iter()
                .any(|diagnostic| { diagnostic.message.contains("2 distinct socket identities") })
        );
    }

    #[test]
    fn incomplete_rows_are_ignored() {
        let parsed = parse_listeners("header\n0: not-an-address", false);
        assert!(parsed.is_ok_and(|listeners| listeners.is_empty()));
    }

    #[test]
    fn discovery_boundary_requires_current_uid_and_local_binding() {
        assert!(owned_by_current_uid(1000, 1000));
        assert!(!owned_by_current_uid(1001, 1000));
        assert!(eligible_listener(SocketAddr::from(([127, 0, 0, 1], 4096))));
        assert!(eligible_listener(SocketAddr::from(([0, 0, 0, 0], 4096))));
        assert!(!eligible_listener(SocketAddr::from(([192, 0, 2, 1], 4096))));
    }

    #[test]
    fn likely_process_filter_requires_opencode_identity() {
        let directory = tempfile::tempdir();
        assert!(directory.is_ok());
        let directory = directory.unwrap_or_else(|error| unreachable!("temp directory: {error}"));
        assert!(fs::write(directory.path().join("comm"), "opencode\n").is_ok());
        assert!(fs::write(directory.path().join("cmdline"), b"opencode\0serve\0").is_ok());
        assert!(likely_opencode(directory.path()));

        assert!(fs::write(directory.path().join("comm"), "unrelated\n").is_ok());
        assert!(fs::write(directory.path().join("cmdline"), b"unrelated\0").is_ok());
        assert!(!likely_opencode(directory.path()));
    }

    #[tokio::test]
    async fn procfs_standalone_uses_private_auth_and_v2_health_pid_identity() {
        let directory = tempfile::tempdir()
            .unwrap_or_else(|error| unreachable!("temporary directory: {error}"));
        let root = directory.path();
        let self_root = root.join("self");
        let process = root.join("123");
        assert!(fs::create_dir_all(self_root.join("net")).is_ok());
        assert!(fs::create_dir_all(self_root.join("ns")).is_ok());
        assert!(fs::create_dir_all(process.join("fd")).is_ok());
        assert!(fs::create_dir_all(process.join("ns")).is_ok());
        let namespace = root.join("namespace");
        assert!(fs::write(&namespace, "namespace").is_ok());
        assert!(fs::hard_link(&namespace, self_root.join("ns/net")).is_ok());
        assert!(fs::hard_link(&namespace, process.join("ns/net")).is_ok());
        let uid = fs::metadata(root)
            .unwrap_or_else(|error| unreachable!("metadata: {error}"))
            .uid();
        assert!(fs::write(self_root.join("status"), synthetic_status(uid)).is_ok());
        assert!(fs::write(process.join("status"), synthetic_status(uid)).is_ok());
        assert!(fs::write(process.join("stat"), synthetic_stat(123, 1, 100)).is_ok());
        assert!(fs::write(process.join("comm"), "opencode2\n").is_ok());
        assert!(
            fs::write(
                process.join("cmdline"),
                b"/tools/opencode2\0serve\0--stdio\0"
            )
            .is_ok()
        );
        assert!(
            fs::write(
                process.join("environ"),
                b"UNRELATED_SECRET=do-not-log\0OPENCODE_PASSWORD=private-password\0"
            )
            .is_ok()
        );
        assert!(std::os::unix::fs::symlink("/tools/opencode2", process.join("exe")).is_ok());
        assert!(std::os::unix::fs::symlink("socket:[42]", process.join("fd/14")).is_ok());

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap_or_else(|error| unreachable!("bind succeeded: {error}"));
        let address = listener
            .local_addr()
            .unwrap_or_else(|error| unreachable!("address exists: {error}"));
        assert!(
            fs::write(
                self_root.join("net/tcp"),
                format!(
                    "header\n0: 0100007F:{:04X} 00000000:0000 0A 0:0 00:0 0 {uid} 0 42\n",
                    address.port()
                )
            )
            .is_ok()
        );
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener
                .accept()
                .await
                .unwrap_or_else(|error| unreachable!("accept succeeded: {error}"));
            let mut request = vec![0_u8; 4096];
            let count = socket
                .read(&mut request)
                .await
                .unwrap_or_else(|error| unreachable!("request read: {error}"));
            let body = r#"{"healthy":true,"version":"2.0.0","pid":123}"#;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            socket
                .write_all(response.as_bytes())
                .await
                .unwrap_or_else(|error| unreachable!("response write: {error}"));
            String::from_utf8_lossy(&request[..count]).into_owned()
        });

        let report = LinuxProcfsDiscovery::new(DiscoveryConfig {
            proc_root: root.to_path_buf(),
            probe_concurrency: 1,
        })
        .discover(&ClientConfig::default())
        .await
        .unwrap_or_else(|error| unreachable!("standalone discovery succeeds: {error}"));
        assert_eq!(report.instances.len(), 1);
        assert_eq!(report.instances[0].protocol, OpenCodeProtocol::V2);
        assert_eq!(report.instances[0].key.pid, 123);
        assert!(report.connections[&report.instances[0].key].auth.is_some());
        assert!(report.diagnostics.is_empty());
        let request = server
            .await
            .unwrap_or_else(|error| unreachable!("server joins: {error}"));
        assert!(request.starts_with("GET /api/health HTTP/1.1"));
        assert!(
            request
                .to_ascii_lowercase()
                .contains("authorization: basic ")
        );
        assert!(!request.contains("private-password"));
        assert!(!request.contains("do-not-log"));
    }

    #[test]
    fn stdio_v2_classification_requires_a_nonempty_private_credential() {
        let directory = tempfile::tempdir()
            .unwrap_or_else(|error| unreachable!("temporary directory: {error}"));
        assert!(
            fs::write(
                directory.path().join("cmdline"),
                b"opencode2\0serve\0--stdio\0"
            )
            .is_ok()
        );
        assert!(fs::write(directory.path().join("environ"), b"OTHER=value\0").is_ok());
        assert!(is_stdio_v2_server(directory.path()));
        assert_eq!(
            standalone_auth(directory.path()).err(),
            Some("standalone credential is unavailable")
        );
    }

    #[tokio::test]
    async fn managed_registration_uses_channel_paths_auth_and_health_identity() {
        let (_directory, proc_config) = synthetic_procfs();
        let state_dir = proc_config.proc_root.join("state");
        assert!(fs::create_dir_all(&state_dir).is_ok());
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap_or_else(|error| unreachable!("bind succeeded: {error}"));
        let address = listener
            .local_addr()
            .unwrap_or_else(|error| unreachable!("address exists: {error}"));
        let registration_path = state_dir.join("service-beta.json");
        assert!(
            fs::write(
                &registration_path,
                format!(
                    r#"{{"id":"service-id","version":"2.0.0","url":"http://{address}","pid":4242,"password":"private-password"}}"#
                )
            )
            .is_ok()
        );
        assert!(fs::set_permissions(&registration_path, fs::Permissions::from_mode(0o600)).is_ok());
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener
                .accept()
                .await
                .unwrap_or_else(|error| unreachable!("accept succeeded: {error}"));
            let mut request = vec![0_u8; 4096];
            let count = socket
                .read(&mut request)
                .await
                .unwrap_or_else(|error| unreachable!("read succeeded: {error}"));
            let body = r#"{"healthy":true,"version":"2.0.0","pid":4242}"#;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            socket
                .write_all(response.as_bytes())
                .await
                .unwrap_or_else(|error| unreachable!("write succeeded: {error}"));
            String::from_utf8_lossy(&request[..count]).into_owned()
        });
        let discovery = ManagedServiceDiscovery::new(
            ManagedDiscoveryConfig {
                state_dir: Some(state_dir),
            },
            proc_config.proc_root,
        );
        let report = discovery
            .discover(&ClientConfig::default())
            .await
            .unwrap_or_else(|error| unreachable!("managed discovery succeeds: {error}"));
        assert_eq!(report.instances.len(), 1);
        assert_eq!(report.instances[0].key.pid, 4242);
        assert!(matches!(
            &report.instances[0].key.source,
            InstanceSource::ManagedService { registration, id }
                if registration == &registration_path && id.as_deref() == Some("service-id")
        ));
        assert!(report.connections[&report.instances[0].key].auth.is_some());
        let request = server
            .await
            .unwrap_or_else(|error| unreachable!("server joins: {error}"));
        assert!(request.starts_with("GET /api/health HTTP/1.1"));
        assert!(
            request
                .to_ascii_lowercase()
                .contains("authorization: basic ")
        );
        assert!(!request.contains("private-password"));
    }

    #[tokio::test]
    async fn managed_registration_rejects_unsafe_files_and_nonlocal_urls() {
        let (_directory, proc_config) = synthetic_procfs();
        let state_dir = proc_config.proc_root.join("state");
        assert!(fs::create_dir_all(&state_dir).is_ok());
        let unsafe_path = state_dir.join("service.json");
        assert!(fs::write(&unsafe_path, r#"{"url":"http://127.0.0.1:1","pid":1}"#).is_ok());
        assert!(fs::set_permissions(&unsafe_path, fs::Permissions::from_mode(0o644)).is_ok());
        let ignored = state_dir.join("service.json.tmp");
        assert!(fs::write(&ignored, "{}").is_ok());
        let discovery = ManagedServiceDiscovery::new(
            ManagedDiscoveryConfig {
                state_dir: Some(state_dir),
            },
            proc_config.proc_root,
        );
        let report = discovery
            .discover(&ClientConfig::default())
            .await
            .unwrap_or_else(|error| unreachable!("unsafe candidate is diagnostic: {error}"));
        assert!(report.instances.is_empty());
        assert_eq!(report.diagnostics.len(), 1);
        assert!(report.diagnostics[0].message.contains("unsafe ownership"));
        assert!(registration_endpoint("http://192.0.2.1:8080").is_err());
        assert!(registration_endpoint("https://127.0.0.1:8080").is_err());
    }

    #[test]
    fn managed_registration_names_match_opencode_channel_sanitization() {
        for name in [
            "service.json",
            "service-local.json",
            "service-preview-a.json",
            "service-a.b_c-1.json",
        ] {
            assert!(is_registration_name(name), "{name}");
        }
        for name in [
            "service-.json",
            "service-preview a.json",
            "service-preview+.json",
            "service-preview.json.tmp",
            "server.json",
        ] {
            assert!(!is_registration_name(name), "{name}");
        }
    }

    #[test]
    fn managed_registration_gate_tracks_permission_only_changes() {
        let (_directory, proc_config) = synthetic_procfs();
        let state_dir = proc_config.proc_root.join("state");
        assert!(fs::create_dir_all(&state_dir).is_ok());
        let registration_path = state_dir.join("service.json");
        assert!(
            fs::write(
                &registration_path,
                r#"{"url":"http://127.0.0.1:1","pid":1}"#
            )
            .is_ok()
        );
        assert!(fs::set_permissions(&registration_path, fs::Permissions::from_mode(0o600)).is_ok());
        let discovery = ManagedServiceDiscovery::new(
            ManagedDiscoveryConfig {
                state_dir: Some(state_dir),
            },
            proc_config.proc_root,
        );
        let before = discovery
            .registration_fingerprint()
            .unwrap_or_else(|error| unreachable!("initial fingerprint succeeds: {error}"));
        assert!(fs::set_permissions(&registration_path, fs::Permissions::from_mode(0o640)).is_ok());
        let after = discovery
            .registration_fingerprint()
            .unwrap_or_else(|error| unreachable!("updated fingerprint succeeds: {error}"));
        assert_ne!(before, after);
    }
}
