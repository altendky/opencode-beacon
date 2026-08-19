use std::collections::{HashMap, HashSet, VecDeque};
use std::fs;
use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, Instant};

use opencode_beacon::model::{BeaconEvent, InstanceKey, InstanceSource};

const HISTORY_WINDOW: Duration = Duration::from_secs(2 * 60 * 60);
const SLOPE_WINDOW: Duration = Duration::from_secs(30 * 60);
const MAX_HISTORY_SAMPLES: usize = 721;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct CgroupKey {
    pub device: u64,
    pub inode: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MemoryValues {
    pub current: u64,
    pub peak: Option<u64>,
    pub swap: u64,
    pub anon: u64,
    pub file: u64,
    pub kernel: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MemoryAvailability {
    Fresh,
    Stale,
    Unavailable,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MemoryView {
    pub availability: MemoryAvailability,
    pub values: Option<MemoryValues>,
    pub observed_peak: Option<u64>,
    pub slope_bytes_per_minute: Option<i64>,
    pub scope: Option<CgroupKey>,
    pub shared: bool,
}

impl MemoryView {
    const fn unavailable(scope: Option<CgroupKey>, shared: bool) -> Self {
        Self {
            availability: MemoryAvailability::Unavailable,
            values: None,
            observed_peak: None,
            slope_bytes_per_minute: None,
            scope,
            shared,
        }
    }
}

#[derive(Debug)]
struct InstanceTarget {
    pid: u32,
    start_time: Option<u64>,
    scope: Option<CgroupKey>,
}

#[derive(Debug)]
struct ResolvedScope {
    key: CgroupKey,
    path: PathBuf,
}

#[derive(Default, Debug)]
struct ScopeHistory {
    path: PathBuf,
    values: Option<MemoryValues>,
    observed_peak: Option<u64>,
    samples: VecDeque<(Instant, u64)>,
    sampled_at: Option<Instant>,
}

pub struct CgroupMemorySampler {
    proc_root: PathBuf,
    cgroup_root: PathBuf,
    instances: HashMap<InstanceKey, InstanceTarget>,
    scopes: HashMap<CgroupKey, ScopeHistory>,
}

impl Default for CgroupMemorySampler {
    fn default() -> Self {
        Self::new(PathBuf::from("/proc"), PathBuf::from("/sys/fs/cgroup"))
    }
}

impl CgroupMemorySampler {
    fn new(proc_root: PathBuf, cgroup_root: PathBuf) -> Self {
        Self {
            proc_root,
            cgroup_root,
            instances: HashMap::new(),
            scopes: HashMap::new(),
        }
    }

    pub fn observe(&mut self, event: &BeaconEvent) {
        match event {
            BeaconEvent::ServerFound(instance)
                if matches!(instance.key.source, InstanceSource::LinuxProcfs) =>
            {
                self.register(instance.key.clone());
            }
            BeaconEvent::ServerRemoved(instance) => self.remove(&instance.key),
            _ => {}
        }
    }

    fn register(&mut self, instance: InstanceKey) {
        let pid = instance.pid;
        let start_time = read_start_time(&self.proc_root, pid).ok();
        let scope = start_time.and_then(|expected| {
            resolve_scope(&self.proc_root, &self.cgroup_root, pid, expected)
                .ok()
                .map(|scope| {
                    self.scopes
                        .entry(scope.key)
                        .or_insert_with(|| ScopeHistory {
                            path: scope.path,
                            ..ScopeHistory::default()
                        });
                    scope.key
                })
        });
        self.instances.insert(
            instance,
            InstanceTarget {
                pid,
                start_time,
                scope,
            },
        );
        self.purge_unreferenced_scopes();
    }

    fn remove(&mut self, instance: &InstanceKey) {
        self.instances.remove(instance);
        self.purge_unreferenced_scopes();
    }

    fn purge_unreferenced_scopes(&mut self) {
        let retained = self
            .instances
            .values()
            .filter_map(|target| target.scope)
            .collect::<HashSet<_>>();
        self.scopes.retain(|key, _| retained.contains(key));
    }

    pub fn sample(&mut self, now: Instant) -> HashMap<InstanceKey, MemoryView> {
        let mut resolved = HashMap::new();
        let mut validators = HashMap::new();
        for (instance, target) in &mut self.instances {
            let start_time = if let Some(start_time) = target.start_time {
                start_time
            } else {
                let Ok(start_time) = read_start_time(&self.proc_root, target.pid) else {
                    continue;
                };
                target.start_time = Some(start_time);
                start_time
            };
            if let Ok(scope) =
                resolve_scope(&self.proc_root, &self.cgroup_root, target.pid, start_time)
            {
                target.scope = Some(scope.key);
                self.scopes
                    .entry(scope.key)
                    .and_modify(|history| history.path.clone_from(&scope.path))
                    .or_insert_with(|| ScopeHistory {
                        path: scope.path.clone(),
                        ..ScopeHistory::default()
                    });
                resolved.insert(instance.clone(), scope.key);
                validators
                    .entry(scope.key)
                    .or_insert_with(Vec::new)
                    .push((target.pid, start_time));
            }
        }
        self.purge_unreferenced_scopes();

        let sampled_scopes = resolved.values().copied().collect::<HashSet<_>>();
        for key in &sampled_scopes {
            let Some(history) = self.scopes.get_mut(key) else {
                continue;
            };
            prune_history(&mut history.samples, now);
            let valid = validators.get(key).is_some_and(|targets| {
                targets.iter().any(|(pid, start_time)| {
                    resolve_scope(&self.proc_root, &self.cgroup_root, *pid, *start_time)
                        .is_ok_and(|scope| scope.key == *key && scope.path == history.path)
                })
            });
            if valid && let Ok(values) = read_memory_values(&history.path) {
                history.values = Some(values);
                history.observed_peak = Some(
                    history
                        .observed_peak
                        .unwrap_or_default()
                        .max(values.current),
                );
                history.samples.push_back((now, values.current));
                while history.samples.len() > MAX_HISTORY_SAMPLES {
                    history.samples.pop_front();
                }
                history.sampled_at = Some(now);
            }
        }

        let counts = self
            .instances
            .values()
            .filter_map(|target| target.scope)
            .fold(HashMap::<CgroupKey, usize>::new(), |mut counts, scope| {
                *counts.entry(scope).or_default() += 1;
                counts
            });
        self.instances
            .iter()
            .map(|(instance, target)| {
                let identity_valid = resolved.contains_key(instance);
                let shared = target
                    .scope
                    .and_then(|scope| counts.get(&scope))
                    .is_some_and(|count| *count > 1);
                let view = target.scope.map_or_else(
                    || MemoryView::unavailable(None, false),
                    |scope| {
                        let Some(history) = self.scopes.get(&scope) else {
                            return MemoryView::unavailable(Some(scope), shared);
                        };
                        let Some(values) = history.values else {
                            return MemoryView::unavailable(Some(scope), shared);
                        };
                        MemoryView {
                            availability: if identity_valid && history.sampled_at == Some(now) {
                                MemoryAvailability::Fresh
                            } else {
                                MemoryAvailability::Stale
                            },
                            values: Some(values),
                            observed_peak: history.observed_peak,
                            slope_bytes_per_minute: slope(&history.samples),
                            scope: Some(scope),
                            shared,
                        }
                    },
                );
                (instance.clone(), view)
            })
            .collect()
    }
}

fn read_start_time(proc_root: &Path, pid: u32) -> io::Result<u64> {
    parse_start_time(&fs::read_to_string(
        proc_root.join(pid.to_string()).join("stat"),
    )?)
}

fn parse_start_time(contents: &str) -> io::Result<u64> {
    let close = contents
        .rfind(')')
        .ok_or_else(|| invalid("process stat has no command end"))?;
    let fields = contents[close + 1..].split_whitespace().collect::<Vec<_>>();
    if fields.len() < 20 {
        return Err(invalid("process stat has too few fields"));
    }
    fields[19].parse().map_err(invalid_data)
}

fn resolve_scope(
    proc_root: &Path,
    cgroup_root: &Path,
    pid: u32,
    expected_start_time: u64,
) -> io::Result<ResolvedScope> {
    if read_start_time(proc_root, pid)? != expected_start_time {
        return Err(invalid("process starttime changed"));
    }
    let cgroup = fs::read_to_string(proc_root.join(pid.to_string()).join("cgroup"))?;
    let relative = parse_unified_cgroup(&cgroup)?;
    let canonical_root = fs::canonicalize(cgroup_root)?;
    let canonical_path = fs::canonicalize(canonical_root.join(relative))?;
    if !canonical_path.starts_with(&canonical_root) {
        return Err(invalid("cgroup path escapes the unified hierarchy"));
    }
    if read_start_time(proc_root, pid)? != expected_start_time {
        return Err(invalid("process starttime changed during cgroup lookup"));
    }
    let metadata = fs::metadata(&canonical_path)?;
    if read_start_time(proc_root, pid)? != expected_start_time {
        return Err(invalid(
            "process starttime changed during cgroup metadata lookup",
        ));
    }
    Ok(ResolvedScope {
        key: CgroupKey {
            device: metadata.dev(),
            inode: metadata.ino(),
        },
        path: canonical_path,
    })
}

fn parse_unified_cgroup(contents: &str) -> io::Result<PathBuf> {
    let mut unified = None;
    for line in contents.lines() {
        let mut fields = line.splitn(3, ':');
        if fields.next() == Some("0") && fields.next() == Some("") {
            if unified.is_some() {
                return Err(invalid("multiple unified cgroup entries"));
            }
            unified = fields.next();
        }
    }
    let path = unified.ok_or_else(|| invalid("no unified cgroup entry"))?;
    if path
        .split('/')
        .any(|component| matches!(component, "." | ".."))
    {
        return Err(invalid("unsafe unified cgroup path component"));
    }
    let mut relative = PathBuf::new();
    let mut components = Path::new(path).components();
    if components.next() != Some(Component::RootDir) {
        return Err(invalid("unified cgroup path is not absolute"));
    }
    for component in components {
        match component {
            Component::Normal(component) => relative.push(component),
            _ => return Err(invalid("unsafe unified cgroup path component")),
        }
    }
    Ok(relative)
}

fn read_memory_values(path: &Path) -> io::Result<MemoryValues> {
    let current = read_u64(path.join("memory.current"))?;
    let peak = match read_u64(path.join("memory.peak")) {
        Ok(peak) => Some(peak),
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        Err(error) => return Err(error),
    };
    let swap = read_u64(path.join("memory.swap.current"))?;
    let (anon, file, kernel) = parse_memory_stat(&fs::read_to_string(path.join("memory.stat"))?)?;
    Ok(MemoryValues {
        current,
        peak,
        swap,
        anon,
        file,
        kernel,
    })
}

fn read_u64(path: PathBuf) -> io::Result<u64> {
    fs::read_to_string(path)?
        .trim()
        .parse()
        .map_err(invalid_data)
}

fn parse_memory_stat(contents: &str) -> io::Result<(u64, u64, u64)> {
    let mut wanted = HashMap::new();
    for line in contents.lines() {
        let mut fields = line.split_whitespace();
        let Some(name @ ("anon" | "file" | "kernel")) = fields.next() else {
            continue;
        };
        let value = fields
            .next()
            .ok_or_else(|| invalid("memory.stat field has no value"))?
            .parse::<u64>()
            .map_err(invalid_data)?;
        if fields.next().is_some() || wanted.insert(name, value).is_some() {
            return Err(invalid("malformed or duplicate memory.stat field"));
        }
    }
    Ok((
        *wanted
            .get("anon")
            .ok_or_else(|| invalid("memory.stat has no anon"))?,
        *wanted
            .get("file")
            .ok_or_else(|| invalid("memory.stat has no file"))?,
        *wanted
            .get("kernel")
            .ok_or_else(|| invalid("memory.stat has no kernel"))?,
    ))
}

fn slope(samples: &VecDeque<(Instant, u64)>) -> Option<i64> {
    let (current_at, current) = samples.back()?;
    let cutoff = current_at.checked_sub(SLOPE_WINDOW)?;
    let (then, old) = samples
        .iter()
        .rev()
        .find(|(sampled, _)| *sampled <= cutoff)?;
    let seconds = current_at.saturating_duration_since(*then).as_secs();
    if seconds < SLOPE_WINDOW.as_secs() {
        return None;
    }
    let delta = i128::from(*current) - i128::from(*old);
    let per_minute = delta.saturating_mul(60) / i128::from(seconds);
    i64::try_from(per_minute.clamp(i128::from(i64::MIN), i128::from(i64::MAX))).ok()
}

fn prune_history(samples: &mut VecDeque<(Instant, u64)>, now: Instant) {
    while samples
        .front()
        .is_some_and(|(sampled, _)| now.saturating_duration_since(*sampled) > HISTORY_WINDOW)
    {
        samples.pop_front();
    }
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn invalid_data(error: impl std::error::Error + Send + Sync + 'static) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error)
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use opencode_beacon::model::{
        InstanceSource, OpenCodeProtocol, ServerEndpoint, ServerInstance,
    };

    use super::*;

    fn stat(pid: u32, start_time: u64) -> String {
        format!(
            "{pid} (synthetic process) S 1 {} {start_time}\n",
            vec!["0"; 17].join(" ")
        )
    }

    fn instance(pid: u32, socket_inode: u64, port: u16) -> ServerInstance {
        let address = SocketAddr::from(([127, 0, 0, 1], port));
        ServerInstance {
            key: InstanceKey {
                network_namespace_inode: 1,
                socket_inode,
                listener: address,
                pid,
                source: InstanceSource::LinuxProcfs,
            },
            endpoint: ServerEndpoint::new(address)
                .unwrap_or_else(|error| unreachable!("test endpoint: {error}")),
            protocol: OpenCodeProtocol::V1,
            executable: None,
            version: "test".to_owned(),
        }
    }

    fn write_process(proc_root: &Path, pid: u32, start_time: u64, cgroup: &str) {
        let process = proc_root.join(pid.to_string());
        assert!(fs::create_dir_all(&process).is_ok());
        assert!(fs::write(process.join("stat"), stat(pid, start_time)).is_ok());
        assert!(fs::write(process.join("cgroup"), format!("0::{cgroup}\n")).is_ok());
    }

    fn write_memory(scope: &Path, current: u64) {
        assert!(fs::write(scope.join("memory.current"), current.to_string()).is_ok());
        assert!(fs::write(scope.join("memory.peak"), "8192\n").is_ok());
        assert!(fs::write(scope.join("memory.swap.current"), "512\n").is_ok());
        assert!(
            fs::write(
                scope.join("memory.stat"),
                "anon 1024\nfile 2048\nkernel 256\n"
            )
            .is_ok()
        );
    }

    #[test]
    fn parsers_accept_synthetic_v2_data_and_reject_escapes() {
        assert_eq!(
            parse_unified_cgroup("0::/user.slice/tui\n").ok(),
            Some(PathBuf::from("user.slice/tui"))
        );
        assert!(parse_unified_cgroup("0::/../../outside\n").is_err());
        assert!(parse_unified_cgroup("0::/scope/./child\n").is_err());
        assert!(parse_unified_cgroup("2:memory:/legacy\n").is_err());
        assert_eq!(
            parse_memory_stat("anon 10\nfile 20\nkernel 30\nother 99\n").ok(),
            Some((10, 20, 30))
        );
        assert!(parse_memory_stat("anon 10\nfile nope\nkernel 30\n").is_err());
        let stat = format!(
            "42 (name with ) parenthesis) S 1 {} 1234\n",
            vec!["0"; 17].join(" ")
        );
        assert_eq!(parse_start_time(&stat).ok(), Some(1234));
    }

    #[test]
    fn slope_requires_thirty_minutes() {
        let start = Instant::now();
        let mut samples = VecDeque::from([(start, 100), (start + SLOPE_WINDOW, 1_900)]);
        assert_eq!(slope(&samples), Some(60));
        samples[1].0 = (start + SLOPE_WINDOW)
            .checked_sub(Duration::from_secs(1))
            .unwrap_or_else(|| unreachable!("test instant supports subtraction"));
        assert_eq!(slope(&samples), None);
        samples.pop_front();
        assert_eq!(slope(&samples), None);
    }

    #[test]
    fn sampler_bounds_history_by_age_and_sample_count() {
        let directory = tempfile::tempdir()
            .unwrap_or_else(|error| unreachable!("temporary directory: {error}"));
        let proc_root = directory.path().join("proc");
        let cgroup_root = directory.path().join("cgroup");
        let scope = cgroup_root.join("direct.scope");
        assert!(fs::create_dir_all(&scope).is_ok());
        write_process(&proc_root, 40, 100, "/direct.scope");
        write_memory(&scope, 4096);
        let server = instance(40, 140, 4040);
        let mut sampler = CgroupMemorySampler::new(proc_root, cgroup_root);
        sampler.observe(&BeaconEvent::ServerFound(server.clone()));

        let start = Instant::now();
        for offset in 0..=MAX_HISTORY_SAMPLES {
            let _ = sampler.sample(start + Duration::from_secs(offset as u64));
        }
        let history = sampler
            .scopes
            .get(
                &sampler.instances[&server.key]
                    .scope
                    .unwrap_or_else(|| unreachable!()),
            )
            .unwrap_or_else(|| unreachable!());
        assert_eq!(history.samples.len(), MAX_HISTORY_SAMPLES);

        let _ = sampler
            .sample(start + HISTORY_WINDOW + Duration::from_secs(MAX_HISTORY_SAMPLES as u64 + 1));
        let history = sampler
            .scopes
            .get(
                &sampler.instances[&server.key]
                    .scope
                    .unwrap_or_else(|| unreachable!()),
            )
            .unwrap_or_else(|| unreachable!());
        assert_eq!(history.samples.len(), 1);
    }

    #[test]
    fn managed_service_pid_is_not_attributed_as_tui_memory() {
        let directory = tempfile::tempdir()
            .unwrap_or_else(|error| unreachable!("temporary directory: {error}"));
        let mut sampler = CgroupMemorySampler::new(
            directory.path().join("proc"),
            directory.path().join("cgroup"),
        );
        let mut service = instance(40, 140, 4040);
        service.key.source = InstanceSource::ManagedService {
            registration: PathBuf::from("/state/service.json"),
            id: Some("service".to_owned()),
        };
        sampler.observe(&BeaconEvent::ServerFound(service));
        assert!(sampler.instances.is_empty());
    }

    #[test]
    fn procfs_v2_standalone_is_attributed_as_direct_memory() {
        let directory = tempfile::tempdir()
            .unwrap_or_else(|error| unreachable!("temporary directory: {error}"));
        let proc_root = directory.path().join("proc");
        let cgroup_root = directory.path().join("cgroup");
        let scope = cgroup_root.join("standalone.scope");
        assert!(fs::create_dir_all(&scope).is_ok());
        write_process(&proc_root, 41, 101, "/standalone.scope");
        write_memory(&scope, 4096);
        let mut standalone = instance(41, 141, 4041);
        standalone.protocol = OpenCodeProtocol::V2;
        let key = standalone.key.clone();
        let mut sampler = CgroupMemorySampler::new(proc_root, cgroup_root);
        sampler.observe(&BeaconEvent::ServerFound(standalone));
        assert!(sampler.instances.contains_key(&key));
    }

    #[test]
    fn optional_peak_allows_absence_but_rejects_malformed_data() {
        let directory = tempfile::tempdir()
            .unwrap_or_else(|error| unreachable!("temporary directory: {error}"));
        write_memory(directory.path(), 4096);
        assert!(fs::remove_file(directory.path().join("memory.peak")).is_ok());
        assert_eq!(
            read_memory_values(directory.path())
                .ok()
                .and_then(|values| values.peak),
            None
        );
        assert!(fs::write(directory.path().join("memory.peak"), "invalid\n").is_ok());
        assert!(read_memory_values(directory.path()).is_err());
    }

    #[test]
    fn sampler_validates_identity_deduplicates_scope_and_purges_lifecycle() {
        let directory = tempfile::tempdir()
            .unwrap_or_else(|error| unreachable!("temporary directory: {error}"));
        let proc_root = directory.path().join("proc");
        let cgroup_root = directory.path().join("cgroup");
        let scope = cgroup_root.join("direct.scope");
        assert!(fs::create_dir_all(&scope).is_ok());
        write_process(&proc_root, 41, 100, "/direct.scope");
        write_process(&proc_root, 42, 200, "/direct.scope");
        write_memory(&scope, 4096);
        let first = instance(41, 141, 4041);
        let second = instance(42, 142, 4042);
        let mut sampler = CgroupMemorySampler::new(proc_root.clone(), cgroup_root);
        sampler.observe(&BeaconEvent::ServerFound(first.clone()));
        sampler.observe(&BeaconEvent::ServerFound(second.clone()));

        let now = Instant::now();
        let views = sampler.sample(now);
        assert_eq!(views.len(), 2);
        for view in views.values() {
            assert_eq!(view.availability, MemoryAvailability::Fresh);
            assert!(view.shared);
            assert_eq!(view.values.map(|values| values.current), Some(4096));
            assert_eq!(view.observed_peak, Some(4096));
        }
        assert_eq!(sampler.scopes.len(), 1);

        sampler.observe(&BeaconEvent::Disconnected {
            endpoint: first.endpoint,
            reason: "synthetic".to_owned(),
        });
        assert_eq!(sampler.sample(now + Duration::from_secs(10)).len(), 2);

        assert!(fs::write(proc_root.join("41/stat"), stat(41, 101)).is_ok());
        let views = sampler.sample(now + Duration::from_secs(20));
        assert_eq!(
            views.get(&first.key).map(|view| view.availability),
            Some(MemoryAvailability::Stale)
        );

        sampler.observe(&BeaconEvent::ServerRemoved(first.clone()));
        let views = sampler.sample(now + Duration::from_secs(30));
        assert!(!views.contains_key(&first.key));
        assert_eq!(views.get(&second.key).map(|view| view.shared), Some(false));
        sampler.observe(&BeaconEvent::ServerRemoved(second));
        assert!(sampler.scopes.is_empty());
    }

    #[test]
    fn sampler_retries_starttime_after_transient_registration_failure() {
        let directory = tempfile::tempdir()
            .unwrap_or_else(|error| unreachable!("temporary directory: {error}"));
        let proc_root = directory.path().join("proc");
        let cgroup_root = directory.path().join("cgroup");
        let scope = cgroup_root.join("direct.scope");
        assert!(fs::create_dir_all(&scope).is_ok());
        write_memory(&scope, 4096);
        let server = instance(43, 143, 4043);
        let mut sampler = CgroupMemorySampler::new(proc_root.clone(), cgroup_root);
        sampler.observe(&BeaconEvent::ServerFound(server.clone()));
        assert_eq!(
            sampler
                .sample(Instant::now())
                .get(&server.key)
                .map(|view| view.availability),
            Some(MemoryAvailability::Unavailable)
        );

        write_process(&proc_root, 43, 300, "/direct.scope");
        assert_eq!(
            sampler
                .sample(Instant::now())
                .get(&server.key)
                .map(|view| view.availability),
            Some(MemoryAvailability::Fresh)
        );
    }

    #[test]
    fn scope_resolution_rejects_symlink_escape() {
        let directory = tempfile::tempdir()
            .unwrap_or_else(|error| unreachable!("temporary directory: {error}"));
        let proc_root = directory.path().join("proc");
        let cgroup_root = directory.path().join("cgroup");
        let outside = directory.path().join("outside");
        assert!(fs::create_dir_all(&cgroup_root).is_ok());
        assert!(fs::create_dir_all(&outside).is_ok());
        assert!(std::os::unix::fs::symlink(&outside, cgroup_root.join("escape")).is_ok());
        write_process(&proc_root, 50, 500, "/escape");
        assert!(resolve_scope(&proc_root, &cgroup_root, 50, 500).is_err());
    }
}
