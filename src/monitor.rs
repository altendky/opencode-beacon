use std::collections::{HashMap, HashSet};
use std::future::{Future, pending};
use std::pin::Pin;
use std::time::Duration;

use futures_util::{FutureExt, StreamExt};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tokio::time::{Instant, Sleep};
use tokio_util::sync::CancellationToken;

use crate::client::{
    ClientConfig, OpenCodeClient, OpenCodeV2Client, SourceEvent, SourceEventStream,
};
use crate::discovery::{
    ConnectionSettings, DiscoveryBackend, DiscoveryConfig, DiscoveryReport, LinuxProcfsDiscovery,
    ListenerTableFingerprint, ManagedDiscoveryConfig, ManagedServiceDiscovery,
};
use crate::model::{
    BeaconEvent, InstanceKey, InstanceSource, OpenCodeProtocol, ServerEndpoint, ServerInstance,
    ServerProjection, Snapshot, WireEvent,
};
use crate::state::ServerState;

const BOOTSTRAP_EVENT_CAPACITY: usize = 1024;
const MAX_BUFFERED_SOURCE_BYTES: usize = 8 * 1024 * 1024;
const MAX_READY_SSE_DRAIN: usize = BOOTSTRAP_EVENT_CAPACITY;
const SETTLING_DELAYS: [Duration; 3] = [
    Duration::from_millis(250),
    Duration::from_secs(1),
    Duration::from_secs(3),
];

/// Discovery, reconciliation, reconnect, and event-delivery behavior.
#[derive(Clone, Debug)]
pub struct MonitorConfig {
    /// Cadence of cheap listener-table gate checks.
    pub discovery_interval: Duration,
    /// Cadence of full authoritative discovery regardless of gate stability.
    pub full_verification_interval: Duration,
    pub resync_interval: Duration,
    pub coalesce_interval: Duration,
    pub event_capacity: usize,
    pub client: ClientConfig,
    pub discovery: DiscoveryConfig,
    pub managed_discovery: ManagedDiscoveryConfig,
}

impl Default for MonitorConfig {
    fn default() -> Self {
        Self {
            discovery_interval: Duration::from_secs(1),
            full_verification_interval: Duration::from_secs(5 * 60),
            resync_interval: Duration::from_secs(30),
            coalesce_interval: Duration::from_millis(50),
            event_capacity: 1024,
            client: ClientConfig::default(),
            discovery: DiscoveryConfig::default(),
            managed_discovery: ManagedDiscoveryConfig::default(),
        }
    }
}

impl MonitorConfig {
    fn validate(&self) -> Result<(), MonitorConfigError> {
        for (field, value) in [
            ("discovery_interval", self.discovery_interval),
            (
                "full_verification_interval",
                self.full_verification_interval,
            ),
            ("resync_interval", self.resync_interval),
            ("coalesce_interval", self.coalesce_interval),
            ("connect_timeout", self.client.connect_timeout),
            ("request_timeout", self.client.request_timeout),
            ("event_header_timeout", self.client.event_header_timeout),
        ] {
            if value.is_zero() {
                return Err(MonitorConfigError::ZeroDuration { field });
            }
        }
        if self.event_capacity == 0 {
            return Err(MonitorConfigError::ZeroCapacity {
                field: "event_capacity",
            });
        }
        if self.discovery.probe_concurrency == 0 {
            return Err(MonitorConfigError::ZeroCapacity {
                field: "probe_concurrency",
            });
        }
        Ok(())
    }
}

/// Invalid monitor configuration.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum MonitorConfigError {
    #[error("{field} must be greater than zero")]
    ZeroDuration { field: &'static str },
    #[error("{field} must be greater than zero")]
    ZeroCapacity { field: &'static str },
}

/// Starts reusable local `OpenCode` monitoring.
#[derive(Clone, Debug)]
pub struct Monitor {
    config: MonitorConfig,
}

impl Monitor {
    /// Validates and creates a monitor.
    ///
    /// # Errors
    ///
    /// Returns a typed error for zero intervals, timeouts, or capacities.
    pub fn new(config: MonitorConfig) -> Result<Self, MonitorConfigError> {
        config.validate()?;
        Ok(Self { config })
    }

    /// Spawns monitoring tasks and returns bounded events plus lifecycle controls.
    #[must_use]
    pub fn spawn(self) -> MonitorRuntime {
        let (events_tx, events_rx) = mpsc::channel(self.config.event_capacity);
        let (resync_tx, resync_rx) = watch::channel(0_u64);
        let (discovery_tx, discovery_rx) = watch::channel(0_u64);
        let shutdown = CancellationToken::new();
        let control = MonitorControl {
            shutdown: shutdown.clone(),
            resync: resync_tx,
            discovery: discovery_tx.clone(),
        };
        let sink = EventSink {
            sender: events_tx,
            shutdown: shutdown.clone(),
        };
        let join = tokio::spawn(run_discovery(
            self.config,
            sink,
            resync_rx,
            discovery_tx,
            discovery_rx,
            shutdown,
        ));
        MonitorRuntime {
            events: events_rx,
            control,
            join: Some(join),
        }
    }
}

/// Controls a running monitor.
#[derive(Clone, Debug)]
pub struct MonitorControl {
    shutdown: CancellationToken,
    resync: watch::Sender<u64>,
    discovery: watch::Sender<u64>,
}

impl MonitorControl {
    /// Requests immediate discovery and complete snapshots.
    pub fn request_resync(&self) {
        let next = self.resync.borrow().wrapping_add(1);
        self.resync.send_replace(next);
        request_discovery(&self.discovery);
    }

    /// Requests graceful shutdown.
    pub fn shutdown(&self) {
        self.shutdown.cancel();
    }
}

/// Event receiver and owned completion handle for a running monitor.
pub struct MonitorRuntime {
    pub events: mpsc::Receiver<BeaconEvent>,
    pub control: MonitorControl,
    join: Option<JoinHandle<()>>,
}

impl MonitorRuntime {
    /// Waits for the owned monitor task to stop.
    ///
    /// # Errors
    ///
    /// Returns an error if the monitor task panicked or was cancelled unexpectedly.
    pub async fn wait(&mut self) -> Result<(), tokio::task::JoinError> {
        let result = match self.join.as_mut() {
            Some(join) => join.await,
            None => return Ok(()),
        };
        self.join.take();
        result
    }
}

impl Drop for MonitorRuntime {
    fn drop(&mut self) {
        self.control.shutdown();
        if let Some(join) = self.join.take() {
            join.abort();
        }
    }
}

#[derive(Clone)]
struct EventSink {
    sender: mpsc::Sender<BeaconEvent>,
    shutdown: CancellationToken,
}

impl EventSink {
    async fn send(
        &self,
        local_cancellation: &CancellationToken,
        event: BeaconEvent,
    ) -> Result<(), EmitStopped> {
        tokio::select! {
            biased;
            () = self.shutdown.cancelled() => Err(EmitStopped),
            () = local_cancellation.cancelled() => Err(EmitStopped),
            result = self.sender.send(event) => {
                if result.is_err() {
                    self.shutdown.cancel();
                    Err(EmitStopped)
                } else {
                    Ok(())
                }
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct EmitStopped;

struct ActiveServer {
    instance: ServerInstance,
    connection: ConnectionSettings,
    misses: u8,
    cancellation: CancellationToken,
    verification: watch::Sender<DiscoveryCompletion>,
    join: Option<JoinHandle<()>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct DiscoveryCompletion {
    generation: u64,
    key: Option<InstanceKey>,
}

#[derive(Default)]
struct EventJournal {
    events: Vec<SourceEvent>,
    source_bytes: usize,
    ready_emitted: HashSet<String>,
}

impl EventJournal {
    const fn can_poll(&self) -> bool {
        self.events.len() < BOOTSTRAP_EVENT_CAPACITY
            && self.source_bytes < MAX_BUFFERED_SOURCE_BYTES
    }

    fn push(&mut self, event: SourceEvent) {
        self.source_bytes = self.source_bytes.saturating_add(event.source_bytes);
        self.events.push(event);
    }
}

impl ActiveServer {
    async fn stop(&mut self) {
        self.cancellation.cancel();
        if let Some(join) = self.join.as_mut() {
            let _ = join.await;
            self.join.take();
        }
    }
}

impl Drop for ActiveServer {
    fn drop(&mut self) {
        self.cancellation.cancel();
        if let Some(join) = self.join.take() {
            join.abort();
        }
    }
}

#[derive(Default)]
struct ServerConnectionState {
    reducer: ServerState,
    initialized: bool,
    reconnect_attempt: u32,
    instance_key: Option<InstanceKey>,
}

trait Discoverer {
    fn listener_fingerprint(&self) -> Result<ListenerTableFingerprint, String>;

    fn discover<'a>(
        &'a self,
        client: &'a ClientConfig,
    ) -> Pin<Box<dyn Future<Output = Result<DiscoveryReport, String>> + Send + 'a>>;
}

impl Discoverer for LinuxProcfsDiscovery {
    fn listener_fingerprint(&self) -> Result<ListenerTableFingerprint, String> {
        self.listener_fingerprint()
            .map_err(|error| error.to_string())
    }

    fn discover<'a>(
        &'a self,
        client: &'a ClientConfig,
    ) -> Pin<Box<dyn Future<Output = Result<DiscoveryReport, String>> + Send + 'a>> {
        Box::pin(async move {
            self.discover(client)
                .await
                .map_err(|error| error.to_string())
        })
    }
}

struct CombinedDiscovery {
    procfs: LinuxProcfsDiscovery,
    managed: ManagedServiceDiscovery,
}

impl Discoverer for CombinedDiscovery {
    fn listener_fingerprint(&self) -> Result<ListenerTableFingerprint, String> {
        let listener = self
            .procfs
            .listener_fingerprint()
            .map_err(|error| error.to_string())?;
        let registrations = self
            .managed
            .registration_fingerprint()
            .map_err(|error| error.to_string())?;
        Ok(listener.with_registrations(registrations))
    }

    fn discover<'a>(
        &'a self,
        client: &'a ClientConfig,
    ) -> Pin<Box<dyn Future<Output = Result<DiscoveryReport, String>> + Send + 'a>> {
        Box::pin(async move {
            let (procfs, managed) =
                tokio::join!(self.procfs.discover(client), self.managed.discover(client));
            merge_backend_reports(
                procfs.map_err(|error| error.to_string()),
                managed.map_err(|error| error.to_string()),
            )
        })
    }
}

fn merge_backend_reports(
    procfs: Result<DiscoveryReport, String>,
    managed: Result<DiscoveryReport, String>,
) -> Result<DiscoveryReport, String> {
    let mut report = match (procfs, managed) {
        (Err(left), Err(right)) => {
            return Err(format!(
                "v1 discovery failed: {left}; v2 discovery failed: {right}"
            ));
        }
        (Ok(mut report), Err(error)) => {
            report
                .diagnostics
                .push(crate::discovery::CandidateDiagnostic {
                    message: format!("v2 discovery failed: {error}"),
                });
            report.incomplete_backends.insert(DiscoveryBackend::Managed);
            report
        }
        (Err(error), Ok(mut report)) => {
            report
                .diagnostics
                .push(crate::discovery::CandidateDiagnostic {
                    message: format!("v1 discovery failed: {error}"),
                });
            report.incomplete_backends.insert(DiscoveryBackend::Procfs);
            report
        }
        (Ok(report), Ok(managed)) => {
            let managed_endpoints = managed
                .instances
                .iter()
                .map(|instance| instance.endpoint)
                .collect::<HashSet<_>>();
            let mut report = report;
            let shadowed = report
                .instances
                .iter()
                .filter(|instance| managed_endpoints.contains(&instance.endpoint))
                .map(|instance| instance.key.clone())
                .collect::<HashSet<_>>();
            report
                .instances
                .retain(|instance| !shadowed.contains(&instance.key));
            report.connections.retain(|key, _| !shadowed.contains(key));
            report.instances.extend(managed.instances);
            report.diagnostics.extend(managed.diagnostics);
            report.connections.extend(managed.connections);
            report.listener_fingerprint = report
                .listener_fingerprint
                .merged(managed.listener_fingerprint);
            report
        }
    };
    report
        .instances
        .sort_by_key(|instance| instance.endpoint.address());
    Ok(report)
}

async fn run_discovery(
    config: MonitorConfig,
    sink: EventSink,
    resync: watch::Receiver<u64>,
    discovery_tx: watch::Sender<u64>,
    discovery_trigger: watch::Receiver<u64>,
    shutdown: CancellationToken,
) {
    let discovery = CombinedDiscovery {
        procfs: LinuxProcfsDiscovery::new(config.discovery.clone()),
        managed: ManagedServiceDiscovery::new(
            config.managed_discovery.clone(),
            config.discovery.proc_root.clone(),
        ),
    };
    run_discovery_with(
        &discovery,
        config,
        sink,
        resync,
        discovery_tx,
        discovery_trigger,
        shutdown,
    )
    .await;
}

#[allow(clippy::too_many_lines)]
async fn run_discovery_with<D: Discoverer + Sync>(
    discovery: &D,
    config: MonitorConfig,
    sink: EventSink,
    mut resync: watch::Receiver<u64>,
    discovery_tx: watch::Sender<u64>,
    mut discovery_trigger: watch::Receiver<u64>,
    shutdown: CancellationToken,
) {
    let mut active: HashMap<InstanceKey, ActiveServer> = HashMap::new();
    let mut generation = 0_u64;
    let mut completed_generation = 0_u64;
    let mut gate_interval = tokio::time::interval(config.discovery_interval);
    gate_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    gate_interval.tick().await;
    let mut full_interval = tokio::time::interval(config.full_verification_interval);
    full_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    full_interval.tick().await;
    let mut baseline = None;
    let mut full_pending = true;
    let mut gate_change_pending = false;
    let mut settling: Option<(usize, Pin<Box<Sleep>>)> = None;
    let mut settling_continuation = None;

    loop {
        if full_pending {
            if resync.has_changed().unwrap_or(false) {
                resync.borrow_and_update();
            }
            if discovery_trigger.has_changed().unwrap_or(false) {
                discovery_trigger.borrow_and_update();
            }
            if gate_interval.tick().now_or_never().is_some() {
                match discovery.listener_fingerprint() {
                    Ok(fingerprint) if baseline.as_ref() == Some(&fingerprint) => {}
                    Ok(_) => gate_change_pending = true,
                    Err(_) => {}
                }
            }
            let _ = full_interval.tick().now_or_never();
            if settling
                .as_mut()
                .is_some_and(|(_, timer)| timer.as_mut().now_or_never().is_some())
            {
                let index = settling.take().map_or(0, |(index, _)| index);
                settling_continuation = Some(index + 1);
            }
            generation = generation.wrapping_add(1);
            let result = discover_once(
                discovery,
                &config,
                &sink,
                &resync,
                &discovery_tx,
                &shutdown,
                &mut active,
                generation,
                &mut completed_generation,
            )
            .await;
            let fingerprint = match result {
                Ok(fingerprint) => fingerprint,
                Err(EmitStopped) => break,
            };
            let changed = fingerprint.as_ref().is_some_and(|fingerprint| {
                baseline
                    .as_ref()
                    .map_or(!fingerprint.is_empty(), |old| old != fingerprint)
            });
            if let Some(fingerprint) = fingerprint {
                baseline = Some(fingerprint);
            }
            if changed || gate_change_pending {
                settling = Some(settling_timer(0));
                settling_continuation = None;
            } else if let Some(index) = settling_continuation.take()
                && index < SETTLING_DELAYS.len()
            {
                settling = Some(settling_timer(index));
            }
            gate_change_pending = false;
            full_pending = false;
            continue;
        }

        tokio::select! {
            () = shutdown.cancelled() => break,
            () = sink.sender.closed() => {
                shutdown.cancel();
                break;
            }
            _ = gate_interval.tick() => {
                match discovery.listener_fingerprint() {
                    Ok(fingerprint) if baseline.as_ref() == Some(&fingerprint) => {}
                    Ok(_) => {
                        gate_change_pending = true;
                        full_pending = true;
                    }
                    Err(_) => full_pending = true,
                }
            }
            _ = full_interval.tick() => full_pending = true,
            changed = resync.changed() => {
                if changed.is_err() {
                    break;
                }
                full_pending = true;
            }
            changed = discovery_trigger.changed() => {
                if changed.is_err() {
                    break;
                }
                full_pending = true;
            }
            () = wait_optional_settling(&mut settling), if settling.is_some() => {
                let index = settling.take().map_or(0, |(index, _)| index);
                settling_continuation = Some(index + 1);
                full_pending = true;
            }
        }
    }

    for (_, mut server) in active.drain() {
        server.stop().await;
    }
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn discover_once<D: Discoverer + Sync>(
    discovery: &D,
    config: &MonitorConfig,
    sink: &EventSink,
    resync: &watch::Receiver<u64>,
    discovery_trigger: &watch::Sender<u64>,
    shutdown: &CancellationToken,
    active: &mut HashMap<InstanceKey, ActiveServer>,
    generation: u64,
    completed_generation: &mut u64,
) -> Result<Option<ListenerTableFingerprint>, EmitStopped> {
    let discovery_result = discovery.discover(&config.client);
    tokio::pin!(discovery_result);
    let mut report = match tokio::select! {
        () = shutdown.cancelled() => return Err(EmitStopped),
        () = sink.sender.closed() => {
            sink.shutdown.cancel();
            return Err(EmitStopped);
        }
        result = &mut discovery_result => result,
    } {
        Ok(report) => report,
        Err(error) => {
            sink.send(
                shutdown,
                BeaconEvent::Diagnostic {
                    endpoint: None,
                    message: format!("discovery failed: {error}"),
                    verbose_only: false,
                },
            )
            .await?;
            return Ok(None);
        }
    };
    if shutdown.is_cancelled() || sink.sender.is_closed() {
        return Err(EmitStopped);
    }
    let listener_fingerprint = report.listener_fingerprint.clone();
    for diagnostic in report.diagnostics {
        sink.send(
            shutdown,
            BeaconEvent::Diagnostic {
                endpoint: None,
                message: diagnostic.message,
                verbose_only: true,
            },
        )
        .await?;
    }

    let found = report
        .instances
        .iter()
        .map(|instance| instance.key.clone())
        .collect::<HashSet<_>>();

    let replacements = active
        .iter()
        .filter(|(_, server)| {
            report.instances.iter().any(|instance| {
                let connection_changed = instance.key == server.instance.key
                    && report
                        .connections
                        .get(&instance.key)
                        .is_some_and(|connection| connection != &server.connection);
                connection_changed
                    || (instance.endpoint == server.instance.endpoint
                        && instance.key != server.instance.key
                        && (matches!(instance.key.source, InstanceSource::ManagedService { .. })
                            || !report
                                .incomplete_backends
                                .contains(&backend_for(&server.instance.key.source))))
            })
        })
        .map(|(key, _)| key.clone())
        .collect::<Vec<_>>();
    for key in replacements {
        if let Some(mut server) = active.remove(&key) {
            let instance = server.instance.clone();
            server.stop().await;
            sink.send(shutdown, BeaconEvent::ServerRemoved(instance))
                .await?;
        }
    }

    for server in active.values_mut() {
        if found.contains(&server.instance.key) {
            server.misses = 0;
        } else if !report
            .incomplete_backends
            .contains(&backend_for(&server.instance.key.source))
        {
            if matches!(
                server.instance.key.source,
                InstanceSource::ManagedService { .. }
            ) {
                server.misses = 2;
            } else {
                server.misses = server.misses.saturating_add(1);
            }
        }
    }

    for instance in report.instances {
        if active.contains_key(&instance.key)
            || active
                .values()
                .any(|server| server.instance.endpoint == instance.endpoint)
        {
            continue;
        }
        let Some(connection) = report.connections.remove(&instance.key) else {
            sink.send(
                shutdown,
                BeaconEvent::Diagnostic {
                    endpoint: Some(instance.endpoint),
                    message: "discovery omitted private connection settings".to_owned(),
                    verbose_only: false,
                },
            )
            .await?;
            continue;
        };
        sink.send(shutdown, BeaconEvent::ServerFound(instance.clone()))
            .await?;
        let cancellation = shutdown.child_token();
        let (verification, verification_rx) = watch::channel(DiscoveryCompletion {
            generation: *completed_generation,
            key: None,
        });
        let join = tokio::spawn(run_server(
            instance.clone(),
            connection.clone(),
            config.clone(),
            sink.clone(),
            resync.clone(),
            discovery_trigger.clone(),
            verification_rx,
            cancellation.clone(),
        ));
        active.insert(
            instance.key.clone(),
            ActiveServer {
                instance,
                connection,
                misses: 0,
                cancellation,
                verification,
                join: Some(join),
            },
        );
    }

    let removed = active
        .iter()
        .filter_map(|(key, server)| (server.misses >= 2).then_some(key.clone()))
        .collect::<Vec<_>>();
    for key in removed {
        if let Some(mut server) = active.remove(&key) {
            let instance = server.instance.clone();
            server.stop().await;
            sink.send(shutdown, BeaconEvent::ServerRemoved(instance))
                .await?;
        }
    }
    if shutdown.is_cancelled() || sink.sender.is_closed() {
        return Err(EmitStopped);
    }
    publish_discovery_completion(active, &found, generation, completed_generation);
    Ok(Some(listener_fingerprint))
}

const fn backend_for(source: &InstanceSource) -> DiscoveryBackend {
    match source {
        InstanceSource::LinuxProcfs => DiscoveryBackend::Procfs,
        InstanceSource::ManagedService { .. } => DiscoveryBackend::Managed,
    }
}

fn settling_timer(index: usize) -> (usize, Pin<Box<Sleep>>) {
    (index, Box::pin(tokio::time::sleep(SETTLING_DELAYS[index])))
}

async fn wait_optional_settling(timer: &mut Option<(usize, Pin<Box<Sleep>>)>) {
    if let Some((_, timer)) = timer {
        timer.await;
    } else {
        pending::<()>().await;
    }
}

fn request_discovery(discovery: &watch::Sender<u64>) {
    let next = discovery.borrow().wrapping_add(1);
    discovery.send_replace(next);
}

fn record_disconnect(
    verification: &mut watch::Receiver<DiscoveryCompletion>,
    discovery: &watch::Sender<u64>,
) -> u64 {
    let generation = verification.borrow_and_update().generation;
    request_discovery(discovery);
    generation
}

fn publish_discovery_completion(
    active: &HashMap<InstanceKey, ActiveServer>,
    found: &HashSet<InstanceKey>,
    generation: u64,
    completed_generation: &mut u64,
) {
    for server in active.values() {
        server.verification.send_replace(DiscoveryCompletion {
            generation,
            key: found
                .contains(&server.instance.key)
                .then(|| server.instance.key.clone()),
        });
    }
    *completed_generation = generation;
}

trait ServerClient {
    fn endpoint(&self) -> ServerEndpoint;

    fn snapshot(&self) -> Pin<Box<dyn Future<Output = Result<Snapshot, String>> + Send + '_>>;

    fn event_stream(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<SourceEventStream, String>> + Send + '_>>;
}

impl ServerClient for OpenCodeClient {
    fn endpoint(&self) -> ServerEndpoint {
        self.endpoint()
    }

    fn snapshot(&self) -> Pin<Box<dyn Future<Output = Result<Snapshot, String>> + Send + '_>> {
        Box::pin(async { self.snapshot().await.map_err(|error| error.to_string()) })
    }

    fn event_stream(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<SourceEventStream, String>> + Send + '_>> {
        Box::pin(async {
            self.source_event_stream()
                .await
                .map_err(|error| error.to_string())
        })
    }
}

impl ServerClient for OpenCodeV2Client {
    fn endpoint(&self) -> ServerEndpoint {
        self.endpoint()
    }

    fn snapshot(&self) -> Pin<Box<dyn Future<Output = Result<Snapshot, String>> + Send + '_>> {
        Box::pin(async { self.snapshot().await.map_err(|error| error.to_string()) })
    }

    fn event_stream(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<SourceEventStream, String>> + Send + '_>> {
        Box::pin(async {
            self.source_event_stream()
                .await
                .map_err(|error| error.to_string())
        })
    }
}

enum BackendClient {
    V1(OpenCodeClient),
    V2(OpenCodeV2Client),
}

impl ServerClient for BackendClient {
    fn endpoint(&self) -> ServerEndpoint {
        match self {
            Self::V1(client) => client.endpoint(),
            Self::V2(client) => client.endpoint(),
        }
    }

    fn snapshot(&self) -> Pin<Box<dyn Future<Output = Result<Snapshot, String>> + Send + '_>> {
        match self {
            Self::V1(client) => ServerClient::snapshot(client),
            Self::V2(client) => ServerClient::snapshot(client),
        }
    }

    fn event_stream(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<SourceEventStream, String>> + Send + '_>> {
        match self {
            Self::V1(client) => ServerClient::event_stream(client),
            Self::V2(client) => ServerClient::event_stream(client),
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_server(
    instance: ServerInstance,
    connection: ConnectionSettings,
    config: MonitorConfig,
    sink: EventSink,
    mut resync: watch::Receiver<u64>,
    discovery_trigger: watch::Sender<u64>,
    mut verification: watch::Receiver<DiscoveryCompletion>,
    cancellation: CancellationToken,
) {
    let mut client_config = config.client.clone();
    if instance.protocol == OpenCodeProtocol::V2 {
        client_config.auth = connection.auth;
    }
    let client = match instance.protocol {
        OpenCodeProtocol::V1 => {
            OpenCodeClient::new(instance.endpoint, client_config).map(BackendClient::V1)
        }
        OpenCodeProtocol::V2 => {
            OpenCodeV2Client::new(instance.endpoint, client_config).map(BackendClient::V2)
        }
    };
    let client = match client {
        Ok(client) => client,
        Err(error) => {
            let _ = send_diagnostic(
                &sink,
                &cancellation,
                instance.endpoint,
                format!("client setup failed: {error}"),
                false,
            )
            .await;
            return;
        }
    };
    let mut connection_state = ServerConnectionState {
        instance_key: Some(instance.key.clone()),
        ..ServerConnectionState::default()
    };

    loop {
        if cancellation.is_cancelled() || sink.shutdown.is_cancelled() {
            break;
        }
        match monitor_connection(
            &client,
            &config,
            &sink,
            &mut resync,
            &cancellation,
            &mut connection_state,
        )
        .await
        {
            Ok(()) => break,
            Err(reason) => {
                let disconnect_generation =
                    record_disconnect(&mut verification, &discovery_trigger);
                if sink
                    .send(
                        &cancellation,
                        BeaconEvent::Disconnected {
                            endpoint: instance.endpoint,
                            reason,
                        },
                    )
                    .await
                    .is_err()
                {
                    break;
                }
                if !wait_to_reconnect(
                    &instance.key,
                    disconnect_generation,
                    &mut verification,
                    &sink.shutdown,
                    &cancellation,
                    connection_state.reconnect_attempt,
                )
                .await
                {
                    break;
                }
                connection_state.reconnect_attempt =
                    connection_state.reconnect_attempt.saturating_add(1);
            }
        }
    }
}

async fn wait_to_reconnect(
    expected_key: &InstanceKey,
    disconnect_generation: u64,
    verification: &mut watch::Receiver<DiscoveryCompletion>,
    shutdown: &CancellationToken,
    cancellation: &CancellationToken,
    attempt: u32,
) -> bool {
    let delay = tokio::time::sleep(reconnect_delay(attempt));
    tokio::pin!(delay);
    let mut delay_elapsed = false;
    let mut verified = false;
    loop {
        let current = verification.borrow_and_update().clone();
        verified |= current.key.as_ref() == Some(expected_key)
            && current.generation > disconnect_generation;
        if verified && delay_elapsed {
            return true;
        }
        tokio::select! {
            () = shutdown.cancelled() => return false,
            () = cancellation.cancelled() => return false,
            () = &mut delay, if !delay_elapsed => delay_elapsed = true,
            changed = verification.changed(), if !verified => {
                if changed.is_err() {
                    return false;
                }
            }
        }
    }
}

async fn monitor_connection<C: ServerClient + Sync>(
    client: &C,
    config: &MonitorConfig,
    sink: &EventSink,
    resync: &mut watch::Receiver<u64>,
    cancellation: &CancellationToken,
    connection_state: &mut ServerConnectionState,
) -> Result<(), String> {
    let Some((mut stream, had_buffered_state)) =
        bootstrap_connection(client, sink, cancellation, connection_state).await?
    else {
        return Ok(());
    };

    let mut periodic = tokio::time::interval(config.resync_interval);
    periodic.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    periodic.tick().await;
    let mut coalesced = had_buffered_state.then(|| {
        Box::pin(tokio::time::sleep_until(
            Instant::now() + config.coalesce_interval,
        )) as Pin<Box<Sleep>>
    });
    let mut reconcile_immediately = false;

    loop {
        if reconcile_immediately {
            let Some((snapshot, journal, rerun)) = reconcile_in_flight(
                client,
                sink,
                cancellation,
                connection_state,
                &mut stream,
                &mut periodic,
                resync,
                &mut coalesced,
                config.coalesce_interval,
            )
            .await?
            else {
                return Ok(());
            };
            apply_reconciliation_result(
                sink,
                cancellation,
                client.endpoint(),
                connection_state,
                snapshot,
                journal,
            )
            .await
            .map_err(|_| "event receiver closed".to_owned())?;
            reconcile_immediately = rerun;
            continue;
        }
        tokio::select! {
            () = sink.shutdown.cancelled() => return Ok(()),
            () = cancellation.cancelled() => return Ok(()),
            () = sink.sender.closed() => {
                sink.shutdown.cancel();
                return Ok(());
            }
            item = stream.next() => {
                let event = match item {
                    Some(Ok(event)) => event,
                    Some(Err(error)) => return Err(error.to_string()),
                    None => return Err("SSE stream ended".to_owned()),
                };
                let state_event = is_state_event(&event.event);
                let _ = handle_live_event(
                    sink,
                    cancellation,
                    client.endpoint(),
                    connection_state.instance_key.as_ref(),
                    &mut connection_state.reducer,
                    &event.event,
                )
                .await
                .map_err(|_| "event receiver closed".to_owned())?;
                if state_event {
                    coalesced = Some(Box::pin(tokio::time::sleep_until(
                        Instant::now() + config.coalesce_interval,
                    )));
                }
            }
            _ = periodic.tick() => {
                reconcile_immediately = true;
            }
            changed = resync.changed() => {
                if changed.is_err() {
                    return Ok(());
                }
                reconcile_immediately = true;
            }
            () = wait_optional(&mut coalesced), if coalesced.is_some() => {
                coalesced = None;
                reconcile_immediately = true;
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn reconcile_in_flight<C: ServerClient + Sync>(
    client: &C,
    sink: &EventSink,
    cancellation: &CancellationToken,
    connection_state: &mut ServerConnectionState,
    stream: &mut SourceEventStream,
    periodic: &mut tokio::time::Interval,
    resync: &mut watch::Receiver<u64>,
    coalesced: &mut Option<Pin<Box<Sleep>>>,
    coalesce_interval: Duration,
) -> Result<Option<(Result<Snapshot, String>, EventJournal, bool)>, String> {
    let snapshot = client.snapshot();
    tokio::pin!(snapshot);
    let mut journal = EventJournal::default();
    let mut rerun = false;
    loop {
        tokio::select! {
            biased;
            () = sink.shutdown.cancelled() => return Ok(None),
            () = cancellation.cancelled() => return Ok(None),
            () = sink.sender.closed() => {
                sink.shutdown.cancel();
                return Ok(None);
            }
            item = stream.next(), if journal.can_poll() => {
                process_reconciliation_item(
                    sink,
                    cancellation,
                    client.endpoint(),
                    connection_state,
                    &mut journal,
                    item,
                    coalesced,
                    coalesce_interval,
                )
                .await?;
                for _ in 1..MAX_READY_SSE_DRAIN {
                    if monitoring_stopped(sink, cancellation) {
                        return Ok(None);
                    }
                    if !journal.can_poll() {
                        break;
                    }
                    let Some(item) = stream.next().now_or_never() else {
                        break;
                    };
                    process_reconciliation_item(
                        sink,
                        cancellation,
                        client.endpoint(),
                        connection_state,
                        &mut journal,
                        item,
                        coalesced,
                        coalesce_interval,
                    )
                    .await?;
                }
                if monitoring_stopped(sink, cancellation) {
                    return Ok(None);
                }
                if let Some(result) = snapshot.as_mut().now_or_never() {
                    let Some(ready_trigger) = drain_ready_reconciliation_triggers(
                        periodic,
                        resync,
                        coalesced,
                    ) else {
                        return Ok(None);
                    };
                    return Ok(Some((result, journal, rerun || ready_trigger)));
                }
            }
            result = &mut snapshot => {
                if monitoring_stopped(sink, cancellation) {
                    return Ok(None);
                }
                let Some(ready_trigger) = drain_ready_reconciliation_triggers(
                    periodic,
                    resync,
                    coalesced,
                ) else {
                    return Ok(None);
                };
                return Ok(Some((result, journal, rerun || ready_trigger)));
            }
            _ = periodic.tick() => rerun = true,
            changed = resync.changed() => {
                if changed.is_err() {
                    return Ok(None);
                }
                rerun = true;
            }
            () = wait_optional(coalesced), if coalesced.is_some() => {
                *coalesced = None;
                rerun = true;
            }
        }
    }
}

fn drain_ready_reconciliation_triggers(
    periodic: &mut tokio::time::Interval,
    resync: &mut watch::Receiver<u64>,
    coalesced: &mut Option<Pin<Box<Sleep>>>,
) -> Option<bool> {
    let periodic_ready = periodic.tick().now_or_never().is_some();
    let manual_ready = match resync.changed().now_or_never() {
        Some(Ok(())) => true,
        Some(Err(_)) => return None,
        None => false,
    };
    let coalesced_ready = coalesced
        .as_mut()
        .is_some_and(|timer| timer.as_mut().now_or_never().is_some());
    if coalesced_ready {
        *coalesced = None;
    }
    Some(periodic_ready || manual_ready || coalesced_ready)
}

#[allow(clippy::too_many_arguments)]
async fn process_reconciliation_item(
    sink: &EventSink,
    cancellation: &CancellationToken,
    endpoint: ServerEndpoint,
    connection_state: &mut ServerConnectionState,
    journal: &mut EventJournal,
    item: Option<Result<SourceEvent, crate::client::ClientError>>,
    coalesced: &mut Option<Pin<Box<Sleep>>>,
    coalesce_interval: Duration,
) -> Result<(), String> {
    let event = match item {
        Some(Ok(event)) => event,
        Some(Err(error)) => return Err(error.to_string()),
        None => return Err("SSE stream ended during reconciliation".to_owned()),
    };
    let state_event = is_state_event(&event.event);
    if state_event {
        journal.push(event.clone());
    }
    let ready_emitted = handle_live_event(
        sink,
        cancellation,
        endpoint,
        connection_state.instance_key.as_ref(),
        &mut connection_state.reducer,
        &event.event,
    )
    .await
    .map_err(|_| "event receiver closed".to_owned())?;
    journal.ready_emitted.extend(ready_emitted);
    if state_event {
        *coalesced = Some(Box::pin(tokio::time::sleep_until(
            Instant::now() + coalesce_interval,
        )));
    }
    Ok(())
}

async fn bootstrap_connection<C: ServerClient + Sync>(
    client: &C,
    sink: &EventSink,
    cancellation: &CancellationToken,
    connection_state: &mut ServerConnectionState,
) -> Result<Option<(SourceEventStream, bool)>, String> {
    let event_stream = client.event_stream();
    tokio::pin!(event_stream);
    let mut stream = tokio::select! {
        () = sink.shutdown.cancelled() => return Ok(None),
        () = cancellation.cancelled() => return Ok(None),
        result = &mut event_stream => result?,
    };
    sink.send(cancellation, BeaconEvent::Connected(client.endpoint()))
        .await
        .map_err(|_| "event receiver closed".to_owned())?;
    let snapshot = client.snapshot();
    tokio::pin!(snapshot);
    let mut buffered = EventJournal::default();
    let bootstrap_snapshot = loop {
        tokio::select! {
            () = sink.shutdown.cancelled() => return Ok(None),
            () = cancellation.cancelled() => return Ok(None),
            () = sink.sender.closed() => {
                sink.shutdown.cancel();
                return Ok(None);
            }
            result = &mut snapshot => break Ok(result),
            item = stream.next(), if buffered.can_poll() => {
                match item {
                    Some(Ok(event)) => buffered.push(event),
                    Some(Err(error)) => break Err(error.to_string()),
                    None => break Err("SSE stream ended during bootstrap".to_owned()),
                }
            }
        }
    };
    if monitoring_stopped(sink, cancellation) {
        return Ok(None);
    }

    let terminal_error = match bootstrap_snapshot {
        Ok(snapshot) => {
            let bootstrap_succeeded = snapshot.is_ok();
            apply_bootstrap_snapshot_result(
                sink,
                cancellation,
                client.endpoint(),
                connection_state,
                snapshot,
            )
            .await
            .map_err(|_| "event receiver closed".to_owned())?;
            if bootstrap_succeeded {
                connection_state.reconnect_attempt = 0;
            }
            None
        }
        Err(error) => Some(error),
    };
    let had_buffered_state = buffered
        .events
        .iter()
        .any(|event| is_state_event(&event.event));
    for event in buffered.events {
        let _ = handle_live_event(
            sink,
            cancellation,
            client.endpoint(),
            connection_state.instance_key.as_ref(),
            &mut connection_state.reducer,
            &event.event,
        )
        .await
        .map_err(|_| "event receiver closed".to_owned())?;
    }
    if let Some(error) = terminal_error {
        return Err(error);
    }
    Ok(Some((stream, had_buffered_state)))
}

async fn wait_optional(timer: &mut Option<Pin<Box<Sleep>>>) {
    if let Some(timer) = timer {
        timer.await;
    } else {
        pending::<()>().await;
    }
}

fn monitoring_stopped(sink: &EventSink, cancellation: &CancellationToken) -> bool {
    if sink.shutdown.is_cancelled() || cancellation.is_cancelled() {
        return true;
    }
    if sink.sender.is_closed() {
        sink.shutdown.cancel();
        return true;
    }
    false
}

async fn handle_live_event(
    sink: &EventSink,
    cancellation: &CancellationToken,
    endpoint: ServerEndpoint,
    instance_key: Option<&InstanceKey>,
    state: &mut ServerState,
    event: &WireEvent,
) -> Result<Vec<String>, EmitStopped> {
    let update = state.apply_event_with_updates(event);
    let ready_emitted = update
        .attention
        .iter()
        .filter(|attention| attention.kind == crate::model::AttentionKind::Ready)
        .map(|attention| attention.root_session_id.clone())
        .collect::<Vec<_>>();
    if event.kind != "server.heartbeat" {
        sink.send(
            cancellation,
            BeaconEvent::Observed {
                endpoint,
                event: ServerState::observe(event),
            },
        )
        .await?;
    }
    emit_transitions(sink, cancellation, endpoint, update.transitions).await?;
    emit_attention(sink, cancellation, endpoint, update.attention).await?;
    if is_state_event(event) {
        emit_projection(sink, cancellation, endpoint, state, instance_key).await?;
    }
    Ok(ready_emitted)
}

async fn apply_bootstrap_snapshot_result(
    sink: &EventSink,
    cancellation: &CancellationToken,
    endpoint: ServerEndpoint,
    connection_state: &mut ServerConnectionState,
    snapshot: Result<Snapshot, String>,
) -> Result<(), EmitStopped> {
    match snapshot {
        Ok(snapshot) => {
            let initial = !connection_state.initialized;
            let update = connection_state
                .reducer
                .reconcile_with_updates(snapshot, initial);
            if initial {
                sink.send(
                    cancellation,
                    BeaconEvent::InitialState {
                        endpoint,
                        active_sessions: connection_state.reducer.active_session_count(),
                    },
                )
                .await?;
                connection_state.initialized = true;
            }
            emit_transitions(sink, cancellation, endpoint, update.transitions).await?;
            emit_attention(sink, cancellation, endpoint, update.attention).await?;
            emit_projection(
                sink,
                cancellation,
                endpoint,
                &connection_state.reducer,
                connection_state.instance_key.as_ref(),
            )
            .await
        }
        Err(error) => {
            send_diagnostic(
                sink,
                cancellation,
                endpoint,
                format!("snapshot reconciliation failed: {error}"),
                false,
            )
            .await
        }
    }
}

async fn apply_reconciliation_result(
    sink: &EventSink,
    cancellation: &CancellationToken,
    endpoint: ServerEndpoint,
    connection_state: &mut ServerConnectionState,
    snapshot: Result<Snapshot, String>,
    journal: EventJournal,
) -> Result<(), EmitStopped> {
    match snapshot {
        Ok(snapshot) => {
            let initial = !connection_state.initialized;
            let update = connection_state.reducer.reconcile_replayed_with_updates(
                snapshot,
                journal.events.iter().map(|event| &event.event),
                initial,
                &journal.ready_emitted,
            );
            if initial {
                sink.send(
                    cancellation,
                    BeaconEvent::InitialState {
                        endpoint,
                        active_sessions: connection_state.reducer.active_session_count(),
                    },
                )
                .await?;
                connection_state.initialized = true;
            }
            emit_transitions(sink, cancellation, endpoint, update.transitions).await?;
            emit_attention(sink, cancellation, endpoint, update.attention).await?;
            emit_projection(
                sink,
                cancellation,
                endpoint,
                &connection_state.reducer,
                connection_state.instance_key.as_ref(),
            )
            .await
        }
        Err(error) => {
            send_diagnostic(
                sink,
                cancellation,
                endpoint,
                format!("snapshot reconciliation failed: {error}"),
                false,
            )
            .await
        }
    }
}

async fn emit_transitions(
    sink: &EventSink,
    cancellation: &CancellationToken,
    endpoint: ServerEndpoint,
    transitions: Vec<crate::model::StateTransition>,
) -> Result<(), EmitStopped> {
    for transition in transitions {
        sink.send(
            cancellation,
            BeaconEvent::Transition {
                endpoint,
                transition,
            },
        )
        .await?;
    }
    Ok(())
}

async fn emit_attention(
    sink: &EventSink,
    cancellation: &CancellationToken,
    endpoint: ServerEndpoint,
    attention_events: Vec<crate::model::AttentionEvent>,
) -> Result<(), EmitStopped> {
    for attention in attention_events {
        sink.send(
            cancellation,
            BeaconEvent::Attention {
                endpoint,
                attention,
            },
        )
        .await?;
    }
    Ok(())
}

async fn emit_projection(
    sink: &EventSink,
    cancellation: &CancellationToken,
    endpoint: ServerEndpoint,
    state: &ServerState,
    instance_key: Option<&InstanceKey>,
) -> Result<(), EmitStopped> {
    let Some(instance_key) = instance_key else {
        return Ok(());
    };
    sink.send(
        cancellation,
        BeaconEvent::StateProjection(ServerProjection {
            instance_key: instance_key.clone(),
            endpoint,
            sessions: state.projection(),
        }),
    )
    .await
}

fn is_state_event(event: &WireEvent) -> bool {
    matches!(
        event.kind.as_str(),
        "session.status"
            | "session.execution.failed"
            | "session.created"
            | "session.updated"
            | "session.renamed"
            | "session.deleted"
            | "permission.asked"
            | "permission.replied"
            | "question.asked"
            | "question.replied"
            | "question.rejected"
    )
}

fn reconnect_delay(attempt: u32) -> Duration {
    let exponent = attempt.min(5);
    let base_millis = (1_000_u64 << exponent).min(30_000);
    let jitter = fastrand::u64(800..=1_200);
    Duration::from_millis(base_millis.saturating_mul(jitter) / 1_000)
}

async fn send_diagnostic(
    sink: &EventSink,
    cancellation: &CancellationToken,
    endpoint: ServerEndpoint,
    message: String,
    verbose_only: bool,
) -> Result<(), EmitStopped> {
    sink.send(
        cancellation,
        BeaconEvent::Diagnostic {
            endpoint: Some(endpoint),
            message,
            verbose_only,
        },
    )
    .await
}

#[cfg(test)]
mod tests {
    use std::collections::{HashMap, VecDeque};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    use futures_util::stream;
    use secrecy::SecretString;
    use serde_json::json;

    use super::*;
    use crate::client::BasicAuth;
    use crate::model::{AttentionKind, QuestionRequest, Session, SessionStatus};

    struct ScriptedClient {
        endpoint: ServerEndpoint,
        snapshots: Mutex<VecDeque<(Duration, Result<Snapshot, String>)>>,
        stream: Mutex<Option<SourceEventStream>>,
    }

    struct PendingHeaderClient {
        endpoint: ServerEndpoint,
    }

    struct PendingSnapshotClient {
        endpoint: ServerEndpoint,
        stream: Mutex<Option<SourceEventStream>>,
    }

    struct ReadySnapshotClient {
        endpoint: ServerEndpoint,
        snapshot: Mutex<Option<Result<Snapshot, String>>>,
    }

    struct PendingDiscoverer;

    struct ReadyDiscoverer {
        report: Mutex<Option<DiscoveryReport>>,
    }

    struct ScriptedGateDiscoverer {
        fingerprint: Mutex<ListenerTableFingerprint>,
        gate_results: Mutex<VecDeque<Result<ListenerTableFingerprint, String>>>,
        reports: Mutex<VecDeque<Result<DiscoveryReport, String>>>,
        full_calls: AtomicUsize,
        gate_calls: AtomicUsize,
    }

    impl Discoverer for PendingDiscoverer {
        fn listener_fingerprint(&self) -> Result<ListenerTableFingerprint, String> {
            Ok(ListenerTableFingerprint::default())
        }

        fn discover<'a>(
            &'a self,
            _client: &'a ClientConfig,
        ) -> Pin<Box<dyn Future<Output = Result<DiscoveryReport, String>> + Send + 'a>> {
            Box::pin(pending())
        }
    }

    impl Discoverer for ReadyDiscoverer {
        fn listener_fingerprint(&self) -> Result<ListenerTableFingerprint, String> {
            Ok(ListenerTableFingerprint::default())
        }

        fn discover<'a>(
            &'a self,
            _client: &'a ClientConfig,
        ) -> Pin<Box<dyn Future<Output = Result<DiscoveryReport, String>> + Send + 'a>> {
            let report = self
                .report
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take()
                .unwrap_or_default();
            Box::pin(std::future::ready(Ok(report)))
        }
    }

    impl ScriptedGateDiscoverer {
        fn new(fingerprint: ListenerTableFingerprint) -> Self {
            Self {
                fingerprint: Mutex::new(fingerprint),
                gate_results: Mutex::new(VecDeque::new()),
                reports: Mutex::new(VecDeque::new()),
                full_calls: AtomicUsize::new(0),
                gate_calls: AtomicUsize::new(0),
            }
        }

        fn set_fingerprint(&self, fingerprint: ListenerTableFingerprint) {
            *self
                .fingerprint
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = fingerprint;
        }

        fn push_gate_error(&self, message: &str) {
            self.gate_results
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push_back(Err(message.to_owned()));
        }

        fn push_report(&self, report: DiscoveryReport) {
            self.reports
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push_back(Ok(report));
        }
    }

    impl Discoverer for ScriptedGateDiscoverer {
        fn listener_fingerprint(&self) -> Result<ListenerTableFingerprint, String> {
            self.gate_calls.fetch_add(1, Ordering::SeqCst);
            self.gate_results
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .pop_front()
                .unwrap_or_else(|| {
                    Ok(self
                        .fingerprint
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .clone())
                })
        }

        fn discover<'a>(
            &'a self,
            _client: &'a ClientConfig,
        ) -> Pin<Box<dyn Future<Output = Result<DiscoveryReport, String>> + Send + 'a>> {
            self.full_calls.fetch_add(1, Ordering::SeqCst);
            let report = self
                .reports
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .pop_front()
                .unwrap_or_else(|| {
                    Ok(DiscoveryReport {
                        listener_fingerprint: self
                            .fingerprint
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .clone(),
                        ..DiscoveryReport::default()
                    })
                });
            Box::pin(std::future::ready(report))
        }
    }

    impl ServerClient for PendingHeaderClient {
        fn endpoint(&self) -> ServerEndpoint {
            self.endpoint
        }

        fn snapshot(&self) -> Pin<Box<dyn Future<Output = Result<Snapshot, String>> + Send + '_>> {
            Box::pin(pending())
        }

        fn event_stream(
            &self,
        ) -> Pin<Box<dyn Future<Output = Result<SourceEventStream, String>> + Send + '_>> {
            Box::pin(pending())
        }
    }

    impl ServerClient for PendingSnapshotClient {
        fn endpoint(&self) -> ServerEndpoint {
            self.endpoint
        }

        fn snapshot(&self) -> Pin<Box<dyn Future<Output = Result<Snapshot, String>> + Send + '_>> {
            Box::pin(pending())
        }

        fn event_stream(
            &self,
        ) -> Pin<Box<dyn Future<Output = Result<SourceEventStream, String>> + Send + '_>> {
            let stream = self
                .stream
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take()
                .ok_or_else(|| "stream already taken".to_owned());
            Box::pin(std::future::ready(stream))
        }
    }

    impl ServerClient for ReadySnapshotClient {
        fn endpoint(&self) -> ServerEndpoint {
            self.endpoint
        }

        fn snapshot(&self) -> Pin<Box<dyn Future<Output = Result<Snapshot, String>> + Send + '_>> {
            let snapshot = self
                .snapshot
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take()
                .unwrap_or_else(|| Err("no ready snapshot".to_owned()));
            Box::pin(std::future::ready(snapshot))
        }

        fn event_stream(
            &self,
        ) -> Pin<Box<dyn Future<Output = Result<SourceEventStream, String>> + Send + '_>> {
            Box::pin(std::future::ready(Err("event stream unused".to_owned())))
        }
    }

    impl ServerClient for ScriptedClient {
        fn endpoint(&self) -> ServerEndpoint {
            self.endpoint
        }

        fn snapshot(&self) -> Pin<Box<dyn Future<Output = Result<Snapshot, String>> + Send + '_>> {
            let scripted = self
                .snapshots
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .pop_front()
                .unwrap_or_else(|| (Duration::ZERO, Err("no scripted snapshot".to_owned())));
            Box::pin(async move {
                tokio::time::sleep(scripted.0).await;
                scripted.1
            })
        }

        fn event_stream(
            &self,
        ) -> Pin<Box<dyn Future<Output = Result<SourceEventStream, String>> + Send + '_>> {
            let stream = self
                .stream
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take()
                .ok_or_else(|| "stream already taken".to_owned());
            Box::pin(std::future::ready(stream))
        }
    }

    fn endpoint() -> ServerEndpoint {
        ServerEndpoint::new(
            "127.0.0.1:4096"
                .parse()
                .unwrap_or_else(|error| unreachable!("static address parses: {error}")),
        )
        .unwrap_or_else(|error| unreachable!("static address is loopback: {error}"))
    }

    fn instance_key(socket_inode: u64) -> InstanceKey {
        InstanceKey {
            network_namespace_inode: 1,
            socket_inode,
            listener: endpoint().address(),
            pid: 3,
            source: InstanceSource::LinuxProcfs,
        }
    }

    fn server_instance(socket_inode: u64) -> ServerInstance {
        ServerInstance {
            key: instance_key(socket_inode),
            endpoint: endpoint(),
            protocol: OpenCodeProtocol::V1,
            executable: None,
            version: "1.17.4".to_owned(),
        }
    }

    fn managed_instance(port: u16, id: &str) -> ServerInstance {
        let endpoint = ServerEndpoint::new(std::net::SocketAddr::from(([127, 0, 0, 1], port)))
            .unwrap_or_else(|error| unreachable!("test endpoint is loopback: {error}"));
        ServerInstance {
            key: InstanceKey {
                network_namespace_inode: 0,
                socket_inode: 0,
                listener: endpoint.address(),
                pid: u32::from(port),
                source: InstanceSource::ManagedService {
                    registration: PathBuf::from(format!("/state/service-{id}.json")),
                    id: Some(id.to_owned()),
                },
            },
            endpoint,
            protocol: OpenCodeProtocol::V2,
            executable: None,
            version: "2.0.0".to_owned(),
        }
    }

    fn managed_connection(password: &str) -> ConnectionSettings {
        ConnectionSettings {
            auth: Some(BasicAuth::new(
                "opencode".to_owned(),
                SecretString::from(password.to_owned()),
            )),
        }
    }

    fn busy_event() -> WireEvent {
        WireEvent {
            kind: "session.status".to_owned(),
            properties: json!({"sessionID": "s", "status": {"type": "busy"}}),
        }
    }

    #[test]
    fn v2_execution_failure_requests_authoritative_reconciliation() {
        assert!(is_state_event(&WireEvent {
            kind: "session.execution.failed".to_owned(),
            properties: json!({
                "sessionID": "ses_1",
                "error": {"type": "ProviderError", "message": "failed"},
            }),
        }));
    }

    fn idle_event() -> WireEvent {
        WireEvent {
            kind: "session.status".to_owned(),
            properties: json!({"sessionID": "s", "status": {"type": "idle"}}),
        }
    }

    fn numbered_event(number: usize) -> WireEvent {
        WireEvent {
            kind: "future.event".to_owned(),
            properties: json!({"id": number.to_string()}),
        }
    }

    fn sourced(event: WireEvent, source_bytes: usize) -> SourceEvent {
        SourceEvent {
            event,
            source_bytes,
        }
    }

    fn busy_snapshot() -> Snapshot {
        Snapshot {
            sessions: vec![Session {
                id: "s".to_owned(),
                ..Session::default()
            }],
            statuses: HashMap::from([("s".to_owned(), SessionStatus::Busy)]),
            permissions: Vec::new(),
            questions: Vec::new(),
        }
    }

    fn named_session(id: &str) -> Session {
        Session {
            id: id.to_owned(),
            title: "Root title".to_owned(),
            slug: "root-slug".to_owned(),
            parent_id: None,
            ..Session::default()
        }
    }

    fn question_event() -> WireEvent {
        WireEvent {
            kind: "question.asked".to_owned(),
            properties: json!({
                "id": "q",
                "sessionID": "s",
                "questions": [{"question": "must not escape"}]
            }),
        }
    }

    fn pending_question_snapshot(status: SessionStatus) -> Snapshot {
        Snapshot {
            sessions: vec![named_session("s")],
            statuses: HashMap::from([("s".to_owned(), status)]),
            questions: vec![QuestionRequest {
                id: "q".to_owned(),
                session_id: "s".to_owned(),
            }],
            ..Snapshot::default()
        }
    }

    async fn wait_for_full_calls(discovery: &ScriptedGateDiscoverer, expected: usize) {
        for _ in 0..100 {
            if discovery.full_calls.load(Ordering::SeqCst) >= expected {
                return;
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(discovery.full_calls.load(Ordering::SeqCst), expected);
    }

    #[tokio::test]
    async fn live_output_orders_observed_transition_then_attention() {
        let (sender, mut receiver) = mpsc::channel(8);
        let shutdown = CancellationToken::new();
        let cancellation = shutdown.child_token();
        let sink = EventSink { sender, shutdown };
        let mut state = ServerState::default();
        let _ = state.reconcile_with_updates(
            Snapshot {
                sessions: vec![named_session("s")],
                statuses: HashMap::from([("s".to_owned(), SessionStatus::Busy)]),
                ..Snapshot::default()
            },
            true,
        );

        assert!(
            handle_live_event(
                &sink,
                &cancellation,
                endpoint(),
                None,
                &mut state,
                &question_event(),
            )
            .await
            .is_ok()
        );
        let events = [
            receiver
                .recv()
                .await
                .unwrap_or_else(|| unreachable!("observed event")),
            receiver
                .recv()
                .await
                .unwrap_or_else(|| unreachable!("transition event")),
            receiver
                .recv()
                .await
                .unwrap_or_else(|| unreachable!("attention event")),
        ];
        assert!(matches!(&events[0], BeaconEvent::Observed { .. }));
        assert!(matches!(
            &events[1],
            BeaconEvent::Transition { transition, .. }
                if transition.current == crate::model::ActivityState::WaitingForInput
        ));
        assert!(matches!(
            &events[2],
            BeaconEvent::Attention { attention, .. }
                if attention.kind == AttentionKind::Question
                    && attention.name() == "Root title"
                    && attention.request_id.as_deref() == Some("q")
        ));
        assert!(!format!("{events:?}").contains("must not escape"));
    }

    #[tokio::test]
    async fn live_state_projection_follows_existing_output_and_is_private() {
        let (sender, mut receiver) = mpsc::channel(8);
        let shutdown = CancellationToken::new();
        let cancellation = shutdown.child_token();
        let sink = EventSink { sender, shutdown };
        let mut state = ServerState::default();
        let _ = state.reconcile_with_updates(
            Snapshot {
                sessions: vec![named_session("s")],
                ..Snapshot::default()
            },
            true,
        );
        let instance = instance_key(12);
        assert!(
            handle_live_event(
                &sink,
                &cancellation,
                endpoint(),
                Some(&instance),
                &mut state,
                &question_event(),
            )
            .await
            .is_ok()
        );
        let events = std::iter::from_fn(|| receiver.try_recv().ok()).collect::<Vec<_>>();
        assert!(matches!(events.first(), Some(BeaconEvent::Observed { .. })));
        assert!(matches!(
            events.get(1),
            Some(BeaconEvent::Transition { .. })
        ));
        assert!(matches!(events.get(2), Some(BeaconEvent::Attention { .. })));
        assert!(matches!(
            events.get(3),
            Some(BeaconEvent::StateProjection(projection))
                if projection.instance_key == instance
                    && projection.endpoint == endpoint()
                    && projection.sessions[0].pending_question_ids == ["q"]
        ));
        assert!(!format!("{events:?}").contains("must not escape"));
    }

    #[tokio::test]
    async fn bootstrap_snapshot_orders_initial_transition_then_initial_attention() {
        let (sender, mut receiver) = mpsc::channel(8);
        let shutdown = CancellationToken::new();
        let cancellation = shutdown.child_token();
        let sink = EventSink { sender, shutdown };
        let mut state = ServerConnectionState {
            instance_key: Some(instance_key(11)),
            ..ServerConnectionState::default()
        };
        assert!(
            apply_bootstrap_snapshot_result(
                &sink,
                &cancellation,
                endpoint(),
                &mut state,
                Ok(pending_question_snapshot(SessionStatus::Busy)),
            )
            .await
            .is_ok()
        );
        assert!(matches!(
            receiver.recv().await,
            Some(BeaconEvent::InitialState { .. })
        ));
        assert!(matches!(
            receiver.recv().await,
            Some(BeaconEvent::Transition { transition, .. })
                if transition.current == crate::model::ActivityState::WaitingForInput
        ));
        assert!(matches!(
            receiver.recv().await,
            Some(BeaconEvent::Attention { attention, .. })
                if attention.kind == AttentionKind::Question && attention.initial
        ));
        assert!(matches!(
            receiver.recv().await,
            Some(BeaconEvent::StateProjection(projection))
                if projection.sessions.len() == 1
                    && projection.sessions[0].pending_question_ids == ["q"]
        ));
        assert!(receiver.try_recv().is_err());
    }

    #[tokio::test]
    async fn reconnect_deduplicates_requests_but_replacement_resets_attention_state() {
        let (sender, mut receiver) = mpsc::channel(16);
        let shutdown = CancellationToken::new();
        let cancellation = shutdown.child_token();
        let sink = EventSink { sender, shutdown };
        let mut retained = ServerConnectionState::default();
        for _ in 0..2 {
            assert!(
                apply_bootstrap_snapshot_result(
                    &sink,
                    &cancellation,
                    endpoint(),
                    &mut retained,
                    Ok(pending_question_snapshot(SessionStatus::Idle)),
                )
                .await
                .is_ok()
            );
        }
        let retained_events = std::iter::from_fn(|| receiver.try_recv().ok()).collect::<Vec<_>>();
        assert_eq!(
            retained_events
                .iter()
                .filter(|event| matches!(event, BeaconEvent::Attention { .. }))
                .count(),
            1
        );

        let mut replacement = ServerConnectionState::default();
        assert!(
            apply_bootstrap_snapshot_result(
                &sink,
                &cancellation,
                endpoint(),
                &mut replacement,
                Ok(pending_question_snapshot(SessionStatus::Idle)),
            )
            .await
            .is_ok()
        );
        assert!(std::iter::from_fn(|| receiver.try_recv().ok()).any(
            |event| matches!(event, BeaconEvent::Attention { attention, .. } if attention.initial)
        ));
    }

    #[tokio::test]
    async fn reconnect_retains_ready_arm_while_replacement_starts_unarmed() {
        let (sender, mut receiver) = mpsc::channel(16);
        let shutdown = CancellationToken::new();
        let cancellation = shutdown.child_token();
        let sink = EventSink { sender, shutdown };
        let mut retained = ServerConnectionState::default();
        assert!(
            apply_bootstrap_snapshot_result(
                &sink,
                &cancellation,
                endpoint(),
                &mut retained,
                Ok(Snapshot {
                    sessions: vec![named_session("s")],
                    statuses: HashMap::from([("s".to_owned(), SessionStatus::Busy)]),
                    ..Snapshot::default()
                }),
            )
            .await
            .is_ok()
        );
        while receiver.try_recv().is_ok() {}
        assert!(
            apply_bootstrap_snapshot_result(
                &sink,
                &cancellation,
                endpoint(),
                &mut retained,
                Ok(Snapshot {
                    sessions: vec![named_session("s")],
                    ..Snapshot::default()
                }),
            )
            .await
            .is_ok()
        );
        assert!(std::iter::from_fn(|| receiver.try_recv().ok()).any(
            |event| matches!(event, BeaconEvent::Attention { attention, .. } if attention.kind == AttentionKind::Ready)
        ));

        let mut replacement = ServerConnectionState::default();
        assert!(
            apply_bootstrap_snapshot_result(
                &sink,
                &cancellation,
                endpoint(),
                &mut replacement,
                Ok(Snapshot {
                    sessions: vec![named_session("s")],
                    ..Snapshot::default()
                }),
            )
            .await
            .is_ok()
        );
        assert!(
            std::iter::from_fn(|| receiver.try_recv().ok())
                .all(|event| !matches!(event, BeaconEvent::Attention { .. }))
        );
    }

    #[test]
    fn rejects_zero_durations_and_capacities() {
        let config = MonitorConfig {
            event_capacity: 0,
            ..MonitorConfig::default()
        };
        assert_eq!(
            Monitor::new(config).err(),
            Some(MonitorConfigError::ZeroCapacity {
                field: "event_capacity"
            })
        );

        let config = MonitorConfig {
            client: ClientConfig {
                event_header_timeout: Duration::ZERO,
                ..ClientConfig::default()
            },
            ..MonitorConfig::default()
        };
        assert_eq!(
            Monitor::new(config).err(),
            Some(MonitorConfigError::ZeroDuration {
                field: "event_header_timeout"
            })
        );

        let config = MonitorConfig {
            discovery: DiscoveryConfig {
                probe_concurrency: 0,
                ..DiscoveryConfig::default()
            },
            ..MonitorConfig::default()
        };
        assert_eq!(
            Monitor::new(config).err(),
            Some(MonitorConfigError::ZeroCapacity {
                field: "probe_concurrency"
            })
        );
    }

    #[tokio::test(start_paused = true)]
    async fn stable_gate_skips_full_work_while_manual_disconnect_slow_and_errors_trigger_it() {
        let discovery = Arc::new(ScriptedGateDiscoverer::new(
            ListenerTableFingerprint::default(),
        ));
        let config = MonitorConfig {
            discovery_interval: Duration::from_secs(1),
            full_verification_interval: Duration::from_secs(5 * 60),
            ..MonitorConfig::default()
        };
        let (sender, _receiver) = mpsc::channel(16);
        let shutdown = CancellationToken::new();
        let sink = EventSink {
            sender,
            shutdown: shutdown.clone(),
        };
        let (resync_tx, resync) = watch::channel(0_u64);
        let (discovery_tx, discovery_rx) = watch::channel(0_u64);
        let task_discovery = discovery.clone();
        let task_shutdown = shutdown.clone();
        let task_discovery_tx = discovery_tx.clone();
        let task = tokio::spawn(async move {
            run_discovery_with(
                task_discovery.as_ref(),
                config,
                sink,
                resync,
                task_discovery_tx,
                discovery_rx,
                task_shutdown,
            )
            .await;
        });

        wait_for_full_calls(&discovery, 1).await;
        tokio::time::advance(Duration::from_secs(10)).await;
        tokio::task::yield_now().await;
        assert_eq!(discovery.full_calls.load(Ordering::SeqCst), 1);
        assert!(discovery.gate_calls.load(Ordering::SeqCst) > 0);

        resync_tx.send_replace(1);
        request_discovery(&discovery_tx);
        wait_for_full_calls(&discovery, 2).await;
        tokio::task::yield_now().await;
        assert_eq!(discovery.full_calls.load(Ordering::SeqCst), 2);

        tokio::time::advance(Duration::from_secs(5 * 60 - 10)).await;
        wait_for_full_calls(&discovery, 3).await;

        discovery.push_gate_error("synthetic listener-table failure");
        tokio::time::advance(Duration::from_secs(1)).await;
        wait_for_full_calls(&discovery, 4).await;

        shutdown.cancel();
        assert!(task.await.is_ok());
    }

    #[tokio::test(start_paused = true)]
    async fn listener_changes_run_the_bounded_settling_schedule() {
        let discovery = Arc::new(ScriptedGateDiscoverer::new(
            ListenerTableFingerprint::default(),
        ));
        let config = MonitorConfig {
            discovery_interval: Duration::from_secs(1),
            full_verification_interval: Duration::from_secs(60 * 60),
            ..MonitorConfig::default()
        };
        let (sender, _receiver) = mpsc::channel(16);
        let shutdown = CancellationToken::new();
        let sink = EventSink {
            sender,
            shutdown: shutdown.clone(),
        };
        let (resync_tx, resync) = watch::channel(0_u64);
        let (discovery_tx, discovery_rx) = watch::channel(0_u64);
        let task_discovery_tx = discovery_tx.clone();
        let task_discovery = discovery.clone();
        let task_shutdown = shutdown.clone();
        let task = tokio::spawn(async move {
            run_discovery_with(
                task_discovery.as_ref(),
                config,
                sink,
                resync,
                task_discovery_tx,
                discovery_rx,
                task_shutdown,
            )
            .await;
        });

        wait_for_full_calls(&discovery, 1).await;
        discovery.set_fingerprint(ListenerTableFingerprint::single(endpoint().address(), 42));
        tokio::time::advance(Duration::from_secs(1)).await;
        wait_for_full_calls(&discovery, 2).await;
        resync_tx.send_replace(1);
        request_discovery(&discovery_tx);
        for (advance, expected) in [
            (Duration::from_millis(250), 4),
            (Duration::from_secs(1), 5),
            (Duration::from_secs(3), 6),
        ] {
            tokio::time::advance(advance).await;
            wait_for_full_calls(&discovery, expected).await;
        }
        tokio::time::advance(Duration::from_secs(30)).await;
        tokio::task::yield_now().await;
        assert_eq!(discovery.full_calls.load(Ordering::SeqCst), 6);

        shutdown.cancel();
        assert!(task.await.is_ok());
    }

    #[tokio::test(start_paused = true)]
    async fn listener_before_health_is_found_by_a_coalesced_settling_followup() {
        let initial = ListenerTableFingerprint::default();
        let changed = ListenerTableFingerprint::single(endpoint().address(), 42);
        let discovery = Arc::new(ScriptedGateDiscoverer::new(initial));
        let config = MonitorConfig {
            discovery_interval: Duration::from_secs(1),
            full_verification_interval: Duration::from_secs(60 * 60),
            ..MonitorConfig::default()
        };
        let (sender, mut receiver) = mpsc::channel(32);
        let shutdown = CancellationToken::new();
        let sink = EventSink {
            sender,
            shutdown: shutdown.clone(),
        };
        let (_resync_tx, resync) = watch::channel(0_u64);
        let (discovery_tx, discovery_rx) = watch::channel(0_u64);
        let task_discovery = discovery.clone();
        let task_shutdown = shutdown.clone();
        let task = tokio::spawn(async move {
            run_discovery_with(
                task_discovery.as_ref(),
                config,
                sink,
                resync,
                discovery_tx,
                discovery_rx,
                task_shutdown,
            )
            .await;
        });

        wait_for_full_calls(&discovery, 1).await;
        discovery.set_fingerprint(changed.clone());
        discovery.push_report(DiscoveryReport {
            listener_fingerprint: changed.clone(),
            ..DiscoveryReport::default()
        });
        discovery.push_report(DiscoveryReport {
            listener_fingerprint: changed.clone(),
            ..DiscoveryReport::default()
        });
        discovery.push_report(DiscoveryReport {
            instances: vec![server_instance(42)],
            connections: HashMap::from([(instance_key(42), ConnectionSettings::default())]),
            listener_fingerprint: changed,
            ..DiscoveryReport::default()
        });

        tokio::time::advance(Duration::from_secs(1)).await;
        wait_for_full_calls(&discovery, 2).await;
        tokio::time::advance(Duration::from_millis(250)).await;
        wait_for_full_calls(&discovery, 3).await;
        tokio::time::advance(Duration::from_secs(1)).await;
        wait_for_full_calls(&discovery, 4).await;
        assert!(std::iter::from_fn(|| receiver.try_recv().ok()).any(
            |event| matches!(event, BeaconEvent::ServerFound(instance) if instance.key.socket_inode == 42)
        ));

        shutdown.cancel();
        assert!(task.await.is_ok());
    }

    #[tokio::test(start_paused = true)]
    async fn startup_listener_before_health_arms_settling_followups() {
        let fingerprint = ListenerTableFingerprint::single(endpoint().address(), 42);
        let discovery = Arc::new(ScriptedGateDiscoverer::new(fingerprint.clone()));
        discovery.push_report(DiscoveryReport {
            listener_fingerprint: fingerprint.clone(),
            ..DiscoveryReport::default()
        });
        discovery.push_report(DiscoveryReport {
            instances: vec![server_instance(42)],
            connections: HashMap::from([(instance_key(42), ConnectionSettings::default())]),
            listener_fingerprint: fingerprint,
            ..DiscoveryReport::default()
        });
        let config = MonitorConfig {
            discovery_interval: Duration::from_secs(1),
            full_verification_interval: Duration::from_secs(60 * 60),
            ..MonitorConfig::default()
        };
        let (sender, mut receiver) = mpsc::channel(32);
        let shutdown = CancellationToken::new();
        let sink = EventSink {
            sender,
            shutdown: shutdown.clone(),
        };
        let (_resync_tx, resync) = watch::channel(0_u64);
        let (discovery_tx, discovery_rx) = watch::channel(0_u64);
        let task_discovery = discovery.clone();
        let task_shutdown = shutdown.clone();
        let task = tokio::spawn(async move {
            run_discovery_with(
                task_discovery.as_ref(),
                config,
                sink,
                resync,
                discovery_tx,
                discovery_rx,
                task_shutdown,
            )
            .await;
        });

        wait_for_full_calls(&discovery, 1).await;
        tokio::time::advance(Duration::from_millis(250)).await;
        wait_for_full_calls(&discovery, 2).await;
        assert!(std::iter::from_fn(|| receiver.try_recv().ok()).any(
            |event| matches!(event, BeaconEvent::ServerFound(instance) if instance.key.socket_inode == 42)
        ));

        shutdown.cancel();
        assert!(task.await.is_ok());
    }

    #[tokio::test]
    async fn two_completed_full_misses_remove_a_server_on_the_followup() {
        let instance = server_instance(2);
        let (sender, mut receiver) = mpsc::channel(8);
        let shutdown = CancellationToken::new();
        let sink = EventSink {
            sender,
            shutdown: shutdown.clone(),
        };
        let (_resync_tx, resync) = watch::channel(0_u64);
        let (discovery_tx, _discovery_rx) = watch::channel(0_u64);
        let cancellation = shutdown.child_token();
        let child_cancellation = cancellation.clone();
        let child = tokio::spawn(async move { child_cancellation.cancelled().await });
        let (verification, _verification_rx) = watch::channel(DiscoveryCompletion {
            generation: 1,
            key: Some(instance.key.clone()),
        });
        let mut active = HashMap::from([(
            instance.key.clone(),
            ActiveServer {
                instance: instance.clone(),
                connection: ConnectionSettings::default(),
                misses: 0,
                cancellation,
                verification,
                join: Some(child),
            },
        )]);
        let mut completed_generation = 1;

        for generation in [2, 3] {
            let discovery = ReadyDiscoverer {
                report: Mutex::new(Some(DiscoveryReport::default())),
            };
            assert!(
                discover_once(
                    &discovery,
                    &MonitorConfig::default(),
                    &sink,
                    &resync,
                    &discovery_tx,
                    &shutdown,
                    &mut active,
                    generation,
                    &mut completed_generation,
                )
                .await
                .is_ok()
            );
            if generation == 2 {
                assert_eq!(
                    active.get(&instance.key).map(|server| server.misses),
                    Some(1)
                );
                assert!(receiver.try_recv().is_err());
            }
        }
        assert!(active.is_empty());
        assert_eq!(completed_generation, 3);
        assert!(matches!(
            receiver.recv().await,
            Some(BeaconEvent::ServerRemoved(removed)) if removed == instance
        ));
    }

    #[test]
    fn disconnect_records_generation_and_requests_discovery_atomically() {
        let key = instance_key(2);
        let (_verification_tx, mut verification) = watch::channel(DiscoveryCompletion {
            generation: 7,
            key: Some(key),
        });
        let (discovery, discovery_rx) = watch::channel(0_u64);
        assert_eq!(record_disconnect(&mut verification, &discovery), 7);
        assert!(discovery_rx.has_changed().is_ok_and(|changed| changed));
    }

    #[tokio::test]
    async fn bounded_sink_blocks_in_fifo_order_and_cancellation_releases_it() {
        let (sender, mut receiver) = mpsc::channel(1);
        let shutdown = CancellationToken::new();
        let local = shutdown.child_token();
        let sink = EventSink {
            sender,
            shutdown: shutdown.clone(),
        };
        let first = BeaconEvent::Connected(endpoint());
        assert!(sink.send(&local, first).await.is_ok());

        let blocked_sink = sink.clone();
        let blocked_local = local.clone();
        let blocked = tokio::spawn(async move {
            blocked_sink
                .send(&blocked_local, BeaconEvent::Connected(endpoint()))
                .await
        });
        tokio::time::sleep(Duration::from_millis(10)).await;
        assert!(!blocked.is_finished());
        let next_event = receiver.recv().await;
        assert!(matches!(next_event, Some(BeaconEvent::Connected(_))));
        assert!(blocked.await.is_ok_and(|result| result.is_ok()));
        let next_event = receiver.recv().await;
        assert!(matches!(next_event, Some(BeaconEvent::Connected(_))));

        assert!(
            sink.send(&local, BeaconEvent::Connected(endpoint()))
                .await
                .is_ok()
        );
        let blocked_sink = sink.clone();
        let blocked_local = local.clone();
        let blocked = tokio::spawn(async move {
            blocked_sink
                .send(&blocked_local, BeaconEvent::Connected(endpoint()))
                .await
        });
        local.cancel();
        assert!(blocked.await.is_ok_and(|result| result == Err(EmitStopped)));
    }

    #[tokio::test]
    async fn receiver_closure_stops_all_producers() {
        let (sender, receiver) = mpsc::channel(1);
        let shutdown = CancellationToken::new();
        let local = shutdown.child_token();
        let sink = EventSink {
            sender,
            shutdown: shutdown.clone(),
        };
        drop(receiver);
        assert_eq!(
            sink.send(&local, BeaconEvent::Connected(endpoint())).await,
            Err(EmitStopped)
        );
        assert!(shutdown.is_cancelled());
    }

    #[tokio::test]
    async fn idle_receiver_closure_is_observable_without_an_event_send() {
        let (sender, receiver) = mpsc::channel(1);
        let shutdown = CancellationToken::new();
        let sink = EventSink {
            sender,
            shutdown: shutdown.clone(),
        };
        let watcher = tokio::spawn(async move {
            sink.sender.closed().await;
            sink.shutdown.cancel();
        });
        drop(receiver);
        assert!(watcher.await.is_ok());
        assert!(shutdown.is_cancelled());
    }

    #[tokio::test]
    async fn cancellation_interrupts_event_header_wait() {
        let client = PendingHeaderClient {
            endpoint: endpoint(),
        };
        let (sender, _receiver) = mpsc::channel(1);
        let shutdown = CancellationToken::new();
        let cancellation = shutdown.child_token();
        let sink = EventSink {
            sender,
            shutdown: shutdown.clone(),
        };
        let task_cancellation = cancellation.clone();
        let task = tokio::spawn(async move {
            let mut state = ServerConnectionState::default();
            bootstrap_connection(&client, &sink, &task_cancellation, &mut state).await
        });
        tokio::task::yield_now().await;
        cancellation.cancel();
        assert!(
            task.await
                .is_ok_and(|result| result.is_ok_and(|value| value.is_none()))
        );
    }

    #[tokio::test]
    async fn cancellation_interrupts_pending_bootstrap_snapshot() {
        let client = PendingSnapshotClient {
            endpoint: endpoint(),
            stream: Mutex::new(Some(Box::pin(stream::pending()))),
        };
        let (sender, mut receiver) = mpsc::channel(4);
        let shutdown = CancellationToken::new();
        let cancellation = shutdown.child_token();
        let sink = EventSink {
            sender,
            shutdown: shutdown.clone(),
        };
        let task_cancellation = cancellation.clone();
        let task = tokio::spawn(async move {
            let mut state = ServerConnectionState::default();
            bootstrap_connection(&client, &sink, &task_cancellation, &mut state).await
        });
        let connected = receiver.recv().await;
        assert!(matches!(connected, Some(BeaconEvent::Connected(_))));
        cancellation.cancel();
        assert!(
            task.await
                .is_ok_and(|result| result.is_ok_and(|value| value.is_none()))
        );
        assert!(receiver.try_recv().is_err());
    }

    #[tokio::test]
    async fn cancellation_discards_pending_discovery_without_verification() {
        let (sender, mut receiver) = mpsc::channel(4);
        let shutdown = CancellationToken::new();
        let sink = EventSink {
            sender,
            shutdown: shutdown.clone(),
        };
        let (resync_tx, resync) = watch::channel(0_u64);
        let (discovery_tx, _discovery_rx) = watch::channel(0_u64);
        let (verification, mut verification_rx) = watch::channel(DiscoveryCompletion {
            generation: 0,
            key: None,
        });
        let child = tokio::spawn(pending::<()>());
        let mut active = HashMap::from([(
            instance_key(2),
            ActiveServer {
                instance: server_instance(2),
                connection: ConnectionSettings::default(),
                misses: 0,
                cancellation: shutdown.child_token(),
                verification,
                join: Some(child),
            },
        )]);
        let config = MonitorConfig::default();
        let task_shutdown = shutdown.clone();
        let task_sink = sink.clone();
        let task = tokio::spawn(async move {
            let mut completed_generation = 0;
            let result = discover_once(
                &PendingDiscoverer,
                &config,
                &task_sink,
                &resync,
                &discovery_tx,
                &task_shutdown,
                &mut active,
                1,
                &mut completed_generation,
            )
            .await;
            drop(resync_tx);
            result
        });
        tokio::task::yield_now().await;
        shutdown.cancel();
        assert!(task.await.is_ok_and(|result| result == Err(EmitStopped)));
        assert!(receiver.try_recv().is_err());
        assert_eq!(verification_rx.borrow_and_update().generation, 0);
        assert!(verification_rx.borrow().key.is_none());
    }

    #[tokio::test]
    async fn full_bootstrap_buffer_pauses_stream_and_replays_fifo() {
        let event_stream = stream::iter(
            (0..BOOTSTRAP_EVENT_CAPACITY + 2).map(|number| Ok(sourced(numbered_event(number), 64))),
        )
        .chain(stream::pending());
        let client = ScriptedClient {
            endpoint: endpoint(),
            snapshots: Mutex::new(VecDeque::from([(
                Duration::from_millis(100),
                Ok(Snapshot::default()),
            )])),
            stream: Mutex::new(Some(Box::pin(event_stream))),
        };
        let (sender, mut receiver) = mpsc::channel(BOOTSTRAP_EVENT_CAPACITY + 4);
        let shutdown = CancellationToken::new();
        let cancellation = shutdown.child_token();
        let sink = EventSink { sender, shutdown };
        let mut state = ServerConnectionState::default();
        let result = bootstrap_connection(&client, &sink, &cancellation, &mut state).await;
        assert!(result.is_ok());
        let (mut remaining_stream, _) = result
            .unwrap_or_else(|error| unreachable!("bootstrap succeeds: {error}"))
            .unwrap_or_else(|| unreachable!("bootstrap was not cancelled"));

        let mut replayed = Vec::new();
        while let Ok(event) = receiver.try_recv() {
            if let BeaconEvent::Observed { event, .. } = event
                && let Some(request_id) = event.request_id
            {
                replayed.push(request_id);
            }
        }
        let expected = (0..BOOTSTRAP_EVENT_CAPACITY)
            .map(|number| number.to_string())
            .collect::<Vec<_>>();
        assert_eq!(replayed, expected);

        let next_expected = BOOTSTRAP_EVENT_CAPACITY.to_string();
        let next = remaining_stream.next().await;
        assert!(next.is_some_and(|event| {
            event.is_ok_and(|event| {
                event.event.properties["id"].as_str() == Some(next_expected.as_str())
            })
        }));
        let next_expected = (BOOTSTRAP_EVENT_CAPACITY + 1).to_string();
        let next = remaining_stream.next().await;
        assert!(next.is_some_and(|event| {
            event.is_ok_and(|event| {
                event.event.properties["id"].as_str() == Some(next_expected.as_str())
            })
        }));
    }

    #[tokio::test]
    async fn bootstrap_byte_budget_allows_one_polled_frame_beyond_threshold() {
        let large = 5 * 1024 * 1024;
        let event_stream = stream::iter([
            Ok(sourced(numbered_event(0), large)),
            Ok(sourced(numbered_event(1), large)),
            Ok(sourced(numbered_event(2), large)),
        ])
        .chain(stream::pending());
        let client = ScriptedClient {
            endpoint: endpoint(),
            snapshots: Mutex::new(VecDeque::from([(
                Duration::from_millis(50),
                Ok(Snapshot::default()),
            )])),
            stream: Mutex::new(Some(Box::pin(event_stream))),
        };
        let (sender, mut receiver) = mpsc::channel(8);
        let shutdown = CancellationToken::new();
        let cancellation = shutdown.child_token();
        let sink = EventSink { sender, shutdown };
        let mut state = ServerConnectionState::default();
        let result = bootstrap_connection(&client, &sink, &cancellation, &mut state).await;
        assert!(result.is_ok());
        let (mut remaining_stream, _) = result
            .unwrap_or_else(|error| unreachable!("bootstrap succeeds: {error}"))
            .unwrap_or_else(|| unreachable!("bootstrap was not cancelled"));
        let observed = std::iter::from_fn(|| receiver.try_recv().ok())
            .filter(|event| matches!(event, BeaconEvent::Observed { .. }))
            .count();
        assert_eq!(observed, 2);
        let next = remaining_stream.next().await;
        assert!(
            next.is_some_and(|event| {
                event.is_ok_and(|event| event.event.properties["id"] == "2")
            })
        );
    }

    #[tokio::test]
    async fn bootstrap_replays_valid_frames_before_eof_or_error() {
        for event_stream in [
            Box::pin(stream::iter([Ok(sourced(busy_event(), 64))])) as SourceEventStream,
            Box::pin(stream::iter([
                Ok(sourced(busy_event(), 64)),
                Err(crate::client::ClientError::SseFrameTooLarge),
            ])) as SourceEventStream,
        ] {
            let client = ScriptedClient {
                endpoint: endpoint(),
                snapshots: Mutex::new(VecDeque::from([(
                    Duration::from_secs(60),
                    Ok(Snapshot::default()),
                )])),
                stream: Mutex::new(Some(event_stream)),
            };
            let (sender, mut receiver) = mpsc::channel(8);
            let shutdown = CancellationToken::new();
            let cancellation = shutdown.child_token();
            let sink = EventSink { sender, shutdown };
            let mut state = ServerConnectionState::default();
            let result = bootstrap_connection(&client, &sink, &cancellation, &mut state).await;
            assert!(result.is_err());
            assert_eq!(state.reducer.active_session_count(), 1);
            let events = std::iter::from_fn(|| receiver.try_recv().ok()).collect::<Vec<_>>();
            assert!(matches!(events.first(), Some(BeaconEvent::Connected(_))));
            assert!(matches!(events.get(1), Some(BeaconEvent::Observed { .. })));
            assert!(matches!(
                events.get(2),
                Some(BeaconEvent::Transition { transition, .. })
                    if transition.current == crate::model::ActivityState::Working
            ));
            assert!(
                !events
                    .iter()
                    .any(|event| matches!(event, BeaconEvent::InitialState { .. }))
            );
        }
    }

    #[tokio::test]
    async fn reconciliation_applies_live_then_emits_only_net_correction() {
        let event_stream = stream::iter([Ok(sourced(busy_event(), 64))]).chain(stream::pending());
        let client = ScriptedClient {
            endpoint: endpoint(),
            snapshots: Mutex::new(VecDeque::from([(
                Duration::from_millis(30),
                Ok(Snapshot {
                    sessions: vec![Session {
                        id: "s".to_owned(),
                        ..Session::default()
                    }],
                    statuses: HashMap::new(),
                    permissions: Vec::new(),
                    questions: Vec::new(),
                }),
            )])),
            stream: Mutex::new(None),
        };
        let (sender, mut receiver) = mpsc::channel(16);
        let shutdown = CancellationToken::new();
        let cancellation = shutdown.child_token();
        let sink = EventSink { sender, shutdown };
        let mut state = ServerConnectionState {
            initialized: true,
            ..ServerConnectionState::default()
        };
        let _ = state.reducer.reconcile(Snapshot {
            sessions: vec![Session {
                id: "s".to_owned(),
                ..Session::default()
            }],
            statuses: HashMap::new(),
            permissions: Vec::new(),
            questions: Vec::new(),
        });
        let mut event_stream: SourceEventStream = Box::pin(event_stream);
        let mut periodic = tokio::time::interval(Duration::from_secs(60));
        periodic.tick().await;
        let (_resync_tx, mut resync) = watch::channel(0_u64);
        let mut coalesced = None;
        let outcome = reconcile_in_flight(
            &client,
            &sink,
            &cancellation,
            &mut state,
            &mut event_stream,
            &mut periodic,
            &mut resync,
            &mut coalesced,
            Duration::from_millis(5),
        )
        .await;
        assert!(outcome.is_ok());
        let (snapshot, journal, rerun) = outcome
            .unwrap_or_else(|error| unreachable!("reconciliation runs: {error}"))
            .unwrap_or_else(|| unreachable!("reconciliation was not cancelled"));
        assert!(rerun);
        assert_eq!(journal.events.len(), 1);
        let live_events = std::iter::from_fn(|| receiver.try_recv().ok()).collect::<Vec<_>>();
        assert!(live_events.iter().any(|event| matches!(
            event,
            BeaconEvent::Transition { transition, .. }
                if transition.source == crate::model::TransitionSource::Live
                    && transition.current == crate::model::ActivityState::Working
        )));
        assert!(
            apply_reconciliation_result(
                &sink,
                &cancellation,
                endpoint(),
                &mut state,
                snapshot,
                journal,
            )
            .await
            .is_ok()
        );
        assert!(receiver.try_recv().is_err());
        assert_eq!(state.reducer.active_session_count(), 1);
    }

    #[tokio::test]
    async fn snapshot_and_sse_overlap_emits_request_attention_once() {
        let event_stream =
            stream::iter([Ok(sourced(question_event(), 64))]).chain(stream::pending());
        let client = ScriptedClient {
            endpoint: endpoint(),
            snapshots: Mutex::new(VecDeque::from([(
                Duration::from_millis(30),
                Ok(pending_question_snapshot(SessionStatus::Idle)),
            )])),
            stream: Mutex::new(None),
        };
        let (sender, mut receiver) = mpsc::channel(16);
        let shutdown = CancellationToken::new();
        let cancellation = shutdown.child_token();
        let sink = EventSink { sender, shutdown };
        let mut state = ServerConnectionState {
            initialized: true,
            ..ServerConnectionState::default()
        };
        let _ = state.reducer.reconcile_with_updates(
            Snapshot {
                sessions: vec![named_session("s")],
                ..Snapshot::default()
            },
            true,
        );
        let mut event_stream: SourceEventStream = Box::pin(event_stream);
        let mut periodic = tokio::time::interval(Duration::from_secs(60));
        periodic.tick().await;
        let (_resync_tx, mut resync) = watch::channel(0_u64);
        let mut coalesced = None;
        let (snapshot, journal, _) = reconcile_in_flight(
            &client,
            &sink,
            &cancellation,
            &mut state,
            &mut event_stream,
            &mut periodic,
            &mut resync,
            &mut coalesced,
            Duration::from_millis(5),
        )
        .await
        .unwrap_or_else(|error| unreachable!("reconciliation runs: {error}"))
        .unwrap_or_else(|| unreachable!("reconciliation was not cancelled"));
        assert_eq!(journal.events.len(), 1);
        let live = std::iter::from_fn(|| receiver.try_recv().ok()).collect::<Vec<_>>();
        assert_eq!(
            live.iter()
                .filter(|event| matches!(event, BeaconEvent::Attention { .. }))
                .count(),
            1
        );
        assert!(
            apply_reconciliation_result(
                &sink,
                &cancellation,
                endpoint(),
                &mut state,
                snapshot,
                journal,
            )
            .await
            .is_ok()
        );
        assert!(receiver.try_recv().is_err());
    }

    #[tokio::test]
    async fn reconciliation_drains_ready_same_chunk_frames_before_ready_snapshot() {
        let client = ReadySnapshotClient {
            endpoint: endpoint(),
            snapshot: Mutex::new(Some(Ok(busy_snapshot()))),
        };
        let mut event_stream: SourceEventStream = Box::pin(
            stream::iter([Ok(sourced(busy_event(), 64)), Ok(sourced(idle_event(), 64))])
                .chain(stream::pending()),
        );
        let (sender, mut receiver) = mpsc::channel(16);
        let shutdown = CancellationToken::new();
        let cancellation = shutdown.child_token();
        let sink = EventSink { sender, shutdown };
        let mut state = ServerConnectionState {
            initialized: true,
            ..ServerConnectionState::default()
        };
        let mut periodic = tokio::time::interval(Duration::from_secs(60));
        periodic.tick().await;
        let (_resync_tx, mut resync) = watch::channel(0_u64);
        let mut coalesced = None;

        let (snapshot, journal, _) = reconcile_in_flight(
            &client,
            &sink,
            &cancellation,
            &mut state,
            &mut event_stream,
            &mut periodic,
            &mut resync,
            &mut coalesced,
            Duration::from_secs(1),
        )
        .await
        .unwrap_or_else(|error| unreachable!("reconciliation runs: {error}"))
        .unwrap_or_else(|| unreachable!("reconciliation was not cancelled"));
        assert_eq!(journal.events.len(), 2);
        assert_eq!(journal.events[0].event.properties["status"]["type"], "busy");
        assert_eq!(journal.events[1].event.properties["status"]["type"], "idle");

        let live = std::iter::from_fn(|| receiver.try_recv().ok()).collect::<Vec<_>>();
        assert_eq!(
            live.iter()
                .filter(|event| matches!(event, BeaconEvent::Transition { .. }))
                .count(),
            2
        );
        assert!(live.iter().all(|event| !matches!(
            event,
            BeaconEvent::Transition { transition, .. }
                if transition.source == crate::model::TransitionSource::Snapshot
        )));
        assert!(
            apply_reconciliation_result(
                &sink,
                &cancellation,
                endpoint(),
                &mut state,
                snapshot,
                journal,
            )
            .await
            .is_ok()
        );
        assert!(matches!(
            receiver.try_recv(),
            Ok(BeaconEvent::Attention { attention, .. })
                if attention.kind == AttentionKind::Ready
                    && attention.source == crate::model::TransitionSource::Snapshot
        ));
        assert!(receiver.try_recv().is_err());
        assert_eq!(state.reducer.active_session_count(), 0);
    }

    #[tokio::test]
    async fn snapshot_completion_drains_simultaneously_ready_triggers_once() {
        let client = ReadySnapshotClient {
            endpoint: endpoint(),
            snapshot: Mutex::new(Some(Ok(Snapshot::default()))),
        };
        let mut event_stream: SourceEventStream = Box::pin(stream::pending());
        let (sender, _receiver) = mpsc::channel(4);
        let shutdown = CancellationToken::new();
        let cancellation = shutdown.child_token();
        let sink = EventSink { sender, shutdown };
        let mut state = ServerConnectionState::default();
        let mut periodic = tokio::time::interval(Duration::from_secs(60));
        let (resync_tx, mut resync) = watch::channel(0_u64);
        resync_tx.send_replace(1);
        let mut coalesced = Some(Box::pin(tokio::time::sleep(Duration::ZERO)) as Pin<Box<Sleep>>);
        tokio::task::yield_now().await;

        let (_, _, rerun) = reconcile_in_flight(
            &client,
            &sink,
            &cancellation,
            &mut state,
            &mut event_stream,
            &mut periodic,
            &mut resync,
            &mut coalesced,
            Duration::from_secs(1),
        )
        .await
        .unwrap_or_else(|error| unreachable!("reconciliation runs: {error}"))
        .unwrap_or_else(|| unreachable!("reconciliation was not cancelled"));
        assert!(rerun);
        assert_eq!(
            drain_ready_reconciliation_triggers(&mut periodic, &mut resync, &mut coalesced,),
            Some(false)
        );
    }

    #[tokio::test]
    async fn ready_snapshot_is_not_starved_by_continuously_ready_stream() {
        let client = ReadySnapshotClient {
            endpoint: endpoint(),
            snapshot: Mutex::new(Some(Ok(busy_snapshot()))),
        };
        let mut event_stream: SourceEventStream =
            Box::pin(stream::repeat(sourced(numbered_event(0), 64)).map(Ok));
        let (sender, _receiver) = mpsc::channel(BOOTSTRAP_EVENT_CAPACITY + 2);
        let shutdown = CancellationToken::new();
        let cancellation = shutdown.child_token();
        let sink = EventSink { sender, shutdown };
        let mut state = ServerConnectionState::default();
        let mut periodic = tokio::time::interval(Duration::from_secs(60));
        periodic.tick().await;
        let (_resync_tx, mut resync) = watch::channel(0_u64);
        let mut coalesced = None;

        let outcome = tokio::time::timeout(
            Duration::from_secs(1),
            reconcile_in_flight(
                &client,
                &sink,
                &cancellation,
                &mut state,
                &mut event_stream,
                &mut periodic,
                &mut resync,
                &mut coalesced,
                Duration::from_secs(1),
            ),
        )
        .await;
        assert!(outcome.is_ok());
        let (_, journal, _) = outcome
            .unwrap_or_else(|_| unreachable!("ready snapshot completes within the drain bound"))
            .unwrap_or_else(|error| unreachable!("reconciliation runs: {error}"))
            .unwrap_or_else(|| unreachable!("reconciliation was not cancelled"));
        assert!(journal.events.is_empty());
    }

    #[tokio::test]
    async fn cancellation_wins_over_ready_stream_and_snapshot() {
        let client = ReadySnapshotClient {
            endpoint: endpoint(),
            snapshot: Mutex::new(Some(Ok(busy_snapshot()))),
        };
        let mut event_stream: SourceEventStream =
            Box::pin(stream::repeat(sourced(busy_event(), 64)).map(Ok));
        let (sender, mut receiver) = mpsc::channel(4);
        let shutdown = CancellationToken::new();
        let cancellation = shutdown.child_token();
        cancellation.cancel();
        let sink = EventSink { sender, shutdown };
        let mut state = ServerConnectionState::default();
        let mut periodic = tokio::time::interval(Duration::from_secs(60));
        periodic.tick().await;
        let (_resync_tx, mut resync) = watch::channel(0_u64);
        let mut coalesced = None;

        let outcome = reconcile_in_flight(
            &client,
            &sink,
            &cancellation,
            &mut state,
            &mut event_stream,
            &mut periodic,
            &mut resync,
            &mut coalesced,
            Duration::from_secs(1),
        )
        .await;
        assert!(outcome.is_ok_and(|outcome| outcome.is_none()));
        assert!(receiver.try_recv().is_err());
    }

    #[tokio::test]
    async fn reconciliation_byte_budget_pauses_sse_after_one_overage() {
        let large = 5 * 1024 * 1024;
        let event_stream = stream::iter([
            Ok(sourced(busy_event(), large)),
            Ok(sourced(busy_event(), large)),
            Ok(sourced(busy_event(), large)),
        ])
        .chain(stream::pending());
        let client = ScriptedClient {
            endpoint: endpoint(),
            snapshots: Mutex::new(VecDeque::from([(
                Duration::from_millis(50),
                Ok(busy_snapshot()),
            )])),
            stream: Mutex::new(None),
        };
        let (sender, _receiver) = mpsc::channel(16);
        let shutdown = CancellationToken::new();
        let cancellation = shutdown.child_token();
        let sink = EventSink { sender, shutdown };
        let mut state = ServerConnectionState::default();
        let mut event_stream: SourceEventStream = Box::pin(event_stream);
        let mut periodic = tokio::time::interval(Duration::from_secs(60));
        periodic.tick().await;
        let (_resync_tx, mut resync) = watch::channel(0_u64);
        let mut coalesced = None;
        let outcome = reconcile_in_flight(
            &client,
            &sink,
            &cancellation,
            &mut state,
            &mut event_stream,
            &mut periodic,
            &mut resync,
            &mut coalesced,
            Duration::from_secs(1),
        )
        .await;
        assert!(outcome.is_ok());
        let (_, journal, _) = outcome
            .unwrap_or_else(|error| unreachable!("reconciliation runs: {error}"))
            .unwrap_or_else(|| unreachable!("reconciliation was not cancelled"));
        assert_eq!(journal.events.len(), 2);
        assert_eq!(journal.source_bytes, 2 * large);
        assert!(event_stream.next().await.is_some());
    }

    #[tokio::test]
    async fn reconciliation_event_capacity_pauses_sse_and_preserves_fifo() {
        let event_stream = stream::iter((0..=BOOTSTRAP_EVENT_CAPACITY).map(|number| {
            let mut event = busy_event();
            event.properties["sequence"] = json!(number);
            Ok(sourced(event, 64))
        }))
        .chain(stream::pending());
        let client = ScriptedClient {
            endpoint: endpoint(),
            snapshots: Mutex::new(VecDeque::from([(
                Duration::from_secs(1),
                Ok(busy_snapshot()),
            )])),
            stream: Mutex::new(None),
        };
        let (sender, _receiver) = mpsc::channel(BOOTSTRAP_EVENT_CAPACITY + 2);
        let shutdown = CancellationToken::new();
        let cancellation = shutdown.child_token();
        let sink = EventSink { sender, shutdown };
        let mut state = ServerConnectionState::default();
        let mut event_stream: SourceEventStream = Box::pin(event_stream);
        let mut periodic = tokio::time::interval(Duration::from_secs(60));
        periodic.tick().await;
        let (_resync_tx, mut resync) = watch::channel(0_u64);
        let mut coalesced = None;
        let outcome = reconcile_in_flight(
            &client,
            &sink,
            &cancellation,
            &mut state,
            &mut event_stream,
            &mut periodic,
            &mut resync,
            &mut coalesced,
            Duration::from_secs(1),
        )
        .await;
        assert!(outcome.is_ok());
        let (_, journal, _) = outcome
            .unwrap_or_else(|error| unreachable!("reconciliation runs: {error}"))
            .unwrap_or_else(|| unreachable!("reconciliation was not cancelled"));
        assert_eq!(journal.events.len(), BOOTSTRAP_EVENT_CAPACITY);
        assert!(journal.events.iter().enumerate().all(|(number, event)| {
            event.event.properties["sequence"].as_u64() == Some(number as u64)
        }));
        assert!(event_stream.next().await.is_some_and(|event| {
            event.is_ok_and(|event| {
                event.event.properties["sequence"].as_u64() == Some(BOOTSTRAP_EVENT_CAPACITY as u64)
            })
        }));
    }

    #[tokio::test]
    async fn failed_reconciliation_keeps_live_state_and_discards_journal() {
        let event_stream = stream::iter([Ok(sourced(busy_event(), 64))]).chain(stream::pending());
        let client = ScriptedClient {
            endpoint: endpoint(),
            snapshots: Mutex::new(VecDeque::from([(
                Duration::from_millis(20),
                Err("snapshot unavailable".to_owned()),
            )])),
            stream: Mutex::new(None),
        };
        let (sender, mut receiver) = mpsc::channel(8);
        let shutdown = CancellationToken::new();
        let cancellation = shutdown.child_token();
        let sink = EventSink { sender, shutdown };
        let mut state = ServerConnectionState {
            initialized: true,
            ..ServerConnectionState::default()
        };
        let mut event_stream: SourceEventStream = Box::pin(event_stream);
        let mut periodic = tokio::time::interval(Duration::from_secs(60));
        periodic.tick().await;
        let (_resync_tx, mut resync) = watch::channel(0_u64);
        let mut coalesced = None;
        let (snapshot, journal, _) = reconcile_in_flight(
            &client,
            &sink,
            &cancellation,
            &mut state,
            &mut event_stream,
            &mut periodic,
            &mut resync,
            &mut coalesced,
            Duration::from_secs(1),
        )
        .await
        .unwrap_or_else(|error| unreachable!("reconciliation runs: {error}"))
        .unwrap_or_else(|| unreachable!("reconciliation was not cancelled"));
        assert_eq!(journal.events.len(), 1);
        assert_eq!(state.reducer.active_session_count(), 1);
        assert!(
            apply_reconciliation_result(
                &sink,
                &cancellation,
                endpoint(),
                &mut state,
                snapshot,
                journal,
            )
            .await
            .is_ok()
        );
        assert_eq!(state.reducer.active_session_count(), 1);
        assert!(std::iter::from_fn(|| receiver.try_recv().ok()).any(|event| {
            matches!(event, BeaconEvent::Diagnostic { message, .. } if message.contains("snapshot unavailable"))
        }));
    }

    #[tokio::test]
    async fn cancellation_interrupts_normal_snapshot_wait() {
        let client = PendingHeaderClient {
            endpoint: endpoint(),
        };
        let (sender, _receiver) = mpsc::channel(4);
        let shutdown = CancellationToken::new();
        let cancellation = shutdown.child_token();
        let sink = EventSink {
            sender,
            shutdown: shutdown.clone(),
        };
        let task_cancellation = cancellation.clone();
        let task = tokio::spawn(async move {
            let mut state = ServerConnectionState::default();
            let mut event_stream: SourceEventStream = Box::pin(stream::pending());
            let mut periodic = tokio::time::interval(Duration::from_secs(60));
            periodic.tick().await;
            let (_resync_tx, mut resync) = watch::channel(0_u64);
            let mut coalesced = None;
            reconcile_in_flight(
                &client,
                &sink,
                &task_cancellation,
                &mut state,
                &mut event_stream,
                &mut periodic,
                &mut resync,
                &mut coalesced,
                Duration::from_millis(5),
            )
            .await
        });
        tokio::task::yield_now().await;
        cancellation.cancel();
        assert!(
            task.await
                .is_ok_and(|result| result.is_ok_and(|outcome| outcome.is_none()))
        );
    }

    #[tokio::test]
    async fn receiver_closure_interrupts_pending_snapshot_without_publication() {
        let client = PendingSnapshotClient {
            endpoint: endpoint(),
            stream: Mutex::new(Some(Box::pin(stream::pending()))),
        };
        let (sender, mut receiver) = mpsc::channel(1);
        let shutdown = CancellationToken::new();
        let cancellation = shutdown.child_token();
        let sink = EventSink {
            sender,
            shutdown: shutdown.clone(),
        };
        let task_cancellation = cancellation.clone();
        let task = tokio::spawn(async move {
            let mut state = ServerConnectionState::default();
            bootstrap_connection(&client, &sink, &task_cancellation, &mut state).await
        });
        assert!(matches!(
            receiver.recv().await,
            Some(BeaconEvent::Connected(_))
        ));
        drop(receiver);
        assert!(
            task.await
                .is_ok_and(|result| result.is_ok_and(|value| value.is_none()))
        );
        assert!(shutdown.is_cancelled());
    }

    #[tokio::test]
    async fn reconnect_backoff_resets_only_after_successful_bootstrap_snapshot() {
        let (sender, _receiver) = mpsc::channel(16);
        let shutdown = CancellationToken::new();
        let cancellation = shutdown.child_token();
        let sink = EventSink { sender, shutdown };
        let mut state = ServerConnectionState {
            reconnect_attempt: 3,
            ..ServerConnectionState::default()
        };

        for _ in 0..2 {
            let header_close = ScriptedClient {
                endpoint: endpoint(),
                snapshots: Mutex::new(VecDeque::from([(
                    Duration::from_secs(1),
                    Ok(Snapshot::default()),
                )])),
                stream: Mutex::new(Some(Box::pin(stream::empty()))),
            };
            assert!(
                bootstrap_connection(&header_close, &sink, &cancellation, &mut state)
                    .await
                    .is_err()
            );
            assert_eq!(state.reconnect_attempt, 3);
        }

        for _ in 0..2 {
            let failed_snapshot = ScriptedClient {
                endpoint: endpoint(),
                snapshots: Mutex::new(VecDeque::from([(
                    Duration::ZERO,
                    Err("snapshot failed".to_owned()),
                )])),
                stream: Mutex::new(Some(Box::pin(stream::pending()))),
            };
            assert!(
                bootstrap_connection(&failed_snapshot, &sink, &cancellation, &mut state)
                    .await
                    .is_ok()
            );
            assert_eq!(state.reconnect_attempt, 3);
        }

        assert!(
            apply_reconciliation_result(
                &sink,
                &cancellation,
                endpoint(),
                &mut state,
                Ok(Snapshot::default()),
                EventJournal::default(),
            )
            .await
            .is_ok()
        );
        assert_eq!(state.reconnect_attempt, 3);

        let successful_snapshot = ScriptedClient {
            endpoint: endpoint(),
            snapshots: Mutex::new(VecDeque::from([(Duration::ZERO, Ok(Snapshot::default()))])),
            stream: Mutex::new(Some(Box::pin(stream::pending()))),
        };
        assert!(
            bootstrap_connection(&successful_snapshot, &sink, &cancellation, &mut state)
                .await
                .is_ok()
        );
        assert_eq!(state.reconnect_attempt, 0);
    }

    #[tokio::test]
    async fn every_reconnect_requires_post_disconnect_exact_instance_verification() {
        let expected_key = instance_key(2);
        let wrong_key = instance_key(4);
        let (verification, mut verification_rx) = watch::channel(DiscoveryCompletion {
            generation: 3,
            key: Some(expected_key.clone()),
        });
        let shutdown = CancellationToken::new();
        let cancellation = shutdown.child_token();
        let task_shutdown = shutdown.clone();
        let task_cancellation = cancellation.clone();
        let task_key = expected_key.clone();
        let task = tokio::spawn(async move {
            wait_to_reconnect(
                &task_key,
                4,
                &mut verification_rx,
                &task_shutdown,
                &task_cancellation,
                0,
            )
            .await
        });
        tokio::time::sleep(Duration::from_millis(10)).await;
        assert!(!task.is_finished());
        verification.send_replace(DiscoveryCompletion {
            generation: 4,
            key: Some(expected_key.clone()),
        });
        tokio::time::sleep(Duration::from_millis(10)).await;
        assert!(!task.is_finished());
        verification.send_replace(DiscoveryCompletion {
            generation: 5,
            key: Some(wrong_key),
        });
        tokio::time::sleep(Duration::from_millis(1_300)).await;
        assert!(!task.is_finished());
        verification.send_replace(DiscoveryCompletion {
            generation: 5,
            key: Some(expected_key),
        });
        assert!(
            tokio::time::timeout(Duration::from_secs(2), task)
                .await
                .is_ok_and(|result| result.is_ok_and(|allowed| allowed))
        );
    }

    #[tokio::test]
    async fn reconnect_accepts_newer_completion_before_waiter_starts() {
        let expected_key = instance_key(2);
        let (_verification, mut verification_rx) = watch::channel(DiscoveryCompletion {
            generation: 5,
            key: Some(expected_key.clone()),
        });
        let shutdown = CancellationToken::new();
        let cancellation = shutdown.child_token();
        assert!(
            wait_to_reconnect(
                &expected_key,
                4,
                &mut verification_rx,
                &shutdown,
                &cancellation,
                0,
            )
            .await
        );
    }

    #[tokio::test]
    async fn reconnect_rejects_verification_closure_and_cancellation() {
        let (verification, mut verification_rx) = watch::channel(DiscoveryCompletion {
            generation: 0,
            key: None,
        });
        let shutdown = CancellationToken::new();
        let cancellation = shutdown.child_token();
        drop(verification);
        assert!(
            !wait_to_reconnect(
                &instance_key(2),
                1,
                &mut verification_rx,
                &shutdown,
                &cancellation,
                0,
            )
            .await
        );

        let (_verification, mut verification_rx) = watch::channel(DiscoveryCompletion {
            generation: 0,
            key: None,
        });
        let cancellation = shutdown.child_token();
        cancellation.cancel();
        assert!(
            !wait_to_reconnect(
                &instance_key(2),
                1,
                &mut verification_rx,
                &shutdown,
                &cancellation,
                0,
            )
            .await
        );
    }

    #[tokio::test]
    async fn reconnect_never_uses_a_cached_endpoint_without_fresh_discovery() {
        let key = instance_key(2);
        let (verification, mut verification_rx) = watch::channel(DiscoveryCompletion {
            generation: 1,
            key: Some(key.clone()),
        });
        let shutdown = CancellationToken::new();
        let cancellation = shutdown.child_token();
        let waiter_shutdown = shutdown.clone();
        let waiter_cancellation = cancellation.clone();
        let waiter_key = key.clone();
        let waiter = tokio::spawn(async move {
            wait_to_reconnect(
                &waiter_key,
                1,
                &mut verification_rx,
                &waiter_shutdown,
                &waiter_cancellation,
                0,
            )
            .await
        });
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(!waiter.is_finished());
        verification.send_replace(DiscoveryCompletion {
            generation: 2,
            key: Some(instance_key(3)),
        });
        tokio::time::sleep(Duration::from_millis(1_300)).await;
        assert!(!waiter.is_finished());
        verification.send_replace(DiscoveryCompletion {
            generation: 3,
            key: Some(key),
        });
        assert!(waiter.await.is_ok_and(|allowed| allowed));
    }

    #[tokio::test]
    async fn same_endpoint_new_inode_replaces_old_task_before_starting_new_one() {
        let old_instance = server_instance(2);
        let new_instance = server_instance(3);
        let (sender, mut receiver) = mpsc::channel(16);
        let shutdown = CancellationToken::new();
        let sink = EventSink {
            sender,
            shutdown: shutdown.clone(),
        };
        let (_resync_tx, resync) = watch::channel(0_u64);
        let (discovery_tx, _discovery_rx) = watch::channel(0_u64);
        let old_cancellation = shutdown.child_token();
        let child_cancellation = old_cancellation.clone();
        let child = tokio::spawn(async move { child_cancellation.cancelled().await });
        let (verification, _verification_rx) = watch::channel(DiscoveryCompletion {
            generation: 1,
            key: Some(old_instance.key.clone()),
        });
        let mut active = HashMap::from([(
            old_instance.key.clone(),
            ActiveServer {
                instance: old_instance.clone(),
                connection: ConnectionSettings::default(),
                misses: 0,
                cancellation: old_cancellation,
                verification,
                join: Some(child),
            },
        )]);
        let discovery = ReadyDiscoverer {
            report: Mutex::new(Some(DiscoveryReport {
                instances: vec![new_instance.clone()],
                connections: HashMap::from([(
                    new_instance.key.clone(),
                    ConnectionSettings::default(),
                )]),
                diagnostics: Vec::new(),
                listener_fingerprint: ListenerTableFingerprint::single(
                    new_instance.key.listener,
                    new_instance.key.socket_inode,
                ),
                ..DiscoveryReport::default()
            })),
        };
        let mut completed_generation = 1;
        assert!(
            discover_once(
                &discovery,
                &MonitorConfig::default(),
                &sink,
                &resync,
                &discovery_tx,
                &shutdown,
                &mut active,
                2,
                &mut completed_generation,
            )
            .await
            .is_ok()
        );
        assert_eq!(active.len(), 1);
        assert!(active.contains_key(&new_instance.key));
        assert!(matches!(
            receiver.recv().await,
            Some(BeaconEvent::ServerRemoved(instance)) if instance == old_instance
        ));
        assert!(matches!(
            receiver.recv().await,
            Some(BeaconEvent::ServerFound(instance)) if instance == new_instance
        ));
    }

    #[tokio::test]
    async fn rotated_managed_credentials_replace_only_that_task_in_lifecycle_order() {
        let managed = managed_instance(5098, "rotated");
        let v1 = server_instance(42);
        let old_connection = managed_connection("old-private-password");
        let new_connection = managed_connection("new-private-password");
        let (sender, mut receiver) = mpsc::channel(16);
        let shutdown = CancellationToken::new();
        let sink = EventSink {
            sender,
            shutdown: shutdown.clone(),
        };
        let (_resync_tx, resync) = watch::channel(0_u64);
        let (discovery_tx, _discovery_rx) = watch::channel(0_u64);

        let managed_cancellation = shutdown.child_token();
        let managed_child_cancellation = managed_cancellation.clone();
        let managed_child =
            tokio::spawn(async move { managed_child_cancellation.cancelled().await });
        let v1_cancellation = shutdown.child_token();
        let v1_child_cancellation = v1_cancellation.clone();
        let v1_child = tokio::spawn(async move { v1_child_cancellation.cancelled().await });
        let mut active = HashMap::from([
            (
                managed.key.clone(),
                ActiveServer {
                    instance: managed.clone(),
                    connection: old_connection,
                    misses: 0,
                    cancellation: managed_cancellation,
                    verification: watch::channel(DiscoveryCompletion {
                        generation: 1,
                        key: Some(managed.key.clone()),
                    })
                    .0,
                    join: Some(managed_child),
                },
            ),
            (
                v1.key.clone(),
                ActiveServer {
                    instance: v1.clone(),
                    connection: ConnectionSettings::default(),
                    misses: 0,
                    cancellation: v1_cancellation.clone(),
                    verification: watch::channel(DiscoveryCompletion {
                        generation: 1,
                        key: Some(v1.key.clone()),
                    })
                    .0,
                    join: Some(v1_child),
                },
            ),
        ]);
        let discovery = ReadyDiscoverer {
            report: Mutex::new(Some(DiscoveryReport {
                instances: vec![managed.clone(), v1.clone()],
                connections: HashMap::from([
                    (managed.key.clone(), new_connection.clone()),
                    (v1.key.clone(), ConnectionSettings::default()),
                ]),
                ..DiscoveryReport::default()
            })),
        };
        let mut completed_generation = 1;
        assert!(
            discover_once(
                &discovery,
                &MonitorConfig::default(),
                &sink,
                &resync,
                &discovery_tx,
                &shutdown,
                &mut active,
                2,
                &mut completed_generation,
            )
            .await
            .is_ok()
        );

        assert!(matches!(
            receiver.recv().await,
            Some(BeaconEvent::ServerRemoved(instance)) if instance == managed
        ));
        assert!(matches!(
            receiver.recv().await,
            Some(BeaconEvent::ServerFound(instance)) if instance == managed
        ));
        assert_eq!(active.len(), 2);
        assert_eq!(active[&managed.key].connection, new_connection);
        assert!(active.contains_key(&v1.key));
        assert!(!v1_cancellation.is_cancelled());
        assert!(!format!("{:?}", active[&managed.key].connection).contains("new-private-password"));
        shutdown.cancel();
    }

    #[tokio::test]
    async fn failed_bootstrap_replays_events_and_later_initializes_from_snapshot() {
        let event_stream = stream::iter([Ok(sourced(busy_event(), 64))]).chain(stream::pending());
        let client = ScriptedClient {
            endpoint: endpoint(),
            snapshots: Mutex::new(VecDeque::from([
                (
                    Duration::from_millis(20),
                    Err("bootstrap unavailable".to_owned()),
                ),
                (Duration::ZERO, Ok(busy_snapshot())),
            ])),
            stream: Mutex::new(Some(Box::pin(event_stream))),
        };
        let config = MonitorConfig {
            coalesce_interval: Duration::from_millis(5),
            resync_interval: Duration::from_secs(60),
            ..MonitorConfig::default()
        };
        let (sender, mut receiver) = mpsc::channel(32);
        let shutdown = CancellationToken::new();
        let cancellation = shutdown.child_token();
        let sink = EventSink {
            sender,
            shutdown: shutdown.clone(),
        };
        let (_resync_tx, mut resync) = watch::channel(0_u64);
        let task_cancellation = cancellation.clone();
        let task_sink = sink.clone();
        let task = tokio::spawn(async move {
            let mut state = ServerConnectionState::default();
            monitor_connection(
                &client,
                &config,
                &task_sink,
                &mut resync,
                &task_cancellation,
                &mut state,
            )
            .await
        });

        let mut sequence = Vec::new();
        while let Ok(Some(event)) =
            tokio::time::timeout(Duration::from_secs(1), receiver.recv()).await
        {
            match event {
                BeaconEvent::Diagnostic { message, .. } => {
                    assert!(message.contains("bootstrap unavailable"));
                    sequence.push("diagnostic");
                }
                BeaconEvent::Observed { event, .. } if event.kind == "session.status" => {
                    sequence.push("observed");
                }
                BeaconEvent::Transition { transition, .. }
                    if transition.current == crate::model::ActivityState::Working =>
                {
                    sequence.push("working");
                }
                BeaconEvent::InitialState { .. } => {
                    sequence.push("initial");
                    break;
                }
                _ => {}
            }
        }
        assert_eq!(sequence, ["diagnostic", "observed", "working", "initial"]);
        cancellation.cancel();
        assert!(task.await.is_ok_and(|result| result.is_ok()));
    }

    #[tokio::test]
    async fn runtime_drop_cancels_root_and_active_server_drop_aborts_child() {
        let (events_tx, events) = mpsc::channel(1);
        let (resync, _resync_rx) = watch::channel(0_u64);
        let (discovery, _discovery_rx) = watch::channel(0_u64);
        let shutdown = CancellationToken::new();
        let join = tokio::spawn(pending::<()>());
        let runtime = MonitorRuntime {
            events,
            control: MonitorControl {
                shutdown: shutdown.clone(),
                resync,
                discovery,
            },
            join: Some(join),
        };
        drop(events_tx);
        drop(runtime);
        assert!(shutdown.is_cancelled());

        let child = tokio::spawn(pending::<()>());
        let abort = child.abort_handle();
        let active = ActiveServer {
            instance: ServerInstance {
                key: instance_key(2),
                endpoint: endpoint(),
                protocol: OpenCodeProtocol::V1,
                executable: None,
                version: "1.17.4".to_owned(),
            },
            connection: ConnectionSettings::default(),
            misses: 0,
            cancellation: CancellationToken::new(),
            verification: watch::channel(DiscoveryCompletion {
                generation: 0,
                key: None,
            })
            .0,
            join: Some(child),
        };
        drop(active);
        tokio::task::yield_now().await;
        assert!(abort.is_finished());
    }

    #[tokio::test]
    async fn runtime_wait_awaits_owned_optional_handle() {
        let (_events_tx, events) = mpsc::channel(1);
        let (resync, _resync_rx) = watch::channel(0_u64);
        let (discovery, _discovery_rx) = watch::channel(0_u64);
        let shutdown = CancellationToken::new();
        let mut runtime = MonitorRuntime {
            events,
            control: MonitorControl {
                shutdown,
                resync,
                discovery,
            },
            join: Some(tokio::spawn(async {})),
        };
        assert!(runtime.wait().await.is_ok());
    }

    #[tokio::test]
    async fn cancelled_runtime_wait_retains_handle_for_retry() {
        let (_events_tx, events) = mpsc::channel(1);
        let (resync, _resync_rx) = watch::channel(0_u64);
        let (discovery, _discovery_rx) = watch::channel(0_u64);
        let shutdown = CancellationToken::new();
        let (release, released) = tokio::sync::oneshot::channel();
        let mut runtime = MonitorRuntime {
            events,
            control: MonitorControl {
                shutdown,
                resync,
                discovery,
            },
            join: Some(tokio::spawn(async move {
                let _ = released.await;
            })),
        };
        assert!(
            tokio::time::timeout(Duration::from_millis(10), runtime.wait())
                .await
                .is_err()
        );
        assert!(release.send(()).is_ok());
        assert!(runtime.wait().await.is_ok());
    }

    #[tokio::test]
    async fn cancelled_active_stop_retains_handle_for_retry_and_drop() {
        let active_with_child = |child| ActiveServer {
            instance: server_instance(2),
            connection: ConnectionSettings::default(),
            misses: 0,
            cancellation: CancellationToken::new(),
            verification: watch::channel(DiscoveryCompletion {
                generation: 0,
                key: None,
            })
            .0,
            join: Some(child),
        };

        let (release, released) = tokio::sync::oneshot::channel();
        let mut retryable = active_with_child(tokio::spawn(async move {
            let _ = released.await;
        }));
        assert!(
            tokio::time::timeout(Duration::from_millis(10), retryable.stop())
                .await
                .is_err()
        );
        assert!(release.send(()).is_ok());
        retryable.stop().await;
        assert!(retryable.join.is_none());

        let child = tokio::spawn(pending::<()>());
        let abort = child.abort_handle();
        let mut active = active_with_child(child);
        assert!(
            tokio::time::timeout(Duration::from_millis(10), active.stop())
                .await
                .is_err()
        );
        assert!(!abort.is_finished());
        drop(active);
        tokio::task::yield_now().await;
        assert!(abort.is_finished());
    }

    #[test]
    fn reconnect_delay_is_bounded() {
        for attempt in 0..100 {
            let delay = reconnect_delay(attempt);
            assert!(delay >= Duration::from_millis(800));
            assert!(delay <= Duration::from_secs(36));
        }
    }

    #[test]
    fn backend_reports_coexist_and_managed_registration_wins_endpoint_collision() {
        let v1 = server_instance(10);
        let managed_same_endpoint = managed_instance(v1.endpoint.address().port(), "same");
        let managed_other = managed_instance(5099, "other");
        let procfs = DiscoveryReport {
            instances: vec![v1.clone()],
            ..DiscoveryReport::default()
        };
        let managed = DiscoveryReport {
            instances: vec![managed_same_endpoint.clone(), managed_other.clone()],
            connections: HashMap::from([
                (
                    managed_same_endpoint.key.clone(),
                    ConnectionSettings { auth: None },
                ),
                (managed_other.key.clone(), ConnectionSettings { auth: None }),
            ]),
            ..DiscoveryReport::default()
        };
        let merged = merge_backend_reports(Ok(procfs), Ok(managed))
            .unwrap_or_else(|error| unreachable!("backend merge succeeds: {error}"));
        assert_eq!(merged.instances.len(), 2);
        assert!(
            !merged
                .instances
                .iter()
                .any(|instance| instance.key == v1.key)
        );
        assert!(
            merged
                .instances
                .iter()
                .any(|instance| instance.key == managed_same_endpoint.key)
        );
        assert!(
            merged
                .instances
                .iter()
                .any(|instance| instance.key == managed_other.key)
        );
    }

    #[tokio::test]
    async fn failed_backend_does_not_remove_or_shadow_its_active_instance() {
        let managed = managed_instance(5099, "managed");
        let mut v1 = server_instance(10);
        v1.endpoint = managed.endpoint;
        v1.key.listener = managed.endpoint.address();
        let (sender, _receiver) = mpsc::channel(16);
        let shutdown = CancellationToken::new();
        let sink = EventSink {
            sender,
            shutdown: shutdown.clone(),
        };
        let (_resync_tx, resync) = watch::channel(0_u64);
        let (discovery_tx, _discovery_rx) = watch::channel(0_u64);
        let cancellation = shutdown.child_token();
        let child_cancellation = cancellation.clone();
        let child = tokio::spawn(async move { child_cancellation.cancelled().await });
        let (verification, _verification_rx) = watch::channel(DiscoveryCompletion {
            generation: 1,
            key: Some(managed.key.clone()),
        });
        let mut active = HashMap::from([(
            managed.key.clone(),
            ActiveServer {
                instance: managed.clone(),
                connection: ConnectionSettings { auth: None },
                misses: 0,
                cancellation,
                verification,
                join: Some(child),
            },
        )]);
        let discovery = ReadyDiscoverer {
            report: Mutex::new(Some(DiscoveryReport {
                instances: vec![v1],
                incomplete_backends: HashSet::from([DiscoveryBackend::Managed]),
                ..DiscoveryReport::default()
            })),
        };
        let mut completed_generation = 1;
        assert!(
            discover_once(
                &discovery,
                &MonitorConfig::default(),
                &sink,
                &resync,
                &discovery_tx,
                &shutdown,
                &mut active,
                2,
                &mut completed_generation,
            )
            .await
            .is_ok()
        );
        assert_eq!(active.len(), 1);
        assert_eq!(active[&managed.key].misses, 0);
    }

    #[test]
    fn partial_backend_reports_record_which_results_are_not_authoritative() {
        let v1 = merge_backend_reports(
            Ok(DiscoveryReport::default()),
            Err("managed unavailable".to_owned()),
        )
        .unwrap_or_else(|error| unreachable!("v1 report remains usable: {error}"));
        assert_eq!(
            v1.incomplete_backends,
            HashSet::from([DiscoveryBackend::Managed])
        );

        let v2 = merge_backend_reports(
            Err("procfs unavailable".to_owned()),
            Ok(DiscoveryReport::default()),
        )
        .unwrap_or_else(|error| unreachable!("v2 report remains usable: {error}"));
        assert_eq!(
            v2.incomplete_backends,
            HashSet::from([DiscoveryBackend::Procfs])
        );
    }
}
