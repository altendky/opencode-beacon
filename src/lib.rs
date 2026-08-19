//! Reusable discovery and monitoring for local `OpenCode` servers.

pub mod client;
pub mod discovery;
pub mod model;
pub mod monitor;
pub mod state;

pub use client::{BasicAuth, ClientConfig, OpenCodeClient, OpenCodeV2Client};
pub use discovery::{
    DiscoveryConfig, LinuxProcfsDiscovery, ManagedDiscoveryConfig, ManagedServiceDiscovery,
};
pub use model::{
    ActivityState, AttentionEvent, AttentionKind, BeaconEvent, InstanceKey, InstanceSource,
    OpenCodeProtocol, ProjectedSession, ProjectedStatus, ServerEndpoint, ServerInstance,
    ServerProjection, TransitionSource,
};
pub use monitor::{Monitor, MonitorConfig, MonitorConfigError, MonitorControl, MonitorRuntime};
pub use state::StateUpdate;
