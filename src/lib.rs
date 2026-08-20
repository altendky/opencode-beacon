//! Reusable discovery and monitoring for local coding-agent sessions.

pub mod claude;
pub mod client;
pub mod discovery;
pub mod model;
pub mod monitor;
pub mod state;

pub use claude::{ClaudeConfig, ClaudeDiscovery};
pub use client::{BasicAuth, ClientConfig, OpenCodeClient, OpenCodeV2Client};
pub use discovery::{
    DiscoveryConfig, LinuxProcfsDiscovery, ManagedDiscoveryConfig, ManagedServiceDiscovery,
};
pub use model::{
    ActivityState, AttentionEvent, AttentionKind, BeaconEvent, ClaudeAttentionEvent,
    ClaudeProjection, ClaudeSession, ClaudeSessionKey, ClaudeStatus, ClaudeTransition, InstanceKey,
    InstanceSource, OpenCodeProtocol, ProjectedSession, ProjectedStatus, ServerEndpoint,
    ServerInstance, ServerProjection, TransitionSource,
};
pub use monitor::{Monitor, MonitorConfig, MonitorConfigError, MonitorControl, MonitorRuntime};
pub use state::StateUpdate;
