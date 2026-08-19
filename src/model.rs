use std::collections::HashMap;
use std::fmt;
use std::net::SocketAddr;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// A local HTTP endpoint for an `OpenCode` server.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ServerEndpoint(SocketAddr);

impl ServerEndpoint {
    /// Creates a loopback endpoint.
    ///
    /// # Errors
    ///
    /// Returns an error for non-loopback addresses.
    pub const fn new(address: SocketAddr) -> Result<Self, EndpointError> {
        if address.ip().is_loopback() {
            Ok(Self(address))
        } else {
            Err(EndpointError::NotLoopback(address))
        }
    }

    /// Returns the endpoint socket address.
    #[must_use]
    pub const fn address(self) -> SocketAddr {
        self.0
    }

    #[must_use]
    pub(crate) fn url(self, path: &str) -> String {
        format!("http://{}{}", self.0, path)
    }
}

impl fmt::Display for ServerEndpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// Invalid local endpoint.
#[derive(Debug, thiserror::Error)]
pub enum EndpointError {
    /// The address could send credentials to another machine.
    #[error("endpoint must be loopback, got {0}")]
    NotLoopback(SocketAddr),
}

/// Discovery source identity for one verified server.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum InstanceSource {
    LinuxProcfs,
    ManagedService {
        registration: PathBuf,
        id: Option<String>,
    },
}

/// HTTP API generation spoken by a discovered `OpenCode` server.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum OpenCodeProtocol {
    V1,
    V2,
}

impl fmt::Display for OpenCodeProtocol {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::V1 => "v1",
            Self::V2 => "v2",
        })
    }
}

/// Process and source-specific identity for one discovered server.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct InstanceKey {
    pub network_namespace_inode: u64,
    pub socket_inode: u64,
    pub listener: SocketAddr,
    pub pid: u32,
    pub source: InstanceSource,
}

/// A verified local `OpenCode` server.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServerInstance {
    pub key: InstanceKey,
    pub endpoint: ServerEndpoint,
    pub protocol: OpenCodeProtocol,
    pub executable: Option<String>,
    pub version: String,
}

/// The effective activity for a session.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActivityState {
    WaitingForInput,
    WaitingForPermission,
    Retrying,
    Working,
    Idle,
}

impl fmt::Display for ActivityState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = match self {
            Self::WaitingForInput => "waiting_for_input",
            Self::WaitingForPermission => "waiting_for_permission",
            Self::Retrying => "retrying",
            Self::Working => "working",
            Self::Idle => "idle",
        };
        formatter.write_str(value)
    }
}

/// `OpenCode`'s base session status.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum SessionStatus {
    #[default]
    Idle,
    Busy,
    Retry {
        #[serde(default)]
        attempt: u64,
        #[serde(default)]
        message: String,
        #[serde(default)]
        next: u64,
    },
    #[serde(other)]
    Unknown,
}

/// Session metadata used for attention attribution; additive API fields are ignored.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq)]
pub struct Session {
    pub id: String,
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub slug: String,
    #[serde(default, rename = "parentID")]
    pub parent_id: Option<String>,
    #[serde(default, rename = "projectID")]
    pub project_id: Option<String>,
    #[serde(default)]
    pub directory: Option<PathBuf>,
    #[serde(default)]
    pub workspace: Option<PathBuf>,
    #[serde(default, alias = "time", deserialize_with = "deserialize_updated")]
    pub updated: Option<u64>,
}

fn deserialize_updated<'de, D>(deserializer: D) -> Result<Option<u64>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Updated {
        Number(u64),
        Time { updated: Option<u64> },
    }
    Ok(match Option::<Updated>::deserialize(deserializer)? {
        Some(Updated::Number(updated)) => Some(updated),
        Some(Updated::Time { updated }) => updated,
        None => None,
    })
}

/// Minimal pending permission representation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct PermissionRequest {
    pub id: String,
    #[serde(rename = "sessionID")]
    pub session_id: String,
}

/// Minimal pending question representation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct QuestionRequest {
    pub id: String,
    #[serde(rename = "sessionID")]
    pub session_id: String,
}

/// A complete authoritative state read from HTTP endpoints.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Snapshot {
    pub sessions: Vec<Session>,
    pub statuses: HashMap<String, SessionStatus>,
    pub permissions: Vec<PermissionRequest>,
    pub questions: Vec<QuestionRequest>,
}

/// Privacy-limited current state for one session in an authoritative projection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectedSession {
    pub id: String,
    pub title: String,
    pub slug: String,
    pub parent_id: Option<String>,
    pub project_id: Option<String>,
    pub directory: Option<PathBuf>,
    pub workspace: Option<PathBuf>,
    pub updated: Option<u64>,
    pub status: ProjectedStatus,
    pub pending_permission_ids: Vec<String>,
    pub pending_question_ids: Vec<String>,
}

/// Privacy-limited base status without retry message payloads.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProjectedStatus {
    Idle,
    Busy,
    Retry,
    Unknown,
}

impl From<&SessionStatus> for ProjectedStatus {
    fn from(status: &SessionStatus) -> Self {
        match status {
            SessionStatus::Idle => Self::Idle,
            SessionStatus::Busy => Self::Busy,
            SessionStatus::Retry { .. } => Self::Retry,
            SessionStatus::Unknown => Self::Unknown,
        }
    }
}

/// An atomic current-state projection for one exact discovered server instance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServerProjection {
    pub instance_key: InstanceKey,
    pub endpoint: ServerEndpoint,
    pub sessions: Vec<ProjectedSession>,
}

/// Health response from `OpenCode`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct Health {
    pub healthy: bool,
    pub version: String,
}

/// One semantic event carried in an SSE `message`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct WireEvent {
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default, alias = "data")]
    pub properties: Value,
}

/// Why a state transition was produced.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransitionSource {
    Live,
    Snapshot,
}

impl fmt::Display for TransitionSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Live => "sse",
            Self::Snapshot => "snapshot",
        })
    }
}

/// A derived session activity change.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StateTransition {
    pub session_id: String,
    pub previous: ActivityState,
    pub current: ActivityState,
    pub source: TransitionSource,
}

/// A direct, non-latched SSE observation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObservedEvent {
    pub kind: String,
    pub session_id: Option<String>,
    pub request_id: Option<String>,
    pub detail: Option<String>,
}

/// A user-facing reason that a root session needs attention.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum AttentionKind {
    Ready,
    Question,
    Permission,
}

impl fmt::Display for AttentionKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Ready => "ready",
            Self::Question => "question",
            Self::Permission => "permission",
        })
    }
}

/// A privacy-limited derived attention event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttentionEvent {
    pub kind: AttentionKind,
    pub root_session_id: String,
    pub root_title: Option<String>,
    pub root_slug: Option<String>,
    pub subject_session_id: String,
    pub request_id: Option<String>,
    pub source: TransitionSource,
    pub initial: bool,
    pub root_resolved: bool,
}

impl AttentionEvent {
    /// Returns the root title, then slug, then ID as a stable display fallback.
    #[must_use]
    pub fn name(&self) -> &str {
        self.root_title
            .as_deref()
            .filter(|value| !value.is_empty())
            .or_else(|| self.root_slug.as_deref().filter(|value| !value.is_empty()))
            .unwrap_or(&self.root_session_id)
    }
}

/// Events emitted by the reusable monitor.
#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub enum BeaconEvent {
    ServerFound(ServerInstance),
    ServerRemoved(ServerInstance),
    Connected(ServerEndpoint),
    Disconnected {
        endpoint: ServerEndpoint,
        reason: String,
    },
    InitialState {
        endpoint: ServerEndpoint,
        active_sessions: usize,
    },
    Observed {
        endpoint: ServerEndpoint,
        event: ObservedEvent,
    },
    Transition {
        endpoint: ServerEndpoint,
        transition: StateTransition,
    },
    Attention {
        endpoint: ServerEndpoint,
        attention: AttentionEvent,
    },
    StateProjection(ServerProjection),
    Diagnostic {
        endpoint: Option<ServerEndpoint>,
        message: String,
        verbose_only: bool,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opencode_1_17_fixtures_tolerate_additive_fields() {
        let health = serde_json::from_str::<Health>(include_str!("../tests/fixtures/health.json"));
        assert!(health.is_ok_and(|health| health.version == "1.17.4"));

        let sessions =
            serde_json::from_str::<Vec<Session>>(include_str!("../tests/fixtures/sessions.json"));
        assert!(sessions.is_ok_and(|sessions| {
            sessions.len() == 2
                && sessions[0].title == "Root session"
                && sessions[0].slug == "root-session"
                && sessions[1].parent_id.as_deref() == Some("ses_busy")
        }));

        let statuses = serde_json::from_str::<HashMap<String, SessionStatus>>(include_str!(
            "../tests/fixtures/status.json"
        ));
        assert!(statuses.is_ok_and(|statuses| statuses.len() == 2));

        let permissions = serde_json::from_str::<Vec<PermissionRequest>>(include_str!(
            "../tests/fixtures/permissions.json"
        ));
        assert!(permissions.is_ok_and(|requests| requests[0].session_id == "ses_busy"));

        let questions = serde_json::from_str::<Vec<QuestionRequest>>(include_str!(
            "../tests/fixtures/questions.json"
        ));
        assert!(questions.is_ok_and(|requests| requests[0].id == "que_1"));
    }

    #[test]
    fn endpoints_reject_non_loopback_addresses() {
        let public = ServerEndpoint::new(SocketAddr::from(([192, 0, 2, 1], 4096)));
        assert!(matches!(public, Err(EndpointError::NotLoopback(_))));
        assert!(ServerEndpoint::new(SocketAddr::from(([127, 0, 0, 1], 4096))).is_ok());
    }
}
