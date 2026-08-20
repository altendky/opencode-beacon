use std::pin::Pin;
use std::time::Duration;

use async_stream::stream;
use futures_util::{Stream, StreamExt};
use reqwest::{Client, StatusCode};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, de::DeserializeOwned};

use crate::model::{
    Health, PermissionRequest, QuestionRequest, ServerEndpoint, Session, SessionStatus, Snapshot,
    WireEvent,
};

const MAX_SSE_FRAME_SIZE: usize = 1_048_576;
const MAX_SSE_DELIMITER_PREFIX: usize = 3;
const SESSION_PATH: &str = "/session?limit=100000";
const V2_SESSION_LIMIT: usize = 100;

/// Optional Basic authentication for a local `OpenCode` server.
#[derive(Clone)]
pub struct BasicAuth {
    username: String,
    password: SecretString,
}

impl BasicAuth {
    /// Creates credentials. The password is redacted from debug output.
    #[must_use]
    pub const fn new(username: String, password: SecretString) -> Self {
        Self { username, password }
    }
}

impl std::fmt::Debug for BasicAuth {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BasicAuth")
            .field("username", &self.username)
            .field("password", &"[REDACTED]")
            .finish()
    }
}

impl PartialEq for BasicAuth {
    fn eq(&self, other: &Self) -> bool {
        self.username == other.username
            && self.password.expose_secret() == other.password.expose_secret()
    }
}

impl Eq for BasicAuth {}

/// HTTP client behavior shared by discovery and monitoring.
#[derive(Clone, Debug)]
pub struct ClientConfig {
    pub connect_timeout: Duration,
    pub request_timeout: Duration,
    pub event_header_timeout: Duration,
    pub auth: Option<BasicAuth>,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_millis(500),
            request_timeout: Duration::from_secs(3),
            event_header_timeout: Duration::from_secs(3),
            auth: None,
        }
    }
}

/// Client for the `OpenCode` 1.17 HTTP and SSE APIs.
#[derive(Clone, Debug)]
pub struct OpenCodeClient {
    endpoint: ServerEndpoint,
    client: Client,
    event_client: Client,
    config: ClientConfig,
}

/// Client for a managed `OpenCode` v2 central service.
#[derive(Clone, Debug)]
pub struct OpenCodeV2Client {
    inner: OpenCodeClient,
}

/// A stream of semantic `OpenCode` events.
pub type EventStream = Pin<Box<dyn Stream<Item = Result<WireEvent, ClientError>> + Send>>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SourceEvent {
    pub event: WireEvent,
    pub source_bytes: usize,
}

pub(crate) type SourceEventStream =
    Pin<Box<dyn Stream<Item = Result<SourceEvent, ClientError>> + Send>>;

impl OpenCodeClient {
    /// Builds a client with redirects disabled to avoid forwarding credentials.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying HTTP client cannot be built.
    pub fn new(endpoint: ServerEndpoint, config: ClientConfig) -> Result<Self, ClientError> {
        let client = Client::builder()
            .connect_timeout(config.connect_timeout)
            .timeout(config.request_timeout)
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .build()?;
        let event_client = Client::builder()
            .connect_timeout(config.connect_timeout)
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .build()?;
        Ok(Self {
            endpoint,
            client,
            event_client,
            config,
        })
    }

    /// Returns the configured local endpoint.
    #[must_use]
    pub const fn endpoint(&self) -> ServerEndpoint {
        self.endpoint
    }

    /// Probes server health and version.
    ///
    /// # Errors
    ///
    /// Returns transport, HTTP status, or JSON errors.
    pub async fn health(&self) -> Result<Health, ClientError> {
        self.get_json("/global/health").await
    }

    /// Fetches all state endpoints concurrently and returns only a complete snapshot.
    ///
    /// # Errors
    ///
    /// Returns an error if any constituent request fails.
    pub async fn snapshot(&self) -> Result<Snapshot, ClientError> {
        let (sessions, statuses, permissions, questions) = tokio::try_join!(
            self.get_json::<Vec<Session>>(SESSION_PATH),
            self.get_json::<std::collections::HashMap<String, SessionStatus>>("/session/status"),
            self.get_json::<Vec<PermissionRequest>>("/permission"),
            self.get_json::<Vec<QuestionRequest>>("/question"),
        )?;
        Ok(Snapshot {
            sessions,
            statuses,
            permissions,
            questions,
        })
    }

    /// Opens `/event` and decodes SSE `message` records.
    ///
    /// # Errors
    ///
    /// Returns an error if the connection cannot be established. Stream errors are
    /// returned as stream items.
    pub async fn event_stream(&self) -> Result<EventStream, ClientError> {
        let stream = self.source_event_stream().await?;
        Ok(Box::pin(
            stream.map(|result| result.map(|event| event.event)),
        ))
    }

    pub(crate) async fn source_event_stream(&self) -> Result<SourceEventStream, ClientError> {
        self.source_event_stream_at("/event").await
    }

    async fn source_event_stream_at(
        &self,
        path: &'static str,
    ) -> Result<SourceEventStream, ClientError> {
        let mut request = self.event_client.get(self.endpoint.url(path));
        if let Some(auth) = &self.config.auth {
            request = request.basic_auth(&auth.username, Some(auth.password.expose_secret()));
        }
        let response = tokio::time::timeout(self.config.event_header_timeout, request.send())
            .await
            .map_err(|_| ClientError::EventHeaderTimeout(self.config.event_header_timeout))??;
        let status = response.status();
        if !status.is_success() {
            return Err(ClientError::HttpStatus {
                path: path.to_owned(),
                status,
            });
        }
        if status != StatusCode::OK {
            return Err(ClientError::HttpStatus {
                path: path.to_owned(),
                status,
            });
        }
        let content_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok());
        if !content_type.is_some_and(|value| {
            value
                .split_once(';')
                .map_or(value, |(media_type, _)| media_type)
                .trim()
                .eq_ignore_ascii_case("text/event-stream")
        }) {
            return Err(ClientError::UnexpectedEventContentType(
                content_type.map(str::to_owned),
            ));
        }

        let stream = stream! {
            let mut bytes = response.bytes_stream();
            let mut buffer = Vec::new();
            let mut search_from = 0;
            let mut end_of_stream = false;
            let mut terminal_error = None;
            loop {
                if let Some(event) = decode_next_frame(&mut buffer, &mut search_from, end_of_stream) {
                    let failed = event.is_err();
                    yield event;
                    if failed {
                        return;
                    }
                    continue;
                }
                if end_of_stream {
                    if let Some(error) = terminal_error.take() {
                        yield Err(ClientError::Transport(error));
                    }
                    return;
                }
                match bytes.next().await {
                    Some(Ok(chunk)) => buffer.extend_from_slice(&chunk),
                    Some(Err(error)) => {
                        terminal_error = Some(error);
                        end_of_stream = true;
                    }
                    None => end_of_stream = true,
                }
            }
        };
        Ok(Box::pin(stream))
    }

    async fn get_json<T: DeserializeOwned>(&self, path: &str) -> Result<T, ClientError> {
        let mut request = self.client.get(self.endpoint.url(path));
        if let Some(auth) = &self.config.auth {
            request = request.basic_auth(&auth.username, Some(auth.password.expose_secret()));
        }
        let response = request.send().await?;
        let status = response.status();
        if !status.is_success() {
            return Err(ClientError::HttpStatus {
                path: path.to_owned(),
                status,
            });
        }
        Ok(response.json().await?)
    }
}

impl OpenCodeV2Client {
    /// Builds a managed v2 client with redirects disabled.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying HTTP client cannot be built.
    pub fn new(endpoint: ServerEndpoint, config: ClientConfig) -> Result<Self, ClientError> {
        Ok(Self {
            inner: OpenCodeClient::new(endpoint, config)?,
        })
    }

    #[must_use]
    pub const fn endpoint(&self) -> ServerEndpoint {
        self.inner.endpoint()
    }

    /// Probes the managed service health endpoint.
    ///
    /// # Errors
    ///
    /// Returns transport, HTTP status, or JSON errors.
    pub async fn health(&self) -> Result<ServiceHealth, ClientError> {
        self.inner.get_json("/api/health").await
    }

    /// Fetches complete paginated metadata and active execution state.
    ///
    /// # Errors
    ///
    /// Returns an error for any failed page, active-state request, or cursor loop.
    pub async fn snapshot(&self) -> Result<Snapshot, ClientError> {
        let (sessions, active) = tokio::try_join!(self.sessions(), self.active_sessions())?;
        let statuses = sessions
            .iter()
            .map(|session| {
                let status = if active.contains(&session.id) {
                    SessionStatus::Busy
                } else {
                    SessionStatus::Idle
                };
                (session.id.clone(), status)
            })
            .collect();
        Ok(Snapshot {
            sessions,
            statuses,
            permissions: Vec::new(),
            questions: Vec::new(),
        })
    }

    pub(crate) async fn source_event_stream(&self) -> Result<SourceEventStream, ClientError> {
        let stream = self.inner.source_event_stream_at("/api/event").await?;
        Ok(Box::pin(stream.map(|result| {
            result.map(|mut source| {
                source.event = adapt_v2_event(source.event);
                source
            })
        })))
    }

    async fn sessions(&self) -> Result<Vec<Session>, ClientError> {
        let mut sessions: Vec<Session> = Vec::new();
        let mut cursor: Option<String> = None;
        let mut seen_cursors = std::collections::HashSet::new();
        loop {
            let mut url = url::Url::parse(&self.endpoint().url("/api/session"))
                .map_err(|error| ClientError::InvalidUrl(error.to_string()))?;
            {
                let mut query = url.query_pairs_mut();
                query.append_pair("limit", &V2_SESSION_LIMIT.to_string());
                if let Some(cursor) = &cursor {
                    query.append_pair("cursor", cursor);
                }
            }
            let path = url[url::Position::BeforePath..].to_owned();
            let page: V2SessionsPage = self.inner.get_json(&path).await?;
            sessions.extend(
                page.data
                    .into_iter()
                    .map(|session| session.into_session(&page.location)),
            );
            let Some(next) = page.cursor.next else {
                break;
            };
            if !seen_cursors.insert(next.clone()) {
                return Err(ClientError::PaginationLoop);
            }
            cursor = Some(next);
        }
        sessions.sort_by(|left, right| left.id.cmp(&right.id));
        sessions.dedup_by(|left, right| left.id == right.id);
        Ok(sessions)
    }

    async fn active_sessions(&self) -> Result<std::collections::HashSet<String>, ClientError> {
        let active: V2ActiveSessions = self.inner.get_json("/api/session/active").await?;
        Ok(active.data.into_keys().collect())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct ServiceHealth {
    pub healthy: bool,
    pub version: String,
    pub pid: u32,
}

#[derive(Deserialize)]
struct V2SessionsPage {
    data: Vec<V2SessionEntry>,
    cursor: V2Cursor,
    #[serde(default)]
    location: V2Location,
}

#[derive(Deserialize)]
struct V2Cursor {
    next: Option<String>,
}

#[derive(Deserialize)]
struct V2Session {
    id: String,
    #[serde(default, rename = "parentID")]
    parent_id: Option<String>,
    #[serde(default)]
    title: String,
    #[serde(default, rename = "projectID")]
    project_id: Option<String>,
    #[serde(default)]
    directory: Option<std::path::PathBuf>,
    #[serde(default)]
    workspace: Option<std::path::PathBuf>,
    #[serde(default)]
    location: V2Location,
    #[serde(default)]
    time: V2SessionTime,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum V2SessionEntry {
    Direct(V2Session),
    Located {
        info: V2Session,
        #[serde(default)]
        location: V2Location,
    },
}

#[derive(Clone, Debug, Default, Deserialize)]
struct V2Location {
    directory: Option<std::path::PathBuf>,
    workspace: Option<std::path::PathBuf>,
}

#[derive(Debug, Default, Deserialize)]
struct V2SessionTime {
    updated: Option<u64>,
}

impl V2Session {
    fn into_session(self, fallback: &V2Location) -> Session {
        Session {
            id: self.id,
            title: self.title,
            slug: String::new(),
            parent_id: self.parent_id,
            project_id: self.project_id,
            directory: self
                .directory
                .or(self.location.directory)
                .or_else(|| fallback.directory.clone()),
            workspace: self
                .workspace
                .or(self.location.workspace)
                .or_else(|| fallback.workspace.clone()),
            updated: self.time.updated,
        }
    }
}

impl V2SessionEntry {
    fn into_session(self, fallback: &V2Location) -> Session {
        match self {
            Self::Direct(session) => session.into_session(fallback),
            Self::Located { mut info, location } => {
                info.location = location;
                info.into_session(fallback)
            }
        }
    }
}

#[derive(Deserialize)]
struct V2ActiveSessions {
    data: std::collections::HashMap<String, V2Active>,
}

#[derive(Deserialize)]
struct V2Active {
    #[serde(rename = "type")]
    _kind: String,
}

fn adapt_v2_event(mut event: WireEvent) -> WireEvent {
    match event.kind.as_str() {
        "session.created" => {
            if event.properties.get("info").is_none() {
                let info = serde_json::json!({
                    "id": event.properties.get("sessionID").and_then(serde_json::Value::as_str).unwrap_or_default(),
                    "title": event.properties.get("title").and_then(serde_json::Value::as_str).unwrap_or_default(),
                    "slug": event.properties.get("slug").and_then(serde_json::Value::as_str).unwrap_or_default(),
                    "parentID": event.properties.get("parentID").cloned().unwrap_or(serde_json::Value::Null),
                });
                event.properties = serde_json::json!({"info": info});
            }
        }
        "session.execution.started" => {
            "session.status".clone_into(&mut event.kind);
            event.properties["status"] = serde_json::json!({"type": "busy"});
        }
        "session.execution.succeeded" | "session.execution.interrupted" => {
            "session.status".clone_into(&mut event.kind);
            event.properties["status"] = serde_json::json!({"type": "idle"});
        }
        "session.retry.scheduled" => {
            let retry = (
                event
                    .properties
                    .get("attempt")
                    .and_then(serde_json::Value::as_u64),
                event
                    .properties
                    .get("at")
                    .and_then(serde_json::Value::as_u64),
                event
                    .properties
                    .pointer("/error/message")
                    .and_then(serde_json::Value::as_str),
            );
            if let (Some(attempt), Some(next), Some(message)) = retry {
                "session.status".clone_into(&mut event.kind);
                event.properties["status"] = serde_json::json!({
                    "type": "retry",
                    "attempt": attempt,
                    "message": message,
                    "next": next,
                });
            }
        }
        _ => {}
    }
    event
}

fn decode_next_frame(
    buffer: &mut Vec<u8>,
    search_from: &mut usize,
    end_of_stream: bool,
) -> Option<Result<SourceEvent, ClientError>> {
    loop {
        if let Some(ending_length) = leading_line_ending_length(buffer, end_of_stream) {
            buffer.drain(..ending_length);
            *search_from = 0;
            continue;
        }
        let Some((end, delimiter)) = frame_end_from(buffer, *search_from, end_of_stream) else {
            if incomplete_frame_is_too_large(buffer) {
                return Some(Err(ClientError::SseFrameTooLarge));
            }
            *search_from = buffer.len().saturating_sub(3);
            return None;
        };
        let source_bytes = end + delimiter;
        if end > MAX_SSE_FRAME_SIZE {
            buffer.drain(..source_bytes);
            *search_from = 0;
            return Some(Err(ClientError::SseFrameTooLarge));
        }
        let result = parse_frame(&buffer[..end]).map(|event| {
            event.map(|event| SourceEvent {
                event,
                source_bytes,
            })
        });
        buffer.drain(..source_bytes);
        *search_from = 0;
        match result {
            Ok(Some(event)) => return Some(Ok(event)),
            Ok(None) => {}
            Err(error) => return Some(Err(error)),
        }
    }
}

fn leading_line_ending_length(buffer: &[u8], allow_trailing_cr: bool) -> Option<usize> {
    match buffer {
        [b'\r', b'\n', ..] => Some(2),
        [b'\r'] if !allow_trailing_cr => None,
        [b'\r' | b'\n', ..] => Some(1),
        _ => None,
    }
}

fn incomplete_frame_is_too_large(buffer: &[u8]) -> bool {
    if buffer.len() <= MAX_SSE_FRAME_SIZE {
        return false;
    }
    let suffix = &buffer[MAX_SSE_FRAME_SIZE..];
    suffix.len() > MAX_SSE_DELIMITER_PREFIX
        || !matches!(
            suffix,
            b"\n" | b"\r" | b"\n\r" | b"\r\r" | b"\r\n" | b"\r\n\r"
        )
}

#[cfg(test)]
fn drain_complete_frames(
    buffer: &mut Vec<u8>,
    search_from: &mut usize,
) -> Vec<Result<SourceEvent, ClientError>> {
    let mut events = Vec::new();
    while let Some(event) = decode_next_frame(buffer, search_from, true) {
        let failed = event.is_err();
        events.push(event);
        if failed {
            break;
        }
    }
    events
}

#[cfg(test)]
fn frame_end(buffer: &[u8]) -> Option<(usize, usize)> {
    frame_end_from(buffer, 0, true)
}

fn frame_end_from(buffer: &[u8], start: usize, allow_trailing_cr: bool) -> Option<(usize, usize)> {
    let mut position = start;
    let mut previous_ending = None;
    while position < buffer.len() {
        let ending_length = match buffer[position] {
            b'\r' if previous_ending.is_some() => 1,
            b'\r' if buffer.get(position + 1) == Some(&b'\n') => 2,
            b'\r'
                if position + 1 == buffer.len()
                    && !allow_trailing_cr
                    && previous_ending.is_none() =>
            {
                break;
            }
            b'\r' | b'\n' => 1,
            _ => {
                previous_ending = None;
                position += 1;
                continue;
            }
        };
        if let Some(previous_position) = previous_ending {
            return Some((
                previous_position,
                position + ending_length - previous_position,
            ));
        }
        previous_ending = Some(position);
        position += ending_length;
    }
    None
}

fn parse_frame(frame: &[u8]) -> Result<Option<WireEvent>, ClientError> {
    let text = std::str::from_utf8(frame)?;
    let normalized = text.replace("\r\n", "\n").replace('\r', "\n");
    let mut wire_event = None;
    let mut data = Vec::new();
    for line in normalized.lines() {
        if line.starts_with(':') || line.is_empty() {
            continue;
        }
        let (field, value) = line.split_once(':').map_or((line, ""), |(field, value)| {
            (field, value.strip_prefix(' ').unwrap_or(value))
        });
        match field {
            "event" => wire_event = Some(value),
            "data" => data.push(value),
            _ => {}
        }
    }
    if !matches!(wire_event, None | Some("message")) || data.is_empty() {
        return Ok(None);
    }
    Ok(Some(serde_json::from_str(&data.join("\n"))?))
}

/// `OpenCode` client failure.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("HTTP transport failed: {0}")]
    Transport(#[from] reqwest::Error),
    #[error("OpenCode returned {status} for {path}")]
    HttpStatus { path: String, status: StatusCode },
    #[error("invalid OpenCode JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("SSE data was not UTF-8: {0}")]
    Utf8(#[from] std::str::Utf8Error),
    #[error("timed out waiting {0:?} for OpenCode event response headers")]
    EventHeaderTimeout(Duration),
    #[error("OpenCode /event returned unexpected Content-Type {0:?}")]
    UnexpectedEventContentType(Option<String>),
    #[error("SSE frame exceeded 1 MiB")]
    SseFrameTooLarge,
    #[error("invalid OpenCode service URL: {0}")]
    InvalidUrl(String),
    #[error("OpenCode session pagination repeated a cursor")]
    PaginationLoop,
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use super::*;

    #[test]
    fn parses_message_and_ignores_heartbeat_comment() {
        assert!(parse_frame(b": heartbeat").is_ok_and(|event| event.is_none()));
        let parsed = parse_frame(
            b"event: message\ndata: {\"type\":\"session.status\",\"properties\":{\"sessionID\":\"s\"}}",
        );
        assert!(
            parsed.is_ok_and(|event| { event.is_some_and(|event| event.kind == "session.status") })
        );
    }

    #[test]
    fn v2_event_fixture_preserves_created_info_and_orders_failure_before_retry() {
        let mut remaining = include_bytes!("../tests/fixtures/v2-events.sse").to_vec();
        let mut events = Vec::new();
        while let Some((end, delimiter)) = frame_end(&remaining) {
            let frame = remaining.drain(..end).collect::<Vec<_>>();
            remaining.drain(..delimiter);
            if let Some(event) = parse_frame(&frame)
                .unwrap_or_else(|error| unreachable!("v2 fixture frame parses: {error}"))
            {
                events.push(adapt_v2_event(event));
            }
        }

        assert_eq!(events[0].kind, "session.created");
        assert_eq!(events[0].properties["sessionID"], "ses_1");
        assert_eq!(events[0].properties["info"]["id"], "ses_1");
        assert_eq!(events[0].properties["info"]["title"], "Fixture title");
        assert_eq!(events[0].properties["info"]["slug"], "fixture-slug");
        assert_eq!(events[0].properties["info"]["parentID"], "ses_parent");
        assert_eq!(events[0].properties["info"]["projectID"], "prj_fixture");

        let mut state = crate::state::ServerState::default();
        state.apply_event(&events[0]);
        let started = state.apply_event_with_updates(&events[1]);
        assert_eq!(
            started.transitions[0].current,
            crate::model::ActivityState::Working
        );
        let failed = state.apply_event_with_updates(&events[2]);
        assert!(failed.transitions.is_empty());
        assert!(failed.attention.is_empty());
        assert_eq!(events[2].kind, "session.execution.failed");
        let retry = state.apply_event_with_updates(&events[3]);
        assert_eq!(
            retry.transitions[0].current,
            crate::model::ActivityState::Retrying
        );
        assert!(retry.attention.is_empty());
        assert_eq!(events[3].properties["status"]["attempt"], 2);
        assert_eq!(events[3].properties["status"]["message"], "retry later");
        assert_eq!(
            events[3].properties["status"]["next"],
            1_786_777_234_567_u64
        );
    }

    #[test]
    fn ignores_future_wire_event_names() {
        assert!(parse_frame(b"event: custom\ndata: {}").is_ok_and(|event| event.is_none()));
    }

    #[test]
    fn supports_multiline_data() {
        let parsed =
            parse_frame(b"data: {\"type\":\"server.connected\",\ndata: \"properties\":{}}");
        assert!(parsed.is_ok_and(|event| event.is_some()));
    }

    #[test]
    fn supports_bare_cr_multiline_data() {
        let parsed = parse_frame(
            b"event: message\rdata: {\"type\":\"server.connected\",\rdata: \"properties\":{}}",
        );
        assert!(
            parsed
                .is_ok_and(|event| { event.is_some_and(|event| event.kind == "server.connected") })
        );
        assert_eq!(
            frame_end(b"data: first\rdata: second\r\rnext"),
            Some((24, 2))
        );
    }

    #[test]
    fn supports_mixed_line_endings_at_event_boundaries() {
        for delimiter in [
            b"\r\n\r".as_slice(),
            b"\r\n\n".as_slice(),
            b"\n\r".as_slice(),
            b"\n\r\n".as_slice(),
            b"\r\r\n".as_slice(),
        ] {
            let mut buffer = b"data: {\"type\":\"server.connected\",\"properties\":{}}".to_vec();
            buffer.extend_from_slice(delimiter);
            let mut search_from = 0;
            let events = drain_complete_frames(&mut buffer, &mut search_from);
            assert!(events.len() == 1);
            assert!(events[0].as_ref().is_ok_and(|event| {
                event.event.kind == "server.connected"
                    && event.source_bytes
                        == b"data: {\"type\":\"server.connected\",\"properties\":{}}".len()
                            + match delimiter {
                                b"\n\r\n" | b"\r\r\n" => 2,
                                _ => delimiter.len(),
                            }
            }));
            assert!(buffer.is_empty());
        }
    }

    #[test]
    fn chooses_the_earliest_mixed_delimiter() {
        assert_eq!(frame_end(b"data: one\r\n\r\ndata: two\n\n"), Some((9, 3)));
        assert_eq!(frame_end(b"data: one\r\r"), Some((9, 2)));
    }

    #[test]
    fn parses_opencode_1_17_sse_fixture() {
        let events = include_bytes!("../tests/fixtures/events.sse")
            .split(|byte| *byte == b'\n')
            .collect::<Vec<_>>()
            .join(&b'\n');
        let mut remaining = events;
        let mut kinds = Vec::new();
        while let Some((end, delimiter)) = frame_end(&remaining) {
            let frame = remaining.drain(..end).collect::<Vec<_>>();
            remaining.drain(..delimiter);
            if let Ok(Some(event)) = parse_frame(&frame) {
                kinds.push(event.kind);
            }
        }
        assert_eq!(
            kinds,
            [
                "session.status",
                "session.error",
                "session.updated",
                "question.asked",
                "permission.asked",
                "question.rejected",
                "permission.replied",
            ]
        );
    }

    #[test]
    fn frame_limit_is_per_frame_after_complete_frames_are_drained() {
        let frame = b"data: {\"type\":\"server.connected\",\"properties\":{}}\n\n";
        let mut buffer = frame.repeat(MAX_SSE_FRAME_SIZE / frame.len() + 2);
        let mut search_from = 0;
        let parsed = drain_complete_frames(&mut buffer, &mut search_from);
        assert!(parsed.iter().all(Result::is_ok));
        assert!(buffer.is_empty());
    }

    #[test]
    fn rejects_complete_and_unterminated_oversized_frames() {
        let mut complete = vec![b'x'; MAX_SSE_FRAME_SIZE + 1];
        complete.extend_from_slice(b"\n\n");
        let mut search_from = 0;
        let decoded = drain_complete_frames(&mut complete, &mut search_from);
        assert!(matches!(
            decoded.as_slice(),
            [Err(ClientError::SseFrameTooLarge)]
        ));

        let mut unterminated = vec![b'x'; MAX_SSE_FRAME_SIZE + 1];
        let mut search_from = 0;
        let decoded = drain_complete_frames(&mut unterminated, &mut search_from);
        assert!(matches!(
            decoded.as_slice(),
            [Err(ClientError::SseFrameTooLarge)]
        ));
    }

    #[test]
    fn fragmented_frame_preserves_incremental_search_position() {
        let frame = b"data: {\"type\":\"server.connected\",\"properties\":{}}\n\n";
        let mut buffer = Vec::new();
        let mut search_from = 0;
        let mut events = Vec::new();
        for byte in frame {
            buffer.push(*byte);
            let decoded = drain_complete_frames(&mut buffer, &mut search_from);
            assert!(decoded.iter().all(Result::is_ok));
            events.extend(decoded.into_iter().filter_map(Result::ok));
        }
        assert_eq!(events.len(), 1);
        assert!(buffer.is_empty());
    }

    #[test]
    fn fragmented_bare_cr_record_is_immediate_and_swallows_following_lf() {
        let payload = b"data: {\"type\":\"server.connected\",\"properties\":{}}";
        let mut buffer = payload.to_vec();
        let mut search_from = 0;
        assert!(decode_next_frame(&mut buffer, &mut search_from, false).is_none());
        buffer.push(b'\r');
        assert!(decode_next_frame(&mut buffer, &mut search_from, false).is_none());
        buffer.push(b'\r');
        assert!(
            decode_next_frame(&mut buffer, &mut search_from, false).is_some_and(|event| {
                event.is_ok_and(|event| {
                    event.event.kind == "server.connected"
                        && event.source_bytes == payload.len() + 2
                })
            })
        );

        buffer.push(b'\n');
        buffer.extend_from_slice(payload);
        buffer.extend_from_slice(b"\n\n");
        assert!(
            decode_next_frame(&mut buffer, &mut search_from, false).is_some_and(|event| {
                event.is_ok_and(|event| {
                    event.event.kind == "server.connected"
                        && event.source_bytes == payload.len() + 2
                })
            })
        );
        assert!(buffer.is_empty());
    }

    #[test]
    fn leading_empty_records_do_not_change_frame_byte_accounting() {
        let payload = b"data: {\"type\":\"server.connected\",\"properties\":{}}";
        let mut buffer = b"\n\n\n\r\n\r\r\n".to_vec();
        buffer.extend_from_slice(payload);
        buffer.extend_from_slice(b"\r\r");
        let mut search_from = 0;
        assert!(
            decode_next_frame(&mut buffer, &mut search_from, false).is_some_and(|event| {
                event.is_ok_and(|event| event.source_bytes == payload.len() + 2)
            })
        );
        assert!(buffer.is_empty());
    }

    #[test]
    fn maximum_frame_accepts_fragmented_mixed_delimiters() {
        let prefix = b"data: {\"type\":\"server.connected\",\"properties\":{}}";
        for delimiter in [
            b"\n\n".as_slice(),
            b"\r\r".as_slice(),
            b"\r\n\r".as_slice(),
            b"\r\n\n".as_slice(),
            b"\r\n\r\n".as_slice(),
        ] {
            let mut buffer = prefix.to_vec();
            buffer.resize(MAX_SSE_FRAME_SIZE, b' ');
            let mut search_from = 0;
            assert!(decode_next_frame(&mut buffer, &mut search_from, false).is_none());
            let delivery_index = match delimiter {
                b"\n\n" | b"\r\r" => 1,
                b"\r\n\r" | b"\r\n\n" | b"\r\n\r\n" => 2,
                _ => unreachable!("all delimiters have a delivery index"),
            };
            for (index, byte) in delimiter.iter().enumerate() {
                buffer.push(*byte);
                let decoded = decode_next_frame(&mut buffer, &mut search_from, false);
                if index == delivery_index {
                    assert!(decoded.is_some_and(|event| event.is_ok_and(|event| {
                        event.event.kind == "server.connected"
                            && event.source_bytes == MAX_SSE_FRAME_SIZE + delivery_index + 1
                    })));
                } else {
                    assert!(decoded.is_none());
                }
            }
            assert!(decode_next_frame(&mut buffer, &mut search_from, true).is_none());
            assert!(buffer.is_empty());
        }
    }

    #[test]
    fn valid_frame_precedes_later_error_in_same_chunk() {
        let valid = b"data: {\"type\":\"server.connected\",\"properties\":{}}\n\n";
        let mut malformed = valid.to_vec();
        malformed.extend_from_slice(b"data: {\"type\":}\n\n");
        let mut search_from = 0;
        let decoded = decode_next_frame(&mut malformed, &mut search_from, false);
        assert!(
            decoded
                .as_ref()
                .is_some_and(|event| event.as_ref().is_ok_and(|event| {
                    event.event.kind == "server.connected" && event.source_bytes == valid.len()
                }))
        );
        assert!(!malformed.is_empty());
        assert!(matches!(
            decode_next_frame(&mut malformed, &mut search_from, false),
            Some(Err(ClientError::Json(_)))
        ));

        let mut oversized = valid.to_vec();
        oversized.extend(std::iter::repeat_n(b'x', MAX_SSE_FRAME_SIZE + 1));
        oversized.extend_from_slice(b"\r\n\r\n");
        let mut search_from = 0;
        let decoded = decode_next_frame(&mut oversized, &mut search_from, false);
        assert!(
            decoded
                .as_ref()
                .is_some_and(|event| event.as_ref().is_ok_and(|event| {
                    event.event.kind == "server.connected" && event.source_bytes == valid.len()
                }))
        );
        assert!(oversized.len() > MAX_SSE_FRAME_SIZE);
        assert!(matches!(
            decode_next_frame(&mut oversized, &mut search_from, false),
            Some(Err(ClientError::SseFrameTooLarge))
        ));

        let mut unterminated = valid.to_vec();
        unterminated.extend(std::iter::repeat_n(b'x', MAX_SSE_FRAME_SIZE + 4));
        let mut search_from = 0;
        assert!(
            decode_next_frame(&mut unterminated, &mut search_from, false).is_some_and(|event| {
                event.is_ok_and(|event| {
                    event.event.kind == "server.connected" && event.source_bytes == valid.len()
                })
            })
        );
        assert!(matches!(
            decode_next_frame(&mut unterminated, &mut search_from, false),
            Some(Err(ClientError::SseFrameTooLarge))
        ));
    }

    #[test]
    fn snapshot_session_request_has_explicit_large_limit() {
        assert_eq!(SESSION_PATH, "/session?limit=100000");
    }

    #[tokio::test]
    async fn snapshot_sends_the_explicit_session_limit() {
        let listener = TcpListener::bind("127.0.0.1:0").await;
        assert!(listener.is_ok());
        let listener = listener.unwrap_or_else(|error| unreachable!("bind succeeded: {error}"));
        let address = listener.local_addr();
        assert!(address.is_ok());
        let address = address.unwrap_or_else(|error| unreachable!("address exists: {error}"));
        let server = tokio::spawn(async move {
            let mut paths = HashSet::new();
            for _ in 0..4 {
                let accepted = listener.accept().await;
                assert!(accepted.is_ok());
                let (mut socket, _) =
                    accepted.unwrap_or_else(|error| unreachable!("accept succeeded: {error}"));
                let mut request = vec![0_u8; 4096];
                let count = socket
                    .read(&mut request)
                    .await
                    .unwrap_or_else(|error| unreachable!("read succeeded: {error}"));
                let request = String::from_utf8_lossy(&request[..count]);
                let path = request
                    .lines()
                    .next()
                    .and_then(|line| line.split_whitespace().nth(1))
                    .unwrap_or("<missing>")
                    .to_owned();
                let body = if path == "/session/status" {
                    "{}"
                } else {
                    "[]"
                };
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                socket
                    .write_all(response.as_bytes())
                    .await
                    .unwrap_or_else(|error| unreachable!("write succeeded: {error}"));
                paths.insert(path);
            }
            paths
        });
        let endpoint = ServerEndpoint::new(address);
        assert!(endpoint.is_ok());
        let client = OpenCodeClient::new(
            endpoint.unwrap_or_else(|error| unreachable!("loopback: {error}")),
            ClientConfig::default(),
        );
        assert!(client.is_ok());
        let snapshot = client
            .unwrap_or_else(|error| unreachable!("client builds: {error}"))
            .snapshot()
            .await;
        assert!(snapshot.is_ok());
        let paths = server
            .await
            .unwrap_or_else(|error| unreachable!("server joins: {error}"));
        assert!(paths.contains("/session?limit=100000"));
    }

    #[tokio::test]
    async fn v2_snapshot_paginates_and_marks_only_active_sessions_busy() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap_or_else(|error| unreachable!("bind succeeded: {error}"));
        let address = listener
            .local_addr()
            .unwrap_or_else(|error| unreachable!("address exists: {error}"));
        let server = tokio::spawn(async move {
            let mut paths = Vec::new();
            for _ in 0..3 {
                let (mut socket, _) = listener
                    .accept()
                    .await
                    .unwrap_or_else(|error| unreachable!("accept succeeded: {error}"));
                let mut request = vec![0_u8; 4096];
                let count = socket
                    .read(&mut request)
                    .await
                    .unwrap_or_else(|error| unreachable!("read succeeded: {error}"));
                let request = String::from_utf8_lossy(&request[..count]);
                let path = request
                    .lines()
                    .next()
                    .and_then(|line| line.split_whitespace().nth(1))
                    .unwrap_or_default()
                    .to_owned();
                let body = if path == "/api/session/active" {
                    r#"{"data":{"ses_2":{"type":"running"}}}"#
                } else if path.contains("cursor=") {
                    r#"{"data":[{"info":{"id":"ses_2","parentID":"ses_1","projectID":"prj","title":"Child","time":{"updated":22}},"location":{"directory":"/child","workspace":"/child-project"}}],"cursor":{}}"#
                } else {
                    r#"{"data":[{"id":"ses_1","projectID":"prj","title":"Root","time":{"updated":11}}],"cursor":{"next":"next page"},"location":{"directory":"/workspace","workspace":"/project"}}"#
                };
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                socket
                    .write_all(response.as_bytes())
                    .await
                    .unwrap_or_else(|error| unreachable!("write succeeded: {error}"));
                paths.push(path);
            }
            paths
        });
        let endpoint = ServerEndpoint::new(address)
            .unwrap_or_else(|error| unreachable!("loopback endpoint: {error}"));
        let snapshot = OpenCodeV2Client::new(endpoint, ClientConfig::default())
            .unwrap_or_else(|error| unreachable!("client builds: {error}"))
            .snapshot()
            .await
            .unwrap_or_else(|error| unreachable!("snapshot succeeds: {error}"));
        assert_eq!(snapshot.sessions.len(), 2);
        assert_eq!(snapshot.sessions[0].project_id.as_deref(), Some("prj"));
        assert_eq!(
            snapshot.sessions[0].directory.as_deref(),
            Some(std::path::Path::new("/workspace"))
        );
        assert_eq!(
            snapshot.sessions[0].workspace.as_deref(),
            Some(std::path::Path::new("/project"))
        );
        assert_eq!(snapshot.sessions[0].updated, Some(11));
        assert_eq!(snapshot.sessions[1].parent_id.as_deref(), Some("ses_1"));
        assert_eq!(
            snapshot.sessions[1].directory.as_deref(),
            Some(std::path::Path::new("/child"))
        );
        assert_eq!(
            snapshot.sessions[1].workspace.as_deref(),
            Some(std::path::Path::new("/child-project"))
        );
        assert_eq!(snapshot.sessions[1].updated, Some(22));
        assert_eq!(snapshot.statuses["ses_1"], SessionStatus::Idle);
        assert_eq!(snapshot.statuses["ses_2"], SessionStatus::Busy);
        let paths = server
            .await
            .unwrap_or_else(|error| unreachable!("server joins: {error}"));
        assert!(paths.iter().any(|path| path == "/api/session?limit=100"));
        assert!(paths.iter().any(|path| path.contains("cursor=next+page")));
    }

    #[test]
    fn credentials_are_redacted_from_debug() {
        let auth = BasicAuth::new(
            "user".to_owned(),
            SecretString::from("not-for-logs".to_owned()),
        );
        let rendered = format!("{auth:?}");
        assert!(rendered.contains("[REDACTED]"));
        assert!(!rendered.contains("not-for-logs"));
    }

    #[tokio::test]
    async fn event_header_wait_has_a_cancellable_timeout() {
        let listener = TcpListener::bind("127.0.0.1:0").await;
        assert!(listener.is_ok());
        let listener = listener.unwrap_or_else(|error| unreachable!("bind succeeded: {error}"));
        let address = listener.local_addr();
        assert!(address.is_ok());
        let address = address.unwrap_or_else(|error| unreachable!("address exists: {error}"));
        let server = tokio::spawn(async move {
            let accepted = listener.accept().await;
            if let Ok((mut socket, _)) = accepted {
                let mut request = [0_u8; 1024];
                let _ = socket.read(&mut request).await;
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        });
        let endpoint = ServerEndpoint::new(address);
        assert!(endpoint.is_ok());
        let config = ClientConfig {
            event_header_timeout: Duration::from_millis(20),
            ..ClientConfig::default()
        };
        let client = OpenCodeClient::new(
            endpoint.unwrap_or_else(|error| unreachable!("loopback: {error}")),
            config,
        );
        assert!(client.is_ok());
        let result = client
            .unwrap_or_else(|error| unreachable!("client builds: {error}"))
            .event_stream()
            .await;
        assert!(matches!(result, Err(ClientError::EventHeaderTimeout(_))));
        server.abort();
    }

    #[tokio::test]
    async fn established_event_body_outlives_request_timeout() {
        let listener = TcpListener::bind("127.0.0.1:0").await;
        assert!(listener.is_ok());
        let listener = listener.unwrap_or_else(|error| unreachable!("bind succeeded: {error}"));
        let address = listener.local_addr();
        assert!(address.is_ok());
        let address = address.unwrap_or_else(|error| unreachable!("address exists: {error}"));
        let server = tokio::spawn(async move {
            let accepted = listener.accept().await;
            assert!(accepted.is_ok());
            let (mut socket, _) =
                accepted.unwrap_or_else(|error| unreachable!("accept succeeded: {error}"));
            let mut request = [0_u8; 1024];
            assert!(socket.read(&mut request).await.is_ok());
            assert!(
                socket
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n",
                    )
                    .await
                    .is_ok()
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
            let payload = "data: {\"type\":\"server.connected\",\"properties\":{}}\n\n";
            let chunk = format!("{:X}\r\n{payload}\r\n", payload.len());
            assert!(socket.write_all(chunk.as_bytes()).await.is_ok());
            tokio::time::sleep(Duration::from_millis(50)).await;
        });
        let endpoint = ServerEndpoint::new(address);
        assert!(endpoint.is_ok());
        let config = ClientConfig {
            request_timeout: Duration::from_millis(10),
            event_header_timeout: Duration::from_millis(100),
            ..ClientConfig::default()
        };
        let client = OpenCodeClient::new(
            endpoint.unwrap_or_else(|error| unreachable!("loopback: {error}")),
            config,
        );
        assert!(client.is_ok());
        let stream = client
            .unwrap_or_else(|error| unreachable!("client builds: {error}"))
            .event_stream()
            .await;
        assert!(stream.is_ok());
        let mut stream = stream.unwrap_or_else(|error| unreachable!("headers arrive: {error}"));
        let event = tokio::time::timeout(Duration::from_secs(1), stream.next()).await;
        assert!(event.is_ok_and(|event| {
            event.is_some_and(|event| event.is_ok_and(|event| event.kind == "server.connected"))
        }));
        assert!(server.await.is_ok());
    }

    #[tokio::test]
    async fn repeated_event_stream_drops_close_every_peer_connection() {
        const CYCLES: usize = 3;
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap_or_else(|error| unreachable!("bind succeeded: {error}"));
        let address = listener
            .local_addr()
            .unwrap_or_else(|error| unreachable!("address exists: {error}"));
        let server = tokio::spawn(async move {
            for _ in 0..CYCLES {
                let (mut socket, _) = listener
                    .accept()
                    .await
                    .unwrap_or_else(|error| unreachable!("accept succeeded: {error}"));
                let mut request = [0_u8; 1024];
                assert!(socket.read(&mut request).await.is_ok());
                assert!(
                    socket
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n",
                        )
                        .await
                        .is_ok()
                );
                let mut byte = [0_u8; 1];
                if !tokio::time::timeout(Duration::from_secs(1), socket.read(&mut byte))
                    .await
                    .is_ok_and(|result| result.is_ok_and(|read| read == 0))
                {
                    return false;
                }
            }
            true
        });
        let endpoint =
            ServerEndpoint::new(address).unwrap_or_else(|error| unreachable!("loopback: {error}"));
        let client = OpenCodeClient::new(endpoint, ClientConfig::default())
            .unwrap_or_else(|error| unreachable!("client builds: {error}"));

        for _ in 0..CYCLES {
            let stream = client
                .event_stream()
                .await
                .unwrap_or_else(|error| unreachable!("stream opens: {error}"));
            drop(stream);
        }

        assert!(server.await.is_ok_and(|closed| closed));
    }

    #[tokio::test]
    async fn event_stream_requires_ok_sse_content_type_before_opening() {
        for (status, content_type, expected) in [
            ("204 No Content", None, "OpenCode returned 204"),
            (
                "200 OK",
                Some("application/json"),
                "unexpected Content-Type",
            ),
            ("200 OK", None, "unexpected Content-Type"),
        ] {
            let listener = TcpListener::bind("127.0.0.1:0")
                .await
                .unwrap_or_else(|error| unreachable!("bind succeeded: {error}"));
            let address = listener
                .local_addr()
                .unwrap_or_else(|error| unreachable!("address exists: {error}"));
            let server = tokio::spawn(async move {
                let (mut socket, _) = listener
                    .accept()
                    .await
                    .unwrap_or_else(|error| unreachable!("accept succeeded: {error}"));
                let mut request = [0_u8; 1024];
                assert!(socket.read(&mut request).await.is_ok());
                let content_type = content_type
                    .map(|value| format!("Content-Type: {value}\r\n"))
                    .unwrap_or_default();
                let response = format!(
                    "HTTP/1.1 {status}\r\n{content_type}Content-Length: 0\r\nConnection: close\r\n\r\n"
                );
                assert!(socket.write_all(response.as_bytes()).await.is_ok());
            });
            let endpoint = ServerEndpoint::new(address)
                .unwrap_or_else(|error| unreachable!("loopback: {error}"));
            let client = OpenCodeClient::new(endpoint, ClientConfig::default())
                .unwrap_or_else(|error| unreachable!("client builds: {error}"));
            let error = client
                .event_stream()
                .await
                .err()
                .unwrap_or_else(|| unreachable!("response must be rejected"));
            assert!(error.to_string().contains(expected));
            assert!(server.await.is_ok());
        }

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap_or_else(|error| unreachable!("bind succeeded: {error}"));
        let address = listener
            .local_addr()
            .unwrap_or_else(|error| unreachable!("address exists: {error}"));
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener
                .accept()
                .await
                .unwrap_or_else(|error| unreachable!("accept succeeded: {error}"));
            let mut request = [0_u8; 1024];
            assert!(socket.read(&mut request).await.is_ok());
            let body = "data: {\"type\":\"server.connected\",\"properties\":{}}\n\n";
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: TeXt/EvEnT-StReAm; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            assert!(socket.write_all(response.as_bytes()).await.is_ok());
        });
        let endpoint =
            ServerEndpoint::new(address).unwrap_or_else(|error| unreachable!("loopback: {error}"));
        let client = OpenCodeClient::new(endpoint, ClientConfig::default())
            .unwrap_or_else(|error| unreachable!("client builds: {error}"));
        let mut stream = client
            .event_stream()
            .await
            .unwrap_or_else(|error| unreachable!("SSE content type accepted: {error}"));
        assert!(stream.next().await.is_some_and(|event| event.is_ok()));
        assert!(server.await.is_ok());
    }

    #[tokio::test]
    async fn bare_cr_record_is_delivered_while_body_remains_idle() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap_or_else(|error| unreachable!("bind succeeded: {error}"));
        let address = listener
            .local_addr()
            .unwrap_or_else(|error| unreachable!("address exists: {error}"));
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener
                .accept()
                .await
                .unwrap_or_else(|error| unreachable!("accept succeeded: {error}"));
            let mut request = [0_u8; 1024];
            assert!(socket.read(&mut request).await.is_ok());
            assert!(socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n").await.is_ok());
            let payload = "data: {\"type\":\"server.connected\",\"properties\":{}}\r\r";
            let chunk = format!("{:X}\r\n{payload}\r\n", payload.len());
            assert!(socket.write_all(chunk.as_bytes()).await.is_ok());
            tokio::time::sleep(Duration::from_millis(200)).await;
        });
        let endpoint =
            ServerEndpoint::new(address).unwrap_or_else(|error| unreachable!("loopback: {error}"));
        let client = OpenCodeClient::new(endpoint, ClientConfig::default())
            .unwrap_or_else(|error| unreachable!("client builds: {error}"));
        let mut stream = client
            .source_event_stream()
            .await
            .unwrap_or_else(|error| unreachable!("stream opens: {error}"));
        let event = tokio::time::timeout(Duration::from_millis(100), stream.next()).await;
        assert!(event.is_ok_and(|event| event.is_some_and(|event| event.is_ok())));
        assert!(server.await.is_ok());
    }

    #[tokio::test]
    async fn public_stream_yields_valid_frame_before_same_chunk_parse_error() {
        let listener = TcpListener::bind("127.0.0.1:0").await;
        assert!(listener.is_ok());
        let listener = listener.unwrap_or_else(|error| unreachable!("bind succeeded: {error}"));
        let address = listener.local_addr();
        assert!(address.is_ok());
        let address = address.unwrap_or_else(|error| unreachable!("address exists: {error}"));
        let server = tokio::spawn(async move {
            let accepted = listener.accept().await;
            assert!(accepted.is_ok());
            let (mut socket, _) =
                accepted.unwrap_or_else(|error| unreachable!("accept succeeded: {error}"));
            let mut request = [0_u8; 1024];
            assert!(socket.read(&mut request).await.is_ok());
            let body = concat!(
                "data: {\"type\":\"server.connected\",\"properties\":{}}\n\n",
                "data: {\"type\":}\n\n"
            );
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            assert!(socket.write_all(response.as_bytes()).await.is_ok());
        });
        let endpoint = ServerEndpoint::new(address);
        assert!(endpoint.is_ok());
        let client = OpenCodeClient::new(
            endpoint.unwrap_or_else(|error| unreachable!("loopback: {error}")),
            ClientConfig::default(),
        );
        assert!(client.is_ok());
        let stream = client
            .unwrap_or_else(|error| unreachable!("client builds: {error}"))
            .event_stream()
            .await;
        assert!(stream.is_ok());
        let mut stream = stream.unwrap_or_else(|error| unreachable!("stream opens: {error}"));
        let first = stream.next().await;
        assert!(
            first
                .is_some_and(|event| { event.is_ok_and(|event| event.kind == "server.connected") })
        );
        assert!(matches!(
            stream.next().await,
            Some(Err(ClientError::Json(_)))
        ));
        assert!(server.await.is_ok());
    }

    #[tokio::test]
    async fn bare_cr_frame_precedes_truncated_body_error() {
        let body = "data: {\"type\":\"server.connected\",\"properties\":{}}\r\r";
        let listener = TcpListener::bind("127.0.0.1:0").await;
        assert!(listener.is_ok());
        let listener = listener.unwrap_or_else(|error| unreachable!("bind succeeded: {error}"));
        let address = listener.local_addr();
        assert!(address.is_ok());
        let address = address.unwrap_or_else(|error| unreachable!("address exists: {error}"));
        let server = tokio::spawn(async move {
            let accepted = listener.accept().await;
            assert!(accepted.is_ok());
            let (mut socket, _) =
                accepted.unwrap_or_else(|error| unreachable!("accept succeeded: {error}"));
            let mut request = [0_u8; 1024];
            assert!(socket.read(&mut request).await.is_ok());
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len() + 1
            );
            assert!(socket.write_all(response.as_bytes()).await.is_ok());
        });
        let endpoint = ServerEndpoint::new(address);
        assert!(endpoint.is_ok());
        let client = OpenCodeClient::new(
            endpoint.unwrap_or_else(|error| unreachable!("loopback: {error}")),
            ClientConfig::default(),
        );
        assert!(client.is_ok());
        let stream = client
            .unwrap_or_else(|error| unreachable!("client builds: {error}"))
            .source_event_stream()
            .await;
        assert!(stream.is_ok());
        let mut stream = stream.unwrap_or_else(|error| unreachable!("stream opens: {error}"));
        assert!(
            stream
                .next()
                .await
                .is_some_and(|event| event.is_ok_and(|event| {
                    event.event.kind == "server.connected" && event.source_bytes == body.len()
                }))
        );
        assert!(matches!(
            stream.next().await,
            Some(Err(ClientError::Transport(_)))
        ));
        assert!(server.await.is_ok());
    }

    #[tokio::test]
    async fn authenticated_loopback_request_sends_redacted_basic_auth() {
        let listener = TcpListener::bind("127.0.0.1:0").await;
        assert!(listener.is_ok());
        let listener = listener.unwrap_or_else(|error| unreachable!("bind succeeded: {error}"));
        let address = listener.local_addr();
        assert!(address.is_ok());
        let address = address.unwrap_or_else(|error| unreachable!("address exists: {error}"));
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
            let body = "{\"healthy\":true,\"version\":\"1.17.4\"}";
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
        let endpoint = ServerEndpoint::new(address);
        assert!(endpoint.is_ok());
        let config = ClientConfig {
            auth: Some(BasicAuth::new(
                "user".to_owned(),
                SecretString::from("secret".to_owned()),
            )),
            ..ClientConfig::default()
        };
        let client = OpenCodeClient::new(
            endpoint.unwrap_or_else(|error| unreachable!("loopback: {error}")),
            config,
        );
        assert!(client.is_ok());
        let health = client
            .unwrap_or_else(|error| unreachable!("client builds: {error}"))
            .health()
            .await;
        assert!(health.is_ok());
        let request = server
            .await
            .unwrap_or_else(|error| unreachable!("server joins: {error}"));
        assert!(request.contains("authorization: Basic "));
        assert!(!request.contains("secret"));
    }
}
