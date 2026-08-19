use std::collections::{HashMap, HashSet};

use serde::Deserialize;
use serde_json::Value;

use crate::model::{
    ActivityState, AttentionEvent, AttentionKind, ObservedEvent, PermissionRequest,
    ProjectedSession, QuestionRequest, Session, SessionStatus, Snapshot, StateTransition,
    TransitionSource, WireEvent,
};

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct SessionRecord {
    metadata_known: bool,
    title: String,
    slug: String,
    parent_id: Option<String>,
    project_id: Option<String>,
    directory: Option<std::path::PathBuf>,
    workspace: Option<std::path::PathBuf>,
    updated: Option<u64>,
    status: SessionStatus,
    permissions: HashSet<String>,
    questions: HashSet<String>,
}

impl SessionRecord {
    fn activity(&self) -> ActivityState {
        if !self.questions.is_empty() {
            ActivityState::WaitingForInput
        } else if !self.permissions.is_empty() {
            ActivityState::WaitingForPermission
        } else {
            match self.status {
                SessionStatus::Retry { .. } => ActivityState::Retrying,
                SessionStatus::Busy => ActivityState::Working,
                SessionStatus::Idle | SessionStatus::Unknown => ActivityState::Idle,
            }
        }
    }

    fn update_metadata(&mut self, session: Session) {
        self.metadata_known = true;
        self.title = session.title;
        self.slug = session.slug;
        self.parent_id = session.parent_id;
        self.project_id = session.project_id;
        self.directory = session.directory;
        self.workspace = session.workspace;
        self.updated = session.updated;
    }
}

/// The derived results of one state mutation.
#[must_use]
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct StateUpdate {
    pub transitions: Vec<StateTransition>,
    pub attention: Vec<AttentionEvent>,
}

#[derive(Clone, Copy)]
enum PendingKind {
    Permission,
    Question,
}

struct NewRequest {
    kind: PendingKind,
    request_id: String,
    subject_session_id: String,
}

#[derive(Clone, Copy)]
struct AttentionContext {
    source: TransitionSource,
    initial: bool,
    root_resolved: bool,
}

/// In-memory state for one `OpenCode` server.
#[derive(Clone, Debug, Default)]
pub struct ServerState {
    sessions: HashMap<String, SessionRecord>,
    permissions: HashMap<String, String>,
    questions: HashMap<String, String>,
    seen_permissions: HashSet<String>,
    seen_questions: HashSet<String>,
    ready_armed: HashSet<String>,
}

impl ServerState {
    /// Returns the number of non-idle sessions.
    #[must_use]
    pub fn active_session_count(&self) -> usize {
        self.sessions
            .values()
            .filter(|session| session.activity() != ActivityState::Idle)
            .count()
    }

    /// Returns a deterministic, privacy-limited projection of all current sessions.
    #[must_use]
    pub fn projection(&self) -> Vec<ProjectedSession> {
        let mut sessions = self
            .sessions
            .iter()
            .map(|(id, record)| {
                let mut pending_permission_ids =
                    record.permissions.iter().cloned().collect::<Vec<_>>();
                pending_permission_ids.sort_unstable();
                let mut pending_question_ids = record.questions.iter().cloned().collect::<Vec<_>>();
                pending_question_ids.sort_unstable();
                ProjectedSession {
                    id: id.clone(),
                    title: record.title.clone(),
                    slug: record.slug.clone(),
                    parent_id: record.parent_id.clone(),
                    project_id: record.project_id.clone(),
                    directory: record.directory.clone(),
                    workspace: record.workspace.clone(),
                    updated: record.updated,
                    status: (&record.status).into(),
                    pending_permission_ids,
                    pending_question_ids,
                }
            })
            .collect::<Vec<_>>();
        sessions.sort_unstable_by(|left, right| left.id.cmp(&right.id));
        sessions
    }

    /// Replaces state and returns only transitions, discarding derived attention.
    ///
    /// Consumers of the attention feed should use [`Self::reconcile_with_updates`]
    /// consistently instead of mixing the two APIs.
    pub fn reconcile(&mut self, snapshot: Snapshot) -> Vec<StateTransition> {
        self.reconcile_with_updates(snapshot, false).transitions
    }

    /// Replaces state with a complete snapshot and derives transitions and attention.
    pub fn reconcile_with_updates(&mut self, snapshot: Snapshot, initial: bool) -> StateUpdate {
        self.reconcile_replayed_with_updates(snapshot, std::iter::empty(), initial, &HashSet::new())
    }

    pub(crate) fn reconcile_replayed_with_updates<'a>(
        &mut self,
        snapshot: Snapshot,
        events: impl IntoIterator<Item = &'a WireEvent>,
        initial: bool,
        live_ready_emitted: &HashSet<String>,
    ) -> StateUpdate {
        let previous = self.activities();
        let mut candidate = Self {
            seen_permissions: self.seen_permissions.clone(),
            seen_questions: self.seen_questions.clone(),
            ready_armed: self.ready_armed.clone(),
            ..Self::default()
        };
        candidate.install_snapshot(snapshot);
        let snapshot_busy_roots = candidate.busy_roots();
        for event in events {
            let _ = candidate.apply_event_core(event);
        }
        candidate.normalize_ready_arms();
        candidate
            .ready_armed
            .extend(snapshot_busy_roots.difference(live_ready_emitted).cloned());
        candidate.arm_busy_roots();

        let mut attention = candidate.new_snapshot_request_attention(initial);
        if initial {
            candidate.disarm_initially_idle_roots();
        } else {
            attention.extend(candidate.take_ready_attention(TransitionSource::Snapshot));
        }
        attention.sort_by(attention_order);
        *self = candidate;
        StateUpdate {
            transitions: self.transitions_from(&previous, TransitionSource::Snapshot),
            attention,
        }
    }

    /// Applies one event and returns only transitions, discarding derived attention.
    ///
    /// Consumers of the attention feed should use [`Self::apply_event_with_updates`]
    /// consistently instead of mixing the two APIs.
    pub fn apply_event(&mut self, event: &WireEvent) -> Vec<StateTransition> {
        self.apply_event_with_updates(event).transitions
    }

    /// Applies one live SSE event and derives transitions and attention.
    pub fn apply_event_with_updates(&mut self, event: &WireEvent) -> StateUpdate {
        let previous = self.activities();
        let new_request = self.apply_event_core(event);
        self.normalize_ready_arms();
        self.arm_busy_roots();

        let mut attention = new_request
            .and_then(|request| self.new_live_request_attention(request))
            .into_iter()
            .collect::<Vec<_>>();
        attention.extend(self.take_ready_attention(TransitionSource::Live));
        attention.sort_by(attention_order);
        StateUpdate {
            transitions: self.transitions_from(&previous, TransitionSource::Live),
            attention,
        }
    }

    /// Produces a privacy-conscious direct observation from a wire event.
    #[must_use]
    pub fn observe(event: &WireEvent) -> ObservedEvent {
        let session_id = string_field(&event.properties, "sessionID").or_else(|| {
            event
                .properties
                .get("info")
                .and_then(|info| string_field(info, "id"))
        });
        let request_id = string_field(&event.properties, "requestID")
            .or_else(|| string_field(&event.properties, "id"));
        let detail = if event.kind == "session.error" {
            Some(error_detail(&event.properties))
        } else if event.kind == "permission.replied" {
            string_field(&event.properties, "reply")
        } else {
            None
        };
        ObservedEvent {
            kind: event.kind.clone(),
            session_id,
            request_id,
            detail,
        }
    }

    fn activities(&self) -> HashMap<String, ActivityState> {
        self.sessions
            .iter()
            .map(|(id, record)| (id.clone(), record.activity()))
            .collect()
    }

    fn transitions_from(
        &self,
        previous: &HashMap<String, ActivityState>,
        source: TransitionSource,
    ) -> Vec<StateTransition> {
        let current = self.activities();
        let mut ids = previous
            .keys()
            .chain(current.keys())
            .cloned()
            .collect::<HashSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        ids.sort_unstable();
        ids.into_iter()
            .filter_map(|session_id| {
                let old = previous
                    .get(&session_id)
                    .copied()
                    .unwrap_or(ActivityState::Idle);
                let new = current
                    .get(&session_id)
                    .copied()
                    .unwrap_or(ActivityState::Idle);
                (old != new).then_some(StateTransition {
                    session_id,
                    previous: old,
                    current: new,
                    source,
                })
            })
            .collect()
    }

    fn install_snapshot(&mut self, snapshot: Snapshot) {
        for session in snapshot.sessions {
            let id = session.id.clone();
            self.sessions
                .entry(id)
                .or_default()
                .update_metadata(session);
        }
        for (session_id, status) in snapshot.statuses {
            self.sessions.entry(session_id).or_default().status = status;
        }
        for request in snapshot.permissions {
            self.upsert_permission(request);
        }
        for request in snapshot.questions {
            self.upsert_question(request);
        }
    }

    fn apply_event_core(&mut self, event: &WireEvent) -> Option<NewRequest> {
        match event.kind.as_str() {
            "session.status" => self.apply_status(&event.properties),
            "session.created" | "session.updated" => self.apply_session_info(&event.properties),
            "session.renamed" => self.rename_session(&event.properties),
            "session.deleted" => self.delete_session(&event.properties),
            "permission.asked" => {
                if let Ok(request) =
                    serde_json::from_value::<PermissionRequest>(event.properties.clone())
                {
                    let new_request = NewRequest {
                        kind: PendingKind::Permission,
                        request_id: request.id.clone(),
                        subject_session_id: request.session_id.clone(),
                    };
                    self.upsert_permission(request);
                    return Some(new_request);
                }
            }
            "permission.replied" => self.remove_permission(&event.properties),
            "question.asked" => {
                if let Ok(request) =
                    serde_json::from_value::<QuestionRequest>(event.properties.clone())
                {
                    let new_request = NewRequest {
                        kind: PendingKind::Question,
                        request_id: request.id.clone(),
                        subject_session_id: request.session_id.clone(),
                    };
                    self.upsert_question(request);
                    return Some(new_request);
                }
            }
            "question.replied" | "question.rejected" => {
                self.remove_question(&event.properties);
            }
            _ => {}
        }
        None
    }

    fn apply_status(&mut self, properties: &Value) {
        #[derive(Deserialize)]
        struct Properties {
            #[serde(rename = "sessionID")]
            session_id: String,
            status: SessionStatus,
        }
        if let Ok(properties) = serde_json::from_value::<Properties>(properties.clone()) {
            self.sessions
                .entry(properties.session_id)
                .or_default()
                .status = properties.status;
        }
    }

    fn apply_session_info(&mut self, properties: &Value) {
        if let Some(info) = properties.get("info")
            && let Ok(session) = serde_json::from_value::<Session>(info.clone())
        {
            let id = session.id.clone();
            self.sessions
                .entry(id)
                .or_default()
                .update_metadata(session);
        }
    }

    fn rename_session(&mut self, properties: &Value) {
        if let (Some(session_id), Some(title)) = (
            string_field(properties, "sessionID"),
            string_field(properties, "title"),
        ) && let Some(session) = self.sessions.get_mut(&session_id)
        {
            session.title = title;
        }
    }

    fn delete_session(&mut self, properties: &Value) {
        let id = properties
            .get("info")
            .and_then(|info| string_field(info, "id"))
            .or_else(|| string_field(properties, "sessionID"));
        if let Some(id) = id {
            self.sessions.remove(&id);
            let permission_ids = self
                .permissions
                .iter()
                .filter(|(_, session_id)| *session_id == &id)
                .map(|(request_id, _)| request_id.clone())
                .collect::<Vec<_>>();
            for request_id in permission_ids {
                self.permissions.remove(&request_id);
            }
            let question_ids = self
                .questions
                .iter()
                .filter(|(_, session_id)| *session_id == &id)
                .map(|(request_id, _)| request_id.clone())
                .collect::<Vec<_>>();
            for request_id in question_ids {
                self.questions.remove(&request_id);
            }
            self.ready_armed.remove(&id);
        }
    }

    fn upsert_permission(&mut self, request: PermissionRequest) {
        if let Some(previous_session_id) = self
            .permissions
            .insert(request.id.clone(), request.session_id.clone())
            && previous_session_id != request.session_id
            && let Some(previous) = self.sessions.get_mut(&previous_session_id)
        {
            previous.permissions.remove(&request.id);
        }
        self.sessions
            .entry(request.session_id.clone())
            .or_default()
            .permissions
            .insert(request.id);
    }

    fn remove_permission(&mut self, properties: &Value) {
        if let Some(request_id) = string_field(properties, "requestID")
            && let Some(session_id) = self.permissions.remove(&request_id)
            && let Some(session) = self.sessions.get_mut(&session_id)
        {
            session.permissions.remove(&request_id);
        }
    }

    fn upsert_question(&mut self, request: QuestionRequest) {
        if let Some(previous_session_id) = self
            .questions
            .insert(request.id.clone(), request.session_id.clone())
            && previous_session_id != request.session_id
            && let Some(previous) = self.sessions.get_mut(&previous_session_id)
        {
            previous.questions.remove(&request.id);
        }
        self.sessions
            .entry(request.session_id.clone())
            .or_default()
            .questions
            .insert(request.id);
    }

    fn remove_question(&mut self, properties: &Value) {
        if let Some(request_id) = string_field(properties, "requestID")
            && let Some(session_id) = self.questions.remove(&request_id)
            && let Some(session) = self.sessions.get_mut(&session_id)
        {
            session.questions.remove(&request_id);
        }
    }

    fn new_live_request_attention(&mut self, request: NewRequest) -> Option<AttentionEvent> {
        let first_seen = match request.kind {
            PendingKind::Permission => self.seen_permissions.insert(request.request_id.clone()),
            PendingKind::Question => self.seen_questions.insert(request.request_id.clone()),
        };
        first_seen.then(|| {
            self.request_attention(
                request.kind,
                request.subject_session_id,
                request.request_id,
                TransitionSource::Live,
                false,
            )
        })
    }

    fn new_snapshot_request_attention(&mut self, initial: bool) -> Vec<AttentionEvent> {
        let mut new_permissions = self
            .permissions
            .iter()
            .filter(|(request_id, _)| !self.seen_permissions.contains(*request_id))
            .map(|(request_id, session_id)| (request_id.clone(), session_id.clone()))
            .collect::<Vec<_>>();
        let mut new_questions = self
            .questions
            .iter()
            .filter(|(request_id, _)| !self.seen_questions.contains(*request_id))
            .map(|(request_id, session_id)| (request_id.clone(), session_id.clone()))
            .collect::<Vec<_>>();
        new_permissions.sort_unstable();
        new_questions.sort_unstable();

        let mut attention = Vec::new();
        for (request_id, session_id) in new_questions {
            self.seen_questions.insert(request_id.clone());
            attention.push(self.request_attention(
                PendingKind::Question,
                session_id,
                request_id,
                TransitionSource::Snapshot,
                initial,
            ));
        }
        for (request_id, session_id) in new_permissions {
            self.seen_permissions.insert(request_id.clone());
            attention.push(self.request_attention(
                PendingKind::Permission,
                session_id,
                request_id,
                TransitionSource::Snapshot,
                initial,
            ));
        }
        attention
    }

    fn request_attention(
        &self,
        kind: PendingKind,
        subject_session_id: String,
        request_id: String,
        source: TransitionSource,
        initial: bool,
    ) -> AttentionEvent {
        let (root_session_id, root_resolved) = self.resolve_root(&subject_session_id);
        self.attention_event(
            match kind {
                PendingKind::Permission => AttentionKind::Permission,
                PendingKind::Question => AttentionKind::Question,
            },
            root_session_id,
            subject_session_id,
            Some(request_id),
            AttentionContext {
                source,
                initial,
                root_resolved,
            },
        )
    }

    fn attention_event(
        &self,
        kind: AttentionKind,
        root_session_id: String,
        subject_session_id: String,
        request_id: Option<String>,
        context: AttentionContext,
    ) -> AttentionEvent {
        let root = self.sessions.get(&root_session_id);
        AttentionEvent {
            kind,
            root_session_id,
            root_title: root
                .filter(|record| record.metadata_known)
                .map(|record| record.title.clone()),
            root_slug: root
                .filter(|record| record.metadata_known)
                .map(|record| record.slug.clone()),
            subject_session_id,
            request_id,
            source: context.source,
            initial: context.initial,
            root_resolved: context.root_resolved,
        }
    }

    fn resolve_root(&self, subject_session_id: &str) -> (String, bool) {
        let mut current = subject_session_id.to_owned();
        let mut visited = HashSet::new();
        loop {
            if !visited.insert(current.clone()) {
                return (subject_session_id.to_owned(), false);
            }
            let Some(record) = self
                .sessions
                .get(&current)
                .filter(|record| record.metadata_known)
            else {
                return (subject_session_id.to_owned(), false);
            };
            let Some(parent_id) = &record.parent_id else {
                return (current, true);
            };
            if !self
                .sessions
                .get(parent_id)
                .is_some_and(|parent| parent.metadata_known)
            {
                return (subject_session_id.to_owned(), false);
            }
            current.clone_from(parent_id);
        }
    }

    fn normalize_ready_arms(&mut self) {
        self.ready_armed.retain(|session_id| {
            self.sessions
                .get(session_id)
                .is_some_and(|record| record.metadata_known && record.parent_id.is_none())
        });
    }

    fn arm_busy_roots(&mut self) {
        self.ready_armed.extend(
            self.sessions
                .iter()
                .filter(|(_, record)| {
                    record.metadata_known
                        && record.parent_id.is_none()
                        && matches!(
                            record.status,
                            SessionStatus::Busy | SessionStatus::Retry { .. }
                        )
                })
                .map(|(session_id, _)| session_id.clone()),
        );
    }

    fn busy_roots(&self) -> HashSet<String> {
        self.sessions
            .iter()
            .filter(|(_, record)| {
                record.metadata_known
                    && record.parent_id.is_none()
                    && matches!(
                        record.status,
                        SessionStatus::Busy | SessionStatus::Retry { .. }
                    )
            })
            .map(|(session_id, _)| session_id.clone())
            .collect()
    }

    fn disarm_initially_idle_roots(&mut self) {
        let idle = self
            .ready_armed
            .iter()
            .filter(|root_id| self.root_is_effectively_idle(root_id))
            .cloned()
            .collect::<Vec<_>>();
        for root_id in idle {
            self.ready_armed.remove(&root_id);
        }
    }

    fn take_ready_attention(&mut self, source: TransitionSource) -> Vec<AttentionEvent> {
        let mut ready = self
            .ready_armed
            .iter()
            .filter(|root_id| self.root_is_effectively_idle(root_id))
            .cloned()
            .collect::<Vec<_>>();
        ready.sort_unstable();
        for root_id in &ready {
            self.ready_armed.remove(root_id);
        }
        ready
            .into_iter()
            .map(|root_id| {
                self.attention_event(
                    AttentionKind::Ready,
                    root_id.clone(),
                    root_id,
                    None,
                    AttentionContext {
                        source,
                        initial: false,
                        root_resolved: true,
                    },
                )
            })
            .collect()
    }

    fn root_is_effectively_idle(&self, root_id: &str) -> bool {
        let own_idle = self.sessions.get(root_id).is_some_and(|record| {
            matches!(record.status, SessionStatus::Idle | SessionStatus::Unknown)
        });
        own_idle
            && !self
                .permissions
                .values()
                .chain(self.questions.values())
                .any(|subject_id| self.resolve_root(subject_id).0 == root_id)
    }
}

fn attention_order(left: &AttentionEvent, right: &AttentionEvent) -> std::cmp::Ordering {
    left.root_session_id
        .cmp(&right.root_session_id)
        .then_with(|| left.kind.cmp(&right.kind))
        .then_with(|| left.request_id.cmp(&right.request_id))
        .then_with(|| left.subject_session_id.cmp(&right.subject_session_id))
}

fn string_field(value: &Value, key: &str) -> Option<String> {
    value.get(key)?.as_str().map(ToOwned::to_owned)
}

fn error_detail(properties: &Value) -> String {
    let error = properties.get("error").unwrap_or(properties);
    let name = string_field(error, "name")
        .or_else(|| string_field(error, "type"))
        .or_else(|| string_field(error, "code"));
    let message = string_field(error, "message").or_else(|| {
        error
            .get("data")
            .and_then(|data| string_field(data, "message"))
    });
    match (name, message) {
        (Some(name), Some(message)) => format!("{name}: {message}"),
        (Some(name), None) => name,
        (None, Some(message)) => message,
        (None, None) => "unknown error".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use serde_json::json;

    use super::*;
    use crate::model::{Session, WireEvent};

    fn event(kind: &str, properties: Value) -> WireEvent {
        WireEvent {
            kind: kind.to_owned(),
            properties,
        }
    }

    fn session(id: &str, title: &str, slug: &str, parent_id: Option<&str>) -> Session {
        Session {
            id: id.to_owned(),
            title: title.to_owned(),
            slug: slug.to_owned(),
            parent_id: parent_id.map(ToOwned::to_owned),
            ..Session::default()
        }
    }

    fn snapshot(sessions: Vec<Session>) -> Snapshot {
        Snapshot {
            sessions,
            ..Snapshot::default()
        }
    }

    #[test]
    fn live_events_follow_required_priority() {
        let mut state = ServerState::default();
        state.apply_event(&event(
            "session.status",
            json!({"sessionID": "s", "status": {"type": "busy"}}),
        ));
        assert_eq!(state.active_session_count(), 1);

        let transitions = state.apply_event(&event(
            "permission.asked",
            json!({"id": "p", "sessionID": "s", "permission": "bash"}),
        ));
        assert_eq!(transitions[0].current, ActivityState::WaitingForPermission);

        let transitions = state.apply_event(&event(
            "question.asked",
            json!({"id": "q", "sessionID": "s", "questions": []}),
        ));
        assert_eq!(transitions[0].current, ActivityState::WaitingForInput);

        let transitions = state.apply_event(&event(
            "question.replied",
            json!({"requestID": "q", "sessionID": "s", "answers": []}),
        ));
        assert_eq!(transitions[0].current, ActivityState::WaitingForPermission);
    }

    #[test]
    fn snapshot_authoritatively_repairs_live_state() {
        let mut state = ServerState::default();
        state.apply_event(&event(
            "session.status",
            json!({"sessionID": "s", "status": {"type": "busy"}}),
        ));
        let transitions = state.reconcile(Snapshot {
            sessions: vec![Session {
                id: "s".to_owned(),
                ..Session::default()
            }],
            statuses: HashMap::new(),
            permissions: Vec::new(),
            questions: Vec::new(),
        });
        assert_eq!(transitions[0].previous, ActivityState::Working);
        assert_eq!(transitions[0].current, ActivityState::Idle);
        assert_eq!(transitions[0].source, TransitionSource::Snapshot);
    }

    #[test]
    fn projection_is_complete_sorted_and_privacy_limited() {
        let mut state = ServerState::default();
        let _ = state.reconcile_with_updates(
            Snapshot {
                sessions: vec![
                    session("z", "Root title", "root-slug", None),
                    session("a", "Child title", "child-slug", Some("z")),
                ],
                statuses: HashMap::from([(
                    "z".to_owned(),
                    SessionStatus::Retry {
                        attempt: 1,
                        message: "private retry message".to_owned(),
                        next: 2,
                    },
                )]),
                permissions: vec![PermissionRequest {
                    id: "p".to_owned(),
                    session_id: "a".to_owned(),
                }],
                questions: vec![QuestionRequest {
                    id: "q".to_owned(),
                    session_id: "a".to_owned(),
                }],
            },
            true,
        );
        let projection = state.projection();
        assert_eq!(
            projection
                .iter()
                .map(|session| session.id.as_str())
                .collect::<Vec<_>>(),
            ["a", "z"]
        );
        assert_eq!(projection[0].parent_id.as_deref(), Some("z"));
        assert_eq!(projection[0].pending_question_ids, ["q"]);
        assert_eq!(projection[0].pending_permission_ids, ["p"]);
        assert_eq!(projection[1].status, crate::model::ProjectedStatus::Retry);
        let rendered = format!("{projection:?}");
        assert!(!rendered.contains("question text"));
        assert!(!rendered.contains("permission pattern"));
        assert!(!rendered.contains("answer"));
        assert!(!rendered.contains("private retry message"));
    }

    #[test]
    fn projection_tracks_live_metadata_requests_and_deletion() {
        let mut state = ServerState::default();
        let _ =
            state.reconcile_with_updates(snapshot(vec![session("root", "Old", "old", None)]), true);
        let _ = state.apply_event_with_updates(&event(
            "session.updated",
            json!({"info": {"id": "root", "title": "New", "slug": "new"}}),
        ));
        let _ = state.apply_event_with_updates(&event(
            "question.asked",
            json!({"id": "q", "sessionID": "root", "questions": [{"question": "secret"}]}),
        ));
        let projection = state.projection();
        assert_eq!(projection[0].title, "New");
        assert_eq!(projection[0].pending_question_ids, ["q"]);
        assert!(!format!("{projection:?}").contains("secret"));
        let _ = state
            .apply_event_with_updates(&event("session.deleted", json!({"info": {"id": "root"}})));
        assert!(state.projection().is_empty());
    }

    #[test]
    fn projection_preserves_optional_v2_attachment_metadata() {
        let mut state = ServerState::default();
        let mut root = session("root", "Root", "", None);
        root.project_id = Some("project".to_owned());
        root.directory = Some(std::path::PathBuf::from("/workspace"));
        root.workspace = Some(std::path::PathBuf::from("/project"));
        root.updated = Some(123);
        let _ = state.reconcile_with_updates(snapshot(vec![root]), true);
        let projected = &state.projection()[0];
        assert_eq!(projected.project_id.as_deref(), Some("project"));
        assert_eq!(
            projected.directory.as_deref(),
            Some(std::path::Path::new("/workspace"))
        );
        assert_eq!(
            projected.workspace.as_deref(),
            Some(std::path::Path::new("/project"))
        );
        assert_eq!(projected.updated, Some(123));
    }

    #[test]
    fn projection_preserves_independent_root_and_descendant_execution_states() {
        let mut state = ServerState::default();
        let _ = state.reconcile_with_updates(
            Snapshot {
                sessions: vec![
                    session("root", "Root", "", None),
                    session("child", "Child", "", Some("root")),
                    session("grandchild", "Grandchild", "", Some("child")),
                ],
                statuses: HashMap::from([
                    ("root".to_owned(), SessionStatus::Idle),
                    ("child".to_owned(), SessionStatus::Busy),
                    (
                        "grandchild".to_owned(),
                        SessionStatus::Retry {
                            attempt: 1,
                            message: "retry".to_owned(),
                            next: 2,
                        },
                    ),
                ]),
                ..Snapshot::default()
            },
            true,
        );
        let projection = state.projection();
        assert_eq!(projection[0].id, "child");
        assert_eq!(projection[0].status, crate::model::ProjectedStatus::Busy);
        assert_eq!(projection[1].id, "grandchild");
        assert_eq!(projection[1].status, crate::model::ProjectedStatus::Retry);
        assert_eq!(projection[2].id, "root");
        assert_eq!(projection[2].status, crate::model::ProjectedStatus::Idle);
    }

    #[test]
    fn error_is_observed_but_not_latched() {
        let mut state = ServerState::default();
        let event = event(
            "session.error",
            json!({"sessionID": "s", "error": {"name": "MessageAbortedError", "message": "aborted"}}),
        );
        assert!(state.apply_event(&event).is_empty());
        assert_eq!(
            ServerState::observe(&event).detail.as_deref(),
            Some("MessageAbortedError: aborted")
        );
        assert_eq!(state.active_session_count(), 0);
    }

    #[test]
    fn unknown_events_are_forward_compatible() {
        let mut state = ServerState::default();
        let event = event("future.event", json!({"anything": true}));
        assert!(state.apply_event(&event).is_empty());
        assert_eq!(ServerState::observe(&event).kind, "future.event");
    }

    #[test]
    fn snapshot_replay_emits_only_net_correction() {
        let mut state = ServerState::default();
        let busy = event(
            "session.status",
            json!({"sessionID": "s", "status": {"type": "busy"}}),
        );
        let _ = state.apply_event(&busy);
        let transitions = state
            .reconcile_replayed_with_updates(
                Snapshot {
                    sessions: vec![Session {
                        id: "s".to_owned(),
                        ..Session::default()
                    }],
                    statuses: HashMap::new(),
                    permissions: Vec::new(),
                    questions: Vec::new(),
                },
                [&busy],
                false,
                &HashSet::new(),
            )
            .transitions;
        assert!(transitions.is_empty());
        assert_eq!(state.active_session_count(), 1);
    }

    #[test]
    fn child_requests_use_root_metadata_and_emit_when_priority_masks_transition() {
        let mut state = ServerState::default();
        let _ = state.reconcile_with_updates(
            snapshot(vec![
                session("root", "Root title", "root-slug", None),
                session("child", "Child", "child-slug", Some("root")),
            ]),
            true,
        );

        let question = state.apply_event_with_updates(&event(
            "question.asked",
            json!({"id": "q1", "sessionID": "child", "questions": [{"header": "secret"}]}),
        ));
        assert_eq!(question.attention.len(), 1);
        assert_eq!(question.attention[0].kind, AttentionKind::Question);
        assert_eq!(question.attention[0].root_session_id, "root");
        assert_eq!(
            question.attention[0].root_title.as_deref(),
            Some("Root title")
        );
        assert_eq!(
            question.attention[0].root_slug.as_deref(),
            Some("root-slug")
        );
        assert_eq!(question.attention[0].subject_session_id, "child");
        assert_eq!(question.attention[0].request_id.as_deref(), Some("q1"));
        assert!(question.attention[0].root_resolved);

        let permission = state.apply_event_with_updates(&event(
            "permission.asked",
            json!({"id": "p1", "sessionID": "child", "permission": "secret"}),
        ));
        assert!(permission.transitions.is_empty());
        assert_eq!(permission.attention.len(), 1);
        assert_eq!(permission.attention[0].kind, AttentionKind::Permission);
        let derived = format!("{question:?}{permission:?}");
        assert!(!derived.contains("secret"));
    }

    #[test]
    fn duplicate_and_reassigned_requests_are_canonical_and_deduplicated() {
        let mut state = ServerState::default();
        let _ = state.reconcile_with_updates(
            snapshot(vec![
                session("a", "A", "a", None),
                session("b", "B", "b", None),
            ]),
            true,
        );
        let asked = event(
            "permission.asked",
            json!({"id": "p", "sessionID": "a", "patterns": ["secret"]}),
        );
        assert_eq!(state.apply_event_with_updates(&asked).attention.len(), 1);
        assert!(state.apply_event_with_updates(&asked).attention.is_empty());

        let reassigned = state.apply_event_with_updates(&event(
            "permission.asked",
            json!({"id": "p", "sessionID": "b"}),
        ));
        assert!(reassigned.attention.is_empty());
        assert!(!state.sessions["a"].permissions.contains("p"));
        assert!(state.sessions["b"].permissions.contains("p"));
        assert_eq!(state.permissions.get("p").map(String::as_str), Some("b"));

        let replied = state.apply_event_with_updates(&event(
            "permission.replied",
            json!({"requestID": "p", "reply": "once"}),
        ));
        assert!(replied.attention.is_empty());
        assert!(!state.sessions["a"].permissions.contains("p"));
        assert!(!state.sessions["b"].permissions.contains("p"));
    }

    #[test]
    fn root_resolution_reports_missing_parents_and_cycles() {
        let mut state = ServerState::default();
        let _ = state.reconcile_with_updates(
            snapshot(vec![
                session("child", "Child", "child", Some("missing")),
                session("deep", "Deep", "deep", Some("known")),
                session("known", "Known", "known", Some("also-missing")),
                session("a", "A", "a", Some("b")),
                session("b", "B", "b", Some("a")),
            ]),
            true,
        );

        let missing = state.apply_event_with_updates(&event(
            "question.asked",
            json!({"id": "missing-q", "sessionID": "child"}),
        ));
        assert_eq!(missing.attention[0].root_session_id, "child");
        assert!(!missing.attention[0].root_resolved);

        let deep = state.apply_event_with_updates(&event(
            "question.asked",
            json!({"id": "deep-q", "sessionID": "deep"}),
        ));
        assert_eq!(deep.attention[0].root_session_id, "deep");
        assert!(!deep.attention[0].root_resolved);

        let cyclic = state.apply_event_with_updates(&event(
            "question.asked",
            json!({"id": "cycle-q", "sessionID": "a"}),
        ));
        assert_eq!(cyclic.attention[0].root_session_id, "a");
        assert!(!cyclic.attention[0].root_resolved);
    }

    #[test]
    fn metadata_updates_change_subsequent_attention_names_and_roots() {
        let mut state = ServerState::default();
        let _ = state.reconcile_with_updates(
            snapshot(vec![
                session("root", "Old", "old", None),
                session("child", "Child", "child", Some("root")),
            ]),
            true,
        );
        let _ = state.apply_event_with_updates(&event(
            "session.updated",
            json!({"info": {"id": "root", "title": "New", "slug": "new", "parentID": null}}),
        ));
        let update = state.apply_event_with_updates(&event(
            "permission.asked",
            json!({"id": "p", "sessionID": "child", "patterns": ["omitted"]}),
        ));
        assert_eq!(update.attention[0].name(), "New");
        assert_eq!(update.attention[0].root_slug.as_deref(), Some("new"));
    }

    #[test]
    fn ready_requires_root_work_and_waits_for_all_root_requests() {
        let mut state = ServerState::default();
        let initial = state.reconcile_with_updates(
            Snapshot {
                sessions: vec![
                    session("root", "Root", "root", None),
                    session("child", "Child", "child", Some("root")),
                ],
                statuses: HashMap::from([("root".to_owned(), SessionStatus::Busy)]),
                ..Snapshot::default()
            },
            true,
        );
        assert!(initial.attention.is_empty());

        let question = state.apply_event_with_updates(&event(
            "question.asked",
            json!({"id": "q", "sessionID": "child"}),
        ));
        assert_eq!(question.attention[0].kind, AttentionKind::Question);
        let idle = state.apply_event_with_updates(&event(
            "session.status",
            json!({"sessionID": "root", "status": {"type": "idle"}}),
        ));
        assert!(idle.attention.is_empty());

        let replied = state.apply_event_with_updates(&event(
            "question.replied",
            json!({"requestID": "q", "answers": ["omitted"]}),
        ));
        assert_eq!(replied.attention.len(), 1);
        assert_eq!(replied.attention[0].kind, AttentionKind::Ready);
        assert_eq!(replied.attention[0].subject_session_id, "root");
        assert!(replied.attention[0].request_id.is_none());
        assert!(
            state
                .apply_event_with_updates(&event(
                    "session.status",
                    json!({"sessionID": "root", "status": {"type": "idle"}}),
                ))
                .attention
                .is_empty()
        );
    }

    #[test]
    fn child_work_and_initial_idle_never_arm_ready() {
        let mut state = ServerState::default();
        let initial = state.reconcile_with_updates(
            snapshot(vec![
                session("root", "Root", "root", None),
                session("child", "Child", "child", Some("root")),
            ]),
            true,
        );
        assert!(initial.attention.is_empty());
        let _ = state.apply_event_with_updates(&event(
            "session.status",
            json!({"sessionID": "child", "status": {"type": "busy"}}),
        ));
        let child_idle = state.apply_event_with_updates(&event(
            "session.status",
            json!({"sessionID": "child", "status": {"type": "idle"}}),
        ));
        assert!(child_idle.attention.is_empty());

        let retry = state.apply_event_with_updates(&event(
            "session.status",
            json!({"sessionID": "root", "status": {"type": "retry", "attempt": 1}}),
        ));
        assert!(retry.attention.is_empty());
        let root_idle = state.apply_event_with_updates(&event(
            "session.status",
            json!({"sessionID": "root", "status": {"type": "idle"}}),
        ));
        assert_eq!(root_idle.attention[0].kind, AttentionKind::Ready);
    }

    #[test]
    fn initial_and_later_snapshots_emit_new_requests_once_in_stable_order() {
        let mut state = ServerState::default();
        let initial = state.reconcile_with_updates(
            Snapshot {
                sessions: vec![session("root", "", "fallback", None)],
                permissions: vec![PermissionRequest {
                    id: "p2".to_owned(),
                    session_id: "root".to_owned(),
                }],
                questions: vec![
                    QuestionRequest {
                        id: "q2".to_owned(),
                        session_id: "root".to_owned(),
                    },
                    QuestionRequest {
                        id: "q1".to_owned(),
                        session_id: "root".to_owned(),
                    },
                ],
                ..Snapshot::default()
            },
            true,
        );
        assert_eq!(initial.attention.len(), 3);
        assert!(initial.attention.iter().all(|attention| attention.initial));
        assert_eq!(initial.attention[0].request_id.as_deref(), Some("q1"));
        assert_eq!(initial.attention[1].request_id.as_deref(), Some("q2"));
        assert_eq!(initial.attention[2].request_id.as_deref(), Some("p2"));
        assert_eq!(initial.attention[0].name(), "fallback");

        let duplicate = state.reconcile_with_updates(
            Snapshot {
                sessions: vec![session("root", "", "fallback", None)],
                permissions: vec![PermissionRequest {
                    id: "p2".to_owned(),
                    session_id: "root".to_owned(),
                }],
                questions: vec![QuestionRequest {
                    id: "q1".to_owned(),
                    session_id: "root".to_owned(),
                }],
                ..Snapshot::default()
            },
            false,
        );
        assert!(duplicate.attention.is_empty());

        let later = state.reconcile_with_updates(
            Snapshot {
                sessions: vec![session("root", "", "fallback", None)],
                questions: vec![QuestionRequest {
                    id: "q3".to_owned(),
                    session_id: "root".to_owned(),
                }],
                ..Snapshot::default()
            },
            false,
        );
        assert_eq!(later.attention.len(), 1);
        assert!(!later.attention[0].initial);
        assert_eq!(later.attention[0].source, TransitionSource::Snapshot);
    }

    #[test]
    fn snapshot_replay_deduplicates_live_requests_and_ready() {
        let mut state = ServerState::default();
        let _ = state
            .reconcile_with_updates(snapshot(vec![session("root", "Root", "root", None)]), true);
        let asked = event("question.asked", json!({"id": "q", "sessionID": "root"}));
        assert_eq!(state.apply_event_with_updates(&asked).attention.len(), 1);
        let replayed = state.reconcile_replayed_with_updates(
            Snapshot {
                sessions: vec![session("root", "Root", "root", None)],
                questions: vec![QuestionRequest {
                    id: "q".to_owned(),
                    session_id: "root".to_owned(),
                }],
                ..Snapshot::default()
            },
            [&asked],
            false,
            &HashSet::new(),
        );
        assert!(replayed.attention.is_empty());
    }

    #[test]
    fn snapshot_busy_then_replayed_idle_emits_ready_without_duplicating_live_cycle() {
        let mut state = ServerState::default();
        let _ = state
            .reconcile_with_updates(snapshot(vec![session("root", "Root", "root", None)]), true);
        let idle = event(
            "session.status",
            json!({"sessionID": "root", "status": {"type": "idle"}}),
        );
        let learned_from_snapshot = state.reconcile_replayed_with_updates(
            Snapshot {
                sessions: vec![session("root", "Root", "root", None)],
                statuses: HashMap::from([("root".to_owned(), SessionStatus::Busy)]),
                ..Snapshot::default()
            },
            [&idle],
            false,
            &HashSet::new(),
        );
        assert_eq!(learned_from_snapshot.attention.len(), 1);
        assert_eq!(
            learned_from_snapshot.attention[0].kind,
            AttentionKind::Ready
        );
        assert_eq!(
            learned_from_snapshot.attention[0].source,
            TransitionSource::Snapshot
        );

        let busy = event(
            "session.status",
            json!({"sessionID": "root", "status": {"type": "busy"}}),
        );
        let _ = state.apply_event_with_updates(&busy);
        assert_eq!(state.apply_event_with_updates(&idle).attention.len(), 1);
        let already_emitted = state.reconcile_replayed_with_updates(
            Snapshot {
                sessions: vec![session("root", "Root", "root", None)],
                statuses: HashMap::from([("root".to_owned(), SessionStatus::Busy)]),
                ..Snapshot::default()
            },
            [&busy, &idle],
            false,
            &HashSet::from(["root".to_owned()]),
        );
        assert!(already_emitted.attention.is_empty());

        let _ = state.apply_event_with_updates(&busy);
        assert_eq!(state.apply_event_with_updates(&idle).attention.len(), 1);
        let prearmed_before_journal = state.reconcile_replayed_with_updates(
            Snapshot {
                sessions: vec![session("root", "Root", "root", None)],
                statuses: HashMap::from([("root".to_owned(), SessionStatus::Busy)]),
                ..Snapshot::default()
            },
            [&idle],
            false,
            &HashSet::from(["root".to_owned()]),
        );
        assert!(prearmed_before_journal.attention.is_empty());

        let mut metadata_missing_live = ServerState::default();
        assert!(
            metadata_missing_live
                .apply_event_with_updates(&busy)
                .attention
                .is_empty()
        );
        assert!(
            metadata_missing_live
                .apply_event_with_updates(&idle)
                .attention
                .is_empty()
        );
        let metadata_from_snapshot = metadata_missing_live.reconcile_replayed_with_updates(
            Snapshot {
                sessions: vec![session("root", "Root", "root", None)],
                statuses: HashMap::from([("root".to_owned(), SessionStatus::Busy)]),
                ..Snapshot::default()
            },
            [&busy, &idle],
            false,
            &HashSet::new(),
        );
        assert_eq!(metadata_from_snapshot.attention.len(), 1);
        assert_eq!(
            metadata_from_snapshot.attention[0].kind,
            AttentionKind::Ready
        );
    }

    #[test]
    fn later_idle_snapshot_emits_ready_once() {
        let mut state = ServerState::default();
        let initial = state.reconcile_with_updates(
            Snapshot {
                sessions: vec![session("root", "Root", "root", None)],
                statuses: HashMap::from([("root".to_owned(), SessionStatus::Busy)]),
                ..Snapshot::default()
            },
            true,
        );
        assert!(initial.attention.is_empty());
        let idle = state
            .reconcile_with_updates(snapshot(vec![session("root", "Root", "root", None)]), false);
        assert_eq!(idle.attention.len(), 1);
        assert_eq!(idle.attention[0].kind, AttentionKind::Ready);
        assert_eq!(idle.attention[0].source, TransitionSource::Snapshot);
        assert!(
            state
                .reconcile_with_updates(
                    snapshot(vec![session("root", "Root", "root", None)]),
                    false,
                )
                .attention
                .is_empty()
        );
    }

    #[test]
    fn duplicate_snapshot_request_ids_use_one_canonical_subject() {
        let mut state = ServerState::default();
        let update = state.reconcile_with_updates(
            Snapshot {
                sessions: vec![session("a", "A", "a", None), session("b", "B", "b", None)],
                questions: vec![
                    QuestionRequest {
                        id: "q".to_owned(),
                        session_id: "a".to_owned(),
                    },
                    QuestionRequest {
                        id: "q".to_owned(),
                        session_id: "b".to_owned(),
                    },
                ],
                ..Snapshot::default()
            },
            true,
        );
        assert_eq!(update.attention.len(), 1);
        assert_eq!(update.attention[0].subject_session_id, "b");
        assert!(!state.sessions["a"].questions.contains("q"));
        assert!(state.sessions["b"].questions.contains("q"));
    }

    #[test]
    fn ready_waits_until_every_root_and_child_request_clears() {
        let mut state = ServerState::default();
        let _ = state.reconcile_with_updates(
            Snapshot {
                sessions: vec![
                    session("root", "Root", "root", None),
                    session("child", "Child", "child", Some("root")),
                ],
                statuses: HashMap::from([("root".to_owned(), SessionStatus::Busy)]),
                ..Snapshot::default()
            },
            true,
        );
        let _ = state.apply_event_with_updates(&event(
            "question.asked",
            json!({"id": "q", "sessionID": "child"}),
        ));
        let _ = state.apply_event_with_updates(&event(
            "permission.asked",
            json!({"id": "p", "sessionID": "root"}),
        ));
        let _ = state.apply_event_with_updates(&event(
            "session.status",
            json!({"sessionID": "root", "status": {"type": "idle"}}),
        ));
        assert!(
            state
                .apply_event_with_updates(&event("question.rejected", json!({"requestID": "q"}),))
                .attention
                .is_empty()
        );
        let final_reply = state.apply_event_with_updates(&event(
            "permission.replied",
            json!({"requestID": "p", "reply": "reject"}),
        ));
        assert_eq!(final_reply.attention.len(), 1);
        assert_eq!(final_reply.attention[0].kind, AttentionKind::Ready);
    }

    #[test]
    fn deleting_pending_child_can_release_an_armed_root() {
        let mut state = ServerState::default();
        let _ = state.reconcile_with_updates(
            Snapshot {
                sessions: vec![
                    session("root", "Root", "root", None),
                    session("child", "Child", "child", Some("root")),
                ],
                statuses: HashMap::from([("root".to_owned(), SessionStatus::Busy)]),
                ..Snapshot::default()
            },
            true,
        );
        let _ = state.apply_event_with_updates(&event(
            "question.asked",
            json!({"id": "q", "sessionID": "child"}),
        ));
        let _ = state.apply_event_with_updates(&event(
            "session.status",
            json!({"sessionID": "root", "status": {"type": "idle"}}),
        ));
        let deleted = state
            .apply_event_with_updates(&event("session.deleted", json!({"info": {"id": "child"}})));
        assert_eq!(deleted.attention[0].kind, AttentionKind::Ready);
    }
}
