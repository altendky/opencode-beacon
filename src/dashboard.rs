use std::cmp::Ordering;
use std::collections::{HashMap, HashSet, VecDeque};
use std::path::Path;
use std::time::{Duration, Instant};

use crossterm::event::{Event, KeyCode, KeyEvent, KeyModifiers};
use opencode_beacon::model::{
    AttentionKind, BeaconEvent, ClaudeProjection, ClaudeSessionKey, ClaudeStatus, InstanceKey,
    OpenCodeProtocol, ProjectedSession, ProjectedStatus, ServerEndpoint, ServerProjection,
};
use ratatui::Frame;
use ratatui::layout::{Constraint, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, HighlightSpacing, Paragraph, Row, Table, TableState};

use crate::attachment::{AttachmentSnapshot, FocusTarget, LikelyTui, TuiKey};
use crate::memory::{CgroupKey, MemoryAvailability, MemoryView};

const MAX_DIAGNOSTICS: usize = 3;
const STATE_WIDTH: usize = 22;
const STATE_COLUMN_WIDTH: u16 = 22;
const MEMORY_COLUMN_WIDTH: u16 = 9;
const ATTACHMENT_COLUMN_WIDTH: u16 = 10;
const ELAPSED_WIDTH: usize = 10;
const MAX_ELAPSED_MINUTES: u64 = 9_999_999;
const MINUTE: Duration = Duration::from_secs(60);

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
enum RowKey {
    OpenCode {
        instance: InstanceKey,
        root_session_id: String,
    },
    Claude(ClaudeSessionKey),
}

impl RowKey {
    const fn opencode(instance: InstanceKey, root_session_id: String) -> Self {
        Self::OpenCode {
            instance,
            root_session_id,
        }
    }

    const fn instance(&self) -> Option<&InstanceKey> {
        match self {
            Self::OpenCode { instance, .. } => Some(instance),
            Self::Claude(_) => None,
        }
    }

    fn session_id<'a>(&'a self, claude_id: &'a str) -> &'a str {
        match self {
            Self::OpenCode {
                root_session_id, ..
            } => root_session_id,
            Self::Claude(_) => claude_id,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum Occurrence {
    Question(Vec<String>),
    Permission(Vec<String>),
    Ready(u64),
}

#[derive(Clone, Debug)]
#[allow(clippy::struct_excessive_bools)]
struct DashboardRow {
    key: RowKey,
    endpoint: Option<ServerEndpoint>,
    session_id: String,
    title: String,
    slug: String,
    busy: bool,
    retry: bool,
    background_count: usize,
    question_ids: Vec<String>,
    permission_ids: Vec<String>,
    ready_eligible: bool,
    ready_generation: u64,
    stale: bool,
    attachment_stale: bool,
    last_non_busy: Option<Instant>,
    first_busy_observed: Option<Instant>,
    frozen_busy_elapsed: Option<Duration>,
    dismissed: Option<Occurrence>,
    category: RowCategory,
    tui: Option<TuiKey>,
    focus: Option<FocusTarget>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RowCategory {
    V1,
    Attached,
    Headless,
    Ambiguous,
    Unresolved,
    Claude,
}

impl RowCategory {
    const fn label(self) -> &'static str {
        match self {
            Self::V1 => "v1",
            Self::Attached => "attached",
            Self::Headless => "headless",
            Self::Ambiguous => "ambiguous",
            Self::Unresolved => "unresolved",
            Self::Claude => "claude",
        }
    }

    const fn has_session_state(self) -> bool {
        matches!(self, Self::Attached | Self::Headless | Self::Claude)
    }
}

#[derive(Clone, Debug)]
struct DismissalStatus {
    key: Option<RowKey>,
    occurrence: Option<Occurrence>,
    message: String,
}

impl DashboardRow {
    fn occurrence(&self) -> Option<Occurrence> {
        if !self.question_ids.is_empty() {
            Some(Occurrence::Question(self.question_ids.clone()))
        } else if !self.permission_ids.is_empty() {
            Some(Occurrence::Permission(self.permission_ids.clone()))
        } else if self.busy || self.background_count > 0 {
            None
        } else if self.ready_eligible
            && matches!(
                self.category,
                RowCategory::V1
                    | RowCategory::Attached
                    | RowCategory::Headless
                    | RowCategory::Claude
            )
        {
            Some(Occurrence::Ready(self.ready_generation))
        } else {
            None
        }
    }

    fn attention(&self) -> Option<AttentionKind> {
        match self.occurrence() {
            Some(Occurrence::Question(_)) => Some(AttentionKind::Question),
            Some(Occurrence::Permission(_)) => Some(AttentionKind::Permission),
            Some(Occurrence::Ready(_)) => Some(AttentionKind::Ready),
            None => None,
        }
    }

    fn marker(&self) -> &'static str {
        match self.attention() {
            Some(AttentionKind::Question) => "question",
            Some(AttentionKind::Permission) => "permission",
            Some(AttentionKind::Ready) => "ready",
            None => "",
        }
    }

    fn name(&self) -> &str {
        if !self.title.is_empty() {
            &self.title
        } else if !self.slug.is_empty() {
            &self.slug
        } else {
            self.key.session_id(&self.session_id)
        }
    }

    fn dismissed(&self) -> bool {
        self.occurrence()
            .is_some_and(|current| self.dismissed.as_ref() == Some(&current))
    }

    fn busy_elapsed(&self, now: Instant) -> Option<Duration> {
        if !self.busy {
            return None;
        }
        self.frozen_busy_elapsed.or_else(|| {
            self.busy_baseline()
                .map(|baseline| now.saturating_duration_since(baseline))
        })
    }

    fn busy_baseline(&self) -> Option<Instant> {
        self.last_non_busy.or(self.first_busy_observed)
    }

    const fn busy_elapsed_is_lower_bound(&self) -> bool {
        self.busy && self.last_non_busy.is_none() && self.first_busy_observed.is_some()
    }

    const fn is_stale(&self) -> bool {
        self.stale || self.attachment_stale
    }
}

#[derive(Default)]
pub struct DashboardModel {
    rows: Vec<DashboardRow>,
    projections: HashMap<InstanceKey, ServerProjection>,
    attachments: HashMap<InstanceKey, Vec<LikelyTui>>,
    v1_focus: HashMap<InstanceKey, FocusTarget>,
    sticky_attachments: HashMap<(InstanceKey, TuiKey), String>,
    endpoint_instances: HashMap<ServerEndpoint, InstanceKey>,
    v2_instances: HashSet<InstanceKey>,
    connected: HashSet<InstanceKey>,
    memory: HashMap<InstanceKey, MemoryView>,
    last_non_busy: HashMap<RowKey, Instant>,
    pending_ready: HashSet<RowKey>,
    diagnostics: VecDeque<String>,
    dismissal_status: Option<DismissalStatus>,
    selected: Option<usize>,
    offset: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DashboardAction {
    Continue,
    Focus(FocusRequest),
    Quit,
    Redraw,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FocusRequest {
    pub target: FocusTarget,
    pub name: String,
}

impl DashboardModel {
    #[cfg(test)]
    pub fn apply(&mut self, event: BeaconEvent) {
        self.apply_at(event, Instant::now());
    }

    pub fn apply_at(&mut self, event: BeaconEvent, now: Instant) {
        let selected_key = self.selected_key();
        match event {
            BeaconEvent::ServerFound(instance) => {
                if let Some(replaced) = self
                    .endpoint_instances
                    .insert(instance.endpoint, instance.key.clone())
                    && replaced != instance.key
                {
                    self.remove_instance(&replaced);
                }
                if instance.protocol == OpenCodeProtocol::V2 {
                    self.v2_instances.insert(instance.key);
                } else {
                    self.v2_instances.remove(&instance.key);
                }
            }
            BeaconEvent::ServerRemoved(instance) => self.remove_instance(&instance.key),
            BeaconEvent::Connected(endpoint) => {
                if let Some(instance) = self.endpoint_instances.get(&endpoint).cloned() {
                    self.connected.insert(instance.clone());
                    self.set_stale(&instance, false, now);
                }
            }
            BeaconEvent::Disconnected { endpoint, .. } => {
                if let Some(instance) = self.endpoint_instances.get(&endpoint).cloned() {
                    self.connected.remove(&instance);
                    self.set_stale(&instance, true, now);
                }
            }
            BeaconEvent::StateProjection(projection) => self.apply_projection(&projection, now),
            BeaconEvent::ClaudeSessionRemoved(session) => {
                self.rows
                    .retain(|row| row.key != RowKey::Claude(session.key));
            }
            BeaconEvent::ClaudeStateProjection(projection) => {
                self.apply_claude_projection(&projection, now);
            }
            BeaconEvent::ClaudeAttention(attention) if attention.kind == AttentionKind::Ready => {
                self.apply_claude_ready(attention.session.key, now);
            }
            BeaconEvent::Attention {
                endpoint,
                attention,
            } => {
                if attention.kind == AttentionKind::Ready
                    && let Some(instance) = self.endpoint_instances.get(&endpoint).cloned()
                {
                    self.apply_ready(&instance, endpoint, &attention.root_session_id, now);
                }
            }
            BeaconEvent::Diagnostic { message, .. } => {
                self.diagnostics.push_back(sanitize(&message));
                while self.diagnostics.len() > MAX_DIAGNOSTICS {
                    self.diagnostics.pop_front();
                }
            }
            _ => {}
        }
        self.normalize_rows(selected_key);
        self.clear_stale_dismissal_status();
    }

    pub fn apply_memory(&mut self, memory: HashMap<InstanceKey, MemoryView>) {
        self.memory = memory;
    }

    pub fn apply_attachments(&mut self, snapshot: AttachmentSnapshot, now: Instant) {
        let selected_key = self.selected_key();
        self.v1_focus = snapshot.v1_focus;
        for row in &mut self.rows {
            match &row.key {
                RowKey::OpenCode { instance, .. } if row.category == RowCategory::V1 => {
                    row.focus = self.v1_focus.get(instance).cloned();
                }
                RowKey::Claude(key) => {
                    row.focus = snapshot
                        .claude_focus
                        .get(&TuiKey {
                            pid: key.pid,
                            start_time: key.start_time,
                        })
                        .cloned();
                }
                RowKey::OpenCode { .. } => {}
            }
        }
        self.attachments.clear();
        for tui in snapshot.tuis {
            self.attachments
                .entry(tui.instance.clone())
                .or_default()
                .push(tui);
        }
        let observed = self
            .attachments
            .iter()
            .flat_map(|(instance, tuis)| tuis.iter().map(|tui| (instance.clone(), tui.key)))
            .collect::<HashSet<_>>();
        self.sticky_attachments
            .retain(|key, _| observed.contains(key));
        if let Some(diagnostic) = snapshot.diagnostic {
            self.diagnostics.push_back(sanitize(&diagnostic));
            while self.diagnostics.len() > MAX_DIAGNOSTICS {
                self.diagnostics.pop_front();
            }
        }
        let managed = self
            .projections
            .keys()
            .filter(|instance| self.v2_instances.contains(*instance))
            .cloned()
            .collect::<Vec<_>>();
        for instance in managed {
            self.rebuild_v2_rows(&instance, now);
        }
        self.normalize_rows(selected_key);
    }

    fn apply_projection(&mut self, projection: &ServerProjection, now: Instant) {
        let instance = projection.instance_key.clone();
        if let Some(replaced) = self
            .endpoint_instances
            .insert(projection.endpoint, instance.clone())
            && replaced != instance
        {
            self.remove_instance(&replaced);
        }
        self.connected.insert(instance.clone());
        self.projections
            .insert(instance.clone(), projection.clone());

        if self.v2_instances.contains(&instance) {
            let aggregates = aggregate_v2_roots(&projection.sessions);
            let root_ids = aggregates
                .iter()
                .map(|aggregate| aggregate.id.as_str())
                .collect::<HashSet<_>>();
            self.last_non_busy.retain(|key, _| {
                key.instance() != Some(&instance) || root_ids.contains(key.session_id(""))
            });
            for aggregate in aggregates {
                if !aggregate.busy {
                    self.last_non_busy
                        .insert(RowKey::opencode(instance.clone(), aggregate.id), now);
                }
            }
            self.rebuild_v2_rows(&instance, now);
            return;
        }

        let session_ids = projection
            .sessions
            .iter()
            .map(|session| session.id.as_str())
            .collect::<HashSet<_>>();
        let aggregates = aggregate_roots(&projection.sessions);
        let root_ids = aggregates
            .iter()
            .map(|aggregate| aggregate.id.as_str())
            .collect::<HashSet<_>>();
        self.rows.retain(|row| {
            row.key.instance() != Some(&instance)
                || (session_ids.contains(row.key.session_id(""))
                    && root_ids.contains(row.key.session_id("")))
        });
        self.last_non_busy.retain(|key, _| {
            key.instance() != Some(&instance) || root_ids.contains(key.session_id(""))
        });
        for aggregate in aggregates {
            let key = RowKey::opencode(instance.clone(), aggregate.id.clone());
            if !aggregate.busy {
                self.last_non_busy.insert(key.clone(), now);
            }
            if let Some(row) = self.rows.iter_mut().find(|row| row.key == key) {
                update_row(row, projection.endpoint, &aggregate, now);
            } else if aggregate.busy
                || !aggregate.question_ids.is_empty()
                || !aggregate.permission_ids.is_empty()
            {
                self.rows.push(new_row(
                    key.clone(),
                    projection.endpoint,
                    &aggregate,
                    self.last_non_busy.get(&key).copied(),
                    now,
                ));
            }
        }
        for row in self
            .rows
            .iter_mut()
            .filter(|row| row.key.instance() == Some(&instance) && row.category == RowCategory::V1)
        {
            row.focus = self.v1_focus.get(&instance).cloned();
        }
        let ready = self
            .pending_ready
            .iter()
            .filter(|key| key.instance() == Some(&instance))
            .cloned()
            .collect::<Vec<_>>();
        for key in ready {
            self.pending_ready.remove(&key);
            self.apply_ready(&instance, projection.endpoint, key.session_id(""), now);
        }
        self.set_stale(&instance, false, now);
    }

    fn apply_ready(
        &mut self,
        instance: &InstanceKey,
        endpoint: ServerEndpoint,
        root_id: &str,
        now: Instant,
    ) {
        let key = RowKey::opencode(instance.clone(), root_id.to_owned());
        self.last_non_busy.insert(key.clone(), now);
        if let Some(row) = self.rows.iter_mut().find(|row| row.key == key) {
            row.ready_generation = row.ready_generation.saturating_add(1);
            row.busy = false;
            row.retry = false;
            row.last_non_busy = Some(now);
            row.first_busy_observed = None;
            row.frozen_busy_elapsed = None;
            row.dismissed = None;
            return;
        }
        if self.v2_instances.contains(instance) {
            return;
        }
        let Some(session) = self.projections.get(instance).and_then(|projection| {
            projection
                .sessions
                .iter()
                .find(|session| session.id == root_id)
        }) else {
            self.pending_ready.insert(key);
            return;
        };
        self.rows.push(DashboardRow {
            key,
            endpoint: Some(endpoint),
            session_id: root_id.to_owned(),
            title: session.title.clone(),
            slug: session.slug.clone(),
            busy: false,
            retry: false,
            background_count: 0,
            question_ids: Vec::new(),
            permission_ids: Vec::new(),
            ready_eligible: true,
            ready_generation: 1,
            stale: false,
            attachment_stale: false,
            last_non_busy: Some(now),
            first_busy_observed: None,
            frozen_busy_elapsed: None,
            dismissed: None,
            category: RowCategory::V1,
            tui: None,
            focus: self.v1_focus.get(instance).cloned(),
        });
    }

    fn remove_instance(&mut self, instance: &InstanceKey) {
        self.rows.retain(|row| row.key.instance() != Some(instance));
        self.projections.remove(instance);
        self.attachments.remove(instance);
        self.v1_focus.remove(instance);
        self.sticky_attachments
            .retain(|(sticky_instance, _), _| sticky_instance != instance);
        self.connected.remove(instance);
        self.memory.remove(instance);
        self.last_non_busy
            .retain(|key, _| key.instance() != Some(instance));
        self.pending_ready
            .retain(|key| key.instance() != Some(instance));
        self.endpoint_instances.retain(|_, value| value != instance);
        self.v2_instances.remove(instance);
    }

    fn apply_claude_projection(&mut self, projection: &ClaudeProjection, now: Instant) {
        let key = RowKey::Claude(projection.session.key);
        if !projection.session.has_tty {
            self.rows.retain(|row| row.key != key);
            return;
        }
        let busy = matches!(
            projection.status,
            ClaudeStatus::Busy | ClaudeStatus::Waiting
        );
        if let Some(row) = self.rows.iter_mut().find(|row| row.key == key) {
            let previous = row.occurrence();
            let was_busy = row.busy;
            let was_stale = row.stale;
            if projection.stale && !was_stale && row.frozen_busy_elapsed.is_none() {
                row.frozen_busy_elapsed = row.busy_elapsed(now);
            }
            row.session_id.clone_from(&projection.session.session_id);
            projection.session.display_name().clone_into(&mut row.title);
            row.slug.clear();
            row.busy = busy;
            row.ready_eligible = projection.status == ClaudeStatus::Idle;
            row.stale = projection.stale;
            if busy {
                if !projection.stale
                    && (was_stale || row.frozen_busy_elapsed.is_some())
                    && let Some(elapsed) = row.frozen_busy_elapsed
                {
                    if row.last_non_busy.is_some() {
                        row.last_non_busy = now.checked_sub(elapsed);
                    } else if row.first_busy_observed.is_some() {
                        row.first_busy_observed = now.checked_sub(elapsed);
                    }
                } else if !was_busy && row.last_non_busy.is_none() {
                    row.first_busy_observed = Some(now);
                }
                if !projection.stale {
                    row.frozen_busy_elapsed = None;
                }
                row.dismissed = None;
            } else if projection.status == ClaudeStatus::Idle && !projection.stale {
                row.last_non_busy = Some(now);
                row.first_busy_observed = None;
                row.frozen_busy_elapsed = None;
            }
            if previous != row.occurrence() {
                row.dismissed = None;
            }
            return;
        }
        self.rows.push(DashboardRow {
            key,
            endpoint: None,
            session_id: projection.session.session_id.clone(),
            title: projection.session.display_name().to_owned(),
            slug: String::new(),
            busy,
            retry: false,
            background_count: 0,
            question_ids: Vec::new(),
            permission_ids: Vec::new(),
            ready_eligible: projection.status == ClaudeStatus::Idle,
            ready_generation: 0,
            stale: projection.stale,
            attachment_stale: false,
            last_non_busy: (!busy && projection.status == ClaudeStatus::Idle).then_some(now),
            first_busy_observed: busy.then_some(now),
            frozen_busy_elapsed: None,
            dismissed: None,
            category: RowCategory::Claude,
            tui: None,
            focus: None,
        });
    }

    fn apply_claude_ready(&mut self, key: ClaudeSessionKey, now: Instant) {
        if let Some(row) = self
            .rows
            .iter_mut()
            .find(|row| row.key == RowKey::Claude(key))
        {
            row.ready_generation = row.ready_generation.saturating_add(1);
            row.busy = false;
            row.ready_eligible = true;
            row.last_non_busy = Some(now);
            row.first_busy_observed = None;
            row.frozen_busy_elapsed = None;
            row.dismissed = None;
        }
    }

    #[allow(clippy::too_many_lines)]
    fn rebuild_v2_rows(&mut self, instance: &InstanceKey, now: Instant) {
        let mut previous = self
            .rows
            .iter()
            .filter(|row| row.key.instance() == Some(instance))
            .map(|row| (row.key.clone(), row.clone()))
            .collect::<HashMap<_, _>>();
        self.rows.retain(|row| row.key.instance() != Some(instance));
        let Some(projection) = self.projections.get(instance) else {
            return;
        };
        let aggregates = aggregate_v2_roots(&projection.sessions);
        let by_root = aggregates
            .iter()
            .map(|aggregate| (aggregate.id.as_str(), aggregate))
            .collect::<HashMap<_, _>>();
        let resolutions = resolve_tuis(
            instance,
            self.attachments.get(instance).map_or(&[], Vec::as_slice),
            &projection.sessions,
            &mut self.sticky_attachments,
        );
        let mut attached = HashSet::new();
        let mut unresolved = Vec::new();
        for (tui, resolution) in resolutions {
            match resolution {
                TuiResolution::Attached(root_id) => {
                    let Some(aggregate) = by_root.get(root_id.as_str()) else {
                        unresolved.push((tui, false, None));
                        continue;
                    };
                    if attached.insert(root_id.clone()) {
                        let key = RowKey::opencode(instance.clone(), root_id);
                        let mut row = previous.remove(&key).map_or_else(
                            || {
                                new_row(
                                    key.clone(),
                                    projection.endpoint,
                                    aggregate,
                                    self.last_non_busy.get(&key).copied(),
                                    now,
                                )
                            },
                            |mut row| {
                                update_row(&mut row, projection.endpoint, aggregate, now);
                                row
                            },
                        );
                        row.category = RowCategory::Attached;
                        row.tui = Some(tui.key);
                        row.focus.clone_from(&tui.focus);
                        row.attachment_stale = tui.stale;
                        self.rows.push(row);
                    }
                }
                TuiResolution::Unresolved { ambiguous, hint } => {
                    unresolved.push((tui, ambiguous, hint));
                }
            }
        }
        for aggregate in aggregates {
            if (aggregate.busy || aggregate.background_count > 0)
                && !attached.contains(&aggregate.id)
            {
                let key = RowKey::opencode(instance.clone(), aggregate.id.clone());
                let mut row = previous.remove(&key).map_or_else(
                    || {
                        new_row(
                            key.clone(),
                            projection.endpoint,
                            &aggregate,
                            self.last_non_busy.get(&key).copied(),
                            now,
                        )
                    },
                    |mut row| {
                        update_row(&mut row, projection.endpoint, &aggregate, now);
                        row
                    },
                );
                row.category = RowCategory::Headless;
                row.attachment_stale = false;
                row.tui = None;
                row.focus = None;
                self.rows.push(row);
            }
        }
        for (tui, ambiguous, hint) in unresolved {
            let id = format!("PID {}", tui.key.pid);
            let title = hint.map_or_else(
                || tui.cwd.display().to_string(),
                |hint| format!("{} (possible {hint})", tui.cwd.display()),
            );
            self.rows.push(DashboardRow {
                key: RowKey::opencode(instance.clone(), id.clone()),
                endpoint: Some(projection.endpoint),
                session_id: id,
                title,
                slug: String::new(),
                busy: false,
                retry: false,
                background_count: 0,
                question_ids: Vec::new(),
                permission_ids: Vec::new(),
                ready_eligible: false,
                ready_generation: 0,
                stale: false,
                attachment_stale: tui.stale,
                last_non_busy: None,
                first_busy_observed: None,
                frozen_busy_elapsed: None,
                dismissed: None,
                category: if ambiguous {
                    RowCategory::Ambiguous
                } else {
                    RowCategory::Unresolved
                },
                tui: Some(tui.key),
                focus: None,
            });
        }
    }

    fn set_stale(&mut self, instance: &InstanceKey, stale: bool, now: Instant) {
        for row in self
            .rows
            .iter_mut()
            .filter(|row| row.key.instance() == Some(instance))
        {
            if stale && !row.stale && row.frozen_busy_elapsed.is_none() {
                row.frozen_busy_elapsed = row.busy_elapsed(now);
            }
            row.stale = stale;
        }
    }

    fn selected_key(&self) -> Option<RowKey> {
        self.selected
            .and_then(|selected| self.rows.get(selected))
            .map(|row| row.key.clone())
    }

    fn normalize_rows(&mut self, selected_key: Option<RowKey>) {
        self.rows.sort_by(compare_rows);
        if let Some(selected) = selected_key
            && let Some(index) = self.rows.iter().position(|row| row.key == selected)
        {
            self.selected = Some(index);
        }
        self.clamp_selection();
    }

    fn clamp_selection(&mut self) {
        self.selected = if self.rows.is_empty() {
            None
        } else {
            Some(self.selected.unwrap_or(0).min(self.rows.len() - 1))
        };
        self.offset = self.offset.min(self.rows.len().saturating_sub(1));
    }

    fn clear_stale_dismissal_status(&mut self) {
        let Some(status) = &self.dismissal_status else {
            return;
        };
        let Some(key) = &status.key else {
            return;
        };
        if !self
            .rows
            .iter()
            .any(|row| &row.key == key && row.occurrence() == status.occurrence)
        {
            self.dismissal_status = None;
        }
    }

    fn move_selection(&mut self, delta: isize, viewport_height: usize) {
        if self.rows.is_empty() {
            return;
        }
        let selected = self
            .selected
            .unwrap_or(0)
            .saturating_add_signed(delta)
            .min(self.rows.len() - 1);
        self.selected = Some(selected);
        if selected < self.offset {
            self.offset = selected;
        } else if selected >= self.offset.saturating_add(viewport_height.max(1)) {
            self.offset = selected + 1 - viewport_height.max(1);
        }
    }

    fn dismiss_selected(&mut self) {
        let Some(selected) = self.selected else {
            self.dismissal_status = Some(DismissalStatus {
                key: None,
                occurrence: None,
                message: "Nothing selected".to_owned(),
            });
            return;
        };
        let Some(row) = self.rows.get_mut(selected) else {
            self.dismissal_status = Some(DismissalStatus {
                key: None,
                occurrence: None,
                message: "Nothing selected".to_owned(),
            });
            return;
        };
        let name = sanitize(row.name());
        let Some(occurrence) = row.occurrence() else {
            self.dismissal_status = Some(DismissalStatus {
                key: Some(row.key.clone()),
                occurrence: None,
                message: format!("Nothing to dismiss for {name}: no active attention"),
            });
            return;
        };
        let reason = row.marker();
        let already_dismissed = row.dismissed();
        row.dismissed = Some(occurrence.clone());
        self.dismissal_status = Some(DismissalStatus {
            key: Some(row.key.clone()),
            occurrence: Some(occurrence),
            message: if already_dismissed {
                format!("Already dismissed {reason} for {name}")
            } else {
                format!("Dismissed {reason} for {name}")
            },
        });
    }

    fn restore_selected(&mut self) {
        let Some(selected) = self.selected else {
            self.dismissal_status = Some(DismissalStatus {
                key: None,
                occurrence: None,
                message: "Nothing selected".to_owned(),
            });
            return;
        };
        let Some(row) = self.rows.get_mut(selected) else {
            self.dismissal_status = Some(DismissalStatus {
                key: None,
                occurrence: None,
                message: "Nothing selected".to_owned(),
            });
            return;
        };
        let name = sanitize(row.name());
        let Some(occurrence) = row.occurrence() else {
            self.dismissal_status = Some(DismissalStatus {
                key: Some(row.key.clone()),
                occurrence: None,
                message: format!("Nothing to restore for {name}: no dismissed attention"),
            });
            return;
        };
        let reason = row.marker();
        let dismissed = row.dismissed();
        if dismissed {
            row.dismissed = None;
        }
        self.dismissal_status = Some(DismissalStatus {
            key: Some(row.key.clone()),
            occurrence: Some(occurrence),
            message: if dismissed {
                format!("Restored {reason} for {name}")
            } else {
                format!("{reason} for {name} is not dismissed")
            },
        });
    }

    fn focus_selected(&mut self) -> Option<FocusRequest> {
        let Some(row) = self.selected.and_then(|selected| self.rows.get(selected)) else {
            self.set_action_status("Nothing selected".to_owned());
            return None;
        };
        let name = sanitize(row.name());
        let unavailable = match row.category {
            RowCategory::Headless => Some("no attached TUI"),
            RowCategory::Ambiguous => Some("TUI association is ambiguous"),
            RowCategory::Unresolved => Some("TUI association is unresolved"),
            RowCategory::Claude if row.is_stale() => Some("Claude process evidence is stale"),
            RowCategory::Claude if row.focus.is_none() => {
                Some("validated terminal focus evidence is unavailable")
            }
            RowCategory::V1 | RowCategory::Attached
                if !row
                    .key
                    .instance()
                    .is_some_and(|instance| self.connected.contains(instance)) =>
            {
                Some("server is disconnected")
            }
            RowCategory::V1 | RowCategory::Attached if row.is_stale() => {
                Some("TUI evidence is stale")
            }
            RowCategory::V1 | RowCategory::Attached if row.focus.is_none() => {
                Some("client focus identifiers are unavailable")
            }
            RowCategory::Claude | RowCategory::V1 | RowCategory::Attached => None,
        };
        if let Some(reason) = unavailable {
            self.set_action_status(format!("Cannot focus {name}: {reason}"));
            return None;
        }
        Some(FocusRequest {
            target: row.focus.clone()?,
            name,
        })
    }

    fn set_action_status(&mut self, message: String) {
        self.dismissal_status = Some(DismissalStatus {
            key: None,
            occurrence: None,
            message,
        });
    }

    pub fn report_focus_result(&mut self, message: &str) {
        self.set_action_status(sanitize(message));
    }

    pub fn handle_terminal_event(
        &mut self,
        event: &Event,
        viewport_height: usize,
    ) -> DashboardAction {
        match event {
            Event::Resize(_, _) => DashboardAction::Redraw,
            Event::Key(key) if is_quit(key) => DashboardAction::Quit,
            Event::Key(key) if matches!(key.code, KeyCode::Up | KeyCode::Char('k')) => {
                self.move_selection(-1, viewport_height);
                DashboardAction::Redraw
            }
            Event::Key(key) if matches!(key.code, KeyCode::Down | KeyCode::Char('j')) => {
                self.move_selection(1, viewport_height);
                DashboardAction::Redraw
            }
            Event::Key(key) if key.code == KeyCode::Right => {
                self.dismiss_selected();
                DashboardAction::Redraw
            }
            Event::Key(key) if key.code == KeyCode::Left => {
                self.restore_selected();
                DashboardAction::Redraw
            }
            Event::Key(key) if key.code == KeyCode::Enter => self
                .focus_selected()
                .map_or(DashboardAction::Redraw, DashboardAction::Focus),
            _ => DashboardAction::Continue,
        }
    }

    pub fn render_at(&mut self, frame: &mut Frame<'_>, now: Instant) {
        let areas = Layout::vertical([
            Constraint::Length(1),
            Constraint::Min(1),
            Constraint::Length(2),
        ])
        .split(frame.area());
        frame.render_widget(
            Paragraph::new("OpenCode Beacon dashboard")
                .style(Style::default().add_modifier(Modifier::BOLD)),
            areas[0],
        );

        let server_counts = self.server_counts();
        let endpoint_duplicates = endpoint_duplicate_sessions(&self.rows);
        let mut rendered_instances = HashSet::new();
        let rows = self.rows.iter().map(|row| {
            let occurrence = row.occurrence();
            let attention_style = occurrence
                .as_ref()
                .map(occurrence_color)
                .unwrap_or_default()
                .add_modifier(if row.dismissed() {
                    Modifier::DIM
                } else {
                    Modifier::empty()
                });
            let state = state_line(row, row.marker(), attention_style, now);
            let session_id = row.key.session_id(&row.session_id);
            let session = if endpoint_duplicates.contains(session_id) {
                format!(
                    "{} @{}",
                    session_id,
                    row.endpoint
                        .map_or_else(|| "-".to_owned(), |endpoint| endpoint.to_string())
                )
            } else {
                session_id.to_owned()
            };
            let memory = row.key.instance().map_or_else(
                || memory_cell(None),
                |instance| {
                    if rendered_instances.insert(instance.clone()) {
                        memory_cell(self.memory.get(instance))
                    } else {
                        Line::default()
                    }
                },
            );
            Row::new([
                Cell::from(sanitize(&session)),
                Cell::from(row.category.label()),
                Cell::from(state),
                Cell::from(memory),
                Cell::from(sanitize(row.name())),
            ])
        });
        let table = Table::new(
            rows,
            [
                Constraint::Length(32),
                Constraint::Length(ATTACHMENT_COLUMN_WIDTH),
                Constraint::Length(STATE_COLUMN_WIDTH),
                Constraint::Length(MEMORY_COLUMN_WIDTH),
                Constraint::Min(10),
            ],
        )
        .header(
            Row::new(["SESSION", "ATTACH", "STATE", "MEM", "TITLE"])
                .style(Style::default().add_modifier(Modifier::BOLD)),
        )
        .block(Block::default().borders(Borders::ALL))
        .row_highlight_style(Style::default().add_modifier(Modifier::BOLD | Modifier::UNDERLINED))
        .highlight_symbol("> ")
        .highlight_spacing(HighlightSpacing::Always);
        let mut state = TableState::default()
            .with_selected(self.selected)
            .with_offset(self.offset);
        frame.render_stateful_widget(table, areas[1], &mut state);
        self.offset = state.offset();

        let summary = format!(
            "q/Ctrl-C quit  Up/Down j/k move  Enter focus  Right dismiss  Left restore | servers {} connected, {} stale",
            server_counts.0, server_counts.1
        );
        let detail = self.selected_memory_detail();
        let status = self.dismissal_status.as_ref().map_or_else(
            || {
                self.diagnostics
                    .back()
                    .map_or(detail.as_str(), String::as_str)
            },
            |status| status.message.as_str(),
        );
        frame.render_widget(
            Paragraph::new(vec![Line::from(summary), Line::from(status)]),
            areas[2],
        );
    }

    fn server_counts(&self) -> (usize, usize) {
        let known = self.endpoint_instances.values().collect::<HashSet<_>>();
        let connected = known
            .iter()
            .filter(|key| self.connected.contains(**key))
            .count();
        (connected, known.len().saturating_sub(connected))
    }

    fn selected_memory_detail(&self) -> String {
        let Some(row) = self.selected.and_then(|selected| self.rows.get(selected)) else {
            return "MEM N/A".to_owned();
        };
        let Some(memory) = row
            .key
            .instance()
            .and_then(|instance| self.memory.get(instance))
        else {
            return "MEM N/A".to_owned();
        };
        let availability = match memory.availability {
            MemoryAvailability::Fresh => "",
            MemoryAvailability::Stale => " stale",
            MemoryAvailability::Unavailable => " N/A",
        };
        let scope = memory.scope.map_or_else(
            || "N/A".to_owned(),
            |CgroupKey { device, inode }| format!("{device}:{inode}"),
        );
        if memory.shared {
            return format!("MEM shared{availability} | scope {scope}");
        }
        let Some(values) = memory.values else {
            return format!("MEM N/A | scope {scope}");
        };
        let trend = memory
            .slope_bytes_per_minute
            .map_or_else(|| "N/A".to_owned(), format_signed_bytes);
        let peak = values.peak.map_or_else(|| "N/A".to_owned(), format_bytes);
        let observed_peak = memory
            .observed_peak
            .map_or_else(|| "N/A".to_owned(), format_bytes);
        format!(
            "MEM total {}{availability} trend {trend}/m | anon {} file {} kernel {} swap {} | peak {peak} observed {observed_peak} | scope {scope}",
            format_bytes(values.current),
            format_bytes(values.anon),
            format_bytes(values.file),
            format_bytes(values.kernel),
            format_bytes(values.swap),
        )
    }

    pub fn next_redraw(&self, now: Instant) -> Option<Instant> {
        self.rows
            .iter()
            .filter(|row| {
                row.busy
                    && !row.is_stale()
                    && row.frozen_busy_elapsed.is_none()
                    && row.occurrence().is_none()
                    && (row.category == RowCategory::Claude
                        || row
                            .key
                            .instance()
                            .is_some_and(|instance| self.connected.contains(instance)))
            })
            .filter_map(|row| {
                let baseline = row.busy_baseline()?;
                let elapsed_minutes = now.saturating_duration_since(baseline).as_secs() / 60;
                if elapsed_minutes >= MAX_ELAPSED_MINUTES {
                    return None;
                }
                baseline.checked_add(
                    MINUTE.saturating_mul(u32::try_from(elapsed_minutes.saturating_add(1)).ok()?),
                )
            })
            .min()
    }
}

fn compare_rows(left: &DashboardRow, right: &DashboardRow) -> Ordering {
    row_group(left.category)
        .cmp(&row_group(right.category))
        .then_with(|| sanitize(left.name()).cmp(&sanitize(right.name())))
        .then_with(|| {
            left.key
                .session_id(&left.session_id)
                .cmp(right.key.session_id(&right.session_id))
        })
        .then_with(|| {
            left.endpoint
                .map(ServerEndpoint::address)
                .cmp(&right.endpoint.map(ServerEndpoint::address))
        })
        .then_with(|| match (&left.key, &right.key) {
            (RowKey::Claude(left), RowKey::Claude(right)) => {
                (left.pid, left.start_time).cmp(&(right.pid, right.start_time))
            }
            _ => Ordering::Equal,
        })
}

const fn row_group(category: RowCategory) -> u8 {
    match category {
        RowCategory::V1 => 0,
        RowCategory::Attached => 1,
        RowCategory::Headless => 2,
        RowCategory::Claude => 3,
        RowCategory::Ambiguous | RowCategory::Unresolved => 4,
    }
}

fn memory_cell(memory: Option<&MemoryView>) -> Line<'static> {
    let text = match memory {
        Some(memory) if memory.shared => "shared".to_owned(),
        Some(MemoryView {
            availability: MemoryAvailability::Fresh,
            values: Some(values),
            ..
        }) => format_bytes(values.current),
        Some(MemoryView {
            availability: MemoryAvailability::Stale,
            ..
        }) => "stale".to_owned(),
        _ => "N/A".to_owned(),
    };
    Line::styled(text, Style::default().fg(Color::DarkGray))
}

fn format_bytes(bytes: u64) -> String {
    const KIB: u64 = 1024;
    const MIB: u64 = KIB * 1024;
    const GIB: u64 = MIB * 1024;
    if bytes >= GIB {
        format_tenths(bytes, GIB, 'G')
    } else if bytes >= MIB {
        format_tenths(bytes, MIB, 'M')
    } else if bytes >= KIB {
        format_tenths(bytes, KIB, 'K')
    } else {
        format!("{bytes}B")
    }
}

fn format_tenths(bytes: u64, unit: u64, suffix: char) -> String {
    let whole = bytes / unit;
    let tenth = bytes % unit * 10 / unit;
    format!("{whole}.{tenth}{suffix}")
}

fn format_signed_bytes(bytes: i64) -> String {
    if bytes < 0 {
        format!("-{}", format_bytes(bytes.unsigned_abs()))
    } else {
        format!("+{}", format_bytes(bytes.unsigned_abs()))
    }
}

fn is_quit(key: &KeyEvent) -> bool {
    key.code == KeyCode::Char('q')
        || (key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL))
}

#[derive(Clone)]
struct RootAggregate {
    id: String,
    title: String,
    slug: String,
    busy: bool,
    retry: bool,
    background_count: usize,
    question_ids: Vec<String>,
    permission_ids: Vec<String>,
}

fn aggregate_roots(sessions: &[ProjectedSession]) -> Vec<RootAggregate> {
    let by_id = sessions
        .iter()
        .map(|session| (session.id.as_str(), session))
        .collect::<HashMap<_, _>>();
    let mut aggregates = HashMap::<String, RootAggregate>::new();
    for session in sessions {
        let root_id = resolve_root(session, &by_id);
        let root = by_id.get(root_id.as_str()).copied().unwrap_or(session);
        let aggregate = aggregates
            .entry(root_id.clone())
            .or_insert_with(|| RootAggregate {
                id: root_id,
                title: root.title.clone(),
                slug: root.slug.clone(),
                busy: matches!(root.status, ProjectedStatus::Busy | ProjectedStatus::Retry),
                retry: root.status == ProjectedStatus::Retry,
                background_count: 0,
                question_ids: Vec::new(),
                permission_ids: Vec::new(),
            });
        aggregate
            .question_ids
            .extend(session.pending_question_ids.clone());
        aggregate
            .permission_ids
            .extend(session.pending_permission_ids.clone());
    }
    let mut aggregates = aggregates.into_values().collect::<Vec<_>>();
    for aggregate in &mut aggregates {
        aggregate.question_ids.sort_unstable();
        aggregate.question_ids.dedup();
        aggregate.permission_ids.sort_unstable();
        aggregate.permission_ids.dedup();
    }
    aggregates.sort_unstable_by(|left, right| left.id.cmp(&right.id));
    aggregates
}

fn aggregate_v2_roots(sessions: &[ProjectedSession]) -> Vec<RootAggregate> {
    let by_id = sessions
        .iter()
        .map(|session| (session.id.as_str(), session))
        .collect::<HashMap<_, _>>();
    let mut aggregates = aggregate_roots(sessions);
    let indexes = aggregates
        .iter()
        .enumerate()
        .map(|(index, aggregate)| (aggregate.id.clone(), index))
        .collect::<HashMap<_, _>>();
    let mut counted = HashSet::new();
    for session in sessions.iter().filter(|session| {
        matches!(
            session.status,
            ProjectedStatus::Busy | ProjectedStatus::Retry
        )
    }) {
        if !counted.insert(session.id.as_str()) {
            continue;
        }
        let root_id = resolve_root(session, &by_id);
        if session.id != root_id
            && let Some(index) = indexes.get(root_id.as_str())
        {
            aggregates[*index].background_count =
                aggregates[*index].background_count.saturating_add(1);
        }
    }
    aggregates
}

fn resolve_root(session: &ProjectedSession, sessions: &HashMap<&str, &ProjectedSession>) -> String {
    let subject = session.id.clone();
    let mut current = session;
    let mut visited = HashSet::new();
    loop {
        if !visited.insert(current.id.as_str()) {
            return subject;
        }
        let Some(parent_id) = current.parent_id.as_deref() else {
            return current.id.clone();
        };
        let Some(parent) = sessions.get(parent_id) else {
            return subject;
        };
        current = parent;
    }
}

fn update_row(
    row: &mut DashboardRow,
    endpoint: ServerEndpoint,
    aggregate: &RootAggregate,
    now: Instant,
) {
    let previous = row.occurrence();
    let was_stale = row.stale;
    let was_busy = row.busy;
    row.endpoint = Some(endpoint);
    row.title.clone_from(&aggregate.title);
    row.slug.clone_from(&aggregate.slug);
    row.busy = aggregate.busy;
    row.retry = aggregate.retry;
    row.background_count = aggregate.background_count;
    row.question_ids.clone_from(&aggregate.question_ids);
    row.permission_ids.clone_from(&aggregate.permission_ids);
    if row.busy {
        if (was_stale || row.frozen_busy_elapsed.is_some())
            && let Some(elapsed) = row.frozen_busy_elapsed
        {
            if row.last_non_busy.is_some() {
                row.last_non_busy = now.checked_sub(elapsed);
            } else if row.first_busy_observed.is_some() {
                row.first_busy_observed = now.checked_sub(elapsed);
            }
        } else if !was_busy && row.last_non_busy.is_none() {
            row.first_busy_observed = Some(now);
        }
        row.frozen_busy_elapsed = None;
        row.dismissed = None;
    } else {
        row.last_non_busy = Some(now);
        row.first_busy_observed = None;
        row.frozen_busy_elapsed = None;
    }
    if previous != row.occurrence() {
        row.dismissed = None;
    }
}

fn new_row(
    key: RowKey,
    endpoint: ServerEndpoint,
    aggregate: &RootAggregate,
    last_non_busy: Option<Instant>,
    now: Instant,
) -> DashboardRow {
    DashboardRow {
        key,
        endpoint: Some(endpoint),
        session_id: aggregate.id.clone(),
        title: aggregate.title.clone(),
        slug: aggregate.slug.clone(),
        busy: aggregate.busy,
        retry: aggregate.retry,
        background_count: aggregate.background_count,
        question_ids: aggregate.question_ids.clone(),
        permission_ids: aggregate.permission_ids.clone(),
        ready_eligible: true,
        ready_generation: 0,
        stale: false,
        attachment_stale: false,
        last_non_busy,
        first_busy_observed: (aggregate.busy && last_non_busy.is_none()).then_some(now),
        frozen_busy_elapsed: None,
        dismissed: None,
        category: RowCategory::V1,
        tui: None,
        focus: None,
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum TuiResolution {
    Attached(String),
    Unresolved {
        ambiguous: bool,
        hint: Option<String>,
    },
}

struct TuiMatch {
    tui: LikelyTui,
    location_roots: Vec<String>,
    fallback: TuiResolution,
    resolution: Option<TuiResolution>,
    blocked: bool,
}

#[allow(clippy::too_many_lines)]
fn resolve_tuis(
    instance: &InstanceKey,
    tuis: &[LikelyTui],
    sessions: &[ProjectedSession],
    sticky: &mut HashMap<(InstanceKey, TuiKey), String>,
) -> Vec<(LikelyTui, TuiResolution)> {
    let by_id = sessions
        .iter()
        .map(|session| (session.id.as_str(), session))
        .collect::<HashMap<_, _>>();
    let roots = sessions
        .iter()
        .map(|session| resolve_root(session, &by_id))
        .collect::<HashSet<_>>();
    sticky.retain(|(sticky_instance, _), root| sticky_instance != instance || roots.contains(root));

    let active_roots = sessions
        .iter()
        .filter(|session| {
            matches!(
                session.status,
                ProjectedStatus::Busy | ProjectedStatus::Retry
            )
        })
        .map(|session| resolve_root(session, &by_id))
        .collect::<HashSet<_>>();
    let mut matches = tuis
        .iter()
        .map(|tui| TuiMatch {
            tui: tui.clone(),
            location_roots: tui_location_roots(tui, sessions, &by_id),
            fallback: resolve_tui(tui, sessions),
            resolution: None,
            blocked: false,
        })
        .collect::<Vec<_>>();
    let mut used_roots = HashSet::new();

    let mut explicit_claims = Vec::new();
    for (index, entry) in matches.iter_mut().enumerate() {
        if let Some(explicit) = &entry.tui.explicit_session {
            entry.blocked = true;
            if let Some(session) = by_id.get(explicit.as_str()) {
                explicit_claims.push((index, resolve_root(session, &by_id)));
            } else {
                entry.resolution = Some(TuiResolution::Unresolved {
                    ambiguous: false,
                    hint: None,
                });
                sticky.remove(&(instance.clone(), entry.tui.key));
            }
        } else if entry.tui.continue_session
            && let TuiResolution::Attached(root) = &entry.fallback
        {
            entry.blocked = true;
            explicit_claims.push((index, root.clone()));
        }
    }
    apply_claims(
        instance,
        &mut matches,
        explicit_claims,
        &mut used_roots,
        sticky,
    );

    let sticky_claims = matches
        .iter()
        .enumerate()
        .filter(|(_, entry)| entry.resolution.is_none() && !entry.blocked)
        .filter_map(|(index, entry)| {
            sticky
                .get(&(instance.clone(), entry.tui.key))
                .filter(|root| roots.contains(*root))
                .cloned()
                .map(|root| (index, root))
        })
        .collect::<Vec<_>>();
    apply_claims(
        instance,
        &mut matches,
        sticky_claims,
        &mut used_roots,
        sticky,
    );

    apply_reciprocal_claims(
        instance,
        &mut matches,
        &mut used_roots,
        sticky,
        |entry, used| {
            entry
                .location_roots
                .iter()
                .filter(|root| !used.contains(*root))
                .cloned()
                .collect()
        },
    );
    apply_reciprocal_claims(
        instance,
        &mut matches,
        &mut used_roots,
        sticky,
        |entry, used| {
            entry
                .location_roots
                .iter()
                .filter(|root| active_roots.contains(*root) && !used.contains(*root))
                .cloned()
                .collect()
        },
    );

    matches
        .into_iter()
        .map(|entry| {
            let resolution = entry.resolution.unwrap_or_else(|| {
                sticky.remove(&(instance.clone(), entry.tui.key));
                match entry.fallback {
                    TuiResolution::Attached(root) => TuiResolution::Unresolved {
                        ambiguous: true,
                        hint: Some(root),
                    },
                    unresolved @ TuiResolution::Unresolved { .. } => unresolved,
                }
            });
            (entry.tui, resolution)
        })
        .collect()
}

fn apply_claims(
    instance: &InstanceKey,
    matches: &mut [TuiMatch],
    claims: Vec<(usize, String)>,
    used_roots: &mut HashSet<String>,
    sticky: &mut HashMap<(InstanceKey, TuiKey), String>,
) {
    let counts = claims.iter().fold(HashMap::new(), |mut counts, (_, root)| {
        *counts.entry(root.clone()).or_insert(0_usize) += 1;
        counts
    });
    for (index, root) in claims {
        let entry = &mut matches[index];
        if counts.get(root.as_str()) == Some(&1) && used_roots.insert(root.clone()) {
            sticky.insert((instance.clone(), entry.tui.key), root.clone());
            entry.resolution = Some(TuiResolution::Attached(root));
        } else {
            sticky.remove(&(instance.clone(), entry.tui.key));
            entry.blocked = true;
            entry.resolution = Some(TuiResolution::Unresolved {
                ambiguous: true,
                hint: Some(root),
            });
        }
    }
}

fn apply_reciprocal_claims<F>(
    instance: &InstanceKey,
    matches: &mut [TuiMatch],
    used_roots: &mut HashSet<String>,
    sticky: &mut HashMap<(InstanceKey, TuiKey), String>,
    candidates: F,
) where
    F: Fn(&TuiMatch, &HashSet<String>) -> Vec<String>,
{
    let by_tui = matches
        .iter()
        .map(|entry| {
            if entry.resolution.is_none() && !entry.blocked {
                candidates(entry, used_roots)
            } else {
                Vec::new()
            }
        })
        .collect::<Vec<_>>();
    let root_counts = by_tui
        .iter()
        .flatten()
        .fold(HashMap::new(), |mut counts, root| {
            *counts.entry(root.clone()).or_insert(0_usize) += 1;
            counts
        });
    let claims = by_tui
        .into_iter()
        .enumerate()
        .filter_map(|(index, roots)| {
            (roots.len() == 1 && root_counts.get(roots[0].as_str()) == Some(&1))
                .then(|| (index, roots[0].clone()))
        })
        .collect::<Vec<_>>();
    apply_claims(instance, matches, claims, used_roots, sticky);
}

fn resolve_tui(tui: &LikelyTui, sessions: &[ProjectedSession]) -> TuiResolution {
    let by_id = sessions
        .iter()
        .map(|session| (session.id.as_str(), session))
        .collect::<HashMap<_, _>>();
    if let Some(explicit) = &tui.explicit_session {
        return by_id.get(explicit.as_str()).map_or(
            TuiResolution::Unresolved {
                ambiguous: false,
                hint: None,
            },
            |session| TuiResolution::Attached(resolve_root(session, &by_id)),
        );
    }

    let mut roots = tui_location_roots(tui, sessions, &by_id);
    if roots.len() == 1 {
        return TuiResolution::Attached(roots.remove(0));
    }
    if roots.is_empty() {
        return TuiResolution::Unresolved {
            ambiguous: false,
            hint: None,
        };
    }

    let mut ranked = roots
        .iter()
        .map(|root| {
            let active = sessions.iter().any(|session| {
                resolve_root(session, &by_id) == *root
                    && matches!(
                        session.status,
                        ProjectedStatus::Busy | ProjectedStatus::Retry
                    )
            });
            let updated = sessions
                .iter()
                .filter(|session| resolve_root(session, &by_id) == *root)
                .filter_map(|session| session.updated)
                .max();
            (root, active, updated)
        })
        .collect::<Vec<_>>();
    if tui.continue_session {
        ranked.sort_unstable_by_key(|(_, _, updated)| std::cmp::Reverse(*updated));
        if ranked
            .first()
            .is_some_and(|(_, _, updated)| updated.is_some())
            && ranked
                .get(1)
                .is_none_or(|(_, _, updated)| updated < &ranked[0].2)
        {
            return TuiResolution::Attached(ranked[0].0.clone());
        }
    }
    let active = ranked
        .iter()
        .filter(|(_, active, _)| *active)
        .collect::<Vec<_>>();
    let hint = if active.len() == 1 {
        Some(active[0].0.clone())
    } else {
        ranked.sort_unstable_by_key(|(_, _, updated)| std::cmp::Reverse(*updated));
        (ranked
            .first()
            .is_some_and(|(_, _, updated)| updated.is_some())
            && ranked
                .get(1)
                .is_none_or(|(_, _, updated)| updated < &ranked[0].2))
        .then(|| ranked[0].0.clone())
    };
    TuiResolution::Unresolved {
        ambiguous: true,
        hint,
    }
}

fn tui_location_roots(
    tui: &LikelyTui,
    sessions: &[ProjectedSession],
    by_id: &HashMap<&str, &ProjectedSession>,
) -> Vec<String> {
    let startup = tui.startup_directory.as_ref().map(|directory| {
        if directory.is_absolute() {
            directory.clone()
        } else {
            tui.cwd.join(directory)
        }
    });
    let mut roots = sessions
        .iter()
        .filter(|session| {
            session_location_matches(session, &tui.cwd)
                || startup
                    .as_deref()
                    .is_some_and(|directory| session_location_matches(session, directory))
        })
        .map(|session| resolve_root(session, by_id))
        .collect::<Vec<_>>();
    roots.sort_unstable();
    roots.dedup();
    roots
}

fn session_location_matches(session: &ProjectedSession, location: &Path) -> bool {
    session.directory.as_deref() == Some(location) || session.workspace.as_deref() == Some(location)
}

fn state_line(
    row: &DashboardRow,
    marker: &'static str,
    marker_style: Style,
    now: Instant,
) -> Line<'static> {
    if row.category == RowCategory::Claude && !row.busy && row.occurrence().is_none() {
        let state = if row.is_stale() {
            "stale unknown"
        } else {
            "unknown"
        };
        return Line::styled(state, Style::default().fg(Color::DarkGray));
    }
    if row.category.has_session_state()
        && row.occurrence().is_none()
        && (!row.busy || row.background_count > 0)
    {
        return v2_state_line(row, now);
    }
    let stale = row.is_stale().then_some("stale");
    let elapsed = if row.occurrence().is_none() && row.busy {
        Some(format_elapsed(
            row.busy_elapsed(now),
            row.busy_elapsed_is_lower_bound(),
        ))
    } else {
        None
    };
    let mut spans = Vec::with_capacity(3);
    if !marker.is_empty() {
        if row.dismissed() {
            if let Some(stale) = stale {
                spans.push(Span::raw(stale));
                spans.push(Span::raw(
                    " ".repeat(STATE_WIDTH.saturating_sub(stale.len() + marker.len())),
                ));
            } else {
                spans.push(Span::raw(
                    " ".repeat(STATE_WIDTH.saturating_sub(marker.len())),
                ));
            }
            spans.push(Span::styled(marker, marker_style));
        } else {
            spans.push(Span::styled(marker, marker_style));
            if stale.is_some() {
                spans.push(Span::raw(" stale"));
            }
        }
    } else if let Some(stale) = stale {
        spans.push(Span::raw(stale));
    }
    if let Some(elapsed) = elapsed {
        let left_width = stale.map_or(0, str::len);
        let padding = STATE_WIDTH.saturating_sub(left_width + elapsed.len());
        spans.push(Span::raw(" ".repeat(padding)));
        spans.push(Span::styled(elapsed, Style::default().fg(Color::DarkGray)));
    }
    Line::from(spans)
}

fn v2_state_line(row: &DashboardRow, now: Instant) -> Line<'static> {
    let state = if row.busy {
        let foreground = if row.retry { "retry" } else { "busy" };
        let elapsed = format_elapsed(row.busy_elapsed(now), row.busy_elapsed_is_lower_bound());
        if row.background_count == 0 {
            format!("{foreground} {}", elapsed.trim())
        } else {
            format!(
                "{foreground} {} +{} background",
                elapsed.trim(),
                row.background_count
            )
        }
    } else {
        debug_assert!(row.background_count > 0);
        format!("background {}", row.background_count)
    };
    let text = if row.is_stale() {
        format!("stale {state}")
    } else {
        state
    };
    Line::styled(text, Style::default().fg(Color::DarkGray))
}

fn format_elapsed(elapsed: Option<Duration>, lower_bound: bool) -> String {
    let minutes = elapsed
        .map(|elapsed| (elapsed.as_secs() / 60).min(MAX_ELAPSED_MINUTES))
        .unwrap_or_default();
    if lower_bound {
        format!("{value:>ELAPSED_WIDTH$}", value = format!("> {minutes}m"))
    } else {
        format!("{minutes:>width$}m", width = ELAPSED_WIDTH - 1)
    }
}

fn occurrence_color(occurrence: &Occurrence) -> Style {
    Style::default().fg(match occurrence {
        Occurrence::Question(_) => Color::Blue,
        Occurrence::Permission(_) => Color::LightYellow,
        Occurrence::Ready(_) => Color::Green,
    })
}

fn endpoint_duplicate_sessions(rows: &[DashboardRow]) -> HashSet<String> {
    let mut endpoints = HashMap::<&str, HashSet<ServerEndpoint>>::new();
    for row in rows {
        if let (Some(_), Some(endpoint)) = (row.key.instance(), row.endpoint) {
            endpoints
                .entry(row.key.session_id(&row.session_id))
                .or_default()
                .insert(endpoint);
        }
    }
    endpoints
        .into_iter()
        .filter_map(|(id, endpoints)| (endpoints.len() > 1).then(|| id.to_owned()))
        .collect()
}

fn sanitize(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_control() || matches!(character, '\u{2028}' | '\u{2029}') {
                ' '
            } else {
                character
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::path::PathBuf;

    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    use super::*;
    use opencode_beacon::model::{AttentionEvent, InstanceSource, TransitionSource};

    fn claude_projection(status: ClaudeStatus, stale: bool) -> BeaconEvent {
        BeaconEvent::ClaudeStateProjection(ClaudeProjection {
            session: opencode_beacon::ClaudeSession {
                key: ClaudeSessionKey {
                    pid: 700,
                    start_time: 9000,
                },
                session_id: "claude-session".to_owned(),
                cwd: PathBuf::from("/workspace/claude-project"),
                name: Some("Claude project".to_owned()),
                has_tty: true,
            },
            status,
            stale,
        })
    }

    #[test]
    fn claude_initial_idle_focus_requires_fresh_validated_konsole_or_kitty_evidence() {
        let mut model = DashboardModel::default();
        let now = Instant::now();
        model.apply_at(claude_projection(ClaudeStatus::Idle, false), now);

        assert_eq!(model.rows.len(), 1);
        assert_eq!(model.rows[0].category, RowCategory::Claude);
        assert_eq!(model.rows[0].occurrence(), Some(Occurrence::Ready(0)));
        assert_eq!(
            memory_cell(
                model.rows[0]
                    .key
                    .instance()
                    .and_then(|key| model.memory.get(key))
            )
            .to_string(),
            "N/A"
        );
        assert_eq!(
            model.handle_terminal_event(&key_event(KeyCode::Enter), 5),
            DashboardAction::Redraw
        );
        assert_eq!(
            model
                .dismissal_status
                .as_ref()
                .map(|status| status.message.as_str()),
            Some("Cannot focus Claude project: validated terminal focus evidence is unavailable")
        );

        let process = TuiKey {
            pid: 700,
            start_time: 9000,
        };
        let konsole = FocusTarget {
            process,
            source: crate::attachment::FocusProcessSource::Claude,
            client: crate::attachment::ClientFocusTarget::Konsole(
                crate::attachment::KonsoleTarget {
                    service: ":1.108".to_owned(),
                    session_path: "/Sessions/4".to_owned(),
                    window_path: "/Windows/9".to_owned(),
                },
            ),
        };
        model.apply_attachments(
            AttachmentSnapshot {
                claude_focus: HashMap::from([(process, konsole.clone())]),
                ..AttachmentSnapshot::default()
            },
            now,
        );
        assert_eq!(
            model.handle_terminal_event(&key_event(KeyCode::Enter), 5),
            DashboardAction::Focus(FocusRequest {
                target: konsole,
                name: "Claude project".to_owned(),
            })
        );

        let kitty = FocusTarget {
            process,
            source: crate::attachment::FocusProcessSource::Claude,
            client: crate::attachment::ClientFocusTarget::Kitty(crate::attachment::KittyTarget {
                process: TuiKey {
                    pid: 500,
                    start_time: 8000,
                },
                window_id: 7,
                socket_path: PathBuf::from("/run/user/1000/kitty-500"),
                socket_device: 1,
                socket_inode: 2,
            }),
        };
        model.apply_attachments(
            AttachmentSnapshot {
                claude_focus: HashMap::from([(process, kitty.clone())]),
                ..AttachmentSnapshot::default()
            },
            now,
        );
        assert_eq!(
            model.handle_terminal_event(&key_event(KeyCode::Enter), 5),
            DashboardAction::Focus(FocusRequest {
                target: kitty,
                name: "Claude project".to_owned(),
            })
        );

        model.apply_at(claude_projection(ClaudeStatus::Idle, true), now);
        assert_eq!(
            model.handle_terminal_event(&key_event(KeyCode::Enter), 5),
            DashboardAction::Redraw
        );
        assert_eq!(
            model
                .dismissal_status
                .as_ref()
                .map(|status| status.message.as_str()),
            Some("Cannot focus Claude project: Claude process evidence is stale")
        );
    }

    #[test]
    fn claude_dashboard_omits_headless_sessions_and_removes_rows_that_lose_tty() {
        let mut model = DashboardModel::default();
        let now = Instant::now();
        let BeaconEvent::ClaudeStateProjection(mut projection) =
            claude_projection(ClaudeStatus::Idle, false)
        else {
            unreachable!("fixture is a Claude projection");
        };
        projection.session.has_tty = false;

        model.apply_at(BeaconEvent::ClaudeStateProjection(projection.clone()), now);
        assert!(model.rows.is_empty());

        projection.session.has_tty = true;
        model.apply_at(BeaconEvent::ClaudeStateProjection(projection.clone()), now);
        assert_eq!(model.rows.len(), 1);

        projection.session.has_tty = false;
        model.apply_at(BeaconEvent::ClaudeStateProjection(projection), now);
        assert!(model.rows.is_empty());
    }

    #[test]
    fn claude_unknown_never_claims_ready_and_live_ready_advances_generation() {
        let mut model = DashboardModel::default();
        let now = Instant::now();
        model.apply_at(claude_projection(ClaudeStatus::Unknown, false), now);
        assert_eq!(model.rows[0].occurrence(), None);
        let screenshot = format!("{:?}", rendered(&mut model, 140, 8));
        assert!(screenshot.contains("unknown"));
        assert!(!screenshot.contains("background 0"));

        model.apply_at(claude_projection(ClaudeStatus::Busy, false), now);
        assert!(model.rows[0].busy);
        model.apply_at(
            BeaconEvent::ClaudeAttention(opencode_beacon::ClaudeAttentionEvent {
                kind: AttentionKind::Ready,
                session: match claude_projection(ClaudeStatus::Idle, false) {
                    BeaconEvent::ClaudeStateProjection(projection) => projection.session,
                    _ => unreachable!("fixture is a Claude projection"),
                },
                initial: false,
            }),
            now,
        );
        assert_eq!(model.rows[0].occurrence(), Some(Occurrence::Ready(1)));
        model.apply_at(claude_projection(ClaudeStatus::Idle, false), now);
        assert_eq!(model.rows[0].occurrence(), Some(Occurrence::Ready(1)));
    }

    #[test]
    fn claude_stale_busy_elapsed_freezes_and_resumes_without_stale_time() {
        let mut model = DashboardModel::default();
        let start = Instant::now();
        model.apply_at(claude_projection(ClaudeStatus::Busy, false), start);
        model.apply_at(
            claude_projection(ClaudeStatus::Busy, true),
            start + Duration::from_secs(30),
        );
        assert_eq!(
            model.rows[0].busy_elapsed(start + Duration::from_secs(90)),
            Some(Duration::from_secs(30))
        );

        model.apply_at(
            claude_projection(ClaudeStatus::Busy, false),
            start + Duration::from_secs(120),
        );
        assert_eq!(
            model.rows[0].busy_elapsed(start + Duration::from_secs(120)),
            Some(Duration::from_secs(30))
        );
        assert!(model.rows[0].frozen_busy_elapsed.is_none());
    }

    #[test]
    fn claude_rows_use_identity_for_order_and_removal_clears_dismissal() {
        let mut model = DashboardModel::default();
        let now = Instant::now();
        let BeaconEvent::ClaudeStateProjection(mut second) =
            claude_projection(ClaudeStatus::Idle, false)
        else {
            unreachable!("fixture is a Claude projection");
        };
        second.session.key.pid = 701;
        model.apply_at(BeaconEvent::ClaudeStateProjection(second), now);
        model.apply_at(claude_projection(ClaudeStatus::Idle, false), now);
        assert_eq!(
            model
                .rows
                .iter()
                .map(|row| match row.key {
                    RowKey::Claude(key) => key.pid,
                    RowKey::OpenCode { .. } => 0,
                })
                .collect::<Vec<_>>(),
            [700, 701]
        );

        model.handle_terminal_event(&key_event(KeyCode::Up), 5);
        model.handle_terminal_event(&key_event(KeyCode::Right), 5);
        assert!(model.rows[0].dismissed());
        let removed = match claude_projection(ClaudeStatus::Idle, false) {
            BeaconEvent::ClaudeStateProjection(projection) => projection.session,
            _ => unreachable!("fixture is a Claude projection"),
        };
        model.apply_at(BeaconEvent::ClaudeSessionRemoved(removed), now);
        assert_eq!(model.rows.len(), 1);
        assert!(model.dismissal_status.is_none());
    }

    fn endpoint(port: u16) -> ServerEndpoint {
        ServerEndpoint::new(SocketAddr::from(([127, 0, 0, 1], port)))
            .unwrap_or_else(|error| unreachable!("test endpoint is loopback: {error}"))
    }

    fn key(socket_inode: u64, port: u16) -> InstanceKey {
        InstanceKey {
            network_namespace_inode: 1,
            socket_inode,
            listener: endpoint(port).address(),
            pid: u32::try_from(socket_inode).unwrap_or(1),
            source: InstanceSource::LinuxProcfs,
        }
    }

    fn managed_key(pid: u32, port: u16) -> InstanceKey {
        InstanceKey {
            network_namespace_inode: 0,
            socket_inode: 0,
            listener: endpoint(port).address(),
            pid,
            source: InstanceSource::ManagedService {
                registration: PathBuf::from("/state/service.json"),
                id: Some("service".to_owned()),
            },
        }
    }

    fn tui(instance: &InstanceKey, pid: u32, directory: &str) -> LikelyTui {
        let process = TuiKey {
            pid,
            start_time: u64::from(pid) * 10,
        };
        LikelyTui {
            key: process,
            instance: instance.clone(),
            kind: crate::attachment::InteractiveKind::Full,
            cwd: PathBuf::from(directory),
            startup_directory: None,
            explicit_session: None,
            continue_session: false,
            focus: Some(FocusTarget {
                process,
                source: crate::attachment::FocusProcessSource::OpenCode,
                client: crate::attachment::ClientFocusTarget::Konsole(
                    crate::attachment::KonsoleTarget {
                        service: ":1.108".to_owned(),
                        session_path: "/Sessions/1".to_owned(),
                        window_path: "/Windows/1".to_owned(),
                    },
                ),
            }),
            stale: false,
        }
    }

    fn session(
        id: &str,
        title: &str,
        parent_id: Option<&str>,
        status: ProjectedStatus,
        questions: &[&str],
        permissions: &[&str],
    ) -> ProjectedSession {
        ProjectedSession {
            id: id.to_owned(),
            title: title.to_owned(),
            slug: format!("{id}-slug"),
            parent_id: parent_id.map(ToOwned::to_owned),
            project_id: None,
            directory: None,
            workspace: None,
            updated: None,
            status,
            pending_permission_ids: permissions.iter().map(|id| (*id).to_owned()).collect(),
            pending_question_ids: questions.iter().map(|id| (*id).to_owned()).collect(),
        }
    }

    fn projection(
        instance: InstanceKey,
        endpoint: ServerEndpoint,
        sessions: Vec<ProjectedSession>,
    ) -> BeaconEvent {
        BeaconEvent::StateProjection(ServerProjection {
            instance_key: instance,
            endpoint,
            sessions,
        })
    }

    #[test]
    fn v2_attached_idle_is_primary_and_busy_without_tui_is_headless() {
        let endpoint = endpoint(4100);
        let instance = managed_key(900, 4100);
        let mut root = session(
            "root",
            "Attached idle",
            None,
            ProjectedStatus::Idle,
            &[],
            &[],
        );
        root.directory = Some(PathBuf::from("/workspace"));
        root.project_id = Some("project".to_owned());
        root.updated = Some(20);
        let child = session(
            "child",
            "Child",
            Some("root"),
            ProjectedStatus::Idle,
            &[],
            &[],
        );
        let mut busy = session(
            "busy",
            "Unattached execution",
            None,
            ProjectedStatus::Busy,
            &[],
            &[],
        );
        busy.directory = Some(PathBuf::from("/other"));
        let mut model = DashboardModel::default();
        model.apply(found(instance.clone(), endpoint));
        model.apply(projection(
            instance.clone(),
            endpoint,
            vec![root, child, busy],
        ));
        let mut attached = tui(&instance, 901, "/unrelated");
        attached.explicit_session = Some("child".to_owned());
        model.apply_attachments(
            AttachmentSnapshot {
                tuis: vec![attached],
                v1_focus: HashMap::new(),
                claude_focus: HashMap::new(),
                diagnostic: None,
            },
            Instant::now(),
        );

        assert!(model.rows.iter().any(|row| {
            row.session_id == "root" && row.category == RowCategory::Attached && !row.busy
        }));
        assert!(model.rows.iter().any(|row| {
            row.session_id == "busy" && row.category == RowCategory::Headless && row.busy
        }));
        let buffer = rendered(&mut model, 140, 10);
        assert!(format!("{buffer:?}").contains("attached"));
        assert!(format!("{buffer:?}").contains("headless"));
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn dashboard_orders_stable_groups_by_displayed_title_then_session() {
        let v1_endpoint = endpoint(4099);
        let v1_instance = key(899, 4099);
        let endpoint = endpoint(4100);
        let instance = managed_key(900, 4100);
        let located = |id: &str, title: &str, directory: &str, updated| {
            let mut value = session(id, title, None, ProjectedStatus::Idle, &[], &[]);
            value.directory = Some(PathBuf::from(directory));
            value.updated = updated;
            value
        };
        let mut model = DashboardModel::default();
        model.apply(found(v1_instance.clone(), v1_endpoint));
        model.apply(projection(
            v1_instance,
            v1_endpoint,
            vec![session(
                "v1",
                "Zulu v1",
                None,
                ProjectedStatus::Busy,
                &[],
                &[],
            )],
        ));
        model.apply(found(instance.clone(), endpoint));
        model.apply(projection(
            instance.clone(),
            endpoint,
            vec![
                located("control", "\nAble", "/attached-control", None),
                located("same-z", "Same", "/attached-z", None),
                located("alpha", "Alpha", "/attached-alpha", None),
                located("same-a", "Same", "/attached-a", None),
                session("head-z", "Head", None, ProjectedStatus::Busy, &[], &[]),
                session("head-a", "Head", None, ProjectedStatus::Busy, &[], &[]),
                located("amb-old", "Old", "/shared", Some(10)),
                located("amb-new", "New", "/shared", Some(20)),
            ],
        ));
        let explicit = |pid, root: &str| {
            let mut value = tui(&instance, pid, "/ignored");
            value.explicit_session = Some(root.to_owned());
            value
        };
        let mut missing_a = explicit(906, "missing");
        missing_a.cwd = PathBuf::from("/a");
        let mut missing_z = explicit(905, "missing");
        missing_z.cwd = PathBuf::from("/z");
        model.apply_attachments(
            AttachmentSnapshot {
                tuis: vec![
                    explicit(904, "control"),
                    explicit(903, "same-z"),
                    explicit(901, "alpha"),
                    explicit(902, "same-a"),
                    missing_z,
                    tui(&instance, 907, "/shared"),
                    missing_a,
                ],
                ..AttachmentSnapshot::default()
            },
            Instant::now(),
        );

        assert_eq!(
            model
                .rows
                .iter()
                .map(|row| (row.category, row.session_id.as_str()))
                .collect::<Vec<_>>(),
            [
                (RowCategory::V1, "v1"),
                (RowCategory::Attached, "control"),
                (RowCategory::Attached, "alpha"),
                (RowCategory::Attached, "same-a"),
                (RowCategory::Attached, "same-z"),
                (RowCategory::Headless, "head-a"),
                (RowCategory::Headless, "head-z"),
                (RowCategory::Unresolved, "PID 906"),
                (RowCategory::Ambiguous, "PID 907"),
                (RowCategory::Unresolved, "PID 905"),
            ]
        );
    }

    #[test]
    fn dashboard_reorders_only_for_metadata_and_preserves_selection_identity() {
        let endpoint = endpoint(4101);
        let instance = managed_key(910, 4101);
        let roots = |first_title: &str, first_status| {
            vec![
                session("first", first_title, None, first_status, &[], &[]),
                session("second", "Beta", None, ProjectedStatus::Idle, &[], &[]),
                session("selected", "Gamma", None, ProjectedStatus::Idle, &[], &[]),
            ]
        };
        let attachments = |reverse| {
            let ids = if reverse {
                ["selected", "second", "first"]
            } else {
                ["first", "second", "selected"]
            };
            AttachmentSnapshot {
                tuis: ids
                    .into_iter()
                    .zip([911, 912, 913])
                    .map(|(id, pid)| {
                        let mut value = tui(&instance, pid, "/ignored");
                        value.explicit_session = Some(id.to_owned());
                        value
                    })
                    .collect(),
                ..AttachmentSnapshot::default()
            }
        };
        let ids = |model: &DashboardModel| {
            model
                .rows
                .iter()
                .map(|row| row.session_id.clone())
                .collect::<Vec<_>>()
        };
        let mut model = DashboardModel::default();
        model.apply(found(instance.clone(), endpoint));
        model.apply(projection(
            instance.clone(),
            endpoint,
            roots("Zulu", ProjectedStatus::Idle),
        ));
        model.apply_attachments(attachments(false), Instant::now());
        assert_eq!(ids(&model), ["second", "selected", "first"]);
        model.move_selection(1, 5);

        model.apply(projection(
            instance.clone(),
            endpoint,
            roots("Zulu", ProjectedStatus::Retry),
        ));
        assert_eq!(ids(&model), ["second", "selected", "first"]);
        assert_eq!(
            model.rows[model.selected.unwrap_or_default()].session_id,
            "selected"
        );

        model.apply(projection(
            instance.clone(),
            endpoint,
            roots("Alpha", ProjectedStatus::Retry),
        ));
        assert_eq!(ids(&model), ["first", "second", "selected"]);
        assert_eq!(model.selected, Some(2));

        model.apply_attachments(attachments(true), Instant::now());
        assert_eq!(ids(&model), ["first", "second", "selected"]);
        assert_eq!(model.selected, Some(2));
    }

    #[test]
    fn procfs_standalone_uses_v2_attachment_rows() {
        let endpoint = endpoint(4101);
        let instance = key(901, 4101);
        let mut root = session(
            "root",
            "Standalone idle",
            None,
            ProjectedStatus::Idle,
            &[],
            &[],
        );
        root.directory = Some(PathBuf::from("/workspace"));
        let mut model = DashboardModel::default();
        model.apply(BeaconEvent::ServerFound(server_instance(
            instance.clone(),
            endpoint,
            OpenCodeProtocol::V2,
        )));
        model.apply(projection(instance.clone(), endpoint, vec![root]));
        model.apply_attachments(
            AttachmentSnapshot {
                tuis: vec![tui(&instance, 902, "/workspace")],
                v1_focus: HashMap::new(),
                claude_focus: HashMap::new(),
                diagnostic: None,
            },
            Instant::now(),
        );
        assert!(
            model
                .rows
                .iter()
                .any(|row| { row.session_id == "root" && row.category == RowCategory::Attached })
        );
        assert!(!model.rows.iter().any(|row| row.category == RowCategory::V1));
    }

    #[test]
    fn v2_resolution_orders_explicit_continue_unique_then_unresolved_tiebreaks() {
        let instance = managed_key(910, 4110);
        let mut old = session("old", "Old", None, ProjectedStatus::Idle, &[], &[]);
        old.directory = Some(PathBuf::from("/workspace"));
        old.project_id = Some("project".to_owned());
        old.updated = Some(10);
        let mut recent = session("recent", "Recent", None, ProjectedStatus::Busy, &[], &[]);
        recent.workspace = Some(PathBuf::from("/workspace"));
        recent.project_id = Some("project".to_owned());
        recent.updated = Some(20);
        let sessions = vec![old.clone(), recent];

        let mut explicit = tui(&instance, 911, "/elsewhere");
        explicit.explicit_session = Some("old".to_owned());
        assert_eq!(
            resolve_tui(&explicit, &sessions),
            TuiResolution::Attached("old".to_owned())
        );

        let mut continued = tui(&instance, 912, "/workspace");
        continued.continue_session = true;
        assert_eq!(
            resolve_tui(&continued, &sessions),
            TuiResolution::Attached("recent".to_owned())
        );

        let unique = tui(&instance, 913, "/unique");
        old.directory = Some(PathBuf::from("/unique"));
        assert_eq!(
            resolve_tui(&unique, &[old]),
            TuiResolution::Attached("old".to_owned())
        );

        let unresolved = tui(&instance, 914, "/workspace");
        assert_eq!(
            resolve_tui(&unresolved, &sessions),
            TuiResolution::Unresolved {
                ambiguous: true,
                hint: Some("recent".to_owned()),
            }
        );
    }

    #[test]
    fn v2_screenshot_pairs_tui_with_unique_descendant_active_root_without_duplicate() {
        let endpoint = endpoint(4120);
        let instance = managed_key(920, 4120);
        let mut first = session("first", "First", None, ProjectedStatus::Idle, &[], &[]);
        first.directory = Some(PathBuf::from("/workspace"));
        first.updated = Some(20);
        let active_child = session(
            "active-child",
            "Active child",
            Some("first"),
            ProjectedStatus::Busy,
            &[],
            &[],
        );
        let mut second = session("second", "Second", None, ProjectedStatus::Idle, &[], &[]);
        second.directory = Some(PathBuf::from("/workspace"));
        second.updated = Some(10);
        let mut model = DashboardModel::default();
        model.apply(found(instance.clone(), endpoint));
        model.apply(projection(
            instance.clone(),
            endpoint,
            vec![first, active_child, second],
        ));
        model.apply_attachments(
            AttachmentSnapshot {
                tuis: vec![tui(&instance, 921, "/workspace")],
                v1_focus: HashMap::new(),
                claude_focus: HashMap::new(),
                diagnostic: None,
            },
            Instant::now(),
        );
        assert_eq!(model.rows.len(), 1);
        assert_eq!(model.rows[0].category, RowCategory::Attached);
        assert_eq!(model.rows[0].session_id, "first");
        assert_eq!(model.rows[0].tui.map(|key| key.pid), Some(921));
        assert_eq!(model.rows[0].background_count, 1);
        assert!(
            !model
                .rows
                .iter()
                .any(|row| row.category == RowCategory::Headless)
        );
        let buffer = rendered(&mut model, 140, 8);
        let screenshot = format!("{buffer:?}");
        assert!(screenshot.contains("attached"));
        assert!(screenshot.contains("background 1"));
        assert!(!screenshot.contains("headless"));
        assert!(!screenshot.contains("ambiguous"));
    }

    #[test]
    fn v2_screenshot_pairs_tui_with_unique_root_active_without_duplicate() {
        let endpoint = endpoint(4125);
        let instance = managed_key(930, 4125);
        let mut active = session("active", "Active", None, ProjectedStatus::Busy, &[], &[]);
        active.directory = Some(PathBuf::from("/workspace"));
        let mut idle = session("idle", "Idle", None, ProjectedStatus::Idle, &[], &[]);
        idle.directory = Some(PathBuf::from("/workspace"));
        let mut model = DashboardModel::default();
        model.apply(found(instance.clone(), endpoint));
        model.apply(projection(instance.clone(), endpoint, vec![active, idle]));
        model.apply_attachments(
            AttachmentSnapshot {
                tuis: vec![tui(&instance, 931, "/workspace")],
                v1_focus: HashMap::new(),
                claude_focus: HashMap::new(),
                diagnostic: None,
            },
            Instant::now(),
        );

        assert_eq!(model.rows.len(), 1);
        assert_eq!(model.rows[0].category, RowCategory::Attached);
        assert_eq!(model.rows[0].session_id, "active");
        assert!(model.rows[0].busy);
        let screenshot = format!("{:?}", rendered(&mut model, 140, 8));
        assert!(screenshot.contains("attached"));
        assert!(!screenshot.contains("headless"));
        assert!(!screenshot.contains("ambiguous"));
    }

    #[test]
    fn v2_reciprocal_collision_retains_ambiguity_and_headless_root() {
        let endpoint = endpoint(4121);
        let instance = managed_key(922, 4121);
        let mut busy = session("busy", "Busy", None, ProjectedStatus::Idle, &[], &[]);
        busy.directory = Some(PathBuf::from("/workspace"));
        let busy_child = session(
            "busy-child",
            "Busy child",
            Some("busy"),
            ProjectedStatus::Busy,
            &[],
            &[],
        );
        let mut idle = session("idle", "Idle", None, ProjectedStatus::Idle, &[], &[]);
        idle.directory = Some(PathBuf::from("/workspace"));
        let mut model = DashboardModel::default();
        model.apply(found(instance.clone(), endpoint));
        model.apply(projection(
            instance.clone(),
            endpoint,
            vec![busy, busy_child, idle],
        ));
        model.apply_attachments(
            AttachmentSnapshot {
                tuis: vec![
                    tui(&instance, 923, "/workspace"),
                    tui(&instance, 924, "/workspace"),
                ],
                v1_focus: HashMap::new(),
                claude_focus: HashMap::new(),
                diagnostic: None,
            },
            Instant::now(),
        );

        assert_eq!(
            model
                .rows
                .iter()
                .filter(|row| row.category == RowCategory::Ambiguous)
                .count(),
            2
        );
        assert!(
            model
                .rows
                .iter()
                .any(|row| { row.category == RowCategory::Headless && row.session_id == "busy" })
        );
        assert!(
            !model
                .rows
                .iter()
                .any(|row| row.category == RowCategory::Attached)
        );
    }

    #[test]
    fn v2_reciprocal_root_collision_retains_ambiguity_and_both_headless_roots() {
        let endpoint = endpoint(4124);
        let instance = managed_key(929, 4124);
        let mut first_busy = session(
            "first-busy",
            "First busy",
            None,
            ProjectedStatus::Busy,
            &[],
            &[],
        );
        first_busy.directory = Some(PathBuf::from("/shared"));
        let mut second_busy = session(
            "second-busy",
            "Second busy",
            None,
            ProjectedStatus::Busy,
            &[],
            &[],
        );
        second_busy.directory = Some(PathBuf::from("/shared"));
        let mut two_roots = DashboardModel::default();
        two_roots.apply(found(instance.clone(), endpoint));
        two_roots.apply(projection(
            instance.clone(),
            endpoint,
            vec![first_busy, second_busy],
        ));
        two_roots.apply_attachments(
            AttachmentSnapshot {
                tuis: vec![tui(&instance, 929, "/shared")],
                v1_focus: HashMap::new(),
                claude_focus: HashMap::new(),
                diagnostic: None,
            },
            Instant::now(),
        );
        assert_eq!(
            two_roots
                .rows
                .iter()
                .filter(|row| row.category == RowCategory::Ambiguous)
                .count(),
            1
        );
        assert_eq!(
            two_roots
                .rows
                .iter()
                .filter(|row| row.category == RowCategory::Headless)
                .count(),
            2
        );
        assert!(
            !two_roots
                .rows
                .iter()
                .any(|row| row.category == RowCategory::Attached)
        );
    }

    #[test]
    fn v2_reciprocal_pair_stays_sticky_when_root_becomes_idle() {
        let endpoint = endpoint(4122);
        let instance = managed_key(925, 4122);
        let located = |id, title| {
            let mut session = session(id, title, None, ProjectedStatus::Idle, &[], &[]);
            session.directory = Some(PathBuf::from("/workspace"));
            session
        };
        let child = |status| session("child", "Child", Some("active"), status, &[], &[]);
        let mut model = DashboardModel::default();
        model.apply(found(instance.clone(), endpoint));
        model.apply(projection(
            instance.clone(),
            endpoint,
            vec![
                located("active", "Active"),
                child(ProjectedStatus::Busy),
                located("other", "Other"),
            ],
        ));
        model.apply_attachments(
            AttachmentSnapshot {
                tuis: vec![tui(&instance, 926, "/workspace")],
                v1_focus: HashMap::new(),
                claude_focus: HashMap::new(),
                diagnostic: None,
            },
            Instant::now(),
        );
        model.apply(projection(
            instance.clone(),
            endpoint,
            vec![
                located("active", "Active"),
                child(ProjectedStatus::Idle),
                located("other", "Other"),
            ],
        ));

        assert_eq!(model.rows.len(), 1);
        assert_eq!(model.rows[0].category, RowCategory::Attached);
        assert_eq!(model.rows[0].session_id, "active");
        assert!(!model.rows[0].busy);
        assert_eq!(
            model
                .sticky_attachments
                .get(&(
                    instance,
                    TuiKey {
                        pid: 926,
                        start_time: 9260
                    }
                ))
                .map(String::as_str),
            Some("active")
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn v2_process_session_instance_and_explicit_changes_clear_sticky_pairing() {
        let endpoint = endpoint(4123);
        let instance = managed_key(927, 4123);
        let located = |id, status| {
            let mut session = session(id, id, None, status, &[], &[]);
            session.directory = Some(PathBuf::from("/workspace"));
            session
        };
        let tui_key = TuiKey {
            pid: 928,
            start_time: 9280,
        };
        let mut observed = tui(&instance, tui_key.pid, "/workspace");
        let mut model = DashboardModel::default();
        model.apply(found(instance.clone(), endpoint));
        model.apply(projection(
            instance.clone(),
            endpoint,
            vec![
                located("first", ProjectedStatus::Busy),
                located("second", ProjectedStatus::Idle),
            ],
        ));
        model.apply_attachments(
            AttachmentSnapshot {
                tuis: vec![observed.clone()],
                ..AttachmentSnapshot::default()
            },
            Instant::now(),
        );

        observed.explicit_session = Some("second".to_owned());
        model.apply_attachments(
            AttachmentSnapshot {
                tuis: vec![observed],
                ..AttachmentSnapshot::default()
            },
            Instant::now(),
        );
        assert_eq!(
            model
                .rows
                .iter()
                .find(|row| row.tui == Some(tui_key))
                .map(|row| row.session_id.as_str()),
            Some("second")
        );
        assert_eq!(
            model
                .sticky_attachments
                .get(&(instance.clone(), tui_key))
                .map(String::as_str),
            Some("second")
        );

        model.apply(projection(
            instance.clone(),
            endpoint,
            vec![located("first", ProjectedStatus::Busy)],
        ));
        assert!(
            !model
                .sticky_attachments
                .contains_key(&(instance.clone(), tui_key))
        );

        model.apply_attachments(AttachmentSnapshot::default(), Instant::now());
        assert!(model.sticky_attachments.is_empty());
        let headless = model
            .rows
            .iter()
            .find(|row| row.category == RowCategory::Headless)
            .unwrap_or_else(|| unreachable!("headless row"));
        assert_eq!(
            (
                headless.session_id.as_str(),
                headless.attachment_stale,
                headless.tui,
                headless.focus.as_ref()
            ),
            ("first", false, None, None)
        );

        model.apply_attachments(
            AttachmentSnapshot {
                tuis: vec![tui(&instance, tui_key.pid, "/workspace")],
                ..AttachmentSnapshot::default()
            },
            Instant::now(),
        );
        assert!(
            model
                .sticky_attachments
                .contains_key(&(instance.clone(), tui_key))
        );
        model.apply_attachments(AttachmentSnapshot::default(), Instant::now());
        assert!(model.sticky_attachments.is_empty());
        assert!(
            model
                .rows
                .iter()
                .any(|row| { row.category == RowCategory::Headless && row.session_id == "first" })
        );

        model.apply_attachments(
            AttachmentSnapshot {
                tuis: vec![tui(&instance, tui_key.pid, "/workspace")],
                ..AttachmentSnapshot::default()
            },
            Instant::now(),
        );
        model.apply(BeaconEvent::ServerRemoved(server_instance(
            instance,
            endpoint,
            OpenCodeProtocol::V2,
        )));
        assert!(model.sticky_attachments.is_empty());
    }

    #[test]
    fn v2_child_execution_is_visible_as_headless_root_activity() {
        let endpoint = endpoint(4130);
        let instance = managed_key(930, 4130);
        let root = session("root", "Root", None, ProjectedStatus::Idle, &[], &[]);
        let child = session(
            "child",
            "Child",
            Some("root"),
            ProjectedStatus::Busy,
            &[],
            &[],
        );
        let mut model = DashboardModel::default();
        model.apply(found(instance.clone(), endpoint));
        model.apply(projection(instance, endpoint, vec![root, child]));
        assert!(model.rows.iter().any(|row| {
            row.session_id == "root"
                && row.category == RowCategory::Headless
                && !row.busy
                && row.background_count == 1
        }));
        let row = model
            .rows
            .iter()
            .find(|row| row.session_id == "root")
            .unwrap_or_else(|| unreachable!("headless background root"));
        assert!(row.last_non_busy.is_some());
        assert_eq!(
            state_line(row, row.marker(), Style::default(), Instant::now()).to_string(),
            "background 1"
        );
    }

    #[test]
    fn v2_busy_root_without_tui_remains_true_headless_activity() {
        let endpoint = endpoint(4131);
        let instance = managed_key(931, 4131);
        let start = Instant::now();
        let mut root = session("root", "Root", None, ProjectedStatus::Busy, &[], &[]);
        root.directory = Some(PathBuf::from("/workspace"));
        let mut model = DashboardModel::default();
        model.apply_at(found(instance.clone(), endpoint), start);
        model.apply_at(projection(instance, endpoint, vec![root]), start);
        assert_eq!(model.rows.len(), 1);
        assert_eq!(model.rows[0].category, RowCategory::Headless);
        assert_eq!(model.rows[0].session_id, "root");
        assert!(model.rows[0].busy);
        assert_eq!(
            state_line(
                &model.rows[0],
                model.rows[0].marker(),
                Style::default(),
                start + MINUTE,
            )
            .to_string(),
            format!("{:>STATE_WIDTH$}", "> 1m")
        );
    }

    #[test]
    fn v2_nested_descendants_keep_foreground_and_background_independent() {
        let root = session("root", "Root", None, ProjectedStatus::Busy, &[], &[]);
        let child = session(
            "child",
            "Child",
            Some("root"),
            ProjectedStatus::Busy,
            &["child-question"],
            &[],
        );
        let grandchild = session(
            "grandchild",
            "Grandchild",
            Some("child"),
            ProjectedStatus::Retry,
            &[],
            &["child-permission"],
        );
        let idle = session(
            "idle-child",
            "Idle",
            Some("grandchild"),
            ProjectedStatus::Idle,
            &[],
            &[],
        );
        let duplicate_grandchild = grandchild.clone();
        let aggregates = aggregate_v2_roots(&[root, child, grandchild, duplicate_grandchild, idle]);
        assert_eq!(aggregates.len(), 1);
        assert!(aggregates[0].busy);
        assert!(!aggregates[0].retry);
        assert_eq!(aggregates[0].background_count, 2);
        assert_eq!(aggregates[0].question_ids, ["child-question"]);
        assert_eq!(aggregates[0].permission_ids, ["child-permission"]);
    }

    #[test]
    fn v2_state_rendering_covers_ready_foreground_retry_and_background() {
        let now = Instant::now();
        let make = |busy, retry, background_count| {
            let mut row = new_row(
                RowKey::opencode(managed_key(940, 4140), "root".to_owned()),
                endpoint(4140),
                &RootAggregate {
                    id: "root".to_owned(),
                    title: "Root".to_owned(),
                    slug: String::new(),
                    busy,
                    retry,
                    background_count,
                    question_ids: Vec::new(),
                    permission_ids: Vec::new(),
                },
                busy.then_some(now),
                now,
            );
            row.category = RowCategory::Attached;
            row
        };
        for (row, expected) in [
            (make(false, false, 0), "ready".to_owned()),
            (make(true, false, 0), format!("{:>STATE_WIDTH$}", "0m")),
            (make(false, false, 2), "background 2".to_owned()),
            (make(true, false, 2), "busy 0m +2 background".to_owned()),
            (make(true, true, 1), "retry 0m +1 background".to_owned()),
        ] {
            assert_eq!(
                state_line(&row, row.marker(), Style::default(), now).to_string(),
                expected
            );
        }
    }

    #[test]
    fn v2_child_attention_keeps_priority_over_background_state() {
        let now = Instant::now();
        let root = session("root", "Root", None, ProjectedStatus::Idle, &[], &[]);
        let child = session(
            "child",
            "Child",
            Some("root"),
            ProjectedStatus::Retry,
            &["question"],
            &["permission"],
        );
        let aggregate = aggregate_v2_roots(&[root, child])
            .into_iter()
            .next()
            .unwrap_or_else(|| unreachable!("root aggregate"));
        let mut row = new_row(
            RowKey::opencode(managed_key(950, 4150), "root".to_owned()),
            endpoint(4150),
            &aggregate,
            Some(now),
            now,
        );
        row.category = RowCategory::Attached;
        assert_eq!(row.background_count, 1);
        assert_eq!(row.marker(), "question");
        let occurrence = row
            .occurrence()
            .unwrap_or_else(|| unreachable!("question occurrence"));
        assert_eq!(
            state_line(&row, row.marker(), occurrence_color(&occurrence), now).to_string(),
            "question"
        );
    }

    #[test]
    fn v2_child_completion_returns_attached_root_to_ready() {
        let endpoint = endpoint(4160);
        let instance = managed_key(960, 4160);
        let root = session("root", "Root", None, ProjectedStatus::Idle, &[], &[]);
        let child = |status| session("child", "Child", Some("root"), status, &[], &[]);
        let now = Instant::now();
        let mut model = DashboardModel::default();
        model.apply_at(found(instance.clone(), endpoint), now);
        model.apply_at(
            projection(
                instance.clone(),
                endpoint,
                vec![root.clone(), child(ProjectedStatus::Busy)],
            ),
            now,
        );
        let mut attached = tui(&instance, 961, "/workspace");
        attached.explicit_session = Some("root".to_owned());
        model.apply_attachments(
            AttachmentSnapshot {
                tuis: vec![attached],
                v1_focus: HashMap::new(),
                claude_focus: HashMap::new(),
                diagnostic: None,
            },
            now,
        );
        assert_eq!(model.rows[0].background_count, 1);
        assert_eq!(
            state_line(
                &model.rows[0],
                model.rows[0].marker(),
                Style::default(),
                now
            )
            .to_string(),
            "background 1"
        );
        model.apply_at(
            projection(instance, endpoint, vec![root, child(ProjectedStatus::Idle)]),
            now + Duration::from_secs(1),
        );
        assert_eq!(model.rows.len(), 1);
        assert_eq!(model.rows[0].category, RowCategory::Attached);
        assert!(!model.rows[0].busy);
        assert_eq!(model.rows[0].background_count, 0);
        assert_eq!(
            state_line(
                &model.rows[0],
                model.rows[0].marker(),
                Style::default(),
                now + Duration::from_secs(1)
            )
            .to_string(),
            "ready"
        );
    }

    #[test]
    fn unresolved_tui_attachment_has_no_invented_execution_state() {
        let endpoint = endpoint(4170);
        let instance = managed_key(970, 4170);
        let mut model = DashboardModel::default();
        model.apply(found(instance.clone(), endpoint));
        model.apply(projection(
            instance.clone(),
            endpoint,
            vec![session(
                "root",
                "Root",
                None,
                ProjectedStatus::Idle,
                &[],
                &[],
            )],
        ));
        model.apply_attachments(
            AttachmentSnapshot {
                tuis: vec![tui(&instance, 971, "/unmatched")],
                v1_focus: HashMap::new(),
                claude_focus: HashMap::new(),
                diagnostic: None,
            },
            Instant::now(),
        );
        let row = model
            .rows
            .iter()
            .find(|row| row.category == RowCategory::Unresolved)
            .unwrap_or_else(|| unreachable!("unresolved TUI row"));
        assert_eq!(
            state_line(row, row.marker(), Style::default(), Instant::now()).to_string(),
            ""
        );
    }

    fn found(instance: InstanceKey, endpoint: ServerEndpoint) -> BeaconEvent {
        let protocol = if matches!(instance.source, InstanceSource::ManagedService { .. }) {
            opencode_beacon::OpenCodeProtocol::V2
        } else {
            opencode_beacon::OpenCodeProtocol::V1
        };
        BeaconEvent::ServerFound(server_instance(instance, endpoint, protocol))
    }

    fn server_instance(
        instance: InstanceKey,
        endpoint: ServerEndpoint,
        protocol: OpenCodeProtocol,
    ) -> opencode_beacon::ServerInstance {
        opencode_beacon::ServerInstance {
            key: instance,
            endpoint,
            protocol,
            executable: None,
            version: "test".to_owned(),
        }
    }

    fn ready(endpoint: ServerEndpoint, root: &str) -> BeaconEvent {
        BeaconEvent::Attention {
            endpoint,
            attention: AttentionEvent {
                kind: AttentionKind::Ready,
                root_session_id: root.to_owned(),
                root_title: None,
                root_slug: None,
                subject_session_id: root.to_owned(),
                request_id: None,
                source: TransitionSource::Live,
                initial: false,
                root_resolved: true,
            },
        }
    }

    fn key_event(code: KeyCode) -> Event {
        Event::Key(KeyEvent::new(code, KeyModifiers::NONE))
    }

    fn rendered(model: &mut DashboardModel, width: u16, height: u16) -> ratatui::buffer::Buffer {
        rendered_at(model, width, height, Instant::now())
    }

    fn rendered_at(
        model: &mut DashboardModel,
        width: u16,
        height: u16,
        now: Instant,
    ) -> ratatui::buffer::Buffer {
        let backend = TestBackend::new(width, height);
        let mut terminal =
            Terminal::new(backend).unwrap_or_else(|error| unreachable!("test terminal: {error}"));
        assert!(terminal.draw(|frame| model.render_at(frame, now)).is_ok());
        terminal.backend().buffer().clone()
    }

    fn text_position(buffer: &ratatui::buffer::Buffer, text: &str) -> (u16, u16) {
        for y in 0..buffer.area.height {
            let rendered = (0..buffer.area.width)
                .map(|x| buffer[(x, y)].symbol())
                .collect::<String>();
            if let Some(x) = rendered.find(text) {
                return (
                    u16::try_from(x).unwrap_or_else(|_| unreachable!("test width fits u16")),
                    y,
                );
            }
        }
        unreachable!("rendered text not found: {text}")
    }

    fn cell_at_text<'a>(
        buffer: &'a ratatui::buffer::Buffer,
        text: &str,
    ) -> &'a ratatui::buffer::Cell {
        cell_at_text_offset(buffer, text, 0)
    }

    fn cell_at_text_offset<'a>(
        buffer: &'a ratatui::buffer::Buffer,
        text: &str,
        offset: usize,
    ) -> &'a ratatui::buffer::Cell {
        let needle = text.chars().collect::<Vec<_>>();
        for y in 0..buffer.area.height {
            let mut rendered = Vec::new();
            let mut positions = Vec::new();
            for x in 0..buffer.area.width {
                let cell = &buffer[(x, y)];
                for character in cell.symbol().chars() {
                    rendered.push(character);
                    positions.push(x);
                }
            }
            if let Some(index) = rendered
                .windows(needle.len())
                .position(|window| window == needle)
            {
                return &buffer[(positions[index + offset], y)];
            }
        }
        unreachable!("rendered text not found: {text}")
    }

    fn cell_at_text_on_row<'a>(
        buffer: &'a ratatui::buffer::Buffer,
        row_text: &str,
        text: &str,
    ) -> &'a ratatui::buffer::Cell {
        let (x, y) = text_position_on_row(buffer, row_text, text);
        &buffer[(x, y)]
    }

    fn text_position_on_row(
        buffer: &ratatui::buffer::Buffer,
        row_text: &str,
        text: &str,
    ) -> (u16, u16) {
        for y in 0..buffer.area.height {
            let rendered = (0..buffer.area.width)
                .map(|x| buffer[(x, y)].symbol())
                .collect::<String>();
            if rendered.contains(row_text)
                && let Some(x) = (0..buffer.area.width).find(|x| {
                    (0..text.chars().count()).all(|offset| {
                        let Ok(offset) = u16::try_from(offset) else {
                            return false;
                        };
                        buffer[(x.saturating_add(offset), y)]
                            .symbol()
                            .starts_with(text.chars().nth(usize::from(offset)).unwrap_or_default())
                    })
                })
            {
                return (x, y);
            }
        }
        unreachable!("rendered text not found on row: {text}")
    }

    fn assert_style(cell: &ratatui::buffer::Cell, foreground: Color, modifiers: Modifier) {
        assert_eq!(cell.fg, foreground);
        assert_eq!(cell.bg, Color::Reset);
        assert_eq!(cell.modifier, modifiers);
    }

    #[test]
    fn v1_admits_only_working_set_and_reorders_only_for_titles() {
        let endpoint = endpoint(4001);
        let instance = key(1, 4001);
        let mut model = DashboardModel::default();
        model.apply(found(instance.clone(), endpoint));
        model.apply(projection(
            instance.clone(),
            endpoint,
            vec![
                session("idle", "Historical", None, ProjectedStatus::Idle, &[], &[]),
                session("b", "Busy B", None, ProjectedStatus::Busy, &[], &[]),
                session("a", "Question A", None, ProjectedStatus::Idle, &["q"], &[]),
            ],
        ));
        assert_eq!(
            model
                .rows
                .iter()
                .map(|row| row.session_id.as_str())
                .collect::<Vec<_>>(),
            ["b", "a"]
        );
        assert!(model.rows.iter().all(|row| row.session_id != "idle"));

        model.apply(projection(
            instance,
            endpoint,
            vec![
                session("a", "A renamed", None, ProjectedStatus::Idle, &["q"], &[]),
                session("b", "Busy B", None, ProjectedStatus::Idle, &[], &[]),
                session("idle", "Historical", None, ProjectedStatus::Idle, &[], &[]),
            ],
        ));
        assert_eq!(
            model
                .rows
                .iter()
                .map(|row| row.session_id.as_str())
                .collect::<Vec<_>>(),
            ["a", "b"]
        );
        assert_eq!(model.rows[0].title, "A renamed");
        assert_eq!(model.rows[1].marker(), "ready");
    }

    #[test]
    fn aggregates_children_with_question_priority_and_safe_ancestry_fallback() {
        let endpoint = endpoint(4002);
        let instance = key(2, 4002);
        let mut model = DashboardModel::default();
        model.apply(found(instance.clone(), endpoint));
        model.apply(projection(
            instance,
            endpoint,
            vec![
                session("root", "Root", None, ProjectedStatus::Busy, &[], &[]),
                session(
                    "child",
                    "Child",
                    Some("root"),
                    ProjectedStatus::Idle,
                    &["q"],
                    &["p"],
                ),
                session(
                    "missing",
                    "Missing",
                    Some("absent"),
                    ProjectedStatus::Idle,
                    &[],
                    &["fallback"],
                ),
                session(
                    "cycle-a",
                    "A",
                    Some("cycle-b"),
                    ProjectedStatus::Idle,
                    &["cycle"],
                    &[],
                ),
                session(
                    "cycle-b",
                    "B",
                    Some("cycle-a"),
                    ProjectedStatus::Idle,
                    &[],
                    &[],
                ),
            ],
        ));
        let root = model
            .rows
            .iter()
            .find(|row| row.session_id == "root")
            .unwrap_or_else(|| unreachable!("root admitted"));
        assert_eq!(root.marker(), "question");
        assert_eq!(root.question_ids, ["q"]);
        assert_eq!(root.permission_ids, ["p"]);
        assert!(model.rows.iter().any(|row| row.session_id == "missing"));
        assert!(model.rows.iter().any(|row| row.session_id == "cycle-a"));
    }

    #[test]
    fn duplicate_session_ids_are_instance_scoped_and_disambiguated() {
        let mut model = DashboardModel::default();
        for (inode, port) in [(3, 4003), (4, 4004)] {
            let endpoint = endpoint(port);
            let instance = key(inode, port);
            model.apply(found(instance.clone(), endpoint));
            model.apply(projection(
                instance,
                endpoint,
                vec![session(
                    "same",
                    "Title",
                    None,
                    ProjectedStatus::Busy,
                    &[],
                    &[],
                )],
            ));
        }
        assert_eq!(model.rows.len(), 2);
        assert_eq!(
            endpoint_duplicate_sessions(&model.rows),
            HashSet::from(["same".to_owned()])
        );
    }

    #[test]
    fn memory_renders_once_per_instance_with_neutral_detail_and_shared_safety() {
        let endpoint = endpoint(4024);
        let instance = key(24, 4024);
        let mut model = DashboardModel::default();
        model.apply(found(instance.clone(), endpoint));
        model.apply(projection(
            instance.clone(),
            endpoint,
            vec![
                session(
                    "a",
                    "First memory row",
                    None,
                    ProjectedStatus::Busy,
                    &[],
                    &[],
                ),
                session(
                    "b",
                    "Second memory row",
                    None,
                    ProjectedStatus::Busy,
                    &[],
                    &[],
                ),
            ],
        ));
        model.apply_memory(HashMap::from([(
            instance.clone(),
            MemoryView {
                availability: MemoryAvailability::Fresh,
                values: Some(crate::memory::MemoryValues {
                    current: 16 * 1024 * 1024,
                    peak: Some(32 * 1024 * 1024),
                    swap: 1024,
                    anon: 10 * 1024 * 1024,
                    file: 5 * 1024 * 1024,
                    kernel: 1024 * 1024,
                }),
                observed_peak: Some(20 * 1024 * 1024),
                slope_bytes_per_minute: Some(1024 * 1024),
                scope: Some(CgroupKey {
                    device: 8,
                    inode: 24,
                }),
                shared: false,
            },
        )]));

        let buffer = rendered(&mut model, 130, 10);
        let memory_x = text_position(&buffer, "MEM").0;
        assert_eq!(memory_x, 72);
        let memory_cell_x = text_position(&buffer, "16.0M").0;
        assert_eq!(
            text_position(&buffer, "16.0M").1,
            text_position(&buffer, "First memory row").1
        );
        let second_row_y = text_position(&buffer, "Second memory row").1;
        assert!(
            (memory_cell_x..memory_cell_x + 5).all(|x| buffer[(x, second_row_y)].symbol() == " ")
        );
        assert_style(
            cell_at_text(&buffer, "16.0M"),
            Color::DarkGray,
            Modifier::BOLD | Modifier::UNDERLINED,
        );
        assert!(format!("{buffer:?}").contains("trend +1.0M/m"));
        assert!(format!("{buffer:?}").contains("peak 32.0M observed 20.0M"));
        assert!(format!("{buffer:?}").contains("scope 8:24"));

        model
            .memory
            .get_mut(&instance)
            .unwrap_or_else(|| unreachable!())
            .shared = true;
        let buffer = rendered(&mut model, 130, 10);
        assert_style(
            cell_at_text(&buffer, "shared"),
            Color::DarkGray,
            Modifier::BOLD | Modifier::UNDERLINED,
        );
        assert!(format!("{buffer:?}").contains("MEM shared"));
        assert!(!format!("{buffer:?}").contains("MEM total"));
    }

    #[test]
    fn memory_uses_na_and_stale_and_is_purged_on_replacement() {
        let endpoint = endpoint(4025);
        let first = key(25, 4025);
        let second = key(26, 4025);
        let mut model = DashboardModel::default();
        model.apply(found(first.clone(), endpoint));
        model.apply(projection(
            first.clone(),
            endpoint,
            vec![session(
                "root",
                "Memory root",
                None,
                ProjectedStatus::Busy,
                &[],
                &[],
            )],
        ));
        let buffer = rendered(&mut model, 110, 9);
        assert_style(
            cell_at_text(&buffer, "N/A"),
            Color::DarkGray,
            Modifier::BOLD | Modifier::UNDERLINED,
        );
        model.apply_memory(HashMap::from([(
            first.clone(),
            MemoryView {
                availability: MemoryAvailability::Stale,
                values: Some(crate::memory::MemoryValues {
                    current: 1,
                    peak: None,
                    swap: 0,
                    anon: 1,
                    file: 0,
                    kernel: 0,
                }),
                observed_peak: Some(1),
                slope_bytes_per_minute: None,
                scope: Some(CgroupKey {
                    device: 1,
                    inode: 2,
                }),
                shared: false,
            },
        )]));
        let buffer = rendered(&mut model, 110, 9);
        assert_style(
            cell_at_text(&buffer, "stale"),
            Color::DarkGray,
            Modifier::BOLD | Modifier::UNDERLINED,
        );

        model.apply(found(second.clone(), endpoint));
        assert!(!model.memory.contains_key(&first));
        model.apply(projection(
            second,
            endpoint,
            vec![session(
                "new",
                "Replacement",
                None,
                ProjectedStatus::Busy,
                &[],
                &[],
            )],
        ));
        let buffer = rendered(&mut model, 110, 9);
        assert!(format!("{buffer:?}").contains("MEM N/A"));
    }

    #[test]
    fn projection_deletion_replacement_and_reconnect_staleness_are_exact() {
        let endpoint = endpoint(4005);
        let first = key(5, 4005);
        let second = key(6, 4005);
        let mut model = DashboardModel::default();
        model.apply(found(first.clone(), endpoint));
        model.apply(projection(
            first.clone(),
            endpoint,
            vec![session(
                "root",
                "Root",
                None,
                ProjectedStatus::Busy,
                &[],
                &[],
            )],
        ));
        model.apply(BeaconEvent::Disconnected {
            endpoint,
            reason: "test".to_owned(),
        });
        assert!(model.rows[0].stale);
        model.apply(BeaconEvent::Connected(endpoint));
        assert!(!model.rows[0].stale);
        model.apply(projection(first, endpoint, Vec::new()));
        assert!(model.rows.is_empty());

        model.apply(found(second.clone(), endpoint));
        model.apply(projection(
            second.clone(),
            endpoint,
            vec![session(
                "root",
                "New",
                None,
                ProjectedStatus::Busy,
                &[],
                &[],
            )],
        ));
        assert_eq!(model.rows[0].key.instance(), Some(&second));
    }

    #[test]
    fn busy_is_blank_and_attention_colors_are_semantic() {
        assert_eq!(
            occurrence_color(&Occurrence::Question(vec![])).fg,
            Some(Color::Blue)
        );
        assert_eq!(
            occurrence_color(&Occurrence::Permission(vec![])).fg,
            Some(Color::LightYellow)
        );
        assert_eq!(
            occurrence_color(&Occurrence::Ready(1)).fg,
            Some(Color::Green)
        );
        let row = new_row(
            RowKey::opencode(key(7, 4007), "root".to_owned()),
            endpoint(4007),
            &RootAggregate {
                id: "root".to_owned(),
                title: "Root".to_owned(),
                slug: String::new(),
                busy: true,
                retry: false,
                background_count: 0,
                question_ids: Vec::new(),
                permission_ids: Vec::new(),
            },
            None,
            Instant::now(),
        );
        assert_eq!(row.marker(), "");
    }

    #[test]
    fn busy_elapsed_uses_observed_non_busy_baselines_and_resets_each_cycle() {
        let endpoint = endpoint(4015);
        let instance = key(15, 4015);
        let start = Instant::now();
        let mut model = DashboardModel::default();
        model.apply_at(found(instance.clone(), endpoint), start);
        model.apply_at(
            projection(
                instance.clone(),
                endpoint,
                vec![session(
                    "root",
                    "Root",
                    None,
                    ProjectedStatus::Idle,
                    &[],
                    &[],
                )],
            ),
            start,
        );
        model.apply_at(
            projection(
                instance.clone(),
                endpoint,
                vec![session(
                    "root",
                    "Root",
                    None,
                    ProjectedStatus::Busy,
                    &[],
                    &[],
                )],
            ),
            start,
        );

        for (elapsed, expected) in [
            (Duration::ZERO, "0m"),
            (Duration::from_secs(59), "0m"),
            (Duration::from_secs(60), "1m"),
            (Duration::from_secs(42 * 60), "42m"),
        ] {
            let buffer = rendered_at(&mut model, 100, 8, start + elapsed);
            assert_eq!(cell_at_text(&buffer, expected).fg, Color::DarkGray);
        }

        let reset = start + Duration::from_secs(100 * 60);
        model.apply_at(
            projection(
                instance.clone(),
                endpoint,
                vec![session(
                    "root",
                    "Root",
                    None,
                    ProjectedStatus::Idle,
                    &[],
                    &[],
                )],
            ),
            reset,
        );
        model.apply_at(
            projection(
                instance,
                endpoint,
                vec![session(
                    "root",
                    "Root",
                    None,
                    ProjectedStatus::Retry,
                    &[],
                    &[],
                )],
            ),
            reset + Duration::from_secs(30),
        );
        let buffer = rendered_at(&mut model, 100, 8, reset + Duration::from_secs(30));
        assert!(cell_at_text(&buffer, "0m").symbol() == "0");
    }

    #[test]
    fn initial_busy_reports_observed_lower_bound_until_a_non_busy_busy_cycle() {
        let endpoint = endpoint(4016);
        let instance = key(16, 4016);
        let start = Instant::now();
        let mut model = DashboardModel::default();
        model.apply_at(found(instance.clone(), endpoint), start);
        model.apply_at(
            projection(
                instance.clone(),
                endpoint,
                vec![session(
                    "root",
                    "Root",
                    None,
                    ProjectedStatus::Busy,
                    &[],
                    &[],
                )],
            ),
            start,
        );
        let buffer = rendered_at(&mut model, 100, 8, start + Duration::from_secs(600));
        let state_x = text_position(&buffer, "STATE").0;
        assert_style(
            cell_at_text(&buffer, "> 10m"),
            Color::DarkGray,
            Modifier::BOLD | Modifier::UNDERLINED,
        );
        assert_eq!(
            text_position(&buffer, "> 10m").0,
            state_x + STATE_COLUMN_WIDTH - 5
        );
        assert_eq!(model.next_redraw(start), start.checked_add(MINUTE));

        model.apply_at(
            BeaconEvent::Disconnected {
                endpoint,
                reason: "test".to_owned(),
            },
            start + Duration::from_secs(650),
        );
        let buffer = rendered_at(&mut model, 100, 8, start + Duration::from_secs(900));
        assert!(cell_at_text(&buffer, "> 10m").symbol() == ">");
        assert_eq!(model.next_redraw(start + Duration::from_secs(900)), None);
        model.apply_at(
            BeaconEvent::Connected(endpoint),
            start + Duration::from_secs(900),
        );
        model.apply_at(
            projection(
                instance.clone(),
                endpoint,
                vec![session(
                    "root",
                    "Root",
                    None,
                    ProjectedStatus::Busy,
                    &[],
                    &[],
                )],
            ),
            start + Duration::from_secs(900),
        );
        let buffer = rendered_at(&mut model, 100, 8, start + Duration::from_secs(910));
        assert!(cell_at_text(&buffer, "> 11m").symbol() == ">");

        model.apply_at(
            projection(
                instance.clone(),
                endpoint,
                vec![session(
                    "root",
                    "Root",
                    None,
                    ProjectedStatus::Idle,
                    &[],
                    &[],
                )],
            ),
            start + Duration::from_secs(1_000),
        );
        model.apply_at(
            projection(
                instance,
                endpoint,
                vec![session(
                    "root",
                    "Root",
                    None,
                    ProjectedStatus::Busy,
                    &[],
                    &[],
                )],
            ),
            start + Duration::from_secs(1_010),
        );
        let buffer = rendered_at(&mut model, 100, 8, start + Duration::from_secs(1_010));
        assert!(cell_at_text(&buffer, "0m").symbol() == "0");
    }

    #[test]
    fn attention_and_dismissal_replace_busy_elapsed() {
        let endpoint = endpoint(4017);
        let instance = key(17, 4017);
        let start = Instant::now();
        let mut model = DashboardModel::default();
        model.apply_at(found(instance.clone(), endpoint), start);
        for (questions, permissions, marker) in [
            (&["q"][..], &[][..], "question"),
            (&[][..], &["p"][..], "permission"),
        ] {
            model.apply_at(
                projection(
                    instance.clone(),
                    endpoint,
                    vec![session(
                        "root",
                        "Root",
                        None,
                        ProjectedStatus::Busy,
                        questions,
                        permissions,
                    )],
                ),
                start,
            );
            let buffer = rendered_at(&mut model, 100, 8, start + Duration::from_secs(120));
            assert!(
                cell_at_text(&buffer, marker)
                    .symbol()
                    .starts_with(&marker[..1])
            );
            assert!(!format!("{buffer:?}").contains("2m"));
        }
        model.handle_terminal_event(&key_event(KeyCode::Right), 5);
        let buffer = rendered_at(&mut model, 100, 8, start + Duration::from_secs(180));
        assert!(cell_at_text(&buffer, "permission").symbol() == "p");
        assert!(!format!("{buffer:?}").contains('✓'));
        assert!(!format!("{buffer:?}").contains("3m"));
    }

    #[test]
    fn ready_immediately_replaces_an_existing_busy_counter() {
        let endpoint = endpoint(4020);
        let instance = key(20, 4020);
        let start = Instant::now();
        let mut model = DashboardModel::default();
        model.apply_at(found(instance.clone(), endpoint), start);
        model.apply_at(
            projection(
                instance,
                endpoint,
                vec![session(
                    "root",
                    "Root",
                    None,
                    ProjectedStatus::Busy,
                    &[],
                    &[],
                )],
            ),
            start,
        );

        model.apply_at(ready(endpoint, "root"), start + MINUTE);

        let buffer = rendered_at(&mut model, 100, 8, start + MINUTE);
        assert!(cell_at_text(&buffer, "ready").symbol() == "r");
        assert!(!format!("{buffer:?}").contains("1m"));
        assert_eq!(model.next_redraw(start + MINUTE), None);
    }

    #[test]
    fn stale_busy_elapsed_freezes_and_resumes_without_counting_disconnect_time() {
        let endpoint = endpoint(4018);
        let instance = key(18, 4018);
        let start = Instant::now();
        let mut model = DashboardModel::default();
        model.apply_at(found(instance.clone(), endpoint), start);
        model.apply_at(
            projection(
                instance.clone(),
                endpoint,
                vec![session(
                    "root",
                    "Root",
                    None,
                    ProjectedStatus::Idle,
                    &[],
                    &[],
                )],
            ),
            start,
        );
        model.apply_at(
            projection(
                instance.clone(),
                endpoint,
                vec![session(
                    "root",
                    "Root",
                    None,
                    ProjectedStatus::Busy,
                    &[],
                    &[],
                )],
            ),
            start,
        );
        model.apply_at(
            BeaconEvent::Disconnected {
                endpoint,
                reason: "test".to_owned(),
            },
            start + Duration::from_secs(90),
        );
        let buffer = rendered_at(&mut model, 100, 8, start + Duration::from_secs(600));
        assert!(cell_at_text(&buffer, "1m").symbol() == "1");
        assert_eq!(model.next_redraw(start + Duration::from_secs(600)), None);

        model.apply_at(
            BeaconEvent::Connected(endpoint),
            start + Duration::from_secs(600),
        );
        assert!(!model.rows[0].stale);
        model.apply_at(
            projection(
                instance,
                endpoint,
                vec![session(
                    "root",
                    "Root",
                    None,
                    ProjectedStatus::Busy,
                    &[],
                    &[],
                )],
            ),
            start + Duration::from_secs(600),
        );
        let buffer = rendered_at(&mut model, 100, 8, start + Duration::from_secs(629));
        assert!(cell_at_text(&buffer, "1m").symbol() == "1");
        let buffer = rendered_at(&mut model, 100, 8, start + Duration::from_secs(630));
        assert!(cell_at_text(&buffer, "2m").symbol() == "2");
    }

    #[test]
    fn repeated_disconnect_before_projection_preserves_the_first_freeze() {
        let endpoint = endpoint(4021);
        let instance = key(21, 4021);
        let start = Instant::now();
        let mut model = DashboardModel::default();
        model.apply_at(found(instance.clone(), endpoint), start);
        model.apply_at(
            projection(
                instance,
                endpoint,
                vec![session(
                    "root",
                    "Root",
                    None,
                    ProjectedStatus::Busy,
                    &[],
                    &[],
                )],
            ),
            start,
        );
        model.rows[0].last_non_busy = Some(start);

        model.apply_at(
            BeaconEvent::Disconnected {
                endpoint,
                reason: "test".to_owned(),
            },
            start + Duration::from_secs(90),
        );
        model.apply_at(
            BeaconEvent::Connected(endpoint),
            start + Duration::from_secs(600),
        );
        model.apply_at(
            BeaconEvent::Disconnected {
                endpoint,
                reason: "test again".to_owned(),
            },
            start + Duration::from_secs(900),
        );

        assert_eq!(
            model.rows[0].frozen_busy_elapsed,
            Some(Duration::from_secs(90))
        );
        let buffer = rendered_at(&mut model, 100, 8, start + Duration::from_secs(1_200));
        assert!(cell_at_text(&buffer, "1m").symbol() == "1");
    }

    #[test]
    fn elapsed_layout_style_overflow_and_scheduling_are_stable() {
        let endpoint = endpoint(4019);
        let instance = key(19, 4019);
        let start = Instant::now();
        let mut model = DashboardModel::default();
        model.apply_at(found(instance.clone(), endpoint), start);
        model.apply_at(
            projection(
                instance.clone(),
                endpoint,
                vec![
                    session("a", "First title", None, ProjectedStatus::Idle, &[], &[]),
                    session("b", "Second title", None, ProjectedStatus::Idle, &[], &[]),
                ],
            ),
            start,
        );
        model.apply_at(
            projection(
                instance,
                endpoint,
                vec![
                    session("a", "First title", None, ProjectedStatus::Busy, &[], &[]),
                    session("b", "Second title", None, ProjectedStatus::Retry, &[], &[]),
                ],
            ),
            start,
        );
        assert_eq!(model.next_redraw(start), start.checked_add(MINUTE));
        assert_eq!(
            model.next_redraw(start + Duration::from_secs(59)),
            start.checked_add(MINUTE)
        );
        assert_eq!(
            model.next_redraw(start + MINUTE),
            start.checked_add(Duration::from_secs(120))
        );

        let initial = rendered_at(&mut model, 100, 8, start);
        let later = rendered_at(&mut model, 100, 8, start + Duration::from_secs(60));
        assert_eq!(
            text_position(&initial, "First title").0,
            text_position(&later, "First title").0
        );
        let first_elapsed = cell_at_text_on_row(&initial, "First title", "0m");
        let second_elapsed = cell_at_text_on_row(&initial, "Second title", "0m");
        assert_style(
            first_elapsed,
            Color::DarkGray,
            Modifier::BOLD | Modifier::UNDERLINED,
        );
        assert_style(second_elapsed, Color::DarkGray, Modifier::empty());
        assert_eq!(
            text_position(&initial, "0m").0,
            text_position(&later, "1m").0
        );

        assert_eq!(
            format_elapsed(Some(Duration::from_secs(u64::MAX)), false),
            "  9999999m"
        );
        assert_eq!(
            format_elapsed(Some(Duration::from_secs(u64::MAX)), true),
            "> 9999999m"
        );
        let saturated = start + Duration::from_secs(MAX_ELAPSED_MINUTES * 60);
        assert_eq!(model.next_redraw(saturated), None);
    }

    #[test]
    fn lower_bound_busy_counters_are_right_aligned_neutral_and_preserve_selection() {
        let endpoint = endpoint(4023);
        let instance = key(23, 4023);
        let start = Instant::now();
        let mut model = DashboardModel::default();
        model.apply_at(found(instance.clone(), endpoint), start);
        model.apply_at(
            projection(
                instance,
                endpoint,
                vec![
                    session(
                        "a",
                        "Selected unknown",
                        None,
                        ProjectedStatus::Busy,
                        &[],
                        &[],
                    ),
                    session(
                        "b",
                        "Unselected unknown",
                        None,
                        ProjectedStatus::Retry,
                        &[],
                        &[],
                    ),
                ],
            ),
            start,
        );

        let buffer = rendered_at(&mut model, 100, 8, start + MINUTE);
        let selected = cell_at_text_on_row(&buffer, "Selected unknown", "> 1m");
        let unselected = cell_at_text_on_row(&buffer, "Unselected unknown", "> 1m");
        assert_style(
            selected,
            Color::DarkGray,
            Modifier::BOLD | Modifier::UNDERLINED,
        );
        assert_style(unselected, Color::DarkGray, Modifier::empty());
        assert_eq!(
            text_position_on_row(&buffer, "Selected unknown", "Selected unknown").0
                - text_position_on_row(&buffer, "Selected unknown", "> 1m").0,
            MEMORY_COLUMN_WIDTH + 6,
            "selected lower-bound counter must end before the fixed MEM column"
        );
        assert_eq!(
            text_position_on_row(&buffer, "Unselected unknown", "Unselected unknown").0
                - text_position_on_row(&buffer, "Unselected unknown", "> 1m").0,
            MEMORY_COLUMN_WIDTH + 6,
            "unselected lower-bound counter must end before the fixed MEM column"
        );
    }

    #[test]
    fn dismissal_tracks_occurrence_and_clears_on_membership_busy_and_ready_cycles() {
        let endpoint = endpoint(4008);
        let instance = key(8, 4008);
        let mut model = DashboardModel::default();
        model.apply(found(instance.clone(), endpoint));
        model.apply(projection(
            instance.clone(),
            endpoint,
            vec![session(
                "root",
                "Root",
                None,
                ProjectedStatus::Idle,
                &["q1"],
                &[],
            )],
        ));
        model.handle_terminal_event(&key_event(KeyCode::Right), 5);
        assert!(model.rows[0].dismissed());
        assert_eq!(
            model
                .dismissal_status
                .as_ref()
                .map(|status| status.message.as_str()),
            Some("Dismissed question for Root")
        );
        model.apply(projection(
            instance.clone(),
            endpoint,
            vec![session(
                "root",
                "Root",
                None,
                ProjectedStatus::Idle,
                &["q1", "q2"],
                &[],
            )],
        ));
        assert!(!model.rows[0].dismissed());
        assert!(model.dismissal_status.is_none());
        model.handle_terminal_event(&key_event(KeyCode::Right), 5);
        model.apply(projection(
            instance.clone(),
            endpoint,
            vec![session(
                "root",
                "Root",
                None,
                ProjectedStatus::Busy,
                &[],
                &[],
            )],
        ));
        assert!(model.rows[0].dismissed.is_none());
        model.apply(projection(
            instance,
            endpoint,
            vec![session(
                "root",
                "Root",
                None,
                ProjectedStatus::Idle,
                &[],
                &[],
            )],
        ));
        model.apply(ready(endpoint, "root"));
        model.handle_terminal_event(&key_event(KeyCode::Right), 5);
        assert!(model.rows[0].dismissed());
        model.apply(ready(endpoint, "root"));
        assert!(!model.rows[0].dismissed());
        assert!(model.dismissal_status.is_none());
        assert_eq!(model.rows[0].ready_generation, 2);
    }

    #[test]
    fn arrow_actions_report_all_success_and_noop_cases_immediately() {
        let mut model = DashboardModel::default();
        assert_eq!(
            model.handle_terminal_event(&key_event(KeyCode::Right), 5),
            DashboardAction::Redraw
        );
        assert_eq!(
            model
                .dismissal_status
                .as_ref()
                .map(|status| status.message.as_str()),
            Some("Nothing selected")
        );
        model.handle_terminal_event(&key_event(KeyCode::Left), 5);
        assert_eq!(
            model
                .dismissal_status
                .as_ref()
                .map(|status| status.message.as_str()),
            Some("Nothing selected")
        );
        let endpoint = endpoint(4009);
        let instance = key(9, 4009);
        model.apply(found(instance.clone(), endpoint));
        model.apply(projection(
            instance,
            endpoint,
            vec![session(
                "root",
                "Root",
                None,
                ProjectedStatus::Busy,
                &[],
                &[],
            )],
        ));
        model.handle_terminal_event(&key_event(KeyCode::Right), 5);
        assert!(model.rows[0].dismissed.is_none());
        assert_eq!(
            model
                .dismissal_status
                .as_ref()
                .map(|status| status.message.as_str()),
            Some("Nothing to dismiss for Root: no active attention")
        );
        model.handle_terminal_event(&key_event(KeyCode::Left), 5);
        assert_eq!(
            model
                .dismissal_status
                .as_ref()
                .map(|status| status.message.as_str()),
            Some("Nothing to restore for Root: no dismissed attention")
        );
    }

    #[test]
    fn right_dismisses_and_left_restores_the_selected_occurrence() {
        let endpoint = endpoint(4012);
        let instance = key(12, 4012);
        let mut model = DashboardModel::default();
        model.apply(found(instance.clone(), endpoint));
        model.apply(projection(
            instance,
            endpoint,
            vec![session(
                "root",
                "Root",
                None,
                ProjectedStatus::Idle,
                &["q"],
                &[],
            )],
        ));

        assert_eq!(
            model.handle_terminal_event(&key_event(KeyCode::Right), 5),
            DashboardAction::Redraw
        );
        let buffer = rendered(&mut model, 100, 12);
        assert!(cell_at_text(&buffer, "Dismissed question for Root").symbol() == "D");
        assert_eq!(
            model.handle_terminal_event(&key_event(KeyCode::Right), 5),
            DashboardAction::Redraw
        );
        assert_eq!(
            model
                .dismissal_status
                .as_ref()
                .map(|status| status.message.as_str()),
            Some("Already dismissed question for Root")
        );
        model.handle_terminal_event(&key_event(KeyCode::Left), 5);
        assert!(!model.rows[0].dismissed());
        assert_eq!(
            model
                .dismissal_status
                .as_ref()
                .map(|status| status.message.as_str()),
            Some("Restored question for Root")
        );
        model.handle_terminal_event(&key_event(KeyCode::Left), 5);
        assert_eq!(
            model
                .dismissal_status
                .as_ref()
                .map(|status| status.message.as_str()),
            Some("question for Root is not dismissed")
        );
    }

    #[test]
    fn initially_quiescent_session_is_dismissible_ready_generation_zero() {
        let endpoint = endpoint(4013);
        let instance = managed_key(13, 4013);
        let root = session("root", "Root", None, ProjectedStatus::Idle, &[], &[]);
        let mut model = DashboardModel::default();
        model.apply(found(instance.clone(), endpoint));
        model.apply(projection(instance.clone(), endpoint, vec![root.clone()]));
        let mut attached = tui(&instance, 14, "/workspace");
        attached.explicit_session = Some("root".to_owned());
        model.apply_attachments(
            AttachmentSnapshot {
                tuis: vec![attached],
                v1_focus: HashMap::new(),
                claude_focus: HashMap::new(),
                diagnostic: None,
            },
            Instant::now(),
        );

        assert_eq!(model.rows[0].marker(), "ready");
        assert_eq!(model.rows[0].ready_generation, 0);
        model.handle_terminal_event(&key_event(KeyCode::Right), 5);
        assert!(model.rows[0].dismissed());

        model.apply(projection(instance, endpoint, vec![root]));
        assert!(model.rows[0].dismissed());
    }

    #[test]
    fn legacy_d_is_unbound_and_enter_focuses_only_a_confident_target() {
        let endpoint = endpoint(4022);
        let instance = key(22, 4022);
        let mut model = DashboardModel::default();
        model.apply(found(instance.clone(), endpoint));
        model.apply(projection(
            instance,
            endpoint,
            vec![session(
                "root",
                "Root",
                None,
                ProjectedStatus::Idle,
                &["q"],
                &[],
            )],
        ));

        assert_eq!(
            model.handle_terminal_event(&key_event(KeyCode::Char('d')), 5),
            DashboardAction::Continue
        );
        assert_eq!(
            model.handle_terminal_event(&key_event(KeyCode::Enter), 5),
            DashboardAction::Redraw
        );
        assert_eq!(
            model
                .dismissal_status
                .as_ref()
                .map(|status| status.message.as_str()),
            Some("Cannot focus Root: client focus identifiers are unavailable")
        );

        let process = TuiKey {
            pid: 22,
            start_time: 220,
        };
        let target = FocusTarget {
            process,
            source: crate::attachment::FocusProcessSource::OpenCode,
            client: crate::attachment::ClientFocusTarget::Konsole(
                crate::attachment::KonsoleTarget {
                    service: ":1.108".to_owned(),
                    session_path: "/Sessions/1".to_owned(),
                    window_path: "/Windows/1".to_owned(),
                },
            ),
        };
        model.apply_attachments(
            AttachmentSnapshot {
                tuis: Vec::new(),
                v1_focus: HashMap::from([(key(22, 4022), target.clone())]),
                claude_focus: HashMap::new(),
                diagnostic: None,
            },
            Instant::now(),
        );
        assert_eq!(
            model.handle_terminal_event(&key_event(KeyCode::Enter), 5),
            DashboardAction::Focus(FocusRequest {
                target,
                name: "Root".to_owned(),
            })
        );
        assert!(!model.rows[0].dismissed());
        assert_eq!(model.selected, Some(0));

        let kitty = FocusTarget {
            process,
            source: crate::attachment::FocusProcessSource::OpenCode,
            client: crate::attachment::ClientFocusTarget::Kitty(crate::attachment::KittyTarget {
                process: TuiKey {
                    pid: 500,
                    start_time: 5000,
                },
                window_id: 7,
                socket_path: PathBuf::from("/run/user/1000/kitty-beacon-500"),
                socket_device: 1,
                socket_inode: 2,
            }),
        };
        model.apply_attachments(
            AttachmentSnapshot {
                tuis: Vec::new(),
                v1_focus: HashMap::from([(key(22, 4022), kitty.clone())]),
                claude_focus: HashMap::new(),
                diagnostic: None,
            },
            Instant::now(),
        );
        assert_eq!(
            model.handle_terminal_event(&key_event(KeyCode::Enter), 5),
            DashboardAction::Focus(FocusRequest {
                target: kitty,
                name: "Root".to_owned(),
            })
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn enter_reports_safe_noops_for_missing_headless_unresolved_and_stale_targets() {
        let mut empty = DashboardModel::default();
        assert_eq!(
            empty.handle_terminal_event(&key_event(KeyCode::Enter), 5),
            DashboardAction::Redraw
        );
        assert_eq!(
            empty
                .dismissal_status
                .as_ref()
                .map(|status| status.message.as_str()),
            Some("Nothing selected")
        );

        let endpoint = endpoint(4023);
        let instance = managed_key(23, 4023);
        let mut root = session("root", "Root", None, ProjectedStatus::Busy, &[], &[]);
        root.directory = Some(PathBuf::from("/workspace"));
        let mut model = DashboardModel::default();
        model.apply(found(instance.clone(), endpoint));
        model.apply(projection(instance.clone(), endpoint, vec![root]));
        model.handle_terminal_event(&key_event(KeyCode::Enter), 5);
        assert_eq!(
            model
                .dismissal_status
                .as_ref()
                .map(|status| status.message.as_str()),
            Some("Cannot focus Root: no attached TUI")
        );

        let mut unresolved = tui(&instance, 24, "/elsewhere");
        unresolved.stale = true;
        model.apply_attachments(
            AttachmentSnapshot {
                tuis: vec![unresolved],
                v1_focus: HashMap::new(),
                claude_focus: HashMap::new(),
                diagnostic: None,
            },
            Instant::now(),
        );
        let unresolved_index = model
            .rows
            .iter()
            .position(|row| row.category == RowCategory::Unresolved)
            .unwrap_or_else(|| unreachable!("unresolved row"));
        model.selected = Some(unresolved_index);
        model.handle_terminal_event(&key_event(KeyCode::Enter), 5);
        assert!(
            model
                .dismissal_status
                .as_ref()
                .is_some_and(|status| status.message.contains("association is unresolved"))
        );

        let mut ambiguous = tui(&instance, 26, "/workspace");
        ambiguous.focus = Some(FocusTarget {
            process: ambiguous.key,
            source: crate::attachment::FocusProcessSource::OpenCode,
            client: crate::attachment::ClientFocusTarget::Konsole(
                crate::attachment::KonsoleTarget {
                    service: ":1.108".to_owned(),
                    session_path: "/Sessions/1".to_owned(),
                    window_path: "/Windows/1".to_owned(),
                },
            ),
        });
        let mut second = ambiguous.clone();
        second.key.pid = 27;
        model.apply_attachments(
            AttachmentSnapshot {
                tuis: vec![ambiguous, second],
                v1_focus: HashMap::new(),
                claude_focus: HashMap::new(),
                diagnostic: None,
            },
            Instant::now(),
        );
        model.selected = model
            .rows
            .iter()
            .position(|row| row.category == RowCategory::Ambiguous);
        model.handle_terminal_event(&key_event(KeyCode::Enter), 5);
        assert!(
            model
                .dismissal_status
                .as_ref()
                .is_some_and(|status| status.message.contains("association is ambiguous"))
        );

        let mut attached = tui(&instance, 25, "/workspace");
        attached.explicit_session = Some("root".to_owned());
        attached.stale = true;
        model.apply_attachments(
            AttachmentSnapshot {
                tuis: vec![attached],
                v1_focus: HashMap::new(),
                claude_focus: HashMap::new(),
                diagnostic: None,
            },
            Instant::now(),
        );
        model.selected = model
            .rows
            .iter()
            .position(|row| row.category == RowCategory::Attached);
        model.handle_terminal_event(&key_event(KeyCode::Enter), 5);
        assert_eq!(
            model
                .dismissal_status
                .as_ref()
                .map(|status| status.message.as_str()),
            Some("Cannot focus Root: TUI evidence is stale")
        );
    }

    #[test]
    fn enter_rejects_disconnected_v1_and_sanitizes_external_feedback() {
        let endpoint = endpoint(4024);
        let instance = key(24, 4024);
        let target = FocusTarget {
            process: TuiKey {
                pid: 24,
                start_time: 240,
            },
            source: crate::attachment::FocusProcessSource::OpenCode,
            client: crate::attachment::ClientFocusTarget::Konsole(
                crate::attachment::KonsoleTarget {
                    service: ":1.108".to_owned(),
                    session_path: "/Sessions/1".to_owned(),
                    window_path: "/Windows/1".to_owned(),
                },
            ),
        };
        let mut model = DashboardModel::default();
        model.apply(found(instance.clone(), endpoint));
        model.apply_attachments(
            AttachmentSnapshot {
                tuis: Vec::new(),
                v1_focus: HashMap::from([(instance.clone(), target)]),
                claude_focus: HashMap::new(),
                diagnostic: None,
            },
            Instant::now(),
        );
        model.apply(projection(
            instance,
            endpoint,
            vec![session(
                "root",
                "root",
                None,
                ProjectedStatus::Busy,
                &[],
                &[],
            )],
        ));
        model.apply(BeaconEvent::Disconnected {
            endpoint,
            reason: "test".to_owned(),
        });

        assert_eq!(
            model.handle_terminal_event(&key_event(KeyCode::Enter), 5),
            DashboardAction::Redraw
        );
        assert_eq!(
            model
                .dismissal_status
                .as_ref()
                .map(|status| status.message.as_str()),
            Some("Cannot focus root: server is disconnected")
        );

        model.report_focus_result("failed\u{1b}[31m\nnext");
        assert_eq!(
            model
                .dismissal_status
                .as_ref()
                .map(|status| status.message.as_str()),
            Some("failed [31m next")
        );
    }

    #[test]
    fn dismissal_feedback_clears_for_fresh_question_permission_and_ready_occurrences() {
        let endpoint = endpoint(4013);
        let instance = key(13, 4013);
        let mut model = DashboardModel::default();
        model.apply(found(instance.clone(), endpoint));
        model.apply(projection(
            instance.clone(),
            endpoint,
            vec![session(
                "root",
                "Root",
                None,
                ProjectedStatus::Idle,
                &["q1"],
                &[],
            )],
        ));
        model.handle_terminal_event(&key_event(KeyCode::Right), 5);
        model.apply(projection(
            instance.clone(),
            endpoint,
            vec![session(
                "root",
                "Root",
                None,
                ProjectedStatus::Idle,
                &["q1", "q2"],
                &[],
            )],
        ));
        assert!(model.dismissal_status.is_none());

        model.handle_terminal_event(&key_event(KeyCode::Right), 5);
        model.apply(projection(
            instance.clone(),
            endpoint,
            vec![session(
                "root",
                "Root",
                None,
                ProjectedStatus::Idle,
                &[],
                &["p1"],
            )],
        ));
        assert!(model.dismissal_status.is_none());
        model.handle_terminal_event(&key_event(KeyCode::Right), 5);
        model.apply(projection(
            instance,
            endpoint,
            vec![session(
                "root",
                "Root",
                None,
                ProjectedStatus::Idle,
                &[],
                &[],
            )],
        ));
        model.apply(ready(endpoint, "root"));
        assert!(model.dismissal_status.is_none());
        model.handle_terminal_event(&key_event(KeyCode::Right), 5);
        model.apply(ready(endpoint, "root"));
        assert!(model.dismissal_status.is_none());
    }

    #[test]
    fn key_handling_selection_scroll_and_resize_are_deterministic() {
        let endpoint = endpoint(4010);
        let instance = key(10, 4010);
        let mut model = DashboardModel::default();
        model.apply(found(instance.clone(), endpoint));
        model.apply(projection(
            instance,
            endpoint,
            (0..5)
                .map(|index| {
                    session(
                        &format!("s{index}"),
                        "",
                        None,
                        ProjectedStatus::Busy,
                        &[],
                        &[],
                    )
                })
                .collect(),
        ));
        assert_eq!(
            model.handle_terminal_event(
                &Event::Key(KeyEvent::new(KeyCode::Char('j'), KeyModifiers::NONE)),
                2
            ),
            DashboardAction::Redraw
        );
        assert_eq!(
            model.handle_terminal_event(
                &Event::Key(KeyEvent::new(KeyCode::Down, KeyModifiers::NONE)),
                2
            ),
            DashboardAction::Redraw
        );
        assert_eq!(model.selected, Some(2));
        assert_eq!(model.offset, 1);
        assert_eq!(
            model.handle_terminal_event(
                &Event::Key(KeyEvent::new(KeyCode::Char('k'), KeyModifiers::NONE)),
                2
            ),
            DashboardAction::Redraw
        );
        assert_eq!(
            model.handle_terminal_event(&Event::Resize(100, 40), 2),
            DashboardAction::Redraw
        );
        assert_eq!(
            model.handle_terminal_event(
                &Event::Key(KeyEvent::new(KeyCode::Char('q'), KeyModifiers::NONE)),
                2
            ),
            DashboardAction::Quit
        );
        assert_eq!(
            model.handle_terminal_event(
                &Event::Key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL)),
                2
            ),
            DashboardAction::Quit
        );
    }

    fn style_test_model() -> (DashboardModel, InstanceKey, ServerEndpoint) {
        let endpoint = endpoint(4011);
        let instance = key(11, 4011);
        let mut model = DashboardModel::default();
        model.apply(found(instance.clone(), endpoint));
        model.apply(projection(
            instance.clone(),
            endpoint,
            vec![
                session(
                    "session-q",
                    "Question title",
                    None,
                    ProjectedStatus::Idle,
                    &["q"],
                    &[],
                ),
                session(
                    "session-p",
                    "Permission title",
                    None,
                    ProjectedStatus::Idle,
                    &[],
                    &["p"],
                ),
                session(
                    "session-b",
                    "Busy title",
                    None,
                    ProjectedStatus::Busy,
                    &[],
                    &[],
                ),
            ],
        ));
        model.apply(BeaconEvent::Disconnected {
            endpoint,
            reason: "test".to_owned(),
        });
        (model, instance, endpoint)
    }

    #[test]
    fn test_backend_preserves_exact_selected_and_unselected_styles() {
        let (mut model, _, _) = style_test_model();
        let selected = Modifier::BOLD | Modifier::UNDERLINED;
        let buffer = rendered(&mut model, 100, 12);
        assert_style(cell_at_text(&buffer, "> "), Color::Reset, selected);
        assert_style(cell_at_text(&buffer, "session-b"), Color::Reset, selected);
        assert_style(cell_at_text(&buffer, "Busy title"), Color::Reset, selected);
        assert_style(
            cell_at_text(&buffer, "permission"),
            Color::LightYellow,
            Modifier::empty(),
        );
        assert_style(
            cell_at_text(&buffer, "Permission title"),
            Color::Reset,
            Modifier::empty(),
        );
        assert_style(
            cell_at_text(&buffer, "question"),
            Color::Blue,
            Modifier::empty(),
        );

        model.move_selection(2, 5);
        let buffer = rendered(&mut model, 100, 12);
        assert_style(cell_at_text(&buffer, "question"), Color::Blue, selected);
        assert_style(
            cell_at_text(&buffer, "Question title"),
            Color::Reset,
            selected,
        );
    }

    #[test]
    fn test_backend_preserves_exact_dismissed_and_ready_styles() {
        let (mut model, instance, endpoint) = style_test_model();
        let selected = Modifier::BOLD | Modifier::UNDERLINED;
        model.move_selection(1, 5);
        let active = rendered(&mut model, 100, 12);
        let state_x = text_position(&active, "STATE").0;
        let session_x = text_position(&active, "session-p").0;
        let title_x = text_position(&active, "Permission title").0;
        assert_eq!(text_position(&active, "permission").0, state_x);
        model.handle_terminal_event(&key_event(KeyCode::Right), 5);
        let buffer = rendered(&mut model, 100, 12);
        assert_eq!(text_position(&buffer, "session-p").0, session_x);
        assert_eq!(text_position(&buffer, "Permission title").0, title_x);
        assert_eq!(
            text_position(&buffer, "permission").0,
            state_x + STATE_COLUMN_WIDTH - 10
        );
        assert_style(
            cell_at_text(&buffer, "permission"),
            Color::LightYellow,
            selected | Modifier::DIM,
        );
        assert_style(
            cell_at_text_on_row(&buffer, "Permission title", "stale"),
            Color::Reset,
            selected,
        );
        assert_style(
            cell_at_text(&buffer, "Permission title"),
            Color::Reset,
            selected,
        );
        assert_style(
            cell_at_text(&buffer, "question"),
            Color::Blue,
            Modifier::empty(),
        );
        assert!(!format!("{buffer:?}").contains('✓'));

        model.apply(BeaconEvent::Connected(endpoint));
        model.apply(projection(
            instance,
            endpoint,
            vec![session(
                "session-p",
                "Permission title",
                None,
                ProjectedStatus::Idle,
                &[],
                &[],
            )],
        ));
        model.apply(ready(endpoint, "session-p"));
        let buffer = rendered(&mut model, 100, 12);
        assert_style(cell_at_text(&buffer, "ready"), Color::Green, selected);
        assert_style(
            cell_at_text(&buffer, "OpenCode Beacon dashboard"),
            Color::Reset,
            Modifier::BOLD,
        );
    }

    #[test]
    fn test_backend_preserves_every_dismissed_semantic_color() {
        let endpoint = endpoint(4014);
        let instance = key(14, 4014);
        let mut model = DashboardModel::default();
        model.apply(found(instance.clone(), endpoint));
        model.apply(projection(
            instance.clone(),
            endpoint,
            vec![session(
                "root",
                "Root",
                None,
                ProjectedStatus::Idle,
                &["q"],
                &[],
            )],
        ));
        let selected_dim = Modifier::BOLD | Modifier::UNDERLINED | Modifier::DIM;
        model.handle_terminal_event(&key_event(KeyCode::Right), 5);
        let buffer = rendered(&mut model, 100, 12);
        assert_style(cell_at_text(&buffer, "question"), Color::Blue, selected_dim);

        model.apply(projection(
            instance.clone(),
            endpoint,
            vec![session(
                "root",
                "Root",
                None,
                ProjectedStatus::Idle,
                &[],
                &["p"],
            )],
        ));
        model.handle_terminal_event(&key_event(KeyCode::Right), 5);
        let buffer = rendered(&mut model, 100, 12);
        assert_style(
            cell_at_text(&buffer, "permission"),
            Color::LightYellow,
            selected_dim,
        );

        model.apply(projection(
            instance,
            endpoint,
            vec![session(
                "root",
                "Root",
                None,
                ProjectedStatus::Idle,
                &[],
                &[],
            )],
        ));
        model.apply(ready(endpoint, "root"));
        model.handle_terminal_event(&key_event(KeyCode::Right), 5);
        let buffer = rendered(&mut model, 100, 12);
        assert_style(cell_at_text(&buffer, "ready"), Color::Green, selected_dim);
        assert!(!format!("{buffer:?}").contains('✓'));
    }
}
