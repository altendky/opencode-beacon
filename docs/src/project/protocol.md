# Protocol and State

The OpenCode 1.17.4 endpoints are `/global/health`, `/session`,
`/session/status`, `/permission`, `/question`, and `/event`.
Session enumeration uses `/session?limit=100000` because the default response is
limited to 100 sessions.
Legacy session title, slug, and parent ID are retained from snapshots and full
session create/update events. Titles can contain summaries derived from prompts.
SSE wire events use the name `message`; their JSON `type` is the semantic event.
Unknown semantic events are preserved as observations and ignored by the
reducer, allowing additive protocol evolution.

OpenCode v2, whether managed or standalone, uses `/api/health`, paginated `/api/session`,
`/api/session/active`, and one global `/api/event` SSE stream. Beacon follows
all forward cursors, maps optional v2 title/parent/project, location
(directory/workspace), and updated-time metadata into the shared
session model, and treats only active-record membership as busy execution.
Membership applies to that exact session ID; parent and child sessions own
independent drains, so dashboard root-tree aggregation must preserve both.
V2 event payloads use `data` rather than `properties`; status and execution
lifecycle events are adapted to shared `session.status` semantics. Supplied
`session.created` info is preserved. `session.retry.scheduled` maps its attempt,
error message, and absolute retry time into shared retry status. Execution
failure remains an observation and requests an active-state snapshot rather than
briefly claiming idle before a following retry. Location and updated metadata
support dashboard-local heuristics but do not identify TUI route state. The
stream is volatile and has no replay cursor, so the existing reconnect snapshot
reconciliation remains authoritative.

Live events mutate the model immediately and emit effective state transitions.
While all four snapshot requests are in flight, overlapping state events are
retained with exact raw frame-plus-delimiter byte lengths and also applied live.
Successful snapshot state is replayed with those events before an atomic commit,
so only net corrective transitions are emitted.
Failed snapshots do not roll back live state.
Absent session-status map entries mean idle.

Legacy question and permission payloads are reduced to request ID and subject
session ID for attention derivation. Request text, patterns, answers, and other
payload fields are not retained in `AttentionEvent`. Canonical request indexes
remove stale membership when a request ID is reassigned.

`AttentionEvent` contains kind, root ID/title/slug, subject ID, optional request
ID, source, initial flag, and root-resolution status. Endpoint context in
`BeaconEvent::Attention` disambiguates simultaneously monitored TUI servers.

`BeaconEvent::StateProjection` carries exact `InstanceKey` plus endpoint and a
sorted list of sessions with ID, title, slug, parent ID, optional
project/directory/workspace/updated fields, base status, and sorted
pending legacy question/permission request IDs. Complete projections follow
successful snapshots and live mutations after existing output, making absence
and replacement meaningful. V2 pending APIs remain outside this scope.
No shared event or projection claims that a TUI is attached to a session.

The reducer does not latch errors.
It prints a privacy-conscious error kind/message observation and leaves session
activity unchanged.

SSE response headers must arrive within the configured header timeout.
The response must be HTTP 200 with a case-insensitive `text/event-stream`
Content-Type; parameters such as `charset=utf-8` are allowed.
Once received, the body remains long-lived without the ordinary request
deadline.
The 1 MiB safety limit applies independently to each complete or currently
unterminated SSE frame.
An incomplete frame may temporarily retain only the possible prefix of its
blank-line delimiter beyond that limit, allowing a maximum-sized frame's LF,
CRLF, bare-CR, or mixed delimiter to arrive fragment by fragment.
The decoder exposes at most one source-aware frame per internal poll, preserving
valid-frame delivery before a later parse/size error without hiding decoded data
outside monitor budgets.
The public stream strips this source accounting and yields `WireEvent` values.
Per-server journals pause source polling at 1,024 events or 8 MiB.
SSE field lines and blank separators accept LF, CRLF, and bare CR endings.
A record ending in two bare CR bytes is delivered immediately while the body is
still open. The decoder consistently chooses that earliest complete separator,
so a later LF is consumed as a leading empty record and frame-byte accounting is
independent of network chunk boundaries.
If bootstrap SSE then fails or ends, valid journaled records are observed and
reduced FIFO before disconnect output.
