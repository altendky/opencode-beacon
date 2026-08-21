# Architecture

The repository is one publishable Cargo package with a library and binary.

- `model` contains tolerant protocol values and public events.
- `state` reduces SSE events and authoritative snapshots.
- `client` implements shared local HTTP/SSE framing plus version-specific v1
  and v2 snapshot/event adapters.
- `discovery` correlates same-UID procfs listeners for v1 and v2 standalone,
  classifies API protocol independently from discovery source, and separately
  validates managed v2 registrations from OpenCode's XDG state directory.
- `monitor` owns discovery, per-server connections, reconciliation, and
  cancellation.
- `claude` is a default-enabled, endpoint-free provider. It polls bounded same-UID
  per-PID live-session markers, validates PID/starttime against procfs, and
  reduces complete scans into provider-specific lifecycle, transition,
  attention, and projection events.
- The binary handles Linux signals and selects the default raw event formatter,
  attention-only `watch` table, or persistent `dashboard` without changing
  monitor logic.
- Dashboard additionally owns a Linux-only v2 TUI attachment sampler. Its
  procfs evidence and confidence remain binary-local and are not monitor events
  or shared protocol authority.

The monitor owns OpenCode and Claude as sibling futures over one bounded event
sink and cancellation root. Manual resync reaches both. Claude never enters the
OpenCode listener, endpoint, HTTP/SSE, reconnect-generation, TUI-association, or
cgroup-memory abstractions. CLI `--no-claude` or programmatic configuration can
disable it without changing OpenCode monitoring. Its bounded directory scan
yields between entries and checks shared cancellation before publishing a
complete result. Dashboard alone uses Claude lifecycle PID/starttime as input to
the existing binary-local client-focus evidence sampler.

The watch renderer emits no startup stdout by default; `--header` writes and
flushes one header before monitoring starts. At the binary sink it suppresses
every non-attention event from stdout and stderr. Explicit verbose mode permits
diagnostics on stderr but still suppresses disconnects and all other non-attention
records. It treats stdout `BrokenPipe` as a clean monitor shutdown. Detection
occurs on output writes; the renderer does not add heartbeat rows. The reusable
monitor continues to publish its full bounded FIFO event stream in both modes;
watch uses that one foreground sink and does not start a raw renderer.

Cgroup-v2 memory collection is binary-private and starts only for dashboard.
Procfs `ServerFound` registers exact dedicated-endpoint process/PID identity; a
managed v2 service PID is transport infrastructure and is deliberately not
reported as TUI memory. The monitor's ordered
`ServerRemoved` then `ServerFound` replacement sequence purges the old target
before adding its successor. A dashboard-local 10-second timer resolves and
validates process starttime and unified cgroup, deduplicates scopes by device and
inode, samples each scope once, and updates the pure render model. It is
independent of SSE connection state, so disconnect does not stop collection.
Per-scope history is bounded by both a two-hour window and 721 samples.

The reducer also retains legacy session title/slug/parent metadata, canonical
request indexes, request-ID dedupe, and per-root ready arms. These remain in the
per-server connection state across reconnects of the same instance and reset
with server replacement. Root resolution is cycle-safe and reports incomplete
ancestry rather than guessing.

Each server task opens SSE before its bootstrap snapshot and buffers events
while the snapshot is fetched.
The server task is the sole SSE owner for its discovered instance. Raw, watch,
dashboard, and all session rows receive locally reduced events from the shared
bounded monitor channel and never subscribe independently.
At the 1,024-event bootstrap capacity, the task stops polling the SSE body and
awaits the in-flight snapshot.
The same pause occurs at a fixed 8 MiB exact source-frame-byte budget; one frame
already requested from the source stream may cross that byte threshold.
TCP and HTTP transport backpressure preserve later events for subsequent reads.
On success, the snapshot is applied first and buffered events are then reduced
in arrival order.
On failure, a diagnostic is emitted, buffered events are still reduced in
arrival order, the healthy SSE stream remains active, and coalesced or periodic
snapshots retry reconciliation.
If SSE ends or fails during bootstrap, every valid frame already buffered is
reduced in arrival order before the disconnect is propagated.
Initial authoritative state is emitted only after the first complete snapshot.
This closes the connection gap without claiming exactly-once delivery.
V1 and v2 clients both normalize into this snapshot/event pipeline. V2 snapshots
page through `/api/session` and combine the result with `/api/session/active`;
the latter is a set of independently executing per-session foreground drains,
not a TUI's selected route or an inherited root-tree status.
The first complete snapshot emits deterministic initial pending-request
attention but only arms busy/retrying roots. Live output for one source event is
ordered observation, transition, then attention.

Normal reconciliation is a one-snapshot state machine rather than a blocking
HTTP call.
SSE observations and live transitions continue immediately while overlapping
state events are journaled FIFO.
When snapshot completion races frames already ready from the current SSE read,
the ready frames are drained first in a bounded batch; snapshot priority then
prevents a continuously ready stream from starving reconciliation.
On success, a candidate is built from the snapshot plus journal replay and
atomically replaces current state; only net corrective transitions are emitted.
Request attention already emitted live is not repeated by journal replay;
snapshot-only busy observations can still arm a later replayed idle.

Every successful bootstrap, reconnect bootstrap, or reconciliation appends one
atomic `StateProjection` after existing output. Every live state mutation
appends a projection after Observed/Transition/Attention. It identifies the
exact `InstanceKey` and endpoint and includes complete metadata, base status,
and legacy pending request-ID membership, exposing initially idle sessions,
metadata-only changes, authoritative removals/resolutions, and replacement.

Dashboard is one foreground sink over the same bounded stream. Its pure model
maintains instance-scoped stable rows, locally dismissible and restorable
attention occurrences, including dashboard-local ready for every fully
quiescent known session, plus selection and scrolling. Rows have stable admission
groups and canonical displayed-title/session ordering within each group; model
updates restore selection by row identity after any required reorder. V1 retains its dedicated
endpoint working-set behavior.

Claude dashboard rows admit only processes with a controlling TTY, key directly
by PID/starttime, display `ATTACH=claude`, and reuse local ready-generation and
elapsed-time behavior. They have no
OpenCode endpoint, TUI association, or memory scope. A row gains a focus target
only while its exact live Claude process yields fully validated Konsole or Kitty
evidence.

For v2, high-confidence attached roots,
including idle roots, are primary; unresolved live TUIs and active executions
without a resolved TUI are separate groups. After explicit route evidence, the
model globally pairs remaining location-compatible TUI/root candidates only when
an active root and TUI are unique to each other. A root is active when it or any
known descendant is busy or retrying. Accepted reciprocal pairs stay
sticky for the same instance/PID/starttime through idle and consume their root
from headless output. Process, session, or instance removal and contradictory
explicit evidence clear the pair. V2 aggregation preserves the root's own
foreground status and separately counts every busy/retrying descendant from
`parentID` ancestry, including nested descendants. Attachment category never
changes execution state. It also retains per-root monotonic
last-observed-non-busy instants and first-observed-busy instants when no exact
baseline is available.
Busy elapsed rendering and the next exact elapsed-minute redraw deadline receive
an explicit `Instant`, keeping tests independent of wall time. A one-shot Tokio
sleep is armed only when at least one connected, unmasked, known counter can
change; monitor or terminal events recompute the deadline. The `ratatouille`
crate renders through Crossterm async events; an RAII guard owns raw
mode, alternate screen, mouse mode, and cursor cleanup.
The separate fixed sampling timer wakes every 10 seconds while dashboard runs;
it samples cgroup memory and v2 attachment procfs evidence. Raw and watch modes
create neither sampler nor timer.
For a stable likely TUI, that sampler also retains only strict bounded
client-focus identifiers from a bounded environment read. Konsole uses D-Bus
service/session/window identifiers. Kitty uses its process/window IDs and an
absolute filesystem Unix remote-control socket, accepted only after same-UID,
namespace, process-starttime, listener-row, and descriptor validation.
Procfs-backed v1 instances and validated live Claude processes can provide the
same focus evidence directly from their exact process identity. The pure model
emits a focus action only for a non-stale v1, high-confidence attached v2, or
non-stale Claude row with complete evidence. The binary revalidates identity and
dispatches through a client-focus backend. Claude provenance additionally
requires same UID, PID/starttime, TTY, exact executable identity, and unchanged
allowlisted identifiers at every process check. For Konsole, it revalidates the
exact retained window/tab. At Enter, target dispatch receives a target-neutral
one-use activation-token broker. A compatible target bridge is always negotiated
before the broker runs. The broker first verifies Beacon's exact inherited Kitty
pane as the active pane in the compositor-focused Kitty OS window. Protocol
version 2 requests a fresh token asynchronously and returns it through a private
mode-0600, nonce-bound, one-shot Unix datagram beneath mode-0700
`XDG_RUNTIME_DIR`. Missing or inactive Kitty source evidence falls through to
Beacon's inherited Konsole activation-cookie API. Thus either source can feed
either exact target bridge without coupling source and destination types.
For a Konsole target, Beacon revalidates the D-Bus owner, exact window, and tab,
then passes the generic token to the versioned per-window bridge. Otherwise a
sole window uses the checked-in PID-scoped KWin script while multiple windows
stop after exact tab selection. For Kitty, Enter revalidates the Kitty process,
listener socket, and exact inherited window before passing the same generic token
to the target-local no-UI handler. Missing, incompatible, or failing bridge
support falls back to the official fixed-argument `focus-window` client with
ambient password use disabled. Tokens remain out of arguments, environment,
files, responses, logs, status, and retained state.
On failure, live state remains current and only the journal is discarded.
Periodic, manual, and coalesced triggers during a snapshot request one follow-up
snapshot rather than starting concurrent requests.
Ready triggers are drained together at snapshot completion so simultaneous
trigger classes cannot schedule multiple follow-ups.

Every server task retains reducer and initialization state after disconnect but
records the last completed discovery generation before emitting disconnect
output.
It reconnects only after the same `InstanceKey` is confirmed by a strictly newer
completed generation, including a pass that was in flight at disconnect, and
local exponential backoff has elapsed.
Each server receives the completed generation and its optional verified key as
one watch value, so disconnect cannot observe one without the other.
Reconnect backoff resets only after a successful bootstrap snapshot.
Discovery rejects multiple socket identities normalized to one endpoint.
If a later pass reports one new identity at an active endpoint, the old task is
stopped and removed before the replacement task starts, making endpoint-bearing
monitor output unambiguous.

Monitor output flows through a configured bounded FIFO channel.
Every send waits for capacity while selecting against root and per-server
cancellation.
Receiver closure cancels the monitor tree.
`MonitorRuntime` owns the root task; dropping it cancels and aborts owned work,
while `wait()` borrows and awaits its optional join handle, clearing it only
after completion.
Per-server shutdown follows the same cancellation-safe ownership rule.
CLI shutdown is bounded: after cooperative cancellation, non-settling owned work
is aborted, while dashboard terminal restoration is attempted before waiting.

Procfs traversal remains owned by the discovery future and cooperatively yields
between processes and bounded file-descriptor batches.
This avoids both a detachable blocking worker and monopolizing a current-thread
async executor during a full scan.
Pending discovery and snapshot futures are selected against root/per-server
cancellation and receiver closure; cancelled passes publish neither results nor
reconnect verification.
Snapshot completion is checked against those stop conditions before reducer
installation or corrective output.

Continuous discovery has a cheap listener-table gate and a full authoritative
path. Startup always performs a full scan. At the default one-second gate
cadence, discovery reads only `/proc/self/net/tcp` and `tcp6`, filters current-UID
loopback and wildcard LISTEN rows, and compares a stable address, port, and inode
fingerprint. An unchanged fingerprint performs no PID, descriptor, namespace,
ancestry, or health work and does not complete a discovery generation.

An added, removed, or inode-replaced row, a gate error, manual resync, SSE
disconnect, or the default five-minute full-verification interval requests full
discovery. Trigger classes use coalescing watch signals; triggers arriving during
a pass request one follow-up pass. Snapshot reconciliation retains its separate
trigger state. Eligible rows present at startup and later listener-table changes
also arm bounded settling passes 250 ms, 1 second, and 3 seconds after preceding
completed passes. Earlier manual or
disconnect passes do not consume a not-yet-due settling pass. This handles
LISTEN-before-health races and supplies the second completed miss required for
prompt removal without creating an unbounded retry loop.

The same gate fingerprint also tracks OpenCode registration filenames and file
identity/metadata. A combined authoritative pass unions both backends. Managed
v2 identity uses registration path and service ID together with PID and endpoint;
managed registration replacement/removal is immediate, while procfs instances
retain the two-completed-miss policy. If both backends verify one endpoint, the managed v2
registration is authoritative so only one task owns endpoint-scoped output. A
failure in one backend is diagnostic rather than an authoritative empty result:
the other backend remains usable without removing or superseding instances that
the failed backend could not revalidate. A changed validated managed connection
descriptor replaces only that task using the normal ordered removal/addition
lifecycle; credentials remain outside public lifecycle values. Backend
completeness is tracked by procfs versus managed source, not API protocol.
