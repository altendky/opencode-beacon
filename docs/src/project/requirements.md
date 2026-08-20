# Requirements

Claude Code monitoring must be enabled by default in raw, watch, dashboard, and
once modes and must run alongside, not instead of, the existing OpenCode
providers. Global `--no-claude` must disable it for one CLI invocation, and
programmatic `ClaudeConfig` must remain capable of disabling it. Disabling
Claude must not disable or change public OpenCode event semantics.

On Linux, Claude discovery must poll the configured Claude directory
(`CLAUDE_CONFIG_DIR`, otherwise `$HOME/.claude`) for exact positive
`sessions/<pid>.json` names. It must accept only bounded regular files owned by
the effective UID, require filename and JSON PID agreement, and validate an
exact `claude` executable basename or argv-zero fallback against a same-effective-
UID procfs process. Proc stat PID/starttime and UID must remain stable around the
marker read. Session ID and optional name must be bounded, cwd must be absolute,
and unknown additive fields or statuses must be tolerated without becoming
activity claims.

Claude `busy`, `working`, and `active` normalize to busy; `waiting` remains
non-quiescent; `idle` is quiescent; every other value is unknown. Initial idle or
unknown must not emit monitor/raw/watch ready. Initial busy or waiting arms the
session without emitting ready. A later idle emits ready once; repeated idle
does not. Unknown preserves uncertainty and must not claim ready. PID reuse must
remove the old PID/starttime identity before adding its successor. One complete
missing scan marks stale; two remove. A failed scan retains known sessions and
does not count as a miss.

Claude events must be additive provider-specific lifecycle, transition,
attention, and projection variants without fabricated OpenCode endpoints or
protocol values. They share monitor bounded FIFO backpressure, receiver-closure
cancellation, runtime ownership, shutdown, and manual resync. Watch suppresses
all non-attention Claude events and sanitizes names and IDs into one physical
line. Dashboard admits every validated Claude session; initial idle is local
dismissible ready generation zero. Claude rows must not expose memory
attribution. A Claude focus action requires fresh dashboard-local validated
terminal evidence; headless, stale, changed, or incomplete evidence must remain
visibly unfocusable.

Beacon must not parse Claude transcripts, install hooks, invoke `claude agents`,
invoke session control, or access the network for Claude monitoring. Outside
dashboard focus evidence it must not inspect Claude process environments.
Dashboard may read one bounded environment from an exact stable same-UID Claude
process and retain only the existing strict Konsole and Kitty allowlist. It must
discard marker fields other than PID, session ID, cwd, optional name, and status,
and must never expose `waitingFor` or arbitrary environment values.

The reusable library and stdout binary must discover every qualifying v1 or v2
standalone OpenCode TCP listener owned by the current user in the current Linux
network namespace, and must simultaneously discover managed v2 central services
from OpenCode registration files. Discovery source and API protocol must remain
independent classifications.
Both the TCP row and owning process must match the current effective UID, and
the process network-namespace identity must match `/proc/self/ns/net` before its
file descriptors are correlated.
Listeners with a positively and stably identified ancestor whose exact
executable basename, or fallback `argv[0]` basename, is
`opencode-orchestrator-mcp` must be excluded. Uncertain ancestry must retain the
candidate.
Discovery must not scan ports or machines.
An exact OpenCode `serve --stdio` listener owner is a v2 standalone candidate.
Discovery must read only its bounded `/proc/<pid>/environ`, retain only the exact
nonempty `OPENCODE_PASSWORD` entry, authenticate as `opencode`, and require
`GET /api/health` to report the candidate PID. Missing credentials, process
identity change, failed authentication, or a PID mismatch rejects the candidate
without exposing environment contents or credentials.
Managed discovery must use `$XDG_STATE_HOME/opencode`, falling back to
`$HOME/.local/state/opencode`, and recognize `service.json` plus sanitized
channel-specific `service-*.json` names. It must accept only bounded regular
files owned by the current effective UID with no group/other permission bits,
an uncredentialed loopback HTTP origin, positive PID, and authenticated
`GET /api/health` whose PID and optional registration version match. It must
never ensure, start, stop, or otherwise control a service.
Continuous monitoring must perform one startup full scan, then use a
current-UID loopback/wildcard LISTEN fingerprint of address, port, and inode as
its cheap gate. An unchanged gate must not walk PIDs, file descriptors,
namespaces, or ancestry, must not probe health, and must not complete an
authoritative discovery generation.
Listener addition, removal, or inode replacement, gate uncertainty or error,
manual control, SSE disconnect, and periodic full verification must request full
discovery. These trigger classes must coalesce without losing one required
follow-up when they overlap a pass.
Eligible startup listeners and later listener changes must schedule bounded
settling verification so a listener that precedes healthy HTTP service can still
be found and two completed misses can remove a departed server promptly.

SSE observations update session, status, pending-question, and
pending-permission state immediately.
Complete HTTP snapshots reconcile that state periodically, after reconnect,
after bootstrap races, after coalesced live changes, and on manual request.
Failed bootstrap snapshots must not discard buffered events or disconnect a
healthy SSE stream.
When the bootstrap buffer reaches its fixed capacity, SSE body polling pauses
until the in-flight snapshot completes so transport backpressure preserves all
later events.
Polling also pauses at a fixed 8 MiB buffered-source-byte threshold, with at
most the one already-polled frame allowed beyond that threshold.
The first initial-state event requires a complete authoritative snapshot.

Session enumeration requests an explicit large limit instead of relying on
OpenCode's default of 100 sessions.
V2 session enumeration must follow every `/api/session` pagination cursor and
combine the complete metadata set with `/api/session/active`. Only entries in
that active record are busy; absence means inactive. V2 `/api/event` data
envelopes and execution/status events must normalize into shared reducer events.
Created-session info must be preserved, retry scheduling must retain its
attempt/message/time, and execution failure must reconcile authoritative active
state without emitting a premature idle transition.
Event response headers have a cancellable timeout, but an established SSE body
does not have a total request deadline.
Valid events decoded before a malformed or oversized later frame must be
delivered first, even when both arrive in one network chunk.
Valid events buffered during bootstrap must be delivered before a later SSE
error or EOF is propagated.
Exact frame-plus-delimiter byte lengths are internal monitor metadata; the
public event stream remains a stream of semantic wire events.
Successful `/event` responses must be HTTP 200 with a `text/event-stream`
Content-Type; media-type casing and parameters are accepted.

Normal reconciliation keeps polling SSE and applies live state immediately.
State events overlapping the snapshot are replayed FIFO over a candidate
snapshot state, which atomically replaces current state and emits only net
corrections.
Frames already ready when the snapshot completes must be journaled first using
a bounded drain that cannot let a continuously ready stream starve completion.
Triggers that overlap an in-flight snapshot coalesce into one follow-up request.
Triggers already ready when that snapshot completes must be drained into the
same single follow-up.

Library events use bounded FIFO backpressure.
All producers stop on cancellation or receiver closure, and runtime ownership
must not detach tasks.
Cancelled discovery and snapshot waits must not publish results or
authentication verification.

After any stream disconnects, a new connection requires fresh discovery
confirmation of the same UID-owned process/socket `InstanceKey`.
The confirmation must come from a strictly newer successfully completed
discovery generation than the latest completion recorded at disconnect.
Generation completion and the key verified by that pass must be observed
atomically by each server task.
Distinct socket identities normalized to the same endpoint must not be monitored
concurrently; an explicit replacement stops before its successor starts.
V1, standalone v2, and managed v2 instances at different endpoints must coexist. A verified managed v2
registration takes precedence if both backends identify one endpoint. Managed
registration disappearance or failed validation removes its task without
applying procfs discovery's delayed two-miss policy. A validated managed connection descriptor
change replaces only that task in removal-then-addition order without exposing
credentials through public events.
Reconnect backoff resets only after a successful bootstrap snapshot.
The disconnect must request full discovery promptly rather than waiting for the
next gate or periodic verification tick.

Effective activity priority is question, permission, retry, busy, then idle.
Errors and `MessageAbortedError` are observations only.

Session snapshots and complete `session.created`/`session.updated` events retain
legacy title, slug, and optional parent ID metadata. Attention resolves a subject
to its highest known root; missing or cyclic ancestry falls back to the subject
and marks resolution incomplete.
V2 snapshots must additionally retain optional project ID, directory, workspace,
updated time, and parent ancestry needed by dashboard-local attachment mapping.
Those fields remain optional for v1.

Question and permission attention is emitted once per newly pending legacy
request ID, independently of effective-transition masking. Child requests use
the root name and ID while retaining subject and request IDs. The first complete
snapshot emits every existing pending request with `initial=true`; later
snapshot discoveries use `initial=false`.

Ready attention is armed only after the known root's own status is observed as
busy or retry. It emits once when that armed root is effectively idle and no
known descendant has a pending legacy question or permission. Initial idle,
initial busy/retry, child idle, and repeated idle observations must not emit
ready attention.

Request IDs and root arms remain deduplicated across SSE/snapshot overlap and
reconnects of one `InstanceKey`; replacement creates fresh state. Snapshot
attention is deterministic, and each live event publishes its observation,
existing transitions, then attention in that per-server order.

The public stream must additionally expose complete atomic state projections
scoped by exact `InstanceKey` and endpoint, containing every known session's ID,
title/slug/parent and optional project/location/updated metadata, base status,
and pending legacy request-ID
membership. Successful snapshots and live state mutations emit projections only
after existing output. They must exclude question text, permission patterns,
messages, answers, and other request payloads.

With no subcommand, the CLI retains the raw line-oriented feed. The continuous
`watch` subcommand conflicts with `--once` and sends only attention rows to
stdout. It emits no default header or startup row; `watch --header` writes one
plain-text header. By default every non-attention event, including disconnects
and diagnostics, is suppressed from both output streams. Explicit verbose mode
may additionally render diagnostics on stderr, but disconnects remain suppressed.
No raw renderer runs alongside watch, and a detected closed stdout pipe triggers
clean shutdown. No-subcommand raw mode retains disconnect and diagnostic output.

The explicit continuous `dashboard` requires TTY stdin/stdout and a non-empty,
non-dumb `TERM`, directing unsuitable users to `watch`. It uses raw mode,
alternate screen, hidden cursor, async keys, resize handling, and cleanup on
ordinary return, errors, Ctrl-C, and `SIGTERM`.

V1 dashboard rows key by `(InstanceKey, root_session_id)` and retain the
dedicated-endpoint proxy behavior. Initially idle v1 history is not admitted;
first busy/retry, pending tree request, or ready during the run admits the row.
Rows leave only on authoritative root absence or exact instance
removal/replacement. Same-instance disconnect marks rows stale.

Dashboard alone must sample likely interactive v2 clients from Linux
procfs. An eligible TUI requires an ESTABLISHED client-side socket whose peer is
a currently validated v2 endpoint, socket-inode ownership by a same-UID
process in Beacon's network namespace, stable PID starttime, readable argv and
cwd, and a TTY. Full default TUI and `mini`, with or without `--standalone`, are
interactive; the managed service, Beacon, `run`, `serve`, `service`, `acp`, `api`,
other known noninteractive commands, and unrelated processes are excluded. Multiple
matching sockets from one stable PID are one TUI. This evidence is heuristic and
must not become protocol authority.

V2 association priority is explicit `--session`, reproducible `--continue`, then
a unique cwd/startup-directory to session location/project/root match. Execution
state and updated time may only resolve `--continue` or label a tie. After that
explicit evidence, remaining location-compatible candidates may pair to an
active root only through a global one-to-one match: the TUI must have exactly one
eligible active root and that root exactly one eligible TUI. Matched roots are
consumed from headless rows. A root is active for matching when its own session
or any known descendant is busy or retrying. Missing explicit IDs, collisions on
either side, and unsupported argv routes remain unresolved or ambiguous rather
than receiving an arbitrary root. A reciprocal match remains sticky for the same managed
instance, PID, and process starttime when the root becomes idle. Contradictory
explicit evidence replaces or clears it; process, session, or exact instance
removal clears it. Startup argv is only evidence about launch intent because the
route may later change. High-confidence attached roots, including idle roots,
form the primary v2 set. Active roots without a resolved attached TUI remain
visible as headless activity, and unresolved/ambiguous live TUIs remain visible
separately. One successful missing-socket sample retains a stale TUI; two remove
it. A failed scan retains prior TUI evidence as stale and does not count as a
miss. Durable session deletion is not required for attachment removal.

Dashboard rows must use stable group boundaries in this order: v1, attached v2,
headless v2, Claude, then unresolved/ambiguous v2. Within each group rows sort by the
displayed title (session title, then the existing slug/session fallback), with
session ID as the tie-breaker and endpoint as the deterministic final
disambiguator. Status, attention, staleness, elapsed time, background count, and
attachment sample order must not affect ordering. A displayed-title change or a
change of admission group intentionally reorders the row. Selection must remain
on the same instance-scoped row across a reorder whenever that row survives.

The `ATTACH` classification must remain orthogonal to execution state. For each
displayed v2 root, foreground status comes only from that root session's own
projected status. Background count is the number of distinct known descendants,
at any ancestry depth, whose own status is busy or retry. An idle root with no
active descendants renders dismissible `ready`, including when first observed;
an idle root with active descendants renders `background N`; a busy or retrying
root without active descendants renders only
its right-aligned elapsed time, while a root with descendants renders foreground
state and elapsed plus `+N background`. A root with only
background activity remains visible as headless when no TUI resolves to it.
Unresolved and ambiguous TUI rows must not invent session execution state.

Question and permission membership from any known descendant retains the
existing root attribution and priority over foreground/background rendering.
Dashboard ready is the fallback for every fully quiescent known session.
Descendant retry contributes to background count and must not turn an idle root
into foreground retry.

V1 retains question, permission, blank busy/retry, then ready priority. Every
admitted, fully quiescent known session renders `ready`, independently of whether
the monitor emitted transition-based ready attention. For both
versions, only the attention word is colored blue, light-yellow/amber, or green respectively,
and selection preserves it. Selection uses a fixed `>` column plus text emphasis,
without setting a background, reversing video, or overriding foreground colors.

Dashboard dismissal is local and non-mutating. It dims only the selected current
kind plus request-ID set or dashboard ready generation. Generation zero
represents initially observed quiescence; monitor ready events advance the
generation. Right dismisses that occurrence and
Left restores it; `d` is unbound. Success and no-op attempts immediately report
status. No-attention actions are no-ops. Active attention is
left-aligned in the fixed STATE field; dismissed attention is right-aligned and
dimmed in the same semantic hue, without a checkmark or background. The
occurrence-bound dismissal and status clear on kind/membership change, busy or
background activity, fresh ready, restart, or replacement.

Dashboard attachment sampling may additionally read at most 256 KiB from an
otherwise eligible stable TUI process environment. It must discard every entry
except strict bounded `KONSOLE_DBUS_SERVICE`, `KONSOLE_DBUS_SESSION`,
`KONSOLE_DBUS_WINDOW`, `KITTY_PID`, `KITTY_WINDOW_ID`, and `KITTY_LISTEN_ON`
identifiers and must not render or retain the broad environment. Procfs-backed
v1 and Claude may collect the same identifiers from their exact PIDs after
same-UID, stable PID/starttime, TTY, and provider process-identity validation;
managed service PIDs must not be treated as TUIs. Malformed or unvalidated Kitty
evidence may fall back to complete valid Konsole evidence, while fully validated
Kitty evidence takes precedence over inherited outer-terminal identifiers.

Enter must emit a focus action only for a connected, non-stale procfs-backed v1
row, a non-stale high-confidence attached v2 row, or a non-stale Claude row with
a complete supported client-focus target. Missing selection/identifiers/targets,
headless execution, unresolved or ambiguous association, stale evidence, PID
reuse, and unsupported client interfaces must produce a clear safe no-op or
error. The pure dashboard model must perform no D-Bus, process, or window side
effect. At the binary boundary every backend must freshly validate PID/starttime.
Claude must additionally revalidate same effective UID, nonzero TTY, exact
`claude` executable basename or argv-zero fallback, and unchanged allowlisted
environment identifiers before and during focus. Konsole must verify
the D-Bus owner and exact tab/window, and select the tab with fixed arguments on
the exact retained window. It may activate through KWin only when that D-Bus window is the
process's sole window and there is a unique normal KWin window for that Konsole
owner PID. Multiple-window selection must report partial success without
choosing an arbitrary compositor window. It must invoke no shell, retain no
generated script, and report request/partial/no-op/error status in the dashboard.

Before fallback activation, Enter may use a versioned Konsole plugin bridge only
at the object corresponding to the retained exact window. Beacon must negotiate
the target protocol and capability before asking a target-neutral broker for a
fresh token. The broker must try only an exact active inherited Kitty source
before the inherited Konsole source; missing, inactive, stale, incompatible, or
failed Kitty evidence must fall through without blocking Konsole. The Konsole
provider must read only Beacon's inherited service, session, and activation
cookie at the action and use native D-Bus without procfs cookie scraping or
command arguments. After any asynchronous source request Beacon must revalidate
the target PID/starttime, D-Bus owner, exact window, and session before passing
the same generic one-use token to the bridge. Missing, old, mismatched, failed,
or tokenless bridges must preserve exact-tab and sole-window KWin fallbacks.
Cookies and tokens must not enter logs, status, retained state, child-process
arguments, or environment.

A Kitty target additionally requires positive numeric process and window IDs
and `KITTY_LISTEN_ON` naming a bounded canonical absolute filesystem Unix
socket. TCP, abstract, relative, and inherited-FD addresses are unsupported.
The Kitty process must retain the sampled starttime, current effective UID, and
Beacon network and mount namespaces. Its `/proc/<pid>/net/unix` must contain
exactly one stream listening row for the path and one of its descriptors must
own that socket-object inode. The filesystem socket must be same-UID,
non-symlink, and canonical. A group/other-writable socket is accepted only when
its canonical path has a same-UID private ancestor directory with no group/other
permissions, such as a conforming mode-0700 `XDG_RUNTIME_DIR`; otherwise the
socket itself must not be group/other writable. Enter must re-read the TUI
environment and repeat process, namespace, effective-path privacy, socket-row,
descriptor, and filesystem-identity validation before invoking `kitten` with
fixed arguments, no shell, no response suppression, and password use disabled.
Missing or changed evidence must fail closed. Successful remote-control response
means Kitty accepted pane/tab selection and an OS-window focus request; it does
not confirm compositor activation and must not change OpenCode route or execution
state.

Before ordinary Kitty focus, Enter may probe protocol version 2 of the installed
Beacon no-UI custom kitten using bounded direct Kitty protocol framing. The
empty-password authorization policy must allow only ordinary `focus-window` and
the exact bridge filename, positive matched ID, protocol version, target
probe/activation or source probe/token operation, callback path, nonce, and
bounded token shape. It must reject non-socket calls, extra fields, mismatched
IDs, arbitrary kitten paths, and every other `kitten` payload. A Kitty source
must be derived from Beacon's own bounded inherited identifiers and validated as
the same-UID stable Kitty PID/starttime, namespace, listener, descriptor, socket,
and exact internal pane. The handler must require that pane to remain active in
the compositor-focused Kitty OS window both before requesting and when receiving
the asynchronous token. It must return a valid token only through a same-UID
mode-0600 Unix datagram socket created beneath canonical same-UID mode-0700
`XDG_RUNTIME_DIR`, bound to a cryptographically random nonce and strict bounds.
Beacon must ignore malformed, oversized, mismatched, duplicate, stale, or timed
out datagrams, close and unlink the socket on every path, revalidate source and
target after receipt, consume the token for one bridge call, and discard it.
The target-local handler must feature-detect Kitty 0.45 internal APIs, resolve
the same exact target window ID, select that pane/tab, and apply the generic
token to its containing OS window. Tokens must not enter child arguments,
environment, files, logs, status, retained state, or bridge responses. Missing
source support, incompatible Kitty APIs, rejected probes, unavailable tokens,
and safe bridge failures must preserve freshly revalidated target-specific
fallback and report partial selection rather than confirmed compositor
activation. Same-process and different-process Kitty source/target pairs must
use the same flow; tokens from another compositor may be ineffective and must
not trigger unsafe retries.

For each admitted connected root whose root status is busy/retry and whose
attention marker is absent, Dashboard must render right-aligned whole elapsed
minutes in a stable fixed-width state area. Elapsed time uses monotonic `Instant`
from the latest observation of that root as non-busy, including pre-admission
observations and ready admission. Initial busy admission without such an
observation starts a first-observed-busy baseline and displays the elapsed whole
minutes as a neutral lower bound (`> 0m`, `> 1m`, ...); any later non-busy
observation establishes the exact baseline for a future busy/retry cycle.
Question, permission, and ready markers,
including dismissed attention, replace elapsed text. Elapsed text uses DarkGray or
an equivalent low-contrast neutral foreground, never an attention hue or
background, and selection may add emphasis without replacing that foreground.
The compact counter saturates at `9999999m`.

Dashboard alone must associate every exact procfs `ServerFound` `InstanceKey` and PID
with a readable process starttime and unified cgroup beneath `/sys/fs/cgroup`.
A managed v2 service PID must not be presented as memory belonging to its TUIs;
a standalone v2 private server remains direct procfs memory.
The process starttime must still match around cgroup resolution, cgroup paths
must reject parent/current-directory components and canonical escapes, and
cgroup identity must be filesystem device plus inode rather than path text.
Every 10 seconds it must read `memory.current`, `memory.swap.current`, and
`memory.stat` anon/file/kernel, plus optional `memory.peak`. Sampling continues
through SSE disconnect and retained state leaves only on exact `ServerRemoved`
or replacement. History is bounded to two hours and retains current and maximum
observed `memory.current`. The 30-minute trend is bytes per minute from the
current sample to the newest retained sample at least 30 minutes old; it is
unknown until sufficient history exists.

The dashboard table has a fixed `MEM` column rendered only on the first stable
row for an instance, in neutral text without a background. Read, parse, identity,
or accounting failures render `N/A`, or `stale` when a previous valid scope
sample is retained, never zero. If more than one retained direct procfs instance maps to the
same device/inode scope, every mapping is marked shared and no per-instance
total is displayed. Selected-row detail reports total, trend, anon/file/kernel,
swap, optional kernel peak, observed peak, and device/inode scope; shared detail
must not present the scope total as belonging to the selected instance.

Disconnect freezes a known busy elapsed duration. Connected alone clears the
stale label but does not advance that frozen duration; the next authoritative
projection either resumes busy timing without including disconnected time or
resets the baseline from an observed non-busy state. Dashboard schedules one-shot
redraws at exact next elapsed-minute boundaries only while a connected, visible,
known, unsaturated counter can change. Masked, stale, non-busy, and
fully saturated rows must not independently cause timer wakeups.

Watch columns are `TIME` at 20 ASCII cells, `SESSION` at a minimum 30, `REASON`
at 10, and an unbounded `TITLE`. Time is whole-second UTC RFC 3339. Canonical
legacy IDs are `ses_` plus 26 generated ASCII characters. Short IDs are padded;
all longer IDs remain complete and shift later columns right. Title controls and
escape characters cannot create additional terminal lines or ANSI commands,
while ordinary Unicode text is retained.
