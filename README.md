# opencode-beacon

`opencode-beacon` discovers local OpenCode HTTP servers and prints session
activity as concise line-oriented output.
It is a Linux-first event-detection MVP with a reusable Rust library.

```console
$ opencode-beacon
2026-08-09T12:34:56Z server=127.0.0.1:4096 event=server_found protocol=v1 version="1.17.4"
2026-08-09T12:34:57Z server=127.0.0.1:4096 source=sse session="ses_123" state=working->waiting_for_input
2026-08-09T12:34:57Z server=127.0.0.1:4096 source=sse event=attention attention=question name="Build release" root="ses_123" subject="ses_child" request="que_123" initial=false root_resolved=true
```

## Install

Install from crates.io after the first release:

```console
cargo install opencode-beacon
```

Static Linux binaries for x86-64 and ARM64 will be attached to GitHub
Releases with `SHA256SUMS`.

## Use

Run continuously with automatic discovery:

```console
opencode-beacon
```

Use the legibility-first attention view:

```console
$ opencode-beacon watch --header
TIME                  SESSION                         REASON      TITLE
2026-08-11T16:00:00Z  ses_0123456789ABCDEFGHIJKLMNOP  question    Synthetic release check
2026-08-11T16:02:03Z  ses_example                     permission  Synthetic deployment approval
2026-08-11T16:05:06Z  ses_0123456789ABCDEFGHIJKLMNOP  ready       Synthetic release check
```

`watch` is continuous-only and conflicts with `--once`. By default its terminal
output contains only attention rows, including startup question and permission
attention; `--header` adds the header once. Lifecycle, observation, transition,
disconnect, and diagnostic records are suppressed from both stdout and stderr.
With explicit `-v`/`--verbose`, diagnostics are additionally written to stderr;
disconnects remain suppressed. A detected closed stdout pipeline shuts the
monitor down cleanly. The full raw feed, including disconnect and diagnostic
rendering, remains the default when no subcommand is selected.

Use the persistent interactive working-set dashboard from a terminal:

```console
opencode-beacon dashboard
```

For v1 dedicated TUI endpoints, the dashboard admits a root when it first
works/retries, has a pending legacy question or permission anywhere in its known
tree, or becomes ready during that run. Initially idle historical v1 roots are
not prepopulated, preserving the existing dedicated-endpoint proxy behavior.

For v2, the primary set is sessions with a high-confidence likely TUI
attachment, including idle attached sessions. The `ATTACH` column distinguishes
these from active executions with no resolved TUI (`headless`) and live TUIs that
cannot be safely assigned (`unresolved` or `ambiguous`). Rows remain local to the
dashboard; no shared Beacon event claims protocol-authoritative TUI route state.
`ATTACH` never changes or implies execution state.
Duplicate IDs from different servers remain distinct and gain endpoint context
only when needed. Disconnected or retained uncertain rows are marked stale.

For v2, `STATE` keeps availability, foreground, and background work distinct. A
fully quiescent known root shows dismissible `ready`, including when first
observed. A root executing
without active descendants uses the same right-aligned elapsed-only display as
other rows; every busy/retrying descendant at any
known `parentID` depth contributes to a separate count. An idle prompt-available
root with two running agents shows `background 2`, while simultaneous root and
child execution shows, for example, `busy 3m +2 background`. A child retry counts
as background and does not turn the root into foreground retry. A background-only
root remains visible as `headless` when no TUI resolves to it.

For v1, the fixed-width `STATE` column retains its existing right-aligned whole
minutes (`0m`, `1m`, ...) while a root is busy/retrying. V2 foreground work uses
the same elapsed-only display and baseline. A root first observed busy reports the
time Beacon has observed it busy as a lower bound (`> 0m`, `> 1m`, ...). After
Beacon observes it non-busy, later busy/retry cycles show exact elapsed minutes.
Disconnected counters freeze and exclude disconnected time. Values saturate at
`9999999m`.
Question and permission from any known child remain attributed to the root and
retain priority over execution text. Ready appears only when the known root and
all known descendants are quiescent.

Dashboard also samples Linux cgroup-v2 memory every 10 seconds. For procfs-discovered
v1 and standalone v2 instances, the fixed
`MEM` column appears only on the first admitted row for each exact server
instance and uses neutral text with no background. It shows the current cgroup total, `N/A`
when identity or accounting cannot be validated, `stale` after a failed sample
following a valid one, or `shared` when multiple retained direct TUIs map to the
same cgroup; a shared total is not repeated as though it belonged to either TUI.
The selected-row detail reports total, 30-minute trend, anon/file/kernel
breakdown, swap, kernel peak when available, Beacon's observed peak, and cgroup
device/inode scope. Trend is the byte change per minute between the current
sample and the newest retained sample at least 30 minutes old, and remains `N/A`
until that history exists. Samples are retained in memory for at most two hours.
Sampling continues through SSE disconnect and stops only on exact removal or
replacement. A managed v2 service PID is shared transport infrastructure, not a
TUI, so managed rows show `N/A` rather than misattribute service memory.

Use Up/Down or `j`/`k` to move, Enter to request focus for the selected attached
TUI, Right to dismiss the selected active attention occurrence locally, Left to
restore it, and `q` or Ctrl-C to exit. `d` remains unbound. Dismissal and focus
never mutate an OpenCode session. Active attention is
left-aligned in `STATE`; dismissed attention keeps its semantic color, becomes
dim, and moves to the right edge. Actions produce immediate success or no-op
feedback in the status line. Dismissal and feedback clear on changed request
membership/kind, busy or background state, or a fresh ready cycle. Dashboard
`ready` means the known session is fully quiescent; the raw and watch feeds retain
transition-based ready semantics. Question is blue, permission is light
yellow/amber, and ready is green. Busy duration is pale neutral text, never an
attention hue. A fixed `>` column marks selection; selected text is
bold and underlined without a selection background, reverse video, or foreground
override.

Konsole focus is a Linux/KDE first draft. During attachment sampling Beacon reads
at most 256 KiB of the stable TUI process environment and retains only strict,
bounded `KONSOLE_DBUS_SERVICE`, `KONSOLE_DBUS_SESSION`, and
`KONSOLE_DBUS_WINDOW` values. Enter is enabled
only for a non-stale `attached` v2 row, or a non-stale procfs-backed v1 row whose
exact process exposes the same identifiers. Headless, unresolved, ambiguous,
stale, missing, and managed-service-only targets are clear no-ops.

At action time Beacon revalidates PID/starttime, uses fixed-argument `qdbus6`
calls to verify the Konsole D-Bus owner and that the exact retained window still
contains the tab, then selects that exact tab. When the Konsole process has one
window, Beacon then asks KWin to run the
repository-owned `src/kwin_focus.js` logic from a one-shot, mode-0600 temporary
script that activates the unique normal window owned by that Konsole PID. The
script is unloaded and deleted immediately. No shell,
`kdotool`, persistent KWin installation, or setup is required; the KDE session
must provide `qdbus6`, Konsole D-Bus, and KWin scripting. Status reports a focus
request, exact tab selection without compositor activation, safe no-op, or error
in the dashboard. For multi-window Konsole processes, exact tab selection works,
but Konsole exposes no safe mapping from `/Windows/N` to a KWin scripting window,
so Beacon does not raise an arbitrary same-PID window by fallback.

The optional, separately built `konsole-plugin/` bridge enables exact
multi-window activation. Beacon feature-detects protocol version 1 and its
activation capability, requests a fresh XDG activation token over native D-Bus
from Beacon's own inherited Konsole session at Enter, revalidates the target,
then asks only the bridge object corresponding to `/Windows/N` to select and
activate atomically. The cookie and token never enter command arguments, logs,
status, or retained dashboard state. Missing/old plugins and unavailable tokens
preserve the fallback behavior above. Konsole has no stable plugin SDK, so the
bridge is version-coupled and must be rebuilt after upgrades. See the
[Konsole Bridge guide](docs/src/project/konsole-bridge.md) for build, install,
uninstall, dependency, and support details.

`dashboard` requires terminal stdin/stdout and a non-dumb `TERM`; use `watch`
for pipes. It restores raw mode, alternate screen, cursor, and mouse state after
ordinary errors, `q`, Ctrl-C, and `SIGTERM`. `SIGKILL` cannot run cleanup; use
`reset` if a shell remains in an unusual mode after a hard kill.

The `TIME` column is 20 ASCII characters in whole-second UTC RFC 3339 form.
Canonical legacy IDs are `ses_` plus 26 generated ASCII characters, so `SESSION`
has a minimum width of 30. Short IDs are padded; IDs are never truncated, and an
unexpected longer ID shifts later columns right. `REASON` is 10 cells and
contains `ready`, `question`, or `permission`. `TITLE` normally starts at column
67, moves right for a longer ID, and is never truncated. Tabs, line breaks,
carriage returns, terminal controls, and escape characters in titles are
replaced with spaces while ordinary Unicode is retained. The raw line-oriented
feed remains the default when no subcommand is selected.

Ordinary v1 OpenCode TUIs must expose a TCP listener to be discoverable. On this
system, start them with the `o` launcher, which supplies `--hostname 127.0.0.1
--port 0 --no-mdns` for default TUI launches while preserving explicit network
options and leaving non-TUI subcommands unchanged. Loopback limits access to the
local host, port `0` selects a distinct available port, and disabled mDNS avoids
advertising the listener. Bare normal TUIs otherwise create no TCP listener.
Restart existing TUIs through `o` after installing or changing the wrapper.

Managed OpenCode v2 central services are discovered independently through
OpenCode's private XDG state registration files. V2 standalone private servers
are discovered from their same-UID procfs listener and exact `serve --stdio`
process shape. Beacon reads only that process's `OPENCODE_PASSWORD` entry and
validates authenticated `/api/health` against the socket owner's PID. It never
ensures or spawns a service. Procfs and managed discovery run together. Dashboard
separately finds likely full and `mini` v2 TUI clients, including `--standalone`, from
same-UID/same-network-namespace ESTABLISHED sockets to that validated endpoint,
stable PID starttime, TTY, argv, and cwd. Known noninteractive commands are
excluded and multiple sockets from one TUI are deduplicated.

V2 mapping prefers explicit `--session`, then reproducible `--continue`, then a
unique cwd/start-directory and session location/project/root match. After that
explicit evidence, a remaining TUI and same-location active root pair only when
each is the other's sole candidate globally. A busy or retrying descendant makes
its known root active for matching. The pair remains sticky for the same
instance/PID/starttime through idle and consumes the duplicate headless row;
collisions remain visible as ambiguous TUI and headless execution rows. Process,
session, or instance removal and contradictory explicit evidence clear the pair.
Startup argv can become stale after navigation, so other ambiguous clients remain
visible instead of being arbitrarily assigned. One successful missing-socket
sample retains stale evidence; the second removes it. Failed scans retain stale
evidence without counting a miss.

Inspect current state and exit:

```console
opencode-beacon --once --verbose
```

Send `SIGUSR1` to request immediate discovery and complete state
reconciliation.
Ctrl-C and `SIGTERM` shut down gracefully.

Optional Basic authentication is read from the environment so the password
does not appear in process arguments:

```console
OPENCODE_BEACON_USERNAME=opencode \
OPENCODE_BEACON_PASSWORD=secret \
opencode-beacon
```

Run `opencode-beacon --help` for timing and diagnostic flags.
`--discover-interval` is the cheap listener-table gate cadence and defaults to
`1s`. `--full-verification-interval` forces authoritative process, descriptor,
ancestry, and health discovery and defaults to `5m`. Library users configure the
same behavior with `MonitorConfig::discovery_interval` and
`MonitorConfig::full_verification_interval`.
The event-response header wait has its own timeout; the established SSE body is
not subject to the ordinary request timeout.

## Activity Model

The effective state uses this priority:

1. Pending question: `waiting_for_input`
2. Pending permission: `waiting_for_permission`
3. Retry status: `retrying`
4. Busy status: `working`
5. Idle or absent status: `idle`

SSE events update the model immediately.
Periodic, coalesced, reconnect, and manual HTTP snapshots run concurrently with
SSE processing.
Overlapping state events are applied immediately and replayed over the completed
snapshot; only net corrective transitions are then printed.
If the bootstrap snapshot fails, buffered SSE events are still applied and the
healthy stream remains connected while later snapshots retry.
If SSE fails or ends during bootstrap, valid buffered events are applied FIFO
before disconnect output.
Bootstrap and in-flight reconciliation journals pause SSE polling at 1,024
events or 8 MiB of exact source-frame bytes, allowing only the already-polled
frame to cross the byte threshold.
Valid frames are delivered before a malformed or oversized later frame from the
same network data.
Source-frame lengths remain internal accounting metadata; library consumers
receive the unchanged semantic `WireEvent` stream.
Errors, including `MessageAbortedError`, are printed observations and are not
latched into session state.

## Attention Feed

`BeaconEvent::Attention` and `event=attention` CLI lines provide three derived
user-facing signals while preserving the existing observations and transitions:

- `question` and `permission` are emitted once for each newly pending legacy
  request ID, even when activity-priority masking produces no transition.
- `ready` is armed only by an observed busy or retry status on a known root
  session. It is emitted once after that root is idle and no pending legacy
  question or permission remains anywhere in its known child tree.

Existing pending requests from the first successful snapshot have
`initial=true`; roots already busy or retrying are armed without an initial
`ready`. Later snapshot discoveries use `source=snapshot` and `initial=false`.
Request IDs and ready arms remain deduplicated across SSE/snapshot overlap and
same-instance reconnects. A replaced server has fresh state and may emit new
initial attention.

Child requests are attributed to the highest known root while preserving the
subject and request IDs. `root_resolved=false` reports missing or cyclic parent
metadata and safely falls back to the subject. CLI `name` uses the root title,
then slug, then ID. Titles can summarize prompt content, so attention output has
a broader privacy surface than ID-only transitions. Request text, permission
patterns, answers, and message content are never copied into attention events.
The `watch` table displays that same name prominently and must be treated as
potentially prompt-derived output.

For each live event, one server task publishes `Observed`, then existing
`Transition` values, then `Attention` values. Snapshot output is deterministic.
No global ordering is claimed across servers. `ready` means observed
idle-after-work; it does not prove every asynchronous cleanup action completed.

Library event delivery uses a configured bounded FIFO channel.
Backpressure is cancellation-aware, and dropping `MonitorRuntime` stops its
owned tasks.
`BeaconEvent::StateProjection` is an additive authoritative view keyed by exact
`InstanceKey` and endpoint. It includes every projected session's ID,
title/slug/parent and optional v2 project/directory/workspace/updated metadata,
base status, and sorted pending legacy request-ID
membership. It follows every successful snapshot and every live state mutation
after existing event ordering. It excludes question text, permission patterns,
messages, answers, and request payloads. Titles can summarize prompts, so
projection consumers must protect this data.
Discovery and snapshot results are discarded when their owning monitor is
cancelled or its receiver closes.
Continuous discovery performs one startup full scan. Stable gate checks compare
current-UID loopback/wildcard LISTEN address, port, and inode rows plus managed
registration file identity. Stable checks do not walk processes or probe health.
Row or registration changes, gate errors, manual resync, SSE disconnect, and
periodic full verification force authoritative discovery.
Eligible startup rows and later changes schedule bounded 250 ms, 1 second, and
3 second settling follow-ups for LISTEN-before-health and two-miss removal races.
Every reconnect requires the same `InstanceKey` in a strictly newer completed
discovery generation and retains local backoff.
Distinct socket identities cannot be monitored concurrently through one
normalized endpoint; an old task stops before a confirmed replacement starts.
Reconnect backoff resets only when the new connection completes a successful
bootstrap snapshot, not when SSE headers arrive or a bootstrap snapshot fails.

## Scope

The MVP does not provide notifications, cross-run dashboard persistence,
OpenCode session control, port scanning, remote discovery, or `/global/event`
support. Dashboard focus changes only the local Konsole tab/window.
Pending-request attention is reconciled only against the legacy `/permission`
and `/question` APIs; V2 pending requests are not yet supported.
V2 activity means exact per-session foreground drains from
`/api/session/active`; Beacon derives root foreground and descendant background
counts from those independent statuses and `parentID`. It is shown separately
when no TUI resolves to that root. OpenCode exposes no server
API for a TUI's locally selected route, so dashboard association remains an
explicitly labeled Linux heuristic. V2 `--server` clients do not own their remote
server and are not a discovery source. Normal bare v1 TUI processes without a TCP
listener likewise cannot be discovered. Standalone discovery depends on Linux
procfs retaining the private server's initial `OPENCODE_PASSWORD` environment
entry.
Discovery retains direct and manually served listeners but excludes listeners
with a stably identified `opencode-orchestrator-mcp` process ancestor.

See the [design documentation](docs/src/SUMMARY.md) for architecture, security,
development, and known limitations.

## License

Licensed under either the Apache License, Version 2.0 or the MIT license at your
option.
