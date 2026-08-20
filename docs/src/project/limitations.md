# Limitations

- Claude Code monitoring is enabled by default and Linux-only, with Claude Code
  2.1.160 as its initial compatibility target. `--no-claude` disables it for one
  CLI invocation. Its per-PID marker directory is an internal interface, not a
  documented stable API; tolerant parsing and unknown-state handling reduce but
  cannot eliminate version-compatibility risk.
- Claude marker and procfs observations are not atomic. PID/starttime and UID
  checks reject ordinary reuse and cross-user evidence, but another process
  under the same UID remains a trusted local principal and can forge markers.
- Claude polling can lag a state change by the configured one-second interval.
  Two successful misses delay removal, while scan failures retain stale rows.
- Claude monitoring covers live per-PID markers only. It does not parse saved
  transcripts or preserve completed background-agent history, and it does not
  invoke the slower `claude agents --json` interface.
- Claude rows have no OpenCode attachment, cgroup-memory attribution,
  prompt/question/permission classification, session control, or notifications.
  Terminal focus is available only when the exact live Claude process has a TTY
  and inherited complete supported Konsole or Kitty identifiers; headless,
  stale, inaccessible, or incomplete evidence remains unfocusable. `waiting` is
  non-quiescent but its potentially sensitive `waitingFor` detail is discarded.

- Discovery supports Linux procfs v1 and v2 standalone listeners plus managed v2
  central-service registration files only.
- Bare v1 OpenCode TUI instances have no discoverable TCP listener. V1 deployment
  requires ordinary TUIs to be restarted through the `o` wrapper, which defaults
  them to loopback, an OS-selected port, and no mDNS while respecting explicit
  network options. Managed v2 uses a different client-socket heuristic.
- Discovery does not cross users, network namespaces, or machines.
- OpenCode provides no stable server ID or SSE replay cursor.
- HTTP snapshot endpoints are complete as a group but not server-transactional.
- An interruption can collapse several missed changes into one reconciled
  transition.
- Attention request IDs and ready arms deduplicate within one discovered server
  instance, but replacement or restart may legitimately repeat initial events.
- Missing or cyclic parent metadata falls back to the subject session with
  incomplete root resolution; later metadata can attribute future events
  differently.
- Ready means an armed root was observed idle after work with no known pending
  legacy request. It does not prove every asynchronous cleanup action completed.
- Live ordering is preserved per server and source stream; concurrently
  monitored servers have no global event order.
- V2 pending permission/question APIs are not reconciled in the MVP. Attention
  and projections use only legacy `/permission`, `/question`, and related SSE.
- OpenCode v2 exposes actively executing drain-owned sessions through
  `/api/session/active`, but no server API exposes a TUI's locally selected route
  or session. Dashboard attachment therefore uses Linux procfs socket/process,
  argv, cwd, TTY, and session metadata heuristics. It can miss, ambiguously map,
  or briefly retain a TUI, and never claims protocol-authoritative route state.
- V2 foreground/background display depends on complete known `parentID`
  ancestry and per-session status. Missing or cyclic ancestry safely prevents
  uncertain child attribution and can undercount a root's background activity.
  Snapshot and SSE reads are not transactional, so a short-lived combination of
  root foreground and descendant count can reflect different observation times.
- Standalone v2 discovery depends on the private `serve --stdio` process retaining
  its initial `OPENCODE_PASSWORD` entry in Linux procfs. Explicit `--server`
  clients do not own that server and are not a discovery source.
- The compact watch table omits endpoint, subject, request, source, initial, and
  root-resolution fields available in the raw feed. Identical root IDs from
  different servers are therefore visually indistinguishable.
- Watch suppresses lifecycle and state records, including disconnects. Explicit
  verbose mode adds diagnostics on stderr, but full troubleshooting output
  requires the no-subcommand raw feed.
- Watch TITLE is intentionally unbounded and can wrap in narrow terminals.
  Unicode display width depends on the terminal. TIME and REASON stay fixed;
  an unexpected session ID longer than the canonical 30 characters is preserved
  and shifts later columns right.
- A quiet watch process cannot detect that a pipeline reader exited until the
  next attention row attempts a write. In `--header` mode, closure after a
  successful header likewise waits for the next row; no synthetic heartbeat rows
  are emitted.
- User-configured v1 Basic credentials apply to every qualifying same-UID v1
  server. Managed v2 credentials come from validated private registrations;
  standalone credentials come only from the verified listener process.
- Procfs ownership verification and TCP connection are not atomic; a listener
  can change during that unavoidable interval.
- The listener-table gate notices eligible row identity changes at its configured
  cadence, one second by default. Stable rows defer repeated process and health
  verification until the configured authoritative interval, five minutes by
  default, unless manual control or disconnect requests it sooner.
- LISTEN can precede healthy HTTP service. Change-driven retries are deliberately
  bounded to 250 ms, 1 second, and 3 seconds after completed passes; a service
  that remains unready beyond them waits for another explicit, disconnect, gate,
  or authoritative trigger.
- Process network-namespace identity is checked before and after descriptor
  correlation, but procfs inspection cannot prevent a later namespace or
  listener change before connection, or detect a namespace change away and back
  between those two reads.
- The orchestrator-descendant filter is a Linux procfs ancestry heuristic with
  one hard-coded exact launcher basename. Procfs is not transactional, so
  disappearing processes, reparenting, PID reuse, malformed data, inaccessible
  ancestry, and cycles retain a candidate and can produce false negatives.
- Stable-looking PID and start-time observations reduce but cannot eliminate
  ancestry races; this filter is routing policy, not a security boundary.
- V2 client socket and process inspection is likewise non-transactional. TUI
  startup argv can become stale after in-process navigation; cwd/location and
  project metadata can be shared; `/api/session/active` is execution, not
  attachment. Active descendants make their known root eligible for reciprocal
  location matching, which deliberately rejects collisions on either side, so
  genuine sharing remains ambiguous. Sticky reciprocal mappings
  are dashboard-process-local and last only while the same instance, PID,
  starttime, and session remain. Two successful misses delay process removal,
  while scan failures retain a stale entry.
- Every reconnect waits for fresh discovery of the same `InstanceKey`, but this
  reduces rather than eliminates the verification-to-connect race.
- Multiple procfs socket identities that normalize to one loopback endpoint are
  rejected as ambiguous for that discovery pass.
- Event delivery intentionally backpressures monitoring when the consumer does
  not drain the configured bounded channel.
- Dashboard rows, title/session order, selection, and dismissals are process-local
  and not persisted. A title, title fallback, or admission-group change can move
  a row; unrelated state updates do not. Dashboard requires terminal stdin/stdout
  and a non-dumb `TERM`; colors are supplemental and depend on terminal support.
- Dashboard focus supports a local KDE session with Konsole, `qdbus6`,
  and the KWin 6 scripting API used by the repository-owned script only.
  Inherited Konsole D-Bus service/session/window identifiers can be absent or
  stale. The exact D-Bus window removes tab-selection ambiguity, but Konsole does
  not expose a safe mapping from that `/Windows/N` object to a KWin scripting
  window. For a process with multiple windows, Beacon selects the exact Konsole
  tab but the fallback does not request compositor activation because PID-only
  KWin matching cannot safely choose one. The optional bridge enables exact
  multi-window activation, but Konsole has no stable plugin SDK: it must be
  rebuilt against matching private source/build headers and libraries after
  Konsole upgrades. Without a compatible bridge or a fresh token from Beacon's
  own active inherited Konsole session, multiple windows retain partial exact-tab
  behavior. A full successful status means Konsole
  accepted tab selection and KWin accepted the one-shot script; KWin does not
  return compositor confirmation that activation occurred. A partial status
  means only exact Konsole tab selection succeeded. Focus changes no OpenCode
  route or execution state.
- Kitty focus requires a modern compatible `kitten` executable on `PATH`, a
  restarted Kitty instance with an absolute filesystem Unix remote-control
  listener, and newly launched TUI children that inherited `KITTY_PID`,
  `KITTY_WINDOW_ID`, and `KITTY_LISTEN_ON`. Beacon deliberately rejects TCP,
  abstract, relative, and inherited-FD endpoints. It validates same-UID process,
  network/mount namespace, listening socket-object inode, descriptor ownership,
  and filesystem identity, but those procfs and pathname observations are not
  atomic. A newer `kitten` client can be rejected by an older Kitty server.
  Successful `focus-window` response confirms Kitty accepted the exact internal
  window/tab operation and requested OS-window focus, not that an X11 window
  manager or Wayland compositor granted foreground activation.
  The optional exact-activation bridge is tested against Kitty 0.45. It uses
  documented custom-kitten and authorization loading but the internal Python
  `Boss.set_active_window(..., activation_token=...)` API is not stable. Other
  Kitty minor versions deliberately fail closed to ordinary `focus-window`.
  Exact bridge activation additionally requires a fresh XDG token; Beacon
  currently obtains one only from its own active inherited Konsole session when
  that session exposes the validated activation-cookie API. Without that source,
  fallback selection remains subject to compositor focus-stealing policy.
- Claude focus inherits the Konsole and Kitty limitations above and additionally
  depends on readable bounded `/proc/<pid>/environ`, stable same-UID PID/starttime
  and TTY evidence, and exact Claude process classification. Environment or PID
  changes between samples remove or invalidate focus; procfs revalidation is
  repeated at Enter but remains non-atomic under the same-UID trust model.
- Dashboard exact busy duration begins with Beacon's latest observed non-busy
  state, not the start of work inside OpenCode. An initially busy root instead
  shows how long Beacon has observed it busy as a lower bound (`> Nm`).
  Disconnect duration is deliberately excluded while state is uncertain, and
  the compact display saturates at `9999999m`.
- Dashboard memory accounting requires a readable Linux cgroup-v2 unified
  hierarchy mounted at `/sys/fs/cgroup`, readable procfs starttime/cgroup files,
  and the `memory` controller files. It does not support cgroup v1 or alternate
  mount locations. `memory.peak` is optional; other missing or malformed values
  make a sample unavailable rather than zero.
- A cgroup total can include processes other than one direct procfs instance. Device/inode sharing
  among retained direct TUIs is detected and labeled, but an unrelated process
  in the same scope cannot be attributed separately. Procfs and cgroup reads are
  not atomic; repeated starttime checks reject ordinary PID reuse but cannot
  eliminate every exit, migration, or namespace race. Memory history is
  process-local, bounded to two hours, and is not persisted.
- Managed v2 service cgroup memory is intentionally not shown as TUI memory;
  managed attachment rows display `N/A` rather than misattribute the shared
  service process. Standalone v2 remains eligible for direct procfs accounting.
- RAII restores raw/alternate-screen/cursor/mouse state on catchable paths.
  `SIGKILL`, power loss, terminal failure, or process abort cannot run cleanup.
- There are no notifications, persisted acknowledgements, OpenCode session controls,
  port scans, remote endpoints, GUI, web UI, or `/global/event` support.

Future platform discovery backends and notification consumers can reuse
`BeaconEvent` without changing the transport/state contract.
