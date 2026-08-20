# Security

Claude monitoring is enabled by default and can be disabled with CLI
`--no-claude` or programmatic configuration. When enabled, it reads only exact
per-PID marker names from the resolved Claude configuration directory.
Markers must be regular, current-effective-UID-owned files no larger than 64
KiB. Filename PID, JSON PID, same-UID procfs identity, exact `claude` executable
basename (or argv-zero fallback), and PID starttime are validated around the
read. Final marker opens reject symlinks and raced special files, and marker
identity plus change metadata remain stable through the bounded read. Proc stat,
status, and the argv fallback are separately bounded. Procfs and marker
inspection are not atomic and same-UID processes remain trusted local principals.

Only PID/starttime, bounded session ID, absolute cwd, bounded optional name, and
normalized status are retained. Marker `waitingFor`, unknown fields, and file
contents are discarded. Beacon never opens Claude transcripts, process
environments outside the dashboard focus-evidence exception below, daemon logs,
or background-job state; never installs hooks or changes settings; never invokes
the Claude CLI or session-control commands; and makes no Claude-provider network
request. Cwd, name, and session ID remain sensitive even after terminal-control
sanitization.

Only loopback HTTP endpoints are constructed.
Redirects are disabled so Basic credentials cannot be forwarded.
V1 passwords come from Beacon's configured environment variable. Managed v2
passwords come from validated private registrations. Standalone v2 passwords
come only from the verified listener process's exact `OPENCODE_PASSWORD` entry.
All are wrapped as secrets and never included in diagnostics or lifecycle events.

Automatic discovery treats current-UID processes in the current network
namespace as trusted local principals.
Any listener that qualifies through a same-UID procfs TCP row, same-UID OpenCode
process ownership, matching `/proc/<pid>/ns/net` identity, loopback/wildcard
binding, and `/global/health` probing may receive the single configured Basic
credential.
Users must not configure shared credentials if they do not trust every process
running under their UID in that namespace.

For an exact `serve --stdio` socket owner, discovery reads a bounded
`/proc/<pid>/environ`, discards every entry except `OPENCODE_PASSWORD`, and checks
stable process identity before using it. It sends that credential only to the
owner's loopback socket and accepts the v2 server only when `/api/health` reports
the same PID. Environment contents and credentials are never rendered.

Managed registrations must be regular, bounded, current-UID-owned files with no
group/other permission bits. Their URLs must be uncredentialed loopback HTTP
origins. Beacon authenticates as `opencode`, then accepts the service only when
`/api/health` matches the registration PID and optional version. Registration
reads do not invoke service ensure/spawn behavior.

After any connection fails, its task does not reconnect from its cached endpoint
alone.
It retains in-memory session state but waits until a fresh discovery pass again
correlates the same `InstanceKey` with a current-UID socket owner and validates
the applicable v1 or v2 health identity.
Discovery generations are numbered before each pass starts but become eligible
verification only after successful completion.
At disconnect, the task records the latest completed generation before any
potentially backpressured output and requires a strictly newer same-key
completion.
The generation and optional key verified by that completion are published as a
single per-server value, preventing split publication from authorizing a
pre-disconnect result.
Discovery fails closed for multiple socket identities normalized to one
endpoint. A confirmed same-endpoint replacement stops the old task before the
new task starts, so endpoint-only connection and state output remains
unambiguous.

There is an unavoidable race between procfs verification and the following HTTP
connection: the listener can exit or ownership can change after verification
but before connect.
The `InstanceKey` gate narrows stale reconnect exposure but cannot make procfs
inspection and TCP connection atomic.

Discovery reads only procfs metadata needed to correlate listeners, plus the
bounded environment of exact standalone server candidates for credential recovery.
Process network-namespace identity is checked before and after its file
descriptors are inspected.
Unreadable, different, changed, or raced namespace links are diagnosed and
skipped; other unreadable or raced process entries are skipped without elevated
privileges.
Dashboard's v2 heuristic additionally reads same-UID process socket descriptors,
network namespace identity, stat/starttime/TTY, argv, and cwd. For focus it reads
at most 256 KiB of an eligible stable TUI environment, discards every entry but
strict bounded Konsole D-Bus service/session/window or Kitty
process/window/listener identifiers, and never
retains or renders the broad environment. Procfs-backed v1 uses the same bounded
extraction from its exact stable process; managed service PIDs are excluded. Attachment
evidence is never sent to OpenCode and remains display confidence, not an
authentication or authorization boundary.

Dashboard applies that same environment allowlist to an exact Claude
PID/starttime learned from provider lifecycle events. Before retaining a target,
it requires current effective UID, stable PID/starttime, nonzero TTY, and exact
`claude` executable basename or bounded argv-zero fallback around the bounded
environment read. It stores only `ClientFocusTarget` identifiers, never the broad
environment. Missing evidence produces no focus target.

Focus revalidates PID/starttime and D-Bus ownership immediately before acting.
For Claude provenance, every process revalidation also repeats effective UID,
TTY, exact process classification, and equality of freshly extracted allowlisted
identifiers. PID reuse, exec replacement, changed terminal identifiers, or an
unreadable/oversized environment fails before external commands.
It selects a tab only through its exact retained D-Bus window after fresh session
membership validation. All external commands use fixed argument vectors without
a shell. The generated KWin script source is repository-owned, substitutes only
a numeric Konsole owner PID, is created exclusively with mode 0600, activates
only one normal matching window, and is unloaded and deleted after use. Multiple
Konsole windows stop after exact tab selection; ambiguous compositor activation
and changed targets fail closed.
The optional bridge registers one same-UID-only D-Bus object per exact Konsole
ViewManager. It validates bounded arguments and local session membership before
selection and activation. Beacon negotiates target version/capability before
asking its target-neutral source broker. Native D-Bus keeps a Konsole source
cookie and fresh token out of process arguments; neither value is logged,
rendered, or retained. Target identity and membership are checked again after
asynchronous token acquisition.
If bridge negotiation or activation falls back, Beacon repeats PID/starttime,
D-Bus owner, exact window, and session membership checks immediately before tab
selection and refreshes the sole/multi-window decision from that validation.
Kitty focus accepts only canonical absolute filesystem Unix sockets. It verifies
the same-UID Kitty process and starttime in Beacon's network and mount
namespaces, correlates exactly one listening `/proc/<pid>/net/unix` row to a
Kitty-owned descriptor, and checks stable filesystem socket identity before the
fixed-argument command. A group/other-writable socket must be protected by a
same-UID private ancestor such as mode-0700 `XDG_RUNTIME_DIR`; otherwise the
socket must deny group/other writes itself. This accounts for Kitty creating
sockets according to its launch-time umask without making a publicly reachable
writable endpoint an accepted target. It does not read remote-control passwords
or public keys, removes ambient Kitty control/password variables from the child
command, and forces `--use-password=never`. The recommended Kitty policy
authorizes only the no-password `focus-window` action. Procfs and pathname checks
are repeated but remain non-atomic under the same-UID local trust model.
The optional Kitty bridge does not authorize the remote `kitten` command by
name. Its custom checker examines the complete no-password socket payload and
allows only the fixed installed bridge, exact positive match, versioned source or
target operation, private callback path, nonce, and bounded visible-ASCII token.
The trusted
no-UI handler runs inside Kitty with full internal API authority, so its files
must remain in the user's private Kitty configuration directory. For source use,
the handler requires Beacon's exact inherited pane to be active in the currently
compositor-focused Kitty OS window before and after Kitty's asynchronous token
request. Beacon accepts one strictly bounded nonce-matched datagram through a
temporary same-UID mode-0600 socket beneath validated mode-0700
`XDG_RUNTIME_DIR`, then unlinks it and revalidates source and target. The broker
tries Kitty before Konsole so stale outer-terminal inheritance cannot override
an active inner Kitty source. Tokens are one-use and absent from process
arguments, environment, files, bridge responses, logs, and status. Unsupported
versions and checker/handler errors fail closed to the next source or ordinary
target fallback.
Cancellation or event-receiver closure discards pending discovery/snapshot
results and prevents a cancelled pass from publishing credential verification.
Question and permission payload contents are not printed by default.
Derived attention retains only request and session identifiers from those
payloads; question text, permission patterns, answers, and message bodies are
excluded.

Attention CLI names use legacy session titles with slug and ID fallbacks.
OpenCode titles may summarize prompt content, so enabling the attention feed
expands output beyond the previous ID-only transition privacy surface. Consumers
must protect stdout and library events accordingly.

The watch table replaces title C0/C1 controls, tabs, CR/LF, DEL, and ESC with
spaces before writing one physical row. It emits no ANSI styling. Sanitization
prevents terminal injection but does not make the title non-sensitive; ordinary
Unicode and prompt-derived wording remain visible and untruncated.
The optional header changes only column labels; headerless and header modes
expose identical attention title content once an event occurs.

State projections expose title/slug/parent metadata, status, and identifiers for
all known sessions to library and raw-feed consumers. Titles may be
prompt-derived. Projections exclude question text, permission patterns,
messages, answers, and request payloads, but remain sensitive.

Dashboard sanitizes title controls before `ratatouille` styling. Color is limited to
the visible attention word and remains supplemental for accessibility. Local
dismissal dims and right-aligns that word, reports local status, and invokes no
control API. It adds no checkmark or background color.
