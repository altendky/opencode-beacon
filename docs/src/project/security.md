# Security

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
strict bounded Konsole D-Bus service/session/window identifiers, and never
retains or renders the broad environment. Procfs-backed v1 uses the same bounded
extraction from its exact stable process; managed service PIDs are excluded. Attachment
evidence is never sent to OpenCode and remains display confidence, not an
authentication or authorization boundary.

Focus revalidates PID/starttime and D-Bus ownership immediately before acting.
It selects a tab only through its exact retained D-Bus window after fresh session
membership validation. All external commands use fixed argument vectors without
a shell. The generated KWin script source is repository-owned, substitutes only
a numeric Konsole owner PID, is created exclusively with mode 0600, activates
only one normal matching window, and is unloaded and deleted after use. Multiple
Konsole windows stop after exact tab selection; ambiguous compositor activation
and changed targets fail closed.
The optional bridge registers one same-UID-only D-Bus object per exact Konsole
ViewManager. It validates bounded arguments and local session membership before
selection and activation. Beacon negotiates version/capability before reading
only its own inherited activation source identifiers and cookie at Enter. Native
D-Bus keeps the cookie and fresh token out of process arguments; neither value is
logged, rendered, or retained. Target identity and membership are checked again
after asynchronous token acquisition.
If bridge negotiation or activation falls back, Beacon repeats PID/starttime,
D-Bus owner, exact window, and session membership checks immediately before tab
selection and refreshes the sole/multi-window decision from that validation.
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
