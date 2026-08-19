# Discovery

## Procfs Listeners

Discovery reads `/proc/self/net/tcp` and `/proc/self/net/tcp6`, selecting TCP
listeners on loopback or wildcard addresses.
It correlates socket inodes with `/proc/<pid>/fd` only for processes whose UID
and `/proc/<pid>/ns/net` identity match the current process.
The process namespace is read before the file-descriptor walk and again before
the matches are committed, so inherited descriptors from a process already in
another namespace and namespace changes observed during traversal are not
accepted.
Inaccessible, different, or changed process namespace links produce diagnostics
and skip that process.
Probes are limited to processes whose executable, command line, or name
identifies OpenCode.

After socket and network-namespace correlation, discovery walks each candidate
owner's Linux procfs parent chain. It excludes the listener only when an
ancestor's exact `/proc/<pid>/exe` basename is `opencode-orchestrator-mcp`, using
the exact `argv[0]` basename from `/proc/<pid>/cmdline` only when the executable
link is unavailable. It does not use truncated `comm` values, substring
matching, later arguments, or process environments for this policy.

The ancestry decision records PPIDs and process start times and validates them
again before exclusion. Missing, unreadable, malformed, cyclic, disappearing,
reparented, or reused-PID observations retain the candidate because they do not
provide stable positive identification.

Wildcard IPv4 listeners are contacted through `127.0.0.1`; wildcard IPv6
listeners use `::1`.
`GET /global/health` is the definitive v1 OpenCode probe.
Socket inode, PID, address, and network-namespace inode form the local instance
identity because the health response has no server identifier.

An exact `serve --stdio` listener owner is classified as v2 standalone before
probing. Beacon reads its bounded process environment, retains only the exact
`OPENCODE_PASSWORD` entry, authenticates `/api/health` as `opencode`, and requires
the health PID to equal the socket owner. Process identity is checked around
credential inspection. Missing credentials or any mismatch rejects the candidate
without falling back to a v1 probe.

## Listener-Table Gate

Continuous monitoring starts with a full discovery pass. Subsequent default
one-second checks read only both `/proc/self/net/tcp{,6}` files and fingerprint
eligible current-UID LISTEN rows by bound address, port, and socket inode. The
fingerprint is order-independent. Unrelated UIDs, non-LISTEN rows, and non-local
bindings do not affect it. IPv4 and IPv6 loopback and wildcard rows do.

An unchanged fingerprint avoids process, descriptor, namespace, ancestry, and
health traversal entirely. Additions, removals, inode replacements, read or
parse uncertainty, manual resync, SSE disconnect, and the default five-minute
full-verification interval enter the existing full correlation and health path.
Gate errors fail toward full discovery.

When eligible rows exist at startup, and after a later listener-table change,
completed full passes are followed at 250 ms, 1 second, and 3 seconds. The finite
sequence lets HTTP health settle after the kernel publishes LISTEN and supplies
a prompt second full miss for removal.
Concurrent gate, periodic, manual, and disconnect requests coalesce; a trigger
arriving during full discovery requests one follow-up, and an early unrelated
full pass does not consume a later settling deadline.

## TUI Listener Prerequisite

Normal OpenCode TUIs otherwise run without a TCP listener. On the deployment
system, launch ordinary TUIs through `o`; its TUI-only defaults are `--hostname
127.0.0.1 --port 0 --no-mdns`, while explicit network options pass through and
registered non-TUI subcommands are unchanged. This creates a loopback-only
listener on an available per-process port without mDNS advertising. Existing
TUIs must be restarted through the wrapper before discovery can see them.

This retains direct TUI listeners and manually launched `opencode serve`
listeners while pruning positively identified descendants of
`opencode-orchestrator-mcp`.

## V2 Managed Services

Managed v2 discovery is observational. It scans OpenCode's state directory,
`$XDG_STATE_HOME/opencode` or `$HOME/.local/state/opencode`, for `service.json`
and channel-specific `service-*.json` registrations. It never calls OpenCode's
ensure path and never starts or controls a service.

Registrations must be bounded regular files owned by the current effective UID
with no group/other permissions. Beacon accepts only explicit loopback HTTP
origins, applies Basic authentication as `opencode:<password>` when present, and
requires `GET /api/health` to return the registered PID and, when registered, the
same version. Registration path and optional service ID, plus PID and endpoint,
form the managed instance identity.

Registration file identity, ownership, mode, size, mtime, and ctime join the
cheap gate fingerprint, so an atomic replacement or permission-only change
requests authoritative discovery. Managed and procfs results are monitored
together. A managed registration wins a collision at the same endpoint;
unrelated v1 and v2 instances coexist. Failure of one backend does not turn its
missing results into removals while the other backend continues.

## V2 Dashboard Attachment

V2 server discovery identifies transport, not which session a person is
viewing. Dashboard separately samples `/proc/self/net/tcp{,6}` for ESTABLISHED
client sockets whose peer is any validated v2 endpoint, correlates socket
inodes to stable same-UID/same-network-namespace PID descriptors, and inspects
argv, cwd, and TTY. It accepts the default full TUI and `mini`, including
`--standalone`, and rejects known
noninteractive commands and service/Beacon processes, and deduplicates multiple
sockets from one TUI.

This is intentionally not a discovery backend or shared event. Dashboard maps a
likely TUI to projected session roots using explicit `--session`, then
`--continue` location/updated behavior, then unique location/project/root
evidence. Activity and recency only label tie-break candidates. Ambiguity remains
visible. A successful first miss marks stale, a second removes; a failed scan
retains stale evidence without advancing misses.
