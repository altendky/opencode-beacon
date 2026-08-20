# Development

Install reproducible tools and run all checks:

```console
mise install --locked
cargo fmt --all --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo nextest run --locked --all-features
cargo test --locked --doc --all-features
cargo deny check
mdbook build docs
mdbook test docs
pre-commit run --show-diff-on-failure --all-files
pre-commit run --hook-stage manual --all-files
cargo package --locked
version="$(cargo metadata --no-deps --format-version=1 | jq -r '.packages[0].version')"
package_dir="$(mktemp -d)"
trap 'rm -rf "$package_dir"' EXIT
tar -xzf "target/package/opencode-beacon-${version}.crate" -C "$package_dir"
manifest="${package_dir}/opencode-beacon-${version}/Cargo.toml"
cargo test --manifest-path "$manifest" --locked --all-features
cargo test --manifest-path "$manifest" --locked --doc --all-features
cargo build --release --locked
target/release/opencode-beacon --version
```

`cargo package --locked` is intentionally run without `--allow-dirty`. A dirty
tracked worktree is a known package-verification block; run packaging from a
clean checkout rather than substituting `--allow-dirty`.

Focused listener-gate verification:

```console
cargo test --locked listener_
cargo test --locked stable_gate_skips
cargo test --locked two_completed_full_misses
cargo test --locked disconnect_records_generation
```

Tests keep protocol parsing and state reduction independent from live servers.
Use mocks for event generation, failed snapshots, backpressure, reconnect, and
session-control scenarios.
Live acceptance against existing user sessions must remain observational;
skip any step that would create, mutate, answer, reject, abort, or otherwise
control those sessions.
Bounded watch acceptance should capture stdout and stderr separately, verify no
default startup stdout, verify the single opt-in `--header`, and report only
formatting/count metadata rather than live titles or session identifiers.
Closing the capture pipe is a valid clean-shutdown test when an attention write
naturally follows; a quiet stream has no write on which to observe `BrokenPipe`.
Because OpenCode currently has a confirmed cleanup bug around repeated real TUI
`/event` disconnects, live acceptance must use one persistent monitor run or an
isolated temporary TUI. Do not repeatedly connect and disconnect existing real
TUI event streams.

Dashboard tests use the pure model and `ratatouille::backend::TestBackend` for admission,
grouped title/session ordering, metadata-driven reorder, stable unrelated updates,
selection preservation/scroll, aggregation, exact foreground/background/modifier
styles, Right dismissal/Left restoration and feedback, unbound legacy keys,
dismissal occurrences, left/right attention alignment without a checkmark,
monotonic exact and lower-bound busy elapsed boundaries, stale freezing,
fixed-column alignment, saturation, and
one-shot timer deadline/no-idle-wakeup behavior.
Synthetic cgroup tests cover proc stat, unified cgroup and memory.stat parsing,
canonical path escape rejection, device/inode deduplication, PID starttime
change, optional peak, bounded 30-minute slope history, shared rendering,
`N/A`/stale rendering, disconnect retention, and removal/replacement purge.
Synthetic v2 attachment tests cover ESTABLISHED client-row parsing, same-UID and
network-namespace FD correlation, stable starttime/TTY checks, full/mini versus
noninteractive argv classification, socket deduplication, explicit/continue/
location resolution, reciprocal one-to-one active matching, both collision
directions, descendant-active root matching, sticky idle retention,
process/session/instance clearing, two-miss
removal, failed-scan retention, and attached-idle/headless dashboard separation.
Synthetic standalone tests cover exact stdio classification, private credential
recovery, authenticated health PID identity, v2 dashboard admission, and direct
cgroup memory classification.
V1 dashboard admission remains a dedicated-endpoint regression case.
V2 root-state tests independently cover initially quiescent dismissible ready,
root busy/retry,
background-only, foreground plus background count, nested descendants, child
completion, child retry/attention priority, headless background roots, and
unresolved attachment rows without invented activity.
Focus tests cover strict bounded Konsole service/session/window and Kitty
process/window/listener environment extraction, confident Enter actions, and safe
missing/headless/unresolved/ambiguous/stale no-ops. A mocked fixed-argument D-Bus
sequence verifies that multi-window focus selects the exact retained tab and
never invokes KWin activation. Live KDE
acceptance must use fixed D-Bus arguments, must not alter OpenCode state, and
should verify tab selection plus KWin activation using an isolated or already
selected test tab.
Bridge tests additionally cover protocol/capability negotiation before source
cookie access, native token acquisition, post-token target revalidation, atomic
call ordering, fallback on absent/old/failing bridges or unavailable tokens, and
cookie/token exclusion from command arguments and debug output. Build the
dependency-light C++ policy tests with the commands in the Konsole Bridge page.
Full plugin verification requires exact matching Konsole source/build headers,
libraries, and KDE Frameworks development packages.
Its non-live tests cover selection-before-activation ordering, fail-closed local
membership, synchronous plugin-owned bridge destruction, MainWindow-removal
cleanup, metadata, dynamic loading, and real plugin ABI construction. Actual
per-window D-Bus registration, caller-UID rejection, and compositor activation
remain explicit post-install acceptance checks because they require a live
restarted Konsole MainWindow.
Synthetic Kitty tests cover malformed/conflicting/unsupported inherited
identifiers, nested-terminal precedence, same-UID PID/starttime and namespace
validation, exact listening `/proc/net/unix` row and descriptor correlation,
mode-0775 sockets beneath a same-UID private ancestor, rejection of reachable
group/other-writable sockets, socket replacement, fixed `kitten` arguments,
disabled ambient password use, no-match and unavailable-client handling, and
stale pre-command rejection. Live Kitty acceptance must use an isolated instance
with the least-privilege policy from the Kitty Focus page and separately observe
exact pane/tab selection versus best-effort compositor activation.
Kitty bridge tests additionally cover exact custom authorization, rejection of
arbitrary kitten execution and mismatched IDs, no-UI target resolution, Kitty
minor-version feature detection, probe-before-token ordering, token exclusion
from child arguments/debug output, bounded direct protocol framing, post-token
target revalidation, exact activation, and safe fallback. Run the extension
policy tests with:

```console
python3 -m unittest discover -s kitty-extension/tests -v
```

Test TTY/TERM and terminal-guard seams independently. A bounded PTY smoke test
may use one isolated temporary source, exercise resize plus `q`, Ctrl-C, and an
error, then verify terminal restoration and no child processes. Never cycle real
user TUI SSE connections for dashboard acceptance.
