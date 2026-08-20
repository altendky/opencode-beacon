# Kitty Focus

Beacon can focus a confidently attached OpenCode TUI in Kitty through Kitty's
official remote-control interface. It selects the exact Kitty window, which also
selects its tab and requests focus for the containing OS window. No Kitty plugin,
shell integration, KDE component, or compositor utility is required.

## Configuration

Use a private absolute filesystem Unix socket and authorize only the
no-password `focus-window` action plus the exact Beacon bridge checker:

```conf
allow_remote_control password
listen_on unix:${XDG_RUNTIME_DIR}/kitty-beacon-{kitty_pid}
remote_control_password "" focus-window opencode_beacon_rc_auth.py
```

For exact OS-window activation, first install the bridge and checker from the
repository root:

```console
config_dir="${XDG_CONFIG_HOME:-$HOME/.config}/kitty"
install -d -m 700 "$config_dir"
install -m 600 kitty-extension/opencode_beacon_focus.py \
  kitty-extension/opencode_beacon_rc_auth.py "$config_dir/"
```

Do not replace the checker filename with the `kitten` command in
`remote_control_password`. Authorizing `kitten` by name would permit arbitrary
custom Python execution inside Kitty. The checker instead accepts only the exact
fixed bridge filename, socket transport, positive matched window ID, protocol
version, source/target operation, private callback, nonce, and bounded activation
token.

Restart Kitty after changing this startup configuration, then launch the
OpenCode TUI inside the restarted instance. Kitty sets `KITTY_PID` and, when the
listener exists, `KITTY_LISTEN_ON` in child environments; it also provides the
current `KITTY_WINDOW_ID`. Beacon must observe all three on the eligible TUI.

The socket should remain beneath the user's private, same-UID, mode-0700
`XDG_RUNTIME_DIR`. Kitty creates the socket with permissions derived from its
launch-time umask, so modes such as 0755 or 0775 are normal. Beacon accepts a
group/other-writable socket there because other users cannot traverse the private
directory. Outside such a private path, the socket itself must not be
group/other writable. In every case it must be owned by the current user,
canonical, and held as the unique listening socket by the retained Kitty
process. Beacon does not support TCP, abstract, relative, or `fd:`
remote-control addresses.

The `password` mode and empty password above do not give Beacon a secret. They
allow Kitty to authorize only plaintext requests accepted by the action list or
checker. Beacon
passes `--use-password=never`, never reads `KITTY_RC_PASSWORD`, and removes
ambient Kitty password/public-key variables from the child command. Do not
substitute `socket-only` unless broad remote-control access for every process
that can reach the socket is intentional.

## Runtime

The `kitten` executable from a compatible Kitty installation must be on
Beacon's `PATH`. Fine-grained remote-control authorization requires Kitty 0.26.0
or newer. Kitty rejects a remote-control client whose major/minor version is
newer than the server, so install the client and terminal from the same package
where possible.

At Enter, Beacon revalidates the OpenCode and Kitty process starttimes, effective
UID, network and mount namespaces, inherited identifiers, filesystem socket,
Kitty listener row, and owning descriptor. It then invokes the equivalent of:

```console
kitten @ --to unix:/absolute/socket --use-password=never \
  focus-window --match id:WINDOW_ID
```

The argument vector is fixed and no shell is used. Missing, changed,
unauthorized, unsupported, or stale targets produce dashboard no-op/error status
without changing OpenCode state.

Before target fallback, Beacon sends a side-effect-free protocol-version-2 probe
directly over the validated socket. On Kitty 0.45, the installed no-UI kitten
feature-detects source and target internal APIs. A target-neutral broker first
checks whether Beacon itself inherited complete Kitty identifiers. It validates
that Kitty process and listener exactly like a target, then asks the exact
inherited pane to prove it is still active in the compositor-focused Kitty OS
window. Kitty asynchronously requests a token using that surface and recent
input serial. The callback rechecks focus and sends one bounded nonce-bound
datagram to a temporary mode-0600 socket under mode-0700 `XDG_RUNTIME_DIR`.
Beacon closes and unlinks the callback socket, revalidates source and target, and
passes the one-use token to the exact target bridge. If the Kitty source is
missing, inactive, incompatible, stale, or timed out, the broker tries Beacon's
inherited Konsole activation-cookie API. Either source token can activate an
exact Kitty or Konsole target, including different Kitty processes on the same
compositor. Tokens never enter child arguments, environment, files, bridge
responses, logs, status, or retained state.

The bridge is deliberately version-coupled because Kitty documents custom
kittens but not its internal `Boss` API. Unsupported Kitty minor versions,
missing files/checker configuration, unavailable source tokens, and bridge
failures fall back to ordinary `focus-window`. The dashboard reports that partial
pane selection without claiming compositor activation. The extension does not
weaken Kitty's behavior when no compatible source is available.

Kitty reports acceptance of the internal selection and focus request, not a
compositor acknowledgement. X11 focus-stealing policy or Wayland activation
rules can leave the OS window in the background even after its exact Kitty
window and tab were selected.

See Kitty's official [remote-control documentation][remote],
[protocol specification][protocol], and [`allow_remote_control` configuration][config].

[remote]: https://sw.kovidgoyal.net/kitty/remote-control/
[protocol]: https://sw.kovidgoyal.net/kitty/rc_protocol/
[config]: https://sw.kovidgoyal.net/kitty/conf/#opt-kitty.allow_remote_control
