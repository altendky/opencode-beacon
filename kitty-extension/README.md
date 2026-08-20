# OpenCode Beacon Kitty Bridge

These dependency-free Python files provide protocol-version-1 exact Kitty
OS-window activation for Kitty 0.45:

- `opencode_beacon_focus.py` is a no-UI custom kitten that runs inside the
  target Kitty process.
- `opencode_beacon_rc_auth.py` authorizes only that kitten's exact bounded
  probe and activation payloads. It does not authorize arbitrary kittens.

Install them in Kitty's configuration directory:

```console
config_dir="${XDG_CONFIG_HOME:-$HOME/.config}/kitty"
install -d -m 700 "$config_dir"
install -m 600 kitty-extension/opencode_beacon_focus.py \
  kitty-extension/opencode_beacon_rc_auth.py "$config_dir/"
```

Then use the configuration and restart instructions in the
[Kitty Focus guide](../docs/src/project/kitty-focus.md). The bridge uses Kitty's
documented custom-kitten and authorization mechanisms, but its activation call
is an internal Python API. Unsupported Kitty versions fail closed to Beacon's
ordinary `focus-window` behavior.

Run its dependency-free policy tests with:

```console
python3 -m unittest discover -s kitty-extension/tests -v
```
