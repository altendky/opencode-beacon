# OpenCode Beacon Kitty Bridge

These dependency-free Python files provide protocol-version-2 activation-token
source and exact OS-window target support for Kitty 0.45:

- `opencode_beacon_focus.py` is a no-UI custom kitten that can request a fresh
  token from Beacon's exact active source pane or apply one to an exact target.
- `opencode_beacon_rc_auth.py` authorizes only that kitten's exact bounded
  source/target payloads. It does not authorize arbitrary kittens.

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
and source-token callback use internal Python APIs. Unsupported Kitty versions
fail closed to Beacon's ordinary target focus behavior and the next source
provider.

Run its dependency-free policy tests with:

```console
python3 -m unittest discover -s kitty-extension/tests -v
```
