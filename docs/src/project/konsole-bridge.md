# Konsole Bridge

The optional `konsole-plugin/` module enables exact activation when one Konsole
process owns multiple native windows. It is separate from the Cargo package and
release. Beacon works without it, using exact tab selection and the existing
sole-window KWin fallback.

## Compatibility

Konsole does not publish a stable plugin SDK or install plugin development
headers. The bridge uses the exported but private `IKonsolePlugin`, `MainWindow`,
and `ViewManager` ABI. Konsole 25.12.3 also requires plugin metadata to match its
25.12 major/minor release. Build against the exact source and configured build
tree for the installed Konsole, and rebuild after every Konsole upgrade. A future
upstream Konsole D-Bus API can replace this module.

Ubuntu 26.04's installed Konsole 25.12.3 package provides the versioned runtime
libraries and plugins, but no matching headers. A full build therefore requires
matching Konsole source, its generated build headers, Qt 6 and Qt Test
development files, Extra CMake Modules, and KDE Frameworks 6 CoreAddons, I18n,
and XmlGui development files.

## Build

Configure the matching Konsole source once so generated headers exist. Library
paths may refer either to that exact build or exact matching installed libraries.

```console
git clone --branch v25.12.3 --depth 1 https://invent.kde.org/utilities/konsole.git konsole-25.12.3
cmake -S konsole-25.12.3 -B konsole-25.12.3-build -G Ninja -DBUILD_TESTING=OFF
cmake -S konsole-plugin -B konsole-plugin-build -G Ninja \
  -DKONSOLE_SOURCE_DIR="$PWD/konsole-25.12.3" \
  -DKONSOLE_BUILD_DIR="$PWD/konsole-25.12.3-build" \
  -DKONSOLE_APP_LIBRARY=/usr/lib/x86_64-linux-gnu/libkonsoleapp.so.25.12.3 \
  -DKONSOLE_PRIVATE_LIBRARY=/usr/lib/x86_64-linux-gnu/libkonsoleprivate.so.25.12.3
cmake --build konsole-plugin-build
ctest --test-dir konsole-plugin-build --output-on-failure
```

Configuration derives plugin metadata from `config-konsole.h`, verifies that the
build tree was generated from the supplied source tree, and requires both
library paths to resolve to versioned files for that derived release. The
release version is intentionally not a user override.

Dependency-light argument and object-path policy tests do not require Konsole or
KDE Frameworks development headers:

```console
cmake -S konsole-plugin -B konsole-plugin-policy-build -G Ninja \
  -DBEACON_BRIDGE_POLICY_ONLY=ON
cmake --build konsole-plugin-policy-build
ctest --test-dir konsole-plugin-policy-build --output-on-failure
```

## Install

Install only after inspecting the build and closing Konsole normally. Automated
verification does not install the module or restart a live Konsole.

```console
cmake --install konsole-plugin-build --prefix "$HOME/.local"
```

Konsole discovers plugins beneath Qt's library paths. On Debian/Ubuntu
multiarch, this build installs beneath
`$HOME/.local/lib/x86_64-linux-gnu/qt6/plugins/konsoleplugins`; other systems may
use `$HOME/.local/lib/qt6/plugins/konsoleplugins`. If the parent of
`konsoleplugins/` is outside the path printed by `qtpaths6 --plugin-dir`, add
that exact parent to `QT_PLUGIN_PATH` before starting Konsole. Configure output
and `cmake_install.cmake` are authoritative.

Each exact window endpoint uses:

```text
/org/altendky/OpenCodeBeacon/KonsoleActivationBridge/v1/Windows/N
org.altendky.OpenCodeBeacon.KonsoleActivationBridge1
```

## Uninstall

Use the same build directory so its exact install manifest is applied, then
restart Konsole normally:

```console
cmake --build konsole-plugin-build --target uninstall
```

## Security

The bridge exposes protocol version 1 and only the
`activate-session-with-xdg-token` capability. Its atomic method accepts a
positive local session ID and a bounded printable activation token. The object
is tied to one `ViewManager`; it rejects sessions not currently owned by that
manager, verifies selection, and emits activation only on that exact manager.
It accepts calls only from the same effective UID on the session bus. Object
registration is removed with the owning window.

Selection resolves the requested session within that manager's actual tab
container, selects and verifies the owning tab, and only then requests focus for
the terminal display. It does not use Konsole's focus-controller-based
`currentSession()` as selection evidence, because that value can remain stale
for a hidden tab in an inactive window.

Beacon reads only its own inherited `KONSOLE_DBUS_SERVICE`,
`KONSOLE_DBUS_SESSION`, and `KONSOLE_DBUS_ACTIVATION_COOKIE` at Enter. It sends
the cookie through native D-Bus rather than a process argument, never logs or
retains it, and rejects missing, malformed, empty, or oversized results. A fresh
token is requested only after capability negotiation and is used only after
target process, D-Bus owner, window, and session revalidation.
Any fallback after bridge attempts repeats that complete target validation and
refreshes the window count immediately before selecting the tab.

The C++ suite verifies strict arguments, hidden/inactive local-session selection
and activation ordering, synchronous plugin-owned object destruction,
owner-removal cleanup, metadata, dynamic loading, and real `IKonsolePlugin`
construction against the installed ABI. Registering a bridge on a real
MainWindow, checking the caller UID through an actual bridge method call, and
observing Wayland activation require a restarted Konsole and remain part of the
explicit live acceptance step.
