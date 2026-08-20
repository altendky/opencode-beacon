# SPDX-License-Identifier: MIT OR Apache-2.0
import contextlib
import io
import json
import os
import runpy
import socket
import sys
import tempfile
import types
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def load_bridge():
    kittens = types.ModuleType("kittens")
    tui = types.ModuleType("kittens.tui")
    handler = types.ModuleType("kittens.tui.handler")

    def result_handler(**options):
        def decorate(function):
            function.no_ui = options.get("no_ui", False)
            return function

        return decorate

    handler.result_handler = result_handler
    kitty = types.ModuleType("kitty")
    constants = types.ModuleType("kitty.constants")
    constants.version = (0, 45, 0)
    constants.is_wayland = lambda: True
    fast_data_types = types.ModuleType("kitty.fast_data_types")
    fast_data_types.focused_os_window_id = 11
    fast_data_types.callbacks = []
    fast_data_types.request_ok = True

    def current_focused_os_window_id():
        return fast_data_types.focused_os_window_id

    def run_with_activation_token(callback):
        fast_data_types.callbacks.append(callback)
        return fast_data_types.request_ok

    fast_data_types.current_focused_os_window_id = current_focused_os_window_id
    fast_data_types.run_with_activation_token = run_with_activation_token
    modules = {
        "kittens": kittens,
        "kittens.tui": tui,
        "kittens.tui.handler": handler,
        "kitty": kitty,
        "kitty.constants": constants,
        "kitty.fast_data_types": fast_data_types,
    }
    previous = {name: sys.modules.get(name) for name in modules}
    sys.modules.update(modules)
    try:
        return runpy.run_path(ROOT / "opencode_beacon_focus.py"), fast_data_types
    finally:
        for name, old in previous.items():
            if old is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = old


class FakeWindow:
    os_window_id = 11


class FakeBoss:
    def __init__(self):
        self.window_id_map = {7: FakeWindow()}
        self.active_window = self.window_id_map[7]
        self.calls = []

    def set_active_window(
        self,
        window,
        switch_os_window_if_needed=False,
        for_keep_focus=False,
        activation_token="",
    ):
        self.calls.append(
            (window, switch_os_window_if_needed, for_keep_focus, activation_token)
        )
        return 11


@contextlib.contextmanager
def private_callback_socket():
    old_runtime = os.environ.get("XDG_RUNTIME_DIR")
    with tempfile.TemporaryDirectory() as runtime:
        os.chmod(runtime, 0o700)
        path = os.path.join(runtime, "callback.sock")
        callback = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        callback.bind(path)
        os.chmod(path, 0o600)
        callback.settimeout(0.1)
        os.environ["XDG_RUNTIME_DIR"] = runtime
        try:
            yield callback, path
        finally:
            callback.close()
            if old_runtime is None:
                os.environ.pop("XDG_RUNTIME_DIR", None)
            else:
                os.environ["XDG_RUNTIME_DIR"] = old_runtime


class BridgeTests(unittest.TestCase):
    def test_target_probe_and_exact_activation(self):
        bridge, _ = load_bridge()
        boss = FakeBoss()
        handle = bridge["handle_result"]

        self.assertTrue(handle.no_ui)
        self.assertEqual(
            handle(["bridge", "probe-target", "2", "7"], None, 7, boss),
            bridge["TARGET_PROBE_OK"],
        )
        self.assertEqual(
            handle(
                ["bridge", "activate", "2", "7", "fresh-token"],
                None,
                7,
                boss,
            ),
            bridge["ACTIVATE_OK"],
        )
        self.assertEqual(
            boss.calls,
            [(boss.window_id_map[7], True, False, "fresh-token")],
        )

    def test_source_token_requires_exact_active_source_and_revalidates_callback(self):
        bridge, fast = load_bridge()
        boss = FakeBoss()
        handle = bridge["handle_result"]
        nonce = "a" * 64
        with private_callback_socket() as (callback, path):
            self.assertEqual(
                handle(["bridge", "probe-source", "2", "7"], None, 7, boss),
                bridge["SOURCE_PROBE_OK"],
            )
            self.assertEqual(
                handle(
                    ["bridge", "source-token", "2", "7", path, nonce],
                    None,
                    7,
                    boss,
                ),
                bridge["SOURCE_REQUESTED"],
            )
            self.assertEqual(len(fast.callbacks), 1)
            fast.callbacks.pop()("fresh-token")
            response = json.loads(callback.recv(8192))
            self.assertEqual(
                response,
                {"version": 2, "nonce": nonce, "token": "fresh-token"},
            )

            handle(
                ["bridge", "source-token", "2", "7", path, nonce],
                None,
                7,
                boss,
            )
            fast.focused_os_window_id = 12
            fast.callbacks.pop()("unused-token")
            with self.assertRaises(TimeoutError):
                callback.recv(8192)

    def test_invalid_or_incompatible_requests_fail_closed_without_output(self):
        bridge, fast = load_bridge()
        boss = FakeBoss()
        handle = bridge["handle_result"]
        output = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            self.assertEqual(
                handle(["bridge", "activate", "2", "8", "fresh-token"], None, 7, boss),
                bridge["UNSUPPORTED"],
            )
            self.assertEqual(
                handle(["bridge", "activate", "2", "7", "bad\ntoken"], None, 7, boss),
                bridge["UNSUPPORTED"],
            )
            fast.focused_os_window_id = 12
            self.assertEqual(
                handle(["bridge", "probe-source", "2", "7"], None, 7, boss),
                bridge["UNSUPPORTED"],
            )
            handle.__globals__["kitty_version"] = (0, 46, 0)
            self.assertEqual(
                handle(["bridge", "probe-target", "2", "7"], None, 7, boss),
                bridge["UNSUPPORTED"],
            )
        self.assertEqual(output.getvalue(), "")
        self.assertEqual(boss.calls, [])

    def test_authorizer_allows_only_exact_bridge_payloads(self):
        auth = runpy.run_path(ROOT / "opencode_beacon_rc_auth.py")
        allowed = auth["is_cmd_allowed"]
        base = {
            "cmd": "kitten",
            "version": [0, 45, 0],
            "no_response": False,
            "payload": {
                "kitten": "opencode_beacon_focus.py",
                "args": ["probe-target", "2", "7"],
                "match": "id:7",
            },
        }
        activate = {
            **base,
            "payload": {
                **base["payload"],
                "args": ["activate", "2", "7", "fresh-token"],
            },
        }
        with private_callback_socket() as (_, path):
            source = {
                **base,
                "payload": {
                    **base["payload"],
                    "args": ["source-token", "2", "7", path, "a" * 64],
                },
            }
            self.assertTrue(allowed(base, None, True, {}))
            self.assertTrue(allowed(activate, None, True, {}))
            self.assertTrue(allowed(source, None, True, {}))
            os.chmod(os.environ["XDG_RUNTIME_DIR"], 0o755)
            self.assertFalse(allowed(source, None, True, {}))
            os.chmod(os.environ["XDG_RUNTIME_DIR"], 0o700)
            self.assertIsNone(allowed({"cmd": "focus-window"}, None, True, {}))
            self.assertFalse(allowed(base, None, False, {}))
            for changed in (
                {**base, "payload": {**base["payload"], "kitten": "other.py"}},
                {**base, "payload": {**base["payload"], "match": "id:8"}},
                {**base, "payload": {**base["payload"], "extra": True}},
                {**base, "no_response": True},
                {**base, "extra": True},
                {
                    **activate,
                    "payload": {
                        **activate["payload"],
                        "args": ["activate", "2", "7", "bad\ntoken"],
                    },
                },
                {
                    **source,
                    "payload": {
                        **source["payload"],
                        "args": ["source-token", "2", "7", path, "bad"],
                    },
                },
            ):
                self.assertFalse(allowed(changed, None, True, {}))


if __name__ == "__main__":
    unittest.main()
