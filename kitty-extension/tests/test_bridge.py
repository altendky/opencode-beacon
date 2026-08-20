# SPDX-License-Identifier: MIT OR Apache-2.0
import contextlib
import io
import runpy
import sys
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
    modules = {
        "kittens": kittens,
        "kittens.tui": tui,
        "kittens.tui.handler": handler,
        "kitty": kitty,
        "kitty.constants": constants,
    }
    previous = {name: sys.modules.get(name) for name in modules}
    sys.modules.update(modules)
    try:
        return runpy.run_path(ROOT / "opencode_beacon_focus.py")
    finally:
        for name, old in previous.items():
            if old is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = old


class FakeBoss:
    def __init__(self):
        self.window_id_map = {7: object()}
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


class BridgeTests(unittest.TestCase):
    def test_probe_and_exact_activation(self):
        bridge = load_bridge()
        boss = FakeBoss()
        handle = bridge["handle_result"]

        self.assertTrue(handle.no_ui)
        self.assertEqual(
            handle(["bridge", "probe", "1", "7"], None, 7, boss),
            bridge["PROBE_OK"],
        )
        self.assertEqual(
            handle(
                ["bridge", "activate", "1", "7", "fresh-token"],
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

    def test_invalid_or_incompatible_requests_fail_closed_without_output(self):
        bridge = load_bridge()
        boss = FakeBoss()
        handle = bridge["handle_result"]
        output = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            self.assertEqual(
                handle(["bridge", "activate", "1", "8", "fresh-token"], None, 7, boss),
                bridge["UNSUPPORTED"],
            )
            self.assertEqual(
                handle(["bridge", "activate", "1", "7", "bad\ntoken"], None, 7, boss),
                bridge["UNSUPPORTED"],
            )
            handle.__globals__["kitty_version"] = (0, 46, 0)
            self.assertEqual(
                handle(["bridge", "probe", "1", "7"], None, 7, boss),
                bridge["UNSUPPORTED"],
            )
        self.assertEqual(output.getvalue(), "")
        self.assertEqual(boss.calls, [])

    def test_authorizer_allows_only_exact_bridge_payload(self):
        auth = runpy.run_path(ROOT / "opencode_beacon_rc_auth.py")
        allowed = auth["is_cmd_allowed"]
        probe = {
            "cmd": "kitten",
            "version": [0, 45, 0],
            "no_response": False,
            "payload": {
                "kitten": "opencode_beacon_focus.py",
                "args": ["probe", "1", "7"],
                "match": "id:7",
            },
        }
        activate = {
            "cmd": "kitten",
            "version": [0, 45, 0],
            "no_response": False,
            "payload": {
                "kitten": "opencode_beacon_focus.py",
                "args": ["activate", "1", "7", "fresh-token"],
                "match": "id:7",
            },
        }

        self.assertTrue(allowed(probe, None, True, {}))
        self.assertTrue(allowed(activate, None, True, {}))
        self.assertIsNone(allowed({"cmd": "focus-window"}, None, True, {}))
        self.assertFalse(allowed(probe, None, False, {}))
        for changed in (
            {**probe, "payload": {**probe["payload"], "kitten": "other.py"}},
            {**probe, "payload": {**probe["payload"], "match": "id:8"}},
            {**probe, "payload": {**probe["payload"], "extra": True}},
            {**probe, "no_response": True},
            {**probe, "extra": True},
            {
                **activate,
                "payload": {
                    **activate["payload"],
                    "args": ["activate", "1", "7", "bad\ntoken"],
                },
            },
        ):
            self.assertFalse(allowed(changed, None, True, {}))


if __name__ == "__main__":
    unittest.main()
