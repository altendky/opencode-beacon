#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0

import inspect
import json
import os
import socket
import stat

from kittens.tui.handler import result_handler
from kitty.constants import is_wayland, version as kitty_version
from kitty.fast_data_types import current_focused_os_window_id, run_with_activation_token

PROTOCOL_VERSION = "2"
SUPPORTED_KITTY_MINOR = (0, 45)
TARGET_PROBE_OK = "opencode-beacon-kitty-bridge/2 target-ready"
SOURCE_PROBE_OK = "opencode-beacon-kitty-bridge/2 source-ready"
SOURCE_REQUESTED = "opencode-beacon-kitty-bridge/2 source-token-requested"
ACTIVATE_OK = "opencode-beacon-kitty-bridge/2 activated"
UNSUPPORTED = "opencode-beacon-kitty-bridge/2 unsupported"
MAX_ACTIVATION_TOKEN_SIZE = 4096
MAX_CALLBACK_PATH_SIZE = 107
NONCE_SIZE = 64


def main(args):
    pass


def valid_positive_id(value):
    return (
        isinstance(value, str)
        and 0 < len(value) <= 20
        and value.isascii()
        and value.isdecimal()
        and value != "0"
    )


def valid_activation_token(value):
    return (
        isinstance(value, str)
        and 0 < len(value) <= MAX_ACTIVATION_TOKEN_SIZE
        and value.isascii()
        and all(0x21 <= ord(character) <= 0x7E for character in value)
    )


def compatible_target_boss(boss):
    if tuple(kitty_version[:2]) != SUPPORTED_KITTY_MINOR:
        return False
    method = getattr(boss, "set_active_window", None)
    if not callable(method):
        return False
    try:
        parameters = inspect.signature(method).parameters
    except (TypeError, ValueError):
        return False
    return "switch_os_window_if_needed" in parameters and "activation_token" in parameters


def compatible_source_boss(boss):
    return (
        compatible_target_boss(boss)
        and is_wayland()
        and callable(run_with_activation_token)
        and callable(current_focused_os_window_id)
    )


def exact_source_is_active(boss, window, target_window_id):
    return (
        boss.window_id_map.get(target_window_id) is window
        and boss.active_window is window
        and current_focused_os_window_id() == window.os_window_id
    )


def valid_nonce(value):
    return (
        isinstance(value, str)
        and len(value) == NONCE_SIZE
        and value.isascii()
        and all(character in "0123456789abcdef" for character in value)
    )


def valid_callback_socket(path):
    if not isinstance(path, str) or not path or len(os.fsencode(path)) > MAX_CALLBACK_PATH_SIZE:
        return False
    runtime = os.environ.get("XDG_RUNTIME_DIR", "")
    if not runtime or not os.path.isabs(path) or not os.path.isabs(runtime):
        return False
    try:
        runtime = os.path.realpath(runtime)
        if os.path.commonpath((runtime, path)) != runtime or os.path.realpath(path) != path:
            return False
        runtime_stat = os.lstat(runtime)
        socket_stat = os.lstat(path)
    except (OSError, ValueError):
        return False
    return (
        stat.S_ISDIR(runtime_stat.st_mode)
        and runtime_stat.st_uid == os.geteuid()
        and runtime_stat.st_mode & 0o077 == 0
        and stat.S_ISSOCK(socket_stat.st_mode)
        and socket_stat.st_uid == os.geteuid()
        and socket_stat.st_mode & 0o077 == 0
    )


def send_source_token(boss, window, target_window_id, callback_path, nonce, token):
    if not exact_source_is_active(boss, window, target_window_id):
        return
    if not valid_callback_socket(callback_path) or not valid_activation_token(token):
        return
    payload = json.dumps(
        {"version": 2, "nonce": nonce, "token": token},
        ensure_ascii=True,
        separators=(",", ":"),
    ).encode("ascii")
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as callback:
            callback.settimeout(0.1)
            callback.sendto(payload, callback_path)
    except OSError:
        pass


@result_handler(no_ui=True)
def handle_result(args, answer, target_window_id, boss):
    del answer
    try:
        if len(args) < 4 or args[2] != PROTOCOL_VERSION or not valid_positive_id(args[3]):
            return UNSUPPORTED
        if target_window_id != int(args[3]):
            return UNSUPPORTED
        window = boss.window_id_map.get(target_window_id)
        if window is None:
            return UNSUPPORTED
        if args[1] == "probe-target" and len(args) == 4:
            return TARGET_PROBE_OK if compatible_target_boss(boss) else UNSUPPORTED
        if args[1] == "probe-source" and len(args) == 4:
            return (
                SOURCE_PROBE_OK
                if compatible_source_boss(boss)
                and exact_source_is_active(boss, window, target_window_id)
                else UNSUPPORTED
            )
        if args[1] == "source-token" and len(args) == 6:
            callback_path, nonce = args[4:]
            if (
                not compatible_source_boss(boss)
                or not exact_source_is_active(boss, window, target_window_id)
                or not valid_callback_socket(callback_path)
                or not valid_nonce(nonce)
            ):
                return UNSUPPORTED

            def token_received(token):
                send_source_token(
                    boss,
                    window,
                    target_window_id,
                    callback_path,
                    nonce,
                    token,
                )

            return SOURCE_REQUESTED if run_with_activation_token(token_received) else UNSUPPORTED
        if args[1] != "activate" or len(args) != 5 or not valid_activation_token(args[4]):
            return UNSUPPORTED
        os_window_id = boss.set_active_window(
            window,
            switch_os_window_if_needed=True,
            activation_token=args[4],
        )
        return ACTIVATE_OK if os_window_id is not None else UNSUPPORTED
    except Exception:
        return UNSUPPORTED
