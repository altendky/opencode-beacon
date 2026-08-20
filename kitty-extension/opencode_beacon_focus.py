#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0

import inspect

from kittens.tui.handler import result_handler
from kitty.constants import version as kitty_version

PROTOCOL_VERSION = "1"
SUPPORTED_KITTY_MINOR = (0, 45)
PROBE_OK = "opencode-beacon-kitty-bridge/1 ready"
ACTIVATE_OK = "opencode-beacon-kitty-bridge/1 activated"
UNSUPPORTED = "opencode-beacon-kitty-bridge/1 unsupported"
MAX_ACTIVATION_TOKEN_SIZE = 4096


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


def compatible_boss(boss):
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


@result_handler(no_ui=True)
def handle_result(args, answer, target_window_id, boss):
    del answer
    try:
        if len(args) < 4 or args[2] != PROTOCOL_VERSION or not valid_positive_id(args[3]):
            return UNSUPPORTED
        if target_window_id != int(args[3]) or not compatible_boss(boss):
            return UNSUPPORTED
        window = boss.window_id_map.get(target_window_id)
        if window is None:
            return UNSUPPORTED
        if args[1] == "probe" and len(args) == 4:
            return PROBE_OK
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
