#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0

BRIDGE_KITTEN = "opencode_beacon_focus.py"
PROTOCOL_VERSION = "1"
MAX_ACTIVATION_TOKEN_SIZE = 4096


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


def is_cmd_allowed(pcmd, window, from_socket, extra_data):
    del window, extra_data
    if pcmd.get("cmd") != "kitten":
        return None
    if not from_socket:
        return False
    if set(pcmd) != {"cmd", "no_response", "payload", "version"}:
        return False
    if pcmd.get("version") != [0, 45, 0] or pcmd.get("no_response") is not False:
        return False
    payload = pcmd.get("payload")
    if not isinstance(payload, dict) or set(payload) != {"args", "kitten", "match"}:
        return False
    if payload.get("kitten") != BRIDGE_KITTEN:
        return False
    match = payload.get("match")
    if not isinstance(match, str) or not match.startswith("id:"):
        return False
    window_id = match[3:]
    if not valid_positive_id(window_id):
        return False
    args = payload.get("args")
    if not isinstance(args, list) or not all(isinstance(value, str) for value in args):
        return False
    if args == ["probe", PROTOCOL_VERSION, window_id]:
        return True
    return (
        len(args) == 4
        and args[:3] == ["activate", PROTOCOL_VERSION, window_id]
        and valid_activation_token(args[3])
    )
