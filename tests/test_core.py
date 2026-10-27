from __future__ import annotations

import os
from unittest.mock import patch

import pytest

from osforge.network import build_ping_command, check_tcp, validate_host
from osforge.packages import (
    MANAGERS,
    build_action_commands,
    build_list_command,
    build_search_command,
    choose_manager,
    validate_package_name,
)
from osforge.processes import terminate_process
from osforge.system import _bytes, _duration, system_info
from osforge.tools import discover_tools


def test_system_info_has_live_host_fields() -> None:
    info = system_info()
    assert info["Operating system"]
    assert info["Python"]
    assert info["CPU cores"] >= 1
    assert info["Elevated"] in {"yes", "no"}


@pytest.mark.parametrize(
    ("value", "expected"),
    [(0, "0.0 B"), (1024, "1.0 KiB"), (1024 * 1024, "1.0 MiB")],
)
def test_bytes(value: int, expected: str) -> None:
    assert _bytes(value) == expected


def test_duration() -> None:
    assert _duration(0) == "0m"
    assert _duration(3661) == "1h 1m"
    assert _duration(90061) == "1d 1h 1m"


def test_package_names_reject_option_injection() -> None:
    assert validate_package_name("ripgrep") == "ripgrep"
    with pytest.raises(ValueError):
        validate_package_name("--help")
    with pytest.raises(ValueError):
        validate_package_name("two packages")


def test_package_commands_are_argument_arrays() -> None:
    assert build_action_commands("dnf", "install", "ripgrep", True) == [
        ["dnf", "install", "-y", "ripgrep"]
    ]
    assert build_action_commands("pacman", "remove", "ripgrep", False) == [
        ["pacman", "-Rns", "ripgrep"]
    ]
    assert build_action_commands("apt-get", "update") == [
        ["apt-get", "update"],
        ["apt-get", "upgrade"],
    ]


def test_package_search_does_not_build_a_shell_string() -> None:
    argv = build_search_command("dnf", "python tools")
    assert argv == ["dnf", "search", "python", "tools"]
    assert all(isinstance(part, str) for part in argv)


def test_package_list_has_supported_native_commands() -> None:
    assert build_list_command("pacman") == ["pacman", "-Q"]
    assert build_list_command("apt-get")[0] == "dpkg-query"


def test_unknown_manager_is_rejected() -> None:
    with pytest.raises(ValueError):
        choose_manager("not-a-real-manager")
    assert len(MANAGERS) >= 10


def test_validate_host_rejects_flags_and_whitespace() -> None:
    assert validate_host("example.com") == "example.com"
    with pytest.raises(ValueError):
        validate_host("-n")
    with pytest.raises(ValueError):
        validate_host("bad host")


@pytest.mark.parametrize(
    ("system", "expected"),
    [
        ("Windows", ["ping", "-n", "4", "localhost"]),
        ("Linux", ["ping", "-c", "4", "localhost"]),
        ("Darwin", ["ping", "-c", "4", "localhost"]),
    ],
)
def test_ping_command_is_os_specific(system: str, expected: list[str]) -> None:
    with patch("osforge.network.platform.system", return_value=system):
        assert build_ping_command("localhost") == expected


def test_ping_count_is_bounded() -> None:
    with pytest.raises(ValueError):
        build_ping_command("localhost", count=100)


def test_tcp_port_validation() -> None:
    with pytest.raises(ValueError):
        check_tcp("localhost", 70000)


def test_process_kill_refuses_current_process() -> None:
    with pytest.raises(ValueError, match="itself"):
        terminate_process(os.getpid())


def test_tool_discovery_returns_catalogued_rows() -> None:
    rows = discover_tools("git")
    assert rows
    assert rows[0][0].name == "git"
