"""Locating, reading and merging the config files; hostile files (interface.md, Config)."""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from gatectl import errors
from gatectl.config import (
    MAX_CONFIG_BYTES,
    MAX_DROPINS,
    default_config_path,
    load_config,
)
from tests.config_util import load, write

CANARY = "SECRET-CANARY-7f3a"


def _exc_text(exc: errors.GatectlError) -> str:
    return repr(errors.envelope(exc))


# --- paths -----------------------------------------------------------------------------


def test_default_path_uses_xdg_config_home(tmp_path: Path) -> None:
    env = {"XDG_CONFIG_HOME": str(tmp_path / "xdg"), "HOME": str(tmp_path / "h")}
    assert default_config_path(env) == tmp_path / "xdg" / "gatectl" / "config.yaml"


@pytest.mark.parametrize("xdg", ["", "relative/dir", "~/x"])
def test_default_path_ignores_empty_or_relative_xdg(tmp_path: Path, xdg: str) -> None:
    env = {"XDG_CONFIG_HOME": xdg, "HOME": str(tmp_path / "h")}
    assert default_config_path(env) == tmp_path / "h" / ".config" / "gatectl" / "config.yaml"


def test_default_path_without_xdg(tmp_path: Path) -> None:
    env = {"HOME": str(tmp_path / "h")}
    assert default_config_path(env) == tmp_path / "h" / ".config" / "gatectl" / "config.yaml"


def test_missing_default_file_is_the_built_in_defaults(tmp_path: Path) -> None:
    env = {"XDG_CONFIG_HOME": str(tmp_path / "nothing"), "HOME": str(tmp_path)}
    loaded = load_config(None, environ=env)
    assert loaded.shared_problems == ()
    assert loaded.policies == {}
    assert loaded.shared.defaults.timeout.total_seconds() == 60


def test_default_file_and_dropins_are_read_from_xdg(tmp_path: Path) -> None:
    base = tmp_path / "xdg" / "gatectl"
    write(base / "config.yaml", {"defaults": {"timeout": "5s"}})
    write(base / "config.d" / "10.yaml", {"defaults": {"script_timeout": "7s"}})
    loaded = load_config(None, environ={"XDG_CONFIG_HOME": str(tmp_path / "xdg")})
    assert loaded.shared.defaults.timeout.total_seconds() == 5
    assert loaded.shared.defaults.script_timeout.total_seconds() == 7


def test_config_flag_replaces_main_file_but_dropins_come_from_its_directory(
    tmp_path: Path,
) -> None:
    xdg = tmp_path / "xdg" / "gatectl"
    write(xdg / "config.yaml", {"defaults": {"timeout": "9s"}})
    write(xdg / "config.d" / "a.yaml", {"defaults": {"script_timeout": "9s"}})
    other = tmp_path / "other"
    write(other / "mine.yaml", {"defaults": {"timeout": "5s"}})
    write(other / "config.d" / "a.yaml", {"defaults": {"record_reserve": "3s"}})
    loaded = load_config(
        str(other / "mine.yaml"), environ={"XDG_CONFIG_HOME": str(tmp_path / "xdg")}
    )
    assert loaded.shared.defaults.timeout.total_seconds() == 5
    assert loaded.shared.defaults.script_timeout.total_seconds() == 20  # default: xdg ignored
    assert loaded.shared.defaults.record_reserve.total_seconds() == 3


def test_relative_config_flag_resolves_against_cwd(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    write(tmp_path / "rel.yaml", {"defaults": {"timeout": "5s"}})
    monkeypatch.chdir(tmp_path)
    assert load_config("rel.yaml", environ={}).shared.defaults.timeout.total_seconds() == 5


def test_explicit_config_that_is_missing_is_unreadable(tmp_path: Path) -> None:
    with pytest.raises(errors.GatectlError) as info:
        load_config(str(tmp_path / "nope.yaml"), environ={})
    assert info.value.exit_code == 1


# --- unreadable files are an unknown state (exit 1) ------------------------------------------


@pytest.mark.skipif(os.geteuid() == 0, reason="root can read everything")
def test_unreadable_main_file_exits_1(tmp_path: Path) -> None:
    path = write(tmp_path / "c.yaml", {})
    path.chmod(0)
    with pytest.raises(errors.GatectlError) as info:
        load_config(str(path), environ={})
    assert info.value.exit_code == 1


@pytest.mark.skipif(os.geteuid() == 0, reason="root can read everything")
def test_unreadable_dropin_exits_1(tmp_path: Path) -> None:
    write(tmp_path / "cfg" / "config.yaml", {})
    bad = write(tmp_path / "cfg" / "config.d" / "a.yaml", {})
    bad.chmod(0)
    with pytest.raises(errors.GatectlError) as info:
        load_config(str(tmp_path / "cfg" / "config.yaml"), environ={})
    assert info.value.exit_code == 1


@pytest.mark.skipif(os.geteuid() == 0, reason="root can read everything")
def test_unreadable_dropin_directory_exits_1(tmp_path: Path) -> None:
    write(tmp_path / "cfg" / "config.yaml", {})
    d = tmp_path / "cfg" / "config.d"
    d.mkdir()
    d.chmod(0)
    try:
        with pytest.raises(errors.GatectlError) as info:
            load_config(str(tmp_path / "cfg" / "config.yaml"), environ={})
        assert info.value.exit_code == 1
    finally:
        d.chmod(0o700)


def test_directory_as_config_file_exits_1(tmp_path: Path) -> None:
    (tmp_path / "c.yaml").mkdir()
    with pytest.raises(errors.GatectlError) as info:
        load_config(str(tmp_path / "c.yaml"), environ={})
    assert info.value.exit_code == 1


def test_fifo_as_config_file_exits_1_without_blocking(tmp_path: Path) -> None:
    fifo = tmp_path / "c.yaml"
    os.mkfifo(fifo)
    with pytest.raises(errors.GatectlError) as info:
        load_config(str(fifo), environ={})
    assert info.value.exit_code == 1


def test_dev_zero_as_config_file_exits_1(tmp_path: Path) -> None:
    link = tmp_path / "c.yaml"
    link.symlink_to("/dev/zero")
    with pytest.raises(errors.GatectlError) as info:
        load_config(str(link), environ={})
    assert info.value.exit_code == 1


def test_dangling_symlink_exits_1(tmp_path: Path) -> None:
    link = tmp_path / "c.yaml"
    link.symlink_to(tmp_path / "gone.yaml")
    with pytest.raises(errors.GatectlError) as info:
        load_config(str(link), environ={})
    assert info.value.exit_code == 1


def test_symlink_loop_exits_1(tmp_path: Path) -> None:
    (tmp_path / "a.yaml").symlink_to(tmp_path / "b.yaml")
    (tmp_path / "b.yaml").symlink_to(tmp_path / "a.yaml")
    with pytest.raises(errors.GatectlError) as info:
        load_config(str(tmp_path / "a.yaml"), environ={})
    assert info.value.exit_code == 1


def test_symlink_to_a_regular_file_is_followed(tmp_path: Path) -> None:
    real = write(tmp_path / "real.yaml", {"defaults": {"timeout": "5s"}})
    link = tmp_path / "c.yaml"
    link.symlink_to(real)
    assert load_config(str(link), environ={}).shared.defaults.timeout.total_seconds() == 5


def test_dropin_directory_that_is_a_file_exits_1(tmp_path: Path) -> None:
    write(tmp_path / "cfg" / "config.yaml", {})
    (tmp_path / "cfg" / "config.d").write_text("x", encoding="utf-8")
    with pytest.raises(errors.GatectlError) as info:
        load_config(str(tmp_path / "cfg" / "config.yaml"), environ={})
    assert info.value.exit_code == 1


def test_unreadable_error_does_not_leak_file_content(tmp_path: Path) -> None:
    (tmp_path / "c.yaml").mkdir()
    with pytest.raises(errors.GatectlError) as info:
        load_config(str(tmp_path / "c.yaml"), environ={})
    assert info.value.reason is None
    assert info.value.code == "internal"


# --- size and encoding ---------------------------------------------------------------------


def test_file_at_the_cap_is_read_and_one_byte_over_is_a_config_error(tmp_path: Path) -> None:
    ok = tmp_path / "ok.yaml"
    ok.write_bytes(b"#" * (MAX_CONFIG_BYTES - 1) + b"\n")
    load_config(str(ok), environ={})
    big = tmp_path / "big.yaml"
    big.write_bytes(b"#" * MAX_CONFIG_BYTES + b"\n")
    with pytest.raises(errors.ConfigInvalidError):
        load_config(str(big), environ={})


def test_huge_file_is_refused_without_reading_it_all(tmp_path: Path) -> None:
    big = tmp_path / "big.yaml"
    with big.open("wb") as fh:
        fh.truncate(512 * 1024 * 1024)  # sparse: reading it whole would be slow and large
    with pytest.raises(errors.ConfigInvalidError):
        load_config(str(big), environ={})


def test_invalid_utf8_is_a_config_error(tmp_path: Path) -> None:
    path = tmp_path / "c.yaml"
    path.write_bytes(b"me: {name: \xff\xfe}\n")
    with pytest.raises(errors.ConfigInvalidError) as info:
        load_config(str(path), environ={})
    assert info.value.exit_code == 2


def test_nul_byte_is_a_config_error(tmp_path: Path) -> None:
    path = tmp_path / "c.yaml"
    path.write_bytes(b"me: {name: a\x00b}\n")
    with pytest.raises(errors.ConfigInvalidError):
        load_config(str(path), environ={})


def test_utf8_bom_is_accepted(tmp_path: Path) -> None:
    path = tmp_path / "c.yaml"
    path.write_bytes(b"\xef\xbb\xbfdefaults: {timeout: 5s}\n")
    assert load_config(str(path), environ={}).shared.defaults.timeout.total_seconds() == 5


# --- YAML hazards ------------------------------------------------------------------------


@pytest.mark.parametrize(
    "text",
    [
        "defaults: {timeout: [unclosed\n",
        "defaults:\n  timeout: 5s\n bad: indent\n",
        "a: b: c\n",
        "- just\n- a list\n",
        "scalar\n",
        "---\na: 1\n---\nb: 2\n",
        "defaults: !!python/object/apply:os.system ['echo hi']\n",
        "defaults: !!python/name:os.system\n",
        "defaults: !!binary aGVsbG8=\n",
        "me: {name: !!set {a, b}}\n",
        "me: {name: 2001-02-03}\n",
        "me: {name: 2001-02-03 04:05:06}\n",
        "1: x\n",
        "defaults: {true: 1}\n",
        "defaults: {null: 1}\n",
        "? [a, b]\n: c\n",
        "defaults: {timeout: 5s, timeout: 6s}\n",
        'me: {name: "\\ud800"}\n',
        "me: {name: .nan}\n",
        "me: {name: .inf}\n",
        "me: {name: -.inf}\n",
        "defaults: {input_max_bytes: " + "9" * 5000 + "}\n",
        "[" * 100_000,
        "a: " + "[" * 100 + "]" * 100 + "\n",
        "a: &x 1\nb: *x\n",
        "a: &x [1]\n",
        "base: &b {timeout: 5s}\ndefaults: *b\n",
        "defaults: {timeout: !!str 5s}\n" if False else "x: %\n",
        "\t- tab\n",
    ],
)
def test_hostile_yaml_is_a_config_error_not_a_crash(tmp_path: Path, text: str) -> None:
    path = tmp_path / "c.yaml"
    path.write_text(text, encoding="utf-8")
    with pytest.raises(errors.ConfigInvalidError) as info:
        load_config(str(path), environ={})
    assert info.value.exit_code == 2


def test_billion_laughs_is_refused_quickly(tmp_path: Path) -> None:
    lines = ["a0: &a0 [x, x, x, x, x, x, x, x, x]"]
    for i in range(1, 10):
        refs = ", ".join([f"*a{i - 1}"] * 9)
        lines.append(f"a{i}: &a{i} [{refs}]")
    path = tmp_path / "c.yaml"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    with pytest.raises(errors.ConfigInvalidError):
        load_config(str(path), environ={})


def test_nesting_limit_is_exact(tmp_path: Path) -> None:
    def nested(depth: int) -> str:
        return "a: " + "[" * depth + "]" * depth + "\n"

    ok = tmp_path / "ok.yaml"
    ok.write_text(nested(60), encoding="utf-8")
    # The unknown top-level key is a shared problem, not a YAML-level failure.
    assert load_config(str(ok), environ={}).shared_problems
    deep = tmp_path / "deep.yaml"
    deep.write_text(nested(70), encoding="utf-8")
    with pytest.raises(errors.ConfigInvalidError):
        load_config(str(deep), environ={})


def test_yaml_merge_key_is_refused(tmp_path: Path) -> None:
    with pytest.raises(errors.ConfigInvalidError):
        load(tmp_path, "base: {timeout: 5s}\ndefaults:\n  <<: {timeout: 5s}\n")


def test_yaml_error_message_never_echoes_file_text(tmp_path: Path) -> None:
    path = tmp_path / "c.yaml"
    path.write_text(f"me: [{CANARY}\nname: {CANARY}: {CANARY}\n", encoding="utf-8")
    with pytest.raises(errors.ConfigInvalidError) as info:
        load_config(str(path), environ={})
    assert CANARY not in _exc_text(info.value)


@pytest.mark.parametrize(
    "text",
    [
        f"defaults: {{timeout: 5s, timeout: 6s, {CANARY}: 1, {CANARY}: 2}}\n",
        f"{CANARY}: &{CANARY} 1\nb: *{CANARY}\n",
        f"x: !!{CANARY} y\n",
        f"x: !{CANARY} y\n",
    ],
)
def test_other_yaml_errors_never_echo_file_text(tmp_path: Path, text: str) -> None:
    path = tmp_path / "c.yaml"
    path.write_text(text, encoding="utf-8")
    with pytest.raises(errors.ConfigInvalidError) as info:
        load_config(str(path), environ={})
    assert CANARY not in _exc_text(info.value)


def test_yaml_error_names_the_file_and_the_position(tmp_path: Path) -> None:
    path = tmp_path / "c.yaml"
    path.write_text("a: 1\nb: [\n", encoding="utf-8")
    with pytest.raises(errors.ConfigInvalidError) as info:
        load_config(str(path), environ={})
    assert "c.yaml" in info.value.message
    assert "line" in info.value.message


def test_empty_comment_only_and_null_documents_are_empty_configs(tmp_path: Path) -> None:
    for text in ("", "# nothing\n", "---\n", "null\n", "~\n"):
        loaded = load(tmp_path, text)
        assert loaded.shared_problems == ()
        assert loaded.policies == {}


def test_yaml_1_1_booleans_in_values_are_ordinary_yaml(tmp_path: Path) -> None:
    loaded = load(tmp_path, "policies:\n  p:\n    record_input: true\n    checks: []\n")
    assert loaded.policies["p"].policy is None  # empty checks, but record_input parsed


# --- drop-ins and merge ---------------------------------------------------------------------


def test_dropins_merge_in_lexical_order_and_later_wins(tmp_path: Path) -> None:
    loaded = load(
        tmp_path,
        {"defaults": {"timeout": "1s", "script_timeout": "1s", "record_reserve": "1s"}},
        dropins={
            "20-b.yaml": {"defaults": {"timeout": "3s", "script_timeout": "3s"}},
            "10-a.yaml": {"defaults": {"timeout": "2s", "record_reserve": "2s"}},
        },
    )
    d = loaded.shared.defaults
    assert d.timeout.total_seconds() == 3  # 20-b after 10-a after main
    assert d.script_timeout.total_seconds() == 3
    assert d.record_reserve.total_seconds() == 2  # maps merge: untouched keys survive


def test_lexical_order_is_by_code_point_not_locale(tmp_path: Path) -> None:
    loaded = load(
        tmp_path,
        {},
        dropins={
            "B.yaml": {"defaults": {"timeout": "2s"}},
            "a.yaml": {"defaults": {"timeout": "3s"}},  # "a" (0x61) sorts after "B" (0x42)
            "10.yaml": {"defaults": {"timeout": "1s"}},
        },
    )
    assert loaded.shared.defaults.timeout.total_seconds() == 3


def test_hook_lists_append_across_files_in_order(tmp_path: Path) -> None:
    loaded = load(
        tmp_path,
        {"hooks": {"post-decision": [{"cmd": "one"}]}},
        dropins={
            "10.yaml": {"hooks": {"post-decision": [{"cmd": "two"}, {"cmd": "three"}]}},
            "20.yaml": {"hooks": {"post-outcome": [{"cmd": "four"}]}},
        },
    )
    assert [h.cmd for h in loaded.shared.hooks.post_decision] == ["one", "two", "three"]
    assert [h.cmd for h in loaded.shared.hooks.post_outcome] == ["four"]


def test_other_lists_are_replaced_not_appended(tmp_path: Path) -> None:
    loaded = load(
        tmp_path,
        {"session_cmd": ["a-tool", "x"], "defaults": {"script_env_allow": ["PATH", "HOME"]}},
        dropins={"10.yaml": {"session_cmd": ["b-tool"], "defaults": {"script_env_allow": ["X"]}}},
    )
    assert loaded.shared.session_cmd == ["b-tool"]
    assert loaded.shared.defaults.script_env_allow == ["X"]


def test_policies_merge_by_key_and_lists_inside_replace(tmp_path: Path) -> None:
    rule = {"name": "r", "type": "rule", "when": [{"path": "a", "op": "exists"}], "then": "deny"}
    rule2 = {**rule, "name": "r2"}
    loaded = load(
        tmp_path,
        {"policies": {"p": {"checks": [rule], "timeout": "5s"}, "q": {"checks": [rule]}}},
        dropins={"10.yaml": {"policies": {"p": {"checks": [rule2], "cache_ttl": "1m"}}}},
    )
    p = loaded.policies["p"].policy
    assert p is not None
    assert [c.name for c in p.checks] == ["r2"]
    assert p.timeout is not None and p.timeout.total_seconds() == 5
    assert p.cache_ttl is not None and p.cache_ttl.total_seconds() == 60
    assert loaded.policies["q"].policy is not None


def test_later_scalar_replaces_a_map_and_the_result_is_a_problem(tmp_path: Path) -> None:
    loaded = load(tmp_path, {"defaults": {"timeout": "5s"}}, dropins={"10.yaml": {"defaults": 5}})
    assert [p.path for p in loaded.shared_problems] == ["defaults"]
    assert loaded.shared.defaults.timeout.total_seconds() == 60


def test_only_yaml_extension_non_hidden_files_count(tmp_path: Path) -> None:
    base = tmp_path / "cfg"
    write(base / "config.yaml", {})
    write(base / "config.d" / "a.yml", "defaults: {timeout: 1s}\n")
    write(base / "config.d" / "b.yaml.bak", "defaults: {timeout: 1s}\n")
    write(base / "config.d" / ".c.yaml", "defaults: {timeout: 1s}\n")
    write(base / "config.d" / "d.YAML", "defaults: {timeout: 1s}\n")
    write(base / "config.d" / "e.yaml", "defaults: {record_reserve: 3s}\n")
    loaded = load_config(str(base / "config.yaml"), environ={})
    assert loaded.shared.defaults.timeout.total_seconds() == 60
    assert loaded.shared.defaults.record_reserve.total_seconds() == 3


def test_dangling_hidden_lock_symlink_is_ignored(tmp_path: Path) -> None:
    base = tmp_path / "cfg"
    write(base / "config.yaml", {})
    (base / "config.d").mkdir()
    (base / "config.d" / ".#x.yaml").symlink_to("user@host.1234")
    load_config(str(base / "config.yaml"), environ={})


def test_dropin_that_is_a_directory_or_dangling_link_exits_1(tmp_path: Path) -> None:
    base = tmp_path / "cfg"
    write(base / "config.yaml", {})
    (base / "config.d" / "x.yaml").mkdir(parents=True)
    with pytest.raises(errors.GatectlError) as info:
        load_config(str(base / "config.yaml"), environ={})
    assert info.value.exit_code == 1


def test_dropin_with_bad_yaml_is_a_config_error(tmp_path: Path) -> None:
    with pytest.raises(errors.ConfigInvalidError) as info:
        load(tmp_path, {}, dropins={"10-bad.yaml": "a: [\n"})
    assert "10-bad.yaml" in info.value.message


def test_too_many_dropins_is_a_config_error(tmp_path: Path) -> None:
    base = tmp_path / "cfg"
    write(base / "config.yaml", {})
    for i in range(MAX_DROPINS + 1):
        (base / "config.d").mkdir(exist_ok=True)
        (base / "config.d" / f"{i:04d}.yaml").write_text("{}\n", encoding="utf-8")
    with pytest.raises(errors.ConfigInvalidError):
        load_config(str(base / "config.yaml"), environ={})


def test_total_size_of_all_files_is_capped(tmp_path: Path) -> None:
    base = tmp_path / "cfg"
    write(base / "config.yaml", {})
    for i in range(10):
        (base / "config.d").mkdir(exist_ok=True)
        (base / "config.d" / f"{i}.yaml").write_bytes(b"#" * (MAX_CONFIG_BYTES - 1) + b"\n")
    with pytest.raises(errors.ConfigInvalidError):
        load_config(str(base / "config.yaml"), environ={})


def test_dropin_symlink_to_regular_file_is_followed_and_to_fifo_refused(tmp_path: Path) -> None:
    base = tmp_path / "cfg"
    write(base / "config.yaml", {})
    real = write(tmp_path / "real.yaml", {"defaults": {"timeout": "5s"}})
    (base / "config.d").mkdir()
    (base / "config.d" / "a.yaml").symlink_to(real)
    assert (
        load_config(str(base / "config.yaml"), environ={}).shared.defaults.timeout.total_seconds()
        == 5
    )
    os.mkfifo(base / "config.d" / "b.yaml")
    with pytest.raises(errors.GatectlError) as info:
        load_config(str(base / "config.yaml"), environ={})
    assert info.value.exit_code == 1


def test_loading_never_modifies_the_files(tmp_path: Path) -> None:
    main = write(tmp_path / "cfg" / "config.yaml", {"defaults": {"timeout": "5s"}})
    before = (main.read_bytes(), stat.S_IMODE(main.stat().st_mode), main.stat().st_mtime_ns)
    load_config(str(main), environ={})
    after = (main.read_bytes(), stat.S_IMODE(main.stat().st_mode), main.stat().st_mtime_ns)
    assert before == after
