"""Policy fingerprint (interface.md, Fingerprint): coverage, exclusions and hostile files."""

from __future__ import annotations

import copy
import hashlib
import json
import os
import random
import re
import sys
from pathlib import Path
from typing import Any

import pytest

from gatectl import fingerprint as fpmod
from gatectl.fingerprint import UNREADABLE, definition, fingerprint, fingerprint_for
from gatectl.gateway import Stdio, SubprocessGateway, read_capped
from gatectl.scope import Scope
from tests.config_util import good_policy, load

A = "github.com/org/a"


def make_plugin(root: Path, name: str = "gatectl", skill_md: bytes = b"skill v1\n") -> Path:
    (root / ".claude-plugin").mkdir(parents=True)
    (root / ".claude-plugin" / "plugin.json").write_text(json.dumps({"name": name}))
    skill = root / "skills" / "gate-check"
    skill.mkdir(parents=True)
    (skill / "SKILL.md").write_bytes(skill_md)
    (root / fpmod.BUNDLED_PROFILE).write_bytes(b'{"profile": "bundled"}\n')
    return root


@pytest.fixture
def bundled(tmp_path: Path) -> Path:
    return make_plugin(tmp_path / "bundled")


def policy_doc(*checks: dict[str, Any], **extra: Any) -> dict[str, Any]:
    return {"checks": list(checks) or good_policy()["checks"], **extra}


def fp(
    tmp_path: Path,
    bundled: Path,
    doc: dict[str, Any],
    *,
    shared: dict[str, Any] | None = None,
    repo: str | None = None,
    **kw: Any,
) -> str:
    cfg = load(tmp_path, {**(shared or {}), "policies": {"p": doc}})
    assert cfg.policy_problems() == [] and cfg.shared_problems == ()
    policy = cfg.resolve_policy("p", repo=repo)
    return fingerprint("p", policy, cfg.shared, bundled_plugin=str(bundled), **kw)


def agent_check(**extra: Any) -> dict[str, Any]:
    return {"name": "a", "type": "agent", "instruction": "be careful", **extra}


def script_check(*argv: str, **extra: Any) -> dict[str, Any]:
    return {"name": "s", "type": "script", "argv": list(argv), **extra}


# --- shape ------------------------------------------------------------------------------


def test_fingerprint_has_the_documented_form(tmp_path: Path, bundled: Path) -> None:
    assert re.fullmatch(r"sha256:[0-9a-f]{64}", fp(tmp_path, bundled, policy_doc()))


def test_fingerprint_is_the_hash_of_the_canonical_definition(tmp_path: Path, bundled: Path) -> None:
    cfg = load(tmp_path, {"policies": {"p": policy_doc()}})
    d = definition("p", cfg.resolve_policy("p"), cfg.shared, bundled_plugin=str(bundled))
    text = json.dumps(d, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    expected = "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()
    assert fp(tmp_path, bundled, policy_doc()) == expected


def test_policy_name_is_covered(tmp_path: Path, bundled: Path) -> None:
    cfg = load(tmp_path, {"policies": {"p": policy_doc(), "q": policy_doc()}})
    pol = cfg.resolve_policy("p")
    assert fingerprint("p", pol, cfg.shared) != fingerprint("q", pol, cfg.shared)


# --- defaults, spelling, order -------------------------------------------------------------


def test_explicit_rule_else_allow_equals_the_default(tmp_path: Path, bundled: Path) -> None:
    rule = {"name": "r", "type": "rule", "when": [{"path": "a", "op": "exists"}], "then": "deny"}
    assert fp(tmp_path, bundled, policy_doc(rule)) == fp(
        tmp_path, bundled, policy_doc({**rule, "else": "allow"})
    )
    assert fp(tmp_path, bundled, policy_doc(rule)) != fp(
        tmp_path, bundled, policy_doc({**rule, "else": "escalate"})
    )


def test_agent_defaults_spelled_out_do_not_change_it(tmp_path: Path, bundled: Path) -> None:
    plain = fp(tmp_path, bundled, policy_doc(agent_check()))
    explicit = agent_check(
        skill="gatectl:gate-check",
        threshold=0.8,
        sandbox="required",
        setting_sources=[],
        env_allowlist=[],
        model=None,
        permission_profile=None,
    )
    assert fp(tmp_path, bundled, policy_doc(explicit)) == plain
    # an explicit input declaration with nothing in it is the absent one
    assert fp(tmp_path, bundled, policy_doc(agent_check(), input={})) == plain


def test_agent_value_equal_to_the_block_value_is_the_same_definition(
    tmp_path: Path, bundled: Path
) -> None:
    shared = {"agent": {"model": "haiku", "sandbox": "preferred", "threshold": 0.5}}
    inherited = fp(tmp_path, bundled, policy_doc(agent_check()), shared=shared)
    own = agent_check(model="haiku", sandbox="preferred", threshold=0.5)
    assert fp(tmp_path, bundled, policy_doc(own), shared=shared) == inherited


def test_changed_agent_model_changes_a_check_without_its_own(tmp_path: Path, bundled: Path) -> None:
    doc = policy_doc(agent_check())
    a = fp(tmp_path, bundled, doc, shared={"agent": {"model": "haiku"}})
    b = fp(tmp_path, bundled, doc, shared={"agent": {"model": "sonnet"}})
    assert a != b
    pinned = policy_doc(agent_check(model="opus"))
    assert fp(tmp_path, bundled, pinned, shared={"agent": {"model": "haiku"}}) == fp(
        tmp_path, bundled, pinned, shared={"agent": {"model": "sonnet"}}
    )


@pytest.mark.parametrize(
    ("shared", "own"),
    [
        ({"agent": {"threshold": 0.9}}, {}),
        ({"agent": {"sandbox": "off"}}, {}),
        ({"agent": {"setting_sources": ["user"]}}, {}),
        ({"agent": {"env_allowlist": ["X"]}}, {}),
        ({"agent": {"skill": "gatectl:other"}}, {}),
        ({}, {"threshold": 0.0}),
    ],
)
def test_each_resolved_agent_value_is_covered(
    tmp_path: Path, bundled: Path, shared: dict[str, Any], own: dict[str, Any]
) -> None:
    base = fp(tmp_path, bundled, policy_doc(agent_check()))
    assert fp(tmp_path, bundled, policy_doc(agent_check(**own)), shared=shared) != base


def test_threshold_spelling_is_one_value(tmp_path: Path, bundled: Path) -> None:
    a = fp(tmp_path, bundled, policy_doc(agent_check(threshold=1)))
    b = fp(tmp_path, bundled, policy_doc(agent_check(threshold=1.0)))
    assert a == b


def test_setting_sources_and_env_allowlist_are_sets(tmp_path: Path, bundled: Path) -> None:
    one = agent_check(setting_sources=["user", "local"], env_allowlist=["A", "B"])
    two = agent_check(setting_sources=["local", "user"], env_allowlist=["B", "A"])
    assert fp(tmp_path, bundled, policy_doc(one)) == fp(tmp_path, bundled, policy_doc(two))


def test_script_env_allow_is_the_effective_list(tmp_path: Path, bundled: Path) -> None:
    plain = fp(tmp_path, bundled, policy_doc(script_check("/no/such")))
    spelled = fp(
        tmp_path, bundled, policy_doc(script_check("/no/such", env_allow=["PATH", "HOME"]))
    )
    # PATH and HOME are already in the default list: the effective list is unchanged
    assert plain == spelled
    extra = fp(tmp_path, bundled, policy_doc(script_check("/no/such", env_allow=["TOKEN"])))
    assert extra != plain
    # order of the two lists is irrelevant
    a = fp(tmp_path, bundled, policy_doc(script_check("/no/such", env_allow=["A", "B"])))
    b = fp(tmp_path, bundled, policy_doc(script_check("/no/such", env_allow=["B", "A"])))
    assert a == b


def test_defaults_script_env_allow_is_covered_by_script_checks_only(
    tmp_path: Path, bundled: Path
) -> None:
    shared = {"defaults": {"script_env_allow": ["PATH", "EXTRA"]}}
    s = policy_doc(script_check("/no/such"))
    assert fp(tmp_path, bundled, s) != fp(tmp_path, bundled, s, shared=shared)
    r = policy_doc()
    assert fp(tmp_path, bundled, r) == fp(tmp_path, bundled, r, shared=shared)


def test_check_order_and_names_matter(tmp_path: Path, bundled: Path) -> None:
    r1 = {"name": "one", "type": "rule", "when": [{"path": "a", "op": "exists"}], "then": "deny"}
    r2 = {"name": "two", "type": "rule", "when": [{"path": "b", "op": "exists"}], "then": "deny"}
    assert fp(tmp_path, bundled, policy_doc(r1, r2)) != fp(tmp_path, bundled, policy_doc(r2, r1))
    assert fp(tmp_path, bundled, policy_doc(r1)) != fp(
        tmp_path, bundled, policy_doc({**r1, "name": "uno"})
    )


def test_key_order_in_the_file_is_irrelevant(tmp_path: Path, bundled: Path) -> None:
    rule = {"name": "r", "type": "rule", "when": [{"path": "a", "op": "eq", "value": 1}]}
    one = {**rule, "then": "deny"}
    two = {"then": "deny", **{k: rule[k] for k in reversed(list(rule))}}
    two["when"] = [{"value": 1, "op": "eq", "path": "a"}]
    assert fp(tmp_path, bundled, policy_doc(one)) == fp(tmp_path, bundled, policy_doc(two))


def test_random_key_order_and_spelling_property(tmp_path: Path, bundled: Path) -> None:
    rng = random.Random(8)
    doc = policy_doc(
        {"name": "r", "type": "rule", "when": [{"path": "a", "op": "exists"}], "then": "deny"},
        script_check("/no/such", env_allow=["A"]),
        agent_check(model="m", threshold=0.7),
        input={"require": ["a"], "types": {"a": "string", "b": "integer?"}, "ignore": ["t"]},
        applies_when=[{"path": "a", "op": "in", "value": [1, "x", None]}],
    )
    want = fp(tmp_path, bundled, doc)

    def shuffled(value: Any) -> Any:
        if isinstance(value, dict):
            items = list(value.items())
            rng.shuffle(items)
            return {k: shuffled(v) for k, v in items}
        if isinstance(value, list):
            return [shuffled(v) for v in value]
        return value

    for _ in range(6):
        assert fp(tmp_path, bundled, shuffled(copy.deepcopy(doc))) == want


# --- excluded and covered keys ------------------------------------------------------------


def test_timeouts_ttl_record_input_recommend_and_state_do_not_change_it(
    tmp_path: Path, bundled: Path
) -> None:
    base = policy_doc(agent_check(), script_check("/no/such"))
    want = fp(tmp_path, bundled, base)
    noisy = policy_doc(
        agent_check(timeout="9s", cache_ttl="1h"),
        script_check("/no/such", timeout="3s"),
        timeout="77s",
        cache_ttl="5m",
        record_input=True,
        recommend={"confidence": 0.9, "max_miss_rate": 0.2},
        state="off",
    )
    assert fp(tmp_path, bundled, noisy) == want
    shared = {
        "defaults": {"timeout": "5m", "script_timeout": "7s", "recommend": {"confidence": 0.5}},
        "agent": {"timeout": "9m", "cache_ttl": "0", "max_parallel": 2},
        "session_cmd": ["/bin/other"],
        "retention": {"older_than": "30d"},
        "me": {"name": "someone"},
    }
    assert fp(tmp_path, bundled, base, shared=shared) == want


def test_input_declaration_is_covered_including_ignore(tmp_path: Path, bundled: Path) -> None:
    base = fp(tmp_path, bundled, policy_doc(input={"ignore": ["t"]}))
    assert fp(tmp_path, bundled, policy_doc(input={"ignore": ["u"]})) != base
    assert fp(tmp_path, bundled, policy_doc(input={})) != base
    assert fp(tmp_path, bundled, policy_doc(input={"require": ["x"]})) != fp(
        tmp_path, bundled, policy_doc(input={"types": {"x": "string"}})
    )


def test_applies_when_is_covered(tmp_path: Path, bundled: Path) -> None:
    w1 = [{"path": "a", "op": "exists"}]
    base = fp(tmp_path, bundled, policy_doc())
    assert fp(tmp_path, bundled, policy_doc(applies_when=w1)) != base
    assert fp(tmp_path, bundled, policy_doc(applies_when=[{"path": "b", "op": "exists"}])) != fp(
        tmp_path, bundled, policy_doc(applies_when=w1)
    )


def test_instruction_text_is_covered(tmp_path: Path, bundled: Path) -> None:
    a = fp(tmp_path, bundled, policy_doc(agent_check(instruction="x")))
    b = fp(tmp_path, bundled, policy_doc(agent_check(instruction="y")))
    assert a != b


def test_instruction_with_lone_surrogate_does_not_raise(tmp_path: Path, bundled: Path) -> None:
    cfg = load(tmp_path, {"policies": {"p": policy_doc(agent_check())}})
    pol = cfg.resolve_policy("p")
    check = pol.checks[0].model_copy(update={"instruction": "bad \ud800 text"})
    pol = pol.model_copy(update={"checks": [check]})
    assert fingerprint("p", pol, cfg.shared, bundled_plugin=str(bundled)).startswith("sha256:")


# --- files: agent -------------------------------------------------------------------------


def test_changed_instruction_file_changes_it(tmp_path: Path, bundled: Path) -> None:
    f = tmp_path / "instr.md"
    f.write_bytes(b"one")
    doc = policy_doc({"name": "a", "type": "agent", "instruction_file": str(f)})
    before = fp(tmp_path, bundled, doc)
    f.write_bytes(b"two")
    after = fp(tmp_path, bundled, doc)
    assert before != after
    f.write_bytes(b"one")
    assert fp(tmp_path, bundled, doc) == before


def test_instruction_file_contents_not_path_decide_the_hash_part(
    tmp_path: Path, bundled: Path
) -> None:
    f = tmp_path / "i.md"
    f.write_bytes(b"same")
    d = definition(
        "p",
        load(
            tmp_path,
            {
                "policies": {
                    "p": policy_doc({"name": "a", "type": "agent", "instruction_file": str(f)})
                }
            },
        ).resolve_policy("p"),
        load(tmp_path, {}).shared,
        bundled_plugin=str(bundled),
    )
    assert d["checks"][0]["instruction_sha256"] == hashlib.sha256(b"same").hexdigest()


def test_unreadable_instruction_file_is_the_marker(tmp_path: Path, bundled: Path) -> None:
    doc = policy_doc({"name": "a", "type": "agent", "instruction_file": str(tmp_path / "gone")})
    cfg = load(tmp_path, {"policies": {"p": doc}})
    d = definition("p", cfg.resolve_policy("p"), cfg.shared, bundled_plugin=str(bundled))
    assert d["checks"][0]["instruction_sha256"] == UNREADABLE == "unreadable"
    assert fp(tmp_path, bundled, doc).startswith("sha256:")


def test_instruction_file_over_64_kib_is_unreadable(tmp_path: Path, bundled: Path) -> None:
    f = tmp_path / "big.md"
    f.write_bytes(b"x" * (64 * 1024 + 1))
    doc = policy_doc({"name": "a", "type": "agent", "instruction_file": str(f)})
    cfg = load(tmp_path, {"policies": {"p": doc}})
    d = definition("p", cfg.resolve_policy("p"), cfg.shared, bundled_plugin=str(bundled))
    assert d["checks"][0]["instruction_sha256"] == UNREADABLE
    f.write_bytes(b"x" * (64 * 1024))
    d = definition("p", cfg.resolve_policy("p"), cfg.shared, bundled_plugin=str(bundled))
    assert d["checks"][0]["instruction_sha256"] != UNREADABLE


def test_changed_skill_file_changes_it(tmp_path: Path, bundled: Path) -> None:
    doc = policy_doc(agent_check())
    before = fp(tmp_path, bundled, doc)
    (bundled / "skills" / "gate-check" / "SKILL.md").write_bytes(b"skill v2\n")
    assert fp(tmp_path, bundled, doc) != before


def test_changed_plugin_json_changes_it(tmp_path: Path, bundled: Path) -> None:
    doc = policy_doc(agent_check())
    before = fp(tmp_path, bundled, doc)
    (bundled / ".claude-plugin" / "plugin.json").write_text(
        json.dumps({"name": "gatectl", "version": "9"})
    )
    assert fp(tmp_path, bundled, doc) != before


def test_other_plugins_files_do_not_matter(tmp_path: Path, bundled: Path) -> None:
    other = make_plugin(tmp_path / "other", name="other", skill_md=b"o1")
    doc = policy_doc(agent_check())
    shared = {"agent": {"plugin_dirs": [str(other)]}}
    before = fp(tmp_path, bundled, doc, shared=shared)
    (other / "skills" / "gate-check" / "SKILL.md").write_bytes(b"o2")
    assert fp(tmp_path, bundled, doc, shared=shared) == before


def test_skill_from_a_configured_plugin_dir_is_hashed(tmp_path: Path, bundled: Path) -> None:
    other = make_plugin(tmp_path / "other", name="other", skill_md=b"o1")
    doc = policy_doc(agent_check(skill="other:gate-check"))
    shared = {"agent": {"plugin_dirs": [str(other)]}}
    before = fp(tmp_path, bundled, doc, shared=shared)
    (other / "skills" / "gate-check" / "SKILL.md").write_bytes(b"o2")
    assert fp(tmp_path, bundled, doc, shared=shared) != before


def test_missing_plugin_or_skill_is_the_marker(tmp_path: Path, bundled: Path) -> None:
    for skill in ("nope:gate-check", "gatectl:nope"):
        cfg = load(tmp_path, {"policies": {"p": policy_doc(agent_check(skill=skill))}})
        d = definition("p", cfg.resolve_policy("p"), cfg.shared, bundled_plugin=str(bundled))
        files = d["checks"][0]["skill_files"]
        assert UNREADABLE in files.values(), skill


def test_permission_profile_file_is_hashed(tmp_path: Path, bundled: Path) -> None:
    prof = tmp_path / "prof.json"
    prof.write_bytes(b"{}")
    doc = policy_doc(agent_check(permission_profile=str(prof)))
    before = fp(tmp_path, bundled, doc)
    prof.write_bytes(b'{"a": 1}')
    assert fp(tmp_path, bundled, doc) != before


def test_default_permission_profile_is_the_bundled_file(tmp_path: Path, bundled: Path) -> None:
    doc = policy_doc(agent_check())
    before = fp(tmp_path, bundled, doc)
    (bundled / fpmod.BUNDLED_PROFILE).write_bytes(b"changed")
    assert fp(tmp_path, bundled, doc) != before


def test_agent_block_profile_is_inherited_and_a_path_change_matters(
    tmp_path: Path, bundled: Path
) -> None:
    p1, p2 = tmp_path / "p1.json", tmp_path / "p2.json"
    p1.write_bytes(b"same")
    p2.write_bytes(b"same")
    doc = policy_doc(agent_check())
    a = fp(tmp_path, bundled, doc, shared={"agent": {"permission_profile": str(p1)}})
    b = fp(tmp_path, bundled, policy_doc(agent_check(permission_profile=str(p1))))
    assert a == b
    assert a != fp(tmp_path, bundled, doc, shared={"agent": {"permission_profile": str(p2)}})


# --- files: script argv --------------------------------------------------------------------


def argv_files(tmp_path: Path, bundled: Path, *argv: str) -> list[Any]:
    cfg = load(tmp_path, {"policies": {"p": policy_doc(script_check(*argv))}})
    d = definition("p", cfg.resolve_policy("p"), cfg.shared, bundled_plugin=str(bundled))
    return d["checks"][0]["argv_files"]


def test_script_file_hash_changes_with_content(tmp_path: Path, bundled: Path) -> None:
    exe = tmp_path / "check.sh"
    exe.write_bytes(b"#!/bin/sh\nexit 0\n")
    doc = policy_doc(script_check(str(exe), "--flag"))
    before = fp(tmp_path, bundled, doc)
    assert argv_files(tmp_path, bundled, str(exe), "--flag") == [
        hashlib.sha256(b"#!/bin/sh\nexit 0\n").hexdigest(),
        None,
    ]
    exe.write_bytes(b"#!/bin/sh\nexit 1\n")
    assert fp(tmp_path, bundled, doc) != before


def test_every_absolute_argv_element_is_hashed(tmp_path: Path, bundled: Path) -> None:
    exe, data = tmp_path / "x", tmp_path / "data.txt"
    exe.write_bytes(b"x")
    data.write_bytes(b"1")
    doc = policy_doc(script_check(str(exe), "-f", str(data)))
    before = fp(tmp_path, bundled, doc)
    data.write_bytes(b"2")
    assert fp(tmp_path, bundled, doc) != before


def test_relative_and_missing_and_directory_elements_contribute_nothing(
    tmp_path: Path, bundled: Path
) -> None:
    (tmp_path / "d").mkdir()
    (tmp_path / "rel").write_bytes(b"x")
    exe = tmp_path / "x"
    exe.write_bytes(b"x")
    got = argv_files(tmp_path, bundled, str(exe), "rel", str(tmp_path / "d"), str(tmp_path / "no"))
    assert got[1:] == [None, None, None]
    assert got[0] != UNREADABLE


def test_relative_argv_never_depends_on_the_working_directory(
    tmp_path: Path, bundled: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "w1").mkdir()
    (tmp_path / "w2").mkdir()
    (tmp_path / "w1" / "rel").write_bytes(b"one")
    (tmp_path / "w2" / "rel").write_bytes(b"two")
    doc = policy_doc(script_check("/no/such", "rel", "./rel"))
    monkeypatch.chdir(tmp_path / "w1")
    a = fp(tmp_path, bundled, doc)
    monkeypatch.chdir(tmp_path / "w2")
    assert fp(tmp_path, bundled, doc) == a


def test_symlink_to_a_regular_file_is_followed(tmp_path: Path, bundled: Path) -> None:
    real = tmp_path / "real"
    real.write_bytes(b"payload")
    link = tmp_path / "link"
    link.symlink_to(real)
    assert argv_files(tmp_path, bundled, str(link)) == [hashlib.sha256(b"payload").hexdigest()]


def test_symlink_loop_and_dangling_link_contribute_nothing(tmp_path: Path, bundled: Path) -> None:
    (tmp_path / "a").symlink_to(tmp_path / "b")
    (tmp_path / "b").symlink_to(tmp_path / "a")
    (tmp_path / "dangling").symlink_to(tmp_path / "nowhere")
    assert argv_files(tmp_path, bundled, str(tmp_path / "a"), str(tmp_path / "dangling")) == [
        None,
        None,
    ]


def test_fifo_is_neither_opened_nor_blocked_on(tmp_path: Path, bundled: Path) -> None:
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo)
    assert argv_files(tmp_path, bundled, str(fifo)) == [None]
    doc = policy_doc({"name": "a", "type": "agent", "instruction_file": str(fifo)})
    cfg = load(tmp_path, {"policies": {"p": doc}})
    d = definition("p", cfg.resolve_policy("p"), cfg.shared, bundled_plugin=str(bundled))
    assert d["checks"][0]["instruction_sha256"] == UNREADABLE


@pytest.mark.skipif(not Path("/dev/null").exists(), reason="no /dev/null")
def test_device_is_not_a_regular_file(tmp_path: Path, bundled: Path) -> None:
    assert argv_files(tmp_path, bundled, "/dev/null", "/dev/zero") == [None, None]
    doc = policy_doc(agent_check(permission_profile="/dev/zero"))
    cfg = load(tmp_path, {"policies": {"p": doc}})
    d = definition("p", cfg.resolve_policy("p"), cfg.shared, bundled_plugin=str(bundled))
    assert d["checks"][0]["permission_profile"]["sha256"] == UNREADABLE


def test_directory_as_required_file_is_unreadable(tmp_path: Path, bundled: Path) -> None:
    doc = policy_doc(agent_check(permission_profile=str(tmp_path)))
    cfg = load(tmp_path, {"policies": {"p": doc}})
    d = definition("p", cfg.resolve_policy("p"), cfg.shared, bundled_plugin=str(bundled))
    assert d["checks"][0]["permission_profile"]["sha256"] == UNREADABLE


@pytest.mark.skipif(os.geteuid() == 0, reason="root reads anything")
def test_permission_denied_is_the_marker_and_does_not_raise(tmp_path: Path, bundled: Path) -> None:
    f = tmp_path / "secret"
    f.write_bytes(b"x")
    f.chmod(0)
    try:
        assert argv_files(tmp_path, bundled, str(f)) == [UNREADABLE]
        assert fp(tmp_path, bundled, policy_doc(script_check(str(f)))).startswith("sha256:")
    finally:
        f.chmod(0o600)


def test_unreadable_differs_from_content_and_from_absent(tmp_path: Path, bundled: Path) -> None:
    f = tmp_path / "x"
    f.write_bytes(b"x")
    doc = policy_doc(script_check(str(f)))
    present = fp(tmp_path, bundled, doc)
    f.unlink()
    assert fp(tmp_path, bundled, doc) != present


def test_non_utf8_content_is_hashed_as_bytes(tmp_path: Path, bundled: Path) -> None:
    f = tmp_path / "bin"
    raw = bytes(range(256))
    f.write_bytes(raw)
    assert argv_files(tmp_path, bundled, str(f)) == [hashlib.sha256(raw).hexdigest()]


def test_non_utf8_path_does_not_raise(tmp_path: Path, bundled: Path) -> None:
    cfg = load(tmp_path, {"policies": {"p": policy_doc(script_check("/no/such"))}})
    pol = cfg.resolve_policy("p")
    bad = pol.checks[0].model_copy(update={"argv": ["/x/\udcff\udc80", "/y/\0z"]})
    pol = pol.model_copy(update={"checks": [bad]})
    assert fingerprint("p", pol, cfg.shared, bundled_plugin=str(bundled)).startswith("sha256:")


def test_name_too_long_does_not_raise(tmp_path: Path, bundled: Path) -> None:
    assert argv_files(tmp_path, bundled, "/" + "a" * 5000) == [None]


# --- size cap --------------------------------------------------------------------------


def test_file_at_the_cap_is_hashed_and_over_it_is_size_and_mtime(
    tmp_path: Path, bundled: Path
) -> None:
    at = tmp_path / "at"
    over = tmp_path / "over"
    at.write_bytes(b"a" * (1024 * 1024))
    over.write_bytes(b"b" * (1024 * 1024 + 1))
    os.utime(over, ns=(5, 1_700_000_000_000_000_123))
    got = argv_files(tmp_path, bundled, str(at), str(over))
    assert got[0] == hashlib.sha256(b"a" * (1024 * 1024)).hexdigest()
    assert got[1] == {"size": 1024 * 1024 + 1, "mtime_ns": 1_700_000_000_000_000_123}


def test_over_cap_file_changes_with_size_and_mtime_not_content(
    tmp_path: Path, bundled: Path
) -> None:
    f = tmp_path / "big"
    f.write_bytes(b"a" * (1024 * 1024 + 10))
    os.utime(f, ns=(1, 2_000_000_000))
    doc = policy_doc(script_check(str(f)))
    base = fp(tmp_path, bundled, doc)
    f.write_bytes(b"b" * (1024 * 1024 + 10))  # same size, new content
    os.utime(f, ns=(1, 2_000_000_000))
    assert fp(tmp_path, bundled, doc) == base
    os.utime(f, ns=(1, 3_000_000_000))
    assert fp(tmp_path, bundled, doc) != base


def test_huge_sparse_file_is_not_read(tmp_path: Path, bundled: Path) -> None:
    f = tmp_path / "sparse"
    with open(f, "wb") as out:
        out.truncate(8 * 1024**3)
    got = argv_files(tmp_path, bundled, str(f))
    assert got[0]["size"] == 8 * 1024**3


def test_file_that_grows_past_the_cap_while_read_is_unreadable(
    tmp_path: Path, bundled: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    f = tmp_path / "grow"
    f.write_bytes(b"x" * 100)
    real_read = os.read
    state = {"done": False}

    def read(fd: int, n: int) -> bytes:
        if not state["done"] and os.fstat(fd).st_ino == f.stat().st_ino:
            state["done"] = True
            with open(f, "ab") as more:
                more.write(b"y" * (2 * 1024 * 1024))
        return real_read(fd, n)

    monkeypatch.setattr(fpmod.os, "read", read)
    assert argv_files(tmp_path, bundled, str(f)) == [UNREADABLE]


def test_file_modified_during_read_is_unreadable(
    tmp_path: Path, bundled: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    f = tmp_path / "chg"
    f.write_bytes(b"x" * 100)
    real_read = os.read

    def read(fd: int, n: int) -> bytes:
        data = real_read(fd, n)
        if data and os.fstat(fd).st_ino == f.stat().st_ino:
            os.utime(f, ns=(1, 424242))
        return data

    monkeypatch.setattr(fpmod.os, "read", read)
    assert argv_files(tmp_path, bundled, str(f)) == [UNREADABLE]


def test_a_non_regular_file_swapped_in_after_the_stat_is_not_read(
    tmp_path: Path, bundled: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    f = tmp_path / "swap"
    f.write_bytes(b"x")
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo)
    real_stat = os.stat

    def stat(path: Any, *a: Any, **k: Any) -> os.stat_result:
        result = real_stat(path, *a, **k)
        if str(path) == str(f):
            f.unlink()
            f.symlink_to(fifo)
        return result

    monkeypatch.setattr(fpmod.os, "stat", stat)
    assert argv_files(tmp_path, bundled, str(f)) == [UNREADABLE]


# --- deadline ---------------------------------------------------------------------------


def test_deadline_is_checked_between_files(tmp_path: Path, bundled: Path) -> None:
    files = []
    for i in range(3):
        p = tmp_path / f"f{i}"
        p.write_bytes(b"x")
        files.append(str(p))
    ticks = iter([0.0, 99.0, 99.0, 99.0])
    cfg = load(tmp_path, {"policies": {"p": policy_doc(script_check(*files))}})
    d = definition(
        "p",
        cfg.resolve_policy("p"),
        cfg.shared,
        bundled_plugin=str(bundled),
        deadline=10.0,
        monotonic=lambda: next(ticks),
    )
    got = d["checks"][0]["argv_files"]
    assert got[0] == hashlib.sha256(b"x").hexdigest()
    assert got[1:] == [UNREADABLE, UNREADABLE]


def test_expired_deadline_does_not_raise(tmp_path: Path, bundled: Path) -> None:
    doc = policy_doc(agent_check(), script_check("/bin/sh"))
    out = fp(tmp_path, bundled, doc, deadline=-1.0)
    assert out.startswith("sha256:")
    assert out != fp(tmp_path, bundled, doc)


# --- overrides and scope ------------------------------------------------------------------


def test_override_has_its_own_fingerprint(tmp_path: Path, bundled: Path) -> None:
    cfg = load(
        tmp_path,
        {
            "policies": {"p": policy_doc()},
            "repos": {
                A: {"policies": {"p": {"input": {"ignore": ["t"]}}}},
                "github.com/org/b": {"policies": {"p": {"timeout": "5s"}}},
            },
        },
    )
    glob = fingerprint_for(cfg, "p", Scope("*", False, ()), bundled_plugin=str(bundled))
    over = fingerprint_for(cfg, "p", Scope(A, False, ()), bundled_plugin=str(bundled))
    same = fingerprint_for(
        cfg, "p", Scope("github.com/org/b", False, ()), bundled_plugin=str(bundled)
    )
    other = fingerprint_for(
        cfg, "p", Scope("github.com/org/c", False, ()), bundled_plugin=str(bundled)
    )
    assert over != glob
    assert same == glob  # only a timeout was overridden
    assert other == glob
    indeterminate = fingerprint_for(cfg, "p", Scope("*", True, ()), bundled_plugin=str(bundled))
    assert indeterminate == glob


# --- stability --------------------------------------------------------------------------


def test_stable_across_processes_and_working_directories(tmp_path: Path, bundled: Path) -> None:
    cfg_doc = {"policies": {"p": policy_doc(agent_check(), script_check("/no/such", "rel"))}}
    cfg = load(tmp_path, cfg_doc)
    want = fingerprint("p", cfg.resolve_policy("p"), cfg.shared, bundled_plugin=str(bundled))
    cwd = tmp_path / "elsewhere"
    cwd.mkdir()
    code = (
        "import sys\n"
        "from gatectl.config import load_config\n"
        "from gatectl.fingerprint import fingerprint\n"
        "c = load_config(sys.argv[1], environ={})\n"
        "print(fingerprint('p', c.resolve_policy('p'), c.shared, bundled_plugin=sys.argv[2]))\n"
    )
    from gatectl.gateway import ChildSpec

    env = {
        "PYTHONPATH": os.pathsep.join(p for p in sys.path if p),
        "PYTHONHASHSEED": "12345",
        "HOME": str(tmp_path / "home"),
        "LC_ALL": "C",
    }
    spec = ChildSpec(
        (sys.executable, "-c", code, str(tmp_path / "cfg" / "config.yaml"), str(bundled)),
        stdin=Stdio.DEVNULL,
        stdout=Stdio.PIPE,
        stderr=Stdio.DEVNULL,
        cwd=str(cwd),
        env=env,
    )
    child = SubprocessGateway().start(spec)
    assert child.stdout is not None
    out = read_capped(child.stdout, 4096).data.decode().strip()
    assert child.wait(timeout=60) == 0
    assert out == want


# --- pinned vectors ----------------------------------------------------------------------

VECTOR_RULES = {
    "name": "r",
    "type": "rule",
    "when": [{"path": "a.b", "op": "eq", "value": 1}],
    "then": "deny",
}


def test_pinned_vector_rule_and_script(tmp_path: Path, bundled: Path) -> None:
    doc = policy_doc(
        VECTOR_RULES,
        script_check("/nonexistent/check", "--x", env_allow=["TOKEN"], timeout="5s"),
        input={"require": ["a"], "types": {"a": "object"}, "ignore": ["ts"]},
        applies_when=[{"path": "tool", "op": "eq", "value": "Bash"}],
    )
    assert (
        fp(tmp_path, bundled, doc)
        == "sha256:30ceebdf53768d7be4d7a4db9aac72d3bbb5487e1d3c9ad2254f909be321ede1"
    )


def test_pinned_vector_agent(tmp_path: Path, bundled: Path) -> None:
    shared = {"agent": {"model": "haiku"}}
    doc = policy_doc(agent_check(instruction="Deny anything that deletes data."))
    assert (
        fp(tmp_path, bundled, doc, shared=shared)
        == "sha256:9b228f842feffadae7d8477c35d22f53b393ec9e6c9074195ef06908ecb03a1c"
    )


def test_pinned_definition_text(tmp_path: Path, bundled: Path) -> None:
    cfg = load(tmp_path, {"policies": {"p": policy_doc(VECTOR_RULES)}})
    d = definition("p", cfg.resolve_policy("p"), cfg.shared, bundled_plugin=str(bundled))
    assert json.dumps(d, sort_keys=True, separators=(",", ":")) == (
        '{"checks":[{"else":"allow","name":"r","then":"deny","type":"rule",'
        '"when":[{"op":"eq","path":"a.b","value":1}]}],'
        '"input":{"ignore":[],"require":[],"types":{}},"policy":"p"}'
    )


# --- review round 1 ---------------------------------------------------------------------


def skill_files_of(
    tmp_path: Path, bundled: Path, skill: str, shared: dict[str, Any] | None = None
) -> dict[str, Any]:
    doc = policy_doc(agent_check(skill=skill))
    cfg = load(tmp_path, {**(shared or {}), "policies": {"p": doc}})
    d = definition("p", cfg.resolve_policy("p"), cfg.shared, bundled_plugin=str(bundled))
    return d["checks"][0]["skill_files"]


def test_hostile_deeply_nested_plugin_json_does_not_raise(tmp_path: Path, bundled: Path) -> None:
    (bundled / ".claude-plugin" / "plugin.json").write_bytes(b"[" * 60000)
    assert set(skill_files_of(tmp_path, bundled, "gatectl:gate-check").values()) == {UNREADABLE}
    other = make_plugin(tmp_path / "other", name="other")
    (other / ".claude-plugin" / "plugin.json").write_bytes(b"[" * 60000)
    files = skill_files_of(
        tmp_path, bundled, "other:gate-check", {"agent": {"plugin_dirs": [str(other)]}}
    )
    assert set(files.values()) == {UNREADABLE}


def test_null_check_model_and_profile_inherit_the_block_value(
    tmp_path: Path, bundled: Path
) -> None:
    shared = {"agent": {"model": "haiku", "permission_profile": str(bundled / "x.json")}}
    (bundled / "x.json").write_bytes(b"{}")
    absent = fp(tmp_path, bundled, policy_doc(agent_check()), shared=shared)
    null = agent_check(model=None, permission_profile=None)
    assert fp(tmp_path, bundled, policy_doc(null), shared=shared) == absent
    own = agent_check(model="haiku", permission_profile=str(bundled / "x.json"))
    assert fp(tmp_path, bundled, policy_doc(own), shared=shared) == absent


def test_plugin_json_of_100_kib_resolves(tmp_path: Path, bundled: Path) -> None:
    doc = {"name": "gatectl", "pad": "x" * (100 * 1024)}
    (bundled / ".claude-plugin" / "plugin.json").write_text(json.dumps(doc))
    assert UNREADABLE not in skill_files_of(tmp_path, bundled, "gatectl:gate-check").values()


def test_plugin_json_over_1_mib_is_not_found(tmp_path: Path, bundled: Path) -> None:
    doc = {"name": "gatectl", "pad": "x" * (1024 * 1024)}
    (bundled / ".claude-plugin" / "plugin.json").write_text(json.dumps(doc))
    assert set(skill_files_of(tmp_path, bundled, "gatectl:gate-check").values()) == {UNREADABLE}


def test_fifo_plugin_json_returns_promptly(tmp_path: Path, bundled: Path) -> None:
    pj = bundled / ".claude-plugin" / "plugin.json"
    pj.unlink()
    os.mkfifo(pj)
    assert set(skill_files_of(tmp_path, bundled, "gatectl:gate-check").values()) == {UNREADABLE}


def test_plugin_json_symlink_to_dev_zero_returns_promptly(tmp_path: Path, bundled: Path) -> None:
    pj = bundled / ".claude-plugin" / "plugin.json"
    pj.unlink()
    pj.symlink_to("/dev/zero")
    assert set(skill_files_of(tmp_path, bundled, "gatectl:gate-check").values()) == {UNREADABLE}


def test_same_size_rewrite_restoring_mtime_during_read_is_unreadable(
    tmp_path: Path, bundled: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    f = tmp_path / "torn"
    f.write_bytes(b"a" * 100)
    st = f.stat()
    real_read = os.read

    def read(fd: int, n: int) -> bytes:
        data = real_read(fd, n)
        if data and os.fstat(fd).st_ino == st.st_ino:
            f.write_bytes(b"b" * 100)
            os.utime(f, ns=(st.st_atime_ns, st.st_mtime_ns))
        return data

    monkeypatch.setattr(fpmod.os, "read", read)
    assert argv_files(tmp_path, bundled, str(f)) == [UNREADABLE]


def test_rewrite_between_the_two_passes_is_unreadable(
    tmp_path: Path, bundled: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    f = tmp_path / "between"
    f.write_bytes(b"a" * 100)
    real_stat = os.stat
    calls = {"n": 0}

    def stat(path: Any, *a: Any, **k: Any) -> os.stat_result:
        if str(path) == str(f):
            calls["n"] += 1
            if calls["n"] == 2:  # the start of the second pass
                f.write_bytes(b"b" * 100)
        return real_stat(path, *a, **k)

    monkeypatch.setattr(fpmod.os, "stat", stat)
    assert argv_files(tmp_path, bundled, str(f)) == [UNREADABLE]
    assert calls["n"] >= 2


def test_recently_written_file_is_still_hashed(tmp_path: Path, bundled: Path) -> None:
    f = tmp_path / "fresh"
    f.write_bytes(b"fresh")
    assert argv_files(tmp_path, bundled, str(f)) == [hashlib.sha256(b"fresh").hexdigest()]
