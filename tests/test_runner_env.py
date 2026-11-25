"""The environment a script check receives is built from an allowlist, never inherited."""

from __future__ import annotations

import pytest

from gatectl.runner import build_env

DEFAULTS = ["PATH", "HOME", "LANG", "LC_*"]
ENVIRON = {
    "PATH": "/usr/bin:/bin",
    "HOME": "/home/u",
    "LANG": "en_US.UTF-8",
    "LC_ALL": "C",
    "LC_CTYPE": "C.UTF-8",
    "LCX": "not a match",
    "GITHUB_TOKEN": "ghp_secret",
    "ANTHROPIC_API_KEY": "sk-secret",
    "AWS_SECRET_ACCESS_KEY": "aws-secret",
    "SCOPE_DIR": "/srv/scope",
    "GATECTL_TIMEOUT": "5s",
}


def test_defaults_pass_only_the_allowlisted_names() -> None:
    env = build_env(ENVIRON, DEFAULTS)
    assert env == {
        "PATH": "/usr/bin:/bin",
        "HOME": "/home/u",
        "LANG": "en_US.UTF-8",
        "LC_ALL": "C",
        "LC_CTYPE": "C.UTF-8",
    }


@pytest.mark.parametrize("name", ["GITHUB_TOKEN", "ANTHROPIC_API_KEY", "AWS_SECRET_ACCESS_KEY"])
def test_token_variables_never_reach_a_check_unless_named(name: str) -> None:
    assert name not in build_env(ENVIRON, DEFAULTS)
    assert name not in build_env(ENVIRON, DEFAULTS, ["SCOPE_DIR"])
    assert build_env(ENVIRON, DEFAULTS, [name])[name] == ENVIRON[name]


def test_a_check_adds_exact_names() -> None:
    env = build_env(ENVIRON, DEFAULTS, ["SCOPE_DIR"])
    assert env["SCOPE_DIR"] == "/srv/scope"
    assert "GATECTL_TIMEOUT" not in env


def test_names_are_case_sensitive_and_exact() -> None:
    assert "SCOPE_DIR" not in build_env(ENVIRON, DEFAULTS, ["scope_dir"])
    assert "SCOPE_DIR" not in build_env(ENVIRON, DEFAULTS, ["SCOPE"])


def test_an_allowed_name_that_is_unset_stays_unset_not_empty() -> None:
    assert "NOPE" not in build_env({}, DEFAULTS, ["NOPE"])


def test_prefix_pattern_only_in_the_defaults() -> None:
    assert build_env(ENVIRON, ["PATH", "GATECTL_*"])["GATECTL_TIMEOUT"] == "5s"
    with pytest.raises(ValueError, match="env_allow"):
        build_env(ENVIRON, DEFAULTS, ["GATECTL_*"])


@pytest.mark.parametrize("bad", ["", "*", "1X", "A=B", "A-B", "A B", "A\n", "Å", "A*B", "$X"])
def test_a_checks_names_follow_the_grammar(bad: str) -> None:
    with pytest.raises(ValueError, match="env_allow"):
        build_env(ENVIRON, DEFAULTS, [bad])


@pytest.mark.parametrize("bad", ["", "*", "1X*", "A=B*", "A**", "*A", "A*B"])
def test_a_default_pattern_follows_its_grammar(bad: str) -> None:
    with pytest.raises(ValueError, match="script_env_allow"):
        build_env(ENVIRON, [bad])


def test_an_empty_default_list_passes_only_the_checks_names() -> None:
    assert build_env(ENVIRON, [], ["SCOPE_DIR"]) == {"SCOPE_DIR": "/srv/scope"}
    assert build_env(ENVIRON, []) == {}


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("/usr/bin:/bin", "/usr/bin:/bin"),
        ("/usr/bin::/bin:", "/usr/bin:/bin"),
        (":/usr/bin", "/usr/bin"),
        ("./bin:/usr/bin:bin:../x:/bin", "/usr/bin:/bin"),
        ("/a:.:/b", "/a:/b"),
        ("/with space:/ok", "/with space:/ok"),
    ],
)
def test_path_loses_empty_and_relative_entries(path: str, expected: str) -> None:
    assert build_env({"PATH": path}, DEFAULTS)["PATH"] == expected


@pytest.mark.parametrize("path", ["", ":", "::", "bin", "./x:../y", "."])
def test_path_with_nothing_absolute_left_is_omitted_never_empty(path: str) -> None:
    # An empty PATH can mean "the current directory" to a shell, so it is never passed.
    assert "PATH" not in build_env({"PATH": path}, DEFAULTS)


def test_path_is_cleaned_when_a_check_names_it_too() -> None:
    env = build_env({"PATH": "rel:/abs"}, [], ["PATH"])
    assert env == {"PATH": "/abs"}


def test_path_is_absent_when_not_allowed() -> None:
    assert "PATH" not in build_env({"PATH": "/bin"}, ["HOME"])


def test_values_are_passed_verbatim() -> None:
    odd = "line1\nline2 \u00e9 \udcff"
    assert build_env({"HOME": odd}, DEFAULTS)["HOME"] == odd


def test_the_input_is_not_mutated_and_the_result_is_independent() -> None:
    environ = dict(ENVIRON)
    env = build_env(environ, DEFAULTS)
    env["X"] = "1"
    assert environ == ENVIRON
