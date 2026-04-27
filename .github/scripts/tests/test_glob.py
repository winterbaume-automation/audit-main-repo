"""Glob translation tests — these underpin the entire classification layer."""

import pytest

from audit_commit import _glob_to_regex


@pytest.mark.parametrize("pattern,path,expected", [
    # **/X matches root-level X and any depth
    ("**/Cargo.toml", "Cargo.toml", True),
    ("**/Cargo.toml", "crates/foo/Cargo.toml", True),
    ("**/Cargo.toml", "Cargo.tomlx", False),
    ("**/Cargo.toml", "xCargo.toml", False),
    # exact path
    (".gitattributes", ".gitattributes", True),
    (".gitattributes", "subdir/.gitattributes", False),
    # trailing **
    ("tools/sccache-wrapper/**", "tools/sccache-wrapper/src/main.rs", True),
    ("tools/sccache-wrapper/**", "tools/sccache-wrapper/", True),
    ("tools/sccache-wrapper/**", "tools/other/main.rs", False),
    # mid-path **
    ("**/auth/**", "crates/foo/auth/lib.rs", True),
    ("**/auth/**", "auth/lib.rs", True),
    ("**/auth/**", "crates/foo/authentication.rs", False),
    # single * does NOT cross /
    ("crates/*.rs", "crates/foo.rs", True),
    ("crates/*.rs", "crates/foo/bar.rs", False),
    # extension
    ("**/*.lock", "Cargo.lock", True),
    ("**/*.lock", "a/b/c.lock", True),
    ("**/*.lock", "Cargo.toml", False),
    # ? matches one non-/ char
    ("a?b", "axb", True),
    ("a?b", "a/b", False),
    # special chars escaped
    ("file.with.dots", "file.with.dots", True),
    ("file.with.dots", "fileXwithXdots", False),
])
def test_glob_to_regex(pattern, path, expected):
    rx = _glob_to_regex(pattern)
    assert (rx.match(path) is not None) is expected, (pattern, path, expected)
