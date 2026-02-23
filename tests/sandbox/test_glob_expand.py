"""
Tests for glob expansion and globToRegex.

Ported from: test/sandbox/glob-expand.test.ts
"""

from __future__ import annotations

import os
import re

import pytest

from srt.sandbox_utils import expand_glob_pattern, glob_to_regex


def _real_path(p: str) -> str:
    try:
        return os.path.realpath(p)
    except OSError:
        return p


class TestExpandGlobPattern:
    """Tests for expand_glob_pattern()."""

    @pytest.fixture(autouse=True)
    def setup_tree(self, tmp_path):
        self.raw_test_dir = str(tmp_path / "testdir")
        os.makedirs(os.path.join(self.raw_test_dir, "subdir", "deeper"), exist_ok=True)

        for name, content in [
            ("token.env", "TOKEN=secret"),
            ("secrets.env", "SECRET=value"),
            ("readme.txt", "readme content"),
            ("config.json", "{}"),
        ]:
            with open(os.path.join(self.raw_test_dir, name), "w") as f:
                f.write(content)

        with open(os.path.join(self.raw_test_dir, "subdir", "nested.env"), "w") as f:
            f.write("NESTED=secret")
        with open(os.path.join(self.raw_test_dir, "subdir", "deep.txt"), "w") as f:
            f.write("deep content")
        with open(os.path.join(self.raw_test_dir, "subdir", "deeper", "bottom.env"), "w") as f:
            f.write("BOTTOM=secret")

        self.test_dir = _real_path(self.raw_test_dir)

    def test_star_env_matches_only_top_level(self):
        results = expand_glob_pattern(os.path.join(self.raw_test_dir, "*.env"))
        assert os.path.join(self.test_dir, "token.env") in results
        assert os.path.join(self.test_dir, "secrets.env") in results
        assert os.path.join(self.test_dir, "readme.txt") not in results
        assert os.path.join(self.test_dir, "subdir", "nested.env") not in results
        assert len(results) == 2

    def test_globstar_env_recursive(self):
        results = expand_glob_pattern(os.path.join(self.raw_test_dir, "**/*.env"))
        assert os.path.join(self.test_dir, "token.env") in results
        assert os.path.join(self.test_dir, "secrets.env") in results
        assert os.path.join(self.test_dir, "subdir", "nested.env") in results
        assert os.path.join(self.test_dir, "subdir", "deeper", "bottom.env") in results
        assert os.path.join(self.test_dir, "readme.txt") not in results
        assert len(results) == 4

    def test_globstar_matches_all(self):
        results = expand_glob_pattern(os.path.join(self.raw_test_dir, "**"))
        assert len(results) > 0
        assert os.path.join(self.test_dir, "token.env") in results
        assert os.path.join(self.test_dir, "readme.txt") in results

    def test_nonexistent_base_returns_empty(self):
        results = expand_glob_pattern("/nonexistent/path/*.env")
        assert results == []

    def test_no_match_returns_empty(self):
        results = expand_glob_pattern(os.path.join(self.raw_test_dir, "*.xyz"))
        assert results == []

    def test_star_matches_dirs_and_files(self):
        results = expand_glob_pattern(os.path.join(self.raw_test_dir, "*"))
        assert os.path.join(self.test_dir, "token.env") in results
        assert os.path.join(self.test_dir, "subdir") in results

    def test_question_mark_wildcard(self):
        results = expand_glob_pattern(os.path.join(self.raw_test_dir, "*.tx?"))
        assert os.path.join(self.test_dir, "readme.txt") in results
        assert os.path.join(self.test_dir, "token.env") not in results

    def test_partial_name_glob(self):
        results = expand_glob_pattern(os.path.join(self.raw_test_dir, "secret*.env"))
        assert os.path.join(self.test_dir, "secrets.env") in results
        assert os.path.join(self.test_dir, "token.env") not in results


class TestGlobToRegex:
    """Tests for glob_to_regex() shared utility."""

    def test_simple_wildcard(self):
        regex = glob_to_regex("/tmp/test/*.env")
        assert re.match(regex, "/tmp/test/token.env")
        assert re.match(regex, "/tmp/test/secrets.env")
        assert not re.match(regex, "/tmp/test/readme.txt")
        assert not re.match(regex, "/tmp/test/sub/token.env")

    def test_globstar_pattern(self):
        regex = glob_to_regex("/tmp/test/**/*.env")
        assert re.match(regex, "/tmp/test/token.env")
        assert re.match(regex, "/tmp/test/sub/token.env")
        assert re.match(regex, "/tmp/test/sub/deep/token.env")
        assert not re.match(regex, "/tmp/test/readme.txt")

    def test_question_wildcard(self):
        regex = glob_to_regex("/tmp/test/file?.txt")
        assert re.match(regex, "/tmp/test/file1.txt")
        assert re.match(regex, "/tmp/test/fileA.txt")
        assert not re.match(regex, "/tmp/test/file12.txt")
        assert not re.match(regex, "/tmp/test/file/.txt")

    def test_globstar_without_trailing_slash(self):
        regex = glob_to_regex("/tmp/test/**")
        assert re.match(regex, "/tmp/test/anything")
        assert re.match(regex, "/tmp/test/sub/deep/file.txt")
