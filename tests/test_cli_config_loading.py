"""
Tests for CLI config file loading.

Ported from: test/cli-config-loading.test.ts
"""

from __future__ import annotations

import json
import os
import tempfile

from srt.config import load_config, load_config_from_string


class TestLoadConfig:
    def setup_method(self):
        self.tmp_dir = tempfile.mkdtemp()
        self.config_path = os.path.join(self.tmp_dir, "config.json")

    def teardown_method(self):
        import shutil

        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_returns_none_when_file_not_exists(self):
        result = load_config("/nonexistent/path/config.json")
        assert result is None

    def test_returns_none_for_empty_file(self):
        with open(self.config_path, "w") as f:
            f.write("")
        result = load_config(self.config_path)
        assert result is None

    def test_returns_none_for_whitespace_only(self):
        with open(self.config_path, "w") as f:
            f.write("  \n\t ")
        result = load_config(self.config_path)
        assert result is None

    def test_returns_none_for_invalid_json(self):
        with open(self.config_path, "w") as f:
            f.write("{ invalid json }")
        result = load_config(self.config_path)
        assert result is None

    def test_partial_schema_gets_defaults(self):
        """Pydantic fills defaults for partial configs."""
        with open(self.config_path, "w") as f:
            json.dump({"network": {}}, f)
        result = load_config(self.config_path)
        assert result is not None
        assert result.network.allowed_domains == []

    def test_returns_valid_config(self):
        valid = {
            "network": {"allowedDomains": ["example.com"], "deniedDomains": []},
            "filesystem": {"denyRead": [], "allowWrite": [], "denyWrite": []},
        }
        with open(self.config_path, "w") as f:
            json.dump(valid, f)
        result = load_config(self.config_path)
        assert result is not None
        assert "example.com" in result.network.allowed_domains


class TestLoadConfigFromString:
    def test_returns_none_for_empty_string(self):
        assert load_config_from_string("") is None

    def test_returns_none_for_whitespace(self):
        assert load_config_from_string("  \n\t ") is None

    def test_returns_none_for_invalid_json(self):
        assert load_config_from_string("{ invalid json }") is None

    def test_partial_schema_gets_defaults(self):
        """Pydantic fills defaults for partial configs."""
        result = load_config_from_string(json.dumps({"network": {}}))
        assert result is not None
        assert result.network.allowed_domains == []

    def test_returns_valid_config(self):
        valid = {
            "network": {"allowedDomains": ["example.com"], "deniedDomains": []},
            "filesystem": {"denyRead": [], "allowWrite": [], "denyWrite": []},
        }
        result = load_config_from_string(json.dumps(valid))
        assert result is not None
        assert "example.com" in result.network.allowed_domains
