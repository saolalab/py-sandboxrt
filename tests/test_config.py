"""Tests for configuration handling."""

from srt import FilesystemConfig, NetworkConfig, SandboxRuntimeConfig


class TestNetworkConfig:
    """Tests for NetworkConfig."""

    def test_default_config(self):
        """Test default network configuration."""
        config = NetworkConfig()
        assert config.allowed_domains == []
        assert config.denied_domains == []

    def test_custom_config(self, sample_network_config):
        """Test network configuration with custom values."""
        config = NetworkConfig(**sample_network_config)
        assert "example.com" in config.allowed_domains
        assert "malicious.com" in config.denied_domains

    def test_wildcard_domains(self):
        """Test wildcard domain patterns."""
        config = NetworkConfig(allowed_domains=["*.example.com"])
        assert "*.example.com" in config.allowed_domains


class TestFilesystemConfig:
    """Tests for FilesystemConfig."""

    def test_default_config(self):
        """Test default filesystem configuration."""
        config = FilesystemConfig()
        assert config.deny_read == []
        assert config.allow_write == []
        assert config.deny_write == []

    def test_custom_config(self, sample_filesystem_config):
        """Test filesystem configuration with custom values."""
        config = FilesystemConfig(**sample_filesystem_config)
        assert "~/.ssh" in config.deny_read
        assert "." in config.allow_write
        assert ".env" in config.deny_write


class TestSandboxRuntimeConfig:
    """Tests for SandboxRuntimeConfig."""

    def test_default_config(self):
        """Test default sandbox runtime configuration."""
        config = SandboxRuntimeConfig()
        assert config.network is not None
        assert config.filesystem is not None

    def test_full_config(self, sample_network_config, sample_filesystem_config):
        """Test full sandbox runtime configuration."""
        config = SandboxRuntimeConfig(
            network=NetworkConfig(**sample_network_config),
            filesystem=FilesystemConfig(**sample_filesystem_config),
        )
        assert "example.com" in config.network.allowed_domains
        assert "~/.ssh" in config.filesystem.deny_read
