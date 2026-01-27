"""Tests for Ory configuration models."""

import pytest
from bindu.auth.ory_config import (
    HydraConfig,
    KratosConfig,
    OAuthProviderConfig,
    OryConfig,
)


class TestHydraConfig:
    """Test Hydra configuration."""

    def test_default_config(self):
        """Test default Hydra configuration."""
        config = HydraConfig()
        assert config.enabled is True
        assert config.timeout == 10
        assert config.verify_ssl is False


class TestKratosConfig:
    """Test Kratos configuration."""

    def test_default_config(self):
        """Test default Kratos configuration."""
        config = KratosConfig()
        assert config.enabled is True
        assert config.timeout == 10

    def test_valid_encryption_key(self):
        """Test valid encryption key."""
        key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="  # pragma: allowlist secret
        config = KratosConfig(encryption_key=key)
        assert config.encryption_key == key

    def test_invalid_encryption_key(self):
        """Test invalid encryption key."""
        with pytest.raises(ValueError):
            KratosConfig(encryption_key="invalid")  # pragma: allowlist secret


class TestOAuthProviderConfig:
    """Test OAuth provider configuration."""

    def test_provider_config(self):
        """Test OAuth provider configuration."""
        config = OAuthProviderConfig(
            name="github",
            client_id="test_id",  # pragma: allowlist secret
            client_secret="test_secret",  # pragma: allowlist secret
            auth_url="https://github.com/login/oauth/authorize",
            token_url="https://github.com/login/oauth/access_token",
            scope="read:user",
            redirect_uri="http://localhost:3000/callback",
        )
        assert config.name == "github"


class TestOryConfig:
    """Test Ory configuration."""

    def test_default_config(self):
        """Test default Ory configuration."""
        config = OryConfig()
        assert config.enable_m2m_auth is True
        assert len(config.public_endpoints) > 0

    def test_validate_config_missing_encryption_key(self):
        """Test validation with missing encryption key."""
        config = OryConfig(
            enable_credential_storage=True,
            kratos=KratosConfig(encryption_key=None),
        )
        errors = config.validate_config()
        assert len(errors) > 0

    def test_get_provider_config(self):
        """Test getting provider configuration."""
        provider = OAuthProviderConfig(
            name="github",
            client_id="id",  # pragma: allowlist secret
            client_secret="secret",  # pragma: allowlist secret
            auth_url="https://github.com/login/oauth/authorize",
            token_url="https://github.com/login/oauth/access_token",
            scope="read:user",
            redirect_uri="http://localhost:3000/callback",
        )
        config = OryConfig(oauth_providers={"github": provider})
        result = config.get_provider_config("github")
        assert result is not None
        assert result.name == "github"
