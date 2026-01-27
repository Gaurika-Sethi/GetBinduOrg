"""Tests for token utility functions."""

import pytest
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

from bindu.auth.token_utils import (
    get_client_credentials_token,
    get_agent_token_from_credentials_file,
    introspect_token,
    revoke_token,
    create_bearer_header,
    validate_token_and_get_subject,
)


class TestGetClientCredentialsToken:
    """Test getting client credentials token."""

    @pytest.mark.asyncio
    async def test_get_token_success(self):
        """Test successfully getting a token."""
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.json = AsyncMock(
            return_value={
                "access_token": "test_token_123",  # pragma: allowlist secret
                "token_type": "Bearer",
                "expires_in": 3600,
            }
        )

        with patch(
            "bindu.auth.token_utils.aiohttp.ClientSession"
        ) as mock_session_class:
            mock_session = MagicMock()
            mock_session.__aenter__ = AsyncMock(return_value=mock_session)
            mock_session.__aexit__ = AsyncMock(return_value=None)

            mock_post_context = MagicMock()
            mock_post_context.__aenter__ = AsyncMock(return_value=mock_response)
            mock_post_context.__aexit__ = AsyncMock(return_value=None)
            mock_session.post = MagicMock(return_value=mock_post_context)

            mock_session_class.return_value = mock_session

            result = await get_client_credentials_token(
                "test-client",
                "test-secret",
                "agent:read agent:write",  # pragma: allowlist secret
            )

            assert result is not None
            assert (
                result["access_token"] == "test_token_123"
            )  # pragma: allowlist secret
            assert result["token_type"] == "Bearer"
            assert result["expires_in"] == 3600

    @pytest.mark.asyncio
    async def test_get_token_without_scope(self):
        """Test getting token without specifying scope."""
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.json = AsyncMock(
            return_value={
                "access_token": "test_token",  # pragma: allowlist secret
                "token_type": "Bearer",
                "expires_in": 3600,
            }
        )

        with patch(
            "bindu.auth.token_utils.aiohttp.ClientSession"
        ) as mock_session_class:
            mock_session = MagicMock()
            mock_session.__aenter__ = AsyncMock(return_value=mock_session)
            mock_session.__aexit__ = AsyncMock(return_value=None)

            mock_post_context = MagicMock()
            mock_post_context.__aenter__ = AsyncMock(return_value=mock_response)
            mock_post_context.__aexit__ = AsyncMock(return_value=None)
            mock_session.post = MagicMock(return_value=mock_post_context)

            mock_session_class.return_value = mock_session

            result = await get_client_credentials_token(
                "test-client", "test-secret"
            )  # pragma: allowlist secret

            assert result is not None
            assert "access_token" in result

    @pytest.mark.asyncio
    async def test_get_token_failure(self):
        """Test handling token request failure."""
        mock_response = AsyncMock()
        mock_response.status = 401
        mock_response.text = AsyncMock(return_value="Unauthorized")

        with patch(
            "bindu.auth.token_utils.aiohttp.ClientSession"
        ) as mock_session_class:
            mock_session = MagicMock()
            mock_session.__aenter__ = AsyncMock(return_value=mock_session)
            mock_session.__aexit__ = AsyncMock(return_value=None)

            mock_post_context = MagicMock()
            mock_post_context.__aenter__ = AsyncMock(return_value=mock_response)
            mock_post_context.__aexit__ = AsyncMock(return_value=None)
            mock_session.post = MagicMock(return_value=mock_post_context)

            mock_session_class.return_value = mock_session

            result = await get_client_credentials_token(
                "invalid-client", "invalid-secret"
            )  # pragma: allowlist secret

            assert result is None

    @pytest.mark.asyncio
    async def test_get_token_exception(self):
        """Test handling exception during token request."""
        with patch(
            "bindu.auth.token_utils.aiohttp.ClientSession"
        ) as mock_session_class:
            mock_session_class.side_effect = Exception("Connection error")

            result = await get_client_credentials_token(
                "test-client", "test-secret"
            )  # pragma: allowlist secret

            assert result is None


class TestGetAgentTokenFromCredentialsFile:
    """Test getting agent token from credentials file."""

    @pytest.mark.asyncio
    async def test_get_agent_token_success(self):
        """Test successfully getting agent token."""
        mock_credentials = MagicMock()
        mock_credentials.client_id = "test-client"
        mock_credentials.client_secret = "test-secret"  # pragma: allowlist secret
        mock_credentials.scopes = ["agent:read", "agent:write"]

        with patch(
            "bindu.auth.token_utils.load_agent_credentials",
            return_value=mock_credentials,
        ):
            with patch(
                "bindu.auth.token_utils.get_client_credentials_token",
                new=AsyncMock(
                    return_value={
                        "access_token": "agent_token",  # pragma: allowlist secret
                        "token_type": "Bearer",
                    }
                ),
            ):
                token = await get_agent_token_from_credentials_file(
                    "test-agent", Path("/tmp/.bindu")
                )

                assert token == "agent_token"  # pragma: allowlist secret

    @pytest.mark.asyncio
    async def test_get_agent_token_no_credentials(self):
        """Test when no credentials found."""
        with patch("bindu.utils.token_utils.load_agent_credentials", return_value=None):
            token = await get_agent_token_from_credentials_file(
                "test-agent", Path("/tmp/.bindu")
            )

            assert token is None

    @pytest.mark.asyncio
    async def test_get_agent_token_request_fails(self):
        """Test when token request fails."""
        mock_credentials = MagicMock()
        mock_credentials.client_id = "test-client"
        mock_credentials.client_secret = "test-secret"  # pragma: allowlist secret
        mock_credentials.scopes = ["agent:read"]

        with patch(
            "bindu.auth.token_utils.load_agent_credentials",
            return_value=mock_credentials,
        ):
            with patch(
                "bindu.auth.token_utils.get_client_credentials_token",
                new=AsyncMock(return_value=None),
            ):
                token = await get_agent_token_from_credentials_file(
                    "test-agent", Path("/tmp/.bindu")
                )

                assert token is None


class TestIntrospectToken:
    """Test token introspection."""

    @pytest.mark.asyncio
    async def test_introspect_token_success(self):
        """Test successfully introspecting a token."""
        mock_hydra = AsyncMock()
        mock_hydra.introspect_token = AsyncMock(
            return_value={"active": True, "sub": "test-user"}
        )

        with patch("bindu.auth.hydra_client.HydraClient") as mock_client_class:
            mock_client_class.return_value.__aenter__.return_value = mock_hydra
            mock_client_class.return_value.__aexit__.return_value = None

            result = await introspect_token("test_token")  # pragma: allowlist secret

            assert result is not None
            assert result["active"] is True
            assert result["sub"] == "test-user"

    @pytest.mark.asyncio
    async def test_introspect_token_exception(self):
        """Test handling exception during introspection."""
        with patch("bindu.auth.hydra_client.HydraClient") as mock_client_class:
            mock_client_class.side_effect = Exception("Connection error")

            result = await introspect_token("test_token")  # pragma: allowlist secret

            assert result is None


class TestRevokeToken:
    """Test token revocation."""

    @pytest.mark.asyncio
    async def test_revoke_token_success(self):
        """Test successfully revoking a token."""
        mock_hydra = AsyncMock()
        mock_hydra.revoke_token = AsyncMock(return_value=True)

        with patch("bindu.auth.hydra_client.HydraClient") as mock_client_class:
            mock_client_class.return_value.__aenter__.return_value = mock_hydra
            mock_client_class.return_value.__aexit__.return_value = None

            result = await revoke_token("test_token")  # pragma: allowlist secret

            assert result is True

    @pytest.mark.asyncio
    async def test_revoke_token_exception(self):
        """Test handling exception during revocation."""
        with patch("bindu.auth.hydra_client.HydraClient") as mock_client_class:
            mock_client_class.side_effect = Exception("Connection error")

            result = await revoke_token("test_token")  # pragma: allowlist secret

            assert result is False


class TestCreateBearerHeader:
    """Test creating bearer header."""

    def test_create_bearer_header(self):
        """Test creating authorization header."""
        header = create_bearer_header("test_token_123")  # pragma: allowlist secret

        assert header == {
            "Authorization": "Bearer test_token_123"
        }  # pragma: allowlist secret


class TestValidateTokenAndGetSubject:
    """Test token validation and subject extraction."""

    @pytest.mark.asyncio
    async def test_validate_active_token(self):
        """Test validating an active token."""
        with patch(
            "bindu.auth.token_utils.introspect_token",
            new=AsyncMock(return_value={"active": True, "sub": "user-123"}),
        ):
            subject = await validate_token_and_get_subject(
                "test_token"
            )  # pragma: allowlist secret

            assert subject == "user-123"

    @pytest.mark.asyncio
    async def test_validate_inactive_token(self):
        """Test validating an inactive token."""
        with patch(
            "bindu.auth.token_utils.introspect_token",
            new=AsyncMock(return_value={"active": False}),
        ):
            subject = await validate_token_and_get_subject(
                "test_token"
            )  # pragma: allowlist secret

            assert subject is None

    @pytest.mark.asyncio
    async def test_validate_token_introspection_fails(self):
        """Test when introspection fails."""
        with patch(
            "bindu.auth.token_utils.introspect_token",
            new=AsyncMock(return_value=None),
        ):
            subject = await validate_token_and_get_subject(
                "test_token"
            )  # pragma: allowlist secret

            assert subject is None
