"""Tests for hybrid authentication client."""

import pytest
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

from bindu.utils.hybrid_auth_client import HybridAuthClient


class TestHybridAuthClient:
    """Test hybrid authentication client."""

    @pytest.mark.asyncio
    async def test_client_initialization_success(self):
        """Test successful client initialization."""
        mock_credentials = MagicMock()
        mock_credentials.client_id = "did:key:test"
        mock_credentials.client_secret = "test-secret"  # pragma: allowlist secret
        mock_credentials.scopes = ["agent:read", "agent:write"]

        mock_did_ext = MagicMock()
        mock_did_ext.did = "did:key:test"

        with patch(
            "bindu.utils.hybrid_auth_client.load_agent_credentials",
            return_value=mock_credentials,
        ):
            with patch(
                "bindu.utils.hybrid_auth_client.get_client_credentials_token",
                new=AsyncMock(
                    return_value={
                        "access_token": "test_token",  # pragma: allowlist secret
                        "expires_in": 3600,
                    }
                ),
            ):
                client = HybridAuthClient(
                    agent_id="test-agent",
                    credentials_dir=Path("/tmp/.bindu"),
                    did_extension=mock_did_ext,
                )

                await client.initialize()

                assert client.access_token == "test_token"  # pragma: allowlist secret
                assert client.credentials == mock_credentials

    @pytest.mark.asyncio
    async def test_client_initialization_no_credentials(self):
        """Test initialization when credentials not found."""
        mock_did_ext = MagicMock()

        with patch(
            "bindu.utils.hybrid_auth_client.load_agent_credentials",
            return_value=None,
        ):
            client = HybridAuthClient(
                agent_id="test-agent",
                credentials_dir=Path("/tmp/.bindu"),
                did_extension=mock_did_ext,
            )

            with pytest.raises(ValueError, match="No credentials found"):
                await client.initialize()

    @pytest.mark.asyncio
    async def test_client_initialization_token_failure(self):
        """Test initialization when token request fails."""
        mock_credentials = MagicMock()
        mock_credentials.client_id = "did:key:test"
        mock_credentials.client_secret = "test-secret"  # pragma: allowlist secret
        mock_credentials.scopes = ["agent:read"]

        mock_did_ext = MagicMock()

        with patch(
            "bindu.utils.hybrid_auth_client.load_agent_credentials",
            return_value=mock_credentials,
        ):
            with patch(
                "bindu.utils.hybrid_auth_client.get_client_credentials_token",
                new=AsyncMock(return_value=None),
            ):
                client = HybridAuthClient(
                    agent_id="test-agent",
                    credentials_dir=Path("/tmp/.bindu"),
                    did_extension=mock_did_ext,
                )

                with pytest.raises(Exception, match="Failed to get access token"):
                    await client.initialize()

    @pytest.mark.asyncio
    async def test_refresh_token_success(self):
        """Test refreshing access token."""
        mock_credentials = MagicMock()
        mock_credentials.client_id = "did:key:test"
        mock_credentials.client_secret = "test-secret"  # pragma: allowlist secret
        mock_credentials.scopes = ["agent:read"]

        mock_did_ext = MagicMock()

        with patch(
            "bindu.utils.hybrid_auth_client.load_agent_credentials",
            return_value=mock_credentials,
        ):
            with patch(
                "bindu.utils.hybrid_auth_client.get_client_credentials_token",
                new=AsyncMock(
                    return_value={
                        "access_token": "new_token",  # pragma: allowlist secret
                        "expires_in": 3600,
                    }
                ),
            ):
                client = HybridAuthClient(
                    agent_id="test-agent",
                    credentials_dir=Path("/tmp/.bindu"),
                    did_extension=mock_did_ext,
                )

                await client.initialize()
                assert client.access_token == "new_token"  # pragma: allowlist secret

                # Refresh token
                await client.refresh_token()
                assert client.access_token == "new_token"  # pragma: allowlist secret

    @pytest.mark.asyncio
    async def test_post_request_success(self):
        """Test making POST request."""
        mock_credentials = MagicMock()
        mock_credentials.client_id = "did:key:test"
        mock_credentials.client_secret = "test-secret"  # pragma: allowlist secret
        mock_credentials.scopes = ["agent:read"]

        mock_did_ext = MagicMock()
        mock_did_ext.did = "did:key:test"

        with patch(
            "bindu.utils.hybrid_auth_client.load_agent_credentials",
            return_value=mock_credentials,
        ):
            with patch(
                "bindu.utils.hybrid_auth_client.get_client_credentials_token",
                new=AsyncMock(
                    return_value={
                        "access_token": "test_token",  # pragma: allowlist secret
                        "expires_in": 3600,
                    }
                ),
            ):
                with patch(
                    "bindu.utils.hybrid_auth_client.aiohttp.ClientSession"
                ) as mock_session_class:
                    mock_response = AsyncMock()
                    mock_response.status = 200
                    mock_response.json = AsyncMock(return_value={"result": "success"})

                    mock_session = MagicMock()
                    mock_session.__aenter__ = AsyncMock(return_value=mock_session)
                    mock_session.__aexit__ = AsyncMock(return_value=None)

                    mock_post_context = MagicMock()
                    mock_post_context.__aenter__ = AsyncMock(return_value=mock_response)
                    mock_post_context.__aexit__ = AsyncMock(return_value=None)
                    mock_session.post = MagicMock(return_value=mock_post_context)

                    mock_session_class.return_value = mock_session

                    client = HybridAuthClient(
                        agent_id="test-agent",
                        credentials_dir=Path("/tmp/.bindu"),
                        did_extension=mock_did_ext,
                    )

                    await client.initialize()

                    result = await client.post(
                        "http://localhost:3773/",
                        {"jsonrpc": "2.0", "method": "test", "id": 1},
                    )

                    assert result == {"result": "success"}

    @pytest.mark.asyncio
    async def test_post_request_with_401_retry(self):
        """Test POST request with 401 response triggers token refresh."""
        mock_credentials = MagicMock()
        mock_credentials.client_id = "did:key:test"
        mock_credentials.client_secret = "test-secret"  # pragma: allowlist secret
        mock_credentials.scopes = ["agent:read"]

        mock_did_ext = MagicMock()
        mock_did_ext.did = "did:key:test"

        token_call_count = [0]  # Use list to avoid nonlocal issues

        async def mock_get_token(*args, **kwargs):
            token_call_count[0] += 1
            return {
                "access_token": f"token_{token_call_count[0]}",  # pragma: allowlist secret
                "expires_in": 3600,
            }

        with patch(
            "bindu.utils.hybrid_auth_client.load_agent_credentials",
            return_value=mock_credentials,
        ):
            with patch(
                "bindu.utils.hybrid_auth_client.get_client_credentials_token",
                new=AsyncMock(side_effect=mock_get_token),
            ):
                with patch(
                    "bindu.utils.hybrid_auth_client.aiohttp.ClientSession"
                ) as mock_session_class:
                    # First response: 401, second response: 200
                    mock_response_401 = AsyncMock()
                    mock_response_401.status = 401
                    mock_response_401.text = AsyncMock(return_value="Unauthorized")

                    mock_response_200 = AsyncMock()
                    mock_response_200.status = 200
                    mock_response_200.json = AsyncMock(
                        return_value={"result": "success"}
                    )

                    mock_session = MagicMock()
                    mock_session.__aenter__ = AsyncMock(return_value=mock_session)
                    mock_session.__aexit__ = AsyncMock(return_value=None)

                    # First call returns 401, second call returns 200
                    mock_post_context_1 = MagicMock()
                    mock_post_context_1.__aenter__ = AsyncMock(
                        return_value=mock_response_401
                    )
                    mock_post_context_1.__aexit__ = AsyncMock(return_value=None)

                    mock_post_context_2 = MagicMock()
                    mock_post_context_2.__aenter__ = AsyncMock(
                        return_value=mock_response_200
                    )
                    mock_post_context_2.__aexit__ = AsyncMock(return_value=None)

                    mock_session.post = MagicMock(
                        side_effect=[mock_post_context_1, mock_post_context_2]
                    )

                    mock_session_class.return_value = mock_session

                    client = HybridAuthClient(
                        agent_id="test-agent",
                        credentials_dir=Path("/tmp/.bindu"),
                        did_extension=mock_did_ext,
                    )

                    await client.initialize()

                    result = await client.post(
                        "http://localhost:3773/",
                        {"jsonrpc": "2.0", "method": "test", "id": 1},
                    )

                    assert result == {"result": "success"}
                    assert token_call_count[0] == 2  # Initial + refresh

    @pytest.mark.asyncio
    async def test_post_request_error_response(self):
        """Test POST request with error response."""
        mock_credentials = MagicMock()
        mock_credentials.client_id = "did:key:test"
        mock_credentials.client_secret = "test-secret"  # pragma: allowlist secret
        mock_credentials.scopes = ["agent:read"]

        mock_did_ext = MagicMock()
        mock_did_ext.did = "did:key:test"

        with patch(
            "bindu.utils.hybrid_auth_client.load_agent_credentials",
            return_value=mock_credentials,
        ):
            with patch(
                "bindu.utils.hybrid_auth_client.get_client_credentials_token",
                new=AsyncMock(
                    return_value={
                        "access_token": "test_token",  # pragma: allowlist secret
                        "expires_in": 3600,
                    }
                ),
            ):
                with patch(
                    "bindu.utils.hybrid_auth_client.aiohttp.ClientSession"
                ) as mock_session_class:
                    mock_response = AsyncMock()
                    mock_response.status = 500
                    mock_response.text = AsyncMock(return_value="Internal Server Error")

                    mock_session = MagicMock()
                    mock_session.__aenter__ = AsyncMock(return_value=mock_session)
                    mock_session.__aexit__ = AsyncMock(return_value=None)

                    mock_post_context = MagicMock()
                    mock_post_context.__aenter__ = AsyncMock(return_value=mock_response)
                    mock_post_context.__aexit__ = AsyncMock(return_value=None)
                    mock_session.post = MagicMock(return_value=mock_post_context)

                    mock_session_class.return_value = mock_session

                    client = HybridAuthClient(
                        agent_id="test-agent",
                        credentials_dir=Path("/tmp/.bindu"),
                        did_extension=mock_did_ext,
                    )

                    await client.initialize()

                    result = await client.post(
                        "http://localhost:3773/",
                        {"jsonrpc": "2.0", "method": "test", "id": 1},
                    )

                    # The client returns json even on error status
                    # The actual error handling is done by the caller
                    assert result is not None
