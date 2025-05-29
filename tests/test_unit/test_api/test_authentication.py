"""
Unit tests for authentication API endpoints
"""
import pytest
from unittest.mock import AsyncMock, MagicMock
from datetime import datetime, timedelta

from api.routers.authentication import router


class TestAuthenticationAPI:
    """Test cases for authentication API endpoints"""
    
    @pytest.mark.unit
    @pytest.mark.api
    def test_login_success(self, client, mock_iam, sample_auth_request):
        """Test successful agent login"""
        # Setup mock authentication result
        auth_result = MagicMock()
        auth_result.success = True
        auth_result.agent_id = "agent:test-001"
        auth_result.auth_method = "jwt"
        auth_result.trust_level = 0.85
        auth_result.expires_at = datetime.utcnow() + timedelta(hours=1)
        auth_result.error_message = None
        
        mock_iam.authenticate = AsyncMock(return_value=auth_result)
        mock_iam.create_session = AsyncMock(return_value="session_001")
        
        # Mock JWT token generation
        mock_agent_entry = MagicMock()
        mock_agent_entry.agent_identity = MagicMock()
        mock_iam.agent_registry.get_agent.return_value = mock_agent_entry
        
        mock_jwt_auth = MagicMock()
        mock_jwt_auth.generate_token.return_value = "jwt_token_123"
        mock_iam.authentication_manager.methods = {"jwt": mock_jwt_auth}
        
        # Test login
        response = client.post("/api/v1/auth/login", json=sample_auth_request)
        
        assert response.status_code == 200
        data = response.json()
        
        assert data["success"] is True
        assert data["agent_id"] == "agent:test-001"
        assert data["token"] == "jwt_token_123"
        assert data["session_id"] == "session_001"
        assert data["trust_level"] == 0.85
        assert data["auth_method"] == "jwt"
        
        # Verify mock calls
        mock_iam.authenticate.assert_called_once()
        mock_iam.create_session.assert_called_once()
    
    @pytest.mark.unit
    @pytest.mark.api
    def test_login_failure(self, client, mock_iam, sample_auth_request):
        """Test failed agent login"""
        # Setup mock authentication result for failure
        auth_result = MagicMock()
        auth_result.success = False
        auth_result.error_message = "Invalid credentials"
        
        mock_iam.authenticate = AsyncMock(return_value=auth_result)
        
        # Test login
        response = client.post("/api/v1/auth/login", json=sample_auth_request)
        
        assert response.status_code == 200
        data = response.json()
        
        assert data["success"] is False
        assert data["error_message"] == "Invalid credentials"
        assert "agent_id" not in data
        assert "token" not in data
    
    @pytest.mark.unit
    @pytest.mark.api
    def test_login_invalid_request(self, client):
        """Test login with invalid request data"""
        invalid_request = {
            "agent_id": "",  # Invalid: empty agent_id
            "method": "jwt",
            "credentials": {}
        }
        
        response = client.post("/api/v1/auth/login", json=invalid_request)
        
        assert response.status_code == 422  # Validation error
    
    @pytest.mark.unit
    @pytest.mark.api
    def test_login_exception_handling(self, client, mock_iam, sample_auth_request):
        """Test login exception handling"""
        # Setup mock to raise exception
        mock_iam.authenticate = AsyncMock(side_effect=Exception("Database connection failed"))
        
        # Test login
        response = client.post("/api/v1/auth/login", json=sample_auth_request)
        
        assert response.status_code == 401
        data = response.json()
        
        assert "error" in data
        assert "Database connection failed" in data["error"]["message"]
    
    @pytest.mark.unit
    @pytest.mark.api
    def test_logout_session_id(self, client, mock_iam):
        """Test logout with session ID"""
        mock_iam.session_manager.terminate_session.return_value = True
        
        response = client.post("/api/v1/auth/logout", params={"session_id": "session_001"})
        
        assert response.status_code == 200
        data = response.json()
        
        assert data["message"] == "Successfully terminated 1 session(s)"
        assert data["data"]["terminated_sessions"] == 1
        
        mock_iam.session_manager.terminate_session.assert_called_once_with(
            "session_001", reason="user_logout"
        )
    
    @pytest.mark.unit
    @pytest.mark.api
    def test_logout_agent_id(self, client, mock_iam):
        """Test logout with agent ID (all sessions)"""
        mock_iam.session_manager.terminate_agent_sessions.return_value = 3
        
        response = client.post("/api/v1/auth/logout", params={"agent_id": "agent:test-001"})
        
        assert response.status_code == 200
        data = response.json()
        
        assert data["message"] == "Successfully terminated 3 session(s)"
        assert data["data"]["terminated_sessions"] == 3
        
        mock_iam.session_manager.terminate_agent_sessions.assert_called_once_with(
            "agent:test-001", reason="user_logout"
        )
    
    @pytest.mark.unit
    @pytest.mark.api
    def test_logout_no_parameters(self, client):
        """Test logout without required parameters"""
        response = client.post("/api/v1/auth/logout")
        
        assert response.status_code == 400
        data = response.json()
        
        assert "Either session_id or agent_id must be provided" in data["error"]["message"]
    
    @pytest.mark.unit
    @pytest.mark.api
    def test_refresh_token_success(self, client, mock_iam):
        """Test successful token refresh"""
        # Setup mock session
        mock_session = MagicMock()
        mock_session.session_id = "session_001"
        mock_session.agent_id = "agent:test-001"
        mock_session.expires_at = datetime.utcnow() + timedelta(hours=1)
        
        mock_iam.session_manager.refresh_session.return_value = True
        mock_iam.session_manager.get_session.return_value = mock_session
        
        # Mock JWT token generation
        mock_agent_entry = MagicMock()
        mock_agent_entry.agent_identity = MagicMock()
        mock_iam.agent_registry.get_agent.return_value = mock_agent_entry
        
        mock_jwt_auth = MagicMock()
        mock_jwt_auth.generate_token.return_value = "new_jwt_token_456"
        mock_iam.authentication_manager.methods = {"jwt": mock_jwt_auth}
        
        refresh_request = {
            "session_id": "session_001",
            "refresh_token": "refresh_token_123"
        }
        
        response = client.post("/api/v1/auth/refresh", json=refresh_request)
        
        assert response.status_code == 200
        data = response.json()
        
        assert data["success"] is True
        assert data["agent_id"] == "agent:test-001"
        assert data["token"] == "new_jwt_token_456"
        assert data["session_id"] == "session_001"
        assert data["auth_method"] == "refresh"
        
        mock_iam.session_manager.refresh_session.assert_called_once_with(
            session_id="session_001", refresh_token="refresh_token_123"
        )
    
    @pytest.mark.unit
    @pytest.mark.api
    def test_refresh_token_invalid_session(self, client, mock_iam):
        """Test token refresh with invalid session"""
        mock_iam.session_manager.refresh_session.return_value = False
        
        refresh_request = {
            "session_id": "invalid_session",
            "refresh_token": "refresh_token_123"
        }
        
        response = client.post("/api/v1/auth/refresh", json=refresh_request)
        
        assert response.status_code == 200
        data = response.json()
        
        assert data["success"] is False
        assert "Invalid refresh token or session expired" in data["error_message"]
    
    @pytest.mark.unit
    @pytest.mark.api
    def test_get_challenge(self, client, mock_iam):
        """Test getting cryptographic challenge"""
        mock_crypto_auth = MagicMock()
        mock_crypto_auth.generate_challenge.return_value = "challenge_string_123"
        mock_iam.authentication_manager.methods = {"crypto": mock_crypto_auth}
        
        response = client.get("/api/v1/auth/challenge/agent:test-001")
        
        assert response.status_code == 200
        data = response.json()
        
        assert data["challenge"] == "challenge_string_123"
        assert data["agent_id"] == "agent:test-001"
        assert data["expires_in"] == 300
        assert data["algorithm"] == "Ed25519"
        assert "timestamp" in data
        
        mock_crypto_auth.generate_challenge.assert_called_once_with("agent:test-001")
    
    @pytest.mark.unit
    @pytest.mark.api
    def test_get_challenge_crypto_not_available(self, client, mock_iam):
        """Test getting challenge when crypto auth not available"""
        mock_iam.authentication_manager.methods = {}  # No crypto method
        
        response = client.get("/api/v1/auth/challenge/agent:test-001")
        
        assert response.status_code == 501
        data = response.json()
        
        assert "Cryptographic authentication not available" in data["error"]["message"]
    
    @pytest.mark.unit
    @pytest.mark.api
    def test_verify_signature_success(self, client, mock_iam):
        """Test successful signature verification"""
        # Setup mock agent
        mock_agent_entry = MagicMock()
        mock_agent_identity = MagicMock()
        mock_agent_identity.get_public_key.return_value = "public_key_data"
        mock_agent_identity.verify_message.return_value = True
        mock_agent_entry.agent_identity = mock_agent_identity
        
        mock_iam.agent_registry.get_agent.return_value = mock_agent_entry
        
        verify_data = {
            "agent_id": "agent:test-001",
            "challenge": "challenge_string_123",
            "signature": "signature_data_456"
        }
        
        response = client.post("/api/v1/auth/verify-signature", params=verify_data)
        
        assert response.status_code == 200
        data = response.json()
        
        assert data["valid"] is True
        assert data["agent_id"] == "agent:test-001"
        assert data["message"] == "Signature verification successful"
        
        mock_agent_identity.verify_message.assert_called_once_with(
            "challenge_string_123", "signature_data_456", "public_key_data"
        )
    
    @pytest.mark.unit
    @pytest.mark.api
    def test_verify_signature_invalid(self, client, mock_iam):
        """Test invalid signature verification"""
        # Setup mock agent with invalid signature
        mock_agent_entry = MagicMock()
        mock_agent_identity = MagicMock()
        mock_agent_identity.get_public_key.return_value = "public_key_data"
        mock_agent_identity.verify_message.return_value = False
        mock_agent_entry.agent_identity = mock_agent_identity
        
        mock_iam.agent_registry.get_agent.return_value = mock_agent_entry
        
        verify_data = {
            "agent_id": "agent:test-001",
            "challenge": "challenge_string_123",
            "signature": "invalid_signature"
        }
        
        response = client.post("/api/v1/auth/verify-signature", params=verify_data)
        
        assert response.status_code == 200
        data = response.json()
        
        assert data["valid"] is False
        assert data["agent_id"] == "agent:test-001"
        assert data["message"] == "Invalid signature"
    
    @pytest.mark.unit
    @pytest.mark.api
    def test_verify_signature_agent_not_found(self, client, mock_iam):
        """Test signature verification for non-existent agent"""
        mock_iam.agent_registry.get_agent.return_value = None
        
        verify_data = {
            "agent_id": "agent:nonexistent",
            "challenge": "challenge_string_123",
            "signature": "signature_data_456"
        }
        
        response = client.post("/api/v1/auth/verify-signature", params=verify_data)
        
        assert response.status_code == 404
        data = response.json()
        
        assert "Agent not found" in data["error"]["message"]
    
    @pytest.mark.unit
    @pytest.mark.api
    def test_get_auth_methods(self, client, mock_iam, test_settings):
        """Test getting available authentication methods"""
        # Setup mock authentication methods
        mock_jwt_method = MagicMock()
        mock_jwt_method.__class__.__name__ = "JWTAuthentication"
        
        mock_crypto_method = MagicMock()
        mock_crypto_method.__class__.__name__ = "CryptographicAuthentication"
        
        mock_iam.authentication_manager.methods = {
            "jwt": mock_jwt_method,
            "crypto": mock_crypto_method
        }
        mock_iam.authentication_manager.default_method = "jwt"
        
        response = client.get("/api/v1/auth/methods")
        
        assert response.status_code == 200
        data = response.json()
        
        assert len(data["methods"]) == 2
        assert data["default_method"] == "jwt"
        assert data["mfa_enabled"] == test_settings.enable_mfa
        assert data["federated_auth_enabled"] == test_settings.enable_federated_auth
        
        # Check method details
        jwt_method = next(m for m in data["methods"] if m["name"] == "jwt")
        assert jwt_method["type"] == "JWTAuthentication"
        assert jwt_method["enabled"] is True
        assert "token_ttl" in jwt_method
    
    @pytest.mark.unit
    @pytest.mark.api
    def test_get_auth_status(self, client, mock_iam):
        """Test getting authentication status for agent"""
        # Setup mock agent
        mock_agent_entry = MagicMock()
        mock_agent_entry.status.value = "active"
        mock_agent_entry.last_accessed = datetime.utcnow()
        
        mock_iam.agent_registry.get_agent.return_value = mock_agent_entry
        
        # Setup mock sessions
        mock_sessions = [
            MagicMock(is_active=lambda: True),
            MagicMock(is_active=lambda: True),
            MagicMock(is_active=lambda: False)
        ]
        mock_iam.session_manager.session_store.get_agent_sessions.return_value = mock_sessions
        
        # Setup mock trust score
        mock_trust_score = MagicMock()
        mock_trust_score.overall_score = 0.85
        mock_trust_score.risk_level.value = "low"
        mock_iam.calculate_trust_score = AsyncMock(return_value=mock_trust_score)
        
        # Setup mock audit events
        mock_audit_events = [
            MagicMock(timestamp=datetime.utcnow())
        ]
        mock_iam.audit_manager.query_events.return_value = mock_audit_events
        
        response = client.get("/api/v1/auth/status/agent:test-001")
        
        assert response.status_code == 200
        data = response.json()
        
        assert data["agent_id"] == "agent:test-001"
        assert data["agent_status"] == "active"
        assert data["is_active"] is True
        assert data["active_sessions"] == 2
        assert data["trust_score"] == 0.85
        assert data["risk_level"] == "low"
    
    @pytest.mark.unit
    @pytest.mark.api
    def test_get_auth_status_agent_not_found(self, client, mock_iam):
        """Test getting status for non-existent agent"""
        mock_iam.agent_registry.get_agent.return_value = None
        
        response = client.get("/api/v1/auth/status/agent:nonexistent")
        
        assert response.status_code == 404
        data = response.json()
        
        assert "Agent not found" in data["error"]["message"]
    
    @pytest.mark.unit
    @pytest.mark.api
    def test_start_mfa_success(self, client, mock_iam, test_settings):
        """Test starting MFA process"""
        test_settings.enable_mfa = True
        
        mock_mfa_method = MagicMock()
        mock_mfa_session = {
            "session_id": "mfa_session_001",
            "required_factors": 2,
            "available_methods": ["totp", "sms"]
        }
        mock_mfa_method.start_authentication.return_value = mock_mfa_session
        
        mock_iam.authentication_manager.methods = {"mfa": mock_mfa_method}
        
        response = client.post("/api/v1/auth/mfa/start", params={"agent_id": "agent:test-001"})
        
        assert response.status_code == 200
        data = response.json()
        
        assert data["mfa_session_id"] == "mfa_session_001"
        assert data["required_factors"] == 2
        assert data["available_methods"] == ["totp", "sms"]
        assert data["expires_in"] == 600
        
        mock_mfa_method.start_authentication.assert_called_once_with("agent:test-001")
    
    @pytest.mark.unit
    @pytest.mark.api
    def test_start_mfa_disabled(self, client, mock_iam, test_settings):
        """Test starting MFA when disabled"""
        test_settings.enable_mfa = False
        
        response = client.post("/api/v1/auth/mfa/start", params={"agent_id": "agent:test-001"})
        
        assert response.status_code == 501
        data = response.json()
        
        assert "Multi-factor authentication is not enabled" in data["error"]["message"]
    
    @pytest.mark.unit
    @pytest.mark.api
    def test_verify_mfa_factor_success(self, client, mock_iam):
        """Test successful MFA factor verification"""
        mock_mfa_method = MagicMock()
        mock_result = MagicMock()
        mock_result.success = True
        mock_result.auth_method = "mfa"
        mock_result.agent_id = "agent:test-001"
        mock_result.trust_level = 0.95
        
        mock_mfa_method.authenticate_factor.return_value = mock_result
        mock_iam.authentication_manager.methods = {"mfa": mock_mfa_method}
        
        verify_data = {
            "mfa_session_id": "mfa_session_001",
            "method": "totp",
            "credentials": {"code": "123456"}
        }
        
        response = client.post("/api/v1/auth/mfa/verify", json=verify_data)
        
        assert response.status_code == 200
        data = response.json()
        
        assert data["success"] is True
        assert data["mfa_complete"] is True
        assert data["agent_id"] == "agent:test-001"
        assert data["trust_level"] == 0.95
        
        mock_mfa_method.authenticate_factor.assert_called_once_with(
            "mfa_session_001", "totp", {"code": "123456"}
        )
    
    @pytest.mark.unit
    @pytest.mark.api
    def test_verify_mfa_factor_partial(self, client, mock_iam):
        """Test partial MFA factor verification (more factors needed)"""
        mock_mfa_method = MagicMock()
        mock_result = MagicMock()
        mock_result.success = True
        mock_result.auth_method = "partial_mfa"
        mock_result.trust_level = 0.5
        mock_result.error_message = "Additional factor required"
        
        mock_mfa_method.authenticate_factor.return_value = mock_result
        mock_iam.authentication_manager.methods = {"mfa": mock_mfa_method}
        
        verify_data = {
            "mfa_session_id": "mfa_session_001",
            "method": "totp",
            "credentials": {"code": "123456"}
        }
        
        response = client.post("/api/v1/auth/mfa/verify", json=verify_data)
        
        assert response.status_code == 200
        data = response.json()
        
        assert data["success"] is True
        assert data["mfa_complete"] is False
        assert data["factors_completed"] == 0.5
        assert data["message"] == "Additional factor required"
    
    @pytest.mark.unit
    @pytest.mark.api
    def test_verify_mfa_factor_failure(self, client, mock_iam):
        """Test failed MFA factor verification"""
        mock_mfa_method = MagicMock()
        mock_result = MagicMock()
        mock_result.success = False
        mock_result.error_message = "Invalid TOTP code"
        
        mock_mfa_method.authenticate_factor.return_value = mock_result
        mock_iam.authentication_manager.methods = {"mfa": mock_mfa_method}
        
        verify_data = {
            "mfa_session_id": "mfa_session_001",
            "method": "totp",
            "credentials": {"code": "wrong"}
        }
        
        response = client.post("/api/v1/auth/mfa/verify", json=verify_data)
        
        assert response.status_code == 200
        data = response.json()
        
        assert data["success"] is False
        assert data["error"] == "Invalid TOTP code"