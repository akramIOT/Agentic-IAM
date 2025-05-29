"""
Unit tests for core AgenticIAM class
"""
import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime, timedelta

from core.agentic_iam import AgenticIAM
from config.settings import Settings


class TestAgenticIAM:
    """Test cases for AgenticIAM core functionality"""
    
    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_initialization(self, test_settings):
        """Test IAM system initialization"""
        iam = AgenticIAM(test_settings)
        
        # Mock all the managers to avoid actual initialization
        with patch.multiple(
            iam,
            identity_manager=MagicMock(),
            authentication_manager=MagicMock(),
            authorization_manager=MagicMock(),
            session_manager=MagicMock(),
            agent_registry=MagicMock(),
            credential_manager=MagicMock(),
            audit_manager=MagicMock(),
            compliance_manager=MagicMock(),
            intelligence_engine=MagicMock()
        ):
            # Mock async initialize methods
            iam.authentication_manager.initialize = AsyncMock()
            iam.authorization_manager.initialize = AsyncMock()
            iam.session_manager.initialize = AsyncMock()
            iam.audit_manager.initialize = AsyncMock()
            iam.compliance_manager.initialize = AsyncMock()
            iam.intelligence_engine.initialize = AsyncMock()
            
            await iam.initialize()
            
            assert iam.is_initialized is True
            assert isinstance(iam.start_time, datetime)
            
            # Verify initialization calls
            iam.authentication_manager.initialize.assert_called_once()
            iam.authorization_manager.initialize.assert_called_once()
            iam.session_manager.initialize.assert_called_once()
    
    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_shutdown(self, mock_iam):
        """Test IAM system shutdown"""
        # Setup shutdown mocks
        mock_iam.intelligence_engine.shutdown = AsyncMock()
        mock_iam.compliance_manager.shutdown = AsyncMock()
        mock_iam.audit_manager.shutdown = AsyncMock()
        mock_iam.session_manager.shutdown = AsyncMock()
        mock_iam.authorization_manager.shutdown = AsyncMock()
        mock_iam.authentication_manager.shutdown = AsyncMock()
        
        await mock_iam.shutdown()
        
        # Verify shutdown calls in reverse order
        mock_iam.intelligence_engine.shutdown.assert_called_once()
        mock_iam.compliance_manager.shutdown.assert_called_once()
        mock_iam.audit_manager.shutdown.assert_called_once()
    
    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_register_agent_success(self, mock_iam, sample_agent_identity):
        """Test successful agent registration"""
        # Setup mocks
        mock_iam.agent_registry.register_agent.return_value = MagicMock(registration_id="reg_001")
        mock_iam.credential_manager.store_agent_credentials = AsyncMock()
        mock_iam.authorization_manager.assign_permissions = AsyncMock()
        mock_iam.audit_manager.log_event = AsyncMock()
        mock_iam.intelligence_engine.initialize_agent_score = AsyncMock()
        
        # Test registration
        permissions = ["agent:read", "system:status"]
        registration_id = await mock_iam.register_agent(sample_agent_identity, permissions)
        
        assert registration_id == "reg_001"
        
        # Verify calls
        mock_iam.agent_registry.register_agent.assert_called_once_with(sample_agent_identity)
        mock_iam.credential_manager.store_agent_credentials.assert_called_once()
        mock_iam.authorization_manager.assign_permissions.assert_called_once()
        mock_iam.audit_manager.log_event.assert_called_once()
        mock_iam.intelligence_engine.initialize_agent_score.assert_called_once()
    
    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_register_agent_not_initialized(self, test_settings):
        """Test agent registration when system not initialized"""
        iam = AgenticIAM(test_settings)
        iam.is_initialized = False
        
        from agent_identity import AgentIdentity
        agent = AgentIdentity.generate("agent:test")
        
        with pytest.raises(RuntimeError, match="IAM system not initialized"):
            await iam.register_agent(agent)
    
    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_authenticate_success(self, mock_iam):
        """Test successful authentication"""
        from authentication import AuthenticationResult
        
        # Setup mock authentication result
        auth_result = MagicMock(spec=AuthenticationResult)
        auth_result.success = True
        auth_result.agent_id = "agent:test-001"
        auth_result.auth_method = "jwt"
        auth_result.trust_level = 0.85
        
        mock_iam.authentication_manager.authenticate = AsyncMock(return_value=auth_result)
        mock_iam.intelligence_engine.update_trust_score = AsyncMock()
        mock_iam.audit_manager.log_event = AsyncMock()
        
        # Test authentication
        result = await mock_iam.authenticate(
            agent_id="agent:test-001",
            credentials={"username": "test", "password": "pass"},
            method="jwt",
            source_ip="127.0.0.1"
        )
        
        assert result.success is True
        assert result.agent_id == "agent:test-001"
        
        # Verify calls
        mock_iam.authentication_manager.authenticate.assert_called_once()
        mock_iam.intelligence_engine.update_trust_score.assert_called_once()
        mock_iam.audit_manager.log_event.assert_called_once()
    
    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_authenticate_failure(self, mock_iam):
        """Test authentication failure"""
        from authentication import AuthenticationResult
        
        # Setup mock authentication result
        auth_result = MagicMock(spec=AuthenticationResult)
        auth_result.success = False
        auth_result.error_message = "Invalid credentials"
        
        mock_iam.authentication_manager.authenticate = AsyncMock(return_value=auth_result)
        mock_iam.audit_manager.log_event = AsyncMock()
        
        # Test authentication
        result = await mock_iam.authenticate(
            agent_id="agent:test-001",
            credentials={"username": "test", "password": "wrong"},
            method="jwt"
        )
        
        assert result.success is False
        assert "Invalid credentials" in result.error_message
        
        # Verify audit log for failure
        mock_iam.audit_manager.log_event.assert_called_once()
    
    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_authorize_success(self, mock_iam):
        """Test successful authorization"""
        from authorization import AuthorizationDecision
        
        # Setup mock authorization decision
        decision = MagicMock(spec=AuthorizationDecision)
        decision.allow = True
        decision.reason = "Access granted"
        
        mock_iam.authorization_manager.authorize = AsyncMock(return_value=decision)
        mock_iam.audit_manager.log_event = AsyncMock()
        
        # Test authorization
        result = await mock_iam.authorize(
            agent_id="agent:test-001",
            resource="data:user-profiles",
            action="read",
            context={"department": "engineering"}
        )
        
        assert result is True
        
        # Verify calls
        mock_iam.authorization_manager.authorize.assert_called_once()
        mock_iam.audit_manager.log_event.assert_called_once()
    
    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_authorize_denial(self, mock_iam):
        """Test authorization denial"""
        from authorization import AuthorizationDecision
        
        # Setup mock authorization decision
        decision = MagicMock(spec=AuthorizationDecision)
        decision.allow = False
        decision.reason = "Insufficient permissions"
        
        mock_iam.authorization_manager.authorize = AsyncMock(return_value=decision)
        mock_iam.audit_manager.log_event = AsyncMock()
        
        # Test authorization
        result = await mock_iam.authorize(
            agent_id="agent:test-001",
            resource="system:admin",
            action="write"
        )
        
        assert result is False
        
        # Verify audit log for denial
        mock_iam.audit_manager.log_event.assert_called_once()
    
    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_create_session_success(self, mock_iam, sample_session):
        """Test successful session creation"""
        from authentication import AuthenticationResult
        
        # Setup mocks
        auth_result = MagicMock(spec=AuthenticationResult)
        auth_result.trust_level = 0.85
        auth_result.auth_method = "jwt"
        
        mock_iam.session_manager.create_session = AsyncMock(return_value="session_001")
        mock_iam.audit_manager.log_event = AsyncMock()
        
        # Test session creation
        session_id = await mock_iam.create_session(
            agent_id="agent:test-001",
            auth_result=auth_result,
            source_ip="127.0.0.1"
        )
        
        assert session_id == "session_001"
        
        # Verify calls
        mock_iam.session_manager.create_session.assert_called_once()
        mock_iam.audit_manager.log_event.assert_called_once()
    
    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_calculate_trust_score(self, mock_iam, sample_trust_score):
        """Test trust score calculation"""
        mock_iam.intelligence_engine.calculate_trust_score = AsyncMock(
            return_value=sample_trust_score
        )
        
        # Test trust score calculation
        score = await mock_iam.calculate_trust_score("agent:test-001")
        
        assert score is not None
        assert score.overall_score == 0.85
        assert score.agent_id == "agent:test-001"
        
        # Verify call
        mock_iam.intelligence_engine.calculate_trust_score.assert_called_once_with("agent:test-001")
    
    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_calculate_trust_score_no_engine(self, mock_iam):
        """Test trust score calculation without intelligence engine"""
        mock_iam.intelligence_engine = None
        
        # Test trust score calculation
        score = await mock_iam.calculate_trust_score("agent:test-001")
        
        assert score is None
    
    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_get_platform_status(self, mock_iam):
        """Test platform status retrieval"""
        # Setup mock data
        mock_agents = [
            MagicMock(status=MagicMock(value="active")),
            MagicMock(status=MagicMock(value="inactive")),
            MagicMock(status=MagicMock(value="active"))
        ]
        
        mock_iam.agent_registry.list_agents.return_value = mock_agents
        mock_iam.session_manager.get_active_session_count.return_value = 5
        mock_iam.session_manager.get_total_session_count.return_value = 10
        mock_iam._get_avg_trust_score = AsyncMock(return_value=0.82)
        mock_iam._get_total_trust_scores = AsyncMock(return_value=15)
        mock_iam._get_anomaly_count = AsyncMock(return_value=3)
        
        # Test platform status
        status = await mock_iam.get_platform_status()
        
        assert status["platform"]["initialized"] is True
        assert status["platform"]["version"] == "1.0.0"
        assert status["agents"]["total_agents"] == 3
        assert status["agents"]["active_agents"] == 2
        assert status["agents"]["inactive_agents"] == 1
        assert status["sessions"]["active_sessions"] == 5
        assert status["intelligence"]["avg_trust_score"] == 0.82
    
    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_get_avg_trust_score_calculation(self, mock_iam, sample_trust_score):
        """Test average trust score calculation"""
        # Setup mock agents
        mock_agents = [
            MagicMock(agent_id="agent:001"),
            MagicMock(agent_id="agent:002"),
            MagicMock(agent_id="agent:003")
        ]
        
        mock_iam.agent_registry.list_agents.return_value = mock_agents
        
        # Mock trust scores for different agents
        trust_scores = [
            MagicMock(overall_score=0.8),
            MagicMock(overall_score=0.9),
            MagicMock(overall_score=0.7)
        ]
        
        mock_iam.intelligence_engine.calculate_trust_score = AsyncMock(
            side_effect=trust_scores
        )
        
        # Test average calculation
        avg_score = await mock_iam._get_avg_trust_score()
        
        # Expected average: (0.8 + 0.9 + 0.7) / 3 = 0.8
        assert abs(avg_score - 0.8) < 0.01
    
    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_error_handling_in_authenticate(self, mock_iam):
        """Test error handling during authentication"""
        # Setup mock to raise exception
        mock_iam.authentication_manager.authenticate = AsyncMock(
            side_effect=Exception("Authentication service unavailable")
        )
        
        # Test that exception is propagated
        with pytest.raises(Exception, match="Authentication service unavailable"):
            await mock_iam.authenticate(
                agent_id="agent:test-001",
                credentials={"username": "test"},
                method="jwt"
            )
    
    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_error_handling_in_authorization(self, mock_iam):
        """Test error handling during authorization"""
        # Setup mock to raise exception
        mock_iam.authorization_manager.authorize = AsyncMock(
            side_effect=Exception("Authorization service unavailable")
        )
        
        # Test that exception is propagated
        with pytest.raises(Exception, match="Authorization service unavailable"):
            await mock_iam.authorize(
                agent_id="agent:test-001",
                resource="test",
                action="read"
            )
    
    @pytest.mark.unit
    def test_settings_integration(self, test_settings):
        """Test settings integration in IAM"""
        iam = AgenticIAM(test_settings)
        
        assert iam.settings == test_settings
        assert iam.settings.environment == "testing"
        assert iam.settings.enable_trust_scoring is True
        assert iam.settings.enable_audit_logging is True
    
    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_component_availability_checks(self, mock_iam):
        """Test behavior when components are not available"""
        # Test with missing intelligence engine
        mock_iam.intelligence_engine = None
        score = await mock_iam.calculate_trust_score("agent:test")
        assert score is None
        
        # Test with missing audit manager
        mock_iam.audit_manager = None
        # Should not raise exception, just skip audit logging
        await mock_iam.authenticate(
            agent_id="agent:test",
            credentials={},
            method="jwt"
        )
    
    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_concurrent_operations(self, mock_iam):
        """Test concurrent IAM operations"""
        # Setup mocks for concurrent operations
        mock_iam.authenticate = AsyncMock(return_value=MagicMock(success=True))
        mock_iam.authorize = AsyncMock(return_value=True)
        mock_iam.calculate_trust_score = AsyncMock(return_value=MagicMock(overall_score=0.8))
        
        # Run concurrent operations
        tasks = [
            mock_iam.authenticate("agent:001", {}, "jwt"),
            mock_iam.authenticate("agent:002", {}, "jwt"),
            mock_iam.authorize("agent:001", "resource", "read"),
            mock_iam.calculate_trust_score("agent:001")
        ]
        
        results = await asyncio.gather(*tasks)
        
        assert len(results) == 4
        assert all(result is not None for result in results)


class TestAgenticIAMSettings:
    """Test cases for settings integration"""
    
    @pytest.mark.unit
    def test_settings_validation(self):
        """Test settings validation"""
        with pytest.raises(ValueError):
            Settings(environment="invalid")
        
        with pytest.raises(ValueError):
            Settings(log_level="INVALID")
        
        with pytest.raises(ValueError):
            Settings(encryption_key="too_short")
    
    @pytest.mark.unit
    def test_settings_defaults(self):
        """Test default settings values"""
        settings = Settings()
        
        assert settings.environment == "development"
        assert settings.api_host == "127.0.0.1"
        assert settings.api_port == 8000
        assert settings.enable_trust_scoring is True
        assert settings.enable_audit_logging is True


class TestAgenticIAMLogging:
    """Test cases for logging integration"""
    
    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_audit_logging_integration(self, mock_iam):
        """Test audit logging integration"""
        # Setup mock
        mock_iam.audit_manager.log_event = AsyncMock()
        
        # Perform operation that should log
        await mock_iam.authenticate(
            agent_id="agent:test",
            credentials={},
            method="jwt"
        )
        
        # Verify audit logging
        mock_iam.audit_manager.log_event.assert_called()
        call_args = mock_iam.audit_manager.log_event.call_args
        assert call_args is not None
    
    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_audit_logging_disabled(self, test_settings):
        """Test behavior when audit logging is disabled"""
        test_settings.enable_audit_logging = False
        iam = AgenticIAM(test_settings)
        
        # Should not have audit manager
        assert iam.audit_manager is None