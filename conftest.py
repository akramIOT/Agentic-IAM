"""
Pytest configuration and shared fixtures for Agentic-IAM tests
"""
import asyncio
import pytest
import tempfile
import shutil
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock
from datetime import datetime, timedelta
import sys

# Add project modules to path
sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).parent.parent))

from fastapi.testclient import TestClient
from core.agentic_iam import AgenticIAM
from config.settings import Settings
from api.main import app


@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of the default event loop for the test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
def temp_dir():
    """Create a temporary directory for tests"""
    temp_dir = tempfile.mkdtemp()
    yield Path(temp_dir)
    shutil.rmtree(temp_dir)


@pytest.fixture
def test_settings(temp_dir):
    """Create test settings with temporary directories"""
    return Settings(
        environment="testing",
        debug=True,
        log_level="DEBUG",
        database_url=f"sqlite:///{temp_dir}/test.db",
        agent_registry_path=str(temp_dir / "agents"),
        credential_storage_path=str(temp_dir / "credentials"),
        audit_storage_path=str(temp_dir / "audit"),
        log_file=str(temp_dir / "test.log"),
        enable_audit_logging=True,
        enable_trust_scoring=True,
        enable_federated_auth=False,  # Disable for tests
        enable_mfa=False,  # Disable for tests
        secret_key="test-secret-key-32-characters-long",
        encryption_key="test-encryption-key-32-chars!!",
        credential_encryption_key="test-credential-key-32-chars!!"
    )


@pytest.fixture
async def mock_iam(test_settings):
    """Create a mock IAM instance for testing"""
    iam = MagicMock(spec=AgenticIAM)
    iam.settings = test_settings
    iam.is_initialized = True
    iam.start_time = datetime.utcnow()
    
    # Mock managers
    iam.identity_manager = MagicMock()
    iam.authentication_manager = MagicMock()
    iam.authorization_manager = MagicMock()
    iam.session_manager = MagicMock()
    iam.agent_registry = MagicMock()
    iam.credential_manager = MagicMock()
    iam.audit_manager = MagicMock()
    iam.compliance_manager = MagicMock()
    iam.intelligence_engine = MagicMock()
    
    # Mock async methods
    iam.initialize = AsyncMock()
    iam.shutdown = AsyncMock()
    iam.authenticate = AsyncMock()
    iam.authorize = AsyncMock()
    iam.register_agent = AsyncMock()
    iam.create_session = AsyncMock()
    iam.calculate_trust_score = AsyncMock()
    iam.get_platform_status = AsyncMock()
    
    return iam


@pytest.fixture
async def iam_instance(test_settings):
    """Create a real IAM instance for integration tests"""
    from agent_identity import AgentIdentityManager
    from authentication import AuthenticationManager
    from authorization import AuthorizationManager
    from session_manager import SessionManager
    from agent_registry import AgentRegistry
    from credential_manager import CredentialManager
    from audit_compliance import AuditManager
    
    # Create real IAM instance
    iam = AgenticIAM(test_settings)
    
    # Initialize with mocked dependencies for testing
    iam.identity_manager = AgentIdentityManager()
    iam.agent_registry = AgentRegistry(
        storage_path=test_settings.agent_registry_path,
        enable_persistence=True
    )
    iam.credential_manager = CredentialManager(
        storage_path=test_settings.credential_storage_path,
        encryption_key=test_settings.credential_encryption_key
    )
    
    # Mock complex dependencies
    iam.authentication_manager = MagicMock(spec=AuthenticationManager)
    iam.authorization_manager = MagicMock(spec=AuthorizationManager)
    iam.session_manager = MagicMock(spec=SessionManager)
    iam.audit_manager = MagicMock(spec=AuditManager)
    iam.compliance_manager = MagicMock()
    iam.intelligence_engine = MagicMock()
    
    iam.is_initialized = True
    
    yield iam
    
    # Cleanup
    await iam.shutdown()


@pytest.fixture
def client(mock_iam):
    """Create test client for API testing"""
    # Override dependencies
    app.dependency_overrides = {}
    
    def get_test_iam():
        return mock_iam
    
    def get_test_settings():
        return mock_iam.settings
    
    from api.main import get_iam, get_settings
    app.dependency_overrides[get_iam] = get_test_iam
    app.dependency_overrides[get_settings] = get_test_settings
    
    with TestClient(app) as test_client:
        yield test_client
    
    # Clear overrides
    app.dependency_overrides = {}


@pytest.fixture
def sample_agent_data():
    """Sample agent data for testing"""
    return {
        "agent_id": "agent:test-001",
        "agent_type": "service",
        "description": "Test agent for unit tests",
        "capabilities": ["read", "write"],
        "metadata": {
            "environment": "test",
            "version": "1.0.0"
        },
        "initial_permissions": ["agent:read", "system:status"]
    }


@pytest.fixture
def sample_auth_request():
    """Sample authentication request for testing"""
    return {
        "agent_id": "agent:test-001",
        "method": "jwt",
        "credentials": {
            "username": "test-agent",
            "password": "test-password"
        },
        "source_ip": "127.0.0.1",
        "user_agent": "test-client/1.0"
    }


@pytest.fixture
def sample_agent_identity():
    """Create a sample agent identity for testing"""
    from agent_identity import AgentIdentity
    
    return AgentIdentity.generate(
        agent_id="agent:test-001",
        metadata={
            "type": "service",
            "description": "Test agent",
            "capabilities": ["read", "write"]
        }
    )


@pytest.fixture
def sample_trust_score():
    """Sample trust score for testing"""
    from agent_intelligence import TrustScore, RiskLevel
    
    return TrustScore(
        agent_id="agent:test-001",
        overall_score=0.85,
        risk_level=RiskLevel.LOW,
        confidence=0.92,
        component_scores={
            "authentication": 0.9,
            "authorization": 0.8,
            "behavior": 0.85,
            "network": 0.88
        },
        last_updated=datetime.utcnow(),
        factors=[
            {"type": "successful_auth", "weight": 0.3, "value": 0.95},
            {"type": "session_duration", "weight": 0.2, "value": 0.8}
        ]
    )


@pytest.fixture
def sample_session():
    """Sample session for testing"""
    from session_manager import Session, SessionStatus
    
    return Session(
        session_id="session_test_001",
        agent_id="agent:test-001",
        status=SessionStatus.ACTIVE,
        trust_level=0.85,
        auth_method="jwt",
        created_at=datetime.utcnow(),
        last_accessed=datetime.utcnow(),
        expires_at=datetime.utcnow() + timedelta(hours=1),
        metadata={
            "source_ip": "127.0.0.1",
            "user_agent": "test-client/1.0"
        }
    )


@pytest.fixture
def sample_audit_event():
    """Sample audit event for testing"""
    from audit_compliance import AuditEvent, AuditEventType, EventSeverity
    
    return AuditEvent(
        event_id="audit_test_001",
        event_type=AuditEventType.AUTH_SUCCESS,
        agent_id="agent:test-001",
        timestamp=datetime.utcnow(),
        severity=EventSeverity.LOW,
        component="authentication",
        outcome="success",
        source_ip="127.0.0.1",
        user_agent="test-client/1.0",
        details={
            "method": "jwt",
            "duration": 150
        }
    )


@pytest.fixture
def mock_redis():
    """Mock Redis for testing"""
    import fakeredis
    return fakeredis.FakeRedis()


@pytest.fixture
def mock_database():
    """Mock database for testing"""
    from unittest.mock import MagicMock
    
    db = MagicMock()
    db.execute = AsyncMock()
    db.fetch = AsyncMock()
    db.fetchrow = AsyncMock()
    db.close = AsyncMock()
    
    return db


# Test utilities
class TestHelpers:
    """Helper methods for tests"""
    
    @staticmethod
    def assert_api_response(response, expected_status=200):
        """Assert API response format and status"""
        assert response.status_code == expected_status
        data = response.json()
        
        if expected_status == 200:
            assert "timestamp" in data
        else:
            assert "error" in data
        
        return data
    
    @staticmethod
    def create_auth_header(token: str) -> dict:
        """Create authorization header for API tests"""
        return {"Authorization": f"Bearer {token}"}
    
    @staticmethod
    async def wait_for_condition(condition, timeout=5.0, interval=0.1):
        """Wait for a condition to become true"""
        import asyncio
        
        end_time = asyncio.get_event_loop().time() + timeout
        while asyncio.get_event_loop().time() < end_time:
            if await condition() if asyncio.iscoroutinefunction(condition) else condition():
                return True
            await asyncio.sleep(interval)
        return False


@pytest.fixture
def test_helpers():
    """Provide test helpers"""
    return TestHelpers


# Pytest configuration
def pytest_configure(config):
    """Configure pytest"""
    # Add custom markers
    config.addinivalue_line("markers", "unit: mark test as unit test")
    config.addinivalue_line("markers", "integration: mark test as integration test")
    config.addinivalue_line("markers", "api: mark test as API test")
    config.addinivalue_line("markers", "slow: mark test as slow running")
    config.addinivalue_line("markers", "security: mark test as security test")


def pytest_collection_modifyitems(config, items):
    """Modify test collection"""
    # Add markers based on file location
    for item in items:
        # Mark tests in specific directories
        if "test_unit" in str(item.fspath):
            item.add_marker(pytest.mark.unit)
        elif "test_integration" in str(item.fspath):
            item.add_marker(pytest.mark.integration)
        elif "test_api" in str(item.fspath):
            item.add_marker(pytest.mark.api)
        elif "test_security" in str(item.fspath):
            item.add_marker(pytest.mark.security)


# Asyncio compatibility
@pytest.fixture(scope="session", autouse=True)
def setup_asyncio():
    """Setup asyncio for testing"""
    import nest_asyncio
    nest_asyncio.apply()


# Cleanup fixtures
@pytest.fixture(autouse=True)
def cleanup_after_test():
    """Cleanup after each test"""
    yield
    # Cleanup any global state
    import logging
    logging.getLogger().handlers.clear()