"""
Agentic-IAM: Core Integration Module

Central orchestrator that integrates all Agent Identity Framework components
into a unified platform for comprehensive agent identity and access management.
"""
import asyncio
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
import sys
from pathlib import Path

# Add framework modules to path
sys.path.append(str(Path(__file__).parent.parent.parent))

# Import all Agent Identity Framework modules
from agent_identity import AgentIdentity, AgentIdentityManager
from authentication import AuthenticationManager
from authorization import AuthorizationManager
from session_manager import SessionManager
from federated_identity import FederatedIdentityManager
from credential_manager import CredentialManager
from agent_registry import AgentRegistry
from transport_binding import TransportSecurityManager
from audit_compliance import AuditManager, ComplianceManager
from agent_intelligence import IntelligenceEngine

from config.settings import Settings
from utils.logger import get_logger


class AgenticIAM:
    """
    Core Agentic Identity and Access Management platform
    
    Integrates all Agent Identity Framework components into a unified system
    providing comprehensive identity management, authentication, authorization,
    session management, federated identity, credential management, agent registry,
    transport binding, audit & compliance, and AI-powered intelligence.
    """
    
    def __init__(self, settings: Settings):
        self.settings = settings
        self.logger = get_logger("AgenticIAM")
        self.is_initialized = False
        self.start_time = datetime.utcnow()
        
        # Initialize core managers
        self.identity_manager: Optional[AgentIdentityManager] = None
        self.authentication_manager: Optional[AuthenticationManager] = None
        self.authorization_manager: Optional[AuthorizationManager] = None
        self.session_manager: Optional[SessionManager] = None
        self.federated_manager: Optional[FederatedIdentityManager] = None
        self.credential_manager: Optional[CredentialManager] = None
        self.agent_registry: Optional[AgentRegistry] = None
        self.transport_manager: Optional[TransportSecurityManager] = None
        self.audit_manager: Optional[AuditManager] = None
        self.compliance_manager: Optional[ComplianceManager] = None
        self.intelligence_engine: Optional[IntelligenceEngine] = None
        
    async def initialize(self):
        """Initialize all IAM components"""
        self.logger.info("Initializing Agentic-IAM system...")
        
        try:
            # Initialize core identity management
            self.identity_manager = AgentIdentityManager()
            
            # Initialize agent registry
            self.agent_registry = AgentRegistry(
                storage_path=self.settings.agent_registry_path,
                enable_persistence=True
            )
            
            # Initialize credential manager
            self.credential_manager = CredentialManager(
                storage_path=self.settings.credential_storage_path,
                encryption_key=self.settings.credential_encryption_key
            )
            
            # Initialize authentication manager
            self.authentication_manager = AuthenticationManager()
            await self.authentication_manager.initialize(
                enable_jwt=True,
                enable_mtls=self.settings.enable_mtls,
                enable_crypto=True,
                enable_mfa=self.settings.enable_mfa
            )
            
            # Initialize authorization manager
            self.authorization_manager = AuthorizationManager()
            await self.authorization_manager.initialize(
                enable_rbac=True,
                enable_abac=True,
                enable_pbac=True,
                hybrid_mode=True
            )
            
            # Initialize session manager
            self.session_manager = SessionManager(
                storage_backend="memory",  # Can be changed to Redis for production
                session_ttl=self.settings.session_ttl,
                cleanup_interval=300
            )
            await self.session_manager.initialize()
            
            # Initialize federated identity (if enabled)
            if self.settings.enable_federated_auth:
                self.federated_manager = FederatedIdentityManager()
                await self.federated_manager.initialize(
                    enable_oidc=True,
                    enable_saml=True,
                    enable_didcomm=True
                )
            
            # Initialize transport security
            self.transport_manager = TransportSecurityManager()
            await self.transport_manager.initialize(
                enable_http=True,
                enable_grpc=True,
                enable_websocket=True,
                enable_stdio=True
            )
            
            # Initialize audit manager
            if self.settings.enable_audit_logging:
                self.audit_manager = AuditManager(
                    storage_backend="file",  # Can be database for production
                    storage_config={"file_path": self.settings.audit_log_path}
                )
                await self.audit_manager.initialize()
            
            # Initialize compliance manager
            self.compliance_manager = ComplianceManager()
            await self.compliance_manager.initialize(
                frameworks=["gdpr", "hipaa", "sox", "pci_dss"]
            )
            
            # Initialize intelligence engine (if enabled)
            if self.settings.enable_trust_scoring:
                self.intelligence_engine = IntelligenceEngine()
                await self.intelligence_engine.initialize(
                    enable_trust_scoring=True,
                    enable_anomaly_detection=True,
                    enable_behavioral_analysis=True,
                    enable_ml_insights=True
                )
            
            self.is_initialized = True
            self.logger.info("Agentic-IAM system initialization complete")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize Agentic-IAM system: {str(e)}")
            raise
    
    async def shutdown(self):
        """Gracefully shutdown all components"""
        self.logger.info("Shutting down Agentic-IAM system...")
        
        try:
            # Shutdown in reverse order
            if self.intelligence_engine:
                await self.intelligence_engine.shutdown()
            
            if self.compliance_manager:
                await self.compliance_manager.shutdown()
            
            if self.audit_manager:
                await self.audit_manager.shutdown()
            
            if self.transport_manager:
                await self.transport_manager.shutdown()
            
            if self.federated_manager:
                await self.federated_manager.shutdown()
            
            if self.session_manager:
                await self.session_manager.shutdown()
            
            if self.authorization_manager:
                await self.authorization_manager.shutdown()
            
            if self.authentication_manager:
                await self.authentication_manager.shutdown()
            
            self.is_initialized = False
            self.logger.info("Agentic-IAM system shutdown complete")
            
        except Exception as e:
            self.logger.error(f"Error during shutdown: {str(e)}")
    
    async def register_agent(self, agent_identity: AgentIdentity, 
                           initial_permissions: Optional[List[str]] = None) -> str:
        """Register a new agent in the system"""
        if not self.is_initialized:
            raise RuntimeError("IAM system not initialized")
        
        try:
            # Register agent in registry
            agent_entry = self.agent_registry.register_agent(agent_identity)
            
            # Store credentials
            await self.credential_manager.store_agent_credentials(
                agent_id=agent_identity.agent_id,
                public_key=agent_identity.get_public_key(),
                private_key=agent_identity.get_private_key() if agent_identity.has_private_key() else None,
                metadata=agent_identity.get_metadata()
            )
            
            # Set initial permissions
            if initial_permissions and self.authorization_manager:
                await self.authorization_manager.assign_permissions(
                    agent_identity.agent_id,
                    initial_permissions
                )
            
            # Log registration event
            if self.audit_manager:
                from audit_compliance import AuditEventType
                await self.audit_manager.log_event(
                    event_type=AuditEventType.AGENT_REGISTERED,
                    agent_id=agent_identity.agent_id,
                    details={
                        "agent_type": agent_identity.get_metadata().get("type", "unknown"),
                        "capabilities": agent_identity.get_metadata().get("capabilities", []),
                        "initial_permissions": initial_permissions or []
                    }
                )
            
            # Initialize trust score
            if self.intelligence_engine:
                await self.intelligence_engine.initialize_agent_score(agent_identity.agent_id)
            
            self.logger.info(f"Agent registered successfully: {agent_identity.agent_id}")
            return agent_entry.registration_id
            
        except Exception as e:
            self.logger.error(f"Failed to register agent {agent_identity.agent_id}: {str(e)}")
            raise
    
    async def authenticate(self, agent_id: str, credentials: Dict[str, Any], 
                          method: str = "auto", **kwargs) -> 'AuthenticationResult':
        """Authenticate an agent"""
        if not self.is_initialized or not self.authentication_manager:
            raise RuntimeError("Authentication system not initialized")
        
        try:
            # Perform authentication
            result = await self.authentication_manager.authenticate(
                agent_id=agent_id,
                credentials=credentials,
                method=method,
                **kwargs
            )
            
            # Update trust score based on authentication
            if self.intelligence_engine and result.success:
                await self.intelligence_engine.update_trust_score(
                    agent_id=agent_id,
                    event_type="authentication_success",
                    context=kwargs
                )
            
            # Log authentication event
            if self.audit_manager:
                from audit_compliance import AuditEventType
                await self.audit_manager.log_event(
                    event_type=AuditEventType.AUTH_SUCCESS if result.success else AuditEventType.AUTH_FAILURE,
                    agent_id=agent_id,
                    details={
                        "method": method,
                        "source_ip": kwargs.get("source_ip"),
                        "user_agent": kwargs.get("user_agent")
                    },
                    outcome="success" if result.success else "failure"
                )
            
            return result
            
        except Exception as e:
            self.logger.error(f"Authentication failed for {agent_id}: {str(e)}")
            raise
    
    async def authorize(self, agent_id: str, resource: str, action: str, 
                       context: Optional[Dict[str, Any]] = None) -> bool:
        """Authorize an agent action"""
        if not self.is_initialized or not self.authorization_manager:
            raise RuntimeError("Authorization system not initialized")
        
        try:
            # Check authorization
            decision = await self.authorization_manager.authorize(
                agent_id=agent_id,
                resource=resource,
                action=action,
                context=context or {}
            )
            
            # Log authorization event
            if self.audit_manager:
                from audit_compliance import AuditEventType
                await self.audit_manager.log_event(
                    event_type=AuditEventType.AUTHORIZATION_DECISION,
                    agent_id=agent_id,
                    details={
                        "resource": resource,
                        "action": action,
                        "decision": "allow" if decision.allow else "deny",
                        "reason": decision.reason,
                        "context": context
                    },
                    outcome="success" if decision.allow else "denied"
                )
            
            return decision.allow
            
        except Exception as e:
            self.logger.error(f"Authorization failed for {agent_id}: {str(e)}")
            raise
    
    async def create_session(self, agent_id: str, auth_result: 'AuthenticationResult',
                           **kwargs) -> str:
        """Create a new session for an authenticated agent"""
        if not self.is_initialized or not self.session_manager:
            raise RuntimeError("Session management not initialized")
        
        try:
            # Create session
            session_id = await self.session_manager.create_session(
                agent_id=agent_id,
                trust_level=auth_result.trust_level,
                auth_method=auth_result.auth_method,
                metadata=kwargs
            )
            
            # Log session creation
            if self.audit_manager:
                from audit_compliance import AuditEventType
                await self.audit_manager.log_event(
                    event_type=AuditEventType.SESSION_CREATED,
                    agent_id=agent_id,
                    details={
                        "session_id": session_id,
                        "auth_method": auth_result.auth_method,
                        "trust_level": auth_result.trust_level
                    }
                )
            
            return session_id
            
        except Exception as e:
            self.logger.error(f"Failed to create session for {agent_id}: {str(e)}")
            raise
    
    async def calculate_trust_score(self, agent_id: str) -> Optional['TrustScore']:
        """Calculate current trust score for an agent"""
        if not self.intelligence_engine:
            return None
        
        try:
            return await self.intelligence_engine.calculate_trust_score(agent_id)
        except Exception as e:
            self.logger.error(f"Failed to calculate trust score for {agent_id}: {str(e)}")
            return None
    
    async def get_platform_status(self) -> Dict[str, Any]:
        """Get comprehensive platform status"""
        status = {
            "platform": {
                "version": "1.0.0",
                "uptime": (datetime.utcnow() - self.start_time).total_seconds(),
                "initialized": self.is_initialized,
                "components": {}
            }
        }
        
        # Component status
        status["platform"]["components"] = {
            "identity_manager": self.identity_manager is not None,
            "authentication": self.authentication_manager is not None,
            "authorization": self.authorization_manager is not None,
            "session_manager": self.session_manager is not None,
            "federated_auth": self.federated_manager is not None,
            "credential_manager": self.credential_manager is not None,
            "agent_registry": self.agent_registry is not None,
            "transport_binding": self.transport_manager is not None,
            "audit_logging": self.audit_manager is not None,
            "compliance": self.compliance_manager is not None,
            "intelligence": self.intelligence_engine is not None
        }
        
        # Agent registry stats
        if self.agent_registry:
            agents = self.agent_registry.list_agents()
            status["agents"] = {
                "total_agents": len(agents),
                "active_agents": len([a for a in agents if a.status.value == "active"]),
                "inactive_agents": len([a for a in agents if a.status.value == "inactive"]),
                "suspended_agents": len([a for a in agents if a.status.value == "suspended"]),
                "deactivated_agents": len([a for a in agents if a.status.value == "deactivated"])
            }
        
        # Session stats
        if self.session_manager:
            status["sessions"] = {
                "active_sessions": self.session_manager.get_active_session_count(),
                "total_sessions": self.session_manager.get_total_session_count()
            }
        
        # Intelligence stats
        if self.intelligence_engine:
            status["intelligence"] = {
                "avg_trust_score": await self._get_avg_trust_score(),
                "total_scores": await self._get_total_trust_scores(),
                "anomalies_detected": await self._get_anomaly_count()
            }
        
        # Feature flags
        status["features"] = {
            "trust_scoring": self.settings.enable_trust_scoring,
            "audit_logging": self.settings.enable_audit_logging,
            "federated_auth": self.settings.enable_federated_auth,
            "mfa": self.settings.enable_mfa,
            "anomaly_detection": self.settings.enable_anomaly_detection
        }
        
        return status
    
    async def _get_avg_trust_score(self) -> float:
        """Get average trust score across all agents"""
        try:
            if not self.intelligence_engine:
                return 0.0
            
            agents = self.agent_registry.list_agents() if self.agent_registry else []
            if not agents:
                return 0.0
            
            total_score = 0.0
            count = 0
            
            for agent in agents:
                score = await self.intelligence_engine.calculate_trust_score(agent.agent_id)
                if score:
                    total_score += score.overall_score
                    count += 1
            
            return total_score / count if count > 0 else 0.0
        except:
            return 0.0
    
    async def _get_total_trust_scores(self) -> int:
        """Get total number of calculated trust scores"""
        try:
            if not self.intelligence_engine:
                return 0
            
            agents = self.agent_registry.list_agents() if self.agent_registry else []
            return len(agents)
        except:
            return 0
    
    async def _get_anomaly_count(self) -> int:
        """Get count of detected anomalies"""
        try:
            if not self.intelligence_engine:
                return 0
            
            # This would query the intelligence engine for anomaly count
            # For now, return a placeholder
            return 5
        except:
            return 0