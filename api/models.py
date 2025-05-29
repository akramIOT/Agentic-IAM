"""
Agentic-IAM: API Models

Pydantic models for request/response serialization and validation.
"""
from datetime import datetime
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field, validator


# Base models
class BaseResponse(BaseModel):
    """Base response model"""
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    

class SuccessResponse(BaseResponse):
    """Success response model"""
    success: bool = True
    message: str
    data: Optional[Dict[str, Any]] = None


class ErrorResponse(BaseResponse):
    """Error response model"""
    success: bool = False
    error_code: str
    error_message: str
    details: Optional[Dict[str, Any]] = None


# Authentication models
class AuthenticationRequest(BaseModel):
    """Authentication request"""
    agent_id: str = Field(..., min_length=1, description="Agent identifier")
    method: str = Field(default="auto", description="Authentication method")
    credentials: Dict[str, Any] = Field(..., description="Authentication credentials")
    source_ip: Optional[str] = Field(None, description="Source IP address")
    user_agent: Optional[str] = Field(None, description="User agent string")
    
    @validator('agent_id')
    def validate_agent_id(cls, v):
        if not v.startswith('agent:'):
            raise ValueError('Agent ID must start with "agent:"')
        return v


class AuthenticationResponse(BaseResponse):
    """Authentication response"""
    success: bool
    agent_id: Optional[str] = None
    token: Optional[str] = None
    expires_at: Optional[datetime] = None
    session_id: Optional[str] = None
    trust_level: Optional[float] = None
    auth_method: Optional[str] = None
    error_message: Optional[str] = None


class TokenRefreshRequest(BaseModel):
    """Token refresh request"""
    session_id: str = Field(..., description="Session identifier")
    refresh_token: Optional[str] = Field(None, description="Refresh token")


# Agent models
class AgentCreateRequest(BaseModel):
    """Agent creation request"""
    agent_id: str = Field(..., description="Unique agent identifier")
    agent_type: str = Field(..., description="Type of agent")
    description: Optional[str] = Field(None, description="Agent description")
    capabilities: List[str] = Field(default_factory=list, description="Agent capabilities")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional metadata")
    initial_permissions: List[str] = Field(default_factory=list, description="Initial permissions")
    
    @validator('agent_id')
    def validate_agent_id(cls, v):
        if not v.startswith('agent:'):
            raise ValueError('Agent ID must start with "agent:"')
        return v


class AgentUpdateRequest(BaseModel):
    """Agent update request"""
    description: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None
    status: Optional[str] = None
    
    @validator('status')
    def validate_status(cls, v):
        if v and v not in ['active', 'inactive', 'suspended', 'deactivated']:
            raise ValueError('Invalid status')
        return v


class AgentResponse(BaseResponse):
    """Agent information response"""
    agent_id: str
    status: str
    agent_type: str
    description: Optional[str]
    capabilities: List[str]
    metadata: Dict[str, Any]
    registration_date: datetime
    last_accessed: datetime
    trust_score: Optional[float] = None
    active_sessions: int = 0


class AgentListResponse(BaseResponse):
    """Agent list response"""
    agents: List[AgentResponse]
    total: int
    page: int = 1
    page_size: int = 100
    has_more: bool = False


# Session models
class SessionCreateRequest(BaseModel):
    """Session creation request"""
    agent_id: str
    auth_method: str = "jwt"
    trust_level: float = Field(default=1.0, ge=0.0, le=1.0)
    ttl: Optional[int] = Field(None, description="Session TTL in seconds")
    metadata: Dict[str, Any] = Field(default_factory=dict)


class SessionResponse(BaseResponse):
    """Session information response"""
    session_id: str
    agent_id: str
    status: str
    trust_level: float
    auth_method: str
    created_at: datetime
    last_accessed: datetime
    expires_at: datetime
    metadata: Dict[str, Any]


# Authorization models
class AuthorizationRequest(BaseModel):
    """Authorization request"""
    agent_id: str
    resource: str = Field(..., description="Resource being accessed")
    action: str = Field(..., description="Action being performed")
    context: Dict[str, Any] = Field(default_factory=dict, description="Request context")


class AuthorizationResponse(BaseResponse):
    """Authorization response"""
    agent_id: str
    resource: str
    action: str
    decision: str  # allow, deny
    reason: Optional[str] = None
    context: Dict[str, Any]


# Trust scoring models
class TrustScoreRequest(BaseModel):
    """Trust score calculation request"""
    agent_id: str
    include_history: bool = False
    time_window_hours: int = Field(default=24, ge=1, le=8760)  # 1 hour to 1 year


class TrustScoreResponse(BaseResponse):
    """Trust score response"""
    agent_id: str
    overall_score: float = Field(..., ge=0.0, le=1.0)
    risk_level: str
    confidence: float = Field(..., ge=0.0, le=1.0)
    components: Dict[str, float]
    last_updated: datetime
    factors: List[Dict[str, Any]] = Field(default_factory=list)
    recommendations: List[str] = Field(default_factory=list)


# Audit models
class AuditEventResponse(BaseResponse):
    """Audit event response"""
    event_id: str
    event_type: str
    agent_id: Optional[str]
    component: str
    severity: str
    outcome: str
    source_ip: Optional[str]
    user_agent: Optional[str]
    details: Dict[str, Any]


class AuditQueryRequest(BaseModel):
    """Audit query request"""
    event_types: Optional[List[str]] = None
    agent_id: Optional[str] = None
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    severity: Optional[str] = None
    outcome: Optional[str] = None
    limit: int = Field(default=100, ge=1, le=1000)
    offset: int = Field(default=0, ge=0)


# Compliance models
class ComplianceReportRequest(BaseModel):
    """Compliance report request"""
    framework: str = Field(..., description="Compliance framework")
    start_date: datetime
    end_date: datetime
    include_violations: bool = True
    include_recommendations: bool = True
    
    @validator('framework')
    def validate_framework(cls, v):
        allowed = ['gdpr', 'hipaa', 'sox', 'pci_dss']
        if v.lower() not in allowed:
            raise ValueError(f'Framework must be one of: {allowed}')
        return v.lower()


class ComplianceReportResponse(BaseResponse):
    """Compliance report response"""
    report_id: str
    framework: str
    report_period: Dict[str, str]
    compliance_score: float = Field(..., ge=0.0, le=100.0)
    violations_found: int = Field(..., ge=0)
    recommendations_count: int = Field(..., ge=0)
    sections: List[Dict[str, Any]]
    generated_by: str


# Analytics models
class AnalyticsRequest(BaseModel):
    """Analytics request"""
    metric_type: str = Field(..., description="Type of metric")
    time_range: str = Field(default="24h", description="Time range")
    agent_id: Optional[str] = None
    granularity: str = Field(default="hour", description="Data granularity")
    
    @validator('time_range')
    def validate_time_range(cls, v):
        allowed = ['1h', '6h', '24h', '7d', '30d']
        if v not in allowed:
            raise ValueError(f'Time range must be one of: {allowed}')
        return v


class AnalyticsResponse(BaseResponse):
    """Analytics response"""
    metric_type: str
    time_range: str
    data_points: List[Dict[str, Any]]
    summary: Dict[str, Any]
    generated_at: datetime


# Health models
class HealthResponse(BaseResponse):
    """Health check response"""
    status: str
    version: str
    uptime: float
    components: Dict[str, str]
    checks: Dict[str, Dict[str, Any]]


# Pagination models
class PaginationRequest(BaseModel):
    """Pagination request"""
    page: int = Field(default=1, ge=1, description="Page number")
    page_size: int = Field(default=100, ge=1, le=1000, description="Items per page")
    sort_by: Optional[str] = Field(None, description="Sort field")
    sort_order: str = Field(default="asc", description="Sort order")
    
    @validator('sort_order')
    def validate_sort_order(cls, v):
        if v not in ['asc', 'desc']:
            raise ValueError('Sort order must be "asc" or "desc"')
        return v


class PaginatedResponse(BaseResponse):
    """Paginated response"""
    items: List[Any]
    total: int
    page: int
    page_size: int
    total_pages: int
    has_previous: bool
    has_next: bool


# Configuration models
class ConfigurationUpdateRequest(BaseModel):
    """Configuration update request"""
    section: str = Field(..., description="Configuration section")
    settings: Dict[str, Any] = Field(..., description="Settings to update")
    
    @validator('section')
    def validate_section(cls, v):
        allowed = ['auth', 'session', 'trust', 'audit', 'compliance']
        if v not in allowed:
            raise ValueError(f'Section must be one of: {allowed}')
        return v


class ConfigurationResponse(BaseResponse):
    """Configuration response"""
    section: str
    settings: Dict[str, Any]
    last_updated: datetime
    updated_by: str


# Metrics models
class MetricsResponse(BaseResponse):
    """Metrics response"""
    metrics: Dict[str, Any]
    timestamp: datetime
    collection_interval: int


# Notification models
class NotificationRequest(BaseModel):
    """Notification request"""
    recipient: str = Field(..., description="Notification recipient")
    message: str = Field(..., description="Notification message")
    priority: str = Field(default="normal", description="Notification priority")
    channel: str = Field(default="email", description="Notification channel")
    
    @validator('priority')
    def validate_priority(cls, v):
        if v not in ['low', 'normal', 'high', 'critical']:
            raise ValueError('Priority must be low, normal, high, or critical')
        return v


class NotificationResponse(BaseResponse):
    """Notification response"""
    notification_id: str
    status: str
    sent_at: datetime