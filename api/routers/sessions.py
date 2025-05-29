"""
Agentic-IAM: Session Management API Router

REST API endpoints for session lifecycle management, monitoring, and administration.
"""
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any

from fastapi import APIRouter, HTTPException, Depends, status
from pydantic import BaseModel

from core.agentic_iam import AgenticIAM
from api.main import get_iam, get_settings
from api.models import SuccessResponse, ErrorResponse
from config.settings import Settings


router = APIRouter()


class SessionInfo(BaseModel):
    """Session information model"""
    session_id: str
    agent_id: str
    status: str  # active, expired, terminated
    trust_level: float
    auth_method: str
    created_at: datetime
    last_accessed: datetime
    expires_at: datetime
    source_ip: Optional[str] = None
    user_agent: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None


class SessionCreateRequest(BaseModel):
    """Request to create a session"""
    agent_id: str
    auth_method: str
    trust_level: float = 1.0
    ttl: Optional[int] = None  # Custom TTL in seconds
    metadata: Optional[Dict[str, Any]] = None


class SessionUpdateRequest(BaseModel):
    """Request to update session metadata"""
    metadata: Dict[str, Any]


class SessionTerminateRequest(BaseModel):
    """Request to terminate sessions"""
    session_ids: Optional[List[str]] = None
    agent_id: Optional[str] = None
    reason: str = "manual_termination"


@router.get("/", response_model=List[SessionInfo])
async def list_sessions(
    agent_id: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
    iam: AgenticIAM = Depends(get_iam)
):
    """
    List active sessions
    
    Returns a paginated list of sessions, optionally filtered by agent or status.
    """
    try:
        if not iam.session_manager:
            raise HTTPException(
                status_code=status.HTTP_501_NOT_IMPLEMENTED,
                detail="Session management not initialized"
            )
        
        sessions = []
        
        if agent_id:
            # Get sessions for specific agent
            agent_sessions = iam.session_manager.session_store.get_agent_sessions(agent_id)
            for session in agent_sessions:
                if not status or session.status.value == status:
                    sessions.append(SessionInfo(
                        session_id=session.session_id,
                        agent_id=session.agent_id,
                        status=session.status.value,
                        trust_level=session.trust_level,
                        auth_method=session.auth_method,
                        created_at=session.created_at,
                        last_accessed=session.last_accessed,
                        expires_at=session.expires_at,
                        source_ip=session.metadata.get("source_ip"),
                        user_agent=session.metadata.get("user_agent"),
                        metadata=session.metadata
                    ))
        else:
            # Get all sessions
            all_sessions = iam.session_manager.session_store.get_all_sessions()
            for session in all_sessions:
                if not status or session.status.value == status:
                    sessions.append(SessionInfo(
                        session_id=session.session_id,
                        agent_id=session.agent_id,
                        status=session.status.value,
                        trust_level=session.trust_level,
                        auth_method=session.auth_method,
                        created_at=session.created_at,
                        last_accessed=session.last_accessed,
                        expires_at=session.expires_at,
                        source_ip=session.metadata.get("source_ip"),
                        user_agent=session.metadata.get("user_agent"),
                        metadata=session.metadata
                    ))
        
        # Apply pagination
        paginated_sessions = sessions[offset:offset+limit]
        
        return paginated_sessions
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to list sessions: {str(e)}"
        )


@router.get("/{session_id}", response_model=SessionInfo)
async def get_session(
    session_id: str,
    iam: AgenticIAM = Depends(get_iam)
):
    """
    Get detailed session information
    
    Returns comprehensive information about a specific session.
    """
    try:
        if not iam.session_manager:
            raise HTTPException(
                status_code=status.HTTP_501_NOT_IMPLEMENTED,
                detail="Session management not initialized"
            )
        
        session = iam.session_manager.get_session(session_id)
        if not session:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Session {session_id} not found"
            )
        
        return SessionInfo(
            session_id=session.session_id,
            agent_id=session.agent_id,
            status=session.status.value,
            trust_level=session.trust_level,
            auth_method=session.auth_method,
            created_at=session.created_at,
            last_accessed=session.last_accessed,
            expires_at=session.expires_at,
            source_ip=session.metadata.get("source_ip"),
            user_agent=session.metadata.get("user_agent"),
            metadata=session.metadata
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get session: {str(e)}"
        )


@router.post("/", response_model=SessionInfo)
async def create_session(
    request: SessionCreateRequest,
    iam: AgenticIAM = Depends(get_iam),
    settings: Settings = Depends(get_settings)
):
    """
    Create a new session
    
    Creates a new session for an agent with specified parameters.
    """
    try:
        if not iam.session_manager:
            raise HTTPException(
                status_code=status.HTTP_501_NOT_IMPLEMENTED,
                detail="Session management not initialized"
            )
        
        # Verify agent exists
        agent_entry = iam.agent_registry.get_agent(request.agent_id)
        if not agent_entry:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Agent {request.agent_id} not found"
            )
        
        # Calculate session TTL
        session_ttl = request.ttl or settings.session_ttl
        
        # Create session
        session_id = await iam.session_manager.create_session(
            agent_id=request.agent_id,
            trust_level=request.trust_level,
            auth_method=request.auth_method,
            ttl=session_ttl,
            metadata=request.metadata or {}
        )
        
        # Get created session
        session = iam.session_manager.get_session(session_id)
        
        # Log session creation
        if iam.audit_manager:
            from audit_compliance import AuditEventType
            await iam.audit_manager.log_event(
                event_type=AuditEventType.SESSION_CREATED,
                agent_id=request.agent_id,
                details={
                    "session_id": session_id,
                    "auth_method": request.auth_method,
                    "trust_level": request.trust_level,
                    "ttl": session_ttl
                }
            )
        
        return SessionInfo(
            session_id=session.session_id,
            agent_id=session.agent_id,
            status=session.status.value,
            trust_level=session.trust_level,
            auth_method=session.auth_method,
            created_at=session.created_at,
            last_accessed=session.last_accessed,
            expires_at=session.expires_at,
            source_ip=session.metadata.get("source_ip"),
            user_agent=session.metadata.get("user_agent"),
            metadata=session.metadata
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create session: {str(e)}"
        )


@router.put("/{session_id}/refresh", response_model=SessionInfo)
async def refresh_session(
    session_id: str,
    iam: AgenticIAM = Depends(get_iam),
    settings: Settings = Depends(get_settings)
):
    """
    Refresh a session
    
    Extends the session expiration time and updates last accessed.
    """
    try:
        if not iam.session_manager:
            raise HTTPException(
                status_code=status.HTTP_501_NOT_IMPLEMENTED,
                detail="Session management not initialized"
            )
        
        # Refresh session
        success = iam.session_manager.refresh_session(session_id)
        if not success:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Session {session_id} not found or cannot be refreshed"
            )
        
        # Get refreshed session
        session = iam.session_manager.get_session(session_id)
        
        # Log session refresh
        if iam.audit_manager:
            from audit_compliance import AuditEventType
            await iam.audit_manager.log_event(
                event_type=AuditEventType.SESSION_REFRESHED,
                agent_id=session.agent_id,
                details={
                    "session_id": session_id,
                    "new_expires_at": session.expires_at.isoformat()
                }
            )
        
        return SessionInfo(
            session_id=session.session_id,
            agent_id=session.agent_id,
            status=session.status.value,
            trust_level=session.trust_level,
            auth_method=session.auth_method,
            created_at=session.created_at,
            last_accessed=session.last_accessed,
            expires_at=session.expires_at,
            source_ip=session.metadata.get("source_ip"),
            user_agent=session.metadata.get("user_agent"),
            metadata=session.metadata
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to refresh session: {str(e)}"
        )


@router.put("/{session_id}/metadata", response_model=SessionInfo)
async def update_session_metadata(
    session_id: str,
    request: SessionUpdateRequest,
    iam: AgenticIAM = Depends(get_iam)
):
    """
    Update session metadata
    
    Updates the metadata associated with a session.
    """
    try:
        if not iam.session_manager:
            raise HTTPException(
                status_code=status.HTTP_501_NOT_IMPLEMENTED,
                detail="Session management not initialized"
            )
        
        # Get current session
        session = iam.session_manager.get_session(session_id)
        if not session:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Session {session_id} not found"
            )
        
        # Update metadata
        session.metadata.update(request.metadata)
        
        # Save updated session
        iam.session_manager.session_store.update_session(session)
        
        # Log metadata update
        if iam.audit_manager:
            from audit_compliance import AuditEventType
            await iam.audit_manager.log_event(
                event_type=AuditEventType.SESSION_UPDATED,
                agent_id=session.agent_id,
                details={
                    "session_id": session_id,
                    "updated_metadata": request.metadata
                }
            )
        
        return SessionInfo(
            session_id=session.session_id,
            agent_id=session.agent_id,
            status=session.status.value,
            trust_level=session.trust_level,
            auth_method=session.auth_method,
            created_at=session.created_at,
            last_accessed=session.last_accessed,
            expires_at=session.expires_at,
            source_ip=session.metadata.get("source_ip"),
            user_agent=session.metadata.get("user_agent"),
            metadata=session.metadata
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to update session metadata: {str(e)}"
        )


@router.delete("/{session_id}", response_model=SuccessResponse)
async def terminate_session(
    session_id: str,
    reason: str = "manual_termination",
    iam: AgenticIAM = Depends(get_iam)
):
    """
    Terminate a specific session
    
    Terminates the specified session and logs the action.
    """
    try:
        if not iam.session_manager:
            raise HTTPException(
                status_code=status.HTTP_501_NOT_IMPLEMENTED,
                detail="Session management not initialized"
            )
        
        # Get session before termination
        session = iam.session_manager.get_session(session_id)
        if not session:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Session {session_id} not found"
            )
        
        # Terminate session
        success = iam.session_manager.terminate_session(session_id, reason)
        if not success:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to terminate session {session_id}"
            )
        
        # Log session termination
        if iam.audit_manager:
            from audit_compliance import AuditEventType
            await iam.audit_manager.log_event(
                event_type=AuditEventType.SESSION_TERMINATED,
                agent_id=session.agent_id,
                details={
                    "session_id": session_id,
                    "reason": reason,
                    "duration": (datetime.utcnow() - session.created_at).total_seconds()
                }
            )
        
        return SuccessResponse(
            message=f"Session {session_id} terminated successfully",
            data={"session_id": session_id, "reason": reason}
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to terminate session: {str(e)}"
        )


@router.post("/terminate", response_model=SuccessResponse)
async def terminate_sessions(
    request: SessionTerminateRequest,
    iam: AgenticIAM = Depends(get_iam)
):
    """
    Terminate multiple sessions
    
    Terminates multiple sessions by ID or all sessions for an agent.
    """
    try:
        if not iam.session_manager:
            raise HTTPException(
                status_code=status.HTTP_501_NOT_IMPLEMENTED,
                detail="Session management not initialized"
            )
        
        terminated_count = 0
        
        if request.session_ids:
            # Terminate specific sessions
            for session_id in request.session_ids:
                success = iam.session_manager.terminate_session(session_id, request.reason)
                if success:
                    terminated_count += 1
                    
                    # Log each termination
                    if iam.audit_manager:
                        from audit_compliance import AuditEventType
                        await iam.audit_manager.log_event(
                            event_type=AuditEventType.SESSION_TERMINATED,
                            details={
                                "session_id": session_id,
                                "reason": request.reason,
                                "batch_operation": True
                            }
                        )
        
        elif request.agent_id:
            # Terminate all sessions for agent
            terminated_count = iam.session_manager.terminate_agent_sessions(
                request.agent_id, request.reason
            )
            
            # Log agent session termination
            if iam.audit_manager:
                from audit_compliance import AuditEventType
                await iam.audit_manager.log_event(
                    event_type=AuditEventType.SESSION_TERMINATED,
                    agent_id=request.agent_id,
                    details={
                        "reason": request.reason,
                        "terminated_count": terminated_count,
                        "agent_operation": True
                    }
                )
        
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Either session_ids or agent_id must be provided"
            )
        
        return SuccessResponse(
            message=f"Terminated {terminated_count} session(s) successfully",
            data={
                "terminated_count": terminated_count,
                "reason": request.reason
            }
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to terminate sessions: {str(e)}"
        )


@router.get("/stats/summary")
async def get_session_stats(
    iam: AgenticIAM = Depends(get_iam)
):
    """
    Get session statistics
    
    Returns comprehensive statistics about session usage and patterns.
    """
    try:
        if not iam.session_manager:
            raise HTTPException(
                status_code=status.HTTP_501_NOT_IMPLEMENTED,
                detail="Session management not initialized"
            )
        
        # Get all sessions
        all_sessions = iam.session_manager.session_store.get_all_sessions()
        
        # Calculate statistics
        total_sessions = len(all_sessions)
        active_sessions = len([s for s in all_sessions if s.is_active()])
        expired_sessions = len([s for s in all_sessions if s.is_expired()])
        terminated_sessions = len([s for s in all_sessions if s.status.value == "terminated"])
        
        # Auth method distribution
        auth_methods = {}
        for session in all_sessions:
            method = session.auth_method
            auth_methods[method] = auth_methods.get(method, 0) + 1
        
        # Trust level distribution
        trust_levels = {
            "high": len([s for s in all_sessions if s.trust_level >= 0.8]),
            "medium": len([s for s in all_sessions if 0.5 <= s.trust_level < 0.8]),
            "low": len([s for s in all_sessions if s.trust_level < 0.5])
        }
        
        # Session duration statistics
        durations = []
        for session in all_sessions:
            if session.status.value == "terminated":
                duration = (session.last_accessed - session.created_at).total_seconds()
                durations.append(duration)
        
        avg_duration = sum(durations) / len(durations) if durations else 0
        
        # Sessions by agent
        agent_sessions = {}
        for session in all_sessions:
            agent_id = session.agent_id
            agent_sessions[agent_id] = agent_sessions.get(agent_id, 0) + 1
        
        return {
            "total_sessions": total_sessions,
            "active_sessions": active_sessions,
            "expired_sessions": expired_sessions,
            "terminated_sessions": terminated_sessions,
            "auth_method_distribution": auth_methods,
            "trust_level_distribution": trust_levels,
            "average_session_duration": avg_duration,
            "unique_agents": len(agent_sessions),
            "sessions_per_agent": {
                "min": min(agent_sessions.values()) if agent_sessions else 0,
                "max": max(agent_sessions.values()) if agent_sessions else 0,
                "avg": sum(agent_sessions.values()) / len(agent_sessions) if agent_sessions else 0
            }
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get session statistics: {str(e)}"
        )


@router.post("/cleanup")
async def cleanup_expired_sessions(
    iam: AgenticIAM = Depends(get_iam)
):
    """
    Clean up expired sessions
    
    Manually triggers cleanup of expired sessions.
    """
    try:
        if not iam.session_manager:
            raise HTTPException(
                status_code=status.HTTP_501_NOT_IMPLEMENTED,
                detail="Session management not initialized"
            )
        
        # Run cleanup
        cleaned_count = await iam.session_manager.cleanup_expired_sessions()
        
        # Log cleanup operation
        if iam.audit_manager:
            from audit_compliance import AuditEventType
            await iam.audit_manager.log_event(
                event_type=AuditEventType.SYSTEM_MAINTENANCE,
                details={
                    "operation": "session_cleanup",
                    "cleaned_sessions": cleaned_count
                }
            )
        
        return SuccessResponse(
            message=f"Cleaned up {cleaned_count} expired session(s)",
            data={"cleaned_count": cleaned_count}
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to cleanup sessions: {str(e)}"
        )