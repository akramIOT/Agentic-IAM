"""
Agentic-IAM: Authorization API Router

REST API endpoints for authorization decisions, policy management, and access control.
"""
from datetime import datetime
from typing import List, Optional, Dict, Any

from fastapi import APIRouter, HTTPException, Depends, status
from pydantic import BaseModel

from core.agentic_iam import AgenticIAM
from api.main import get_iam, get_settings
from api.models import SuccessResponse, ErrorResponse
from config.settings import Settings


router = APIRouter()


class AuthorizationRequest(BaseModel):
    """Request model for authorization decisions"""
    agent_id: str
    resource: str
    action: str
    context: Optional[Dict[str, Any]] = None


class AuthorizationResponse(BaseModel):
    """Response model for authorization decisions"""
    agent_id: str
    resource: str
    action: str
    decision: str  # allow, deny
    reason: Optional[str] = None
    context: Optional[Dict[str, Any]] = None
    timestamp: datetime
    expires_at: Optional[datetime] = None


class PolicyRequest(BaseModel):
    """Request model for policy creation/updates"""
    name: str
    description: Optional[str] = None
    policy_type: str  # rbac, abac, pbac
    rules: Dict[str, Any]
    enabled: bool = True
    priority: int = 100


class PolicyResponse(BaseModel):
    """Response model for policy information"""
    policy_id: str
    name: str
    description: Optional[str]
    policy_type: str
    rules: Dict[str, Any]
    enabled: bool
    priority: int
    created_at: datetime
    updated_at: datetime


class RoleRequest(BaseModel):
    """Request model for role management"""
    role_name: str
    description: Optional[str] = None
    permissions: List[str]
    inherits_from: Optional[List[str]] = None


class RoleResponse(BaseModel):
    """Response model for role information"""
    role_name: str
    description: Optional[str]
    permissions: List[str]
    inherits_from: Optional[List[str]]
    created_at: datetime
    updated_at: datetime


@router.post("/authorize", response_model=AuthorizationResponse)
async def authorize_action(
    request: AuthorizationRequest,
    iam: AgenticIAM = Depends(get_iam)
):
    """
    Make an authorization decision for an agent action
    
    Evaluates whether an agent is authorized to perform a specific action
    on a resource given the current context.
    """
    try:
        # Make authorization decision
        decision = await iam.authorize(
            agent_id=request.agent_id,
            resource=request.resource,
            action=request.action,
            context=request.context
        )
        
        return AuthorizationResponse(
            agent_id=request.agent_id,
            resource=request.resource,
            action=request.action,
            decision="allow" if decision else "deny",
            reason="Access granted based on current policies" if decision else "Access denied by policy",
            context=request.context,
            timestamp=datetime.utcnow(),
            expires_at=datetime.utcnow().replace(hour=23, minute=59, second=59)  # End of day
        )
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Authorization failed: {str(e)}"
        )


@router.post("/batch-authorize")
async def batch_authorize(
    requests: List[AuthorizationRequest],
    iam: AgenticIAM = Depends(get_iam)
):
    """
    Make multiple authorization decisions in batch
    
    Efficiently evaluates multiple authorization requests for an agent.
    """
    try:
        results = []
        
        for request in requests:
            try:
                decision = await iam.authorize(
                    agent_id=request.agent_id,
                    resource=request.resource,
                    action=request.action,
                    context=request.context
                )
                
                results.append(AuthorizationResponse(
                    agent_id=request.agent_id,
                    resource=request.resource,
                    action=request.action,
                    decision="allow" if decision else "deny",
                    reason="Access granted" if decision else "Access denied",
                    context=request.context,
                    timestamp=datetime.utcnow()
                ))
                
            except Exception as e:
                results.append(AuthorizationResponse(
                    agent_id=request.agent_id,
                    resource=request.resource,
                    action=request.action,
                    decision="error",
                    reason=f"Authorization error: {str(e)}",
                    context=request.context,
                    timestamp=datetime.utcnow()
                ))
        
        return {"results": results, "total": len(results)}
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Batch authorization failed: {str(e)}"
        )


@router.get("/policies")
async def list_policies(
    policy_type: Optional[str] = None,
    enabled_only: bool = True,
    iam: AgenticIAM = Depends(get_iam)
):
    """
    List authorization policies
    
    Returns all policies or filtered by type and status.
    """
    try:
        if not iam.authorization_manager:
            raise HTTPException(
                status_code=status.HTTP_501_NOT_IMPLEMENTED,
                detail="Authorization system not initialized"
            )
        
        # Get policies from authorization manager
        policies = []
        
        # RBAC policies
        if not policy_type or policy_type == "rbac":
            rbac_engine = iam.authorization_manager.rbac_engine
            if rbac_engine:
                rbac_policies = rbac_engine.get_all_policies()
                for policy in rbac_policies:
                    policies.append(PolicyResponse(
                        policy_id=f"rbac_{policy.get('name', 'unknown')}",
                        name=policy.get("name", "RBAC Policy"),
                        description=policy.get("description"),
                        policy_type="rbac",
                        rules=policy,
                        enabled=policy.get("enabled", True),
                        priority=policy.get("priority", 100),
                        created_at=datetime.utcnow(),
                        updated_at=datetime.utcnow()
                    ))
        
        # ABAC policies
        if not policy_type or policy_type == "abac":
            abac_engine = iam.authorization_manager.abac_engine
            if abac_engine:
                abac_policies = abac_engine.get_all_policies()
                for policy in abac_policies:
                    policies.append(PolicyResponse(
                        policy_id=f"abac_{policy.get('name', 'unknown')}",
                        name=policy.get("name", "ABAC Policy"),
                        description=policy.get("description"),
                        policy_type="abac",
                        rules=policy,
                        enabled=policy.get("enabled", True),
                        priority=policy.get("priority", 100),
                        created_at=datetime.utcnow(),
                        updated_at=datetime.utcnow()
                    ))
        
        # Filter by enabled status
        if enabled_only:
            policies = [p for p in policies if p.enabled]
        
        return {"policies": policies, "total": len(policies)}
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to list policies: {str(e)}"
        )


@router.post("/policies", response_model=PolicyResponse)
async def create_policy(
    request: PolicyRequest,
    iam: AgenticIAM = Depends(get_iam)
):
    """
    Create a new authorization policy
    
    Creates a new policy in the specified authorization engine.
    """
    try:
        if not iam.authorization_manager:
            raise HTTPException(
                status_code=status.HTTP_501_NOT_IMPLEMENTED,
                detail="Authorization system not initialized"
            )
        
        # Create policy based on type
        policy_id = f"{request.policy_type}_{request.name}_{datetime.utcnow().timestamp()}"
        
        if request.policy_type == "rbac":
            engine = iam.authorization_manager.rbac_engine
            if engine:
                await engine.create_policy(
                    name=request.name,
                    rules=request.rules,
                    description=request.description,
                    enabled=request.enabled,
                    priority=request.priority
                )
        elif request.policy_type == "abac":
            engine = iam.authorization_manager.abac_engine
            if engine:
                await engine.create_policy(
                    name=request.name,
                    rules=request.rules,
                    description=request.description,
                    enabled=request.enabled,
                    priority=request.priority
                )
        elif request.policy_type == "pbac":
            engine = iam.authorization_manager.pbac_engine
            if engine:
                await engine.create_policy(
                    name=request.name,
                    rules=request.rules,
                    description=request.description,
                    enabled=request.enabled,
                    priority=request.priority
                )
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Unsupported policy type: {request.policy_type}"
            )
        
        # Log policy creation
        if iam.audit_manager:
            from audit_compliance import AuditEventType
            await iam.audit_manager.log_event(
                event_type=AuditEventType.POLICY_CREATED,
                details={
                    "policy_id": policy_id,
                    "policy_name": request.name,
                    "policy_type": request.policy_type,
                    "enabled": request.enabled
                }
            )
        
        return PolicyResponse(
            policy_id=policy_id,
            name=request.name,
            description=request.description,
            policy_type=request.policy_type,
            rules=request.rules,
            enabled=request.enabled,
            priority=request.priority,
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow()
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create policy: {str(e)}"
        )


@router.get("/roles")
async def list_roles(
    iam: AgenticIAM = Depends(get_iam)
):
    """
    List all RBAC roles
    
    Returns all roles in the RBAC system.
    """
    try:
        if not iam.authorization_manager or not iam.authorization_manager.rbac_engine:
            raise HTTPException(
                status_code=status.HTTP_501_NOT_IMPLEMENTED,
                detail="RBAC system not initialized"
            )
        
        roles = []
        rbac_roles = iam.authorization_manager.rbac_engine.get_all_roles()
        
        for role_name, role_data in rbac_roles.items():
            roles.append(RoleResponse(
                role_name=role_name,
                description=role_data.get("description"),
                permissions=role_data.get("permissions", []),
                inherits_from=role_data.get("inherits_from", []),
                created_at=datetime.utcnow(),
                updated_at=datetime.utcnow()
            ))
        
        return {"roles": roles, "total": len(roles)}
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to list roles: {str(e)}"
        )


@router.post("/roles", response_model=RoleResponse)
async def create_role(
    request: RoleRequest,
    iam: AgenticIAM = Depends(get_iam)
):
    """
    Create a new RBAC role
    
    Creates a new role with specified permissions and inheritance.
    """
    try:
        if not iam.authorization_manager or not iam.authorization_manager.rbac_engine:
            raise HTTPException(
                status_code=status.HTTP_501_NOT_IMPLEMENTED,
                detail="RBAC system not initialized"
            )
        
        # Create role
        await iam.authorization_manager.rbac_engine.create_role(
            role_name=request.role_name,
            permissions=request.permissions,
            description=request.description,
            inherits_from=request.inherits_from
        )
        
        # Log role creation
        if iam.audit_manager:
            from audit_compliance import AuditEventType
            await iam.audit_manager.log_event(
                event_type=AuditEventType.ROLE_CREATED,
                details={
                    "role_name": request.role_name,
                    "permissions": request.permissions,
                    "inherits_from": request.inherits_from
                }
            )
        
        return RoleResponse(
            role_name=request.role_name,
            description=request.description,
            permissions=request.permissions,
            inherits_from=request.inherits_from,
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow()
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create role: {str(e)}"
        )


@router.post("/agents/{agent_id}/roles/{role_name}")
async def assign_role(
    agent_id: str,
    role_name: str,
    iam: AgenticIAM = Depends(get_iam)
):
    """
    Assign a role to an agent
    
    Adds the specified role to the agent's role assignments.
    """
    try:
        if not iam.authorization_manager or not iam.authorization_manager.rbac_engine:
            raise HTTPException(
                status_code=status.HTTP_501_NOT_IMPLEMENTED,
                detail="RBAC system not initialized"
            )
        
        # Assign role
        await iam.authorization_manager.rbac_engine.assign_role(agent_id, role_name)
        
        # Log role assignment
        if iam.audit_manager:
            from audit_compliance import AuditEventType
            await iam.audit_manager.log_event(
                event_type=AuditEventType.ROLE_ASSIGNED,
                agent_id=agent_id,
                details={
                    "role_name": role_name
                }
            )
        
        return SuccessResponse(
            message=f"Role '{role_name}' assigned to agent '{agent_id}' successfully"
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to assign role: {str(e)}"
        )


@router.delete("/agents/{agent_id}/roles/{role_name}")
async def revoke_role(
    agent_id: str,
    role_name: str,
    iam: AgenticIAM = Depends(get_iam)
):
    """
    Revoke a role from an agent
    
    Removes the specified role from the agent's role assignments.
    """
    try:
        if not iam.authorization_manager or not iam.authorization_manager.rbac_engine:
            raise HTTPException(
                status_code=status.HTTP_501_NOT_IMPLEMENTED,
                detail="RBAC system not initialized"
            )
        
        # Revoke role
        await iam.authorization_manager.rbac_engine.revoke_role(agent_id, role_name)
        
        # Log role revocation
        if iam.audit_manager:
            from audit_compliance import AuditEventType
            await iam.audit_manager.log_event(
                event_type=AuditEventType.ROLE_REVOKED,
                agent_id=agent_id,
                details={
                    "role_name": role_name
                }
            )
        
        return SuccessResponse(
            message=f"Role '{role_name}' revoked from agent '{agent_id}' successfully"
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to revoke role: {str(e)}"
        )


@router.get("/agents/{agent_id}/permissions")
async def get_agent_permissions(
    agent_id: str,
    effective: bool = True,
    iam: AgenticIAM = Depends(get_iam)
):
    """
    Get permissions for an agent
    
    Returns direct permissions and/or effective permissions (including inherited).
    """
    try:
        if not iam.authorization_manager:
            raise HTTPException(
                status_code=status.HTTP_501_NOT_IMPLEMENTED,
                detail="Authorization system not initialized"
            )
        
        permissions = {
            "agent_id": agent_id,
            "direct_permissions": [],
            "effective_permissions": [],
            "roles": []
        }
        
        # Get RBAC permissions
        if iam.authorization_manager.rbac_engine:
            rbac_perms = iam.authorization_manager.rbac_engine.get_agent_permissions(
                agent_id, effective=effective
            )
            permissions["direct_permissions"].extend(rbac_perms.get("direct", []))
            permissions["effective_permissions"].extend(rbac_perms.get("effective", []))
            permissions["roles"] = rbac_perms.get("roles", [])
        
        # Get ABAC permissions
        if iam.authorization_manager.abac_engine:
            abac_perms = iam.authorization_manager.abac_engine.get_agent_permissions(agent_id)
            permissions["effective_permissions"].extend(abac_perms)
        
        # Remove duplicates
        permissions["direct_permissions"] = list(set(permissions["direct_permissions"]))
        permissions["effective_permissions"] = list(set(permissions["effective_permissions"]))
        
        return permissions
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get agent permissions: {str(e)}"
        )


@router.get("/permissions")
async def list_permissions(
    iam: AgenticIAM = Depends(get_iam)
):
    """
    List all available permissions
    
    Returns all permissions defined in the system.
    """
    try:
        if not iam.authorization_manager:
            raise HTTPException(
                status_code=status.HTTP_501_NOT_IMPLEMENTED,
                detail="Authorization system not initialized"
            )
        
        all_permissions = set()
        
        # Get permissions from RBAC
        if iam.authorization_manager.rbac_engine:
            rbac_perms = iam.authorization_manager.rbac_engine.get_all_permissions()
            all_permissions.update(rbac_perms)
        
        # Get permissions from ABAC
        if iam.authorization_manager.abac_engine:
            abac_perms = iam.authorization_manager.abac_engine.get_all_permissions()
            all_permissions.update(abac_perms)
        
        permissions = sorted(list(all_permissions))
        
        return {
            "permissions": permissions,
            "total": len(permissions),
            "categories": {
                "agent": [p for p in permissions if p.startswith("agent:")],
                "system": [p for p in permissions if p.startswith("system:")],
                "data": [p for p in permissions if p.startswith("data:")],
                "admin": [p for p in permissions if p.startswith("admin:")]
            }
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to list permissions: {str(e)}"
        )