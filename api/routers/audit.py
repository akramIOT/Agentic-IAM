"""
Agentic-IAM: Audit & Compliance API Router

REST API endpoints for audit logging, compliance reporting, and regulatory compliance.
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


class AuditEventResponse(BaseModel):
    """Audit event information"""
    event_id: str
    event_type: str
    agent_id: Optional[str]
    timestamp: datetime
    severity: str
    component: str
    outcome: str
    source_ip: Optional[str]
    user_agent: Optional[str]
    details: Dict[str, Any]


class AuditQueryRequest(BaseModel):
    """Request for audit event queries"""
    event_types: Optional[List[str]] = None
    agent_id: Optional[str] = None
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    severity: Optional[str] = None
    outcome: Optional[str] = None
    limit: int = 100
    offset: int = 0


class ComplianceReportRequest(BaseModel):
    """Request for compliance report generation"""
    framework: str  # gdpr, hipaa, sox, pci_dss
    start_date: datetime
    end_date: datetime
    include_violations: bool = True
    include_recommendations: bool = True


class ComplianceReportResponse(BaseModel):
    """Compliance report information"""
    report_id: str
    framework: str
    report_period: Dict[str, str]
    compliance_score: float
    violations_found: int
    recommendations_count: int
    sections: List[Dict[str, Any]]
    generated_at: datetime
    generated_by: str


@router.get("/events")
async def list_audit_events(
    event_type: Optional[str] = None,
    agent_id: Optional[str] = None,
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
    severity: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
    iam: AgenticIAM = Depends(get_iam)
):
    """
    List audit events
    
    Returns paginated audit events with optional filtering.
    """
    try:
        if not iam.audit_manager:
            raise HTTPException(
                status_code=status.HTTP_501_NOT_IMPLEMENTED,
                detail="Audit logging not initialized"
            )
        
        # Build query
        from audit_compliance import AuditQuery, AuditEventType
        
        # Parse event types
        event_types = None
        if event_type:
            try:
                event_types = [AuditEventType(event_type)]
            except ValueError:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Invalid event type: {event_type}"
                )
        
        # Set default time range if not provided
        if not start_time:
            start_time = datetime.utcnow() - timedelta(days=7)
        if not end_time:
            end_time = datetime.utcnow()
        
        query = AuditQuery(
            event_types=event_types,
            agent_id=agent_id,
            start_time=start_time,
            end_time=end_time,
            severity=severity,
            limit=limit,
            offset=offset
        )
        
        # Execute query
        events = iam.audit_manager.query_events(query)
        
        # Convert to response format
        event_responses = []
        for event in events:
            event_responses.append(AuditEventResponse(
                event_id=event.event_id,
                event_type=event.event_type.value,
                agent_id=event.agent_id,
                timestamp=event.timestamp,
                severity=event.severity.value,
                component=event.component,
                outcome=event.outcome,
                source_ip=event.source_ip,
                user_agent=event.user_agent,
                details=event.details
            ))
        
        return {
            "events": event_responses,
            "total": len(event_responses),
            "query_parameters": {
                "event_type": event_type,
                "agent_id": agent_id,
                "start_time": start_time.isoformat(),
                "end_time": end_time.isoformat(),
                "severity": severity,
                "limit": limit,
                "offset": offset
            }
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to list audit events: {str(e)}"
        )


@router.post("/events/query")
async def query_audit_events(
    request: AuditQueryRequest,
    iam: AgenticIAM = Depends(get_iam)
):
    """
    Advanced audit event query
    
    Performs complex queries on audit events with multiple filters.
    """
    try:
        if not iam.audit_manager:
            raise HTTPException(
                status_code=status.HTTP_501_NOT_IMPLEMENTED,
                detail="Audit logging not initialized"
            )
        
        # Build query
        from audit_compliance import AuditQuery, AuditEventType
        
        # Parse event types
        event_types = None
        if request.event_types:
            try:
                event_types = [AuditEventType(et) for et in request.event_types]
            except ValueError as e:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Invalid event type: {str(e)}"
                )
        
        query = AuditQuery(
            event_types=event_types,
            agent_id=request.agent_id,
            start_time=request.start_time,
            end_time=request.end_time,
            severity=request.severity,
            outcome=request.outcome,
            limit=request.limit,
            offset=request.offset
        )
        
        # Execute query
        events = iam.audit_manager.query_events(query)
        
        # Convert to response format
        event_responses = []
        for event in events:
            event_responses.append(AuditEventResponse(
                event_id=event.event_id,
                event_type=event.event_type.value,
                agent_id=event.agent_id,
                timestamp=event.timestamp,
                severity=event.severity.value,
                component=event.component,
                outcome=event.outcome,
                source_ip=event.source_ip,
                user_agent=event.user_agent,
                details=event.details
            ))
        
        return {
            "events": event_responses,
            "total": len(event_responses),
            "query": request.dict()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to query audit events: {str(e)}"
        )


@router.get("/events/{event_id}", response_model=AuditEventResponse)
async def get_audit_event(
    event_id: str,
    iam: AgenticIAM = Depends(get_iam)
):
    """
    Get specific audit event
    
    Returns detailed information about a specific audit event.
    """
    try:
        if not iam.audit_manager:
            raise HTTPException(
                status_code=status.HTTP_501_NOT_IMPLEMENTED,
                detail="Audit logging not initialized"
            )
        
        # Get event
        event = iam.audit_manager.get_event(event_id)
        if not event:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Audit event {event_id} not found"
            )
        
        return AuditEventResponse(
            event_id=event.event_id,
            event_type=event.event_type.value,
            agent_id=event.agent_id,
            timestamp=event.timestamp,
            severity=event.severity.value,
            component=event.component,
            outcome=event.outcome,
            source_ip=event.source_ip,
            user_agent=event.user_agent,
            details=event.details
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get audit event: {str(e)}"
        )


@router.get("/statistics")
async def get_audit_statistics(
    time_window: int = 24,  # hours
    iam: AgenticIAM = Depends(get_iam)
):
    """
    Get audit statistics
    
    Returns aggregated statistics about audit events and system activity.
    """
    try:
        if not iam.audit_manager:
            raise HTTPException(
                status_code=status.HTTP_501_NOT_IMPLEMENTED,
                detail="Audit logging not initialized"
            )
        
        # Get statistics
        start_time = datetime.utcnow() - timedelta(hours=time_window)
        stats = await iam.audit_manager.get_statistics(start_time)
        
        return {
            "statistics": stats,
            "time_window_hours": time_window,
            "generated_at": datetime.utcnow().isoformat()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get audit statistics: {str(e)}"
        )


@router.post("/integrity/verify")
async def verify_audit_integrity(
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
    iam: AgenticIAM = Depends(get_iam),
    settings: Settings = Depends(get_settings)
):
    """
    Verify audit log integrity
    
    Verifies the integrity of audit logs using cryptographic signatures.
    """
    try:
        if not iam.audit_manager:
            raise HTTPException(
                status_code=status.HTTP_501_NOT_IMPLEMENTED,
                detail="Audit logging not initialized"
            )
        
        if not settings.enable_audit_integrity:
            raise HTTPException(
                status_code=status.HTTP_501_NOT_IMPLEMENTED,
                detail="Audit integrity verification not enabled"
            )
        
        # Set default time range
        if not start_time:
            start_time = datetime.utcnow() - timedelta(days=1)
        if not end_time:
            end_time = datetime.utcnow()
        
        # Verify integrity
        result = await iam.audit_manager.verify_integrity(start_time, end_time)
        
        return {
            "integrity_check": result,
            "time_range": {
                "start": start_time.isoformat(),
                "end": end_time.isoformat()
            },
            "verified_at": datetime.utcnow().isoformat()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to verify audit integrity: {str(e)}"
        )


@router.get("/compliance/frameworks")
async def list_compliance_frameworks(
    iam: AgenticIAM = Depends(get_iam)
):
    """
    List available compliance frameworks
    
    Returns supported compliance frameworks and their configurations.
    """
    try:
        if not iam.compliance_manager:
            raise HTTPException(
                status_code=status.HTTP_501_NOT_IMPLEMENTED,
                detail="Compliance management not initialized"
            )
        
        # Get available frameworks
        frameworks = iam.compliance_manager.get_available_frameworks()
        
        return {
            "frameworks": frameworks,
            "total": len(frameworks)
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to list compliance frameworks: {str(e)}"
        )


@router.post("/compliance/reports", response_model=ComplianceReportResponse)
async def generate_compliance_report(
    request: ComplianceReportRequest,
    iam: AgenticIAM = Depends(get_iam)
):
    """
    Generate compliance report
    
    Generates a comprehensive compliance report for the specified framework.
    """
    try:
        if not iam.compliance_manager:
            raise HTTPException(
                status_code=status.HTTP_501_NOT_IMPLEMENTED,
                detail="Compliance management not initialized"
            )
        
        # Generate report
        report = await iam.compliance_manager.generate_report(
            framework=request.framework,
            start_date=request.start_date,
            end_date=request.end_date,
            include_violations=request.include_violations,
            include_recommendations=request.include_recommendations
        )
        
        # Log report generation
        if iam.audit_manager:
            from audit_compliance import AuditEventType
            await iam.audit_manager.log_event(
                event_type=AuditEventType.COMPLIANCE_REPORT_GENERATED,
                details={
                    "framework": request.framework,
                    "report_id": report.report_id,
                    "compliance_score": report.compliance_score,
                    "violations_found": report.violations_found
                }
            )
        
        return ComplianceReportResponse(
            report_id=report.report_id,
            framework=report.framework,
            report_period={
                "start": request.start_date.isoformat(),
                "end": request.end_date.isoformat()
            },
            compliance_score=report.compliance_score,
            violations_found=report.violations_found,
            recommendations_count=len(report.recommendations),
            sections=report.sections,
            generated_at=report.generated_at,
            generated_by="system"
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to generate compliance report: {str(e)}"
        )


@router.get("/compliance/reports")
async def list_compliance_reports(
    framework: Optional[str] = None,
    limit: int = 50,
    iam: AgenticIAM = Depends(get_iam)
):
    """
    List compliance reports
    
    Returns previously generated compliance reports.
    """
    try:
        if not iam.compliance_manager:
            raise HTTPException(
                status_code=status.HTTP_501_NOT_IMPLEMENTED,
                detail="Compliance management not initialized"
            )
        
        # Get reports
        reports = await iam.compliance_manager.list_reports(
            framework=framework,
            limit=limit
        )
        
        report_responses = []
        for report in reports:
            report_responses.append({
                "report_id": report.report_id,
                "framework": report.framework,
                "compliance_score": report.compliance_score,
                "violations_found": report.violations_found,
                "generated_at": report.generated_at.isoformat(),
                "report_period": {
                    "start": report.start_date.isoformat(),
                    "end": report.end_date.isoformat()
                }
            })
        
        return {
            "reports": report_responses,
            "total": len(report_responses),
            "framework_filter": framework
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to list compliance reports: {str(e)}"
        )


@router.get("/compliance/reports/{report_id}")
async def get_compliance_report(
    report_id: str,
    iam: AgenticIAM = Depends(get_iam)
):
    """
    Get detailed compliance report
    
    Returns complete compliance report with all sections and details.
    """
    try:
        if not iam.compliance_manager:
            raise HTTPException(
                status_code=status.HTTP_501_NOT_IMPLEMENTED,
                detail="Compliance management not initialized"
            )
        
        # Get report
        report = await iam.compliance_manager.get_report(report_id)
        if not report:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Compliance report {report_id} not found"
            )
        
        return {
            "report": report,
            "retrieved_at": datetime.utcnow().isoformat()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get compliance report: {str(e)}"
        )


@router.post("/compliance/assess")
async def assess_compliance(
    framework: str,
    iam: AgenticIAM = Depends(get_iam)
):
    """
    Perform real-time compliance assessment
    
    Evaluates current system state against compliance requirements.
    """
    try:
        if not iam.compliance_manager:
            raise HTTPException(
                status_code=status.HTTP_501_NOT_IMPLEMENTED,
                detail="Compliance management not initialized"
            )
        
        # Perform assessment
        assessment = await iam.compliance_manager.assess_compliance(framework)
        
        # Log assessment
        if iam.audit_manager:
            from audit_compliance import AuditEventType
            await iam.audit_manager.log_event(
                event_type=AuditEventType.COMPLIANCE_ASSESSMENT,
                details={
                    "framework": framework,
                    "compliance_score": assessment.compliance_score,
                    "violations_found": len(assessment.violations)
                }
            )
        
        return {
            "assessment": assessment,
            "framework": framework,
            "assessed_at": datetime.utcnow().isoformat()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to assess compliance: {str(e)}"
        )


@router.get("/export/events")
async def export_audit_events(
    format: str = "json",  # json, csv, xml
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
    iam: AgenticIAM = Depends(get_iam)
):
    """
    Export audit events
    
    Exports audit events in various formats for external analysis.
    """
    try:
        if not iam.audit_manager:
            raise HTTPException(
                status_code=status.HTTP_501_NOT_IMPLEMENTED,
                detail="Audit logging not initialized"
            )
        
        # Set default time range
        if not start_time:
            start_time = datetime.utcnow() - timedelta(days=7)
        if not end_time:
            end_time = datetime.utcnow()
        
        # Export events
        export_data = await iam.audit_manager.export_events(
            format=format,
            start_time=start_time,
            end_time=end_time
        )
        
        # Log export operation
        if iam.audit_manager:
            from audit_compliance import AuditEventType
            await iam.audit_manager.log_event(
                event_type=AuditEventType.DATA_EXPORT,
                details={
                    "export_type": "audit_events",
                    "format": format,
                    "time_range": {
                        "start": start_time.isoformat(),
                        "end": end_time.isoformat()
                    }
                }
            )
        
        return {
            "export_data": export_data,
            "format": format,
            "time_range": {
                "start": start_time.isoformat(),
                "end": end_time.isoformat()
            },
            "exported_at": datetime.utcnow().isoformat()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to export audit events: {str(e)}"
        )