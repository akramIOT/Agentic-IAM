"""
Agentic-IAM: Intelligence & Trust Scoring API Router

REST API endpoints for trust scoring, anomaly detection, behavioral analysis,
and AI-powered insights.
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


class TrustScoreResponse(BaseModel):
    """Trust score information"""
    agent_id: str
    overall_score: float
    risk_level: str
    confidence: float
    components: Dict[str, float]
    last_updated: datetime
    factors: List[Dict[str, Any]]
    recommendations: List[str]


class AnomalyResponse(BaseModel):
    """Anomaly detection result"""
    anomaly_id: str
    agent_id: str
    anomaly_type: str
    severity: str
    confidence: float
    detected_at: datetime
    description: str
    context: Dict[str, Any]
    recommended_actions: List[str]


class BehaviorAnalysisResponse(BaseModel):
    """Behavioral analysis result"""
    agent_id: str
    analysis_period: str
    behavior_patterns: Dict[str, Any]
    changes_detected: List[Dict[str, Any]]
    risk_indicators: List[Dict[str, Any]]
    confidence_score: float
    generated_at: datetime


class TrustUpdateRequest(BaseModel):
    """Request to update trust factors"""
    agent_id: str
    event_type: str
    event_data: Dict[str, Any]
    context: Optional[Dict[str, Any]] = None


class AnalysisRequest(BaseModel):
    """Request for behavioral analysis"""
    agent_id: str
    analysis_type: str  # behavior, risk, pattern
    time_period: int = 24  # hours
    include_recommendations: bool = True


@router.get("/trust-score/{agent_id}", response_model=TrustScoreResponse)
async def get_trust_score(
    agent_id: str,
    iam: AgenticIAM = Depends(get_iam)
):
    """
    Get trust score for an agent
    
    Returns comprehensive trust score information including components,
    risk level, and recommendations.
    """
    try:
        if not iam.intelligence_engine:
            raise HTTPException(
                status_code=status.HTTP_501_NOT_IMPLEMENTED,
                detail="Intelligence engine not initialized"
            )
        
        # Verify agent exists
        agent_entry = iam.agent_registry.get_agent(agent_id)
        if not agent_entry:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Agent {agent_id} not found"
            )
        
        # Calculate trust score
        trust_score = await iam.intelligence_engine.calculate_trust_score(agent_id)
        if not trust_score:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Trust score not available for agent {agent_id}"
            )
        
        # Get trust factors and recommendations
        factors = await iam.intelligence_engine.get_trust_factors(agent_id)
        recommendations = await iam.intelligence_engine.get_trust_recommendations(agent_id)
        
        return TrustScoreResponse(
            agent_id=agent_id,
            overall_score=trust_score.overall_score,
            risk_level=trust_score.risk_level.value,
            confidence=trust_score.confidence,
            components=trust_score.component_scores,
            last_updated=trust_score.last_updated,
            factors=factors,
            recommendations=recommendations
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get trust score: {str(e)}"
        )


@router.post("/trust-score/update", response_model=TrustScoreResponse)
async def update_trust_score(
    request: TrustUpdateRequest,
    iam: AgenticIAM = Depends(get_iam)
):
    """
    Update trust score based on new event
    
    Updates the trust score for an agent based on a new security event
    or behavioral observation.
    """
    try:
        if not iam.intelligence_engine:
            raise HTTPException(
                status_code=status.HTTP_501_NOT_IMPLEMENTED,
                detail="Intelligence engine not initialized"
            )
        
        # Update trust score
        await iam.intelligence_engine.update_trust_score(
            agent_id=request.agent_id,
            event_type=request.event_type,
            event_data=request.event_data,
            context=request.context or {}
        )
        
        # Get updated trust score
        trust_score = await iam.intelligence_engine.calculate_trust_score(request.agent_id)
        
        # Get updated factors and recommendations
        factors = await iam.intelligence_engine.get_trust_factors(request.agent_id)
        recommendations = await iam.intelligence_engine.get_trust_recommendations(request.agent_id)
        
        # Log trust score update
        if iam.audit_manager:
            from audit_compliance import AuditEventType
            await iam.audit_manager.log_event(
                event_type=AuditEventType.TRUST_SCORE_UPDATED,
                agent_id=request.agent_id,
                details={
                    "event_type": request.event_type,
                    "new_score": trust_score.overall_score,
                    "risk_level": trust_score.risk_level.value
                }
            )
        
        return TrustScoreResponse(
            agent_id=request.agent_id,
            overall_score=trust_score.overall_score,
            risk_level=trust_score.risk_level.value,
            confidence=trust_score.confidence,
            components=trust_score.component_scores,
            last_updated=trust_score.last_updated,
            factors=factors,
            recommendations=recommendations
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to update trust score: {str(e)}"
        )


@router.get("/anomalies")
async def list_anomalies(
    agent_id: Optional[str] = None,
    severity: Optional[str] = None,
    time_window: int = 24,  # hours
    limit: int = 100,
    iam: AgenticIAM = Depends(get_iam)
):
    """
    List detected anomalies
    
    Returns anomalies detected in the specified time window, optionally
    filtered by agent or severity.
    """
    try:
        if not iam.intelligence_engine:
            raise HTTPException(
                status_code=status.HTTP_501_NOT_IMPLEMENTED,
                detail="Intelligence engine not initialized"
            )
        
        # Get anomalies from intelligence engine
        start_time = datetime.utcnow() - timedelta(hours=time_window)
        anomalies = await iam.intelligence_engine.get_anomalies(
            agent_id=agent_id,
            severity=severity,
            start_time=start_time,
            limit=limit
        )
        
        anomaly_responses = []
        for anomaly in anomalies:
            anomaly_responses.append(AnomalyResponse(
                anomaly_id=anomaly.anomaly_id,
                agent_id=anomaly.agent_id,
                anomaly_type=anomaly.anomaly_type,
                severity=anomaly.severity.value,
                confidence=anomaly.confidence,
                detected_at=anomaly.detected_at,
                description=anomaly.description,
                context=anomaly.context,
                recommended_actions=anomaly.recommended_actions
            ))
        
        return {
            "anomalies": anomaly_responses,
            "total": len(anomaly_responses),
            "time_window_hours": time_window
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to list anomalies: {str(e)}"
        )


@router.get("/anomalies/{anomaly_id}", response_model=AnomalyResponse)
async def get_anomaly(
    anomaly_id: str,
    iam: AgenticIAM = Depends(get_iam)
):
    """
    Get detailed anomaly information
    
    Returns comprehensive information about a specific anomaly.
    """
    try:
        if not iam.intelligence_engine:
            raise HTTPException(
                status_code=status.HTTP_501_NOT_IMPLEMENTED,
                detail="Intelligence engine not initialized"
            )
        
        anomaly = await iam.intelligence_engine.get_anomaly(anomaly_id)
        if not anomaly:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Anomaly {anomaly_id} not found"
            )
        
        return AnomalyResponse(
            anomaly_id=anomaly.anomaly_id,
            agent_id=anomaly.agent_id,
            anomaly_type=anomaly.anomaly_type,
            severity=anomaly.severity.value,
            confidence=anomaly.confidence,
            detected_at=anomaly.detected_at,
            description=anomaly.description,
            context=anomaly.context,
            recommended_actions=anomaly.recommended_actions
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get anomaly: {str(e)}"
        )


@router.post("/analyze", response_model=BehaviorAnalysisResponse)
async def analyze_behavior(
    request: AnalysisRequest,
    iam: AgenticIAM = Depends(get_iam)
):
    """
    Perform behavioral analysis
    
    Analyzes agent behavior patterns and identifies potential risks
    or unusual activities.
    """
    try:
        if not iam.intelligence_engine:
            raise HTTPException(
                status_code=status.HTTP_501_NOT_IMPLEMENTED,
                detail="Intelligence engine not initialized"
            )
        
        # Verify agent exists
        agent_entry = iam.agent_registry.get_agent(request.agent_id)
        if not agent_entry:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Agent {request.agent_id} not found"
            )
        
        # Perform analysis
        analysis = await iam.intelligence_engine.analyze_behavior(
            agent_id=request.agent_id,
            analysis_type=request.analysis_type,
            time_period=request.time_period,
            include_recommendations=request.include_recommendations
        )
        
        # Log analysis request
        if iam.audit_manager:
            from audit_compliance import AuditEventType
            await iam.audit_manager.log_event(
                event_type=AuditEventType.BEHAVIOR_ANALYSIS,
                agent_id=request.agent_id,
                details={
                    "analysis_type": request.analysis_type,
                    "time_period": request.time_period,
                    "confidence": analysis.confidence_score
                }
            )
        
        return BehaviorAnalysisResponse(
            agent_id=request.agent_id,
            analysis_period=f"{request.time_period} hours",
            behavior_patterns=analysis.behavior_patterns,
            changes_detected=analysis.changes_detected,
            risk_indicators=analysis.risk_indicators,
            confidence_score=analysis.confidence_score,
            generated_at=datetime.utcnow()
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to analyze behavior: {str(e)}"
        )


@router.get("/insights/risk-summary")
async def get_risk_summary(
    time_window: int = 24,  # hours
    iam: AgenticIAM = Depends(get_iam)
):
    """
    Get platform-wide risk summary
    
    Returns aggregated risk information across all agents and systems.
    """
    try:
        if not iam.intelligence_engine:
            raise HTTPException(
                status_code=status.HTTP_501_NOT_IMPLEMENTED,
                detail="Intelligence engine not initialized"
            )
        
        # Get risk summary from intelligence engine
        summary = await iam.intelligence_engine.get_risk_summary(
            time_window_hours=time_window
        )
        
        return {
            "risk_summary": summary,
            "time_window_hours": time_window,
            "generated_at": datetime.utcnow().isoformat()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get risk summary: {str(e)}"
        )


@router.get("/insights/trust-trends")
async def get_trust_trends(
    agent_id: Optional[str] = None,
    time_window: int = 168,  # 7 days
    iam: AgenticIAM = Depends(get_iam)
):
    """
    Get trust score trends
    
    Returns trust score trends over time for an agent or platform-wide.
    """
    try:
        if not iam.intelligence_engine:
            raise HTTPException(
                status_code=status.HTTP_501_NOT_IMPLEMENTED,
                detail="Intelligence engine not initialized"
            )
        
        # Get trust trends
        trends = await iam.intelligence_engine.get_trust_trends(
            agent_id=agent_id,
            time_window_hours=time_window
        )
        
        return {
            "trends": trends,
            "agent_id": agent_id,
            "time_window_hours": time_window,
            "generated_at": datetime.utcnow().isoformat()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get trust trends: {str(e)}"
        )


@router.get("/insights/recommendations/{agent_id}")
async def get_agent_recommendations(
    agent_id: str,
    category: Optional[str] = None,  # security, performance, trust
    iam: AgenticIAM = Depends(get_iam)
):
    """
    Get recommendations for an agent
    
    Returns AI-generated recommendations for improving agent security,
    performance, or trust score.
    """
    try:
        if not iam.intelligence_engine:
            raise HTTPException(
                status_code=status.HTTP_501_NOT_IMPLEMENTED,
                detail="Intelligence engine not initialized"
            )
        
        # Verify agent exists
        agent_entry = iam.agent_registry.get_agent(agent_id)
        if not agent_entry:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Agent {agent_id} not found"
            )
        
        # Get recommendations
        recommendations = await iam.intelligence_engine.get_recommendations(
            agent_id=agent_id,
            category=category
        )
        
        return {
            "agent_id": agent_id,
            "category": category,
            "recommendations": recommendations,
            "generated_at": datetime.utcnow().isoformat()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get recommendations: {str(e)}"
        )


@router.post("/models/retrain")
async def retrain_ml_models(
    model_type: Optional[str] = None,  # trust, anomaly, behavior
    iam: AgenticIAM = Depends(get_iam),
    settings: Settings = Depends(get_settings)
):
    """
    Trigger ML model retraining
    
    Retrains machine learning models with latest data.
    """
    try:
        if not iam.intelligence_engine:
            raise HTTPException(
                status_code=status.HTTP_501_NOT_IMPLEMENTED,
                detail="Intelligence engine not initialized"
            )
        
        if not settings.enable_experimental_features:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Model retraining requires experimental features to be enabled"
            )
        
        # Trigger retraining
        result = await iam.intelligence_engine.retrain_models(model_type=model_type)
        
        # Log retraining request
        if iam.audit_manager:
            from audit_compliance import AuditEventType
            await iam.audit_manager.log_event(
                event_type=AuditEventType.SYSTEM_MAINTENANCE,
                details={
                    "operation": "model_retraining",
                    "model_type": model_type or "all",
                    "status": "initiated"
                }
            )
        
        return SuccessResponse(
            message=f"Model retraining initiated for {model_type or 'all'} models",
            data=result
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrain models: {str(e)}"
        )


@router.get("/models/status")
async def get_model_status(
    iam: AgenticIAM = Depends(get_iam)
):
    """
    Get ML model status
    
    Returns status information about the intelligence engine models.
    """
    try:
        if not iam.intelligence_engine:
            raise HTTPException(
                status_code=status.HTTP_501_NOT_IMPLEMENTED,
                detail="Intelligence engine not initialized"
            )
        
        # Get model status
        status = await iam.intelligence_engine.get_model_status()
        
        return {
            "model_status": status,
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get model status: {str(e)}"
        )


@router.get("/statistics")
async def get_intelligence_statistics(
    iam: AgenticIAM = Depends(get_iam)
):
    """
    Get intelligence engine statistics
    
    Returns comprehensive statistics about trust scoring, anomaly detection,
    and behavioral analysis.
    """
    try:
        if not iam.intelligence_engine:
            raise HTTPException(
                status_code=status.HTTP_501_NOT_IMPLEMENTED,
                detail="Intelligence engine not initialized"
            )
        
        # Get statistics
        stats = await iam.intelligence_engine.get_statistics()
        
        return {
            "statistics": stats,
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get intelligence statistics: {str(e)}"
        )