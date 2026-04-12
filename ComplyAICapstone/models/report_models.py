# -*- coding: utf-8 -*-
"""
Pydantic models for NIST CSF compliance reporting.

This module defines structured data models for:
- Questionnaire answers
- Compliance gaps and risk assessment
- Final compliance reports
- Export-ready data structures
"""

from datetime import datetime
from enum import Enum
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field, validator


class RiskLevel(str, Enum):
    """Risk level enumeration for compliance findings."""
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


class NISTFunction(str, Enum):
    """NIST CSF 2.0 function enumeration."""
    GOVERN = "Govern"
    IDENTIFY = "Identify"
    PROTECT = "Protect"
    DETECT = "Detect"
    RESPOND = "Respond"
    RECOVER = "Recover"


class QuestionType(str, Enum):
    """Question type enumeration."""
    MULTIPLE_CHOICE = "multiple_choice"
    YES_NO = "yes_no"
    TEXT = "text"
    SCALE = "scale"


class QuestionAnswer(BaseModel):
    """Model for individual questionnaire responses."""
    question_id: str = Field(..., description="Unique question identifier", max_length=200)
    question_text: str = Field(..., description="Full question text", max_length=2000)
    question_type: QuestionType = Field(..., description="Type of question")
    nist_function: NISTFunction = Field(..., description="NIST CSF function")
    category: str = Field(..., description="NIST CSF category", max_length=200)
    subcategory: str = Field(..., description="NIST CSF subcategory", max_length=200)
    answer: str = Field(..., description="User's answer", max_length=5000)
    confidence: Optional[float] = Field(None, ge=0, le=1, description="Confidence score 0-1")
    evidence: Optional[str] = Field(None, description="Supporting evidence or notes", max_length=5000)
    timestamp: datetime = Field(default_factory=datetime.now, description="When answered")
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }


class ComplianceGap(BaseModel):
    """Model for identified compliance gaps."""
    gap_id: str = Field(..., description="Unique gap identifier", max_length=200)
    control_id: str = Field(..., description="NIST control identifier", max_length=200)
    control_title: str = Field(..., description="NIST control title", max_length=500)
    nist_function: NISTFunction = Field(..., description="NIST CSF function")
    category: str = Field(..., description="NIST CSF category", max_length=200)
    subcategory: str = Field(..., description="NIST CSF subcategory", max_length=200)
    description: str = Field(..., description="Gap description", max_length=5000)
    reasoning: str = Field(..., description="AI reasoning for gap identification", max_length=5000)
    risk_level: RiskLevel = Field(..., description="Risk level")
    affected_assets: List[str] = Field(default_factory=list, description="Affected systems/assets")
    evidence_sources: List[str] = Field(default_factory=list, description="Source evidence")
    source_metadata: List[Dict[str, Any]] = Field(default_factory=list, description="Source references with page and snippet metadata")
    related_questions: List[str] = Field(default_factory=list, description="Related question IDs")
    confidence_score: float = Field(..., ge=0, le=1, description="AI confidence 0-1")
    
    @validator('confidence_score')
    def validate_confidence(cls, v):
        if not 0 <= v <= 1:
            raise ValueError('Confidence score must be between 0 and 1')
        return v


class RiskItem(BaseModel):
    """Model for individual risk assessment items."""
    risk_id: str = Field(..., description="Unique risk identifier", max_length=200)
    title: str = Field(..., description="Risk title", max_length=500)
    description: str = Field(..., description="Risk description", max_length=5000)
    risk_level: RiskLevel = Field(..., description="Risk level")
    likelihood: str = Field(..., description="Likelihood assessment", max_length=200)
    impact: str = Field(..., description="Impact assessment", max_length=200)
    nist_function: NISTFunction = Field(..., description="Primary NIST function")
    related_gaps: List[str] = Field(default_factory=list, description="Related gap IDs")
    mitigation_status: str = Field(default="Unmitigated", description="Current mitigation status", max_length=200)
    business_impact: str = Field(..., description="Business impact description", max_length=5000)


class Recommendation(BaseModel):
    """Model for remediation recommendations."""
    recommendation_id: str = Field(..., description="Unique recommendation identifier", max_length=200)
    title: str = Field(..., description="Recommendation title", max_length=500)
    description: str = Field(..., description="Detailed recommendation", max_length=5000)
    priority: str = Field(..., description="Priority level (High/Medium/Low)", max_length=200)
    nist_function: NISTFunction = Field(..., description="Target NIST function")
    related_gaps: List[str] = Field(default_factory=list, description="Related gap IDs")
    related_risks: List[str] = Field(default_factory=list, description="Related risk IDs")
    implementation_steps: List[str] = Field(default_factory=list, description="Implementation steps")
    estimated_effort: str = Field(..., description="Implementation effort estimate", max_length=500)
    dependencies: List[str] = Field(default_factory=list, description="Dependencies")
    success_criteria: List[str] = Field(default_factory=list, description="Success criteria")
    
    @validator('priority')
    def validate_priority(cls, v):
        if v not in ['High', 'Medium', 'Low']:
            raise ValueError('Priority must be High, Medium, or Low')
        return v


class OrganizationInfo(BaseModel):
    """Model for organization metadata."""
    organization_name: str = Field(..., description="Organization name", max_length=500)
    industry: str = Field(..., description="Industry sector", max_length=200)
    size: str = Field(..., description="Organization size", max_length=200)
    contact_person: str = Field(..., description="Contact person", max_length=200)
    contact_email: str = Field(..., description="Contact email", max_length=200)
    assessment_date: datetime = Field(default_factory=datetime.now, description="Assessment date")
    assessor_name: Optional[str] = Field(None, description="Assessor name", max_length=200)
    scope: str = Field(..., description="Assessment scope", max_length=2000)


class ComplianceSummary(BaseModel):
    """Model for compliance summary statistics."""
    total_gaps: int = Field(..., description="Total number of gaps found")
    gaps_by_function: Dict[NISTFunction, int] = Field(..., description="Gaps by NIST function")
    gaps_by_risk_level: Dict[RiskLevel, int] = Field(..., description="Gaps by risk level")
    overall_risk_score: float = Field(..., ge=0, le=10, description="Overall risk score 0-10")
    compliance_percentage: float = Field(..., ge=0, le=100, description="Compliance percentage")
    critical_findings: int = Field(..., description="Number of critical findings")
    high_priority_recommendations: int = Field(..., description="High priority recommendations count")


class FinalReport(BaseModel):
    """Complete compliance report model."""
    report_id: str = Field(..., description="Unique report identifier", max_length=200)
    organization_info: OrganizationInfo = Field(..., description="Organization details")
    compliance_summary: ComplianceSummary = Field(..., description="Summary statistics")
    questionnaire_answers: List[QuestionAnswer] = Field(..., description="All questionnaire responses")
    compliance_gaps: List[ComplianceGap] = Field(..., description="Identified gaps")
    risk_assessment: List[RiskItem] = Field(..., description="Risk assessment items")
    recommendations: List[Recommendation] = Field(..., description="Remediation recommendations")
    heatmap: Any = Field(default=None, description="Heatmap risk analysis report")
    document_analysis: Dict[str, Any] = Field(..., description="Document analysis results")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional metadata")
    generated_at: datetime = Field(default_factory=datetime.now, description="Report generation timestamp")
    version: str = Field(default="1.0", description="Report version", max_length=20)
    ai_confidence_score: Optional[float] = Field(None, ge=0, le=1, description="Aggregate AI confidence score 0-1")
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }


class QuestionnaireTemplate(BaseModel):
    """Model for questionnaire templates."""
    template_id: str = Field(..., description="Template identifier", max_length=200)
    nist_function: NISTFunction = Field(..., description="NIST function")
    category: str = Field(..., description="Category", max_length=200)
    subcategory: str = Field(..., description="Subcategory", max_length=200)
    questions: List[Dict[str, Any]] = Field(..., description="Questions list")
    description: str = Field(..., description="Template description", max_length=2000)
    estimated_time: int = Field(..., description="Estimated completion time (minutes)")


class ReportExportRequest(BaseModel):
    """Model for report export requests."""
    report_id: str = Field(..., description="Report ID to export", max_length=200)
    format: str = Field(..., description="Export format (pdf/docx)", max_length=20)
    include_attachments: bool = Field(default=False, description="Include attachments")
    watermark: Optional[str] = Field(None, description="Optional watermark text", max_length=500)
    
    @validator('format')
    def validate_format(cls, v):
        if v not in ['pdf', 'docx']:
            raise ValueError('Format must be pdf or docx')
        return v


class AnalysisContext(BaseModel):
    """Model for LLM analysis context."""
    document_text: str = Field(..., description="Extracted document text", max_length=10000)
    questionnaire_answers: List[QuestionAnswer] = Field(..., description="Questionnaire responses")
    organization_metadata: Dict[str, Any] = Field(..., description="Organization info")
    nist_controls_context: Dict[str, Any] = Field(..., description="NIST controls context")
    analysis_instructions: str = Field(..., description="Analysis instructions", max_length=5000)
    output_format: str = Field(default="json", description="Expected output format", max_length=20)


class RiskApproach(str, Enum):
    """Risk approach enumeration."""
    VERY_CONSERVATIVE = "Very conservative"
    CONSERVATIVE = "Conservative"
    BALANCED = "Balanced"
    AGGRESSIVE = "Aggressive"
    VERY_AGGRESSIVE = "Very aggressive"


class MaxAcceptableRisk(str, Enum):
    """Maximum acceptable risk level."""
    ONLY_LOW = "Only Low"
    LOW_AND_MEDIUM = "Low and some Medium"
    MEDIUM_WITH_MITIGATION = "Medium acceptable; High must be mitigated"
    HIGH_WITH_APPROVAL = "High acceptable with management sign-off"


class RiskTreatment(str, Enum):
    """Risk treatment preference."""
    REDUCE = "Reduce (add controls)"
    TRANSFER = "Transfer (insurance, contracts)"
    AVOID = "Avoid (change design, stop activity)"
    ACCEPT = "Accept with justification"


class MitigationTimeline(str, Enum):
    """Expected mitigation timeline for high risks."""
    ONE_MONTH = "1 month"
    THREE_MONTHS = "3 months"
    EXECUTIVE_APPROVAL = "Executive approval"
    OTHER = "Other"


class ImpactType(str, Enum):
    """Types of potential harms."""
    HARM_TO_INDIVIDUALS = "Harm to individuals (safety, rights, discrimination)"
    REGULATORY_LEGAL = "Regulatory / legal breaches"
    FINANCIAL_LOSS = "Financial loss"
    SERVICE_DOWNTIME = "Service downtime / operational disruption"
    REPUTATIONAL = "Reputational damage"
    ENVIRONMENTAL = "Environmental / societal harm"


class RiskAppetiteProfile(BaseModel):
    """Model for organizational risk appetite."""
    profile_id: str = Field(..., description="Unique profile identifier")
    session_id: str = Field(..., description="Session ID for questionnaire")
    organization_name: str = Field(..., description="Organization name")
    assessment_date: datetime = Field(default_factory=datetime.now, description="When profile was created")
    
    # Q1: Overall risk posture
    overall_risk_posture: RiskApproach = Field(..., description="Organization's general approach to risk")
    
    # Q2: Maximum acceptable risk level
    max_acceptable_risk: MaxAcceptableRisk = Field(..., description="Highest acceptable risk level")
    
    # Q3: Impact sensitivity (top 2-3)
    impact_sensitivities: List[ImpactType] = Field(..., description="Types of harms organization least tolerates")
    
    # Q4: Prioritization rules
    high_risk_mitigation_timeline: MitigationTimeline = Field(..., description="Expected response timeline for High risks")
    high_risk_mitigation_timeline_other: Optional[str] = Field(None, description="Custom timeline if 'Other' selected")
    
    # Q5: Treatment preference
    preferred_risk_treatment: RiskTreatment = Field(..., description="Usual preferred risk treatment")


class HeatMapItem(BaseModel):
    """Model for individual heat-map items (documents/policies/systems)."""
    item_id: str = Field(..., description="Unique item identifier")
    name: str = Field(..., description="Document/policy/system name")
    description: str = Field(..., description="Short description of what it governs/controls")
    
    # H2: Impact score (1-5)
    impact_score: int = Field(..., ge=1, le=5, description="Impact score (1=minimal, 5=critical)")
    
    # H3: Likelihood score (1-5)
    likelihood_score: int = Field(..., ge=1, le=5, description="Likelihood score (1=unlikely, 5=very likely)")
    
    # H4: Primary risk type
    primary_risk_type: str = Field(..., description="Main nature of risk (Safety, Regulatory, Privacy, Financial, Operational, Fairness)")
    
    # H5: Residual risk level (expert judgment)
    residual_risk_level: str = Field(..., description="Residual risk: Low/Medium/High")


class HeatMapAnalysis(BaseModel):
    """Model for heat-map risk analysis result."""
    item_id: str = Field(..., description="Item being analyzed")
    name: str = Field(..., description="Item name")
    impact: int = Field(..., description="Impact score")
    likelihood: int = Field(..., description="Likelihood score")
    risk_level: str = Field(..., description="Calculated risk level (Low/Medium/High)")
    color_code: str = Field(..., description="Color for visualization (#hex)")
    above_appetite: bool = Field(..., description="Is this risk above organizational appetite?")
    reasoning: str = Field(..., description="Explanation of risk classification")


class HeatMapReport(BaseModel):
    """Model for complete heat-map report."""
    report_id: str = Field(..., description="Unique report identifier")
    session_id: str = Field(..., description="Session ID")
    organization: str = Field(..., description="Organization name")
    risk_appetite_profile: RiskAppetiteProfile = Field(..., description="Risk appetite context")
    heat_map_items: List[HeatMapAnalysis] = Field(..., description="Analyzed heat-map items")
    items_above_appetite: int = Field(..., description="Count of items above organizational appetite")
    generated_at: datetime = Field(default_factory=datetime.now, description="When report was generated")
    visualization_path: Optional[str] = Field(None, description="Path to generated visualization")
